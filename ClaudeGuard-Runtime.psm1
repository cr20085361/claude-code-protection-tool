Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard.psm1')
function Get-GuardReaderPythonCandidates {
    # Ordinary callers use a limited token. Same-account elevated maintenance
    # (matching deployment UserSid) also inspects that user's non-reparse installs.
    $roots=@('HKLM:\SOFTWARE\Python\PythonCore')
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    $principal=[Security.Principal.WindowsPrincipal]::new($identity)
    $limited=-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $includeUser=$limited
    if(-not $limited -and $identity.User -and $identity.User.Value -match '^S-1-5-21-' -and $PSScriptRoot){
        $deployFile=Join-Path $PSScriptRoot 'private\deployment.json'
        if([IO.File]::Exists($deployFile)){
            try{
                $deployObj=[IO.File]::ReadAllText($deployFile,[Text.Encoding]::UTF8)|ConvertFrom-Json
                if($deployObj -and $deployObj.PSObject.Properties['UserSid'] -and [string]$deployObj.UserSid -ceq $identity.User.Value){
                    $includeUser=$true
                }
            }catch{}
        }
    }
    if($includeUser){$roots+=@('HKCU:\SOFTWARE\Python\PythonCore')}
    $raw=[Collections.Generic.List[string]]::new()
    foreach($root in $roots){
        $versions=Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue |
            Where-Object {$_.PSChildName -match '^3\.\d+(\.\d+)?$'} | Sort-Object {[version]$_.PSChildName} -Descending
        foreach($version in $versions){
            $install=Get-Item -LiteralPath (Join-Path $version.PSPath 'InstallPath') -ErrorAction SilentlyContinue
            if(-not $install){continue}
            $exe=$install.GetValue('ExecutablePath')
            if($exe){$raw.Add([string]$exe)}elseif($install.GetValue('')){$raw.Add((Join-Path ([string]$install.GetValue('')) 'python.exe'))}
        }
    }
    if($includeUser -and $env:LOCALAPPDATA){
        foreach($spec in @(
            @{Folder=(Join-Path $env:LOCALAPPDATA 'Programs\Python');Filter='Python3*'},
            @{Folder=(Join-Path $env:LOCALAPPDATA 'Python');Filter='pythoncore-3*'}
        )){
            Get-ChildItem -LiteralPath $spec.Folder -Directory -Filter $spec.Filter -ErrorAction SilentlyContinue |
                ForEach-Object {$raw.Add((Join-Path $_.FullName 'python.exe'))}
        }
    }
    foreach($candidate in $raw){
        if(-not $limited){
            $cursor=$candidate;$safe=$true
            while($cursor){
                if(([IO.File]::Exists($cursor) -or [IO.Directory]::Exists($cursor)) -and (([IO.File]::GetAttributes($cursor) -band [IO.FileAttributes]::ReparsePoint) -ne 0)){$safe=$false;break}
                $parent=[IO.Directory]::GetParent($cursor);$cursor=if($parent){$parent.FullName}else{$null}
            }
            if(-not $safe){continue}
        }
        $candidate
    }
}
function Test-GuardReaderPythonPath([string]$Path) {
    $Path -match '^[A-Za-z]:\\' -and [IO.Path]::GetFileName($Path) -ieq 'python.exe' -and $Path -notmatch '\\WindowsApps\\'
}
function Invoke-GuardReaderPythonProbe([string]$Path,[int]$TimeoutMilliseconds) {
    $clock=[Diagnostics.Stopwatch]::StartNew()
    $result=[ordered]@{Outcome='StartFailed';ExitCode=$null;NativeErrorCode=$null;ElapsedMilliseconds=0}
    $info=[Diagnostics.ProcessStartInfo]::new()
    $info.FileName=$Path;$info.UseShellExecute=$false;$info.CreateNoWindow=$true
    $info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
    foreach($arg in @('-I','-S','-c','import ctypes, json, pathlib, struct, sys, threading, urllib.parse; sys.exit(0 if sys.implementation.name == "cpython" and sys.version_info.major == 3 and struct.calcsize("P") == 8 else 1)')){$info.ArgumentList.Add($arg)}
    $probe=[Diagnostics.Process]::new();$probe.StartInfo=$info
    try{
        if($probe.Start()){
            $null=$probe.StandardOutput.ReadToEndAsync();$null=$probe.StandardError.ReadToEndAsync()
            $remaining=[Math]::Max(0,$TimeoutMilliseconds-[int]$clock.ElapsedMilliseconds)
            if($remaining -gt 0 -and $probe.WaitForExit($remaining) -and $clock.ElapsedMilliseconds -le $TimeoutMilliseconds){
                $result.ExitCode=$probe.ExitCode
                $result.Outcome=if($result.ExitCode -eq 0){'Passed'}else{'NonZeroExit'}
            }else{
                $result.Outcome='TimedOut'
                try{$probe.Kill()}catch [InvalidOperationException] {}catch [System.ComponentModel.Win32Exception] {$result.NativeErrorCode=$_.Exception.NativeErrorCode}
            }
        }
    }catch [System.ComponentModel.Win32Exception] {
        $result.NativeErrorCode=$_.Exception.NativeErrorCode
    }finally{
        $probe.Dispose()
        $result.ElapsedMilliseconds=$clock.ElapsedMilliseconds
    }
    [pscustomobject]$result
}
function Resolve-GuardReaderPython([ValidateRange(1,8000)][int]$TimeoutMilliseconds=8000,[ref]$ProbeFailures) {
    $clock=[Diagnostics.Stopwatch]::StartNew()
    $failures=[Collections.Generic.List[object]]::new()
    $candidates=[Collections.Generic.List[object]]::new()
    $paths=@(Get-GuardReaderPythonCandidates | Select-Object -Unique)
    for($index=0;$index -lt $paths.Count -and $clock.ElapsedMilliseconds -lt $TimeoutMilliseconds;$index++){
        $path=$paths[$index]
        $outcome=if(-not (Test-GuardReaderPythonPath $path)){'InvalidCandidate'}elseif(-not [IO.File]::Exists($path)){'MissingFile'}
        if($outcome){
            $failures.Add([pscustomobject]@{CandidateIndex=$index+1;Round=0;Outcome=$outcome;ElapsedMilliseconds=$null;ExitCode=$null;NativeErrorCode=$null})
        }else{$candidates.Add([pscustomobject]@{Index=$index+1;Path=$path})}
    }
    # Try the alternatives before returning to an interpreter that failed once.
    # Never accept a cached success or mark a timed-out runtime snapshot safe.
    foreach($round in 1,2){
        if(-not $candidates.Count){break}
        $limit=if($round -eq 1){1500}else{2250}
        if($round -eq 2){
            $remaining=$TimeoutMilliseconds-[int]$clock.ElapsedMilliseconds
            if($remaining -le 1){break}
            Start-Sleep -Milliseconds ([Math]::Min(150,$remaining-1))
        }
        foreach($candidate in $candidates){
            $remaining=$TimeoutMilliseconds-[int]$clock.ElapsedMilliseconds
            if($remaining -le 0){break}
            $probe=Invoke-GuardReaderPythonProbe $candidate.Path ([Math]::Min($limit,$remaining))
            if($probe.Outcome -eq 'Passed' -and $clock.ElapsedMilliseconds -le $TimeoutMilliseconds){
                if($null -ne $ProbeFailures){$ProbeFailures.Value=$failures.ToArray()}
                return [IO.Path]::GetFullPath($candidate.Path)
            }
            if($probe.Outcome -ne 'Passed'){
                # Keep only numeric codes and fixed categories, never paths or child output.
                $failures.Add([pscustomobject]@{CandidateIndex=$candidate.Index;Round=$round;Outcome=$probe.Outcome;ElapsedMilliseconds=$probe.ElapsedMilliseconds;ExitCode=$probe.ExitCode;NativeErrorCode=$probe.NativeErrorCode})
            }
        }
    }
    $summary=if($clock.ElapsedMilliseconds -ge $TimeoutMilliseconds){'BudgetExhausted'}elseif(-not $paths.Count){'NoCandidate'}
    if($summary){
        $failures.Add([pscustomobject]@{CandidateIndex=$null;Round=0;Outcome=$summary;ElapsedMilliseconds=$clock.ElapsedMilliseconds;ExitCode=$null;NativeErrorCode=$null})
    }
    if($null -ne $ProbeFailures){$ProbeFailures.Value=$failures.ToArray()}
    throw 'RuntimeReaderUnavailable: 未能确认 64 位 CPython 3 可运行。请查看解释器探测诊断。'
}
function Invoke-GuardEnvironmentReader([string]$PythonPath,[string]$ReaderPath,[int]$ProcessId,[int]$TimeoutMilliseconds,[string]$LocalServicePath='',[long]$LocalServiceStarted=0) {
    if($TimeoutMilliseconds -le 0){return [pscustomobject]@{ExitCode=124;Output='';TimedOut=$true}}
    $info=[Diagnostics.ProcessStartInfo]::new()
    $info.FileName=$PythonPath;$info.UseShellExecute=$false;$info.CreateNoWindow=$true
    $info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
    $info.ArgumentList.Add('-I');$info.ArgumentList.Add('-S');$info.ArgumentList.Add($ReaderPath);$info.ArgumentList.Add([string]$ProcessId)
    if($LocalServicePath){
        $info.ArgumentList.Add('--local-service-path');$info.ArgumentList.Add($LocalServicePath)
        $info.ArgumentList.Add('--local-service-started');$info.ArgumentList.Add([string]$LocalServiceStarted)
    }
    $reader=[Diagnostics.Process]::new();$reader.StartInfo=$info
    $deadlineClock=[Diagnostics.Stopwatch]::StartNew()
    try {
        if(-not $reader.Start()){throw 'Environment evidence reader could not start.'}
        $output=$reader.StandardOutput.ReadToEndAsync();$errors=$reader.StandardError.ReadToEndAsync()
        $remaining=[Math]::Max(0,$TimeoutMilliseconds-[int]$deadlineClock.ElapsedMilliseconds)
        if(-not $remaining -or -not $reader.WaitForExit($remaining)){
            # 仅结束本次创建的 reader；不终止目标 Claude 或其它证据进程。
            try{$reader.Kill()}catch{}
            return [pscustomobject]@{ExitCode=124;Output='';TimedOut=$true}
        }
        $remaining=[Math]::Max(0,$TimeoutMilliseconds-[int]$deadlineClock.ElapsedMilliseconds)
        if(-not $remaining -or -not $output.Wait($remaining)){
            return [pscustomobject]@{ExitCode=124;Output='';TimedOut=$true}
        }
        [pscustomobject]@{ExitCode=$reader.ExitCode;Output=$output.GetAwaiter().GetResult();TimedOut=($reader.ExitCode -eq 124)}
    }finally{$reader.Dispose()}
}
function Initialize-GuardNativeEnvironmentType {
    if('ClaudeGuardNativeEnvironment' -as [type]){return}
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

public static class ClaudeGuardNativeEnvironment {
    [StructLayout(LayoutKind.Sequential)]
    private struct FILETIME { public uint dwLowDateTime; public uint dwHighDateTime; }
    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_BASIC_INFORMATION {
        public IntPtr ExitStatus;
        public IntPtr PebBaseAddress;
        public UIntPtr AffinityMask;
        public int BasePriority;
        public UIntPtr UniqueProcessId;
        public UIntPtr InheritedFromUniqueProcessId;
    }
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool QueryFullProcessImageNameW(IntPtr process, uint flags, StringBuilder exeName, ref uint size);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(IntPtr process, IntPtr baseAddress, [Out] byte[] buffer, UIntPtr size, out UIntPtr numberOfBytesRead);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetProcessTimes(IntPtr process, out FILETIME creation, out FILETIME exit, out FILETIME kernel, out FILETIME user);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr LocalFree(IntPtr mem);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string fileName, uint desiredAccess, uint shareMode, IntPtr securityAttributes, uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(SafeFileHandle file, StringBuilder filePath, uint filePathSize, uint flags);
    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(IntPtr process, int processInformationClass, ref PROCESS_BASIC_INFORMATION processInformation, int processInformationLength, out int returnLength);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(IntPtr tokenHandle, int tokenInformationClass, byte[] tokenInformation, uint tokenInformationLength, out uint returnLength);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool ConvertSidToStringSidW(IntPtr sid, out IntPtr stringSid);
    [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CommandLineToArgvW(string cmdLine, out int numArgs);

    private static byte[] ReadExact(IntPtr process, ulong address, int size) {
        byte[] buf = new byte[size];
        UIntPtr read;
        if (!ReadProcessMemory(process, new IntPtr(unchecked((long)address)), buf, (UIntPtr)size, out read) || (int)read != size) {
            throw new IOException("Process environment evidence unavailable.");
        }
        return buf;
    }

    private static string ResolveFinalPath(string path) {
        string full = Path.GetFullPath(path);
        using (SafeFileHandle handle = CreateFileW(full, 0, 7, IntPtr.Zero, 3, 0x02000000, IntPtr.Zero)) {
            if (!handle.IsInvalid) {
                StringBuilder sb = new StringBuilder(32768);
                uint len = GetFinalPathNameByHandleW(handle, sb, (uint)sb.Capacity, 0);
                if (len > 0 && len < sb.Capacity) {
                    string resolved = sb.ToString();
                    if (resolved.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase)) return @"\\" + resolved.Substring(8);
                    if (resolved.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase)) return resolved.Substring(4);
                    return resolved;
                }
            }
        }
        return full;
    }

    private static string GetProcessUserSid(IntPtr process) {
        IntPtr token;
        if (!OpenProcessToken(process, 0x0008, out token)) throw new IOException("Local service owner unavailable.");
        try {
            uint needed = 0;
            GetTokenInformation(token, 1, null, 0, out needed);
            if (needed == 0) throw new IOException("Local service owner unavailable.");
            byte[] buf = new byte[needed];
            if (!GetTokenInformation(token, 1, buf, needed, out needed)) throw new IOException("Local service owner unavailable.");
            GCHandle pinned = GCHandle.Alloc(buf, GCHandleType.Pinned);
            try {
                IntPtr sidPtr = Marshal.ReadIntPtr(pinned.AddrOfPinnedObject());
                IntPtr strPtr;
                if (!ConvertSidToStringSidW(sidPtr, out strPtr)) throw new IOException("Local service owner unavailable.");
                try {
                    return Marshal.PtrToStringUni(strPtr);
                } finally {
                    LocalFree(strPtr);
                }
            } finally {
                pinned.Free();
            }
        } finally {
            CloseHandle(token);
        }
    }

    private static string DetectStandaloneWebServer(IntPtr process, ulong parameters, string executable) {
        byte[] header = ReadExact(process, parameters + 0x70, 16);
        ushort length = BitConverter.ToUInt16(header, 0);
        ulong pointer = BitConverter.ToUInt64(header, 8);
        if (length == 0 || length > 32766 || (length % 2) != 0) return "";
        string raw = Encoding.Unicode.GetString(ReadExact(process, pointer, length));
        int count;
        IntPtr argvPtr = CommandLineToArgvW(raw, out count);
        if (argvPtr == IntPtr.Zero) return "";
        List<string> argv = new List<string>();
        try {
            for (int i = 1; i < count; i++) {
                IntPtr itemPtr = Marshal.ReadIntPtr(argvPtr, i * IntPtr.Size);
                argv.Add(Marshal.PtrToStringUni(itemPtr) ?? "");
            }
        } finally {
            LocalFree(argvPtr);
        }
        string imageName = Path.GetFileName(executable).ToLowerInvariant();
        if (imageName == "node.exe" && argv.Count > 0) {
            string entry = argv[0].Replace('\\', '/').ToLowerInvariant();
            if (entry.EndsWith("/node_modules/vite/bin/vite.js", StringComparison.Ordinal) || entry == "node_modules/vite/bin/vite.js") {
                return "vite";
            }
        }
        if (imageName == "python.exe" || imageName == "pythonw.exe") {
            int offset = (argv.Count > 0 && argv[0] == "-I") ? 1 : 0;
            if (argv.Count - offset >= 2 && argv[offset] == "-m" && argv[offset + 1] == "http.server" && !argv.Contains("--cgi")) {
                return "python-http";
            }
            if (argv.Count - offset >= 2 && Path.GetFileName(argv[offset]).ToLowerInvariant() == "manage.py" && argv[offset + 1] == "runserver") {
                return "django";
            }
        }
        return "";
    }

    private static string GetEnv(Dictionary<string, string> env, string key) {
        string val;
        return env.TryGetValue(key, out val) ? val : "";
    }

    private static string EscapeJson(string s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder(s.Length + 4);
        foreach (char c in s) {
            switch (c) {
                case '\\': sb.Append("\\\\"); break;
                case '"': sb.Append("\\\""); break;
                case '\b': sb.Append("\\b"); break;
                case '\f': sb.Append("\\f"); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                default:
                    if (c < 0x20) sb.AppendFormat("\\u{0:x4}", (int)c);
                    else sb.Append(c);
                    break;
            }
        }
        return sb.ToString();
    }

    private static string JsonArray(List<string> items) {
        if (items.Count == 0) return "[]";
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < items.Count; i++) {
            if (i > 0) sb.Append(",");
            sb.Append("\"").Append(EscapeJson(items[i])).Append("\"");
        }
        sb.Append("]");
        return sb.ToString();
    }

    public static string ReadJson(int pid, string[] approvedPaths, string userSid, string configDir, string proxyUrl, string localServicePath, long localServiceStarted, bool hasLocalService) {
        if (IntPtr.Size != 8) throw new PlatformNotSupportedException("64-bit process required.");
        IntPtr h = OpenProcess(0x0410, false, pid);
        if (h == IntPtr.Zero) throw new IOException("Approved process cannot be opened for read-only evidence.");
        try {
            StringBuilder imgBuf = new StringBuilder(32768);
            uint imgLen = (uint)imgBuf.Capacity;
            if (!QueryFullProcessImageNameW(h, 0, imgBuf, ref imgLen)) throw new IOException("Process path could not be verified.");
            string image = imgBuf.ToString();
            bool approvedPath = false;
            if (approvedPaths != null) {
                foreach (string p in approvedPaths) {
                    if (!string.IsNullOrEmpty(p) && string.Equals(image, p, StringComparison.OrdinalIgnoreCase)) {
                        approvedPath = true;
                        break;
                    }
                }
            }
            bool localServiceVerified = false;
            if (hasLocalService) {
                if (!string.Equals(ResolveFinalPath(image), ResolveFinalPath(localServicePath), StringComparison.OrdinalIgnoreCase)) {
                    throw new InvalidOperationException("Local service image changed.");
                }
                FILETIME creation, exit, kernel, user;
                if (!GetProcessTimes(h, out creation, out exit, out kernel, out user)) {
                    throw new IOException("Local service creation time unavailable.");
                }
                long started = unchecked((long)(((ulong)creation.dwHighDateTime << 32) | creation.dwLowDateTime));
                if (started != localServiceStarted) {
                    throw new InvalidOperationException("Local service process identity changed.");
                }
                if (!string.Equals(GetProcessUserSid(h), userSid, StringComparison.Ordinal)) {
                    throw new InvalidOperationException("Local service belongs to another account.");
                }
                localServiceVerified = true;
            } else if (!approvedPath) {
                throw new InvalidOperationException("Refusing environment read outside approved Claude paths.");
            }

            PROCESS_BASIC_INFORMATION pbi = new PROCESS_BASIC_INFORMATION();
            int returned;
            if (NtQueryInformationProcess(h, 0, ref pbi, Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION)), out returned) != 0) {
                throw new IOException("Process basic information unavailable.");
            }
            ulong peb = unchecked((ulong)pbi.PebBaseAddress.ToInt64());
            ulong parameters = BitConverter.ToUInt64(ReadExact(h, peb + 0x20, 8), 0);
            ulong envAddress = BitConverter.ToUInt64(ReadExact(h, parameters + 0x80, 8), 0);

            Encoding utf16 = new UnicodeEncoding(false, false, false);
            byte[] data = new byte[1024 * 1024];
            int total = 0;
            string text = null;
            for (int offset = 0; offset < 1024 * 1024; offset += 256) {
                byte[] chunk = ReadExact(h, envAddress + (ulong)offset, 256);
                Buffer.BlockCopy(chunk, 0, data, total, 256);
                total += 256;
                string decoded = utf16.GetString(data, 0, total);
                int term = decoded.IndexOf("\0\0", StringComparison.Ordinal);
                if (term >= 0) {
                    text = decoded.Substring(0, term);
                    break;
                }
            }
            if (text == null) throw new InvalidOperationException("Environment terminator was not found.");

            Dictionary<string, string> env = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (string item in text.Split('\0')) {
                int eq = item.IndexOf('=');
                if (eq > 0) {
                    env[item.Substring(0, eq).ToUpperInvariant()] = item.Substring(eq + 1);
                }
            }

            string[] overrides = new string[] { "ANTHROPIC_BASE_URL", "ANTHROPIC_MODEL", "CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY" };
            string rawBase = GetEnv(env, "ANTHROPIC_BASE_URL");
            string baseHost = "";
            bool officialBase = false;
            Uri parsedBase;
            if (!string.IsNullOrEmpty(rawBase) && Uri.TryCreate(rawBase, UriKind.Absolute, out parsedBase)) {
                baseHost = (parsedBase.Host ?? "").ToLowerInvariant();
                officialBase = string.Equals(parsedBase.Scheme, "https", StringComparison.OrdinalIgnoreCase)
                    && baseHost == "api.anthropic.com"
                    && (parsedBase.IsDefaultPort || parsedBase.Port == 443)
                    && string.IsNullOrEmpty(parsedBase.UserInfo);
            }

            string standaloneKind = "";
            if (localServiceVerified) {
                string hp = GetEnv(env, "HTTP_PROXY"), hsp = GetEnv(env, "HTTPS_PROXY"), ap = GetEnv(env, "ALL_PROXY");
                if ((hp == "" || hp == proxyUrl) && (hsp == "" || hsp == proxyUrl) && (ap == "" || ap == proxyUrl)) {
                    standaloneKind = DetectStandaloneWebServer(h, parameters, image);
                }
            }

            HashSet<string> noProxySet = new HashSet<string>(GetEnv(env, "NO_PROXY").Split(','), StringComparer.Ordinal);
            bool noProxyLoopback = noProxySet.Count == 3 && noProxySet.Contains("localhost") && noProxySet.Contains("127.0.0.1") && noProxySet.Contains("::1");

            List<string> providerNames = new List<string>();
            List<string> unexpectedProviders = new List<string>();
            foreach (string key in overrides) {
                if (!string.IsNullOrEmpty(GetEnv(env, key))) {
                    providerNames.Add(key);
                    if (!(key == "ANTHROPIC_BASE_URL" && officialBase)) unexpectedProviders.Add(key);
                }
            }

            string[] tlsKeys = new string[] { "NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE", "SSL_CERT_DIR", "CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE" };
            List<string> unexpectedTls = new List<string>();
            foreach (string key in tlsKeys) {
                if (!string.IsNullOrEmpty(GetEnv(env, key))) unexpectedTls.Add(key);
            }

            bool configMatches = string.Equals(GetEnv(env, "CLAUDE_CONFIG_DIR"), configDir ?? "", StringComparison.OrdinalIgnoreCase);
            bool httpMatches = GetEnv(env, "HTTP_PROXY") == proxyUrl;
            bool httpsMatches = GetEnv(env, "HTTPS_PROXY") == proxyUrl;
            bool allMatches = GetEnv(env, "ALL_PROXY") == proxyUrl;
            bool autoUpdaterDisabled = GetEnv(env, "DISABLE_AUTOUPDATER") == "1";
            bool tlsEnabled = GetEnv(env, "NODE_TLS_REJECT_UNAUTHORIZED") != "0";

            StringBuilder json = new StringBuilder(512);
            json.Append("{\"Pid\":").Append(pid);
            json.Append(",\"ApprovedPath\":").Append(approvedPath ? "true" : "false");
            json.Append(",\"LocalServiceIdentityVerified\":").Append(localServiceVerified ? "true" : "false");
            json.Append(",\"StandaloneWebServer\":\"").Append(EscapeJson(standaloneKind)).Append("\"");
            json.Append(",\"ConfigDirMatches\":").Append(configMatches ? "true" : "false");
            json.Append(",\"HttpProxyMatches\":").Append(httpMatches ? "true" : "false");
            json.Append(",\"HttpsProxyMatches\":").Append(httpsMatches ? "true" : "false");
            json.Append(",\"AllProxyMatches\":").Append(allMatches ? "true" : "false");
            json.Append(",\"NoProxyOnlyLoopback\":").Append(noProxyLoopback ? "true" : "false");
            json.Append(",\"ProviderOverrideNames\":").Append(JsonArray(providerNames));
            json.Append(",\"BaseUrlHost\":\"").Append(EscapeJson(baseHost)).Append("\"");
            json.Append(",\"BaseUrlIsOfficialAnthropicApi\":").Append(officialBase ? "true" : "false");
            json.Append(",\"UnexpectedProviderOverrideNames\":").Append(JsonArray(unexpectedProviders));
            json.Append(",\"AutoUpdaterDisabled\":").Append(autoUpdaterDisabled ? "true" : "false");
            json.Append(",\"TlsVerificationEnabled\":").Append(tlsEnabled ? "true" : "false");
            json.Append(",\"UnexpectedTlsOverrideNames\":").Append(JsonArray(unexpectedTls));
            json.Append("}");
            return json.ToString();
        } finally {
            CloseHandle(h);
        }
    }
}
'@
}
function Invoke-GuardNativeEnvironmentRead([int]$ProcessId,$State=$null,[string]$LocalServicePath='',[long]$LocalServiceStarted=0) {
    if(-not $State){$State=Get-GuardState}
    Initialize-GuardNativeEnvironmentType
    $approved=@([string]$State.Desktop.Path)+@($State.CodePaths|ForEach-Object {[string]$_})
    $hasLocal=-not [string]::IsNullOrEmpty($LocalServicePath)
    $json=[ClaudeGuardNativeEnvironment]::ReadJson($ProcessId,[string[]]$approved,[string]$State.UserSid,[string]$State.ConfigDir,[string]$State.ProxyUrl,$LocalServicePath,$LocalServiceStarted,$hasLocal)
    [pscustomobject]@{ExitCode=0;Output=$json;TimedOut=$false}
}
function Test-GuardNativeReaderEligible($Reader) {
    if($Reader.ContainsKey('NativeEligible')){return [bool]$Reader.NativeEligible}
    $eligible=$false
    try{
        $readerCmd=Get-Command Invoke-GuardEnvironmentReader -ErrorAction SilentlyContinue
        if([Environment]::Is64BitProcess -and $PSCommandPath -and $readerCmd -and $readerCmd.ScriptBlock -and
            [string]::Equals($readerCmd.ScriptBlock.File,$PSCommandPath,[StringComparison]::OrdinalIgnoreCase) -and
            $Reader.Script -and [IO.File]::Exists($Reader.Script)){
            $state=Get-GuardState
            if($state -and $state.PSObject.Properties['UserSid'] -and $state.PSObject.Properties['ConfigDir'] -and
                $state.PSObject.Properties['ProxyUrl'] -and $state.PSObject.Properties['Reliability'] -and
                $state.Reliability -and $state.Reliability.PSObject.Properties['EnvironmentReaderHash'] -and
                (Get-GuardHash $Reader.Script) -eq $state.Reliability.EnvironmentReaderHash){
                $Reader['NativeState']=$state
                $eligible=$true
            }
        }
    }catch{}
    $Reader['NativeEligible']=$eligible
    $eligible
}
function Read-GuardRuntimeEvidence($Reader,[int]$ProcessId,[string]$LocalServicePath='',[long]$LocalServiceStarted=0) {
    if($null -eq $Reader.Candidates){
        $Reader.Candidates=@(Get-GuardReaderPythonCandidates | Select-Object -Unique |
            Where-Object {(Test-GuardReaderPythonPath $_) -and [IO.File]::Exists($_)})
    }
    if(-not $Reader.Candidates.Count){
        $Reader.Failures.Add([pscustomobject]@{
            ProcessId=$ProcessId;CandidateIndex=$null;Round=0;Outcome='NoCandidate'
            ElapsedMilliseconds=$null;ExitCode=$null;NativeErrorCode=$null
        })
        return
    }
    # Fast in-process read avoids repeated cold-start Python process starvation under heavy CPU/IO load,
    # while falling back to the isolated Python reader if the target is inaccessible or in test fixtures.
    if(($Reader.BudgetMilliseconds-[int]$Reader.Clock.ElapsedMilliseconds) -gt 0 -and (Test-GuardNativeReaderEligible $Reader)){
        try{
            $fast=Invoke-GuardNativeEnvironmentRead -ProcessId $ProcessId -State $Reader['NativeState'] -LocalServicePath $LocalServicePath -LocalServiceStarted $LocalServiceStarted
            if($fast.ExitCode -eq 0 -and $Reader.Clock.ElapsedMilliseconds -lt $Reader.BudgetMilliseconds){
                return $fast
            }
        }catch{}
    }
    # Reuse the interpreter path that worked in this snapshot. Every PID still
    # requires a fresh response from the isolated reader.
    $order=@($Reader.PreferredIndex)+@(0..($Reader.Candidates.Count-1)|Where-Object {$_ -ne $Reader.PreferredIndex})
    foreach($round in 1,2){
        foreach($index in $order){
            $remaining=$Reader.BudgetMilliseconds-[int]$Reader.Clock.ElapsedMilliseconds
            if($remaining -le 0){return}
            $limit=[Math]::Min($Reader.TimeoutMilliseconds,$remaining)
            # Give another attempt time to run even when the caller's budget is short.
            if($round -eq 1){$limit=[Math]::Min($limit,[Math]::Max(1,[int][Math]::Min(5000,[Math]::Floor($remaining/2))))}
            $attempt=[Diagnostics.Stopwatch]::StartNew()
            $read=$null;$nativeError=$null;$outcome='ReadFailed'
            try{
                $read=Invoke-GuardEnvironmentReader $Reader.Candidates[$index] $Reader.Script $ProcessId $limit $LocalServicePath $LocalServiceStarted
                if($read.ExitCode -eq 0 -and $Reader.Clock.ElapsedMilliseconds -lt $Reader.BudgetMilliseconds){
                    $Reader.PreferredIndex=$index
                    return $read
                }
                $outcome=if($read.TimedOut -or $read.ExitCode -eq 0){'TimedOut'}else{'NonZeroExit'}
            }catch [System.ComponentModel.Win32Exception]{
                $outcome='StartFailed';$nativeError=$_.Exception.GetBaseException().NativeErrorCode
            }catch{
                # Child output and exception details can include local paths.
            }
            $Reader.Failures.Add([pscustomobject]@{
                ProcessId=$ProcessId;CandidateIndex=$index+1;Round=$round;Outcome=$outcome
                ElapsedMilliseconds=$attempt.ElapsedMilliseconds;ExitCode=if($read){$read.ExitCode};NativeErrorCode=$nativeError
            })
        }
    }
}
function Test-GuardRuntimeEnvironment($Evidence) {
    $required=@('ConfigDirMatches','HttpProxyMatches','HttpsProxyMatches','AllProxyMatches','NoProxyOnlyLoopback','TlsVerificationEnabled','UnexpectedTlsOverrideNames','UnexpectedProviderOverrideNames')
    if(-not $Evidence -or @($required|Where-Object {-not $Evidence.PSObject.Properties[$_]}).Count){return $false}
    $Evidence.ConfigDirMatches -eq $true -and $Evidence.HttpProxyMatches -eq $true -and $Evidence.HttpsProxyMatches -eq $true -and
        $Evidence.AllProxyMatches -eq $true -and $Evidence.NoProxyOnlyLoopback -eq $true -and $Evidence.TlsVerificationEnabled -eq $true -and
        @($Evidence.UnexpectedTlsOverrideNames).Count -eq 0 -and @($Evidence.UnexpectedProviderOverrideNames).Count -eq 0
}
function Test-GuardLoopbackAddress([string]$Address){$Address -eq '::1' -or $Address -like '127.*' -or $Address -like '::ffff:127.*'}
function Get-GuardTcpListeners {
    # Query the LISTENER table class, not State or an empty remote endpoint:
    # Windows also exposes non-listening bind() sockets with remote port zero.
    if(-not ('ClaudeGuardNativeListeners' -as [type])){
        Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Net;
using System.Runtime.InteropServices;
public sealed class ClaudeGuardListenerRow {
    public int OwningProcess; public string LocalAddress; public int LocalPort;
    public int ReportedState; public string State = "Listen";
}
public static class ClaudeGuardNativeListeners {
    // TcpConnectionEstatsSynOpts / TCP_ESTATS_SYN_OPTS_ROS_v0.ActiveOpen.
    // Only a successful passive-open observation can excuse a non-loopback incoming peer.
    [DllImport("iphlpapi.dll")] static extern uint GetPerTcpConnectionEStats(byte[] row, int type, IntPtr rw, int rwVersion, int rwSize, [Out] byte[] ros, int rosVersion, int rosSize, IntPtr rod, int rodVersion, int rodSize);
    [DllImport("iphlpapi.dll")] static extern uint GetPerTcp6ConnectionEStats(byte[] row, int type, IntPtr rw, int rwVersion, int rwSize, [Out] byte[] ros, int rosVersion, int rosSize, IntPtr rod, int rodVersion, int rodSize);
    public static bool IsPassive(string local, int localPort, string remote, int remotePort) {
        IPAddress a, b;
        if (!IPAddress.TryParse(local,out a) || !IPAddress.TryParse(remote,out b) || a.AddressFamily!=b.AddressFamily) return false;
        bool v6=a.GetAddressBytes().Length==16;
        byte[] row=new byte[v6?52:20], ros=new byte[12];
        row[0]=5; // MIB_TCP_STATE_ESTAB
        a.GetAddressBytes().CopyTo(row,4);
        b.GetAddressBytes().CopyTo(row,v6?28:12);
        if (v6) {
            BitConverter.GetBytes((uint)a.ScopeId).CopyTo(row,20);
            BitConverter.GetBytes((uint)b.ScopeId).CopyTo(row,44);
        }
        int p=v6?24:8, q=v6?48:16;
        row[p]=(byte)(localPort>>8); row[p+1]=(byte)localPort;
        row[q]=(byte)(remotePort>>8); row[q+1]=(byte)remotePort;
        uint status=v6?GetPerTcp6ConnectionEStats(row,0,IntPtr.Zero,0,0,ros,0,ros.Length,IntPtr.Zero,0,0):
                       GetPerTcpConnectionEStats(row,0,IntPtr.Zero,0,0,ros,0,ros.Length,IntPtr.Zero,0,0);
        return status==0 && ros[0]==0;
    }
    [DllImport("iphlpapi.dll")]
    private static extern uint GetExtendedTcpTable(IntPtr table, ref uint size, bool order, uint family, int tableClass, uint reserved);
    public static ClaudeGuardListenerRow[] Read() {
        var result = new List<ClaudeGuardListenerRow>();
        foreach(uint family in new uint[]{2,23}) {
            uint size=0; uint code=GetExtendedTcpTable(IntPtr.Zero, ref size, false, family, 3, 0);
            if(code!=122 && code!=0) throw new InvalidOperationException("Listener table sizing failed: "+code);
            bool complete=false;
            for(int attempt=0;attempt<5;attempt++) {
                if(size<4 || size>67108864) throw new InvalidOperationException("Invalid listener table size.");
                int capacity=(int)size; IntPtr buffer=Marshal.AllocHGlobal(capacity);
                try {
                    code=GetExtendedTcpTable(buffer, ref size, false, family, 3, 0);
                    if(code==122) continue;
                    if(code!=0) throw new InvalidOperationException("Listener table read failed: "+code);
                    int count=Marshal.ReadInt32(buffer), stride=family==2?24:56;
                    if(count<0 || count>(capacity-4)/stride) throw new InvalidOperationException("Truncated listener table.");
                    for(int i=0;i<count;i++) {
                        IntPtr row=IntPtr.Add(buffer,4+i*stride); string address;
                        if(family==2) address=new IPAddress((long)(uint)Marshal.ReadInt32(row,4)).ToString();
                        else {var bytes=new byte[16];Marshal.Copy(row,bytes,0,16);address=new IPAddress(bytes,(long)(uint)Marshal.ReadInt32(row,16)).ToString();}
                        int port=Marshal.ReadInt32(row,family==2?8:20);
                        result.Add(new ClaudeGuardListenerRow{OwningProcess=Marshal.ReadInt32(row,family==2?20:52),
                            LocalAddress=address,LocalPort=((port&255)<<8)|((port>>8)&255),ReportedState=Marshal.ReadInt32(row,family==2?0:48)});
                    }
                    complete=true;break;
                } finally {Marshal.FreeHGlobal(buffer);}
            }
            if(!complete) throw new InvalidOperationException("Listener table kept changing.");
        }
        return result.ToArray();
    }
}
'@
    }
    [ClaudeGuardNativeListeners]::Read()
}
function Test-GuardLocalServiceConnection($Connection,$Services) {
    @($Services|Where-Object {$_.LocalPort -eq $Connection.RemotePort -and ($_.LocalAddress -eq $Connection.RemoteAddress -or $_.LocalAddress -in @('0.0.0.0','::'))}).Count -gt 0
}
function Get-GuardSocketKey($Address,$Port,$PeerAddress,$PeerPort) {
    $Address=$Address -replace '^::ffff:(?=\d+\.)',''
    $PeerAddress=$PeerAddress -replace '^::ffff:(?=\d+\.)',''
    "$Address|$Port|$PeerAddress|$PeerPort"
}
function Test-GuardBoundAddress([string]$Bind,[string]$Address) {
    $Bind -eq $Address -or ($Bind -eq '0.0.0.0' -and $Address -notlike '*:*') -or $Bind -eq '::'
}
function Test-GuardTcpPassive($Connection) {
    [ClaudeGuardNativeListeners]::IsPassive($Connection.LocalAddress,$Connection.LocalPort,$Connection.RemoteAddress,$Connection.RemotePort)
}
function Get-GuardPreviewPeer($Connection,$ListenerPorts,$Established) {
    if($Connection.State -ne 'Established' -or -not (Test-GuardLoopbackAddress $Connection.RemoteAddress) -or
       $Connection.RemotePort -in @(10808,10813,10818)){return}
    $key=Get-GuardSocketKey $Connection.RemoteAddress $Connection.RemotePort $Connection.LocalAddress $Connection.LocalPort
    $peer=$Established[$key]
    if(-not $peer){return}
    foreach($listener in $ListenerPorts[[int]$Connection.RemotePort]){
        if($listener.OwningProcess -eq $peer.OwningProcess -and (Test-GuardBoundAddress $listener.LocalAddress $peer.LocalAddress) -and (Test-GuardTcpPassive $peer)){
            return $listener
        }
    }
}
function Test-GuardPreviewInbound($Connection,$ListenerPorts) {
    if($Connection.State -ne 'Established'){return $false}
    foreach($listener in $ListenerPorts[[int]$Connection.LocalPort]){
        if($listener.OwningProcess -ne $Connection.OwningProcess -or -not (Test-GuardBoundAddress $listener.LocalAddress $Connection.LocalAddress)){continue}
        return (Test-GuardTcpPassive $Connection)
    }
    return $false
}
function Get-GuardRuntimeSnapshot([ValidateRange(1,30000)][int]$EvidenceBudgetMilliseconds=30000,[ValidateRange(1,10000)][int]$ReaderTimeoutMilliseconds=10000) {
    $d=Get-GuardState
    $processes=@(Get-CimInstance Win32_Process)
    $desktop=@($processes|Where-Object ExecutablePath -eq $d.Desktop.Path)
    $code=@($processes|Where-Object {$_.ExecutablePath -in @($d.CodePaths)})
    $mains=@($desktop|Where-Object {$_.CommandLine -notmatch '--type='})
    $issues=[Collections.Generic.List[string]]::new()
    foreach($main in $mains){if($main.CommandLine -notmatch '--proxy-server=http://127.0.0.1:10818'){$issues.Add('DesktopFixedProxyMissing')}}
    $pids=@($desktop|ForEach-Object ProcessId)+@($code|ForEach-Object ProcessId)
    $descendants=@($pids)
    do{$added=@($processes|Where-Object {$_.ParentProcessId -in $descendants -and $_.ProcessId -notin $descendants}|ForEach-Object ProcessId);$descendants+=@($added)}while($added.Count)
    $tcp=@(Get-NetTCPConnection -ErrorAction Stop)
    $listeners=@(Get-GuardTcpListeners)
    $connections=@($tcp|Where-Object {$_.OwningProcess -in $pids -and $_.State -in 'Established','SynSent'})
    $listenerPorts=@{};$established=@{};$pairedOwners=@{}
    foreach($listener in $listeners){$listenerPorts[[int]$listener.LocalPort]=@($listenerPorts[[int]$listener.LocalPort] | Where-Object {$_})+@($listener)}
    foreach($row in $tcp){
        if($row.State -eq 'Established' -and (Test-GuardLoopbackAddress $row.LocalAddress)){
            $key=Get-GuardSocketKey $row.LocalAddress $row.LocalPort $row.RemoteAddress $row.RemotePort
            $established[$key]=$row
        }
    }
    $localServices=@($listeners|Where-Object {$_.OwningProcess -in $descendants -and (Test-GuardLoopbackAddress $_.LocalAddress)})
    $reader=@{
        Clock=[Diagnostics.Stopwatch]::StartNew(); BudgetMilliseconds=$EvidenceBudgetMilliseconds
        TimeoutMilliseconds=$ReaderTimeoutMilliseconds; Script=(Join-Path $PSScriptRoot 'Read-ClaudeProcessEnvironment.py')
        Candidates=$null; PreferredIndex=0; Failures=[Collections.Generic.List[object]]::new()
    }
    $previewServices=@();$previewPids=@();$standalonePids=@();$deadlineExceeded=$false
    $previewChecks=[Collections.Generic.List[object]]::new()
    # detached 服务不依赖已经退出的 shell；仅核验 Claude 实际连接的回环端点。
    $candidates=@($listeners|Where-Object {
        $listener=$_
        $listener.OwningProcess -notin $descendants -and $listener.LocalPort -notin @(10808,10813,10818) -and
        (Test-GuardLoopbackAddress $listener.LocalAddress) -and @($connections|Where-Object {
            $_.State -eq 'Established' -and $_.RemoteAddress -eq $listener.LocalAddress -and $_.RemotePort -eq $listener.LocalPort
        }).Count -gt 0
    }|Sort-Object OwningProcess -Unique)
    # Verify root services first, then listeners of their live descendants. The
    # latter are needed for a gateway's internal worker, not an arbitrary port grant.
    $pending=[Collections.Generic.Queue[object]]::new()
    # A wildcard listener alone proves nothing. Match the accepted socket's
    # complete reversed tuple and PID before treating it as a preview candidate.
    foreach($connection in $connections){
        $peer=Get-GuardPreviewPeer $connection $listenerPorts $established
        if($peer -and $peer.OwningProcess -notin $pids){$pairedOwners[[int]$peer.OwningProcess]=$true;$pending.Enqueue($peer)}
    }
    foreach($candidate in $candidates){$pending.Enqueue($candidate)}
    $checkedOwners=@();$previewDescendants=@()
    while($pending.Count){
        $candidate=$pending.Dequeue()
        $ownerId=[int]$candidate.OwningProcess
        if($ownerId -in $checkedOwners){continue};$checkedOwners+=@($ownerId)
        $check=[pscustomobject]@{Pid=$ownerId;LocalAddress=$candidate.LocalAddress;LocalPort=$candidate.LocalPort;Accepted=$false;Reason='OwnerUnavailable'}
        $previewChecks.Add($check)
        $owner=@($processes|Where-Object ProcessId -eq $ownerId|Select-Object -First 1)
        if($owner.Count -ne 1 -or -not $owner[0].ExecutablePath){continue}
        if(-not $pairedOwners[$ownerId] -and @($listeners|Where-Object {$_.OwningProcess -eq $ownerId -and -not (Test-GuardLoopbackAddress $_.LocalAddress)}).Count){$check.Reason='NonLoopbackListener';continue}
        try{
            $live=Get-Process -Id $ownerId -ErrorAction Stop
            $started=$live.StartTime.ToUniversalTime().ToFileTimeUtc()
            $read=Read-GuardRuntimeEvidence $reader $ownerId $owner[0].ExecutablePath $started
            if(-not $read){
                if($reader.Clock.ElapsedMilliseconds -ge $EvidenceBudgetMilliseconds){$deadlineExceeded=$true;$check.Reason='EvidenceDeadline'}
                elseif(-not $reader.Candidates.Count){$check.Reason='RuntimeReaderUnavailable'}
                elseif(@($reader.Failures|Where-Object {$_.ProcessId -eq $ownerId -and $_.Outcome -eq 'TimedOut'}).Count){$check.Reason='ReaderTimeout'}
                else{$check.Reason='IdentityReaderFailed'}
                continue
            }
            $e=$read.Output|ConvertFrom-Json
            if($e.Pid -ne $ownerId -or $e.LocalServiceIdentityVerified -ne $true){$check.Reason='IdentityMismatch';continue}
            $managed=Test-GuardRuntimeEnvironment $e
            if(-not $managed){
                # Ordinary web servers do not need Claude's configuration directory.
                # Restrict independent origins to a recognized entry point, a verified
                # TCP pair and clean provider, TLS and proxy settings. Audit all peers.
                $independent=$pairedOwners[$ownerId] -and $e.PSObject.Properties['StandaloneWebServer'] -and
                    $e.StandaloneWebServer -in @('vite','python-http','django') -and $e.TlsVerificationEnabled -eq $true -and
                    @($e.UnexpectedTlsOverrideNames).Count -eq 0 -and @($e.UnexpectedProviderOverrideNames).Count -eq 0
                if(-not $independent){$check.Reason='EnvironmentMismatch';continue}
                $standalonePids+=@($ownerId)
            }
            if((Get-Process -Id $ownerId -ErrorAction Stop).StartTime.ToUniversalTime().ToFileTimeUtc() -ne $started){$check.Reason='ProcessIdentityChanged';continue}
            $previewServices+=@([pscustomobject]@{Pid=$ownerId;Started=$live.StartTime.ToUniversalTime().ToString('o');Path=$owner[0].ExecutablePath;IdentityVerified=$true;Environment=$e})
            $previewPids+=@($ownerId)
            $check.Accepted=$true;$check.Reason=if($managed){'Verified'}else{'VerifiedStandaloneWebServer'}
            $previewDescendants=@($previewPids)
            do{$added=@($processes|Where-Object {$_.ParentProcessId -in $previewDescendants -and $_.ProcessId -notin $previewDescendants}|ForEach-Object ProcessId);$previewDescendants+=@($added)}while($added.Count)
            # A frontend may call an independently started local API. Verify the
            # receiving owner independently and include its traffic in the same graph.
            foreach($edge in $tcp.Where({$_.OwningProcess -in $previewDescendants -and $_.State -eq 'Established'})){
                if(Test-GuardPreviewInbound $edge $listenerPorts){continue}
                $peer=Get-GuardPreviewPeer $edge $listenerPorts $established
                if($peer -and $peer.OwningProcess -notin $pids -and $peer.OwningProcess -notin $checkedOwners){
                    $pairedOwners[[int]$peer.OwningProcess]=$true;$pending.Enqueue($peer)
                }
            }
            foreach($childListener in @($listeners|Where-Object {$_.OwningProcess -in $previewDescendants -and $_.OwningProcess -notin $checkedOwners})){$pending.Enqueue($childListener)}
        }catch{$check.Reason='EvidenceException';continue}
    }
    $previewDescendants=@($previewPids)
    do{$added=@($processes|Where-Object {$_.ParentProcessId -in $previewDescendants -and $_.ProcessId -notin $previewDescendants}|ForEach-Object ProcessId);$previewDescendants+=@($added)}while($added.Count)
    $localServices+=@($listeners|Where-Object {$_.OwningProcess -in $previewPids -and $_.OwningProcess -notin $standalonePids -and (Test-GuardLoopbackAddress $_.LocalAddress)})
    # 预览服务和存活子进程的出站一并受检；服务端已接受连接按本地监听端点识别。
    $connections+=@($tcp|Where-Object {
        $connection=$_
        $connection.OwningProcess -in $previewDescendants -and $connection.OwningProcess -notin $pids -and $connection.State -in 'Established','SynSent' -and
        -not (Test-GuardPreviewInbound $connection $listenerPorts)
    })
    # 未建立的本机连接不代表已通过其它服务联网；监听器启动/退出也可能跨越两次快照。
    # 共享代理始终拒绝，已建立的未知本机连接和外部直连仍触发保护。
    $unconfirmedLoopback=@($connections|Where-Object {
        (Test-GuardLoopbackAddress $_.RemoteAddress) -and
        $_.State -eq 'SynSent' -and $_.RemotePort -notin @(10808,10813,10818) -and -not (Test-GuardLocalServiceConnection $_ $localServices)
    })
    $unexpected=@($connections|Where-Object {
        if(-not (Test-GuardLoopbackAddress $_.RemoteAddress)){$true}
        elseif($_.RemotePort -in @(10808,10813)){$true}
        elseif($_.RemoteAddress -eq '127.0.0.1' -and $_.RemotePort -eq 10818){$false}
        elseif(($peer=Get-GuardPreviewPeer $_ $listenerPorts $established) -and $peer.OwningProcess -in $previewPids){$false}
        elseif(Test-GuardLocalServiceConnection $_ $localServices){$false}
        else{$_.State -ne 'SynSent'}
    })
    if($unexpected.Count){$issues.Add('UnexpectedRuntimeNetworkPath')}
    $environments=@()
    $timedOutEnvironments=@()
    $invalidEnvironments=@()
    foreach($p in @($mains)+@($code)) {
        # 瞬间已退出的子进程不作为失败；仍在运行却不能回读时停止核准。
        if(-not (Get-Process -Id $p.ProcessId -ErrorAction SilentlyContinue)){continue}
        $read=Read-GuardRuntimeEvidence $reader $p.ProcessId
        if(-not $read){
            if($reader.Clock.ElapsedMilliseconds -ge $EvidenceBudgetMilliseconds){$deadlineExceeded=$true}
            if(Get-Process -Id $p.ProcessId -ErrorAction SilentlyContinue){
                $issue=if($reader.Candidates.Count){'RuntimeEnvironmentUnreadable'}else{'RuntimeReaderUnavailable'}
                if($issue -notin $issues){$issues.Add($issue)}
                $attempts=@($reader.Failures|Where-Object ProcessId -eq $p.ProcessId)
                if($attempts.Count -and -not @($attempts|Where-Object Outcome -ne 'TimedOut').Count){
                    $timedOutEnvironments+=@($p.ProcessId)
                }elseif(-not $attempts.Count -and $deadlineExceeded -and
                    @($reader.Failures|Where-Object Outcome -eq 'TimedOut').Count){
                    $timedOutEnvironments+=@($p.ProcessId)
                }else{$invalidEnvironments+=@($p.ProcessId)}
            }
            continue
        }
        try{
            $e=$read.Output|ConvertFrom-Json
            $required=@('Pid','ApprovedPath','ConfigDirMatches','HttpProxyMatches','HttpsProxyMatches','AllProxyMatches','NoProxyOnlyLoopback','TlsVerificationEnabled','UnexpectedTlsOverrideNames','UnexpectedProviderOverrideNames')
            if(-not $e -or @($required|Where-Object {-not $e.PSObject.Properties[$_]}).Count -or $e.Pid -ne $p.ProcessId -or $e.ApprovedPath -ne $true){throw 'Runtime evidence response is invalid.'}
        }catch{
            if(Get-Process -Id $p.ProcessId -ErrorAction SilentlyContinue){
                if('RuntimeEnvironmentUnreadable' -notin $issues){$issues.Add('RuntimeEnvironmentUnreadable')}
                $invalidEnvironments+=@($p.ProcessId)
            }
            continue
        }
        $environments+=$e
        if(-not (Test-GuardRuntimeEnvironment $e)){$issues.Add('RuntimeEnvironmentMismatch')}
    }
    $identities=@($pids|ForEach-Object {$running=Get-Process -Id $_ -ErrorAction SilentlyContinue;if($running){@{Pid=$_;Started=$running.StartTime.ToUniversalTime().ToString('o')}}})
    $readerTimeoutPids=@($reader.Failures|Where-Object Outcome -eq 'TimedOut'|Select-Object -ExpandProperty ProcessId -Unique)
    [pscustomobject]@{Time=[datetime]::UtcNow.ToString('o');Safe=($issues.Count -eq 0);Issues=@($issues);DesktopProcessCount=$desktop.Count;CodeProcessCount=$code.Count;UnexpectedConnections=@($unexpected|Select-Object OwningProcess,LocalAddress,LocalPort,RemoteAddress,RemotePort,State);UnconfirmedLoopbackConnections=@($unconfirmedLoopback|Select-Object OwningProcess,RemoteAddress,RemotePort,State);PreviewServices=$previewServices;PreviewMonitoredPids=$previewDescendants;PreviewServiceChecks=@($previewChecks);ListenerSource='GetExtendedTcpTable/OWNER_PID_LISTENER/IPv4+IPv6';PreviewListeners=@($listeners|Where-Object {$_.OwningProcess -in $checkedOwners}|Select-Object OwningProcess,LocalAddress,LocalPort,ReportedState);Environments=$environments;OwnedPids=@($pids);OwnedProcesses=$identities;EvidenceDeadlineExceeded=$deadlineExceeded;ReaderTimeoutPids=$readerTimeoutPids;EvidenceReaderElapsedMilliseconds=$reader.Clock.ElapsedMilliseconds;RuntimeReaderFailures=$reader.Failures.ToArray();RuntimeEvidenceTimedOut=($timedOutEnvironments.Count -gt 0 -and -not $invalidEnvironments.Count);TimedOutEnvironmentPids=$timedOutEnvironments;InvalidEnvironmentPids=$invalidEnvironments}
}
function Get-GuardRuntimeSafety([ValidateRange(1,30000)][int]$EvidenceBudgetMilliseconds=30000,[ValidateRange(1,10000)][int]$ReaderTimeoutMilliseconds=10000) {
    $clock=[Diagnostics.Stopwatch]::StartNew()
    $snapshot=Get-GuardRuntimeSnapshot -EvidenceBudgetMilliseconds $EvidenceBudgetMilliseconds -ReaderTimeoutMilliseconds $ReaderTimeoutMilliseconds
    # Listener/process/connection enumeration is not atomic. Re-read once only
    # for a loopback-only network mismatch; persistent unknown services still fail.
    $retry=-not $snapshot.Safe -and @($snapshot.Issues|Where-Object {$_ -ne 'UnexpectedRuntimeNetworkPath'}).Count -eq 0 -and
        @($snapshot.UnexpectedConnections).Count -gt 0 -and @($snapshot.UnexpectedConnections|Where-Object {-not (Test-GuardLoopbackAddress $_.RemoteAddress) -or $_.RemotePort -in @(10808,10813)}).Count -eq 0
    $remaining=$EvidenceBudgetMilliseconds-[int]$clock.ElapsedMilliseconds
    if($retry -and $remaining -gt 0){
        $first=[pscustomobject]@{Time=$snapshot.Time;UnexpectedConnections=$snapshot.UnexpectedConnections;PreviewServiceChecks=$snapshot.PreviewServiceChecks;PreviewListeners=$snapshot.PreviewListeners}
        $snapshot=Get-GuardRuntimeSnapshot -EvidenceBudgetMilliseconds $remaining -ReaderTimeoutMilliseconds $ReaderTimeoutMilliseconds
        $snapshot|Add-Member -NotePropertyName LoopbackRecheck -NotePropertyValue $first
    }
    $snapshot
}
function Assert-GuardLaunchedRuntime([int]$ProcessId,[datetime]$ProcessStart,[datetime]$DeadlineUtc) {
    $remaining=[Math]::Min(30000,($DeadlineUtc-[datetime]::UtcNow).TotalMilliseconds)
    if($remaining -lt 1){throw 'RuntimeVerificationTimeout: 本次启动核验已超时。'}
    $snapshot=Get-GuardRuntimeSafety -EvidenceBudgetMilliseconds ([int]$remaining)
    if(-not $snapshot.Safe){throw ('RuntimeVerificationFailed: '+($snapshot.Issues -join ','))}
    $stamp=$ProcessStart.ToUniversalTime().Ticks
    $identity=@($snapshot.OwnedProcesses|Where-Object {$_.Pid -eq $ProcessId -and ([datetime]$_.Started).ToUniversalTime().Ticks -eq $stamp})
    $evidence=@($snapshot.Environments|Where-Object {$_.Pid -eq $ProcessId -and $_.ApprovedPath -eq $true})
    $live=Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
    if($identity.Count -ne 1 -or $evidence.Count -ne 1 -or -not $live -or $live.StartTime.ToUniversalTime().Ticks -ne $stamp){
        throw 'RuntimeLaunchIdentityChanged: 无法确认本次启动的客户端仍在运行。'
    }
    if([datetime]::UtcNow -ge $DeadlineUtc){throw 'RuntimeVerificationTimeout: 本次启动核验已超时。'}
}
function Stop-GuardUnsafeRuntime($Snapshot) {
    $d=Get-GuardState
    foreach($identity in @($Snapshot.OwnedProcesses)) {
        $ownedPid=$identity.Pid
        $p=Get-CimInstance Win32_Process -Filter "ProcessId=$ownedPid" -ErrorAction SilentlyContinue
        $running=Get-Process -Id $ownedPid -ErrorAction SilentlyContinue
        if($p -and $running -and $running.StartTime.ToUniversalTime().Ticks -eq ([datetime]$identity.Started).ToUniversalTime().Ticks -and ($p.ExecutablePath -eq $d.Desktop.Path -or $p.ExecutablePath -in @($d.CodePaths))){Stop-Process -Id $ownedPid -ErrorAction SilentlyContinue}
    }
}
function Stop-GuardProtectedProcesses($State=$null) {
    if(-not $State){$State=Get-GuardState}
    $targets=@($State.Desktop.Path)+@($State.CodePaths)
    $stopped=[Collections.Generic.List[int]]::new()
    foreach($proc in @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue|Where-Object {$_.ExecutablePath -in $targets})) {
        $live=Get-Process -Id $proc.ProcessId -ErrorAction SilentlyContinue
        if(-not $live){continue}
        try{
            Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue
            $stopped.Add([int]$proc.ProcessId)
        }catch{}
    }
    @($stopped)
}
Export-ModuleMember -Function *-Guard*
