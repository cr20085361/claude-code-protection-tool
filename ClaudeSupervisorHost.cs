// Compile with .NET Framework 4 csc /target:winexe /r:System.Web.Extensions.dll.
// Only the PowerShell supervisor belongs to the job. Its children silently break away.
using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Web.Script.Serialization;
using Microsoft.Win32.SafeHandles;

internal static class ClaudeSupervisorHost
{
    private const uint CREATE_SUSPENDED = 0x4, CREATE_NO_WINDOW = 0x08000000;
    private const uint KILL_ON_JOB_CLOSE = 0x2000, SILENT_BREAKAWAY_OK = 0x1000;
    private const int LogLimit = 2097152;
    private static readonly JavaScriptSerializer Json = new JavaScriptSerializer();
    private static readonly object LogLock = new object();
    private static readonly List<Thread> Readers = new List<Thread>();
    private static string Root, Private, RunId, Stage = "initialization";
    private static readonly int HostPid = Process.GetCurrentProcess().Id;
    private static readonly DateTime HostStarted = Process.GetCurrentProcess().StartTime.ToUniversalTime();
    private static double WatchdogSeconds = 120, PollMilliseconds = 1000;
    private static bool Fixture;

    [STAThread]
    private static int Main(string[] args)
    {
        Mutex mutex = null; bool held = false; IntPtr job = IntPtr.Zero;
        PROCESS_INFORMATION process = new PROCESS_INFORMATION();
        Dictionary<string, object> recovery = null;
        bool recoveryActive = false, workerAttempt = false;
        try
        {
            string executable = Path.GetFullPath(Process.GetCurrentProcess().MainModule.FileName);
            string productionRoot = Directory.GetParent(Path.GetDirectoryName(executable)).FullName;
            Root = productionRoot;
            if (args.Length != 0)
            {
                if (args.Length != 2 || args[0] != "--fixture-root" || !IsAbsolute(args[1])) return 20;
                Root = Path.GetFullPath(args[1]);
                if (Within(Root, productionRoot) || Within(productionRoot, Root)) return 20;
                Fixture = true;
            }
            CheckNoReparse(Root);
            Private = Path.Combine(Root, "private");
            if (!Directory.Exists(Private)) throw new InvalidDataException("private-directory-missing");
            CheckNoReparse(Private);
            RunId = Guid.NewGuid().ToString("D");
            mutex = new Mutex(false, "Local\\ClaudeSupervisorHost-" + HashText(Root.ToUpperInvariant()).Substring(0, 24));
            try { held = mutex.WaitOne(0); } catch (AbandonedMutexException) { held = true; }
            if (!held) return 0;
            Stage = "deployment-validation";
            Dictionary<string, object> deployment = ReadObject(Path.Combine(Private, "deployment.json"));
            Dictionary<string, object> reliability = Object(deployment, "Reliability");
            if (Number(reliability, "SchemaVersion") != 2) throw new InvalidDataException("schema-version-required");
            string shell = String(reliability, "ShellPath");
            if (!IsAbsolute(shell)) throw new InvalidDataException("shell-path-must-be-absolute");
            shell = Path.GetFullPath(shell);
            string scriptValue = String(reliability, "SupervisorScript");
            string script = Path.GetFullPath(Path.Combine(Root, scriptValue));
            if (!Within(script, Root) || !File.Exists(script)) throw new InvalidDataException("script-path-outside-root");
            CheckNoReparse(script); CheckNoReparse(shell);
            RequireHash(shell, String(reliability, "ShellHash"), "shell-hash-mismatch");
            RequireHash(executable, String(reliability, "HostHash"), "host-hash-mismatch");
            RequireHash(script, String(reliability, "SupervisorHash"), "script-hash-mismatch");
            if (Fixture)
            {
                // Overrides exist only in the separate fixture root; production still verifies every hash.
                Dictionary<string, object> fixture = ReadObject(Path.Combine(Private, "host-fixture.json"));
                if (String(fixture, "Kind") != "ClaudeSupervisorHostFixture") throw new InvalidDataException("fixture-marker-required");
                WatchdogSeconds = Number(fixture, "WatchdogSeconds");
                PollMilliseconds = Number(fixture, "PollMilliseconds");
                if (WatchdogSeconds < 1 || WatchdogSeconds > 120 || PollMilliseconds < 25 || PollMilliseconds > 1000)
                    throw new InvalidDataException("fixture-timing-outside-policy");
            }
            Stage = "maintenance-check";
            if (MaintenanceActive())
            {
                if (File.Exists(Path.Combine(Private, "supervisor-host-recovery.json")))
                { recovery = LoadRecovery(); ClearActive(recovery); SaveRecovery(recovery); }
                Event("MaintenanceSkipped", Data("Reason", "valid-maintenance")); return 0;
            }
            Stage = "recovery-budget";
            recovery = LoadRecovery();
            // A terminated host cannot execute finally. A persisted active run is counted on the next invocation.
            if (!System.String.IsNullOrEmpty(OptionalString(recovery, "ActiveRunId")))
                AddFailure(recovery, "previous-host-interrupted");
            DateTime nextRestart;
            if (TryDate(OptionalString(recovery, "NextRestart"), out nextRestart) && nextRestart > DateTime.UtcNow)
            {
                SaveRecovery(recovery);
                Event("BackoffSkipped", Data("NextRestart", Iso(nextRestart), "Reason", "persistent-worker-failure-budget"));
                return 21;
            }
            SaveRecovery(recovery);
            workerAttempt = true;
            Stage = "create-job";
            job = CreateJobObject(IntPtr.Zero, "Local\\ClaudeSupervisorWorker-" + RunId);
            if (job == IntPtr.Zero) ThrowNative();
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
            limits.BasicLimitInformation.LimitFlags = KILL_ON_JOB_CLOSE | SILENT_BREAKAWAY_OK;
            int size = Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
            IntPtr limitsMemory = Marshal.AllocHGlobal(size);
            try
            {
                Marshal.StructureToPtr(limits, limitsMemory, false);
                if (!SetInformationJobObject(job, 9, limitsMemory, (uint)size)) ThrowNative();
            }
            finally { Marshal.FreeHGlobal(limitsMemory); }
            Stage = "create-worker-suspended";
            string command = Quote(shell) + " -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File " + Quote(script)
                + " -RunId " + Quote(RunId) + " -HostPid " + HostPid.ToString(CultureInfo.InvariantCulture)
                + " -HostStarted " + Quote(Iso(HostStarted));
            CreateWorker(shell, command, out process);
            Stage = "assign-worker-job";
            if (!AssignProcessToJobObject(job, process.hProcess)) ThrowNative();
            DateTime workerStarted = CreationTime(process.hProcess);
            WriteAtomic(Path.Combine(Private, "supervisor-host-identity.json"), Data(
                "RunId", RunId, "HostPid", HostPid, "HostStarted", Iso(HostStarted),
                "SupervisorPid", process.dwProcessId, "SupervisorStarted", Iso(workerStarted),
                "ShellPath", shell, "ScriptPath", script));
            recovery["ActiveRunId"] = RunId; recovery["ActiveHostPid"] = HostPid; recovery["ActiveHostStarted"] = Iso(HostStarted);
            SaveRecovery(recovery); recoveryActive = true;
            Stage = "resume-worker";
            if (ResumeThread(process.hThread) == UInt32.MaxValue) ThrowNative();
            CloseHandle(process.hThread); process.hThread = IntPtr.Zero;
            Event("WorkerStarted", Data("SupervisorPid", process.dwProcessId, "SupervisorStarted", Iso(workerStarted)));
            Stopwatch progress = Stopwatch.StartNew();
            DateTime lastHealth = DateTime.MinValue;
            string lastInvalid = null;
            Stage = "watchdog";
            while (true)
            {
                if (WaitForSingleObject(process.hProcess, (uint)PollMilliseconds) == 0)
                {
                    DrainReaders();
                    uint exitCode; if (!GetExitCodeProcess(process.hProcess, out exitCode)) ThrowNative();
                    Event("WorkerExited", Data("SupervisorPid", process.dwProcessId, "ExitCode", exitCode));
                    bool maintenance = MaintenanceActive();
                    if (exitCode != 0 && !maintenance) AddFailure(recovery, "worker-exit-" + exitCode.ToString(CultureInfo.InvariantCulture));
                    else ClearActive(recovery);
                    SaveRecovery(recovery); recoveryActive = false;
                    return maintenance ? 0 : unchecked((int)exitCode);
                }
                if (MaintenanceActive())
                {
                    Event("MaintenanceStop", Data("SupervisorPid", process.dwProcessId));
                    CloseHandle(job); job = IntPtr.Zero;
                    WaitForSingleObject(process.hProcess, 5000);
                    uint exitCode; GetExitCodeProcess(process.hProcess, out exitCode);
                    Event("WorkerExited", Data("SupervisorPid", process.dwProcessId, "ExitCode", exitCode, "Reason", "maintenance"));
                    ClearActive(recovery); SaveRecovery(recovery); recoveryActive = false; return 0;
                }
                DateTime healthTime; string invalid;
                bool valid = ReadHealth(process.dwProcessId, workerStarted, out healthTime, out invalid);
                if (valid && healthTime > lastHealth)
                {
                    lastHealth = healthTime;
                    progress.Restart(); lastInvalid = null;
                }
                else if (!valid && invalid != lastInvalid)
                {
                    Event("HealthRejected", Data("Reason", invalid)); lastInvalid = invalid;
                }
                if (progress.Elapsed.TotalSeconds > WatchdogSeconds)
                {
                    Event("WatchdogExpired", Data("SupervisorPid", process.dwProcessId, "Reason", lastInvalid ?? "health-progress-stalled"));
                    CloseHandle(job); job = IntPtr.Zero;
                    WaitForSingleObject(process.hProcess, 5000);
                    uint exitCode; GetExitCodeProcess(process.hProcess, out exitCode);
                    Event("WorkerExited", Data("SupervisorPid", process.dwProcessId, "ExitCode", exitCode, "Reason", "watchdog"));
                    AddFailure(recovery, "worker-health-timeout"); SaveRecovery(recovery); recoveryActive = false;
                    return 22;
                }
            }
        }
        catch (Exception error)
        {
            // Log only a classification and numeric native error. Exception text may contain credentials.
            try
            {
                Event("HostException", Data("ExceptionType", error.GetType().FullName,
                    "NativeError", error is Win32Exception ? ((Win32Exception)error).NativeErrorCode : 0,
                    "Reason", error is InvalidDataException && Regex.IsMatch(error.Message, "^[a-z0-9-]{1,100}$") ? error.Message : "classified-host-error"));
                if ((recoveryActive || workerAttempt) && recovery != null) { AddFailure(recovery, "host-" + Stage); SaveRecovery(recovery); }
            }
            catch { }
            return Stage == "deployment-validation" || Stage == "initialization" ? 20 : 23;
        }
        finally
        {
            if (job != IntPtr.Zero) CloseHandle(job);
            // A failed job assignment leaves the suspended worker outside the job. It never gets resumed.
            if (process.hProcess != IntPtr.Zero)
            {
                if (WaitForSingleObject(process.hProcess, 0) != 0) TerminateProcess(process.hProcess, 23);
                CloseHandle(process.hProcess);
            }
            if (process.hThread != IntPtr.Zero) CloseHandle(process.hThread);
            if (held && mutex != null) mutex.ReleaseMutex();
            if (mutex != null) mutex.Dispose();
        }
    }

    private static bool ReadHealth(uint workerPid, DateTime started, out DateTime time, out string reason)
    {
        time = DateTime.MinValue; reason = "health-missing-or-unreadable";
        try
        {
            Dictionary<string, object> health = ReadObject(Path.Combine(Private, "supervisor-health.json"));
            object schema;
            if (!health.TryGetValue("SchemaVersion", out schema) || Convert.ToDouble(schema, CultureInfo.InvariantCulture) != 2)
            { reason = "health-schema-version-invalid"; return false; }
            if (String(health, "RunId") != RunId || Number(health, "SupervisorPid") != workerPid
                || Number(health, "HostPid") != HostPid) { reason = "health-identity-mismatch"; return false; }
            DateTime identity;
            if (!TryDate(String(health, "HostStarted"), out identity) || identity.Ticks != HostStarted.Ticks
                || !TryDate(String(health, "SupervisorStarted"), out identity) || Math.Abs((identity - started).TotalMilliseconds) > 1)
            { reason = "health-process-start-mismatch"; return false; }
            if (!TryDate(String(health, "Time"), out time) || time < started.AddSeconds(-1)
                || time > DateTime.UtcNow.AddSeconds(5) || (DateTime.UtcNow - time).TotalSeconds > WatchdogSeconds)
            { reason = "health-time-invalid-or-stale"; return false; }
            string status = String(health, "Status");
            if (status == "Healthy" || status == "ProbeDegraded")
            {
                DateTime safety;
                if (!TryDate(OptionalString(health, "LastSafetyCheck"), out safety) || safety > DateTime.UtcNow.AddSeconds(5)
                    || safety < started.AddSeconds(-1) || (DateTime.UtcNow - safety).TotalSeconds > 120)
                { reason = "healthy-safety-check-stale"; return false; }
                DateTime egress;
                if (!TryDate(OptionalString(health, "LastEgressCheck"), out egress) || egress > DateTime.UtcNow.AddSeconds(5)
                    || egress < started.AddSeconds(-1) || (DateTime.UtcNow - egress).TotalSeconds > 120)
                { reason = "healthy-egress-check-stale"; return false; }
            }
            return true;
        }
        catch { return false; }
    }
    private static bool MaintenanceActive()
    {
        string path = Path.Combine(Private, "maintenance.json");
        if (!File.Exists(path)) return false;
        try
        {
            DateTime until;
            return TryDate(String(ReadObject(path), "Until"), out until) && until > DateTime.UtcNow && until < DateTime.UtcNow.AddMinutes(10);
        }
        catch { return false; }
    }
    private static Dictionary<string, object> LoadRecovery()
    {
        string path = Path.Combine(Private, "supervisor-host-recovery.json");
        Dictionary<string, object> result = File.Exists(path) ? ReadObject(path) : Data("FailureTimes", new object[0], "NextRestart", null, "Reason", null);
        List<string> failures = new List<string>();
        object values; DateTime date;
        if (result.TryGetValue("FailureTimes", out values) && values is IEnumerable)
            foreach (object value in (IEnumerable)values)
            {
                if (!TryDate(Convert.ToString(value, CultureInfo.InvariantCulture), out date)) throw new InvalidDataException("recovery-time-invalid");
                if (date > DateTime.UtcNow.AddSeconds(5)) throw new InvalidDataException("recovery-time-in-future");
                if (date >= DateTime.UtcNow.AddMinutes(-5)) failures.Add(Iso(date));
            }
        else throw new InvalidDataException("recovery-failures-invalid");
        result["FailureTimes"] = failures.ToArray();
        string next = OptionalString(result, "NextRestart");
        if (next != null && !TryDate(next, out date)) throw new InvalidDataException("recovery-restart-invalid");
        return result;
    }
    private static void ClearActive(Dictionary<string, object> recovery)
    {
        recovery["ActiveRunId"] = null; recovery["ActiveHostPid"] = null; recovery["ActiveHostStarted"] = null;
    }
    private static void AddFailure(Dictionary<string, object> recovery, string reason)
    {
        List<string> failures = new List<string>(); object values;
        if (recovery.TryGetValue("FailureTimes", out values) && values is IEnumerable)
            foreach (object value in (IEnumerable)values)
            {
                DateTime date;
                if (TryDate(Convert.ToString(value, CultureInfo.InvariantCulture), out date) && date >= DateTime.UtcNow.AddMinutes(-5)) failures.Add(Iso(date));
            }
        failures.Add(Iso(DateTime.UtcNow));
        recovery["FailureTimes"] = failures.ToArray(); recovery["Reason"] = reason;
        if (failures.Count >= 3) recovery["NextRestart"] = Iso(DateTime.UtcNow.AddMinutes(5));
        ClearActive(recovery);
        Event("WorkerFailureRecorded", Data("Reason", reason, "FailureCount", failures.Count, "NextRestart", recovery["NextRestart"]));
    }
    private static void SaveRecovery(Dictionary<string, object> recovery)
    { WriteAtomic(Path.Combine(Private, "supervisor-host-recovery.json"), recovery); }
    private static void Event(string kind, Dictionary<string, object> data)
    {
        if (Private == null || !Directory.Exists(Private)) return;
        AppendLog(Path.Combine(Private, "host-events.jsonl"), Serialize(Data("Time", Iso(DateTime.UtcNow),
            "RunId", RunId, "HostPid", HostPid, "Stage", Stage, "Kind", kind, "Data", data)));
    }
    private static void AppendLog(string path, string line)
    {
        lock (LogLock)
        {
            if (File.Exists(path) && new FileInfo(path).Length + Encoding.UTF8.GetByteCount(line) + 2 > LogLimit)
            {
                if (File.Exists(path + ".previous")) File.Delete(path + ".previous");
                File.Move(path, path + ".previous");
            }
            File.AppendAllText(path, line + Environment.NewLine, new UTF8Encoding(false));
        }
    }
    private static string Redact(string value)
    {
        // Drop entire secret-bearing output lines; redact userinfo URLs and recognizable bearer tokens.
        if (Regex.IsMatch(value, "(?i)(password|passwd|authorization|api[_-]?key|token|secret|credential)[\"']?\\s*[:=]")) return "[sensitive worker output redacted]";
        value = Regex.Replace(value, @"(?i)(https?|socks5?)://[^\s/@]+:[^\s/@]+@", "$1://[redacted]@");
        value = Regex.Replace(value, @"(?i)\bBearer\s+\S+", "Bearer [redacted]");
        value = Regex.Replace(value, @"\bsk-[A-Za-z0-9_-]{8,}\b", "[redacted token]");
        return value;
    }
    private static void StartReader(IntPtr read, string name)
    {
        Thread thread = new Thread(delegate()
        {
            try
            {
                using (FileStream stream = new FileStream(new SafeFileHandle(read, true), FileAccess.Read))
                using (StreamReader reader = new StreamReader(stream, Encoding.UTF8, true))
                {
                    // Bounded chunks also prevent unlimited allocation from output without newlines.
                    StringBuilder line = new StringBuilder(); bool oversized = false; int next;
                    while ((next = reader.Read()) >= 0)
                    {
                        if (next == '\n')
                        {
                            AppendLog(Path.Combine(Private, "supervisor-worker-" + name + ".log"),
                                oversized ? "[oversized worker output omitted]" : Redact(line.ToString().TrimEnd('\r')));
                            line.Length = 0; oversized = false;
                        }
                        else if (line.Length < 4096 && !oversized) line.Append((char)next);
                        else { oversized = true; line.Length = 0; }
                    }
                    if (line.Length != 0 || oversized)
                        AppendLog(Path.Combine(Private, "supervisor-worker-" + name + ".log"), oversized ? "[oversized worker output omitted]" : Redact(line.ToString()));
                }
            }
            catch { /* Closing a killed worker can close its pipe. No secret exception text is logged. */ }
        });
        thread.IsBackground = true; Readers.Add(thread); thread.Start();
    }
    private static void DrainReaders() { foreach (Thread reader in Readers) reader.Join(250); }
    private static void CreateWorker(string shell, string command, out PROCESS_INFORMATION process)
    {
        IntPtr stdoutRead = IntPtr.Zero, stdoutWrite = IntPtr.Zero, stderrRead = IntPtr.Zero, stderrWrite = IntPtr.Zero, input = IntPtr.Zero;
        process = new PROCESS_INFORMATION(); bool created = false;
        SECURITY_ATTRIBUTES security = new SECURITY_ATTRIBUTES(); security.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES)); security.bInheritHandle = true;
        try
        {
            if (!CreatePipe(out stdoutRead, out stdoutWrite, ref security, 0) || !CreatePipe(out stderrRead, out stderrWrite, ref security, 0)) ThrowNative();
            if (!SetHandleInformation(stdoutRead, 1, 0) || !SetHandleInformation(stderrRead, 1, 0)) ThrowNative();
            input = CreateFile("NUL", 0x80000000, 3, ref security, 3, 0, IntPtr.Zero);
            if (input == new IntPtr(-1)) ThrowNative();
            STARTUPINFO startup = new STARTUPINFO(); startup.cb = Marshal.SizeOf(typeof(STARTUPINFO));
            startup.dwFlags = 0x100; startup.hStdInput = input; startup.hStdOutput = stdoutWrite; startup.hStdError = stderrWrite;
            if (!CreateProcess(shell, new StringBuilder(command), IntPtr.Zero, IntPtr.Zero, true,
                CREATE_SUSPENDED | CREATE_NO_WINDOW, IntPtr.Zero, Root, ref startup, out process)) ThrowNative();
            created = true;
            StartReader(stdoutRead, "stdout"); stdoutRead = IntPtr.Zero;
            StartReader(stderrRead, "stderr"); stderrRead = IntPtr.Zero;
        }
        finally
        {
            if (stdoutWrite != IntPtr.Zero) CloseHandle(stdoutWrite);
            if (stderrWrite != IntPtr.Zero) CloseHandle(stderrWrite);
            if (stdoutRead != IntPtr.Zero) CloseHandle(stdoutRead);
            if (stderrRead != IntPtr.Zero) CloseHandle(stderrRead);
            if (input != IntPtr.Zero && input != new IntPtr(-1)) CloseHandle(input);
            if (!created) process = new PROCESS_INFORMATION();
        }
    }
    private static void WriteAtomic(string path, object value)
    {
        string temp = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            File.WriteAllText(temp, Serialize(value), new UTF8Encoding(false));
            if (File.Exists(path)) File.Replace(temp, path, null); else File.Move(temp, path);
        }
        finally { if (File.Exists(temp)) File.Delete(temp); }
    }
    private static string Serialize(object value) { lock (Json) return Json.Serialize(value); }
    private static Dictionary<string, object> ReadObject(string path)
    {
        using (FileStream stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
        using (StreamReader reader = new StreamReader(stream, Encoding.UTF8, true))
        { lock (Json) return Json.Deserialize<Dictionary<string, object>>(reader.ReadToEnd()); }
    }
    private static Dictionary<string, object> Data(params object[] entries)
    {
        Dictionary<string, object> result = new Dictionary<string, object>();
        for (int i = 0; i < entries.Length; i += 2) result.Add((string)entries[i], entries[i + 1]);
        return result;
    }
    private static Dictionary<string, object> Object(Dictionary<string, object> value, string key) { return (Dictionary<string, object>)value[key]; }
    private static string String(Dictionary<string, object> value, string key)
    { string result = OptionalString(value, key); if (System.String.IsNullOrEmpty(result)) throw new InvalidDataException("required-value-missing"); return result; }
    private static string OptionalString(Dictionary<string, object> value, string key)
    { object result; return value.TryGetValue(key, out result) && result != null ? Convert.ToString(result, CultureInfo.InvariantCulture) : null; }
    private static double Number(Dictionary<string, object> value, string key) { return Convert.ToDouble(value[key], CultureInfo.InvariantCulture); }
    private static string Iso(DateTime value) { return value.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture); }
    private static bool TryDate(string value, out DateTime date)
    {
        date = DateTime.MinValue;
        return value != null && Regex.IsMatch(value, @"T.*(?:Z|[+-]\d{2}:\d{2})$")
            && DateTime.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out date)
            && (date = date.ToUniversalTime()) != DateTime.MinValue;
    }
    private static bool IsAbsolute(string path)
    {
        return !System.String.IsNullOrEmpty(path) && !path.StartsWith("\\\\?\\", StringComparison.Ordinal)
            && !path.StartsWith("\\\\.\\", StringComparison.Ordinal)
            && (Regex.IsMatch(path, @"^[A-Za-z]:[\\/]") || Regex.IsMatch(path, @"^\\\\[^\\]+\\[^\\]+(?:\\|$)"));
    }
    private static bool Within(string path, string root)
    {
        path = Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar);
        root = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar);
        return path.Equals(root, StringComparison.OrdinalIgnoreCase) || path.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }
    private static void CheckNoReparse(string path)
    {
        string current = Path.GetFullPath(path);
        while (current != null)
        {
            if ((File.Exists(current) || Directory.Exists(current)) && (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("reparse-point-rejected");
            DirectoryInfo parent = Directory.GetParent(current); current = parent == null ? null : parent.FullName;
        }
    }
    private static void RequireHash(string path, string expected, string reason)
    {
        if (!Regex.IsMatch(expected, "^[A-Fa-f0-9]{64}$") || !HashFile(path).Equals(expected, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException(reason);
    }
    private static string HashFile(string path) { using (SHA256 hash = SHA256.Create()) using (FileStream stream = File.OpenRead(path)) return Hex(hash.ComputeHash(stream)); }
    private static string HashText(string value) { using (SHA256 hash = SHA256.Create()) return Hex(hash.ComputeHash(Encoding.UTF8.GetBytes(value))); }
    private static string Hex(byte[] value) { return BitConverter.ToString(value).Replace("-", ""); }
    private static string Quote(string value) { return "\"" + value.Replace("\\\"", "\\\\\"").Replace("\"", "\\\"") + "\""; }
    private static void ThrowNative() { throw new Win32Exception(Marshal.GetLastWin32Error()); }
    private static DateTime CreationTime(IntPtr process)
    {
        long creation, exit, kernel, user;
        if (!GetProcessTimes(process, out creation, out exit, out kernel, out user)) ThrowNative();
        return DateTime.FromFileTimeUtc(creation);
    }
    [StructLayout(LayoutKind.Sequential)] private struct SECURITY_ATTRIBUTES { public int nLength; public IntPtr lpSecurityDescriptor; [MarshalAs(UnmanagedType.Bool)] public bool bInheritHandle; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] private struct STARTUPINFO
    { public int cb; public string lpReserved, lpDesktop, lpTitle; public uint dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags; public short wShowWindow, cbReserved2; public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError; }
    [StructLayout(LayoutKind.Sequential)] private struct PROCESS_INFORMATION { public IntPtr hProcess, hThread; public uint dwProcessId, dwThreadId; }
    [StructLayout(LayoutKind.Sequential)] private struct JOBOBJECT_BASIC_LIMIT_INFORMATION
    { public long PerProcessUserTimeLimit, PerJobUserTimeLimit; public uint LimitFlags; public UIntPtr MinimumWorkingSetSize, MaximumWorkingSetSize; public uint ActiveProcessLimit; public UIntPtr Affinity; public uint PriorityClass, SchedulingClass; }
    [StructLayout(LayoutKind.Sequential)] private struct IO_COUNTERS { public ulong ReadOperationCount, WriteOperationCount, OtherOperationCount, ReadTransferCount, WriteTransferCount, OtherTransferCount; }
    [StructLayout(LayoutKind.Sequential)] private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
    { public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation; public IO_COUNTERS IoInfo; public UIntPtr ProcessMemoryLimit, JobMemoryLimit, PeakProcessMemoryUsed, PeakJobMemoryUsed; }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool CreateProcess(string application, StringBuilder command, IntPtr processAttributes, IntPtr threadAttributes, bool inherit, uint flags, IntPtr environment, string directory, ref STARTUPINFO startup, out PROCESS_INFORMATION process);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool CreatePipe(out IntPtr read, out IntPtr write, ref SECURITY_ATTRIBUTES security, uint size);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool SetHandleInformation(IntPtr handle, uint mask, uint flags);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern IntPtr CreateFile(string file, uint access, uint sharing, ref SECURITY_ATTRIBUTES security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern IntPtr CreateJobObject(IntPtr attributes, string name);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool SetInformationJobObject(IntPtr job, int infoClass, IntPtr info, uint length);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GetExitCodeProcess(IntPtr process, out uint code);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool TerminateProcess(IntPtr process, uint code);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GetProcessTimes(IntPtr process, out long creation, out long exit, out long kernel, out long user);
}
