"""Read only approved Claude processes; emit comparisons, never credentials."""
import ctypes
from ctypes import wintypes as w
import argparse
import json
import os
import pathlib
import threading
from urllib.parse import urlsplit

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('pid', type=int)
parser.add_argument('--timeout-seconds', type=float, default=10.0,
                    help='Read deadline, at most 10 seconds; timeout exits 124 without evidence.')
args = parser.parse_args()
if not 0 < args.timeout_seconds <= 10:
    parser.error('timeout-seconds must be greater than zero and at most 10')
# A daemon watchdog also bounds native calls that cannot be cancelled by Python.
# It exits only this reader and emits no partial environment or credentials.
watchdog = threading.Timer(args.timeout_seconds, lambda: os._exit(124))
watchdog.daemon = True
watchdog.start()
root = pathlib.Path(__file__).resolve().parent
state = json.loads((root / 'private' / 'deployment.json').read_text(encoding='utf-8-sig'))
pid = args.pid
k = ctypes.WinDLL('kernel32', use_last_error=True)
nt = ctypes.WinDLL('ntdll')
k.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
k.OpenProcess.restype = w.HANDLE
k.CloseHandle.argtypes = [w.HANDLE]
k.QueryFullProcessImageNameW.argtypes = [w.HANDLE, w.DWORD, w.LPWSTR, ctypes.POINTER(w.DWORD)]
k.ReadProcessMemory.argtypes = [w.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]

class BasicInfo(ctypes.Structure):
    _fields_ = [('exit', w.LONG), ('peb', ctypes.c_void_p), ('affinity', ctypes.c_size_t),
                ('priority', w.LONG), ('pid', ctypes.c_size_t), ('parent', ctypes.c_size_t)]

nt.NtQueryInformationProcess.argtypes = [w.HANDLE, w.ULONG, ctypes.c_void_p, w.ULONG, ctypes.POINTER(w.ULONG)]
nt.NtQueryInformationProcess.restype = w.LONG
h = k.OpenProcess(0x410, False, pid)
if not h:
    raise OSError('Approved process cannot be opened for read-only evidence.')

def read(address, size):
    buf = ctypes.create_string_buffer(size)
    count = ctypes.c_size_t()
    if not k.ReadProcessMemory(h, address, buf, size, ctypes.byref(count)):
        raise OSError('Process environment evidence unavailable.')
    return buf.raw[:count.value]

try:
    image = ctypes.create_unicode_buffer(32768)
    length = w.DWORD(len(image))
    if not k.QueryFullProcessImageNameW(h, 0, image, ctypes.byref(length)):
        raise OSError('Process path could not be verified.')
    approved = [state['Desktop']['Path']] + state['CodePaths']
    if image.value.casefold() not in [p.casefold() for p in approved]:
        raise ValueError('Refusing environment read outside approved Claude paths.')
    pbi = BasicInfo()
    returned = w.ULONG()
    if nt.NtQueryInformationProcess(h, 0, ctypes.byref(pbi), ctypes.sizeof(pbi), ctypes.byref(returned)) != 0:
        raise OSError('Process basic information unavailable.')
    params = int.from_bytes(read(pbi.peb + 0x20, 8), 'little')
    address = int.from_bytes(read(params + 0x80, 8), 'little')
    data = bytearray()
    for offset in range(0, 1024 * 1024, 256):
        data.extend(read(address + offset, 256))
        text = data.decode('utf-16-le', errors='replace')
        if '\0\0' in text:
            text = text.split('\0\0', 1)[0]
            break
    else:
        raise ValueError('Environment terminator was not found.')
    env = {}
    for item in text.split('\0'):
        if '=' in item and not item.startswith('='):
            key, value = item.split('=', 1)
            env[key.upper()] = value
    overrides = ['ANTHROPIC_BASE_URL', 'ANTHROPIC_MODEL', 'CLAUDE_CODE_USE_BEDROCK',
                 'CLAUDE_CODE_USE_VERTEX', 'CLAUDE_CODE_USE_FOUNDRY']
    base_url = urlsplit(env.get('ANTHROPIC_BASE_URL', ''))
    base_host = (base_url.hostname or '').casefold()
    official_base = (base_url.scheme == 'https' and base_host == 'api.anthropic.com'
                     and base_url.port in (None, 443) and not base_url.username and not base_url.password)
    print(json.dumps({
        'Pid': pid, 'ApprovedPath': True,
        'ConfigDirMatches': env.get('CLAUDE_CONFIG_DIR', '').casefold() == state['ConfigDir'].casefold(),
        'HttpProxyMatches': env.get('HTTP_PROXY') == state['ProxyUrl'],
        'HttpsProxyMatches': env.get('HTTPS_PROXY') == state['ProxyUrl'],
        'AllProxyMatches': env.get('ALL_PROXY') == state['ProxyUrl'],
        'NoProxyOnlyLoopback': set(env.get('NO_PROXY', '').split(',')) == {'localhost', '127.0.0.1', '::1'},
        'ProviderOverrideNames': [key for key in overrides if env.get(key)],
        'BaseUrlHost': base_host,
        'BaseUrlIsOfficialAnthropicApi': official_base,
        'UnexpectedProviderOverrideNames': [key for key in overrides if env.get(key)
                                           and not (key == 'ANTHROPIC_BASE_URL' and official_base)],
        'AutoUpdaterDisabled': env.get('DISABLE_AUTOUPDATER') == '1',
        'TlsVerificationEnabled': env.get('NODE_TLS_REJECT_UNAUTHORIZED') != '0',
        'UnexpectedTlsOverrideNames': [key for key in ['NODE_EXTRA_CA_CERTS', 'SSL_CERT_FILE',
                                     'SSL_CERT_DIR', 'CURL_CA_BUNDLE', 'REQUESTS_CA_BUNDLE'] if env.get(key)],
    }))
finally:
    k.CloseHandle(h)
    watchdog.cancel()
