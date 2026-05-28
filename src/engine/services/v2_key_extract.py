"""Extract V2 image AES keys from WeChat (Weixin.exe) process memory.

WeChat 4.x V2 format uses per-image AES-128-ECB keys that are ONLY stored
in process memory while images are being viewed. They are never persisted to disk.

WeChat stores these keys as 32-character hex strings in memory (bounded by
non-alphanumeric characters). This module uses regex scanning to find them —
the same approach used by ZedeX/weixin-decrypte-script.

Key verification: a correct key decrypts the first AES block into a valid
image header (JPEG: FF D8 FF, PNG: 89 50 4E 47, GIF: 47 49 46 38, etc.).

Usage:
    from engine.services.v2_key_extract import find_keys_for_files, is_wechat_running
    found = find_keys_for_files(decrypted_dir, wxid, [md5_val])
"""

import ctypes
import ctypes.wintypes as wt
import os
import re
import sqlite3
import struct
import sys

kernel32 = ctypes.windll.kernel32

# ---------------------------------------------------------------------------
# Win32 helpers
# ---------------------------------------------------------------------------

MEM_COMMIT = 0x1000
PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80

_RW_FLAGS = (PAGE_READWRITE | PAGE_WRITECOPY |
             PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)

# Regex: 32 alphanumeric chars bounded by non-alphanumeric chars
# (same as ZedeX/weixin-decrypte-script RE_KEY32)
_RE_KEY32 = re.compile(rb'(?<![a-zA-Z0-9])[a-zA-Z0-9]{32}(?![a-zA-Z0-9])')
_RE_KEY16 = re.compile(rb'(?<![a-zA-Z0-9])[a-zA-Z0-9]{16}(?![a-zA-Z0-9])')


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wt.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wt.DWORD),
        ("Protect", wt.DWORD),
        ("Type", wt.DWORD),
    ]


def _get_wechat_pids():
    """Return list of Weixin.exe PIDs."""
    import subprocess
    try:
        result = subprocess.run(
            ['tasklist.exe', '/FI', 'IMAGENAME eq Weixin.exe', '/FO', 'CSV', '/NH'],
            capture_output=True, text=True, timeout=10
        )
        pids = []
        for line in result.stdout.strip().split('\n'):
            if 'Weixin.exe' in line:
                parts = line.strip('"').split('","')
                if len(parts) >= 2:
                    try:
                        pids.append(int(parts[1]))
                    except ValueError:
                        pass
        return pids
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Image verification (same as ZedeX try_key)
# ---------------------------------------------------------------------------

def _is_valid_image_header(first_bytes):
    """Check if decrypted data starts with a known image header (strong check)."""
    if len(first_bytes) < 8:
        return False

    # JPEG: FF D8 FF
    if first_bytes[:3] == b'\xff\xd8\xff':
        return True

    # PNG: 89 50 4E 47 0D 0A 1A 0A
    if first_bytes[:8] == b'\x89PNG\r\n\x1a\n':
        return True

    # GIF: 47 49 46 38 (37 61 | 39 61)
    if first_bytes[:6] in (b'GIF87a', b'GIF89a'):
        return True

    # WebP: 52 49 46 46 ... 57 45 42 50
    if first_bytes[:4] == b'RIFF' and len(first_bytes) >= 12 and first_bytes[8:12] == b'WEBP':
        return True

    # WeChat WxGF: 77 78 67 66
    if first_bytes[:4] == b'wxgf':
        return True

    return False


def _try_key(key_bytes, ciphertext):
    """Test a key candidate against ciphertext (same algorithm as ZedeX).

    Args:
        key_bytes: raw bytes from memory (ASCII string)
        ciphertext: 32 bytes of AES ciphertext from file

    Returns:
        Image format string ('JPEG', 'PNG', etc.) or None.
    """
    try:
        from Crypto.Cipher import AES
    except ImportError:
        return None

    try:
        # ZedeX uses the full key_bytes directly (32 bytes → AES-256)
        cipher = AES.new(key_bytes, AES.MODE_ECB)
        decrypted = cipher.decrypt(ciphertext[:16])
    except Exception:
        return None

    if _is_valid_image_header(decrypted):
        if decrypted[:3] == b'\xff\xd8\xff':
            return 'JPEG'
        if decrypted[:4] == b'\x89PNG':
            return 'PNG'
        if decrypted[:4] == b'RIFF':
            return 'WEBP'
        if decrypted[:4] == b'wxgf':
            return 'WXGF'
        if decrypted[:3] == b'GIF':
            return 'GIF'
    return None


# ---------------------------------------------------------------------------
# HardLink path resolution (inline, same as media.py)
# ---------------------------------------------------------------------------

def _get_base_storage(decrypted_dir):
    """Get WeChat file storage root from hardlink.db db_info."""
    hardlink_db = os.path.join(decrypted_dir, "hardlink", "hardlink.db")
    if not os.path.isfile(hardlink_db):
        return None
    try:
        conn = sqlite3.connect(hardlink_db)
        row = conn.execute("SELECT ValueStdStr FROM db_info WHERE Key='uuid'").fetchone()
        conn.close()
        if row and row[0]:
            parts = str(row[0]).split('_', 2)
            if len(parts) >= 3:
                storage_path = parts[-1]
                if os.path.isdir(storage_path):
                    return storage_path
    except sqlite3.Error:
        pass
    return None


def _resolve_hardlink_path(decrypted_dir, media_info, wxid):
    """Resolve a media md5 to an absolute file path.

    Tries both the md5 column (CDN md5) and file_name LIKE match (file md5)
    since the hardlink DB's md5 column stores CDN md5, not the local file's md5.
    """
    if not media_info:
        return None
    md5 = media_info.get('md5', '')
    if not md5 or len(md5) != 32:
        return None

    hardlink_db = os.path.join(decrypted_dir, "hardlink", "hardlink.db")
    if not os.path.isfile(hardlink_db):
        return None

    try:
        conn = sqlite3.connect(hardlink_db)
        # First try direct md5 match (works when md5 is the CDN md5 from XML)
        row = conn.execute(
            "SELECT file_name, dir1, dir2 FROM image_hardlink_info_v4 WHERE md5=?",
            (md5,)
        ).fetchone()
        # If direct match fails, try file_name LIKE (file md5 is the .dat file name prefix)
        if not row:
            row = conn.execute(
                "SELECT file_name, dir1, dir2 FROM image_hardlink_info_v4 "
                "WHERE file_name LIKE ? LIMIT 1",
                (md5 + '%',)
            ).fetchone()
        if not row:
            conn.close()
            return None

        file_name, dir1, dir2 = row
        d2 = conn.execute("SELECT username FROM dir2id WHERE rowid=?", (dir2,)).fetchone()
        dir2_name = d2[0] if d2 else None
        d1 = conn.execute("SELECT username FROM dir2id WHERE rowid=?", (dir1,)).fetchone()
        dir1_name = d1[0] if d1 else None
        conn.close()

        if dir1_name and dir2_name:
            rel_path = f'msg/attach/{dir1_name}/{dir2_name}/Img/{file_name}'
            rel_path = rel_path.replace('/', os.sep)
            base = _get_base_storage(decrypted_dir) or 'D:\\xwechat_files'
            for sr in [base, 'D:\\xwechat_files', 'C:\\xwechat_files']:
                if os.path.isdir(sr) and wxid:
                    candidate = os.path.join(sr, wxid, rel_path)
                    if os.path.isfile(candidate):
                        return candidate
    except sqlite3.Error:
        pass
    return None


# ---------------------------------------------------------------------------
# Memory scanning
# ---------------------------------------------------------------------------

def _scan_memory_for_aes_keys(h_process, ciphertext, print_fn=None):
    """Scan process memory for AES keys using regex (ZedeX algorithm).

    Searches for 32-char and 16-char alphanumeric strings in readable
    committed memory regions, testing each as an AES key.

    Args:
        h_process: OpenProcess handle
        ciphertext: 16 bytes of AES ciphertext from the file
        print_fn: optional logging function

    Returns:
        First 16 chars of the found key string, or None
    """
    import time
    if print_fn is None:
        print_fn = lambda *args, **kwargs: None

    # Enumerate regions
    mbi = MEMORY_BASIC_INFORMATION()
    all_regions = []
    rw_regions = []

    address = 0
    while address < 0x7FFFFFFFFFFF:
        result = kernel32.VirtualQueryEx(
            h_process, ctypes.c_void_p(address),
            ctypes.byref(mbi), ctypes.sizeof(mbi)
        )
        if result == 0:
            break
        if (mbi.State == MEM_COMMIT and
            mbi.Protect != PAGE_NOACCESS and
            (mbi.Protect & PAGE_GUARD) == 0 and
            mbi.RegionSize <= 50 * 1024 * 1024):
            region = (mbi.BaseAddress, mbi.RegionSize, mbi.Protect)
            all_regions.append(region)
            if (mbi.Protect & _RW_FLAGS) != 0:
                rw_regions.append(region)
        next_addr = address + mbi.RegionSize
        if next_addr <= address:
            break
        address = next_addr

    rw_mb = sum(r[1] for r in rw_regions) / 1024 / 1024
    all_mb = sum(r[1] for r in all_regions) / 1024 / 1024
    print_fn(f"[v2_key] RW: {len(rw_regions)} regions ({rw_mb:.0f}MB), "
             f"Total: {len(all_regions)} ({all_mb:.0f}MB)")

    # Phase 1: scan RW regions first (more likely to contain keys)
    for phase_name, regions in [("Phase 1 (RW)", rw_regions),
                                 ("Phase 2 (all)", all_regions)]:
        if phase_name == "Phase 2 (all)":
            rw_set = set((r[0], r[1]) for r in rw_regions)
            regions = [r for r in all_regions if (r[0], r[1]) not in rw_set]

        candidates_32 = 0
        candidates_16 = 0
        t0 = time.time()

        for idx, (base_addr, region_size, _protect) in enumerate(regions):
            if idx % 200 == 0:
                elapsed = time.time() - t0
                print_fn(f"  [{phase_name}] {idx}/{len(regions)} ({elapsed:.1f}s, "
                         f"32c:{candidates_32} 16c:{candidates_16})",
                         end='', flush=True)

            buf = ctypes.create_string_buffer(region_size)
            bytes_read = ctypes.c_size_t(0)
            ok = kernel32.ReadProcessMemory(
                h_process, ctypes.c_void_p(base_addr),
                buf, region_size, ctypes.byref(bytes_read)
            )
            if not ok or bytes_read.value < 32:
                continue
            data = buf.raw[:bytes_read.value]

            # Search for 32-char hex strings
            for m in _RE_KEY32.finditer(data):
                key_bytes = m.group()
                candidates_32 += 1

                # Try multiple key formats (WeChat may store keys differently):
                # 1. Raw ASCII (first 16 bytes) -> AES-128
                fmt = _try_key(key_bytes[:16], ciphertext)
                if fmt:
                    key_str = key_bytes.decode('ascii')
                    print_fn(f"\n[v2_key] Found AES key (32-char ASCII-AES128)! -> {fmt}")
                    print_fn(f"  Full: {key_str}")
                    return key_str

                # 2. Raw ASCII (full 32 bytes) -> AES-256 (ZedeX approach)
                fmt = _try_key(key_bytes, ciphertext)
                if fmt:
                    key_str = key_bytes.decode('ascii')
                    print_fn(f"\n[v2_key] Found AES key (32-char ASCII-AES256)! -> {fmt}")
                    print_fn(f"  Full: {key_str}")
                    return key_str

                # 3. Hex-decoded -> AES-128 (most likely correct format)
                try:
                    decoded = bytes.fromhex(key_bytes.decode('ascii'))
                    fmt = _try_key(decoded, ciphertext)
                    if fmt:
                        key_str = key_bytes.decode('ascii')
                        print_fn(f"\n[v2_key] Found AES key (32-char hex-decoded)! -> {fmt}")
                        print_fn(f"  Full: {key_str}")
                        return key_str
                except ValueError:
                    pass

            # Search for 16-char strings
            for m in _RE_KEY16.finditer(data):
                key_bytes = m.group()
                candidates_16 += 1

                # Try raw ASCII -> AES-128
                fmt = _try_key(key_bytes, ciphertext)
                if fmt:
                    key_str = key_bytes.decode('ascii')
                    print_fn(f"\n[v2_key] Found AES key (16-char ASCII)! -> {fmt}")
                    print_fn(f"  Key: {key_str}")
                    return key_str

                # Try hex-decoded (e.g., "a1b2c3d4e5f6a7b8" -> 8 bytes, too short for AES
                # but the original 16 ASCII chars could be half a 32-char key)
                try:
                    key_str = key_bytes.decode('ascii')
                    if all(c in '0123456789abcdefABCDEF' for c in key_str):
                        decoded = bytes.fromhex(key_str)
                        if len(decoded) == 16:  # 32 hex chars -> 16 bytes
                            fmt = _try_key(decoded, ciphertext)
                            if fmt:
                                print_fn(f"\n[v2_key] Found AES key (hex-decoded from 32-char)! -> {fmt}")
                                return key_str
                except ValueError:
                    pass

        elapsed = time.time() - t0
        total = candidates_32 + candidates_16
        print_fn(f"\n  [{phase_name}] Done: {total} candidates ({elapsed:.1f}s)")

    return None


def _scan_near_v2_headers(h_process, ciphertext, print_fn=None):
    """Scan memory near V2 header patterns for AES keys (raw binary or ASCII hex).

    wx_key's analysis reveals that WeChat stores the V2 AES key as raw bytes in
    memory near the V2 header. The previous printable-ASCII-only filter was
    discarding genuine raw-binary keys. This version uses a sliding 16-byte
    window over a 512-byte buffer around each V2 header and tests every
    candidate — no character-set filtering.

    Also tests hex-decoded interpretation: if the 16-byte window looks like
    printable hex, we hex-decode to 16 raw bytes (32 hex → 16 bytes) and test
    that too, covering the case where WeChat stores hex-encoded keys in memory.

    Strategy (ordered by likelihood, from wx_key analysis):
      1. Raw 16-byte windows near V2 headers (step=4 for speed)
      2. Hex-decoded windows (32-char hex → 16 raw bytes)
      3. Full 32-byte windows near V2 headers (step=8)

    Returns:
        Key bytes (16 raw bytes), or None
    """
    import time
    if print_fn is None:
        print_fn = lambda *args, **kwargs: None

    V2_MAGIC = b'\x07\x08\x56\x32\x08\x07'
    WINDOW_HALF = 256
    t0 = time.time()

    # Find all V2 magic occurrences in committed readable memory
    mbi = MEMORY_BASIC_INFORMATION()
    v2_addrs = []
    address = 0
    while address < 0x7FFFFFFFFFFF:
        result = kernel32.VirtualQueryEx(
            h_process, ctypes.c_void_p(address),
            ctypes.byref(mbi), ctypes.sizeof(mbi)
        )
        if result == 0:
            break
        if (mbi.State == MEM_COMMIT and
            mbi.Protect != PAGE_NOACCESS and
            (mbi.Protect & PAGE_GUARD) == 0 and
            0 < mbi.RegionSize <= 50 * 1024 * 1024):
            region_base = ctypes.cast(mbi.BaseAddress, ctypes.c_void_p).value
            if region_base is None:
                next_addr = address + mbi.RegionSize
                address = next_addr
                continue
            region_size = mbi.RegionSize
            try:
                buf = ctypes.create_string_buffer(region_size)
            except (OverflowError, MemoryError):
                next_addr = address + mbi.RegionSize
                address = next_addr
                continue
            bytes_read = ctypes.c_size_t(0)
            ok = kernel32.ReadProcessMemory(
                h_process, ctypes.c_void_p(region_base),
                buf, region_size, ctypes.byref(bytes_read)
            )
            if ok and bytes_read.value > 0:
                data = buf.raw[:bytes_read.value]
                idx = data.find(V2_MAGIC)
                while idx != -1:
                    v2_addrs.append(region_base + idx)
                    idx = data.find(V2_MAGIC, idx + 1)
        next_addr = address + mbi.RegionSize
        if next_addr <= address:
            break
        address = next_addr

    elapsed = time.time() - t0
    print_fn(f"[v2_key:headers] Found {len(v2_addrs)} V2 header matches in {elapsed:.1f}s")

    if not v2_addrs:
        return None

    # For each V2 header, read the full ±256 byte buffer once,
    # then slide a 16-byte window across it testing every candidate.
    tested_16 = 0
    tested_32 = 0
    tested_hex = 0

    for addr in v2_addrs:
        buf_start = addr - WINDOW_HALF
        buf_size = WINDOW_HALF * 2
        try:
            buf = ctypes.create_string_buffer(buf_size)
        except (OverflowError, MemoryError):
            continue
        bytes_read = ctypes.c_size_t(0)
        ok = kernel32.ReadProcessMemory(
            h_process, ctypes.c_void_p(buf_start),
            buf, buf_size, ctypes.byref(bytes_read)
        )
        if not ok or bytes_read.value < 16:
            continue
        data = buf.raw[:bytes_read.value]

        # Pass 1: raw 16-byte sliding window, step=4
        for i in range(0, len(data) - 16, 4):
            candidate = data[i:i + 16]
            tested_16 += 1
            fmt = _try_key(candidate, ciphertext)
            if fmt:
                print_fn(f"\n[v2_key:headers] Found raw AES key! -> {fmt}")
                print_fn(f"  Key (hex): {candidate.hex()}")
                return candidate

        # Pass 2: hex-decoded interpretation
        # If a 32-byte window looks like ASCII hex, decode to 16 raw bytes
        for i in range(0, len(data) - 32, 16):
            chunk = data[i:i + 32]
            try:
                hex_str = chunk.decode('ascii')
            except UnicodeDecodeError:
                continue
            if not all(c in '0123456789abcdefABCDEF' for c in hex_str):
                continue
            try:
                decoded = bytes.fromhex(hex_str)
            except ValueError:
                continue
            tested_hex += 1
            fmt = _try_key(decoded, ciphertext)
            if fmt:
                print_fn(f"\n[v2_key:headers] Found hex-encoded AES key! -> {fmt}")
                print_fn(f"  Key (hex): {decoded.hex()}")
                return decoded

        # Pass 3: raw 32-byte sliding window, step=8
        # (wx_key captures 32 raw bytes — the first 16 may be the AES key)
        for i in range(0, len(data) - 32, 8):
            candidate32 = data[i:i + 32]
            tested_32 += 1
            fmt = _try_key(candidate32[:16], ciphertext)
            if fmt:
                key16 = candidate32[:16]
                print_fn(f"\n[v2_key:headers] Found AES key in 32-byte block! -> {fmt}")
                print_fn(f"  Key (hex): {key16.hex()}")
                return key16

    print_fn(f"[v2_key:headers] Tested {tested_16} raw-16 + {tested_hex} hex-decode"
             f" + {tested_32} raw-32 candidates — no key found")
    return None


# ---------------------------------------------------------------------------
# wx_key pattern-based function location
# ---------------------------------------------------------------------------

# Version-specific byte patterns from wx_key/remote_scanner.cpp
# These locate the image decryption function in Weixin.dll.
# offset: applied to the matched pattern address to get the hook/key location.
_WX_KEY_PATTERNS = [
    # >4.1.6.14
    {
        'min_ver': (4, 1, 6, 15),
        'max_ver': (99, 0, 0, 0),
        'pattern': bytes([
            0x24, 0x50, 0x48, 0xC7, 0x45, 0x00, 0xFE, 0xFF,
            0xFF, 0xFF, 0x44, 0x89, 0xCF, 0x44, 0x89, 0xC3,
            0x49, 0x89, 0xD6, 0x48, 0x89, 0xCE, 0x48, 0x89,
        ]),
        'mask': 'xxxxxxxxxxxxxxxxxxxxxxxx',  # all exact
        'offset': -3,
    },
    # >=4.1.4 && <=4.1.6.14
    {
        'min_ver': (4, 1, 4, 0),
        'max_ver': (4, 1, 6, 14),
        'pattern': bytes([
            0x24, 0x08, 0x48, 0x89, 0x6C, 0x24, 0x10, 0x48,
            0x89, 0x74, 0x00, 0x18, 0x48, 0x89, 0x7C, 0x00,
            0x20, 0x41, 0x56, 0x48, 0x83, 0xEC, 0x50, 0x41,
        ]),
        'mask': 'xxxxxxxxxx?xxxx?xxxxxxxx',  # wildcards at pos 10, 15
        'offset': -3,
    },
    # <4.1.4 (4.0.x, 4.1.0–4.1.3)
    {
        'min_ver': (4, 0, 0, 0),
        'max_ver': (4, 1, 3, 9999),
        'pattern': bytes([
            0x24, 0x50, 0x48, 0xC7, 0x45, 0x00, 0xFE, 0xFF,
            0xFF, 0xFF, 0x44, 0x89, 0xCF, 0x44, 0x89, 0xC3,
            0x49, 0x89, 0xD6, 0x48, 0x89, 0xCE, 0x48, 0x89,
        ]),
        'mask': 'xxxxxxxxxxxxxxxxxxxxxxxx',  # all exact, same as >4.1.6.14
        'offset': -0xF,  # different offset for older versions
    },
]


def _get_wechat_version(h_process):
    """Extract WeChat (Weixin.dll) version from the target process.

    Returns a (major, minor, build, revision) tuple, or None.
    """
    import time

    # Find Weixin.dll base address
    try:
        psapi = ctypes.windll.psapi
    except Exception:
        psapi = ctypes.windll.kernel32

    hModules = (ctypes.c_ulonglong * 1024)()
    cbNeeded = wt.DWORD(0)
    # Use K32EnumProcessModulesEx to get all modules
    try:
        k32 = ctypes.windll.kernel32
        ok = k32.K32EnumProcessModulesEx(h_process, ctypes.byref(hModules),
                                          ctypes.sizeof(hModules),
                                          ctypes.byref(cbNeeded), 0x03)
    except Exception:
        return None
    if not ok:
        return None

    n_modules = cbNeeded.value // ctypes.sizeof(ctypes.c_ulonglong)
    for i in range(min(n_modules, 1024)):
        mod_handle = ctypes.c_void_p(hModules[i])
        name_buf = ctypes.create_unicode_buffer(260)
        k32.K32GetModuleBaseNameW(h_process, mod_handle, name_buf, 260)
        mod_name = name_buf.value.lower()
        if mod_name == 'weixin.dll':
            # Get full path for version info
            path_buf = ctypes.create_unicode_buffer(260)
            k32.K32GetModuleFileNameExW(h_process, mod_handle, path_buf, 260)
            dll_path = path_buf.value
            if not dll_path:
                continue

            # Get version info size
            import ctypes.wintypes as _wt
            dummy = wt.DWORD(0)
            size = ctypes.windll.version.GetFileVersionInfoSizeW(dll_path, ctypes.byref(dummy))
            if size == 0:
                continue

            ver_buf = ctypes.create_string_buffer(size)
            ok = ctypes.windll.version.GetFileVersionInfoW(dll_path, 0, size, ver_buf)
            if not ok:
                continue

            fixed_info = ctypes.c_void_p()
            fixed_len = wt.UINT(0)
            ok = ctypes.windll.version.VerQueryValueW(
                ver_buf, '\\', ctypes.byref(fixed_info), ctypes.byref(fixed_len))
            if not ok:
                continue

            # VS_FIXEDFILEINFO: dwProductVersionMS (major.minor), dwProductVersionLS (build.revision)
            class VS_FIXEDFILEINFO(ctypes.Structure):
                _fields_ = [
                    ("dwSignature", wt.DWORD),
                    ("dwStrucVersion", wt.DWORD),
                    ("dwFileVersionMS", wt.DWORD),
                    ("dwFileVersionLS", wt.DWORD),
                    ("dwProductVersionMS", wt.DWORD),
                    ("dwProductVersionLS", wt.DWORD),
                ]
            info = ctypes.cast(fixed_info, ctypes.POINTER(VS_FIXEDFILEINFO)).contents
            ms_val = info.dwProductVersionMS
            ls_val = info.dwProductVersionLS
            major = ms_val >> 16
            minor = ms_val & 0xFFFF
            build = ls_val >> 16
            revision = ls_val & 0xFFFF
            return (major, minor, build, revision)

    return None


def _match_pattern(data, pattern_bytes, mask_str, start=0):
    """Find pattern in data using mask. Returns offset or -1."""
    plen = len(pattern_bytes)
    if len(data) - start < plen:
        return -1
    for i in range(start, len(data) - plen + 1):
        match = True
        for j in range(plen):
            if mask_str[j] == '?':
                continue
            if data[i + j] != pattern_bytes[j]:
                match = False
                break
        if match:
            return i
    return -1


def _scan_wx_key_pattern(h_process, ciphertext, print_fn=None):
    """Use wx_key's version-specific patterns to locate the image decryption
    function in Weixin.dll and extract keys from nearby memory.

    wx_key hooks a function in Weixin.dll that receives/handles the 32-byte
    image key during decryption. We can't hook from Python, but we can:
    1. Locate the function using the same byte patterns
    2. Read memory around the function during active image viewing
    3. Test 16-byte/32-byte windows near the function as key candidates

    Returns:
        Key bytes (16 raw bytes), or None
    """
    import time
    if print_fn is None:
        print_fn = lambda *args, **kwargs: None

    t0 = time.time()

    # Get WeChat version
    ver = _get_wechat_version(h_process)
    if ver is None:
        print_fn("[v2_key:wx_pattern] Could not determine WeChat version")
        return None
    ver_str = '.'.join(str(v) for v in ver)
    print_fn(f"[v2_key:wx_pattern] WeChat version: {ver_str}")

    # Select matching pattern
    selected = None
    for cfg in _WX_KEY_PATTERNS:
        if (ver >= cfg['min_ver'] and ver <= cfg['max_ver']):
            selected = cfg
            break

    if selected is None:
        print_fn(f"[v2_key:wx_pattern] No pattern for version {ver_str}")
        return None

    print_fn(f"[v2_key:wx_pattern] Using pattern (offset={selected['offset']})")

    # Find Weixin.dll module
    try:
        k32 = ctypes.windll.kernel32
    except Exception:
        return None
    hModules = (ctypes.c_ulonglong * 1024)()
    cbNeeded = wt.DWORD(0)
    ok = k32.K32EnumProcessModulesEx(h_process, ctypes.byref(hModules),
                                      ctypes.sizeof(hModules),
                                      ctypes.byref(cbNeeded), 0x03)
    if not ok:
        return None

    n_modules = cbNeeded.value // ctypes.sizeof(ctypes.c_ulonglong)
    weixin_base = None
    weixin_size = 0
    for i in range(min(n_modules, 1024)):
        mod_handle = ctypes.c_void_p(hModules[i])
        name_buf = ctypes.create_unicode_buffer(260)
        k32.K32GetModuleBaseNameW(h_process, mod_handle, name_buf, 260)
        mod_name = name_buf.value.lower()
        if mod_name == 'weixin.dll':
            class MODULEINFO(ctypes.Structure):
                _fields_ = [
                    ("lpBaseOfDll", ctypes.c_void_p),
                    ("SizeOfImage", wt.DWORD),
                    ("EntryPoint", ctypes.c_void_p),
                ]
            mod_info = MODULEINFO()
            ok2 = k32.K32GetModuleInformation(h_process, mod_handle,
                                               ctypes.byref(mod_info),
                                               ctypes.sizeof(mod_info))
            if ok2:
                weixin_base = mod_info.lpBaseOfDll or None
                weixin_size = mod_info.SizeOfImage
            break

    if weixin_base is None or weixin_size == 0:
        print_fn("[v2_key:wx_pattern] Weixin.dll not found")
        return None

    print_fn(f"[v2_key:wx_pattern] Weixin.dll at 0x{weixin_base:X}, size={weixin_size / 1024 / 1024:.1f}MB")

    # Read Weixin.dll memory in chunks and search for pattern
    CHUNK = 1024 * 1024
    plen = len(selected['pattern'])
    pattern_found_at = None
    for chunk_start in range(0, weixin_size, CHUNK):
        chunk_size = min(CHUNK + plen, weixin_size - chunk_start)
        buf = ctypes.create_string_buffer(chunk_size)
        bytes_read = ctypes.c_size_t(0)
        ok = kernel32.ReadProcessMemory(
            h_process, ctypes.c_void_p(weixin_base + chunk_start),
            buf, chunk_size, ctypes.byref(bytes_read))
        if not ok or bytes_read.value < plen:
            continue
        data = buf.raw[:bytes_read.value]
        offset = _match_pattern(data, selected['pattern'], selected['mask'])
        if offset >= 0:
            pattern_found_at = weixin_base + chunk_start + offset
            break

    if pattern_found_at is None:
        print_fn("[v2_key:wx_pattern] Pattern not found in Weixin.dll")
        return None

    target_addr = pattern_found_at + selected['offset']
    print_fn(f"[v2_key:wx_pattern] Pattern at 0x{pattern_found_at:X}, target=0x{target_addr:X}")

    # Read memory around the target address (±1024 bytes) to find key candidates
    SCAN_RANGE = 1024
    buf_start = target_addr - SCAN_RANGE
    buf_size = SCAN_RANGE * 2
    try:
        buf = ctypes.create_string_buffer(buf_size)
    except (OverflowError, MemoryError):
        return None
    bytes_read = ctypes.c_size_t(0)
    ok = kernel32.ReadProcessMemory(
        h_process, ctypes.c_void_p(buf_start),
        buf, buf_size, ctypes.byref(bytes_read))
    if not ok or bytes_read.value < 16:
        return None

    data = buf.raw[:bytes_read.value]

    # Test 16-byte sliding window, step=4
    tested = 0
    for i in range(0, len(data) - 16, 4):
        candidate = data[i:i + 16]
        tested += 1
        fmt = _try_key(candidate, ciphertext)
        if fmt:
            print_fn(f"\n[v2_key:wx_pattern] Found key at target+{i - SCAN_RANGE}! -> {fmt}")
            print_fn(f"  Key (hex): {candidate.hex()}")
            return candidate

    # Also test hex-decoded 32-byte windows
    for i in range(0, len(data) - 32, 16):
        chunk = data[i:i + 32]
        try:
            hex_str = chunk.decode('ascii')
        except UnicodeDecodeError:
            continue
        if not all(c in '0123456789abcdefABCDEF' for c in hex_str):
            continue
        try:
            decoded = bytes.fromhex(hex_str)
        except ValueError:
            continue
        fmt = _try_key(decoded, ciphertext)
        if fmt:
            print_fn(f"\n[v2_key:wx_pattern] Found hex-encoded key! -> {fmt}")
            return decoded

    elapsed = time.time() - t0
    print_fn(f"[v2_key:wx_pattern] Tested {tested} candidates in {elapsed:.1f}s — no key found")
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def find_keys_for_files(decrypted_dir, wxid, md5_list, print_fn=None):
    """Extract V2 AES keys for specific image md5s from running WeChat process.

    Searches WeChat process memory for 32-char hex strings that decrypt
    the requested files' AES blocks. This requires the images to have been
    viewed in WeChat (which loads their keys into memory).

    Args:
        decrypted_dir: path to the decrypted backup directory
        wxid: WeChat user ID (e.g., 'wxid_cpyn7pe119rs21_10e8')
        md5_list: list of XML md5 hex strings
        print_fn: optional logging function

    Returns:
        dict: {md5: aes_key_ascii (16 bytes)} for found keys
    """
    if print_fn is None:
        print_fn = lambda *args, **kwargs: None

    if not md5_list:
        return {}

    # Build tasks: resolve each md5 to a file and get ciphertext
    tasks = []
    for md5_val in md5_list:
        if len(md5_val) != 32:
            continue
        media_info = {'md5': md5_val, 'media_type': 3}
        file_path = _resolve_hardlink_path(decrypted_dir, media_info, wxid)
        if not file_path or not os.path.isfile(file_path):
            continue

        try:
            with open(file_path, 'rb') as f:
                data = f.read(128)
        except OSError:
            continue

        if len(data) < 31 or data[:6] != b'\x07\x08V2\x08\x07':
            continue

        # First 16 bytes of AES section (for verification)
        aes_block = data[15:31]
        tasks.append((md5_val, file_path, aes_block))

    if not tasks:
        print_fn("[v2_key] No valid V2 files found to find keys for")
        return {}

    print_fn(f"[v2_key] Searching memory for {len(tasks)} file(s)...")

    pids = _get_wechat_pids()
    if not pids:
        print_fn("[v2_key] Weixin.exe is not running")
        return {}

    found = {}
    for md5_val, file_path, aes_block in tasks:
        for pid in pids:
            print_fn(f"[v2_key] Scanning PID {pid} for md5={md5_val[:16]}...")
            access = 0x0010 | 0x0400  # PROCESS_VM_READ | PROCESS_QUERY_INFORMATION
            h_process = kernel32.OpenProcess(access, False, pid)
            if not h_process:
                continue
            try:
                # Strategy 1: Scan near V2 headers (raw binary + hex-decode windows)
                # This is the most reliable — keys are near where they're used.
                key_bytes = _scan_near_v2_headers(h_process, aes_block, print_fn)
                if key_bytes:
                    found[md5_val] = key_bytes
                    break

                # Strategy 2: wx_key pattern-based function location
                # Locate the image decryption function and read nearby memory.
                key_bytes = _scan_wx_key_pattern(h_process, aes_block, print_fn)
                if key_bytes:
                    found[md5_val] = key_bytes
                    break

                # Strategy 3: Regex hex-string scan (ZedeX approach)
                # Fallback — finds 32-char/16-char hex strings in all RW memory.
                key_str = _scan_memory_for_aes_keys(h_process, aes_block, print_fn)
                if key_str:
                    found[md5_val] = key_str[:16].encode('ascii')
                    break
            finally:
                kernel32.CloseHandle(h_process)

        if md5_val in found:
            break  # Move to next file (but we only process first one)

    print_fn(f"[v2_key] Found {len(found)}/{len(md5_list)} keys")
    if found:
        _merge_into_cache(decrypted_dir, found)
    return found


def _merge_into_cache(decrypted_dir, new_keys):
    """Merge newly found keys into _media_keys.json cache."""
    import json
    keys_file = os.path.join(decrypted_dir, '_media_keys.json')

    existing = {}
    try:
        if os.path.isfile(keys_file):
            with open(keys_file, 'r', encoding='utf-8') as f:
                existing = json.load(f)
    except Exception:
        pass

    md5_keys = existing.get('md5_keys', {})
    added = 0
    for md5_val, aes_key in new_keys.items():
        if md5_val not in md5_keys:
            md5_keys[md5_val] = {
                'aes_key': aes_key.hex(),
                'xor_key': '0xc9',
            }
            added += 1

    if added > 0:
        existing['md5_keys'] = md5_keys
        try:
            with open(keys_file, 'w', encoding='utf-8') as f:
                json.dump(existing, f, indent=2)
        except Exception:
            pass

    return added


def is_wechat_running():
    """Check if Weixin.exe is currently running."""
    return len(_get_wechat_pids()) > 0


# ---------------------------------------------------------------------------
# MMKV-based local key extraction (py_wx_key algorithm)
# ---------------------------------------------------------------------------

def _scan_mmkv_kvcomm_dirs():
    """Find all kvcomm directories under xwechat paths.

    Returns list of absolute directory paths.
    """
    import glob as _glob
    dirs = []
    appdata = os.environ.get('APPDATA', '')
    if not appdata:
        return dirs

    xwechat_root = os.path.join(appdata, 'Tencent', 'xwechat')
    if not os.path.isdir(xwechat_root):
        return dirs

    # Scan all subdirectories for kvcomm folders
    for root, subdirs, _files in os.walk(xwechat_root):
        # Limit depth to avoid scanning too deep
        depth = root[len(xwechat_root):].count(os.sep)
        if depth > 3:
            subdirs.clear()
            continue
        if os.path.basename(root) == 'kvcomm':
            dirs.append(root)

    return dirs


def _parse_mmkv_codes(kvcomm_dirs: list) -> list:
    """Extract numeric codes from key_*_.statistic files in kvcomm directories.

    Returns list of unique integer codes found.
    """
    import re as _re
    _KEY_FILE_RE = _re.compile(r'^key_(\d+)_.+\.statistic$')

    codes = set()
    for d in kvcomm_dirs:
        if not os.path.isdir(d):
            continue
        try:
            for fname in os.listdir(d):
                m = _KEY_FILE_RE.match(fname)
                if m:
                    code = int(m.group(1))
                    # py_wx_key filters: code > 0 && code <= 4294967295
                    if code > 0 and code <= 4294967295:
                        codes.add(code)
        except OSError:
            continue

    return sorted(codes)


def _derive_key_from_mmkv(code: int, wxid: str) -> tuple:
    """Derive V2 AES key and XOR key from an MMKV statistic code + wxid.

    Algorithm from py_wx_key (H3CoF6):
      xorKey = code & 0xFF
      aesKey = MD5(str(code) + wxid).hex()[:16]  (first 16 hex chars)

    The aesKey is used as 16 ASCII bytes (NOT hex-decoded to 8 raw bytes).
    pycryptodome's AES.new() accepts these 16 ASCII chars directly as a
    128-bit key.

    Returns (xor_key: int, aes_key: bytes) — aes_key is 16 ASCII bytes.
    """
    import hashlib
    code_str = str(code)
    hash_input = (code_str + wxid).encode('utf-8')
    md5_hex = hashlib.md5(hash_input).hexdigest()
    # First 16 hex chars used as ASCII bytes (16 bytes = AES-128 key)
    aes_key = md5_hex[:16].encode('ascii')
    xor_key = code & 0xFF
    return xor_key, aes_key


def _clean_wxid(wxid: str) -> str:
    """Strip the suffix after the second underscore (py_wx_key CleanWxid).

    'wxid_cpyn7pe119rs21_10e8' -> 'wxid_cpyn7pe119rs21'
    """
    if not wxid or not wxid.startswith('wxid_'):
        return wxid
    parts = wxid.split('_')
    if len(parts) >= 3:
        return '_'.join(parts[:2])
    return wxid


def extract_keys_from_mmkv(decrypted_dir: str, wxid: str = None) -> dict:
    """Extract V2 AES keys from local MMKV statistic files (no WeChat process needed).

    Scans %APPDATA%\\Tencent\\xwechat\\**\\kvcomm\\ for key_*_.statistic files,
    derives per-account AES/XOR keys, and tests them against V2 ciphertexts in
    the backup. Working keys are cached to _media_keys.json.

    This is the py_wx_key approach — purely offline, local file-based key
    derivation. No WeChat process or memory scanning required.

    Args:
        decrypted_dir: path to decrypted backup directory
        wxid: WeChat user ID (auto-detected if None)

    Returns:
        dict: {md5: key_bytes} for all newly found keys
    """
    if wxid is None:
        wxid = os.path.basename(os.path.dirname(decrypted_dir))
        if not wxid.startswith('wxid_'):
            # Try detection from hardlink DB
            hardlink_db = os.path.join(decrypted_dir, "hardlink", "hardlink.db")
            if not os.path.isfile(hardlink_db):
                hardlink_db = os.path.join(decrypted_dir, "HardLink", "hardlink.db")
            if os.path.isfile(hardlink_db):
                try:
                    conn = sqlite3.connect(hardlink_db)
                    row = conn.execute(
                        "SELECT ValueStdStr FROM db_info WHERE Key='uuid'"
                    ).fetchone()
                    conn.close()
                    if row and row[0]:
                        parts = str(row[0]).split('_', 2)
                        if len(parts) >= 3 and os.path.isdir(parts[-1]):
                            for d in os.listdir(parts[-1]):
                                if d.startswith('wxid_') and os.path.isdir(
                                    os.path.join(parts[-1], d)):
                                    wxid = d
                                    break
                except sqlite3.Error:
                    pass

    # Clean wxid: strip suffix after second underscore (py_wx_key CleanWxid)
    wxid = _clean_wxid(wxid)

    if not wxid or not wxid.startswith('wxid_'):
        print("[mmkv] Cannot determine wxid — skipping MMKV extraction", flush=True)
        return {}

    # 1. Find kvcomm directories and parse codes
    kvcomm_dirs = _scan_mmkv_kvcomm_dirs()
    if not kvcomm_dirs:
        print("[mmkv] No kvcomm directories found", flush=True)
        return {}

    codes = _parse_mmkv_codes(kvcomm_dirs)
    if not codes:
        print("[mmkv] No key statistic files found in kvcomm dirs", flush=True)
        return {}

    print(f"[mmkv] Found {len(codes)} MMKV code(s) in {len(kvcomm_dirs)} kvcomm dirs: {codes}",
          flush=True)

    # 2. Derive candidate keys for each code
    candidates = []
    for code in codes:
        xor_key, aes_key = _derive_key_from_mmkv(code, wxid)
        print(f"[mmkv] Code {code} -> xor=0x{xor_key:02X} aes={aes_key.hex()}",
              flush=True)
        candidates.append((xor_key, aes_key, code))

    if not candidates:
        return {}

    # 3. Load V2 ciphertexts for verification
    tasks = _load_v2_ciphertexts(decrypted_dir, wxid)
    if not tasks:
        print("[mmkv] No V2 .dat files found for verification", flush=True)
        return {}

    print(f"[mmkv] Testing {len(candidates)} candidate(s) against {len(tasks)} V2 file(s)...",
          flush=True)

    # 4. Verify each candidate against a small sample, then cache globally.
    #    The key is per-account (not per-image), so we only need to verify
    #    against a few files to confirm it works.
    import json as _json
    found_all = {}
    keys_file = os.path.join(decrypted_dir, '_media_keys.json')

    # Load existing keys to avoid re-work
    existing_md5s = set()
    try:
        if os.path.isfile(keys_file) and os.path.getsize(keys_file) > 0:
            with open(keys_file, 'r', encoding='utf-8') as f:
                cached = _json.load(f)
            existing_md5s = set(cached.get('md5_keys', {}).keys())
    except Exception:
        pass

    pending = {md5: v for md5, v in tasks.items() if md5 not in existing_md5s}
    if not pending:
        print("[mmkv] All V2 keys already cached", flush=True)
        return {}

    # Sample up to 5 files for verification; if the key works on these,
    # it works for ALL files (per-account key, not per-image).
    sample_md5s = list(pending.keys())[:5]
    verified_codes = set()

    for xor_key, aes_key, code in candidates:
        match_count = 0
        for md5 in sample_md5s:
            fmt = _try_key(aes_key, pending[md5][1])
            if fmt:
                match_count += 1
        if match_count == len(sample_md5s):
            print(f"[mmkv] Code {code} verified ({match_count}/{len(sample_md5s)} sample files)",
                  flush=True)
            verified_codes.add(code)
            # Cache for ALL pending files (not just the sample)
            for md5 in pending:
                found_all[md5] = aes_key
            break  # One working code is enough
        elif match_count > 0:
            print(f"[mmkv] Code {code} partial match ({match_count}/{len(sample_md5s)})",
                  flush=True)
            verified_codes.add(code)
            for md5 in pending:
                found_all[md5] = aes_key
            break
        else:
            print(f"[mmkv] Code {code} no match on sample files", flush=True)

    if found_all:
        print(f"[mmkv] Success! Account key derived locally — cached for {len(found_all)} files",
              flush=True)
        _merge_into_cache(decrypted_dir, found_all)
    else:
        print("[mmkv] No keys matched — account may use different wxid or codes",
              flush=True)

    return found_all


# ---------------------------------------------------------------------------
# Continuous key harvester
# ---------------------------------------------------------------------------

def _load_v2_ciphertexts(decrypted_dir, wxid):
    """Pre-load ciphertexts from all V2 .dat files in the backup.

    Returns dict: {md5: (file_path, aes_block_16b)} for all V2 files.
    """
    import glob as _glob

    tasks = {}
    # Search for .dat files in media/images (backup) and original storage
    search_dirs = [
        os.path.join(decrypted_dir, 'media', 'images'),
    ]
    # Also search original WeChat storage
    base = _get_base_storage(decrypted_dir)
    if base and wxid:
        for pattern in ['msg/attach/*/*/Img/*.dat', 'msg/image/*/*.dat']:
            search_dirs.append(os.path.join(base, wxid, pattern))

    for sdir in search_dirs:
        if '*' in sdir:
            for fpath in _glob.glob(sdir):
                md5 = os.path.splitext(os.path.basename(fpath))[0]
                # Strip _t, _h suffixes
                for sfx in ('_t', '_h'):
                    if md5.endswith(sfx):
                        md5 = md5[:-2]
                if md5 in tasks or len(md5) < 16:
                    continue
                try:
                    with open(fpath, 'rb') as f:
                        data = f.read(128)
                except OSError:
                    continue
                if len(data) >= 31 and data[:6] == b'\x07\x08V2\x08\x07':
                    tasks[md5] = (fpath, data[15:31])
        elif os.path.isdir(sdir):
            for fname in os.listdir(sdir):
                if not fname.lower().endswith('.dat'):
                    continue
                fpath = os.path.join(sdir, fname)
                md5 = os.path.splitext(fname)[0]
                for sfx in ('_t', '_h'):
                    if md5.endswith(sfx):
                        md5 = md5[:-2]
                if md5 in tasks or len(md5) < 16:
                    continue
                try:
                    with open(fpath, 'rb') as f:
                        data = f.read(128)
                except OSError:
                    continue
                if len(data) >= 31 and data[:6] == b'\x07\x08V2\x08\x07':
                    tasks[md5] = (fpath, data[15:31])

    return tasks


def _test_key_against_all(key_bytes, tasks):
    """Test a key candidate against all known ciphertexts.

    Returns (md5, format) for the first match, or (None, None).
    """
    for md5, (_, ciphertext) in tasks.items():
        fmt = _try_key(key_bytes, ciphertext)
        if fmt:
            return md5, fmt
    return None, None


def harvest_v2_keys(decrypted_dir, wxid=None, interval=2.0,
                    max_rounds=None, print_fn=None, stop_event=None):
    """Continuously scan WeChat memory for V2 AES keys and cache them.

    Pre-loads all V2 file ciphertexts from the backup, then polls WeChat
    process memory at the given interval. Each round tries all 3 strategies
    against ALL known ciphertexts — much more efficient than one-at-a-time.

    Keys are immediately cached to _media_keys.json so subsequent offline
    viewing works without WeChat running.

    Args:
        decrypted_dir: path to decrypted backup directory
        wxid: WeChat user ID (auto-detected if None)
        interval: seconds between scan rounds (default 2.0)
        max_rounds: maximum scan rounds (None = run until interrupted)
        print_fn: optional logging function
        stop_event: optional threading.Event — when set, harvester exits cleanly

    Returns:
        dict: {md5: key_bytes} for all found keys
    """
    import time

    if print_fn is None:
        print_fn = lambda *a, **kw: None

    # Auto-detect wxid if not provided
    if wxid is None:
        wxid = os.path.basename(os.path.dirname(decrypted_dir))
        if not wxid.startswith('wxid_'):
            # Try to detect from hardlink DB
            wxid = None
            hardlink_db = os.path.join(decrypted_dir, "hardlink", "hardlink.db")
            if not os.path.isfile(hardlink_db):
                hardlink_db = os.path.join(decrypted_dir, "HardLink", "hardlink.db")
            if os.path.isfile(hardlink_db):
                try:
                    conn = sqlite3.connect(hardlink_db)
                    row = conn.execute(
                        "SELECT ValueStdStr FROM db_info WHERE Key='uuid'"
                    ).fetchone()
                    conn.close()
                    if row and row[0]:
                        parts = str(row[0]).split('_', 2)
                        if len(parts) >= 3:
                            storage_root = parts[-1]
                            if os.path.isdir(storage_root):
                                for d in os.listdir(storage_root):
                                    if d.startswith('wxid_') and os.path.isdir(
                                        os.path.join(storage_root, d)
                                    ):
                                        wxid = d
                                        break
                except sqlite3.Error:
                    pass

    if not wxid:
        print_fn("[v2_harvest] ERROR: Cannot determine wxid")
        return {}

    # Load V2 ciphertexts
    tasks = _load_v2_ciphertexts(decrypted_dir, wxid)
    if not tasks:
        print_fn("[v2_harvest] No V2 .dat files found in backup")
        return {}

    print_fn(f"[v2_harvest] Loaded {len(tasks)} V2 ciphertexts for verification")

    # Load existing cache to avoid re-scanning
    found_all = {}
    import json as _json
    keys_file = os.path.join(decrypted_dir, '_media_keys.json')
    existing_md5s = set()
    try:
        if os.path.isfile(keys_file) and os.path.getsize(keys_file) > 0:
            with open(keys_file, 'r', encoding='utf-8') as f:
                cached = _json.load(f)
            md5_keys = cached.get('md5_keys', {})
            existing_md5s = set(md5_keys.keys())
            print_fn(f"[v2_harvest] {len(existing_md5s)} keys already cached")
    except Exception:
        pass

    pending = {md5: v for md5, v in tasks.items() if md5 not in existing_md5s}
    if not pending:
        print_fn("[v2_harvest] All V2 keys already cached!")
        return {}

    print_fn(f"[v2_harvest] {len(pending)} files still need keys")

    # --- Baseline: try MMKV-based local key derivation (py_wx_key approach) ---
    # This can resolve keys OFFLINE without WeChat running at all.
    try:
        mmkv_found = extract_keys_from_mmkv(decrypted_dir, wxid)
        if mmkv_found:
            for md5, key_bytes in mmkv_found.items():
                found_all[md5] = key_bytes
                if md5 in pending:
                    del pending[md5]
            print_fn(f"[v2_harvest] MMKV baseline resolved {len(mmkv_found)} keys, "
                     f"{len(pending)} remaining")
        if not pending:
            print_fn("[v2_harvest] All keys resolved via MMKV local derivation!")
            return found_all
    except Exception as e:
        print_fn(f"[v2_harvest] MMKV extraction failed: {e}")

    if not is_wechat_running():
        print_fn("[v2_harvest] WeChat is not running. Start WeChat and scroll through "
                 "chats with images to expose keys in memory, then run this command.")
        return {}

    round_num = 0
    last_new = 0
    t_start = time.time()

    try:
        while max_rounds is None or round_num < max_rounds:
            if stop_event and stop_event.is_set():
                print_fn("[v2_harvest] Stop event received — exiting")
                break
            round_num += 1
            t0 = time.time()

            pids = _get_wechat_pids()
            if not pids:
                print_fn(f"[v2_harvest:r{round_num}] WeChat exited — stopping")
                break

            round_found = 0
            for pid in pids:
                access = 0x0010 | 0x0400
                h_process = kernel32.OpenProcess(access, False, pid)
                if not h_process:
                    continue
                try:
                    # Strategy 1: V2 header proximity scan
                    # Find all V2 headers, read ±256 bytes around each,
                    # test 16-byte sliding windows against ALL ciphertexts
                    V2_MAGIC = b'\x07\x08\x56\x32\x08\x07'
                    WINDOW_HALF = 256
                    mbi = MEMORY_BASIC_INFORMATION()
                    v2_addrs = []
                    address = 0
                    while address < 0x7FFFFFFFFFFF:
                        result = kernel32.VirtualQueryEx(
                            h_process, ctypes.c_void_p(address),
                            ctypes.byref(mbi), ctypes.sizeof(mbi)
                        )
                        if result == 0:
                            break
                        if (mbi.State == MEM_COMMIT and
                            mbi.Protect != PAGE_NOACCESS and
                            (mbi.Protect & PAGE_GUARD) == 0 and
                            0 < mbi.RegionSize <= 50 * 1024 * 1024):
                            region_base = ctypes.cast(mbi.BaseAddress, ctypes.c_void_p).value
                            if region_base is None:
                                next_addr = address + mbi.RegionSize
                                address = next_addr
                                continue
                            try:
                                buf = ctypes.create_string_buffer(mbi.RegionSize)
                            except (OverflowError, MemoryError):
                                next_addr = address + mbi.RegionSize
                                address = next_addr
                                continue
                            br = ctypes.c_size_t(0)
                            ok = kernel32.ReadProcessMemory(
                                h_process, ctypes.c_void_p(region_base),
                                buf, mbi.RegionSize, ctypes.byref(br)
                            )
                            if ok and br.value > 0:
                                data = buf.raw[:br.value]
                                idx = data.find(V2_MAGIC)
                                while idx != -1:
                                    v2_addrs.append(region_base + idx)
                                    idx = data.find(V2_MAGIC, idx + 1)
                        next_addr = address + mbi.RegionSize
                        if next_addr <= address:
                            break
                        address = next_addr

                    if v2_addrs:
                        tested = 0
                        for addr in v2_addrs:
                            buf_start = addr - WINDOW_HALF
                            buf_size = WINDOW_HALF * 2
                            try:
                                buf = ctypes.create_string_buffer(buf_size)
                            except (OverflowError, MemoryError):
                                continue
                            br = ctypes.c_size_t(0)
                            ok = kernel32.ReadProcessMemory(
                                h_process, ctypes.c_void_p(buf_start),
                                buf, buf_size, ctypes.byref(br)
                            )
                            if not ok or br.value < 16:
                                continue
                            data = buf.raw[:br.value]

                            # 16-byte windows, step=4
                            for i in range(0, len(data) - 16, 4):
                                candidate = data[i:i + 16]
                                tested += 1
                                md5_match, fmt = _test_key_against_all(candidate, pending)
                                if md5_match:
                                    key_hex = candidate.hex()
                                    print_fn(f"  [v2_harvest:r{round_num}] "
                                             f"Found key for {md5_match[:16]}... -> {fmt}")
                                    found_all[md5_match] = candidate
                                    _merge_into_cache(decrypted_dir,
                                                      {md5_match: candidate})
                                    del pending[md5_match]
                                    round_found += 1
                                    if not pending:
                                        break
                            if not pending:
                                break

                            # 32-char hex decode windows
                            for i in range(0, len(data) - 32, 16):
                                chunk = data[i:i + 32]
                                try:
                                    hex_str = chunk.decode('ascii')
                                except UnicodeDecodeError:
                                    continue
                                if not all(c in '0123456789abcdefABCDEF'
                                          for c in hex_str):
                                    continue
                                try:
                                    decoded = bytes.fromhex(hex_str)
                                except ValueError:
                                    continue
                                md5_match, fmt = _test_key_against_all(decoded, pending)
                                if md5_match:
                                    print_fn(f"  [v2_harvest:r{round_num}] "
                                             f"Found key for {md5_match[:16]}... -> {fmt} (hex)")
                                    found_all[md5_match] = decoded
                                    _merge_into_cache(decrypted_dir,
                                                      {md5_match: decoded})
                                    del pending[md5_match]
                                    round_found += 1
                                    if not pending:
                                        break
                            if not pending:
                                break

                    # Strategy 2: Scan RW memory for 32-char hex strings
                    if pending:
                        rw_regions = []
                        address = 0
                        while address < 0x7FFFFFFFFFFF:
                            result = kernel32.VirtualQueryEx(
                                h_process, ctypes.c_void_p(address),
                                ctypes.byref(mbi), ctypes.sizeof(mbi)
                            )
                            if result == 0:
                                break
                            if (mbi.State == MEM_COMMIT and
                                (mbi.Protect & _RW_FLAGS) != 0 and
                                (mbi.Protect & PAGE_GUARD) == 0 and
                                0 < mbi.RegionSize <= 50 * 1024 * 1024):
                                rw_regions.append(
                                    (ctypes.cast(mbi.BaseAddress, ctypes.c_void_p).value,
                                     mbi.RegionSize)
                                )
                            next_addr = address + mbi.RegionSize
                            if next_addr <= address:
                                break
                            address = next_addr

                        for base_addr, region_size in rw_regions:
                            if not pending:
                                break
                            try:
                                buf = ctypes.create_string_buffer(region_size)
                            except (OverflowError, MemoryError):
                                continue
                            br = ctypes.c_size_t(0)
                            ok = kernel32.ReadProcessMemory(
                                h_process, ctypes.c_void_p(base_addr),
                                buf, region_size, ctypes.byref(br)
                            )
                            if not ok or br.value < 32:
                                continue
                            data = buf.raw[:br.value]

                            for m in _RE_KEY32.finditer(data):
                                key_bytes = m.group()
                                # hex-decoded
                                try:
                                    decoded = bytes.fromhex(
                                        key_bytes.decode('ascii'))
                                    md5_match, fmt = _test_key_against_all(
                                        decoded, pending)
                                    if md5_match:
                                        print_fn(f"  [v2_harvest:r{round_num}] "
                                                 f"Found key for {md5_match[:16]}..."
                                                 f" -> {fmt} (regex)")
                                        found_all[md5_match] = decoded
                                        _merge_into_cache(
                                            decrypted_dir,
                                            {md5_match: decoded})
                                        del pending[md5_match]
                                        round_found += 1
                                        if not pending:
                                            break
                                except ValueError:
                                    pass

                                if not pending:
                                    break

                finally:
                    kernel32.CloseHandle(h_process)

                if not pending:
                    break

            elapsed = time.time() - t0
            total_found = len(found_all)
            if round_found > 0:
                last_new = round_num
                print_fn(f"[v2_harvest:r{round_num}] +{round_found} keys "
                         f"({elapsed:.1f}s) — {total_found} total, "
                         f"{len(pending)} remaining")
            elif round_num % 5 == 0:
                runtime = time.time() - t_start
                print_fn(f"[v2_harvest:r{round_num}] no new keys ({elapsed:.1f}s) "
                         f"— {total_found} total, {len(pending)} remaining "
                         f"(running {runtime:.0f}s)")

            if not pending:
                print_fn(f"[v2_harvest] ALL {total_found} keys found in "
                         f"{round_num} rounds!")
                break

            # Auto-stop: if no new keys for 20 rounds (40s at 2s interval),
            # reduce frequency to every 5s
            if round_num - last_new > 20:
                if interval < 5.0:
                    print_fn("[v2_harvest] No new keys for 20 rounds — "
                             "slowing to 5s interval. Keep scrolling in WeChat.")
                    interval = 5.0
            if round_num - last_new > 60:
                print_fn("[v2_harvest] No new keys for 60 rounds — giving up. "
                         "Open more images in WeChat and re-run.")
                break

            # Sleep in sub-second increments to allow responsive stop
            if stop_event:
                for _ in range(int(interval * 10)):
                    if stop_event.is_set():
                        break
                    time.sleep(0.1)
            else:
                time.sleep(interval)

    except KeyboardInterrupt:
        print_fn(f"\n[v2_harvest] Interrupted. Saved {len(found_all)} keys.")

    return found_all
