"""Operating-system abstractions shared by the app, catalogue and storage code.

Everything Linux-specific that the rest of the code base used directly
(``select`` on pipes, ``fcntl.flock``, ``O_NOFOLLOW``, POSIX permission bits,
console-less child processes) goes through this module, so the security
model is the same on Linux and Windows:

* Secret files and private directories are readable only by the current
  user (POSIX: 0700/0600; Windows: a *protected* DACL granting only the
  current user and SYSTEM, inherited by everything created inside).
* Reading a secret refuses symlinks/reparse points and any file another
  (non-administrative) account can read.
* Child processes never get a console window on Windows and are placed in a
  kill-on-close Job Object, so a crashed app never leaves an orphaned
  conductor holding the database lock.

Windows code paths import ``ctypes.windll`` lazily, so this module imports
(and its pure helpers are unit-tested) on every platform.
"""
from __future__ import annotations

import os
from pathlib import Path
import queue
import stat
import subprocess
import sys
import threading

IS_WINDOWS = os.name == "nt"

O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
O_BINARY = getattr(os, "O_BINARY", 0)
O_NOINHERIT = getattr(os, "O_NOINHERIT", 0)

# Well-known SIDs allowed to read private files besides the current user.
SID_SYSTEM = "S-1-5-18"
SID_ADMINISTRATORS = "S-1-5-32-544"


class PortabilityError(RuntimeError):
    pass


class AlreadyLocked(PortabilityError):
    pass


def exe(tool: str) -> str:
    """Executable file name for a bundled tool on this platform."""
    return f"{tool}.exe" if IS_WINDOWS and not tool.lower().endswith(".exe") else tool


# --------------------------------------------------------------------------
# Child processes
# --------------------------------------------------------------------------

def popen_kwargs() -> dict:
    """Extra ``subprocess.Popen`` arguments for supervised children.

    Windows: no console window (the app is launched with ``pythonw``) and
    no inherited handles beyond the explicit pipes. POSIX: unchanged.
    """
    if IS_WINDOWS:
        return {"creationflags": subprocess.CREATE_NO_WINDOW}
    return {}


class _Job:
    """A Windows Job Object that kills every assigned child when the app's
    process exits for any reason (including a crash or Task Manager kill)."""

    def __init__(self):
        import ctypes
        from ctypes import wintypes
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.CreateJobObjectW.restype = wintypes.HANDLE
        k32.CreateJobObjectW.argtypes = (wintypes.LPVOID, wintypes.LPCWSTR)
        k32.SetInformationJobObject.argtypes = (wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD)
        k32.AssignProcessToJobObject.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
        handle = k32.CreateJobObjectW(None, None)
        if not handle:
            raise ctypes.WinError(ctypes.get_last_error())

        class IO_COUNTERS(ctypes.Structure):
            _fields_ = [(n, ctypes.c_ulonglong) for n in (
                "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

        class BASIC(ctypes.Structure):
            _fields_ = [("PerProcessUserTimeLimit", ctypes.c_longlong), ("PerJobUserTimeLimit", ctypes.c_longlong),
                        ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                        ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                        ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD),
                        ("SchedulingClass", wintypes.DWORD)]

        class EXTENDED(ctypes.Structure):
            _fields_ = [("BasicLimitInformation", BASIC), ("IoInfo", IO_COUNTERS),
                        ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                        ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]

        info = EXTENDED()
        info.BasicLimitInformation.LimitFlags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not k32.SetInformationJobObject(handle, 9, ctypes.byref(info), ctypes.sizeof(info)):
            raise ctypes.WinError(ctypes.get_last_error())
        self._k32, self.handle = k32, handle  # handle deliberately never closed

    def assign(self, proc: subprocess.Popen) -> None:
        if not self._k32.AssignProcessToJobObject(self.handle, int(proc._handle)):
            import ctypes
            raise ctypes.WinError(ctypes.get_last_error())


_job: _Job | None = None
_job_lock = threading.Lock()


def supervise(proc: subprocess.Popen) -> subprocess.Popen:
    """Tie a child's lifetime to this process (Windows Job Object).

    POSIX keeps its existing behaviour: children are stopped explicitly by
    the supervisors' ``stop()`` methods.
    """
    global _job
    if IS_WINDOWS:
        with _job_lock:
            if _job is None:
                _job = _Job()
        try:
            _job.assign(proc)
        except OSError:
            # Assignment can fail only if the child already exited or the
            # app itself runs in a job that forbids nesting (pre-Windows 8).
            if proc.poll() is None:
                proc.kill()
                raise
    return proc


def terminate(proc: subprocess.Popen, *, grace: float) -> None:
    """Stop a supervised child: polite request, then kill after `grace` s.

    POSIX sends SIGTERM. Windows has no SIGTERM for console-less children;
    ``Popen.terminate`` is TerminateProcess, so the grace period is moot.
    Holochain's databases are crash-safe (SQLite WAL), and the Linux
    conductor does not install a SIGTERM handler either, so both platforms
    end the conductor in the same way.
    """
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


# --------------------------------------------------------------------------
# Pipes
# --------------------------------------------------------------------------

class PipeReader:
    """Read a child's stdout with a timeout on every platform.

    ``read(timeout)`` returns bytes, ``None`` on timeout, or ``b""`` at EOF.
    POSIX uses ``select`` exactly as before. Windows cannot ``select`` on
    pipes, so one daemon thread does blocking reads into a *bounded* queue
    (the pipe's own back-pressure is preserved: the thread stops reading when
    the consumer stops consuming). ``threaded=True`` forces the Windows path,
    which is how Linux CI exercises it.
    """

    CHUNK = 65536
    MAX_QUEUED = 32
    # Tests set this to True to run the Windows (threaded) path on Linux.
    force_threaded = False

    def __init__(self, stream, *, threaded: bool | None = None):
        self.stream = stream
        self.fd = stream.fileno()
        self.threaded = (IS_WINDOWS or PipeReader.force_threaded) if threaded is None else threaded
        self._eof = False
        self._closed = threading.Event()
        if self.threaded:
            self._queue: queue.Queue = queue.Queue(self.MAX_QUEUED)
            threading.Thread(target=self._pump, name="pipe-reader", daemon=True).start()

    def _pump(self) -> None:
        while not self._closed.is_set():
            try:
                data = os.read(self.fd, self.CHUNK)
            except (OSError, ValueError):
                data = b""
            while not self._closed.is_set():
                try:
                    self._queue.put(data, timeout=0.5)
                    break
                except queue.Full:
                    continue
            if not data:
                return

    def read(self, timeout: float) -> bytes | None:
        if self._eof:
            return b""
        if self.threaded:
            try:
                data = self._queue.get(timeout=max(0.0, timeout))
            except queue.Empty:
                return None
        else:
            import select
            try:
                readable, _, _ = select.select([self.stream], [], [], max(0.0, timeout))
            except (ValueError, OSError):
                data = b""
            else:
                if not readable:
                    return None
                try:  # fileno() re-checked: never read a reused fd after close
                    data = os.read(self.stream.fileno(), self.CHUNK)
                except (ValueError, OSError):
                    data = b""
        if not data:
            self._eof = True
        return data

    def close(self) -> None:
        self._closed.set()


def replace(src, dst, *, attempts: int = 40, delay: float = 0.025) -> None:
    """Atomic rename-over. POSIX: ``os.replace``. Windows refuses to replace a
    file that another handle (e.g. a concurrent reader polling the library)
    has open without FILE_SHARE_DELETE, which Python's ``open`` never sets;
    such readers are brief, so retry for up to ~1 s before giving up."""
    if not IS_WINDOWS:
        os.replace(src, dst)
        return
    for attempt in range(attempts):
        try:
            os.replace(src, dst)
            return
        except PermissionError:
            if attempt == attempts - 1:
                raise
            import time
            time.sleep(delay)


# --------------------------------------------------------------------------
# Single-instance lock
# --------------------------------------------------------------------------

def lock_file(path: Path) -> int:
    """Take an exclusive, non-blocking lock; return the fd to keep open."""
    fd = os.open(path, os.O_RDWR | os.O_CREAT | O_NOINHERIT | O_BINARY, 0o600)
    try:
        if IS_WINDOWS:
            import msvcrt
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:  # BlockingIOError (POSIX) / PermissionError (msvcrt)
        os.close(fd)
        raise AlreadyLocked(str(path)) from exc
    return fd


# --------------------------------------------------------------------------
# Private files and directories
# --------------------------------------------------------------------------

def private_sddl(user_sid: str, *, directory: bool) -> str:
    """Protected DACL: full control for the user and SYSTEM only. On
    directories the ACEs are inherited by new files and subdirectories."""
    for sid in (user_sid,):
        if not sid.startswith("S-1-") or not all(p.isdecimal() for p in sid[4:].split("-")):
            raise PortabilityError("invalid SID")
    inherit = "OICI" if directory else ""
    return f"D:P(A;{inherit};FA;;;{user_sid})(A;{inherit};FA;;;SY)"


# ACE types that *grant* access (ACCESS_ALLOWED_*). Object/callback variants
# carry their SID at a different offset; they never occur on files we
# create, so they are treated as "someone else can read" (fail closed).
_ACCESS_ALLOWED = 0x00
_ALLOWED_OTHER = {0x04, 0x05, 0x09, 0x0B, 0x11, 0x13}
_INHERIT_ONLY = 0x08


def aces_are_private(aces, user_sid: str) -> bool:
    """Pure check over ``(ace_type, ace_flags, sid_or_None)`` tuples.

    Private = every effective allow-ACE names the user, SYSTEM or the
    local Administrators group (the Windows analogue of root, who can read
    a 0600 file on Linux too). ``aces is None`` means a NULL DACL
    (everyone has full access).
    """
    if aces is None:
        return False
    allowed = {user_sid, SID_SYSTEM, SID_ADMINISTRATORS}
    for ace_type, flags, sid in aces:
        if flags & _INHERIT_ONLY:
            continue  # does not apply to this object itself
        if ace_type in _ALLOWED_OTHER:
            return False
        if ace_type == _ACCESS_ALLOWED and sid not in allowed:
            return False
    return True


class _Win32Security:
    """Minimal advapi32 bindings (no pywin32 dependency)."""

    def __init__(self):
        import ctypes
        from ctypes import wintypes
        self.ctypes, self.wt = ctypes, wintypes
        self.adv = ctypes.WinDLL("advapi32", use_last_error=True)
        self.k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        a, k = self.adv, self.k32
        a.OpenProcessToken.argtypes = (wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE))
        a.GetTokenInformation.argtypes = (wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD,
                                          ctypes.POINTER(wintypes.DWORD))
        a.ConvertSidToStringSidW.argtypes = (wintypes.LPVOID, ctypes.POINTER(wintypes.LPWSTR))
        a.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = (
            wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(wintypes.LPVOID), ctypes.POINTER(wintypes.ULONG))
        a.GetSecurityDescriptorDacl.argtypes = (wintypes.LPVOID, ctypes.POINTER(wintypes.BOOL),
                                                ctypes.POINTER(wintypes.LPVOID), ctypes.POINTER(wintypes.BOOL))
        a.SetNamedSecurityInfoW.argtypes = (wintypes.LPWSTR, ctypes.c_int, wintypes.DWORD, wintypes.LPVOID,
                                            wintypes.LPVOID, wintypes.LPVOID, wintypes.LPVOID)
        a.SetNamedSecurityInfoW.restype = wintypes.DWORD
        a.GetNamedSecurityInfoW.argtypes = (wintypes.LPCWSTR, ctypes.c_int, wintypes.DWORD,
                                            wintypes.LPVOID, wintypes.LPVOID, ctypes.POINTER(wintypes.LPVOID),
                                            wintypes.LPVOID, ctypes.POINTER(wintypes.LPVOID))
        a.GetNamedSecurityInfoW.restype = wintypes.DWORD
        a.GetAce.argtypes = (wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.LPVOID))
        a.GetAclInformation.argtypes = (wintypes.LPVOID, wintypes.LPVOID, wintypes.DWORD, ctypes.c_int)
        k.GetCurrentProcess.restype = wintypes.HANDLE
        k.CloseHandle.argtypes = (wintypes.HANDLE,)
        k.LocalFree.argtypes = (wintypes.LPVOID,)
        k.LocalFree.restype = wintypes.LPVOID
        self._user_sid: str | None = None

    def _err(self):
        return self.ctypes.WinError(self.ctypes.get_last_error())

    def _sid_string(self, psid) -> str:
        out = self.wt.LPWSTR()
        if not self.adv.ConvertSidToStringSidW(psid, self.ctypes.byref(out)):
            raise self._err()
        try:
            return out.value
        finally:
            self.k32.LocalFree(out)

    def user_sid(self) -> str:
        if self._user_sid:
            return self._user_sid
        c, wt = self.ctypes, self.wt
        token = wt.HANDLE()
        if not self.adv.OpenProcessToken(self.k32.GetCurrentProcess(), 0x0008, c.byref(token)):  # TOKEN_QUERY
            raise self._err()
        try:
            size = wt.DWORD()
            self.adv.GetTokenInformation(token, 1, None, 0, c.byref(size))  # TokenUser
            buf = c.create_string_buffer(size.value)
            if not self.adv.GetTokenInformation(token, 1, buf, size, c.byref(size)):
                raise self._err()
            psid = c.cast(buf, c.POINTER(c.c_void_p))[0]  # TOKEN_USER.User.Sid
            self._user_sid = self._sid_string(psid)
            return self._user_sid
        finally:
            self.k32.CloseHandle(token)

    def make_private(self, path: Path, *, directory: bool) -> None:
        c, wt = self.ctypes, self.wt
        sd = wt.LPVOID()
        sddl = private_sddl(self.user_sid(), directory=directory)
        if not self.adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, c.byref(sd), None):
            raise self._err()
        try:
            present, defaulted, dacl = wt.BOOL(), wt.BOOL(), wt.LPVOID()
            if not self.adv.GetSecurityDescriptorDacl(sd, c.byref(present), c.byref(dacl), c.byref(defaulted)):
                raise self._err()
            # DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION:
            # drop inherited ACEs (e.g. from %LOCALAPPDATA%) and propagate ours
            # to existing children.
            rc = self.adv.SetNamedSecurityInfoW(str(path), 1, 0x00000004 | 0x80000000, None, None, dacl, None)
            if rc:
                raise c.WinError(rc)
        finally:
            self.k32.LocalFree(sd)

    def read_aces(self, path: Path):
        c, wt = self.ctypes, self.wt
        dacl, sd = wt.LPVOID(), wt.LPVOID()
        rc = self.adv.GetNamedSecurityInfoW(str(path), 1, 0x00000004, None, None, c.byref(dacl), None, c.byref(sd))
        if rc:
            raise c.WinError(rc)
        try:
            if not dacl.value:
                return None  # NULL DACL: everyone has access

            class ACL_SIZE_INFORMATION(c.Structure):
                _fields_ = [("AceCount", wt.DWORD), ("AclBytesInUse", wt.DWORD), ("AclBytesFree", wt.DWORD)]
            info = ACL_SIZE_INFORMATION()
            if not self.adv.GetAclInformation(dacl, c.byref(info), c.sizeof(info), 2):  # AclSizeInformation
                raise self._err()
            aces = []
            for i in range(info.AceCount):
                pace = wt.LPVOID()
                if not self.adv.GetAce(dacl, i, c.byref(pace)):
                    raise self._err()
                header = c.cast(pace, c.POINTER(c.c_ubyte))
                ace_type, flags = header[0], header[1]
                sid = None
                if ace_type == _ACCESS_ALLOWED:
                    # ACCESS_ALLOWED_ACE: 4-byte header, 4-byte mask, then SID.
                    sid = self._sid_string(c.c_void_p(pace.value + 8))
                aces.append((ace_type, flags, sid))
            return aces
        finally:
            self.k32.LocalFree(sd)


_win: _Win32Security | None = None


def _win32() -> _Win32Security:
    global _win
    if _win is None:
        _win = _Win32Security()
    return _win


def make_private_dir(path: Path) -> None:
    """Restrict a directory (and, on Windows, everything inside it) to the
    current user. Refuses symlinks/junctions, like the POSIX code did."""
    path = Path(path)
    if path.is_symlink() or (IS_WINDOWS and _is_reparse_point(path)):
        raise PortabilityError(f"refusing symlinked application directory {path}")
    if IS_WINDOWS:
        _win32().make_private(path, directory=True)
    else:
        path.chmod(0o700)


def make_private_file(path: Path) -> None:
    if IS_WINDOWS:
        _win32().make_private(Path(path), directory=False)
    else:
        os.chmod(path, 0o600)


def _is_reparse_point(path: Path) -> bool:
    try:
        attrs = os.lstat(path).st_file_attributes  # Windows only
    except (OSError, AttributeError):
        return False
    return bool(attrs & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def is_private(path: Path, info: os.stat_result | None = None) -> bool:
    """True if no other ordinary account can read `path`."""
    if IS_WINDOWS:
        return aces_are_private(_win32().read_aces(Path(path)), _win32().user_sid())
    info = info or os.lstat(path)
    return not info.st_mode & 0o077


def check_secret_file(path: Path) -> os.stat_result:
    """lstat a secret, refusing links/reparse points and shared files."""
    info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or (IS_WINDOWS and _is_reparse_point(path)):
        raise PortabilityError(f"refusing non-regular key file {Path(path).name}")
    if not is_private(path, info):
        hint = "run chmod 600" if not IS_WINDOWS else "restrict it to your Windows account"
        raise PortabilityError(f"key file {Path(path).name} is readable by other users; {hint}")
    return info


# --------------------------------------------------------------------------
# Per-user directories
# --------------------------------------------------------------------------

def user_data_root(app_posix: str, app_windows: str) -> tuple[Path, Path]:
    """(data, config) directories for this user.

    Linux: XDG (``~/.local/share/<app>``, ``~/.config/<app>``).
    Windows: both under ``%LOCALAPPDATA%\\<App>``. Not ``%APPDATA%``
    (Roaming): the conductor identity and DNA pins are bound to this
    machine's conductor and must not roam to another computer.
    """
    if IS_WINDOWS:
        base = os.environ.get("LOCALAPPDATA")
        root = Path(base) if base and Path(base).is_absolute() else Path.home() / "AppData" / "Local"
        root = root / app_windows
        return root / "data", root / "config"

    def xdg(name: str, fallback: str) -> Path:
        value = os.environ.get(name)
        return Path(value) if value and Path(value).is_absolute() else Path.home() / fallback
    return xdg("XDG_DATA_HOME", ".local/share") / app_posix, xdg("XDG_CONFIG_HOME", ".config") / app_posix


def python_for_children() -> str:
    """The interpreter to run Python helpers with (console-less on Windows)."""
    return sys.executable
