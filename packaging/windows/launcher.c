/*
 * Holochain Music launcher for Windows (counterpart of packaging/holochain-music.sh).
 *
 *   HolochainMusic.exe   (built with -DHM_GUI, -mwindows): Start-menu entry.
 *                         Runs runtime\pythonw.exe, so no console window.
 *   holochain-music.exe  (console): the CLI, e.g. `holochain-music.exe status`.
 *
 * Both resolve the installation relative to their own path and run only the
 * bundled interpreter in isolated mode (-I: ignores PYTHONPATH and user
 * site-packages), in UTF-8 mode, with the bundled packages from python\ (via
 * the runtime's ._pth file). No shell is involved; arguments are passed on
 * verbatim.
 */
#define WIN32_LEAN_AND_MEAN
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#include <windows.h>
#include <stdio.h>
#include <wchar.h>

#define CMD_MAX 32767

static const wchar_t *skip_argv0(const wchar_t *p)
{
    if (*p == L'"') {
        for (++p; *p && *p != L'"'; ++p) {}
        if (*p == L'"') ++p;
    } else {
        while (*p && *p != L' ' && *p != L'\t') ++p;
    }
    while (*p == L' ' || *p == L'\t') ++p;
    return p;
}

static void fail(const wchar_t *what)
{
#ifdef HM_GUI
    wchar_t msg[512];
    _snwprintf(msg, 511, L"Holochain Music could not start (%ls, error %lu).\n\n"
               L"Reinstall the application or see %%LOCALAPPDATA%%\\HolochainMusic\\data\\logs.",
               what, GetLastError());
    msg[511] = 0;
    MessageBoxW(NULL, msg, L"Holochain Music", MB_ICONERROR | MB_OK);
#else
    fwprintf(stderr, L"holochain-music: %ls (error %lu)\n", what, GetLastError());
#endif
}

static int run(void)
{
    static wchar_t dir[MAX_PATH * 4];
    static wchar_t cmd[CMD_MAX];
    DWORD n = GetModuleFileNameW(NULL, dir, (DWORD)(sizeof dir / sizeof dir[0]));
    if (n == 0 || n >= sizeof dir / sizeof dir[0]) { fail(L"cannot resolve the install folder"); return 1; }
    wchar_t *slash = wcsrchr(dir, L'\\');
    if (!slash) { fail(L"cannot resolve the install folder"); return 1; }
    *slash = 0;

#ifdef HM_GUI
    const wchar_t *interp = L"pythonw.exe";
#else
    const wchar_t *interp = L"python.exe";
#endif
    const wchar_t *rest = skip_argv0(GetCommandLineW());
    int len = _snwprintf(cmd, CMD_MAX - 1, L"\"%ls\\runtime\\%ls\" -I -X utf8 -m holochain_music%ls%ls",
                         dir, interp, *rest ? L" " : L"", rest);
    if (len < 0) { fail(L"command line too long"); return 1; }
    cmd[CMD_MAX - 1] = 0;

    wchar_t exe[MAX_PATH * 4 + 32];
    _snwprintf(exe, sizeof exe / sizeof exe[0] - 1, L"%ls\\runtime\\%ls", dir, interp);
    exe[sizeof exe / sizeof exe[0] - 1] = 0;

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof si);
    si.cb = sizeof si;
    ZeroMemory(&pi, sizeof pi);
#ifdef HM_GUI
    DWORD flags = 0;
#else
    /* Console: the app (and, via nested jobs, its conductor/bridge/MoQ
     * children) lives in a kill-on-close job, so ending this launcher - by
     * Ctrl+C, closing the console or a kill - never orphans the app. */
    DWORD flags = CREATE_SUSPENDED;
    HANDLE job = CreateJobObjectW(NULL, NULL);
    if (job) {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits;
        ZeroMemory(&limits, sizeof limits);
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof limits);
    }
#endif
    /* Working directory = install folder; the app never writes there. */
    if (!CreateProcessW(exe, cmd, NULL, NULL, TRUE, flags, NULL, dir, &si, &pi)) {
        fail(L"cannot start the bundled Python runtime");
        return 1;
    }
#ifdef HM_GUI
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
#else
    if (job && !AssignProcessToJobObject(job, pi.hProcess)) {
        /* e.g. already inside a job that forbids nesting (pre-Windows 8) */
        CloseHandle(job);
        job = NULL;
    }
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    /* Console: let Ctrl+C reach the child (same console), wait, forward exit code. */
    SetConsoleCtrlHandler(NULL, TRUE);
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = 1;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    return (int)code;
#endif
}

#ifdef HM_GUI
int WINAPI wWinMain(HINSTANCE h, HINSTANCE p, PWSTR c, int s)
{
    (void)h; (void)p; (void)c; (void)s;
    return run();
}
#else
int wmain(void)
{
    return run();
}
#endif
