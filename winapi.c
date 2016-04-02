#include <windows.h>
#include <sys/wait.h>
#include <sys/signal.h>

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>

#include <fcntl.h>
#include <errno.h>
#include <assert.h>

#include "winapi.h"

#ifdef __CYGWIN__
#include <sys/cygwin.h>
#endif

/** globals */
pf_NtRtlCloneUserProcess CloneUserProcess;
pf_NtRtlCreateProcessReflection CreateProcessReflection;
pf_NtQueryInformationProcess QueryInformationProcess;
pf_NtUnicodeStringToAnsiString UnicodeStringToAnsiString;
pf_RtlFreeAnsiString FreeAnsiString;
pf_NtQuerySystemInformation QuerySystemInformation;
pf_NtQueryObject QueryObject;
pf_LdrpInitializeProcess LdrpInitializeProcess;
//const size_t o_LdrpInitializeProcess = 0x474f9;
//const size_t o_LdrpInitialize = 0x39336;
#define o_LdrpInitializeProcess 0x474f9
#define o_LdrpInitialize 0x39336

struct import_t { PCHAR name; size_t offset; void* target; };

static LPVOID ntdll_base;
static struct import_t Ntdll_Imports[] =
{
    {"RtlCloneUserProcess", 0, &CloneUserProcess},
    {"RtlCreateProcessReflection", 0, &CreateProcessReflection},
    {"ZwQueryInformationProcess", 0, &QueryInformationProcess},
    {"RtlUnicodeStringToAnsiString", 0, &UnicodeStringToAnsiString},
    {"RtlFreeAnsiString", 0, &FreeAnsiString},
    {"NtQuerySystemInformation", 0, &QuerySystemInformation},
    {"NtQueryObject", 0, &QueryObject},
    {NULL, o_LdrpInitializeProcess, &LdrpInitializeProcess},
    {NULL, o_LdrpInitialize, NULL},
    {NULL, 0, NULL}
};

/** constructor */
__attribute__((noreturn))
static void 
fatal(const char* fmt, ...)
{
    va_list va;
    va_start(va, fmt);
    vfprintf(stderr, fmt, va);
    fprintf(stderr, "\n");
    va_end(va);
    exit(errno);
    DebugBreak();
}

__attribute__((constructor))
void
native_init(void)
{
    struct import_t* imp;
    FARPROC fp;

    ntdll_base = LoadLibrary("ntdll.dll");
    if (ntdll_base == NULL)
        fatal("LoadLibrary(\"ntdll.dll\") = %x", ntdll_base);

    for (imp = &Ntdll_Imports[0]; imp->target != NULL; imp++) {
        fp = imp->name?
            GetProcAddress(ntdll_base, imp->name) :
            ntdll_base+imp->offset
        ;
        if (fp == NULL)
            fatal("GetProcAddress(\"ntdll.dll\", \"%s\") failed!", imp->name);
        memcpy(imp->target, &fp, sizeof(fp));
    }
}

int
whereExt(const char* path, char** result)
{
    static const char* PathExt_variable = "PATHEXT";
    static const char* PathExt_delimiter = ";";
    int res;
    char* pathext, *ext;
    char* fullpath;
    char* wherextst;

    assert(result != NULL);
    *result = NULL;

    if (access(path, X_OK) == 0) {
        *result = strdup(path);
        return 1;
    }

    pathext = strdup(getenv(PathExt_variable)? getenv(PathExt_variable) : "");
    if (pathext == NULL)
        return -ENOMEM;
    res = 0;

    ext = strtok_r(pathext, PathExt_delimiter, &wherextst);
    while (ext != NULL) {
        fullpath = malloc(strlen(path) + strlen(ext) + sizeof(""));
        if (fullpath == NULL) {
            res = -ENOMEM;
            goto leaving;
        }
        strcpy(fullpath, path);
        strcat(fullpath, ext);

        if (access(fullpath, X_OK) == 0) {
            *result = fullpath;
            res = 1;
            goto leaving;
        }

        free(fullpath);
        ext = strtok_r(NULL, PathExt_delimiter, &wherextst);
    }
    res = 0;

leaving:
    free(pathext);
    return res;
}

int
where(const char* cmd, char** result)
{
    // build-platform specific environment variables
    static const char* Path_variable = "PATH";
    static const char* Path_delimiter =
    #ifdef _MSC_VER
        ";"
    #else
        ":"
    #endif
    ;

    // regular variable definitions
    char* path;
    char* p; char* s, *sext;
    char* wherest;

    assert(result != NULL);
    *result = NULL;

    if (access(cmd, X_OK) == 0) {
        *result = strdup(cmd);
        return 1;
    }

    path = strdup(getenv(Path_variable)? getenv(Path_variable) : "");
    if (path == NULL)
        return -ENOMEM;

    p = strtok_r(path, Path_delimiter, &wherest);
    while (p != NULL) {
        s = malloc(strlen(p) + strlen(cmd) + sizeof(Path_delimiter));
        if (s == NULL) {
            free(path);
            return -ENOMEM;
        }

        strcpy(s, p);
        strcat(s, "/");

        if (whereExt(strcat(s,cmd), &sext) == 1) {
            free(s); s = sext; break;
        }
        free(sext);

        free(s); s = NULL;
        p = strtok_r(NULL, Path_delimiter, &wherest);
    }
    *result = p? s : NULL;
    free(path);
    return (s == NULL)? 0 : 1;
}

void
yield()
{
    int prio = GetThreadPriority(GetCurrentThread());
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_IDLE);
    Sleep(0);
    SetThreadPriority(GetCurrentThread(), prio);
}

void
block()
{
    (void)WaitForSingleObject(GetCurrentProcess(), INFINITE);
}

LPVOID
_get_PebBaseAddress(HANDLE hProcess)
{
    PROCESS_BASIC_INFORMATION pbi; ULONG sz;

    if (QueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &sz) != ERROR_SUCCESS)
        return NULL;
    if (sz != sizeof(pbi))
        return NULL;

    return pbi.PebBaseAddress;
}

static inline
int
_from_descriptor(void* fd, HANDLE* result)
{
    intptr_t res = (intptr_t)fd;
    static const DWORD StdHandleTable[] = { STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE };

    if (res < 0 || !(res < 3)) {
        errno = EINVAL;
        return -1;
    }
    assert(res < sizeof(StdHandleTable)/sizeof(StdHandleTable[0]) );
    *result = GetStdHandle(StdHandleTable[res]);
    return *result == INVALID_HANDLE_VALUE? -1 : 0;
}

static inline
int
_to_descriptor(HANDLE source, void* fd)
{
    intptr_t res = (intptr_t)fd;
    static const DWORD StdHandleTable[] = { STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE };

    if (res < 0 || !(res < 3)) {
        errno = EINVAL;
        return -1;
    }
    // FIXME: int cygwin_attach_handle_to_fd(char* name, int fd, HANDLE handle, mode_t bin, DWORD myaccess)

    assert(res < sizeof(StdHandleTable)/sizeof(StdHandleTable[0]) );
    return SetStdHandle(StdHandleTable[res], source)? 0 : -1;
}

static int
_copy_memorypages(HANDLE hChild, LPVOID ptr)
{
    PVOID p; SIZE_T size;
    MEMORY_BASIC_INFORMATION mbi; DWORD oProtect;
    memset(&mbi, 0, sizeof(mbi));

    if (VirtualQuery(ptr, &mbi, sizeof(mbi)) != sizeof(mbi))
        return -1;
    assert(ptr == mbi.BaseAddress);

    // allocate
    p = VirtualAllocEx(hChild, mbi.BaseAddress, mbi.RegionSize, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
    if (p == NULL)
        return -1;
    if (p != mbi.BaseAddress)
        goto fail;

    // copy it
    if (!WriteProcessMemory(hChild, mbi.BaseAddress, mbi.BaseAddress, mbi.RegionSize, &size))
        goto fail;
    if (size != mbi.RegionSize)
        goto fail;

    // restore perms
    if (!VirtualProtectEx(hChild, mbi.BaseAddress, mbi.RegionSize, mbi.Protect, &oProtect))
        goto fail;
    return 0;

fail:
    if (!VirtualFreeEx(hChild, mbi.BaseAddress, 0, MEM_RELEASE))
        return -2;
    return -1;
}

/** fork internals */
struct _fork_shared {
    HANDLE hStdin, hStdout, hStderr;
};
static const size_t _fork_shared_size = sizeof(struct _fork_shared);

static int
_fork_prepare_child(HANDLE hChild, HANDLE hData)
{
    // this can have side-effects upon failure
    int res;
    struct _fork_shared* shared;
    HANDLE hCurrentProcess = GetCurrentProcess();
    HANDLE handle;

    struct _PEB* peb = _get_PebBaseAddress(hCurrentProcess);
#if 0
    struct _PEB cPeb; SIZE_T cPeb_size;

    // platform state
    if (ReadProcessMemory(hChild, _get_PebBaseAddress(hChild),
            &cPeb, sizeof(cPeb), &cPeb_size) == FALSE)
        return -1;
    assert(cPeb_size == sizeof(cPeb));
#endif

    /*
    +0x04c ReadOnlySharedMemoryBase : Ptr32 Void
    ...
    +0x054 ReadOnlyStaticServerData : Ptr32 Ptr32 Void
    */
    res = _copy_memorypages(hChild, *(PVOID*)((char*)(peb)+0x4c));
    assert(res == 0);

    // user-defined data
    shared = MapViewOfFile(hData, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    if (shared == NULL)
        return -1;

    handle = GetStdHandle(STD_INPUT_HANDLE);
    assert( handle != INVALID_HANDLE_VALUE );
    assert( DuplicateHandle(hCurrentProcess, handle, hChild, &shared->hStdin, 0, TRUE, DUPLICATE_SAME_ACCESS) != 0);

    handle = GetStdHandle(STD_OUTPUT_HANDLE);
    assert( handle != INVALID_HANDLE_VALUE );
    assert( DuplicateHandle(hCurrentProcess, handle, hChild, &shared->hStdout, 0, TRUE, DUPLICATE_SAME_ACCESS) != 0 );

    handle = GetStdHandle(STD_ERROR_HANDLE);
    assert( handle != INVALID_HANDLE_VALUE );
    assert( DuplicateHandle(hCurrentProcess, handle, hChild, &shared->hStderr, 0, TRUE, DUPLICATE_SAME_ACCESS) != 0 );

    if (UnmapViewOfFile(shared) == FALSE)
        return -1;
    return 0;
}

static int
_fork_child_entry(HANDLE hData)
{
    struct _fork_shared* shared;

    shared = MapViewOfFile(hData, FILE_MAP_READ, 0, 0, 0);
    if (shared == NULL)
        return -1;

    // snag handles that parent has duped for us
    assert( _to_descriptor(shared->hStdin, (void*)STDIN_FILENO) >= 0);
    assert( _to_descriptor(shared->hStdout, (void*)STDOUT_FILENO) >= 0);
    assert( _to_descriptor(shared->hStderr, (void*)STDERR_FILENO) >= 0);

#if defined(__CYGWIN__)
    // re-initialize cygwin
    dll_dllcrt0();
#endif
#if defined(__CYGWIN__) && defined(_NATIVE_)
    _fork_override_cygwin_exceptions();
#endif

    if (UnmapViewOfFile(shared) == FALSE)
        return -1;
    return 0;
}

#if defined(__CYGWIN__) && defined(_NATIVE_)
LONG CALLBACK
_fork_cygwin_exception_handler(PEXCEPTION_POINTERS ExceptionInfo)
{
    DWORD errorCode;
    errorCode = ExceptionInfo->ExceptionRecord->ExceptionCode;
    ExitProcess(errorCode);
//    return EXCEPTION_CONTINUE_EXECUTION;
}

LONG CALLBACK
_fork_cygwin_continue_handler(PEXCEPTION_POINTERS ExceptionInfo)
{
    DWORD errorCode;
    errorCode = ExceptionInfo->ExceptionRecord->ExceptionCode;
    return EXCEPTION_CONTINUE_SEARCH;
}

int
_fork_override_cygwin_exceptions()
{
    HANDLE hr;
    hr = AddVectoredExceptionHandler(1, &_fork_cygwin_exception_handler);
    assert(hr != NULL);
    hr = AddVectoredContinueHandler(1, &_fork_cygwin_continue_handler);
    assert(hr != NULL);
}

#else // defined(__CYGWIN__) && defined(_NATIVE_)

int
_fork_override_cygwin_exceptions()
{
    return 0;
}

#endif // defined(__CYGWIN__) && defined(_NATIVE_)

#ifdef _NATIVE_
_pid_t
native_fork(void)
{
	RTL_USER_PROCESS_INFORMATION pri;
	NTSTATUS hr; int res;

    HANDLE hFile, ev; SECURITY_ATTRIBUTES attr;
    memset(&attr, 0, sizeof attr);

    // create event and shared page
    attr.nLength = sizeof(attr);
    attr.lpSecurityDescriptor = NULL;
    attr.bInheritHandle = TRUE;

    if ((ev = CreateEvent(&attr, FALSE, FALSE, NULL)) == NULL)
        goto fail;
    hFile = CreateFileMapping(INVALID_HANDLE_VALUE, &attr,
        PAGE_EXECUTE_READWRITE,
        (_fork_shared_size >> 32) & 0xffffffff, (_fork_shared_size & 0xffffffff),
        NULL);
    if (hFile == NULL)
        goto fail_event;

    // clone process
	hr = CloneUserProcess(
        RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED | RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES,
        NULL, NULL, NULL, &pri
    );
    if (!((hr == RTL_CLONE_PARENT) || (hr == RTL_CLONE_CHILD)))
        goto fail_shmem;

    // child
	if (hr == RTL_CLONE_CHILD) {
        if (WaitForSingleObject(ev, INFINITE) != WAIT_OBJECT_0)
            goto fail_process;
        CloseHandle(ev);
        CloseHandle(pri.ProcessHandle); CloseHandle(pri.ThreadHandle);

        // This is the only clean way I've found to re-allocate the handles
        //   that ntdll keeps open to some registry keys and other things..
        hr = LdrpInitializeProcess(NULL, ntdll_base);

        _fork_child_entry(hFile);
        CloseHandle(hFile);
        return 0;
    }

    // parent
    assert(hr == RTL_CLONE_PARENT);
    ResumeThread(pri.ThreadHandle); CloseHandle(pri.ThreadHandle);

    res = _fork_prepare_child(pri.ProcessHandle, hFile);
    if ((res < 0) || (SetEvent(ev) == FALSE))
        TerminateProcess(pri.ProcessHandle, -1);
    CloseHandle(ev); CloseHandle(hFile);

    if (res < 0) {
        CloseHandle(pri.ProcessHandle);
        return (_pid_t) -1;
    }
    return (_pid_t) pri.ProcessHandle;

fail_process:
    CloseHandle(pri.ThreadHandle);
    CloseHandle(pri.ProcessHandle);

fail_shmem: CloseHandle(hFile);
fail_event: CloseHandle(ev);
fail:
    // FIXME: set errno to some kind of error so that this actually will work
    return (_pid_t) -1;
}
#else
void _shm_restore(DWORD pid);

_pid_t
native_fork(void)
{
    int res;
    DWORD pid = cygwin_internal(CW_CYGWIN_PID_TO_WINPID, getpid());
    
    res = fork();
    if (res == 0) {
        _shm_restore(pid);
    }
    return res;
}
#endif

_pid_t
native_waitpid(_pid_t wpid, int* status, int options)
{
    DWORD res; HANDLE _wpid = (HANDLE) wpid;

    assert(wpid > 0);

    if (!(options & WUNTRACED)) {
        errno = EINVAL;
        return (_pid_t)-1;
    }

    res = STILL_ACTIVE;
    while (res == STILL_ACTIVE) {
        // wait for a signal
        res = WaitForSingleObject(_wpid, INFINITE);
        if (res == WAIT_FAILED)
            return (_pid_t)-1;
        assert(res == WAIT_OBJECT_0);

        // check signal reason
        if (GetExitCodeProcess(_wpid, &res) == 0)
            return (_pid_t)-1;

        if (res == STILL_ACTIVE)
            continue;

        /// store termination reason (FIXME: is this correct?)
        int winfo, wcode;

        // exception (use the high-byte as an error code)
        if ((res & 0xc0000000) == 0xc0000000) {
            wcode = (res >> 30) & 3; winfo = res & 0x3fffffff;

        // some other error
        } else if ((res & 0x80000000) == 0x80000000) {
            wcode = (res >> 30) & 3; winfo = res & 0x3fffffff;

        // terminated ok
        } else {

            wcode = 0; winfo = res & 0x3fffffff;
        }
        
#if defined(__CYGWIN__)
        // from cygwin/wait.h
        /* A status is 16 bits, and looks like:
              <1 byte info> <1 byte code>

              <code> == 0, child has exited, info is the exit value
              <code> == 1..7e, child has exited, info is the signal number.
              <code> == 7f, child has stopped, info was the signal number.
              <code> == 80, there was a core dump.
        */
        *status = (wcode&0xff) | ((winfo&0xff)<<8);
#elif defined(__MINGW32__)
        // from sys/wait.h
        /* A status looks like:
              <2 bytes info> <2 bytes code>

              <code> == 0, child has exited, info is the exit value
              <code> == 1..7e, child has exited, info is the signal number.
              <code> == 7f, child has stopped, info was the signal number.
              <code> == 80, there was a core dump.
        */
        *status = (wcode&0xffff) | ((winfo&0xffff)<<16);
#else
    #error "Unsupported status format"
#endif
        break;

    }
    return wpid;
}

_pfd
native_dup(_pfd oldd)
{
    HANDLE fd, res;

    if (_from_descriptor(oldd, &fd) == -1)
        return (_pfd)-1;

    HANDLE hProcess = GetCurrentProcess();
    if (!DuplicateHandle(hProcess, fd, hProcess, &res, 0, TRUE, DUPLICATE_SAME_ACCESS))
        return (_pfd)-1;
    assert(((intptr_t)res & 3) != (intptr_t)res); // ensure that returned handle is not a magic value (should be aligned to 4 anyways)
    return (_pfd)res;
}

_pfd
native_dup2(_pfd oldd, _pfd newd)
{
    HANDLE hTarget;
    HANDLE res;

    if (_from_descriptor(newd, &hTarget) == 0)
        CloseHandle(hTarget);
    res = (HANDLE) native_dup(oldd);
    if (_to_descriptor(res, newd) == -1)
        return (_pfd)-1;
    return (_pfd)res;
}

int
_open_dev(const char* device_path, int flags, mode_t mode)
{
    // FIXME: open up a device, and then call cygwin_attach_handle_to_fd
    return open(device_path, flags, mode);
}

int
native_open(const char* path, int flags, ...)
{
    // magic for file path prefixes
    static const char* Dev_prefix = "/dev/";
    va_list va; mode_t mode;
    
    // figure out the mode_t
    if (flags & O_CREAT) {
        va_start(va, flags);
            mode = va_arg(va, mode_t);
        va_end(va);
    } else {
        mode = umask(0); (void)umask(mode);
    }

    // check if we're trying to open a special path, if not..then passthrough.
    //     XXX: implement something table based so we can do /sys/ and /proc/
    if (memcmp(path, Dev_prefix, sizeof(Dev_prefix)-1) != 0)
        return open(path, flags, mode);

    // we're opening up /dev/
    return _open_dev(path, flags, mode);
}

ssize_t
native_read(_pfd fd, void* buf, size_t nbytes)
{
    DWORD sz; HANDLE _fd;
    assert(buf != NULL);

    if (_from_descriptor(fd, &_fd) == -1)
        return -1;

    if (ReadFile(_fd, buf, nbytes, &sz, NULL) == FALSE) {
        errno = EIO;    // XXX
        return -1;
    }
    return sz;
}

ssize_t
native_write(_pfd fd, const void* buf, size_t nbytes)
{
    DWORD sz; HANDLE _fd;
    assert(buf != NULL);

    if (_from_descriptor(fd, &_fd) == -1)
        return -1;

    if (WriteFile(_fd, buf, nbytes, &sz, NULL) == FALSE) {
        errno = EIO;    // XXX
        return -1;
    }
    return sz;
}

int
native_close(_pfd fd)
{
    HANDLE _fd;
    if (_from_descriptor(fd, &_fd) == -1)
        return -1;

    return CloseHandle(_fd)? 0 : -1;
}

int
//native_pipe(_pfd fildes[2])
native_pipe(_pfd* fildes)
{
    SECURITY_ATTRIBUTES attr;
    HANDLE _fildes[2];
    assert(fildes != NULL);

    attr.nLength = sizeof(attr);
    attr.lpSecurityDescriptor = NULL;
    attr.bInheritHandle = TRUE;

    if (CreatePipe(&_fildes[0], &_fildes[1], &attr, 0) == 0)
        return -1;

    if (SetHandleInformation(_fildes[0], HANDLE_FLAG_INHERIT, 0) == 0) {
        CloseHandle(_fildes[0]); CloseHandle(_fildes[1]);
        return -1;
    }

#ifdef __CYGWIN__
    // FIXME: int cygwin_attach_handle_to_fd(char* name, int fd, HANDLE handle, mode_t bin, DWORD myaccess)
#endif
    fildes[0] = (_pfd)_fildes[0]; fildes[1] = (_pfd)_fildes[1];
    return 0;
}

int
native_execv(const char* path, char* const argv[])
{
    return native_execve(path, argv, environ);
}

int
native_execve(const char* posixpath, char* const argv[], char*const envp[])
{
    static const char delimiter[] = " ";
    static const char terminator[] = "\x00";

    char* commandline, *environment;
    STARTUPINFO si; PROCESS_INFORMATION pi;
    DWORD exitCode;

    char*const* p; size_t length;
    char* path;

    #ifdef __CYGWIN__
    ssize_t cygsz;
    char* cygpath;
    #endif

    memset(&si, 0, sizeof(si));
    memset(&pi, 0, sizeof(pi));

    #ifdef __CYGWIN__
        // convert from posix path to windows path
        cygsz = cygwin_conv_path(CCP_POSIX_TO_WIN_A, posixpath, NULL, 0);
        if (cygsz < 0)
            goto fail;

        cygpath = malloc(cygsz);
        if (cygpath == NULL)
            goto fail;

        if (cygwin_conv_path(CCP_POSIX_TO_WIN_A, posixpath, cygpath, cygsz) < 0) {
            free(cygpath);
            goto fail;
        }
        path = cygpath;
    #else
        path = strdup(posixpath);
        if (path == NULL)
            goto fail;
    #endif

    // build commandline
    length = strlen(path)+sizeof(delimiter);
    if (argv[0])
        for (p = &argv[1]; *p != NULL; p++)
            length += strlen(*p) + sizeof(delimiter);

    commandline = malloc(length);
    if (commandline == NULL) {
        errno = ENOMEM;
        goto fail;
    }

    strcpy(commandline, path);
    if (argv[0])
        for (p = &argv[1]; *p != NULL; p++) {
            strcat(commandline, delimiter);
            strcat(commandline, *p);
        }

    // build environment
    length = sizeof(terminator)*2;
    for (p = &envp[0]; *p != NULL; p++)
        length += strlen(*p) + sizeof("");

    environment = malloc(length);
    if (environment == NULL) {
        errno = ENOMEM;
        goto fail_commandline;
    }

    length = 0;
    for (p = &envp[0]; *p != NULL; p++) {
        strcpy(&environment[length], *p);
        length += strlen(*p) + sizeof("");
    }
    memcpy(&environment[length], terminator, sizeof(terminator)); length += sizeof(terminator);
    memcpy(&environment[length], terminator, sizeof(terminator)); length += sizeof(terminator);
    
    // create the process
    si.cb = sizeof(si);

        // XXX: maybe we should hollow out our process in order to preserve our pid..
        //      or we could figure out how to map to cygwin's task<->pid table
    if (CreateProcess(NULL, commandline, NULL, NULL, TRUE, 0,
                        environment, NULL, &si, &pi) == FALSE)
    {
        errno = GetLastError();
        goto fail_environment;
    }

    do {
        WaitForSingleObject(pi.hProcess, INFINITE);
        GetExitCodeProcess(pi.hProcess, &exitCode);
    } while (exitCode != STILL_ACTIVE);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    ExitProcess(exitCode);
    DebugBreak();

fail_environment:
    free(environment);

fail_commandline:
    free(commandline);
    free(path);

fail:
    return -1;
}

int
native_execvp(const char *file, char *const argv[])
{
    int res;
    char* path;

    res = where(file, &path);
    if (res == -1)
        return -1;

    if (res < 0) {
        errno = ENOENT;
        goto fail;
    }

    res = native_execv(path, argv);
    free(path);
    return res;

fail:
    if (path) free(path);
    return -1;
}

_pid_t
native_setsid(void)
{
    return (_pid_t)-1;
}

int
native_kill(_pid_t pid, int sig)
{
    UINT code;
    HANDLE _pid = (HANDLE) pid;

    if (!pid || (pid == INVALID_HANDLE_VALUE)) {
        errno = EINVAL;
        return -1;
    }

    // XXX: map sig to an exit code
    code = sig;
    switch(sig) {
        case SIGUSR1: case SIGUSR2:
            code |= 0x200;
            break;

        case SIGABRT: case SIGQUIT: case SIGTERM: case SIGKILL:
            code |= 0x80000000;
            break;

        default:
            code |= 0xc0000000;
    }

    if (TerminateProcess(_pid, code) == FALSE) {
        errno = GetLastError();
        return -1;
    }
    return 0;
}

/** shm internals */
struct _shm_cache {
    int identifier;
    HANDLE handle;
    struct _shm_cache* next;

    void* _address;
    DWORD _access;
};

#define SHM_PREFIX "winapi-shm-"

// wraps _shm_tail out of the global namespace
struct _shm_cache*
__shm_get(int index)
{
    static struct _shm_cache _shm_head = { -1, INVALID_HANDLE_VALUE, NULL };

    struct _shm_cache* p = &_shm_head;
    while ((index-- > 0) && (p != NULL))
        p = p->next;
    return p;
}

struct _shm_cache*
__shm_push(int identifier, HANDLE handle)
{
    struct _shm_cache* head = __shm_get(0);
    struct _shm_cache* p;

    if ((p = malloc(sizeof *p)) == NULL)
        return NULL;

    memcpy(p, head, sizeof *p);
    head->identifier = identifier;
    head->handle = handle;
    head->next = p;

    head->_address = NULL;
    head->_access = 0;
    return head;
}

struct _shm_cache*
__shm_find(int identifier)
{
    struct _shm_cache* p = __shm_get(0);
    while (p->next != NULL) {
        if (p->identifier == identifier)
            return p;
        p = p->next;
    }
    return NULL;
}

HANDLE
_shm_create(int identifier, size_t size)
{
    HANDLE hFile; SECURITY_ATTRIBUTES attr;
    char* name;

    // ensure id is not in cache
    if (__shm_find(identifier) != NULL) {
        errno = EEXIST;
        return INVALID_HANDLE_VALUE;
    }

    // generate a key name
    if (asprintf(&name, "Local\\"SHM_PREFIX"%d", identifier) == -1) {
        errno = ENOMEM;
        return INVALID_HANDLE_VALUE;
    }

    // create file mapping
    memset(&attr, 0, sizeof(attr));
    attr.nLength = sizeof(attr);
    attr.bInheritHandle = TRUE;

    hFile = CreateFileMapping(INVALID_HANDLE_VALUE, &attr,
        PAGE_EXECUTE_READWRITE,
        0, size,
        name);

    free(name);
    if (hFile == NULL)
        return INVALID_HANDLE_VALUE;

    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(hFile);
        return INVALID_HANDLE_VALUE;
    }

    // store handle and identifier in cache
    if (__shm_push(identifier, hFile) != NULL)
        return hFile;

    // ack!
    CloseHandle(hFile);
    errno = ENOMEM;
    return INVALID_HANDLE_VALUE;
}

HANDLE
_shm_open(int identifier)
{
    HANDLE hFile;
    char* name;
    struct _shm_cache* p;
    
    // if id is in cache..
    if ((p = __shm_find(identifier)) != NULL)
        return p->handle;

    // generate a key name
    if (asprintf(&name, "Local\\"SHM_PREFIX"%d", identifier) == -1) {
        errno = ENOMEM;
        return INVALID_HANDLE_VALUE;
    }

#ifdef __CYGWIN__
//int cygwin_attach_handle_to_fd(char* name, int fd, HANDLE handle, mode_t bin, DWORD myaccess);
#endif

    // fetch the mapping
    hFile = OpenFileMapping(FILE_MAP_ALL_ACCESS, FALSE, name);
    free(name);
    if (hFile == NULL)
        return INVALID_HANDLE_VALUE;

    // whee
    if (__shm_push(identifier, hFile) != NULL)
        return hFile;

    CloseHandle(hFile);
    errno = ENOMEM;
    return INVALID_HANDLE_VALUE;
}

int
_shm_close(int identifier)
{
    struct _shm_cache* p, *n;

    p = __shm_find(identifier);
    if (p == NULL)
        return -1;

    n = p->next;
    CloseHandle(p->handle);
    memcpy(p, n, sizeof *p);
    free(n);
    return 0;
}

void
_shm_restore(DWORD pid)
{
    struct _shm_cache* ch = __shm_get(0);
    LPVOID p;

    HANDLE handle, hParent = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);

    if (hParent == NULL)
        fatal("OpenProcess(PROCESS_DUP_HANDLE, FALSE, %x)", pid);

    // go through and map all shared memory back into the address-space
    while (ch->next != NULL) {

        // copy the handle from the parent
        if (!DuplicateHandle(hParent, ch->handle, GetCurrentProcess(), &handle, 0, FALSE, DUPLICATE_SAME_ACCESS))
            fatal("DuplicateHandle(%p, %p, %p, %p, 0, FALSE, DUPLICATE_SAME_ACCESS)", hParent, ch->handle, GetCurrentProcess(), &handle);
        ch->handle = handle;

        // if there's no address, then skip
        if (ch->_address == NULL)
            continue;

        // check to see if something is in the way so we can rudely remove it.
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(ch->_address, &mbi, sizeof(mbi)) != sizeof(mbi))
            fatal("VirtualQuery(%p, %p, %x) -> %x", ch->_address, &mbi, sizeof(mbi), GetLastError());

        if (mbi.State != MEM_FREE) {
            switch(mbi.Type) {
                case MEM_IMAGE:
                    fatal("MEMORY_BASIC_INFORMATION.Type == MEM_IMAGE");
                    break;
                    
                case MEM_MAPPED:
                    if (!UnmapViewOfFile(mbi.BaseAddress))
                        fatal("UnmapViewOfFile(%p) -> %x", mbi.BaseAddress, GetLastError());
                    break;

                case MEM_PRIVATE:
                    if (!VirtualFree(mbi.AllocationBase, mbi.RegionSize, MEM_RELEASE))
                        fatal("VirtualFree(%p, %x, MEM_RELEASE) -> %x", mbi.AllocationBase, mbi.RegionSize, GetLastError());
                    break;
            }
        }
        
        // now map our shmem back to the expected address
        p = MapViewOfFileEx(ch->handle, ch->_access, 0, 0, 0, ch->_address);
        if (p != ch->_address)
            fatal("MapViewOfFileEx(%p, %x, 0, 0, 0, %p) returned %p -> %x", ch->handle, ch->_access, ch->_address, p, GetLastError());

        // iterate to next mapping
        ch = ch->next;
    }
}

/** shm wrappers */

// FIXME: key and id are actually treated the same here..
//          it shouldn't matter since we're not supporting IPC_EXCL
int
native_shmget(_key_t key, size_t size, int shmflg)
{
    HANDLE hFile;
    int res;

    if ((key == IPC_PRIVATE) && !(shmflg & IPC_CREAT)) {
        errno = EINVAL;
        return -1;
    }

    if (key == IPC_PRIVATE)
        res = random() ^ GetCurrentProcessId(); // FIXME: predictable, but whatev
    else
        res = (int) key;

    hFile = (shmflg & IPC_CREAT)? _shm_create(res, size) : _shm_open(res);
    if (hFile == INVALID_HANDLE_VALUE)
        return -1;
    return res;
}

int
native_shmctl(int shmid, int cmd, void* buf)
{
    enum _shmcmd_t _cmd = cmd;
    switch (_cmd) {
        case IPC_STAT:
        case IPC_SET:
            errno = EINVAL;
            return -1;
        default:
            break;
    }
    assert(_cmd == IPC_RMID);

    if (_shm_close(shmid) == -1)
        return -1;
    return 0;
}

void*
native_shmat(int shmid, const void* shmaddr, int shmflg)
{
    HANDLE hFile;
    DWORD axxs; LPVOID p;

    if ((shmid == -1) || (shmaddr != NULL) ||
        (shmflg && !(shmflg & SHM_RDONLY)))
    {
        errno = EINVAL;
        return (void*)-1;
    }
    hFile = _shm_open(shmid);
    if (hFile == INVALID_HANDLE_VALUE) {
        errno = ENOENT;
        return (void*)-1;
    }

    struct _shm_cache* ch = __shm_find(shmid);
    if (ch->_address)
        return ch->_address;

    axxs = ch->_access = shmflg? FILE_MAP_READ : FILE_MAP_READ|FILE_MAP_WRITE;
    p = ch->_address = MapViewOfFile(hFile, axxs, 0, 0, 0);
    if (p == NULL) {
        errno = ENOTSUP;
        return (void*)-1;
    }
    return p;
}

int
native_shmdt(const void* shmaddr)
{
    if (UnmapViewOfFile(shmaddr))
        return 0;
    errno = EINVAL;
    return -1;
}

/** mutex */
int
mtx_init(mtx_t* mtx, int type)
{
    HANDLE hMutex;
    SECURITY_ATTRIBUTES attr;
    assert(mtx != NULL);

    memset(&attr, 0, sizeof(attr));
    attr.nLength = sizeof(attr);
    attr.bInheritHandle = TRUE;

    hMutex = CreateMutex(&attr, FALSE, NULL);
    if (hMutex == NULL)
        return -1;

    mtx->h = hMutex;
    mtx->t = type;
    return 0;
}

void
mtx_destroy(mtx_t* mtx)
{
    assert(mtx != NULL);
    CloseHandle(mtx->h);
}

int
mtx_lock(mtx_t* mtx)
{
    HANDLE hMutex = mtx->h;
    DWORD dwResult;
    assert(hMutex != INVALID_HANDLE_VALUE);

    dwResult = WaitForSingleObject(hMutex, INFINITE);
    if ((dwResult == WAIT_FAILED) || (dwResult == WAIT_ABANDONED))
        return -1;
    assert(dwResult == WAIT_OBJECT_0);  // != WAIT_TIMEOUT
    return 0;
}

int
mtx_timedlock(mtx_t* mtx, const struct timespec* ts)
{
    HANDLE hMutex = mtx->h;
    DWORD dwResult, dwMilliseconds;
    assert(hMutex != INVALID_HANDLE_VALUE);
/*
    ts->tv_sec  // seconds
    ts->tv_nsec // nanoseconds
*/

    dwMilliseconds = (ts->tv_nsec / 1000000) + (ts->tv_sec * 1000);

    dwResult = WaitForSingleObject(hMutex, dwMilliseconds);
    if ((dwResult == WAIT_FAILED) || (dwResult == WAIT_ABANDONED))
        return -1;
    return 0;
}

int
mtx_trylock(mtx_t* mtx)
{
    HANDLE hMutex = mtx->h;
    DWORD dwResult;
    assert(hMutex != INVALID_HANDLE_VALUE);

    dwResult = WaitForSingleObject(hMutex, 0);
    if ((dwResult == WAIT_FAILED) || (dwResult == WAIT_ABANDONED))
        return -1;

    return 0;
}

int
mtx_unlock(mtx_t* mtx)
{
    HANDLE hMutex = mtx->h;
    if (ReleaseMutex(hMutex) == FALSE)
        return -1;
    return 0;
}
