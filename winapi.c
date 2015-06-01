#include <windows.h>

#include <sys/signal.h>

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>

#include <fcntl.h>
#include <errno.h>
#include <assert.h>

#include "winapi.h"

/** globals */
pf_NtRtlCloneUserProcess CloneUserProcess;
pf_NtRtlCreateProcessReflection CreateProcessReflection;
pf_NtQueryInformationProcess QueryInformationProcess;
pf_NtUnicodeStringToAnsiString UnicodeStringToAnsiString;
pf_RtlFreeAnsiString FreeAnsiString;
pf_NtQuerySystemInformation QuerySystemInformation;
pf_NtQueryObject QueryObject;

struct import_t { PCHAR name; void* target; };

static struct import_t Ntdll_Imports[] =
{
    {"RtlCloneUserProcess", &CloneUserProcess},
    {"RtlCreateProcessReflection", &CreateProcessReflection},
    {"ZwQueryInformationProcess", &QueryInformationProcess},
    {"RtlUnicodeStringToAnsiString", &UnicodeStringToAnsiString},
    {"RtlFreeAnsiString", &FreeAnsiString},
    {"NtQuerySystemInformation", &QuerySystemInformation},
    {"NtQueryObject", &QueryObject},
    {NULL, NULL}
};

/** constructor */
__attribute__((noreturn))
static void 
fatal(const char* fmt, ...)
{
    va_list va;
    va_start(va, fmt);
    vfprintf(stderr, fmt, va);
    va_end(va);
    exit(errno);
    for(;;);
}

__attribute__((constructor))
void
init(void)
{
    struct import_t* imp;
    HMODULE h; FARPROC fp;

    h = LoadLibrary("ntdll.dll");
    if (h == NULL)
        fatal("LoadLibrary(\"ntdll.dll\") = %x", h);

    for (imp = &Ntdll_Imports[0]; imp->name != NULL; imp++) {
        fp = GetProcAddress(h, imp->name);
        if (fp == NULL)
            fatal("GetProcAddress(\"ntdll.dll\", \"%s\") failed!", imp->name);
        memcpy(imp->target, &fp, sizeof(fp));
    }
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
    char* p; char* s;

    assert(result != NULL);
    *result = NULL;

    if (access(cmd, X_OK) == 0) {
        *result = strdup(cmd);
        return 1;
    }

    path = strdup(getenv(Path_variable)? getenv(Path_variable) : "");
    if (path == NULL)
        return ENOMEM;

    p = strtok(path, Path_delimiter);
    while (p != NULL) {
        s = malloc(strlen(p) + strlen(cmd) + sizeof(Path_delimiter));
        if (s == NULL) {
            free(path);
            return ENOMEM;
        }

        strcpy(s, p);
        strcat(s, "/");

        if (access(strcat(s, cmd), X_OK) == 0)
            break;

        free(s); s = NULL;
        p = strtok(NULL, Path_delimiter);
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

/** posix wrappers */
_pid_t
native_fork()
{
	RTL_USER_PROCESS_INFORMATION pri;
	NTSTATUS hr;

	hr = CloneUserProcess(
        RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED | RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES,
        NULL, NULL, NULL, &pri
    );
    if ((hr != RTL_CLONE_PARENT) && (hr != RTL_CLONE_CHILD))
        return (_pfd)-1;

	if (hr == RTL_CLONE_CHILD) {
        CloseHandle(pri.ThreadHandle);
        CloseHandle(pri.ProcessHandle);
        return 0;
    }

    assert(hr == RTL_CLONE_PARENT);
    ResumeThread(pri.ThreadHandle);
    CloseHandle(pri.ThreadHandle);
    return (_pid_t) pri.ProcessHandle;
}

_pid_t
native_waitpid(_pid_t wpid, int* status, int options)
{
    DWORD res; HANDLE _wpid = (HANDLE) wpid;

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

static inline       // XXX: this could be made more performant (table-lookup on demand) if we had c++'s templates or overloading
int
_from_descriptor(int fd, HANDLE* result)
{
    static const DWORD StdHandleTable[] = { STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE };
    if (fd != (fd & 3)) {
        errno = EINVAL;
        return -1;
    }
    assert( (fd & 3) <= sizeof(StdHandleTable)/sizeof(StdHandleTable[0]) );
    *result = GetStdHandle(StdHandleTable[fd&3]);
    return 0;
}

static inline       // XXX: this could be made more performant (lookup on demand) if we had c++'s templates or overloading
int
_to_descriptor(HANDLE source, int target)
{
    static const DWORD StdHandleTable[] = { STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE };
    if (target != (target & 3)) {
        errno = EINVAL;
        return -1;
    }
    // FIXME: int cygwin_attach_handle_to_fd(char* name, int fd, HANDLE handle, mode_t bin, DWORD myaccess)

    assert( (target & 3) <= sizeof(StdHandleTable)/sizeof(StdHandleTable[0]) );
    SetStdHandle(StdHandleTable[target&3], source);
    return 0;
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
    assert(((int)(res) & 3) != (int)res); // ensure that returned handle is not a magic value (should be aligned to 4 anyways)
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

    fildes[0] = (_pfd)_fildes[0]; fildes[1] = (_pfd)_fildes[1];
    return 0;
}

_pid_t
native_execv(const char* path, char* const argv[])
{
    return native_execve(path, argv, environ);
}

_pid_t
native_execve(const char* path, char* const argv[], char*const envp[])
{
    static const char delimiter[] = " ";
    static const char terminator[] = "\x00";

    char* commandline, *environment;
    STARTUPINFO si; PROCESS_INFORMATION pi;

    char*const* p; size_t length;

    memset(&si, 0, sizeof(si));
    memset(&pi, 0, sizeof(pi));

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

    printf("Executing: %s\n", commandline);
/*
    printf("Environment:\n");
    int i;
    for (i = 0; i < length; i += strlen(&environment[i])+sizeof(""))
        printf("[%d] %s\n", i, &environment[i]);
*/
    
        // XXX: maybe we should hollow out our process in order to preserve our pid..
    if (CreateProcess(NULL, commandline, NULL, NULL, TRUE, 0,
                        environment, NULL, &si, &pi) == FALSE)
    {
        printf("Failed: %x\n", GetLastError());
        errno = GetLastError();
        goto fail_environment;
    }
    CloseHandle(pi.hThread);
    printf("Executed: %x/%x\n", pi.dwProcessId, pi.dwThreadId);
    return (_pid_t) pi.hProcess;

fail_environment:
    free(environment);

fail_commandline:
    free(commandline);

fail:
    return (_pid_t) INVALID_HANDLE_VALUE;
}

_pid_t
native_execvp(const char *file, char *const argv[])
{
    /* FIXME: search the path */
    int res; _pid_t result;
    char* path;

    res = where(file, &path);
    if (res == -1)
        return (_pid_t) INVALID_HANDLE_VALUE;

    if (res > 0) {
        errno = ENOENT;
        goto fail;
    }

    result = native_execv(path, argv);
    free(path);
    return result;

fail:
    if (path) free(path);
    return (_pid_t) INVALID_HANDLE_VALUE;
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

    if ((pid == 0) || (pid == -1)) {
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
    attr.bInheritHandle = FALSE;

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

/** shm wrappers */

// FIXME: key and id are actually treated the same here..
//          it shouldn't matter since we're not support IPC_EXCL
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
    axxs = shmflg? FILE_MAP_READ : FILE_MAP_READ|FILE_MAP_WRITE;

    hFile = _shm_open(shmid);
    if (hFile == INVALID_HANDLE_VALUE) {
        errno = ENOENT;
        return (void*)-1;
    }

    p = MapViewOfFile(hFile, axxs, 0, 0, 0);
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

    memset(&attr, 0, sizeof(attr));
    attr.nLength = sizeof(attr);
    attr.bInheritHandle = TRUE;

    hMutex = CreateMutex(&attr, FALSE, NULL);
    if (hMutex == NULL)
        return -1;
    return 0;
}

int
mtx_lock(mtx_t* mtx)
{
    HANDLE hMutex = mtx->h;
    DWORD dwResult;

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

/** passthrough wrappers */
void (*native_exit)(int) = exit;
char* (*native_getenv)(const char*) = getenv;
int (*native_atoi)(const char*) = atoi;
void (*native_init)(void) = init;
