#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>

#include <errno.h>
#include <assert.h>

#include "winapi.h"

static const char* Path_delimiter =
#ifdef _MSC_VER
    ";"
#else
    ":"
#endif
;
static const char* Path_variable = "PATH";

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
init_library_calls(void)
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
    static char* path;
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
    return pri.ProcessHandle;
}

_pid_t
native_waitpid(_pid_t wpid, int* status, int options)
{
    DWORD res;

    if (!(options & WUNTRACED)) {
        errno = EINVAL;
        return (_pid_t)-1;
    }

    res = STILL_ACTIVE;
    while (res == STILL_ACTIVE) {
        // wait for a signal
        res = WaitForSingleObject(wpid, INFINITE);
        if (res == WAIT_FAILED)
            return (_pid_t)-1;
        assert(res == WAIT_OBJECT_0);

        // check signal reason
        if (GetExitCodeProcess(wpid, &res) == 0)
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
    HANDLE res;
    int _fd = (int) oldd;    // XXX: cast to int to silence gcc

    switch (_fd) {
        case STDIN_FILENO: return native_dup(GetStdHandle(STD_INPUT_HANDLE));
        case STDOUT_FILENO: return native_dup(GetStdHandle(STD_OUTPUT_HANDLE));
        case STDERR_FILENO: return native_dup(GetStdHandle(STD_ERROR_HANDLE));
    }

    HANDLE hProcess = GetCurrentProcess();
    if (!DuplicateHandle(hProcess, oldd, hProcess, &res, 0, TRUE, DUPLICATE_SAME_ACCESS))
        return (_pfd)-1;
    return res;
}

_pfd
native_dup2(_pfd oldd, _pfd newd)
{
    HANDLE res;
    if (newd)
        CloseHandle(newd);

    res = native_dup(oldd);
    switch ((int)newd) {
        case STDIN_FILENO: SetStdHandle(STD_INPUT_HANDLE, res); break;
        case STDOUT_FILENO: SetStdHandle(STD_OUTPUT_HANDLE, res); break;
        case STDERR_FILENO: SetStdHandle(STD_ERROR_HANDLE, res); break;
    }
    return res;
}

int
native_close(_pfd fd)
{
    int _fd = (int) fd; // XXX: cast to int to silence gcc
    switch (_fd) {
        case STDIN_FILENO: return native_close(GetStdHandle(STD_INPUT_HANDLE));
        case STDOUT_FILENO: return native_close(GetStdHandle(STD_OUTPUT_HANDLE));
        case STDERR_FILENO: return native_close(GetStdHandle(STD_ERROR_HANDLE));
    }
    return CloseHandle(fd)? 0 : -1;
}

int
//native_pipe(_pfd fildes[2])
native_pipe(_pfd* fildes)
{
    SECURITY_ATTRIBUTES attr;
    assert(fildes != NULL);

    attr.nLength = sizeof(attr);
    attr.lpSecurityDescriptor = NULL;
    attr.bInheritHandle = TRUE;

    if (CreatePipe(&fildes[0], &fildes[1], &attr, 0) == 0)
        return -1;

    if (SetHandleInformation(fildes[0], HANDLE_FLAG_INHERIT, 0) == 0)
        return -1;

    return 0;
}

int
native_execv(const char* path, char* const argv[])
{
    return native_execve(path, argv, environ);
}

int
native_execve(const char* path, char* const argv[], char*const envp[])
{
    return -1;
}

int
native_execvp(const char *file, char *const argv[])
{
    /* FIXME: search the path */
    return -1;
}

_pid_t
native_setsid(void)
{
    return (_pid_t)-1;
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
