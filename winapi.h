#ifndef __winapi_h
#define __winapi_h

#include <windows.h>
#include <winternl.h>
#include <ntdef.h>
#include <sys/types.h>

#ifdef __CYGWIN__
#include <sys/cygwin.h>
#endif

#define DebugMark(...) do {   \
    printf("[%s:%d] Debug attach to %u<%3$x>\n",__FILE__,__LINE__,(unsigned)GetCurrentProcessId());   \
    __asm__("jmp .\nmovl %0, %%eax\n" :: "i" (__LINE__) : "eax"); \
} while (0)

/** posix types */
#ifdef _WIN32
    typedef HANDLE _pfd;        // dual posix file-descriptor and HANDLE
    typedef HANDLE _pid_t;      // really a HANDLE to a process

//        #define pid_t _pid_t
#else
    typedef int _pfd;       // really an fd
    typedef int _pid_t;     // really a posix pid
/*
    #if defined(HAVE_PID_T)
        typedef DWORD _pid_t;
        #define pid_t _pid_t      // gcc blows because here it wants to treats a
                                  //     cpp define as a type definition...
    #else
        typedef DWORD pid_t;
    #endif
*/
#endif

/** posix wrappers */
_pid_t native_fork();
_pid_t native_waitpid(_pid_t, int*, int);
_pfd native_dup(_pfd);
_pfd native_dup2(_pfd, _pfd);
int native_open(const char*, int, ...);
ssize_t native_read(_pfd, void*, size_t);
ssize_t native_write(_pfd, const void*, size_t);
int native_close(_pfd);
int native_pipe(_pfd*);
int native_execv(const char*, char* const[]);
int native_execve(const char*, char* const[], char*const[]);
int native_execvp(const char *, char *const[]);

/** shm wrappers */
#ifdef _SYS_SHM_H
    #error __FILE__ "needs to be included before <sys/shm.h>"
#endif
#define _SYS_SHM_H   // prevent <sys/shm.h> from being included

typedef enum { IPC_PRIVATE } _key_t;
//_shmflg_t
#define IPC_CREAT 0x0200
#define IPC_EXCL 0x0400
#define SHM_RDONLY 0x01
enum _shmcmd_t { IPC_STAT, IPC_SET, IPC_RMID };

int native_shmget(_key_t, size_t, int);
void* native_shmat(int, const void*, int);
int native_shmdt(const void*);
//int native_shmctl(int, int, struct shmid_ds*);
int native_shmctl(int, int, void*);

/** mutex wrappers */
#define restrict
enum mtx_type { mtx_timed, mtx_plain };
typedef struct { HANDLE h; enum mtx_type t; } mtx_t;

int mtx_init(mtx_t*, int);
void mtx_destroy(mtx_t*);
int mtx_lock(mtx_t*);
int mtx_timedlock(mtx_t* restrict, const struct timespec* restrict);
int mtx_trylock(mtx_t*);
int mtx_unlock(mtx_t*);

/** api defines */
#define RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED 0x00000001
#define RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES 0x00000002
#define RTL_CLONE_PROCESS_FLAGS_NO_SYNCHRONIZE 0x00000004 // don't update synchronization objects
#define RTL_CLONE_PROCESS_FLAGS_EXECUTE_CALLBACK 0x00000008

#define RTL_CLONE_PARENT				0
#define RTL_CLONE_CHILD					297

/** api structures */
typedef struct _SECTION_IMAGE_INFORMATION
{
    PVOID TransferAddress;
    ULONG ZeroBits;
    ULONG MaximumStackSize;
    ULONG CommittedStackSize;
    ULONG SubSystemType;
    union
    {
        struct
        {
            USHORT SubSystemMinorVersion;
            USHORT SubSystemMajorVersion;
        };
        ULONG SubSystemVersion;
    };
    ULONG GpValue;
    USHORT ImageCharacteristics;
    USHORT DllCharacteristics;
    USHORT Machine;
    UCHAR ImageContainsCode;
    union
    {
        struct
        {
            UCHAR ComPlusNativeReady:1;
            UCHAR ComPlusILOnly:1;
            UCHAR ImageDynamicallyRelocated:1;
            UCHAR ImageMappedFlat:1;
            UCHAR Reserved:4;
        };
        UCHAR ImageFlags;
    };
    ULONG LoaderFlags;
    ULONG ImageFileSize;
    ULONG CheckSum;
} SECTION_IMAGE_INFORMATION, *PSECTION_IMAGE_INFORMATION;

typedef struct _RTL_USER_PROCESS_INFORMATION
{
    ULONG Size;
    HANDLE ProcessHandle;
    HANDLE ThreadHandle;
    CLIENT_ID ClientId;
    SECTION_IMAGE_INFORMATION ImageInformation;
} RTL_USER_PROCESS_INFORMATION, *PRTL_USER_PROCESS_INFORMATION;

typedef struct _RTL_PROCESS_REFLECTION_INFORMATION
{
    HANDLE Process;
    HANDLE Thread;
    CLIENT_ID ClientId;
} RTL_PROCESS_REFLECTION_INFORMATION, *PRTL_PROCESS_REFLECTION_INFORMATION;

/** api types */
typedef NTSTATUS (WINAPI *pf_NtRtlCloneUserProcess)(ULONG, PSECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR, HANDLE, PRTL_USER_PROCESS_INFORMATION);
typedef NTSTATUS (WINAPI *pf_NtRtlCreateProcessReflection)(HANDLE, ULONG, PVOID, PVOID, HANDLE, PRTL_PROCESS_REFLECTION_INFORMATION);
typedef NTSTATUS (WINAPI *pf_NtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS (WINAPI *pf_NtUnicodeStringToAnsiString)(PANSI_STRING, PCUNICODE_STRING, BOOLEAN);
typedef NTSTATUS (WINAPI *pf_RtlFreeAnsiString)(PANSI_STRING);
typedef NTSTATUS (WINAPI *pf_NtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS (WINAPI *pf_NtQueryObject)(HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS (WINAPI *pf_LdrpInitializeProcess)(PCONTEXT, PVOID);

/** api */
extern pf_NtRtlCloneUserProcess CloneUserProcess;
extern pf_NtRtlCreateProcessReflection CreateProcessReflection;
extern pf_NtQueryInformationProcess QueryInformationProcess;
extern pf_NtUnicodeStringToAnsiString UnicodeStringToAnsiString;
extern pf_RtlFreeAnsiString FreeAnsiString;
extern pf_NtQuerySystemInformation QuerySystemInformation;
extern pf_NtQueryObject QueryObject;
extern pf_LdrpInitializeProcess LdrpInitializeProcess;

/** redefinitions */
#include <sys/shm.h>
#define shmctl native_shmctl
#define shmget native_shmget
#define shmat native_shmat
#include <unistd.h>
#define fork native_fork
#define execv native_execv
#include <sys/wait.h>
#define waitpid native_waitpid
#include <signal.h>
#define kill native_kill

#endif
