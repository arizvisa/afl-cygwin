#ifndef __winapi_h
#define __winapi_h

#include <windows.h>
#include <ntdef.h>

/** posix types */
#ifdef _WIN32
    typedef HANDLE _pfd; // posix file-descriptor
    typedef HANDLE _pid_t;

//        #define pid_t _pid_t
#else
    typedef int _pfd;
    typedef int _pid_t;
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
int native_close(_pfd);
int native_pipe(_pfd*);
int native_execv(const char*, char* const[]);
int native_execve(const char*, char* const[], char*const[]);
int native_execvp(const char *, char *const[]);

/** shm wrappers */
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

int mtx_init(mtx_t *mtx, int type);
int mtx_lock(mtx_t *mtx);
int mtx_timedlock(mtx_t * restrict mtx, const struct timespec * restrict ts);
int mtx_trylock(mtx_t *mtx);
int mtx_unlock(mtx_t *mtx);

/** api defines */
#define RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED 0x00000001
#define RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES 0x00000002
#define RTL_CLONE_PROCESS_FLAGS_NO_SYNCHRONIZE 0x00000004 // don't update synchronization objects
#define RTL_CLONE_PROCESS_FLAGS_EXECUTE_CALLBACK 0x00000008

#define RTL_CLONE_PARENT				0
#define RTL_CLONE_CHILD					297

/** api enums */
typedef enum _PROCESSINFOCLASS
{
    ProcessBasicInformation,
    ProcessQuotaLimits,
    ProcessIoCounters,
    ProcessVmCounters,
    ProcessTimes,
    ProcessBasePriority,
    ProcessRaisePriority,
    ProcessDebugPort,
    ProcessExceptionPort,
    ProcessAccessToken,
    ProcessLdtInformation,
    ProcessLdtSize,
    ProcessDefaultHardErrorMode,
    ProcessIoPortHandlers,
    ProcessPooledUsageAndLimits,
    ProcessWorkingSetWatch,
    ProcessUserModeIOPL,
    ProcessEnableAlignmentFaultFixup,
    ProcessPriorityClass,
    ProcessWx86Information,
    ProcessHandleCount,
    ProcessAffinityMask,
    ProcessPriorityBoost,
    ProcessDeviceMap,
    ProcessSessionInformation,
    ProcessForegroundInformation,
    ProcessWow64Information,
    ProcessImageFileName,
    ProcessLUIDDeviceMapsEnabled,
    ProcessBreakOnTermination,
    ProcessDebugObjectHandle,
    ProcessDebugFlags,
    ProcessHandleTracing,
    ProcessIoPriority,
    ProcessExecuteFlags,
    ProcessTlsInformation,
    ProcessCookie,
    ProcessImageInformation,
    ProcessCycleTime,
    ProcessPagePriority,
    ProcessInstrumentationCallback,
    MaxProcessInfoClass
} PROCESSINFOCLASS;

typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemBasicInformation,
    SystemProcessorInformation,
    SystemPerformanceInformation,
    SystemTimeOfDayInformation,
    SystemPathInformation, /// Obsolete: Use KUSER_SHARED_DATA
    SystemProcessInformation,
    SystemCallCountInformation,
    SystemDeviceInformation,
    SystemProcessorPerformanceInformation,
    SystemFlagsInformation,
    SystemCallTimeInformation,
    SystemModuleInformation,
    SystemLocksInformation,
    SystemStackTraceInformation,
    SystemPagedPoolInformation,
    SystemNonPagedPoolInformation,
    SystemHandleInformation,
    SystemObjectInformation,
    SystemPageFileInformation,
    SystemVdmInstemulInformation,
    SystemVdmBopInformation,
    SystemFileCacheInformation,
    SystemPoolTagInformation,
    SystemInterruptInformation,
    SystemDpcBehaviorInformation,
    SystemFullMemoryInformation,
    SystemLoadGdiDriverInformation,
    SystemUnloadGdiDriverInformation,
    SystemTimeAdjustmentInformation,
    SystemSummaryMemoryInformation,
    SystemMirrorMemoryInformation,
    SystemPerformanceTraceInformation,
    SystemObsolete0,
    SystemExceptionInformation,
    SystemCrashDumpStateInformation,
    SystemKernelDebuggerInformation,
    SystemContextSwitchInformation,
    SystemRegistryQuotaInformation,
    SystemExtendServiceTableInformation,
    SystemPrioritySeperation,
    SystemPlugPlayBusInformation,
    SystemDockInformation,
    SystemPowerInformationNative,
    SystemProcessorSpeedInformation,
    SystemCurrentTimeZoneInformation,
    SystemLookasideInformation,
    SystemTimeSlipNotification,
    SystemSessionCreate,
    SystemSessionDetach,
    SystemSessionInformation,
    SystemRangeStartInformation,
    SystemVerifierInformation,
    SystemAddVerifier,
    SystemSessionProcessesInformation,
    SystemLoadGdiDriverInSystemSpaceInformation,
    SystemNumaProcessorMap,
    SystemPrefetcherInformation,
    SystemExtendedProcessInformation,
    SystemRecommendedSharedDataAlignment,
    SystemComPlusPackage,
    SystemNumaAvailableMemory,
    SystemProcessorPowerInformation,
    SystemEmulationBasicInformation,
    SystemEmulationProcessorInformation,
    SystemExtendedHanfleInformation,
    SystemLostDelayedWriteInformation,
    SystemBigPoolInformation,
    SystemSessionPoolTagInformation,
    SystemSessionMappedViewInformation,
    SystemHotpatchInformation,
    SystemObjectSecurityMode,
    SystemWatchDogTimerHandler,
    SystemWatchDogTimerInformation,
    SystemLogicalProcessorInformation,
    SystemWo64SharedInformationObosolete,
    SystemRegisterFirmwareTableInformationHandler,
    SystemFirmwareTableInformation,
    SystemModuleInformationEx,
    SystemVerifierTriageInformation,
    SystemSuperfetchInformation,
    SystemMemoryListInformation,
    SystemFileCacheInformationEx,
    SystemThreadPriorityClientIdInformation,
    SystemProcessorIdleCycleTimeInformation,
    SystemVerifierCancellationInformation,
    SystemProcessorPowerInformationEx,
    SystemRefTraceInformation,
    SystemSpecialPoolInformation,
    SystemProcessIdInformation,
    SystemErrorPortInformation,
    SystemBootEnvironmentInformation,
    SystemHypervisorInformation,
    SystemVerifierInformationEx,
    SystemTimeZoneInformation,
    SystemImageFileExecutionOptionsInformation,
    SystemCoverageInformation,
    SystemPrefetchPathInformation,
    SystemVerifierFaultsInformation,
    MaxSystemInfoClass,
} SYSTEM_INFORMATION_CLASS;

typedef enum _OBJECT_INFORMATION_CLASS
{
    ObjectBasicInformation,
    ObjectNameInformation,
    ObjectTypeInformation,
    ObjectTypesInformation,
    ObjectHandleFlagInformation,
    ObjectSessionInformation,
    MaxObjectInfoClass
} OBJECT_INFORMATION_CLASS;

/** api structures */
typedef struct _CLIENT_ID
{
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID;

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

/** api */
extern pf_NtRtlCloneUserProcess CloneUserProcess;
extern pf_NtRtlCreateProcessReflection CreateProcessReflection;
extern pf_NtQueryInformationProcess QueryInformationProcess;
extern pf_NtUnicodeStringToAnsiString UnicodeStringToAnsiString;
extern pf_RtlFreeAnsiString FreeAnsiString;
extern pf_NtQuerySystemInformation QuerySystemInformation;
extern pf_NtQueryObject QueryObject;

#endif

