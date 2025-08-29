#pragma once

#include "Dependencies.h"

typedef short CSHORT;

typedef struct _DISPATCHER_HEADER {
    union {
        struct {
            UCHAR Type;
            union {
                UCHAR Abandoned;
                UCHAR Absolute;
                UCHAR NpxIrql;
                UCHAR Signalling;
            };
            union {
                UCHAR Size;
                UCHAR Hand;
            };
            union {
                UCHAR Inserted;
                UCHAR DebugActive;
                UCHAR DpcActive;
            };
        };
        LONG Lock;
    };
    LONG SignalState;
    LIST_ENTRY WaitListHead;
} DISPATCHER_HEADER, * PDISPATCHER_HEADER;

typedef struct _KSEMAPHORE {
    DISPATCHER_HEADER Header;
    LONG Limit;
} KSEMAPHORE, * PKSEMAPHORE;

typedef struct _OWNER_ENTRY {
    ULONG OwnerThread;
    union {
        LONG OwnerCount;
        ULONG TableSize;
    };
} OWNER_ENTRY, * POWNER_ENTRY;

typedef struct _KEVENT {
    DISPATCHER_HEADER Header;
} KEVENT, * PKEVENT;

typedef struct _ERESOURCE {
    LIST_ENTRY SystemResourcesList;
    POWNER_ENTRY OwnerTable;
    SHORT ActiveCount;
    WORD Flag;
    PKSEMAPHORE SharedWaiters;
    PKEVENT ExclusiveWaiters;
    OWNER_ENTRY OwnerEntry;
    ULONG ActiveEntries;
    ULONG ContentionCount;
    ULONG NumberOfSharedWaiters;
    ULONG NumberOfExclusiveWaiters;
    union
    {
        PVOID Address;
        ULONG CreatorBackTraceIndex;
    };
    ULONG SpinLock;
} ERESOURCE, * PERESOURCE;

typedef enum _POOL_TYPE {
    NonPagedPool = 0,
    PagedPool = 1,
    NonPagedPoolMustSucceed = 2,
    DontUseThisType = 3,
    NonPagedPoolCacheAligned = 4,
    PagedPoolCacheAligned = 5,
    NonPagedPoolCacheAlignedMustS = 6,
    MaxPoolType = 7,
    NonPagedPoolSession = 32,
    PagedPoolSession = 33,
    NonPagedPoolMustSucceedSession = 34,
    DontUseThisTypeSession = 35,
    NonPagedPoolCacheAlignedSession = 36,
    PagedPoolCacheAlignedSession = 37,
    NonPagedPoolCacheAlignedMustSSession = 38
} POOL_TYPE;

typedef struct _OBJECT_TYPE_INITIALIZER {
    WORD Length;
    UCHAR ObjectTypeFlags;
    ULONG CaseInsensitive : 1;
    ULONG UnnamedObjectsOnly : 1;
    ULONG UseDefaultObject : 1;
    ULONG SecurityRequired : 1;
    ULONG MaintainHandleCount : 1;
    ULONG MaintainTypeList : 1;
    ULONG ObjectTypeCode;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccessMask;
    POOL_TYPE PoolType;
    ULONG DefaultPagedPoolCharge;
    ULONG DefaultNonPagedPoolCharge;
    PVOID DumpProcedure;
    LONG* OpenProcedure;
    PVOID CloseProcedure;
    PVOID DeleteProcedure;
    LONG* ParseProcedure;
    LONG* SecurityProcedure;
    LONG* QueryNameProcedure;
    UCHAR* OkayToCloseProcedure;
} OBJECT_TYPE_INITIALIZER, * POBJECT_TYPE_INITIALIZER;

typedef struct _EX_PUSH_LOCK {
    union {
        ULONG Locked : 1;
        ULONG Waiting : 1;
        ULONG Waking : 1;
        ULONG MultipleShared : 1;
        ULONG Shared : 28;
        ULONG Value;
        PVOID Ptr;
    };
} EX_PUSH_LOCK, * PEX_PUSH_LOCK;

typedef struct _OBJECT_TYPE {
    ERESOURCE Mutex;
    LIST_ENTRY TypeList;
    UNICODE_STRING Name;
    PVOID DefaultObject;
    ULONG Index;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    OBJECT_TYPE_INITIALIZER TypeInfo;
    ULONG Key;
    EX_PUSH_LOCK ObjectLocks[32];
} OBJECT_TYPE, * POBJECT_TYPE;

enum KPROCESSOR_MODE {
    KernelMode,
    UserMode,
};

typedef struct _OBJECT_HANDLE_INFORMATION {
    ULONG HandleAttributes;
    ULONG GrantedAccess;
} OBJECT_HANDLE_INFORMATION, * POBJECT_HANDLE_INFORMATION;

typedef struct _SECURITY_SUBJECT_CONTEXT {
    PACCESS_TOKEN                ClientToken;
    SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
    PACCESS_TOKEN                PrimaryToken;
    PVOID                        ProcessAuditId;
} SECURITY_SUBJECT_CONTEXT, * PSECURITY_SUBJECT_CONTEXT;

typedef struct _ACCESS_STATE {
    LUID                     OperationID;
    BOOLEAN                  SecurityEvaluated;
    BOOLEAN                  GenerateAudit;
    BOOLEAN                  GenerateOnClose;
    BOOLEAN                  PrivilegesAllocated;
    ULONG                    Flags;
    ACCESS_MASK              RemainingDesiredAccess;
    ACCESS_MASK              PreviouslyGrantedAccess;
    ACCESS_MASK              OriginalDesiredAccess;
    SECURITY_SUBJECT_CONTEXT SubjectSecurityContext;
    PSECURITY_DESCRIPTOR     SecurityDescriptor;
    PVOID                    AuxData;
    union {
        PRIVILEGE_SET        InitialPrivilegeSet;
        PRIVILEGE_SET        PrivilegeSet;
    } Privileges;
    BOOLEAN                  AuditPrivileges;
    UNICODE_STRING           ObjectName;
    UNICODE_STRING           ObjectTypeName;
} ACCESS_STATE, * PACCESS_STATE;

typedef UCHAR KIRQL;
typedef KIRQL* PKIRQL;

typedef enum _MM_PAGE_PRIORITY {
    LowPagePriority,
    NormalPagePriority = 16,
    HighPagePriority = 32
} MM_PAGE_PRIORITY;

typedef CLIENT_ID* PCLIENT_ID;

typedef struct _PROCESS_ACCESS_TOKEN {
    HANDLE                  Token;
    HANDLE                  Thread;
} PROCESS_ACCESS_TOKEN, * PPROCESS_ACCESS_TOKEN;

typedef enum _MEMORY_CACHING_TYPE {
    MmNonCached,
    MmCached,
    MmWriteCombined,
    MmHardwareCoherentCached,
    MmNonCachedUnordered,
    MmUSWCCached,
    MmMaximumCacheType,
    MmNotMapped
} MEMORY_CACHING_TYPE;

typedef enum _LOCK_OPERATION {
    IoReadAccess,
    IoWriteAccess,
    IoModifyAccess
} LOCK_OPERATION;

typedef struct _EPROCESS {
    UCHAR NotNeeded1[0x460];
    union {
        ULONG Flags2;
        struct {
            ULONG JobNotReallyActive : 1;
            ULONG AccountingFolded : 1;
            ULONG NewProcessReported : 1;
            ULONG ExitProcessReported : 1;
            ULONG ReportCommitChanges : 1;
            ULONG LastReportMemory : 1;
            ULONG ReportPhysicalPageChanges : 1;
            ULONG HandleTableRundown : 1;
            ULONG NeedsHandleRundown : 1;
            ULONG RefTraceEnabled : 1;
            ULONG NumaAware : 1;
            ULONG ProtectedProcess : 1;
            ULONG DefaultPagePriority : 3;
            ULONG PrimaryTokenFrozen : 1;
            ULONG ProcessVerifierTarget : 1;
            ULONG StackRandomizationDisabled : 1;
            ULONG AffinityPermanent : 1;
            ULONG AffinityUpdateEnable : 1;
            ULONG PropagateNode : 1;
            ULONG ExplicitAffinity : 1;
        };
    };
    UCHAR NotNeeded2[0x50];
} EPROCESS, * PEPROCESS;

typedef struct _MDL {
    struct _MDL* Next;
    CSHORT           Size;
    CSHORT           MdlFlags;
    struct _EPROCESS* Process;
    PVOID            MappedSystemVa;
    PVOID            StartVa;
    ULONG            ByteCount;
    ULONG            ByteOffset;
} MDL, * PMDL;

typedef struct _VPB {
    CSHORT                Type;
    CSHORT                Size;
    USHORT                Flags;
    USHORT                VolumeLabelLength;
    struct _DEVICE_OBJECT* DeviceObject;
    struct _DEVICE_OBJECT* RealDevice;
    ULONG                 SerialNumber;
    ULONG                 ReferenceCount;
    WCHAR                 VolumeLabel[MAXIMUM_VOLUME_LABEL_LENGTH / sizeof(WCHAR)];
} VPB, * PVPB;

typedef struct _KDEVICE_QUEUE_ENTRY {
    LIST_ENTRY DeviceListEntry;
    ULONG SortKey;
    UCHAR Inserted;
} KDEVICE_QUEUE_ENTRY, * PKDEVICE_QUEUE_ENTRY;

typedef struct _KDPC {
    UCHAR Type;
    UCHAR Importance;
    WORD Number;
    LIST_ENTRY DpcListEntry;
    PVOID DeferredRoutine;
    PVOID DeferredContext;
    PVOID SystemArgument1;
    PVOID SystemArgument2;
    PVOID DpcData;
} KDPC, * PKDPC;

typedef struct _WAIT_CONTEXT_BLOCK {
    union {
        KDEVICE_QUEUE_ENTRY WaitQueueEntry;
        struct {
            LIST_ENTRY DmaWaitEntry;
            ULONG      NumberOfChannels;
            ULONG      SyncCallback : 1;
            ULONG      DmaContext : 1;
            ULONG      ZeroMapRegisters : 1;
            ULONG      Reserved : 9;
            ULONG      NumberOfRemapPages : 20;
        };
    };
    DWORD64         DeviceRoutine; // pointer
    PVOID           DeviceContext;
    ULONG           NumberOfMapRegisters;
    PVOID           DeviceObject;
    PVOID           CurrentIrp;
    PKDPC           BufferChainingDpc;
} WAIT_CONTEXT_BLOCK, * PWAIT_CONTEXT_BLOCK;

typedef struct _KDEVICE_QUEUE {
    SHORT Type;
    SHORT Size;
    LIST_ENTRY DeviceListHead;
    ULONG Lock;
    UCHAR Busy;
} KDEVICE_QUEUE, * PKDEVICE_QUEUE;

typedef struct _DEVICE_OBJECT {
    CSHORT                   Type;
    USHORT                   Size;
    LONG                     ReferenceCount;
    struct _DRIVER_OBJECT* DriverObject;
    struct _DEVICE_OBJECT* NextDevice;
    struct _DEVICE_OBJECT* AttachedDevice;
    struct _IRP* CurrentIrp;
    DWORD64                  Timer;     // pointer
    ULONG                    Flags;
    ULONG                    Characteristics;
    __volatile PVPB          Vpb;
    PVOID                    DeviceExtension;
    DEVICE_TYPE              DeviceType;
    CCHAR                    StackSize;
    union {
        LIST_ENTRY         ListEntry;
        WAIT_CONTEXT_BLOCK Wcb;
    } Queue;
    ULONG                    AlignmentRequirement;
    KDEVICE_QUEUE            DeviceQueue;
    KDPC                     Dpc;
    ULONG                    ActiveThreadCount;
    PSECURITY_DESCRIPTOR     SecurityDescriptor;
    KEVENT                   DeviceLock;
    USHORT                   SectorSize;
    USHORT                   Spare1;
    struct _DEVOBJ_EXTENSION* DeviceObjectExtension;
    PVOID                    Reserved;
} DEVICE_OBJECT, * PDEVICE_OBJECT;

typedef struct _DRIVER_OBJECT {
    CSHORT             Type;
    CSHORT             Size;
    PDEVICE_OBJECT     DeviceObject;
    ULONG              Flags;
    PVOID              DriverStart;
    ULONG              DriverSize;
    PVOID              DriverSection;
    DWORD64            DriverExtension; // pointer
    UNICODE_STRING     DriverName;
    PUNICODE_STRING    HardwareDatabase;
    DWORD64            FastIoDispatch; // pointer
    DWORD64            DriverInit;      // function pointer 
    DWORD64            DriverStartIo;   // function pointer
    DWORD64            DriverUnload;    // function pointer
    DWORD64            MajorFunction[IRP_MJ_MAXIMUM_FUNCTION + 1]; // array to dispatch function
} DRIVER_OBJECT, * PDRIVER_OBJECT;

typedef NTSYSAPI NTSTATUS(NTAPI* _NtCreateToken)(OUT PHANDLE TokenHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES   ObjectAttributes, IN TOKEN_TYPE           TokenType, IN PLUID AuthenticationId, IN PLARGE_INTEGER       ExpirationTime, IN PTOKEN_USER          TokenUser, IN PTOKEN_GROUPS        TokenGroups, IN PTOKEN_PRIVILEGES    TokenPrivileges, IN PTOKEN_OWNER         TokenOwner, IN PTOKEN_PRIMARY_GROUP TokenPrimaryGroup, IN PTOKEN_DEFAULT_DACL  TokenDefaultDacl, IN PTOKEN_SOURCE        TokenSource);
typedef NTSYSAPI NTSTATUS(NTAPI* _NtAllocateLocallyUniqueId)(OUT PLUID LocallyUniqueId);

typedef struct _SECTION_OBJECT_POINTERS {
    PVOID DataSectionObject;
    PVOID SharedCacheMap;
    PVOID ImageSectionObject;
} SECTION_OBJECT_POINTERS, * PSECTION_OBJECT_POINTERS;

typedef struct _FILE_OBJECT {
    CSHORT                                Type;
    CSHORT                                Size;
    PDEVICE_OBJECT                        DeviceObject;
    PVPB                                  Vpb;
    PVOID                                 FsContext;
    PVOID                                 FsContext2;
    PSECTION_OBJECT_POINTERS              SectionObjectPointer;
    PVOID                                 PrivateCacheMap;
    NTSTATUS                              FinalStatus;
    struct _FILE_OBJECT* RelatedFileObject;
    BOOLEAN                               LockOperation;
    BOOLEAN                               DeletePending;
    BOOLEAN                               ReadAccess;
    BOOLEAN                               WriteAccess;
    BOOLEAN                               DeleteAccess;
    BOOLEAN                               SharedRead;
    BOOLEAN                               SharedWrite;
    BOOLEAN                               SharedDelete;
    ULONG                                 Flags;
    UNICODE_STRING                        FileName;
    LARGE_INTEGER                         CurrentByteOffset;
    __volatile ULONG                      Waiters;
    __volatile ULONG                      Busy;
    PVOID                                 LastLock;
    KEVENT                                Lock;
    KEVENT                                Event;
    __volatile DWORD64                       CompletionContext;//pointers
    KSPIN_LOCK                            IrpListLock;
    LIST_ENTRY                            IrpList;
    __volatile DWORD64                      FileObjectExtension;
    struct                                _IOP_FILE_OBJECT_EXTENSION;
} FILE_OBJECT, * PFILE_OBJECT;

typedef struct _KAPC {
    UCHAR Type;
    UCHAR SpareByte0;
    UCHAR Size;
    UCHAR SpareByte1;
    ULONG SpareLong0;
    DWORD64 Thread; // KTHREAD*
    LIST_ENTRY ApcListEntry;
    PVOID KernelRoutine;
    PVOID RundownRoutine;
    PVOID NormalRoutine;
    PVOID NormalContext;
    PVOID SystemArgument1;
    PVOID SystemArgument2;
    CHAR ApcStateIndex;
    CHAR ApcMode;
    UCHAR Inserted;
} KAPC, * PKAPC;

typedef struct _IRP {
    CSHORT                    Type;
    USHORT                    Size;
    PMDL                      MdlAddress;
    ULONG                     Flags;
    union {
        struct _IRP* MasterIrp;
        __volatile LONG IrpCount;
        PVOID           SystemBuffer;
    } AssociatedIrp;
    LIST_ENTRY                ThreadListEntry;
    IO_STATUS_BLOCK           IoStatus;
    KPROCESSOR_MODE           RequestorMode;
    BOOLEAN                   PendingReturned;
    CHAR                      StackCount;
    CHAR                      CurrentLocation;
    BOOLEAN                   Cancel;
    KIRQL                     CancelIrql;
    CCHAR                     ApcEnvironment;
    UCHAR                     AllocationFlags;
    union {
        PIO_STATUS_BLOCK UserIosb;
        PVOID            IoRingContext;
    };
    PKEVENT                   UserEvent;
    union {
        struct {
            union {
                PIO_APC_ROUTINE UserApcRoutine;
                PVOID           IssuingProcess;
            };
            union {
                PVOID                 UserApcContext;
                struct _IORING_OBJECT* IoRing;
            };
        } AsynchronousParameters;
        LARGE_INTEGER AllocationSize;
    } Overlay;
    __volatile DWORD64 CancelRoutine; // DRIVER_CANCEL*
    PVOID                     UserBuffer;
    union {
        struct {
            union {
                KDEVICE_QUEUE_ENTRY DeviceQueueEntry;
                struct {
                    PVOID DriverContext[4];
                };
            };
            DWORD64     Thread; // ETHREAD*
            PCHAR        AuxiliaryBuffer;
            struct {
                LIST_ENTRY ListEntry;
                union {
                    struct _IO_STACK_LOCATION* CurrentStackLocation;
                    ULONG                     PacketType;
                };
            };
            PFILE_OBJECT OriginalFileObject;
        } Overlay;
        KAPC  Apc;
        PVOID CompletionKey;
    } Tail;
} IRP, * PIRP;

DECLSPEC_ALIGN(8) typedef struct _DXGKWIN32K_INTERFACE {
    WORD	 Size; // 2
    WORD	 Magic; // 2
    DWORD64	 Null; // + 8
    PVOID	 pFn[0x1FE]; // + 16
}DXGKWIN32K_INTERFACE, * PDXGKWIN32K_INTERFACE;

typedef enum _EVENT_TYPE {
    NotificationEvent = 0,
    SynchronizationEvent = 1
} EVENT_TYPE;

typedef enum _KWAIT_REASON {
    Executive = 0,
    FreePage = 1,
    PageIn = 2,
    PoolAllocation = 3,
    DelayExecution = 4,
    Suspended = 5,
    UserRequest = 6,
    WrExecutive = 7,
    WrFreePage = 8,
    WrPageIn = 9,
    WrPoolAllocation = 10,
    WrDelayExecution = 11,
    WrSuspended = 12,
    WrUserRequest = 13,
    WrEventPair = 14,
    WrQueue = 15,
    WrLpcReceive = 16,
    WrLpcReply = 17,
    WrVirtualMemory = 18,
    WrPageOut = 19,
    WrRendezvous = 20,
    Spare2 = 21,
    Spare3 = 22,
    Spare4 = 23,
    Spare5 = 24,
    WrCalloutStack = 25,
    WrKernel = 26,
    WrResource = 27,
    WrPushLock = 28,
    WrMutex = 29,
    WrQuantumEnd = 30,
    WrDispatchInt = 31,
    WrPreempted = 32,
    WrYieldExecution = 33,
    WrFastMutex = 34,
    WrGuardedMutex = 35,
    WrRundown = 36,
    MaximumWaitReason = 37
} KWAIT_REASON;

typedef BOOLEAN(*fRtlEqualUnicodeString)(PCUNICODE_STRING, PCUNICODE_STRING, BOOLEAN);

typedef struct KAPC_STATE;

typedef KAPC_STATE* PRKAPC_STATE;

typedef struct _KTIMER {
    struct _DISPATCHER_HEADER Header;
    union _ULARGE_INTEGER DueTime;
    struct _LIST_ENTRY TimerListEntry;
    struct _KDPC* Dpc;
    ULONG Period;
} KTIMER, * PKTIMER;

typedef struct KPRCB {

};

typedef KPRCB* PKPRCB;

typedef struct _KTIMER_TABLE_ENTRY {
    unsigned __int64 Lock;
    LIST_ENTRY Entry;
    ULARGE_INTEGER Time;
} KTIMER_TABLE_ENTRY, * PKTIMER_TABLE_ENTRY;

struct _KTIMER_TABLE_STATE {
    ULONGLONG LastTimerExpiration[2];                                       //0x0
    ULONG LastTimerHand[2];                                                 //0x10
};

typedef struct _MM_PHYSICAL_ADDRESS_LIST {
    LARGE_INTEGER PhysicalAddress;
    SIZE_T           NumberOfBytes;
} MM_PHYSICAL_ADDRESS_LIST, * PMM_PHYSICAL_ADDRESS_LIST;

typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT, * PSECTION_INHERIT;