#pragma once
#include "Utils.h"
#include "FunctionBackend.h"
#include "KernelTypes.h"

namespace KernelFunction {
	typedef struct RVOID {};

	template <typename ReturnType, typename ...Args>
	class Function {
	public:
		Function(LPCSTR ProcName, FunctionBackend* func_back, Args... args) {
			if (!func_back->EnableHook()) {
				printf("[!] Failed to enable hook.\n");
				return;
			}

			DWORD64 FuncPtr = (DWORD64)func_back->CreatePointer(ProcName);
			if (!FuncPtr) {
				func_back->CleanupPointer();
				func_back->DisableHook();
				return;
			}

			typedef ReturnType(*FunctionTemplate)(Args...);

			FunctionTemplate func = (FunctionTemplate)FuncPtr;

			if (std::is_same<ReturnType, RVOID>::value) {
				func(args...);
			}
			else {
				result = func(args...);
			}

			func_back->CleanupPointer();
			func_back->DisableHook();
		}

		ReturnType result;
	};

	template <class ReturnType, typename ...Args>
	ReturnType KINVOKE(FunctionBackend* syscall_handler, LPCSTR ProcName, Args... args) {
		if (!std::is_same<ReturnType, RVOID>::value) {
			Function<ReturnType, Args...>* fn = new Function<ReturnType, Args...>(ProcName, syscall_handler, args...);
			return fn->result;
		}
		else {
			new Function<ReturnType, Args...>(ProcName, syscall_handler, args...);
			return ReturnType{};
		}
	}

	KIRQL KeGetCurrentIrql(FunctionBackend* USER_MODE_PARAM_ONLY);
	HANDLE PsGetCurrentProcessId(FunctionBackend* USER_MODE_PARAM_ONLY);
	HANDLE PsGetCurrentProcess(FunctionBackend* USER_MODE_PARAM_ONLY);
	LARGE_INTEGER MmGetPhysicalAddress(FunctionBackend* USER_MODE_PARAM_ONLY, PVOID BaseAddress);
	PVOID MmMapIoSpace(FunctionBackend* USER_MODE_PARAM_ONLY, LARGE_INTEGER PhysicalAddress, SIZE_T NumberOfBytes, MEMORY_CACHING_TYPE CacheType);
	void MmUnmapIoSpace(FunctionBackend* USER_MODE_PARAM_ONLY, PVOID BaseAddress, SIZE_T NumberOfBytes);
	NTSTATUS ObReferenceObjectByHandle(FunctionBackend* USER_MODE_PARAM_ONLY, HANDLE Handle, ACCESS_MASK DesiredAccess, POBJECT_TYPE ObjectType, KPROCESSOR_MODE AccessMode, PVOID* Object, POBJECT_HANDLE_INFORMATION HandleInformation);
	NTSTATUS ObOpenObjectByPointer(FunctionBackend* USER_MODE_PARAM_ONLY, PVOID Object, ULONG HandleAttributes, PACCESS_STATE PassedAccessState, ACCESS_MASK DesiredAccess, POBJECT_TYPE ObjectType, KPROCESSOR_MODE AccessMode, PHANDLE Handle);
	PMDL MmAllocatePagesForMdlEx(FunctionBackend* USER_MODE_PARAM_ONLY, LARGE_INTEGER LowAddress, LARGE_INTEGER HighAddress, LARGE_INTEGER SkipBytes, SIZE_T TotalBytes, MEMORY_CACHING_TYPE CacheType, ULONG Flags);
	PVOID MmMapLockedPagesSpecifyCache(FunctionBackend* USER_MODE_PARAM_ONLY, PMDL MemoryDescriptorList, KPROCESSOR_MODE AccessMode, MEMORY_CACHING_TYPE CacheType, PVOID RequestedAddress, ULONG BugCheckOnFailure, ULONG Priority);
	NTSTATUS MmProtectMdlSystemAddress(FunctionBackend* USER_MODE_PARAM_ONLY, PMDL MemoryDescriptorList, ULONG NewProtect);
	void MmUnmapLockedPages(FunctionBackend* USER_MODE_PARAM_ONLY, PVOID BaseAddress, PMDL MemoryDescriptorList);
	void MmFreePagesFromMdl(FunctionBackend* USER_MODE_PARAM_ONLY, PMDL MemoryDescriptorList);
	PVOID RtlFindExportedRoutineByName(FunctionBackend* USER_MODE_PARAM_ONLY, PVOID DllBase, PCHAR RoutineName);
	NTSTATUS NtOpenFile(FunctionBackend* USER_MODE_PARAM_ONLY, PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions);
	NTSTATUS ZwDeviceIoControlFile(FunctionBackend* USER_MODE_PARAM_ONLY, HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG IoControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength);
	NTSTATUS PsLookupProcessByProcessId(FunctionBackend* USER_MODE_PARAM_ONLY, HANDLE ProcessId, PEPROCESS* Process);
	NTSTATUS ZwOpenProcess(FunctionBackend* USER_MODE_PARAM_ONLY, PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
	NTSTATUS ZwOpenProcessTokenEx(FunctionBackend* USER_MODE_PARAM_ONLY, HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, PHANDLE TokenHandle);
	NTSTATUS ZwClose(FunctionBackend* USER_MODE_PARAM_ONLY, HANDLE Handle);
	NTSTATUS ZwDuplicateToken(FunctionBackend* USER_MODE_PARAM_ONLY, HANDLE ExistingTokenHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, BOOLEAN EffectiveOnly, TOKEN_TYPE TokenType, PHANDLE NewTokenHandle);
	NTSTATUS ZwSetInformationProcess(FunctionBackend* USER_MODE_PARAM_ONLY, HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength);
	NTSTATUS IoGetDeviceObjectPointer(FunctionBackend* USER_MODE_PARAM_ONLY, PUNICODE_STRING ObjectName, ACCESS_MASK DesiredAccess, PFILE_OBJECT* FileObject, PDEVICE_OBJECT* DeviceObject);
	PIRP IoBuildDeviceIoControlRequest(FunctionBackend* USER_MODE_PARAM_ONLY, ULONG IoControlCode, PDEVICE_OBJECT DeviceObject, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, BOOLEAN InternalDeviceIoControl, PKEVENT Event, PIO_STATUS_BLOCK IoStatusBlock);
	void KeInitializeEvent(FunctionBackend* USER_MODE_PARAM_ONLY, PKEVENT Event, EVENT_TYPE Type, BOOLEAN State);
	NTSTATUS KeWaitForSingleObject(FunctionBackend* USER_MODE_PARAM_ONLY, PVOID Object, KWAIT_REASON WaitReason, KPROCESSOR_MODE WaitMode, BOOLEAN Alertable, PLARGE_INTEGER Timeout);
	NTSTATUS IofCallDriver(FunctionBackend* USER_MODE_PARAM_ONLY, PDEVICE_OBJECT DeviceObject, PIRP Irp);
	PVOID ExAllocatePoolWithTag(FunctionBackend* USER_MODE_PARAM_ONLY, POOL_TYPE PoolType, SIZE_T NumberOfBytes, ULONG Tag);
	void ExFreePool(FunctionBackend* USER_MODE_PARAM_ONLY, PVOID P);
	NTSTATUS ZwProtectVirtualMemory(FunctionBackend* USER_MODE_PARAM_ONLY, HANDLE ProcessHandle, PVOID* BaseAddress, PULONG NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection);
	NTSTATUS MmCopyVirtualMemory(FunctionBackend* USER_MODE_PARAM_ONLY, PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);
	PVOID MmGetSystemRoutineAddress(FunctionBackend* USER_MODE_PARAM_ONLY, PUNICODE_STRING SystemRoutineName);
	PPEB PsGetProcessPeb(FunctionBackend* USER_MODE_PARAM_ONLY, PEPROCESS Process);
	void KeStackAttachProcess(FunctionBackend* USER_MODE_PARAM_ONLY, PEPROCESS PROCESS, PRKAPC_STATE ApcState);
	void KeUnstackDetachProcess(FunctionBackend* USER_MODE_PARAM_ONLY, PRKAPC_STATE ApcState);
	PVOID MmAllocateContiguousMemory(FunctionBackend* USER_MODE_PARAM_ONLY, SIZE_T NumberOfBytes, LARGE_INTEGER HighestAcceptableAddress);
	void MmFreeContiguousMemory(FunctionBackend* USER_MODE_PARAM_ONLY, PVOID BaseAddress);
	PVOID KeQueryPrcbAddress(FunctionBackend* USER_MODE_PARAM_ONLY, int Processor);
	void KeBugCheckEx(FunctionBackend* USER_MODE_PARAM_ONLY, ULONG BugCheckCode, ULONG_PTR BugCheckParameter1, ULONG_PTR BugCheckParameter2, ULONG_PTR BugCheckParameter3, ULONG_PTR BugCheckParameter4);
	BOOLEAN MmIsAddressValid(FunctionBackend* USER_MODE_PARAM_ONLY, PVOID VirtualAddress);
	BOOLEAN KeCancelTimer(FunctionBackend* USER_MODE_PARAM_ONLY, PKTIMER unamedParam1);
	NTSTATUS ZwOpenSection(FunctionBackend* USER_MODE_PARAM_ONLY, PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
	NTSTATUS ZwMapViewOfSection(FunctionBackend* USER_MODE_PARAM_ONLY, HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseHandle, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect);
	NTSTATUS ZwUnmapViewOfSection(FunctionBackend* USER_MODE_PARAM_ONLY, HANDLE ProcessHandle, PVOID BaseAddress);
	PVOID MmAllocateNonCachedMemory(FunctionBackend* USER_MODE_PARAM_ONLY, SIZE_T NumberOfBytes);
	void MmFreeNonCachedMemory(FunctionBackend* USER_MODE_PARAM_ONLY, PVOID BaseAddress, SIZE_T NumberOfBytes);
	PMDL IoAllocateMdl(FunctionBackend* USER_MODE_PARAM_ONLY, PVOID VirtualAddress, ULONG Length, BOOLEAN SecondaryBuffer, BOOLEAN ChargeQuota, PIRP Irp);
	void MmBuildMdlForNonPagedPool(FunctionBackend* USER_MODE_PARAM_ONLY, PMDL MemoryDescriptorList);
	NTSTATUS MmAllocateMdlForIoSpace(FunctionBackend* USER_MODE_PARAM_ONLY, PMM_PHYSICAL_ADDRESS_LIST PhysicalAddressList, SIZE_T NumberOfEntries, MDL* NewMdl);
	HANDLE PsGetProcessId(FunctionBackend* USER_MODE_PARAM_ONLY, PEPROCESS Process);
	void MmProbeAndLockPages(FunctionBackend* USER_MODE_PARAM_ONLY, PMDL MemoryDescriptorList, KPROCESSOR_MODE AccessMode, LOCK_OPERATION Operation);
	BYTE MmSetPageProtection(FunctionBackend* USER_MODE_PARAM_ONLY, DWORD64 address, DWORD size, ULONG protection);
}