#include "Functions.h"

namespace KernelFunction {

NTSTATUS PsLookupProcessByProcessId(FunctionBackend* USER_MODE_PARAM_ONLY, HANDLE ProcessId, PEPROCESS* Process) {
	return KINVOKE<NTSTATUS, HANDLE, PEPROCESS*>
		(USER_MODE_PARAM_ONLY, "PsLookupProcessByProcessId", ProcessId, Process);
}

HANDLE PsGetCurrentProcessId(FunctionBackend* USER_MODE_PARAM_ONLY) {
	return KINVOKE<HANDLE>
		(USER_MODE_PARAM_ONLY, "PsGetCurrentProcessId");
}

HANDLE PsGetCurrentProcess(FunctionBackend* USER_MODE_PARAM_ONLY) {
	return KINVOKE<HANDLE>
		(USER_MODE_PARAM_ONLY, "PsGetCurrentProcess");
}

NTSTATUS ObReferenceObjectByHandle(FunctionBackend* USER_MODE_PARAM_ONLY, HANDLE Handle, ACCESS_MASK DesiredAccess, POBJECT_TYPE ObjectType, KPROCESSOR_MODE AccessMode, PVOID* Object, POBJECT_HANDLE_INFORMATION HandleInformation) {
	return KINVOKE<NTSTATUS, HANDLE, ACCESS_MASK, POBJECT_TYPE, KPROCESSOR_MODE, PVOID*, POBJECT_HANDLE_INFORMATION>
		(USER_MODE_PARAM_ONLY, "ObReferenceObjectByHandle", Handle, DesiredAccess, ObjectType, AccessMode, Object, HandleInformation);
}

LARGE_INTEGER MmGetPhysicalAddress(FunctionBackend* USER_MODE_PARAM_ONLY, PVOID BaseAddress) {
	return KINVOKE<LARGE_INTEGER, PVOID>
		(USER_MODE_PARAM_ONLY, "MmGetPhysicalAddress", BaseAddress);
}

PVOID MmMapIoSpace(FunctionBackend* USER_MODE_PARAM_ONLY, LARGE_INTEGER PhysicalAddress, SIZE_T NumberOfBytes, MEMORY_CACHING_TYPE CacheType) {
	return KINVOKE<PVOID, LARGE_INTEGER, SIZE_T, MEMORY_CACHING_TYPE>
		(USER_MODE_PARAM_ONLY, "MmMapIoSpace", PhysicalAddress, NumberOfBytes, CacheType);
}

void MmUnmapIoSpace(FunctionBackend* USER_MODE_PARAM_ONLY, PVOID BaseAddress, SIZE_T NumberOfBytes) {
	KINVOKE<RVOID, PVOID, SIZE_T>
		(USER_MODE_PARAM_ONLY, "MmUnmapIoSpace", BaseAddress, NumberOfBytes);
}

NTSTATUS ObOpenObjectByPointer(FunctionBackend* USER_MODE_PARAM_ONLY, PVOID Object, ULONG HandleAttributes, PACCESS_STATE PassedAccessState, ACCESS_MASK DesiredAccess, POBJECT_TYPE ObjectType, KPROCESSOR_MODE AccessMode, PHANDLE Handle) {
	return KINVOKE<NTSTATUS, PVOID, ULONG, PACCESS_STATE, ACCESS_MASK, POBJECT_TYPE, KPROCESSOR_MODE, PHANDLE>
		(USER_MODE_PARAM_ONLY, "ObOpenObjectByPointer", Object, HandleAttributes, PassedAccessState, DesiredAccess, ObjectType, AccessMode, Handle);
}

KIRQL KeGetCurrentIrql(FunctionBackend* USER_MODE_PARAM_ONLY) {
	return KINVOKE<KIRQL>
		(USER_MODE_PARAM_ONLY, "KeGetCurrentIrql");
}

PMDL MmAllocatePagesForMdlEx(FunctionBackend* USER_MODE_PARAM_ONLY, LARGE_INTEGER LowAddress, LARGE_INTEGER HighAddress, LARGE_INTEGER SkipBytes, SIZE_T TotalBytes, MEMORY_CACHING_TYPE CacheType, ULONG Flags) {
	return KINVOKE<PMDL, LARGE_INTEGER, LARGE_INTEGER, LARGE_INTEGER, SIZE_T, MEMORY_CACHING_TYPE, ULONG>
		(USER_MODE_PARAM_ONLY, "MmAllocatePagesForMdlEx", LowAddress, HighAddress, SkipBytes, TotalBytes, CacheType, Flags);
}

PVOID MmMapLockedPagesSpecifyCache(FunctionBackend* USER_MODE_PARAM_ONLY, PMDL MemoryDescriptorList, KPROCESSOR_MODE AccessMode, MEMORY_CACHING_TYPE CacheType, PVOID RequestedAddress, ULONG BugCheckOnFailure, ULONG Priority) {
	return KINVOKE<PVOID, PMDL, KPROCESSOR_MODE, MEMORY_CACHING_TYPE, PVOID, ULONG, ULONG>
		(USER_MODE_PARAM_ONLY, "MmMapLockedPagesSpecifyCache", MemoryDescriptorList, AccessMode, CacheType, RequestedAddress, BugCheckOnFailure, Priority);
}

NTSTATUS MmProtectMdlSystemAddress(FunctionBackend* USER_MODE_PARAM_ONLY, PMDL MemoryDescriptorList, ULONG NewProtect) {
	return KINVOKE<NTSTATUS, PMDL, ULONG>
		(USER_MODE_PARAM_ONLY, "MmProtectMdlSystemAddress", MemoryDescriptorList, NewProtect);
}

void MmUnmapLockedPages(FunctionBackend* USER_MODE_PARAM_ONLY, PVOID BaseAddress, PMDL MemoryDescriptorList) {
	KINVOKE<RVOID, PVOID, PMDL>
		(USER_MODE_PARAM_ONLY, "MmUnmapLockedPages", BaseAddress, MemoryDescriptorList);
}

void MmFreePagesFromMdl(FunctionBackend* USER_MODE_PARAM_ONLY, PMDL MemoryDescriptorList) {
	KINVOKE<RVOID, PMDL>
		(USER_MODE_PARAM_ONLY, "MmFreePagesFromMdl", MemoryDescriptorList);
}

PVOID RtlFindExportedRoutineByName(FunctionBackend* USER_MODE_PARAM_ONLY, PVOID DllBase, PCHAR RoutineName) {
	return KINVOKE<PVOID, PVOID, PCHAR>
		(USER_MODE_PARAM_ONLY, "RtlFindExportedRoutineByName", DllBase, RoutineName);
}

NTSTATUS NtOpenFile(FunctionBackend* USER_MODE_PARAM_ONLY, PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions) {
	return KINVOKE<NTSTATUS, PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG>
		(USER_MODE_PARAM_ONLY, "NtOpenFile", FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
}

NTSTATUS ZwDeviceIoControlFile(FunctionBackend* USER_MODE_PARAM_ONLY, HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG IoControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength) {
	return KINVOKE<NTSTATUS, HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG>
		(USER_MODE_PARAM_ONLY, "ZwDeviceIoControlFile", FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
}

NTSTATUS ZwOpenProcess(FunctionBackend* USER_MODE_PARAM_ONLY, PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId) {
	return KINVOKE<NTSTATUS, PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID>
		(USER_MODE_PARAM_ONLY, "ZwOpenProcess", ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

NTSTATUS ZwOpenProcessTokenEx(FunctionBackend* USER_MODE_PARAM_ONLY, HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, PHANDLE TokenHandle) {
	return KINVOKE<NTSTATUS, HANDLE, ACCESS_MASK, ULONG, PHANDLE>
		(USER_MODE_PARAM_ONLY, "ZwOpenProcessTokenEx", ProcessHandle, DesiredAccess, HandleAttributes, TokenHandle);
}

NTSTATUS ZwClose(FunctionBackend* USER_MODE_PARAM_ONLY, HANDLE Handle) {
	return KINVOKE<NTSTATUS, HANDLE>
		(USER_MODE_PARAM_ONLY, "ZwClose", Handle);
}

NTSTATUS ZwDuplicateToken(FunctionBackend* USER_MODE_PARAM_ONLY, HANDLE ExistingTokenHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, BOOLEAN EffectiveOnly, TOKEN_TYPE TokenType, PHANDLE NewTokenHandle) {
	return KINVOKE<NTSTATUS, HANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, BOOLEAN, TOKEN_TYPE, PHANDLE>
		(USER_MODE_PARAM_ONLY, "ZwDuplicateToken", ExistingTokenHandle, DesiredAccess, ObjectAttributes, EffectiveOnly, TokenType, NewTokenHandle);
}

NTSTATUS ZwSetInformationProcess(FunctionBackend* USER_MODE_PARAM_ONLY, HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength) {
	return KINVOKE<NTSTATUS, HANDLE, PROCESSINFOCLASS, PVOID, ULONG>
		(USER_MODE_PARAM_ONLY, "ZwSetInformationProcess", ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength);
}

NTSTATUS IoGetDeviceObjectPointer(FunctionBackend* USER_MODE_PARAM_ONLY, PUNICODE_STRING ObjectName, ACCESS_MASK DesiredAccess, PFILE_OBJECT* FileObject, PDEVICE_OBJECT* DeviceObject) {
	return KINVOKE<NTSTATUS, PUNICODE_STRING, ACCESS_MASK, PFILE_OBJECT*, PDEVICE_OBJECT*>
		(USER_MODE_PARAM_ONLY, "IoGetDeviceObjectPointer", ObjectName, DesiredAccess, FileObject, DeviceObject);
}

PIRP IoBuildDeviceIoControlRequest(FunctionBackend* USER_MODE_PARAM_ONLY, ULONG IoControlCode, PDEVICE_OBJECT DeviceObject, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, BOOLEAN InternalDeviceIoControl, PKEVENT Event, PIO_STATUS_BLOCK IoStatusBlock) {
	return KINVOKE<PIRP, ULONG, PDEVICE_OBJECT, PVOID, ULONG, PVOID, ULONG, BOOLEAN, PKEVENT, PIO_STATUS_BLOCK>
		(USER_MODE_PARAM_ONLY, "IoBuildDeviceIoControlRequest", IoControlCode, DeviceObject, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength, InternalDeviceIoControl, Event, IoStatusBlock);
}

void KeInitializeEvent(FunctionBackend* USER_MODE_PARAM_ONLY, PKEVENT Event, EVENT_TYPE Type, BOOLEAN State) {
	KINVOKE<RVOID, PKEVENT, EVENT_TYPE, BOOLEAN>
		(USER_MODE_PARAM_ONLY, "KeInitializeEvent", Event, Type, State);
}

NTSTATUS KeWaitForSingleObject(FunctionBackend* USER_MODE_PARAM_ONLY, PVOID Object, KWAIT_REASON WaitReason, KPROCESSOR_MODE WaitMode, BOOLEAN Alertable, PLARGE_INTEGER Timeout) {
	return KINVOKE<NTSTATUS, PVOID, KWAIT_REASON, KPROCESSOR_MODE, BOOLEAN, PLARGE_INTEGER>
		(USER_MODE_PARAM_ONLY, "KeWaitForSingleObject", Object, WaitReason, WaitMode, Alertable, Timeout);
}

NTSTATUS IofCallDriver(FunctionBackend* USER_MODE_PARAM_ONLY, PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	return KINVOKE<NTSTATUS, PDEVICE_OBJECT, PIRP>
		(USER_MODE_PARAM_ONLY, "IofCallDriver", DeviceObject, Irp);
}

PVOID ExAllocatePoolWithTag(FunctionBackend* USER_MODE_PARAM_ONLY, POOL_TYPE PoolType, SIZE_T NumberOfBytes, ULONG Tag) {
	return KINVOKE<PVOID, POOL_TYPE, SIZE_T, ULONG>
		(USER_MODE_PARAM_ONLY, "ExAllocatePoolWithTag", PoolType, NumberOfBytes, Tag);
}

void ExFreePool(FunctionBackend* USER_MODE_PARAM_ONLY, PVOID P) {
	KINVOKE<RVOID, PVOID>
		(USER_MODE_PARAM_ONLY, "ExFreePool", P);
}

NTSTATUS ZwProtectVirtualMemory(FunctionBackend* USER_MODE_PARAM_ONLY, HANDLE ProcessHandle, PVOID* BaseAddress, PULONG NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection) {
	return KINVOKE<NTSTATUS, HANDLE, PVOID*, PULONG, ULONG, PULONG>
		(USER_MODE_PARAM_ONLY, "ZwProtectVirtualMemory", ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);
}

NTSTATUS MmCopyVirtualMemory(FunctionBackend* USER_MODE_PARAM_ONLY, PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize) {
	return KINVOKE<NTSTATUS, PEPROCESS, PVOID, PEPROCESS, PVOID, SIZE_T, KPROCESSOR_MODE, PSIZE_T>
		(USER_MODE_PARAM_ONLY, "MmCopyVirtualMemory", SourceProcess, SourceAddress, TargetProcess, TargetAddress, BufferSize, PreviousMode, ReturnSize);
}

PPEB PsGetProcessPeb(FunctionBackend* USER_MODE_PARAM_ONLY, PEPROCESS Process) {
	return KINVOKE<PPEB, PEPROCESS>
		(USER_MODE_PARAM_ONLY, "PsGetProcessPeb", Process);
}

PVOID MmGetSystemRoutineAddress(FunctionBackend* USER_MODE_PARAM_ONLY, PUNICODE_STRING SystemRoutineName) {
	return KINVOKE<PVOID, PUNICODE_STRING>
		(USER_MODE_PARAM_ONLY, "MmGetSystemRoutineAddress", SystemRoutineName);
}

void KeStackAttachProcess(FunctionBackend* USER_MODE_PARAM_ONLY, PEPROCESS PROCESS, PRKAPC_STATE ApcState) {
	KINVOKE<RVOID, PEPROCESS, PRKAPC_STATE>
		(USER_MODE_PARAM_ONLY, "KeStackAttachProcess", PROCESS, ApcState);
}

void KeUnstackDetachProcess(FunctionBackend* USER_MODE_PARAM_ONLY, PRKAPC_STATE ApcState) {
	KINVOKE<RVOID, PRKAPC_STATE>
		(USER_MODE_PARAM_ONLY, "KeUnstackDetachProcess", ApcState);
}

PVOID MmAllocateContiguousMemory(FunctionBackend* USER_MODE_PARAM_ONLY, SIZE_T NumberOfBytes, LARGE_INTEGER HighestAcceptableAddress) {
	return KINVOKE<PVOID, SIZE_T, LARGE_INTEGER>
		(USER_MODE_PARAM_ONLY, "MmAllocateContiguousMemory", NumberOfBytes, HighestAcceptableAddress);
}

void MmFreeContiguousMemory(FunctionBackend* USER_MODE_PARAM_ONLY, PVOID BaseAddress) {
	KINVOKE<RVOID, PVOID>
		(USER_MODE_PARAM_ONLY, "MmFreeContiguousMemory", BaseAddress);
}

PVOID KeQueryPrcbAddress(FunctionBackend* USER_MODE_PARAM_ONLY, int Processor) {
	return KINVOKE<PVOID, int>
		(USER_MODE_PARAM_ONLY, "KeQueryPrcbAddress", Processor);
}

void KeBugCheckEx(FunctionBackend* USER_MODE_PARAM_ONLY, ULONG BugCheckCode, ULONG_PTR BugCheckParameter1, ULONG_PTR BugCheckParameter2, ULONG_PTR BugCheckParameter3, ULONG_PTR BugCheckParameter4) {
	KINVOKE<RVOID, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR>
		(USER_MODE_PARAM_ONLY, "KeBugCheckEx", BugCheckCode, BugCheckParameter1, BugCheckParameter2, BugCheckParameter3, BugCheckParameter4);
}

BOOLEAN MmIsAddressValid(FunctionBackend* USER_MODE_PARAM_ONLY, PVOID VirtualAddress) {
	return KINVOKE<BOOLEAN, PVOID>
		(USER_MODE_PARAM_ONLY, "MmIsAddressValid", VirtualAddress);
}

BOOLEAN KeCancelTimer(FunctionBackend* USER_MODE_PARAM_ONLY, PKTIMER unamedParam1) {
	return KINVOKE<BOOLEAN, PKTIMER>
		(USER_MODE_PARAM_ONLY, "KeCancelTimer", unamedParam1);
}

NTSTATUS ZwOpenSection(FunctionBackend* USER_MODE_PARAM_ONLY, PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
	return KINVOKE<NTSTATUS, PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES>
		(USER_MODE_PARAM_ONLY, "ZwOpenSection", SectionHandle, DesiredAccess, ObjectAttributes);
}

NTSTATUS ZwMapViewOfSection(FunctionBackend* USER_MODE_PARAM_ONLY, HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseHandle, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect) {
	return KINVOKE<NTSTATUS, HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, SECTION_INHERIT, ULONG, ULONG>
		(USER_MODE_PARAM_ONLY, "ZwMapViewOfSection", SectionHandle, ProcessHandle, BaseHandle, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect);
}

NTSTATUS ZwUnmapViewOfSection(FunctionBackend* USER_MODE_PARAM_ONLY, HANDLE ProcessHandle, PVOID BaseAddress) {
	return KINVOKE<NTSTATUS, HANDLE, PVOID>
		(USER_MODE_PARAM_ONLY, "ZwUnmapViewOfSection", ProcessHandle, BaseAddress);
}

PVOID MmAllocateNonCachedMemory(FunctionBackend* USER_MODE_PARAM_ONLY, SIZE_T NumberOfBytes) {
	return KINVOKE<PVOID, SIZE_T>
		(USER_MODE_PARAM_ONLY, "MmAllocateNonCachedMemory", NumberOfBytes);
}

void MmFreeNonCachedMemory(FunctionBackend* USER_MODE_PARAM_ONLY, PVOID BaseAddress, SIZE_T NumberOfBytes) {
	KINVOKE<RVOID, PVOID, SIZE_T>
		(USER_MODE_PARAM_ONLY, "MmFreeNonCachedMemory", BaseAddress, NumberOfBytes);
}

PMDL IoAllocateMdl(FunctionBackend* USER_MODE_PARAM_ONLY, PVOID VirtualAddress, ULONG Length, BOOLEAN SecondaryBuffer, BOOLEAN ChargeQuota, PIRP Irp) {
	return KINVOKE<PMDL, PVOID, ULONG, BOOLEAN, BOOLEAN, PIRP>
		(USER_MODE_PARAM_ONLY, "IoAllocateMdl", VirtualAddress, Length, SecondaryBuffer, ChargeQuota, Irp);
}

void MmBuildMdlForNonPagedPool(FunctionBackend* USER_MODE_PARAM_ONLY, PMDL MemoryDescriptorList) {
	KINVOKE<RVOID, PMDL>
		(USER_MODE_PARAM_ONLY, "MmBuildMdlForNonPagedPool", MemoryDescriptorList);
}

NTSTATUS MmAllocateMdlForIoSpace(FunctionBackend* USER_MODE_PARAM_ONLY, PMM_PHYSICAL_ADDRESS_LIST PhysicalAddressList, SIZE_T NumberOfEntries, MDL* NewMdl) {
	return KINVOKE<NTSTATUS, PMM_PHYSICAL_ADDRESS_LIST, SIZE_T, MDL*>
		(USER_MODE_PARAM_ONLY, "MmAllocateMdlForIoSpace", PhysicalAddressList, NumberOfEntries, NewMdl);
}

HANDLE PsGetProcessId(FunctionBackend* USER_MODE_PARAM_ONLY, PEPROCESS Process) {
	return KINVOKE<HANDLE, PEPROCESS>
		(USER_MODE_PARAM_ONLY, "PsGetProcessId", Process);
}

void MmProbeAndLockPages(FunctionBackend* USER_MODE_PARAM_ONLY, PMDL MemoryDescriptorList, KPROCESSOR_MODE AccessMode, LOCK_OPERATION Operation) {
	KINVOKE<RVOID, PMDL, KPROCESSOR_MODE, LOCK_OPERATION>
		(USER_MODE_PARAM_ONLY, "MmProbeAndLockPages", MemoryDescriptorList, AccessMode, Operation);
}

BYTE MmSetPageProtection(FunctionBackend* USER_MODE_PARAM_ONLY, DWORD64 address, DWORD size, ULONG protection) {
	return KINVOKE<BYTE, DWORD64, DWORD, ULONG>
		(USER_MODE_PARAM_ONLY, "MmSetPageProtection", address, size, protection);
}

}
