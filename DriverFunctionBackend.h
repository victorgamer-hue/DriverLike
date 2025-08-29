#pragma once
#include "FunctionBackend.h"
#include "SymbolHandler.h"
#include "Driver.h"

class DriverFunctionBackend : public FunctionBackend {
	public:
		DriverFunctionBackend(DriverInterface* pDriverInterface, SymbolHandler* pSymbolHandler);

		bool EnableHook() override;
		DWORD64 CreatePointer(LPCSTR FunctionName) override;
		void CleanupPointer() override;
		void DisableHook() override;

		DWORD64 GetKernelBaseAddress();
		DWORD64 _CreatePointerFromArbitrarySystemSpaceFunctionPointer(DWORD64 SystemSpaceFunctionPointer);

	private:
		static const DWORD JumpHookSize = 12;
		static const DWORD SyscallExecSize = 11;

		BYTE syscall_execute[SyscallExecSize];
		BYTE original_bytes[JumpHookSize];

		DWORD64 CurrentFunctionPointer;
		DWORD64 CurrentHookedFunctionPtr;

		DriverInterface* pDriverInterface;
		SymbolHandler* pSymbolHandler;
};