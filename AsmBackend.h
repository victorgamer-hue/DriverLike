#pragma once
#include "FunctionBackend.h"
#include "DriverFunctionBackend.h"

class AsmBackend : public FunctionBackend {
	public:
		bool EnableHook() override;
		DWORD64 CreatePointer(LPCSTR FunctionName) override;
		void CleanupPointer() override;
		void DisableHook() override;

	private:
		
};