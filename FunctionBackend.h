#pragma once
#include "Dependencies.h"

class FunctionBackend {
	public:
		virtual bool EnableHook();
		virtual DWORD64 CreatePointer(LPCSTR FunctionName);
		virtual void CleanupPointer();
		virtual void DisableHook();
};