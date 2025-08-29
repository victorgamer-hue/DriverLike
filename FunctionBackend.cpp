#pragma once
#include "FunctionBackend.h"

bool FunctionBackend::EnableHook() {
	return false;
}

DWORD64 FunctionBackend::CreatePointer(LPCSTR FunctionName) {
	return NULL;
}

void FunctionBackend::CleanupPointer() {
	return;
}

void FunctionBackend::DisableHook() {
	return;
}
