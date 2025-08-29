#include "AsmBackend.h"

bool AsmBackend::EnableHook() {
	// everything here will be controlled by request handler
	return true;
}

DWORD64 AsmBackend::CreatePointer(LPCSTR FunctionName) {
	return NULL;
}

void AsmBackend::CleanupPointer() {

}

void AsmBackend::DisableHook() {
	return;
}
