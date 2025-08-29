#include "RequestHandler.h"
#include "BackendCode.h"

// while hooking NtAddAtom, there is a very very slight possibility another program calls it
// to minimize the time NtAddAtom is hooked, and to complete more functions at ring 0 privilage level,
// we use some assembly injected in the kernel address space to do memory r/w

RequestHandler::RequestHandler(DriverFunctionBackend* pDriverFunctionBacked, DriverInterface* pDriverInterface, SymbolHandler* pSymbolHandler, bool debug) {
	this->debug = debug;
	this->pDriverFunctionBackend = pDriverFunctionBacked;
	this->pDriverInterface = pDriverInterface;
	this->pSymbolHandler = pSymbolHandler;
	this->KernelBaseAddress = pDriverFunctionBacked->GetKernelBaseAddress();
	this->ServerSystemAddress = NULL;
	this->isServerRunning = FALSE;
}

void RequestHandler::FillFunctionsAndData(DWORD64 ServerDataAddress) {
	AsmDataManager* pDataMgr = new AsmDataManager(2048);
	pDataMgr->set_base_address(ServerDataAddress);


}

BOOL RequestHandler::CreateAndStartServer() {
	if (this->CheckServerExist()) {
		DBGPRINT("[!] Server already exists in kernel mode, something wrong happend.\n");
		DBGPRINT("[!] Disabling server and starting over.\n");
		if (!this->DisableServer()) return false;
		if (this->CheckServerExist()) return false; // if server wasn't disabled even after second time, just restart your pc bro
	}

	PVOID ServerSystemAddress = KernelFunction::ExAllocatePoolWithTag(pDriverFunctionBackend, NonPagedPool, sizeof(RequestBackend), 'cbVS');
	if (!ServerSystemAddress) return false;
	DBGPRINT("[+] Allocated a NonPagedPool memory page: %p\n", ServerSystemAddress);
	
	if (!KernelFunction::MmSetPageProtection(this->pDriverFunctionBackend, (DWORD64)ServerSystemAddress, sizeof(RequestBackend), PAGE_EXECUTE_READWRITE)) return false;
	DBGPRINT("[+] Made page RWX. \n");

	PVOID ServerLocalAddress = VirtualAlloc(NULL, sizeof(RequestBackend), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!ServerLocalAddress) return false;
	memcpy(ServerLocalAddress, RequestBackend, sizeof(RequestBackend));
	if (!this->pDriverInterface->WriteMemory((DWORD64)ServerSystemAddress, ServerLocalAddress, sizeof(RequestBackend))) return FALSE;
	DBGPRINT("[+] Wrote %d bytes to the page\n", (DWORD) sizeof(RequestBackend));
	DWORD64 pStartFunction = start_offset + (DWORD64) ServerSystemAddress;

	this->pDriverFunctionBackend->EnableHook();

	PVOID ptr = (PVOID) this->pDriverFunctionBackend->_CreatePointerFromArbitrarySystemSpaceFunctionPointer(pStartFunction);
	((void(*)()) ptr)();

	this->pDriverFunctionBackend->CleanupPointer();
	this->pDriverFunctionBackend->DisableHook();
}

BOOL RequestHandler::ShutdownServer() {


	if(this->isServerRunning && this->ServerSystemAddress)
		KernelFunction::ExFreePool(pDriverFunctionBackend, this->ServerSystemAddress);
	return true;
}

BOOL RequestHandler::DisableServer() {
	return true;
}

BOOL RequestHandler::CheckServerExist() {
	return false;
}