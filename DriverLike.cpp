#include "Dependencies.h"
#include "Utils.h"
#include "Driver.h"
#include "SymbolHandler.h"
#include "DriverFunctionBackend.h"
#include "Functions.h"
#include "RequestHandler.h"

int main() {
    bool debug = true;
    DBGPRINT("[d] Program is set to debug mode, will output all details.\n");
    EnableAllPrivileges();
    
    std::wstring wsWorkingDir = GetWorkingDir();
    printf("[+] Working directory is %ws\n", wsWorkingDir.c_str());
    
    SetDllDirectory(wsWorkingDir.c_str());
    
    DriverInterface* pDriverInterface = new DriverInterface(debug);
    SymbolHandler* pSymbolHandler = new SymbolHandler(debug);
    DriverFunctionBackend* pDriverFunctionBackend = new DriverFunctionBackend(pDriverInterface, pSymbolHandler);
    
    pSymbolHandler->GetPDB(GetSystem32Path(), L"ntoskrnl.exe");

    DBGPRINT("\n");
    DBGPRINT("[d] Kernel base address: %p\n", pDriverFunctionBackend->GetKernelBaseAddress());
    DBGPRINT("[d] PID: %d (PsGetCurrentProcessId)\n         %d (GetCurrentProcessId)\n", (int) KernelFunction::PsGetCurrentProcessId(pDriverFunctionBackend), GetCurrentProcessId());
    DBGPRINT("\n");

    RequestHandler* pRequestHandler = new RequestHandler(pDriverFunctionBackend, pDriverInterface, pSymbolHandler, debug);
    pRequestHandler->CreateAndStartServer();
    DBGPRINT("\n");

    pRequestHandler->ShutdownServer();

    pSymbolHandler->~SymbolHandler();
    pDriverInterface->~DriverInterface();
}
