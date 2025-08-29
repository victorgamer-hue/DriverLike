#pragma once
#include "DriverFunctionBackend.h"
#include "AsmBackend.h"
#include "Functions.h"
#include "AsmData.h"

class RequestHandler {
	public:
		RequestHandler(DriverFunctionBackend* pDriverFunctionBacked, DriverInterface* pDriverInterface, SymbolHandler* pSymbolHandler,bool debug);

		BOOL CreateAndStartServer();
		BOOL ShutdownServer();
		void FillFunctionsAndData(DWORD64 ServerDataAddress);
		BOOL CheckServerExist();
		BOOL DisableServer();

	private:
		bool isServerRunning;

		PVOID ServerSystemAddress;
		DWORD64 KernelBaseAddress;

		DriverFunctionBackend* pDriverFunctionBackend;
		DriverInterface* pDriverInterface;
		SymbolHandler* pSymbolHandler;
		bool debug;
};