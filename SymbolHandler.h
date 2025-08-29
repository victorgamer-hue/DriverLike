#pragma once
#include "Dependencies.h"
#include "Defines.h"
#include "Utils.h"

class SymbolHandler {
	public:
		SymbolHandler(bool debug);
		~SymbolHandler();

		void GetPDB(std::wstring ModulePath, std::wstring ModuleName);
		DWORD64 GetOffset(std::wstring ModuleName, std::wstring SymbolName);

	private:
		std::wstring _GetPDB(std::wstring ProgramPath);
		std::wstring _LookupModulePath(std::wstring ModuleName);
		DWORD GetFileSize(std::wstring FilePath);

		std::vector<std::pair<std::wstring, std::wstring>> ModulePathPairs;
		HANDLE hProcess;

		bool debug;
};