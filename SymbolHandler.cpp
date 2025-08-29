#include "SymbolHandler.h"

SymbolHandler::SymbolHandler(bool debug) {
	this->hProcess = GetCurrentProcess();
	std::wstring wsWorkingDirectory = GetWorkingDir();

	std::wstring wsUserPath = L"cache*";
	wsUserPath += wsWorkingDirectory;
	wsUserPath += L";SRV*http://msdl.microsoft.com/download/symbols";

	SymInitializeW(this->hProcess, wsUserPath.c_str(), false);
	SymSetOptions(SYMOPT_EXACT_SYMBOLS | SYMOPT_DEBUG);
	this->debug = debug;
}

SymbolHandler::~SymbolHandler() {
	SymCleanup(this->hProcess);
}

std::wstring SymbolHandler::_GetPDB(std::wstring ProgramPath) {
	SYMSRV_INDEX_INFOW ssii {};
	ssii.sizeofstruct = sizeof(SYMSRV_INDEX_INFOW);

	bool success = SymSrvGetFileIndexInfoW(ProgramPath.c_str(), &ssii, NULL);
	if (!success) {
		printf("[!] Error 0x%X getting binary info for: %ws\n", GetLastError(), ProgramPath.c_str());
		return {};
	}

	void* id; DWORD idType;
	if (ssii.guid == GUID{}) {
		id = &ssii.sig;
		idType = SSRVOPT_DWORDPTR;
	} else {
		id = &ssii.guid;
		idType = SSRVOPT_GUIDPTR;
	}

	auto PDBPath = std::make_unique<WCHAR[]>(4096);
	success = SymFindFileInPathW(
		this->hProcess,
		NULL,
		ssii.pdbfile,
		id,
		ssii.age,
		NULL,
		idType,
		PDBPath.get(),
		NULL,
		NULL
	);

	std::wstring wsPDBPath = std::wstring(PDBPath.get());

	if (wsPDBPath.empty() && GetModuleHandleA("symsrv.dll") == nullptr) {
		printf("[!] Please provide proper dbghelp.dll and symsrv.dll!\n");
	}

	return wsPDBPath;
}

std::wstring SymbolHandler::_LookupModulePath(std::wstring ModuleName) {
	for (auto pair : ModulePathPairs) {
		if (pair.first == ModuleName)
			return pair.second;
	}

	return {};
}

void SymbolHandler::GetPDB(std::wstring ModulePath, std::wstring ModuleName) {
	std::wstring _wsDownloadedPDBPath = this->_LookupModulePath(ModuleName);
	if (!_wsDownloadedPDBPath.empty()) return;

	std::wstring wsDownloadedPDBPath = this->_GetPDB(ModulePath + ModuleName);
	auto ModuleNamePath = std::make_pair(ModuleName, wsDownloadedPDBPath);
	this->ModulePathPairs.push_back(ModuleNamePath);

	DBGPRINT("[*] Got PDB for module: %ws\n", ModuleName.c_str());
}

DWORD SymbolHandler::GetFileSize(std::wstring FilePath) {
	std::ifstream f;
	f.open(FilePath, std::ios_base::binary | std::ios_base::in);
	if (!f.good() || f.eof() || !f.is_open()) { return 0; }
	f.seekg(0, std::ios_base::beg);
	std::ifstream::pos_type begin_pos = f.tellg();
	f.seekg(0, std::ios_base::end);
	return static_cast<int>(f.tellg() - begin_pos);
}

DWORD64 SymbolHandler::GetOffset(std::wstring ModuleName, std::wstring SymbolName) {
	// first off, try getting the offset by LoadLibrary and searching DOS headers
	
	std::string sSymbolName = std::string(SymbolName.begin(), SymbolName.end());
	PVOID pModule = LoadLibraryEx(ModuleName.c_str(), NULL, DONT_RESOLVE_DLL_REFERENCES);

	if (pModule != NULL) {
		PIMAGE_DOS_HEADER dh = (PIMAGE_DOS_HEADER)pModule;
		PIMAGE_NT_HEADERS nth = (PIMAGE_NT_HEADERS)((DWORD64)pModule + dh->e_lfanew);
		DWORD ed = nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		PIMAGE_EXPORT_DIRECTORY ped = (PIMAGE_EXPORT_DIRECTORY)((DWORD64)pModule + ed);
		PDWORD functions = (PDWORD)((DWORD64)pModule + ped->AddressOfFunctions);
		PDWORD names = (PDWORD)((DWORD64)pModule + ped->AddressOfNames);
		PWORD ordinals = (PWORD)((DWORD64)pModule + ped->AddressOfNameOrdinals);
		for (DWORD64 idx = 0; idx < ped->NumberOfFunctions; idx++) {
			LPCSTR name = (LPCSTR)((DWORD64)pModule + names[idx]);
			if (strcmp(name, sSymbolName.c_str()) == 0) {
				DWORD64 result = (DWORD64)functions[ordinals[idx]];
				FreeLibrary((HMODULE)pModule);

				return result;
			}
		}

		FreeLibrary((HMODULE)pModule);
	}

	// if not found in DOS header, try in PDB

	std::wstring wsPDBPath = this->_LookupModulePath(ModuleName);
	if (wsPDBPath.empty()) {
		printf("[!] Could not find PDB path for module %ws. The module may not exist, or you did not call GetPDB().\n", ModuleName.c_str());
		return NULL;
	}

	DWORD64 BaseAddress = 0x40000;
	DWORD FileSize = this->GetFileSize(wsPDBPath);
	DWORD64 ModuleBase = SymLoadModuleExW(
		this->hProcess,
		NULL,
		wsPDBPath.c_str(),
		NULL,
		BaseAddress,
		FileSize,
		NULL,
		NULL
	);

	if (ModuleBase == NULL) {
		printf("[!] SymLoadModuleExW failed. Error: 0x%hhX\n", GetLastError());
		return NULL;
	}
	
	SYMBOL_INFO_PACKAGEW SymbolInfoPackage {  };
	SymbolInfoPackage.si.SizeOfStruct = sizeof(SYMBOL_INFOW);
	SymbolInfoPackage.si.MaxNameLen = sizeof(SymbolInfoPackage.name);

	BOOL success = SymFromNameW(this->hProcess, SymbolName.c_str(), &SymbolInfoPackage.si);
	if (!success || !SymbolInfoPackage.si.Address) {
		printf("[!] Failed to get symbol %ws\n", SymbolName.c_str());
		return NULL;
	}

	DWORD64 Offset = SymbolInfoPackage.si.Address - ModuleBase;
	SymUnloadModule64(this->hProcess, ModuleBase);

	return Offset;
}
