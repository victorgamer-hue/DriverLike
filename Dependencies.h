#include <stdio.h>
#include <string>
#include <Windows.h>
#include <tlhelp32.h>
#include <vector>
#include <fstream>
#include <winternl.h>
#include <dbghelp.h>
#include <Psapi.h>

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "ntdll.lib")

#include "Defines.h"
