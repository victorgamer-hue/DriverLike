#pragma once
#include "Dependencies.h"
#include "iqvw64e.h"

void EnableAllPrivileges();

std::wstring GetCurrentDir();

std::wstring GetWorkingDir();

std::wstring WriteDriverToFile();

bool CheckAndDisableDriverCheck(bool debug);

std::wstring GetSystem32Path();
