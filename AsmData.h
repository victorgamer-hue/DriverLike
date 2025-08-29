#pragma once
#include "Dependencies.h"

class AsmDataManager {
	public:
		AsmDataManager(DWORD64 BufferSize);

		void add_string(std::string string);
		void add_wstring(std::wstring string);
		void add_unicode_string(UNICODE_STRING string);

		void write_strings_in_order(BYTE* Buffer, DWORD Offset, DWORD string_index);
		
		void set_base_address(DWORD64 address);
		void write_to_alloc(PVOID ServerLocalAddress, DWORD BackendCodeSize);


	private:
		std::vector<DWORD> offsets;
		DWORD current_offset;
		DWORD64 base_address = 0;
		BYTE* Buffer;
		DWORD BufferSize;
};