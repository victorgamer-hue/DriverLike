#include "AsmData.h"

AsmDataManager::AsmDataManager(DWORD64 BufferSize) {
	this->Buffer = (BYTE*) malloc(BufferSize);
	current_offset = 0;
	this->BufferSize = BufferSize;
}

void AsmDataManager::add_string(std::string string) {
	LPCSTR pString = string.c_str();
	DWORD size = string.size() * sizeof(char);
	
	if (!Buffer) return;
	memcpy(&this->Buffer[current_offset], pString, size);
	offsets.push_back(current_offset);
	current_offset += size;
}

void AsmDataManager::add_wstring(std::wstring string) {
	LPCWSTR pString = string.c_str();
	DWORD size = string.size() * sizeof(wchar_t);

	if (!Buffer) return;
	memcpy(&this->Buffer[current_offset], pString, size);
	offsets.push_back(current_offset);
	current_offset += size;
}

void AsmDataManager::add_unicode_string(UNICODE_STRING string) {
	DWORD size = sizeof(UNICODE_STRING);
	UNICODE_STRING TranslatedString;

	TranslatedString.Length = string.Length;
	TranslatedString.MaximumLength = string.MaximumLength;
	
	DWORD64 TranslatedBuffer = this->base_address; // start at the base address
	TranslatedBuffer += current_offset;			   // now we are right before the unicode string
	TranslatedBuffer += size;					   // right after unicode string

	TranslatedString.Buffer = (PWSTR) TranslatedBuffer;

	memcpy(&this->Buffer[current_offset], &TranslatedString, size); // paste in the UNICODE_STRING
	// now we need to add the string to the buffer
	current_offset += size; // move by the size of UNICODE_STRING
	memset(&this->Buffer[current_offset], 0x00, TranslatedString.MaximumLength); // allocate a size of MaximumLength in the buffer
	memcpy(&this->Buffer[current_offset], string.Buffer, string.Length); // fill out the buffer with the existing string
	current_offset += TranslatedString.MaximumLength; // next string will be written after the max size of the buffer
}

void AsmDataManager::write_strings_in_order(BYTE* oBuffer, DWORD Offset, DWORD string_index) {
	DWORD sOffset = offsets[string_index];
	DWORD64 StringAddress = base_address + sOffset;
	memcpy(&oBuffer[Offset], &StringAddress, sizeof(DWORD64));
}

void AsmDataManager::set_base_address(DWORD64 address) {
	this->base_address = address;
}

void AsmDataManager::write_to_alloc(PVOID ServerLocalAddress, DWORD BackendCodeSize) {
	memcpy((PVOID)((DWORD64)ServerLocalAddress + BackendCodeSize), this->Buffer, BufferSize);
}