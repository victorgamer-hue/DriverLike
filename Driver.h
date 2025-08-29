#pragma once
#include "Utils.h"

typedef NTSTATUS (*fNtLoadDriver)(PUNICODE_STRING DriverServiceName);
typedef NTSTATUS (*fNtUnloadDriver)(PUNICODE_STRING DriverServiceName);

namespace Driver_IOCTL {
	typedef struct _COPY_MEMORY_BUFFER_INFO {
		DWORD64 case_number;
		DWORD64 reserved;
		DWORD64 source;
		DWORD64 destination;
		DWORD64 length;
	} COPY_MEMORY_BUFFER_INFO, * PCOPY_MEMORY_BUFFER_INFO;

	typedef struct _FILL_MEMORY_BUFFER_INFO {
		DWORD64 case_number;
		DWORD64 reserved1;
		DWORD value;
		DWORD reserved2;
		DWORD64 destination;
		DWORD64 length;
	} FILL_MEMORY_BUFFER_INFO, * PFILL_MEMORY_BUFFER_INFO;

	typedef struct _GET_PHYS_ADDRESS_BUFFER_INFO {
		DWORD64 case_number;
		DWORD64 reserved;
		DWORD64 return_physical_address;
		DWORD64 address_to_translate;
	} GET_PHYS_ADDRESS_BUFFER_INFO, * PGET_PHYS_ADDRESS_BUFFER_INFO;

	typedef struct _MAP_IO_SPACE_BUFFER_INFO {
		DWORD64 case_number;
		DWORD64 reserved;
		DWORD64 return_value;
		DWORD64 return_virtual_address;
		DWORD64 physical_address_to_map;
		DWORD size;
	} MAP_IO_SPACE_BUFFER_INFO, * PMAP_IO_SPACE_BUFFER_INFO;

	typedef struct _UNMAP_IO_SPACE_BUFFER_INFO {
		DWORD64 case_number;
		DWORD64 reserved1;
		DWORD64 reserved2;
		DWORD64 virt_address;
		DWORD64 reserved3;
		DWORD number_of_bytes;
	} UNMAP_IO_SPACE_BUFFER_INFO, * PUNMAP_IO_SPACE_BUFFER_INFO;
}

class DriverInterface {
	public:
		DriverInterface(bool debug);
		~DriverInterface();

		bool VirtualMemoryCopy(DWORD64 destination, DWORD64 source, DWORD64 size);
		bool VirtualSetMemory(DWORD64 address, DWORD value, DWORD64 size);
		bool GetPhysicalAddress(DWORD64 virtual_address, DWORD64* physical_address);
		DWORD64 MapIoSpace(DWORD64 physical_address, DWORD size);
		bool UnmapIoSpace(DWORD64 address, DWORD size);

		bool ReadMemory(DWORD64 address, PVOID buffer, DWORD64 size);
		bool WriteMemory(DWORD64 address, PVOID buffer, DWORD64 size);
		bool PhysicalWrite(DWORD64 address, PVOID buffer, DWORD size);

	private:
		std::wstring wsServiceName;

		DWORD ioctl = 0x80862007;
		HANDLE hDevice;

		bool DeviceExists();
		bool debug;
};