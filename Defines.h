#pragma once

// macros
#define DBGPRINT(...) if(debug) printf(__VA_ARGS__);

// defines
#define DRIVER_NAME L"iqvw64e.sys"

// windows constants
#define IRP_MJ_MAXIMUM_FUNCTION					0x1b
#define MAXIMUM_VOLUME_LABEL_LENGTH				(32 * sizeof(WCHAR))