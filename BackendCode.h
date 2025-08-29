#pragma once
#include "Dependencies.h"

DWORD start_offset = 0;

BYTE RequestBackend[] = {
	// start_server

	// stack prolog
	0x48, 0x89, 0x4C, 0x24, 0x08,								// mov [rsp + 0x8], rcx
	0x41, 0x57,													// push r15
	0x41, 0x56,													// push r14
	0x41, 0x55,													// push r13
	0x48, 0x83, 0xEC, 0x30,										// sub rsp, 48h
	// size: 15 offset: 15

	

	// stack epilog
	0x48, 0x83, 0xC4, 0x30,										// add rsp, 48h
	0x41, 0x5D,													// pop r13
	0x41, 0x5E,													// pop r14
	0x41, 0x5F,													// pop r15
	0xC3														// ret
	// size: 11 offset: 
};