#include "Process.h"

ProcessIndex::ProcessIndex(bool debug) {
    this->debug = debug;

    this->toolhelp32snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    this->pe = { 0 };
}

void ProcessIndex::InitializeProcessSearch() {
    this->pe = { 0 };
    this->pe.dwSize = sizeof(PROCESSENTRY32);
}

Process* ProcessIndex::PID(int pid){
    this->InitializeProcessSearch();
    if (Process32First(this->toolhelp32snapshot, &this->pe)) {
        do {
            if (this->pe.th32ProcessID == pid) {
                return new Process(this->pe, this->debug);
            }
        } while (Process32Next(this->toolhelp32snapshot, &this->pe));
    }

    return nullptr;
}

ProcessIndex::~ProcessIndex() {
    CloseHandle(this->toolhelp32snapshot);
}

Process::Process(PROCESSENTRY32 ProcessEntry, bool debug) {
    this->handle = OpenProcess(PROCESS_ALL_ACCESS, false, ProcessEntry.th32ProcessID);
    this->pid = ProcessEntry.th32ProcessID;
    this->ppid = ProcessEntry.th32ParentProcessID;
    this->size = ProcessEntry.dwSize;
    this->debug = debug;
}

Process::~Process() {
    CloseHandle(this->handle);
}

void Process::DebugPrintInfo() {
    DBGPRINT("[+] Opened process -- PID:%d PPID:%d Handle:%p Image Size:0x%hhX", this->pid, this->ppid, this->handle, this->size);
}