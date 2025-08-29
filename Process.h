#pragma once
#include "Dependencies.h"

class Process {
public:
    Process(PROCESSENTRY32 ProcessEntry, bool debug);
    ~Process();

    void DebugPrintInfo();

private:
    HANDLE handle;
    int pid;
    int ppid;
    DWORD size;

    bool debug;
};

class ProcessIndex {
    public:
        ProcessIndex(bool debug);
        ~ProcessIndex();

        Process* PID(int pid);

    private:
        void InitializeProcessSearch();
        HANDLE toolhelp32snapshot;
        PROCESSENTRY32 pe;
        bool debug;
};

