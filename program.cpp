#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>

void listProcesses()
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 processEntry;
        processEntry.dwSize = sizeof(PROCESSENTRY32);

        while (Process32Next(hSnapshot, &processEntry))
        {
            if (processEntry.th32ProcessID == 0)
            {
                continue;
            }

            std::wcout << processEntry.szExeFile << " PID: " << processEntry.th32ProcessID << '\n';
        }

        CloseHandle(hSnapshot);
    }
}

void terminalBreak()
{
    std::cout << '\n' << '\n';
    std::cout << "-----------------------------------------------------------------------" << '\n';
    std::cout << '\n' << '\n';
}

void findPattern(HANDLE hProcess, MEMORY_BASIC_INFORMATION memInfo, void* addr, void* pattern, size_t patternSize)
{
    size_t size = (char*)addr  - (char *)memInfo.BaseAddress;
			char *localCopyContents = new char[size];
			if (ReadProcessMemory(hProcess, memInfo.BaseAddress, localCopyContents, size, NULL))
			{
				char *cur = localCopyContents;
				size_t curPos = 0;
				while (curPos < size - patternSize + 1)
				{
					if (memcmp(cur, pattern, patternSize) == 0)
					{
                        std::cout << "Found at: " << (void *)((char *)memInfo.BaseAddress + curPos) << '\n';
						//returnVec.push_back((char *)low + curPos);
					}
					curPos++;
					cur++;
				}
			}
			delete[] localCopyContents;
}

void scanVirtualPages(HANDLE hProcess, void* pattern, size_t patternSize)
{
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    MEMORY_BASIC_INFORMATION memInfo;
    void* addr = 0;

    while (true)
    {
        SIZE_T readBytes = 
			VirtualQueryEx(hProcess, addr, &memInfo, sizeof(MEMORY_BASIC_INFORMATION));

		if (!readBytes)
		{
			break;
		}

        addr = (char*)memInfo.BaseAddress + memInfo.RegionSize;

        if (memInfo.State == MEM_COMMIT && memInfo.Protect != PAGE_NOACCESS && memInfo.Protect != PAGE_GUARD)
		{
            findPattern(hProcess, memInfo, addr, pattern, patternSize);
        }

    }
}

int main () 
{
    listProcesses();
    terminalBreak();

    DWORD pid; 
    std::cout << "Enter the process ID: ";
    std::cin >> pid;

    // Open the process with rights to necessary to read and write memory
    DWORD access = PROCESS_VM_READ |
                   PROCESS_QUERY_INFORMATION |
                   PROCESS_VM_WRITE |
                   PROCESS_VM_OPERATION;
    HANDLE hProcess = OpenProcess(access, FALSE, pid);

    if (hProcess == NULL)
    {
        std::cerr << "Failed to open the process. \n";
        return 1;
    }

    terminalBreak();
    float value;
    std::cout << "Enter the value to search for: ";
    std::cin >> value;
    unsigned char floatBuffer[sizeof(value)];
    memcpy(floatBuffer, &value, sizeof(float));

    scanVirtualPages(hProcess, floatBuffer, sizeof(float));
}