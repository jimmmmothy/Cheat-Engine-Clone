#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
#include <algorithm>

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

void findPattern(HANDLE hProcess, MEMORY_BASIC_INFORMATION memInfo, void* addr, void* pattern, size_t patternSize, std::vector<void*>& foundAddresses)
{
    size_t size = (char*)addr  - (char *)memInfo.BaseAddress;
	char *localCopyContents = new char[size];
	if (ReadProcessMemory(hProcess, memInfo.BaseAddress, localCopyContents, size, NULL))
	{
        // Copy the contents of the memory region to a local buffer
		char *cur = localCopyContents;
		size_t curPos = 0;
        // Iterate through the memory region and search for the pattern
		while (curPos < size - patternSize + 1)
		{
			if (memcmp(cur, pattern, patternSize) == 0)
			{
                std::cout << "Pattern found at address: " << (void*)((char*)memInfo.BaseAddress + curPos) << '\n';
                foundAddresses.push_back((char*)memInfo.BaseAddress + curPos);
			}
			curPos++;
			cur++;
		}
	}
	delete[] localCopyContents;
}

void scanVirtualPages(HANDLE hProcess, void* pattern, size_t patternSize, std::vector<void*>& foundAddresses)
{
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    MEMORY_BASIC_INFORMATION memInfo;
    void* addr = 0;

    while (true)
    {
        // Read the memory information of the current page
        SIZE_T readBytes = 
			VirtualQueryEx(hProcess, addr, &memInfo, sizeof(MEMORY_BASIC_INFORMATION));

		if (!readBytes)
		{
			break;
		}

        addr = (char*)memInfo.BaseAddress + memInfo.RegionSize;

        if (memInfo.State == MEM_COMMIT && memInfo.Protect != PAGE_NOACCESS && memInfo.Protect != PAGE_GUARD)
		{
            findPattern(hProcess, memInfo, addr, pattern, patternSize, foundAddresses);
        }

    }
}

void narrowDownAddress(HANDLE hProcess, const void* pattern, size_t patternSize, std::vector<void*>& foundAddresses)
{
    for (std::vector<void*>::iterator i = foundAddresses.begin(); i != foundAddresses.end();)
    {
        size_t bufferSize = 256; // Size of the buffer to read
        char* buffer = new char[bufferSize];
        void* addr = *i;
        size_t bytesRead = 0;

        // Read the memory from the process
        if (ReadProcessMemory(hProcess, addr, buffer, bufferSize, &bytesRead))
        {
            // Compare the read memory with the pattern
            if (memcmp(buffer, pattern, patternSize) == 0)
            {
                std::cout << "Pattern found at address: " << addr << "\n";
                i++;
            }
            else
            {
                i = foundAddresses.erase(i);
            }
        }
        else
        {
            std::cout << "Failed to read memory at address: " << addr << "\n";
        }

        delete[] buffer;
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

    // Convert the float to a byte array
    unsigned char floatBuffer[sizeof(value)];
    memcpy(floatBuffer, &value, sizeof(float));

    // Initialize a vector to store the found addresses
    std::vector<void*> foundAddresses;

    scanVirtualPages(hProcess, floatBuffer, sizeof(float), foundAddresses);
    terminalBreak();

    std::cout << "Enter next value to search for: ";
    std::cin >> value;

    // Convert the float to a byte array
    memcpy(floatBuffer, &value, sizeof(float));

    narrowDownAddress(hProcess, floatBuffer, sizeof(float), foundAddresses);
    terminalBreak();

    std::cout << "Enter the address to write to: ";
    void* addr;
    std::cin >> std::hex >> addr;
    std::cout << "Enter the value to write: ";
    std::cin >> value;

    WriteProcessMemory(hProcess, addr, &value, sizeof(value), NULL);

    CloseHandle(hProcess);
}