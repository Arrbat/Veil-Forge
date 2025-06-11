#include <stdio.h>
#include <stdbool.h>
#include <windows.h>
#include "crypto/hashing/sha.h"
#include "crypto/chacha20-poly1305/chacha20poly1305.h"

int HexcharToInt(char c)
{
    if ('0' <= c && c <= '9') return c - '0';
    if ('a' <= c && c <= 'f') return c - 'a' + 10;
    if ('A' <= c && c <= 'F') return c - 'A' + 10;
    return -1;
}

int HexcharToBytes(const char *hexStr, uint8_t *output, size_t expectedLen)
{
    size_t i;
    for (i = 0; i < expectedLen; i++)
    {
        int hi = HexcharToInt(hexStr[2 * i]);
        int lo = HexcharToInt(hexStr[2 * i + 1]);
        if (hi == -1 || lo == -1)
        {
            return -1; 
        }
        output[i] = (hi << 4) | lo;
    }
    return 0;
}

int PrintMessage(HANDLE hCon, const char* text, int consoleColorCode, int errorCode)
{
    SetConsoleTextAttribute(hCon, consoleColorCode);
    fprintf(stderr, "%s\n", text);
    SetConsoleTextAttribute(hCon, 7);
    return errorCode;
}

int main(int argc, char* argv[])
{
    HANDLE hCon = GetStdHandle(STD_OUTPUT_HANDLE);
    int errorCode;

    PrintMessage(hCon, "Checking input arguments...", 7, 0);
    if (argc < 4) 
    {
        errorCode = PrintMessage(hCon, "Error: Start this program with valid arguments.", 4, ERROR_BAD_ARGUMENTS);
        return errorCode;
    }

    PrintMessage(hCon, "Arguments are valid.", 2, 0);

    const char *inputFile = argv[1];
    const char *keyHex = argv[2];
    const char *nonceHex = argv[3];

    if (strlen(keyHex) != 64 || strlen(nonceHex) != 48)
    {
        errorCode = PrintMessage(hCon, "Error: Invalid key or nonce length. Key must be 64 hex chars, nonce 48 hex chars.", 4, ERROR_INVALID_DATA);
        return errorCode;
    }

    // Read the input PE file that we want to pack
    PrintMessage(hCon, "Reading input file... ", 7, 0);
    FILE *filePtr;
    char *fileBuff;
    long fileLen;

    filePtr = fopen(inputFile, "rb");
    if (filePtr == NULL)
    {
        errorCode = PrintMessage(hCon, "Error: Could not open input file.", 4, ERROR_FILE_NOT_FOUND);
        return errorCode;
    }

    fseek(filePtr, 0, SEEK_END);
    fileLen = ftell(filePtr);
    rewind(filePtr);

    fileBuff = (char *)malloc(fileLen);
    if (fileBuff == NULL)
    {
        errorCode = PrintMessage(hCon, "Error: Memory allocation failed.", 4, ERROR_NOT_ENOUGH_MEMORY);
        fclose(filePtr);
        return errorCode;
    }

    size_t bytesRead = fread(fileBuff, 1, fileLen, filePtr);
    fclose(filePtr);
    if (bytesRead != (size_t)fileLen)
    {
        errorCode = PrintMessage(hCon, "Error: Could not read input file.", 4, ERROR_FILE_NOT_FOUND);
        free(fileBuff);
        return errorCode;
    }

    PrintMessage(hCon, "Read file succesfully.", 2, 0);

    // Validate that input is x64 PE
    PrintMessage(hCon, "Validate input file as x64 PE... ", 7, 0);
    IMAGE_DOS_HEADER* _dosHeader = (PIMAGE_DOS_HEADER) fileBuff;
    IMAGE_NT_HEADERS64* _ntHeader = (IMAGE_NT_HEADERS64*)((char*)fileBuff + _dosHeader->e_lfanew);
    bool is64 = _ntHeader->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64;
    if (!is64)
    {
        errorCode = PrintMessage(hCon, "Error. Input file is not a valid x64 PE", 4, ERROR_BAD_FORMAT);
        free(fileBuff);
        return errorCode;
    }
    PrintMessage(hCon, "File is valid x64 PE.", 2, 0);

    /* 
    Payload encryption
    1) key&nonce&counter init -> tranforming key&nonce from hex to bytes format
    2) chacha20 ctx init, encrypted payload init -> payload encryption
    */

    uint8_t key[32];
    uint8_t nonce[24] = {0};
    uint32_t counter = 0;

    if (HexcharToBytes(keyHex, key, 32) != 0)
    {
        errorCode = PrintMessage(hCon, "Error: Invalid characters in key.", 4, ERROR_INVALID_DATA);
        return errorCode;
    }
    if (HexcharToBytes(nonceHex, nonce, 24) != 0)
    {
        errorCode = PrintMessage(hCon, "Error: Invalid characters in nonce.", 4, ERROR_INVALID_DATA);
        return errorCode;
    }

    chacha20poly1305_ctx encCtx;
    xchacha20poly1305_init(&encCtx, key, nonce);

    PrintMessage(hCon, "Encrypting data...", 7, 0);
    uint8_t* encryptedPayload = (uint8_t*)malloc(fileLen);
    if (!encryptedPayload)
    {
        errorCode = PrintMessage(hCon, "Error: Memory allocation failed for encryption.", 4, ERROR_NOT_ENOUGH_MEMORY);
        return errorCode;
    }

    chacha20poly1305_encrypt(&encCtx, (uint8_t*)fileBuff, encryptedPayload, fileLen);
    PrintMessage(hCon, "Encryption ended successfully", 2, 0);

    // Copy the pre-compiled stub as base for final.exe
    PrintMessage(hCon, "Copying stub template... ", 7, 0);
    if (!CopyFileA("stub.exe", "final.exe", FALSE))
    { 
        errorCode = PrintMessage(hCon, "Error: Could not copy stub.exe to final.exe. Make sure stub.exe exists!", 4, ERROR_FILE_NOT_FOUND);
        free(fileBuff);
        free(encryptedPayload);
        return errorCode;
    }
    PrintMessage(hCon, "Copying stub template ended succesfully", 2, 0);


    /* 
    Obfuscation of key and nonce
    1) Compute SHA-256 of encrypted payload
    2) Derive salt = first 16 bytes of that hash
    3) HKDF-Extract & Expand → OKM[80]
        OKM[0..31]   = obfuscation key
        OKM[32..55]  = obfuscation nonce
        OKM[56..79]  = meta-nonce for AEAD
    4) ChaCha20-Poly1305(obf_key, meta_nonce) encrypts key & nonce
    */

    SHA256Context shaCTX;
    HKDFContext hkdfCTX;
    chacha20poly1305_ctx obfuscationCtx;
    uint8_t hash[SHA256HashSize];
    uint8_t salt[16];
    uint8_t prk[USHAMaxHashSize];
    uint8_t okm[80];
    uint8_t metaNonce[24];
    uint8_t *obfuscatedKey = (uint8_t *)malloc(32);
    uint8_t *obfuscatedNonce = (uint8_t *)malloc(24);

    // 1) hash = SHA256(encryptedPayload)
    SHA256Reset(&shaCTX);
    SHA256Input(&shaCTX, encryptedPayload, fileLen);
    SHA256Result(&shaCTX, hash);

    // 2) salt = hash[0..15]
    memcpy(salt, hash, 16);

    // 3) HKDF(salt, IKM=hash) → okm[80]
    memset(&hkdfCTX, 0, sizeof(hkdfCTX));
    int hkdf_r1 = hkdfReset(&hkdfCTX, SHA256, salt, 16);
    int hkdf_r2 = hkdfInput(&hkdfCTX, hash, 32);
    int hkdf_r3 = hkdfResult(&hkdfCTX, prk, (const uint8_t *)"obfuscation-context", (int)strlen("obfuscation-context"), okm, 80);
    
    char debugMsg[128];
    snprintf(debugMsg, sizeof(debugMsg), "HKDF: reset=%d input=%d result=%d", hkdf_r1, hkdf_r2, hkdf_r3);
    PrintMessage(hCon, debugMsg, 6, 0);
    if (hkdf_r1 != 0 || hkdf_r2 != 0 || hkdf_r3 != 0)
    {
        errorCode = PrintMessage(hCon, "Error: HKDF derivation failed.", 4, ERROR_INTERNAL_ERROR);
        return errorCode;
    }

    // Split OKM into key, nonce, meta-nonce
    memcpy(obfuscatedKey, okm, 32);
    memcpy(obfuscatedNonce, okm + 32, 24);
    memcpy(metaNonce, okm + 56, 24);

    // 4) AEAD with (obfuscatedKey, metaNonce)
    xchacha20poly1305_init(&obfuscationCtx, obfuscatedKey, metaNonce);
    chacha20poly1305_encrypt(&obfuscationCtx, key, obfuscatedKey, 32);
    chacha20poly1305_encrypt(&obfuscationCtx, nonce, obfuscatedNonce, 24);


    // Adding resouces (encrypted data, obfuscated key&nonce) to final.exe 
    PrintMessage(hCon, "Adding encrypted resource to final.exe... ", 7, 0);
    HANDLE hUpdateRes;
    BOOL result;
    
    hUpdateRes = BeginUpdateResource("final.exe", FALSE);
    if (hUpdateRes == NULL)
    {
        errorCode = PrintMessage(hCon, "Error: Could not open final.exe for resource update.", 4, 1);
        free(fileBuff);
        free(encryptedPayload);
        if (obfuscatedKey) free(obfuscatedKey);
        if (obfuscatedNonce) free(obfuscatedNonce);
        return errorCode;
    }

    result = UpdateResource(hUpdateRes,
                            RT_RCDATA,
                            MAKEINTRESOURCE(132),
                            MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL),
                            encryptedPayload,
                            (DWORD)fileLen);
    
    if (result == FALSE)
    {
        errorCode = PrintMessage(hCon, "Error: Could not add payload-resource to final.exe.", 4, 1);
        EndUpdateResource(hUpdateRes, TRUE);
        free(fileBuff);
        free(encryptedPayload);
        if (obfuscatedKey) free(obfuscatedKey);
        if (obfuscatedNonce) free(obfuscatedNonce);
        return errorCode;
    }

    result = UpdateResource(hUpdateRes,
                            RT_RCDATA,
                            MAKEINTRESOURCE(133),
                            MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL),
                            obfuscatedKey,
                            32);
    
    if (result == FALSE)
    {
        errorCode = PrintMessage(hCon, "Error: Could not add key-resource to final.exe.", 4, 1);
        EndUpdateResource(hUpdateRes, TRUE);
        free(fileBuff);
        free(encryptedPayload);
        if (obfuscatedKey) free(obfuscatedKey);
        if (obfuscatedNonce) free(obfuscatedNonce);
        return errorCode;
    }
    
    result = UpdateResource(hUpdateRes,
                            RT_RCDATA,
                            MAKEINTRESOURCE(134),
                            MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL),
                            obfuscatedNonce,
                            24);

    if (result == FALSE)
    {
        errorCode = PrintMessage(hCon, "Error: Could not add nonce-resource to final.exe.", 4, 1);
        EndUpdateResource(hUpdateRes, TRUE);
        free(fileBuff);
        free(encryptedPayload);
        if (obfuscatedKey) free(obfuscatedKey);
        if (obfuscatedNonce) free(obfuscatedNonce);
        return errorCode;
    }

    if (!EndUpdateResource(hUpdateRes, FALSE))
    {
        errorCode = PrintMessage(hCon, "Error: Could not finalize resource update", 4, 1);
        free(fileBuff);
        free(encryptedPayload);
        if (obfuscatedKey) free(obfuscatedKey);
        if (obfuscatedNonce) free(obfuscatedNonce);
        return errorCode;
    }

    PrintMessage(hCon, "Added encrypted resources.", 2, 0);
    PrintMessage(hCon, "Packing completed successfully! Output file: final.exe", 10, 0);

    free(fileBuff);
    free(encryptedPayload);
    free(obfuscatedKey);
    free(obfuscatedNonce);

    errorCode = 0;
    return errorCode;
}