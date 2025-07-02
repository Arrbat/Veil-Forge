#include <stdio.h>
#include <stdbool.h>
#include <windows.h>
#include "crypto/hashing/sha.h"
#include "crypto/chacha20-poly1305/chacha20poly1305.h"
#include "headers/packer.h"

/**
 * @brief Print a message to the console with color and error code.
 */
static int PrintMessage(HANDLE hCon, const char* text, int consoleColorCode, int errorCode)
{
    SetConsoleTextAttribute(hCon, consoleColorCode);
    fprintf(stderr, "%s\n", text);
    SetConsoleTextAttribute(hCon, 7);
    return errorCode;
}

/**
 * @brief Convert a hex character to its integer value.
 */
static int HexcharToInt(char c)
{
    if ('0' <= c && c <= '9') return c - '0';
    if ('a' <= c && c <= 'f') return c - 'a' + 10;
    if ('A' <= c && c <= 'F') return c - 'A' + 10;
    return -1;
}

/**
 * @brief Convert a hex string to bytes.
 */
static int HexcharToBytes(const char* hexStr, uint8_t* output, size_t expectedLen)
{
    for (size_t i = 0; i < expectedLen; i++)
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

/**
 * @brief Free all allocated resources in BuildContext and CryptoContext.
 */
static void CleanupResources(BuildContext* buildCtx, CryptoContext* cryptoCtx)
{
    if (buildCtx->fileBuff) free(buildCtx->fileBuff);
    if (buildCtx->encryptedPayload) free(buildCtx->encryptedPayload);
    if (cryptoCtx->obfuscatedKey) free(cryptoCtx->obfuscatedKey);
    if (cryptoCtx->obfuscatedNonce) free(cryptoCtx->obfuscatedNonce);
}

/**
 * @brief Validate that the input file is a valid x64 PE file.
 */
static int ValidatePE(BuildContext* buildCtx, ConsoleContext* consoleCtx)
{
    PrintMessage(consoleCtx->hCon, "Validate input file as x64 PE... ", 7, 0);
    IMAGE_DOS_HEADER* _dosHeader = (PIMAGE_DOS_HEADER)buildCtx->fileBuff;
    IMAGE_NT_HEADERS64* _ntHeader = (IMAGE_NT_HEADERS64*)((char*)buildCtx->fileBuff + _dosHeader->e_lfanew);

    bool is64 = _ntHeader->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64;
    if (!is64)
    {
        consoleCtx->errorCode = PrintMessage(consoleCtx->hCon, "Error. Input file is not a valid x64 PE.", 4, ERROR_BAD_FORMAT);
        return 0;
    }
    
    PrintMessage(consoleCtx->hCon, "File is valid x64 PE.", 2, 0);
    return 1;
}

/**
 * @brief Read the input file into memory.
 */
static int ReadInputFile(BuildContext* buildCtx, ConsoleContext* consoleCtx)
{
    PrintMessage(consoleCtx->hCon, "Reading input file... ", 7, 0);
    FILE* filePtr = fopen(buildCtx->inputFile, "rb");
    if (!filePtr)
    {
        consoleCtx->errorCode = PrintMessage(consoleCtx->hCon, "Error: Could not open input file.", 4, ERROR_FILE_NOT_FOUND);
        return 0;
    }

    fseek(filePtr, 0, SEEK_END);
    buildCtx->fileLen = ftell(filePtr);
    rewind(filePtr);

    buildCtx->fileBuff = (char*)malloc(buildCtx->fileLen);
    if (!buildCtx->fileBuff)
    {
        consoleCtx->errorCode = PrintMessage(consoleCtx->hCon, "Error: Memory allocation failed.", 4, ERROR_NOT_ENOUGH_MEMORY);
        fclose(filePtr);
        return 0;
    }

    size_t bytesRead = fread(buildCtx->fileBuff, 1, buildCtx->fileLen, filePtr);
    fclose(filePtr);
    
    if (bytesRead != (size_t)buildCtx->fileLen)
    {
        consoleCtx->errorCode = PrintMessage(consoleCtx->hCon, "Error: Could not read input file.", 4, ERROR_FILE_NOT_FOUND);
        return 0;
    }

    PrintMessage(consoleCtx->hCon, "Read file successfully.", 2, 0);
    return 1;
}

/**
 * @brief Update resources in the output executable.
 */
static int UpdateResources(BuildContext* buildCtx, CryptoContext* cryptoCtx, ConsoleContext* consoleCtx)
{
    PrintMessage(consoleCtx->hCon, "Adding encrypted resource to final.exe... ", 7, 0);
    
    buildCtx->hUpdateRes = BeginUpdateResource("final.exe", FALSE);
    if (!buildCtx->hUpdateRes) {
        consoleCtx->errorCode = PrintMessage(consoleCtx->hCon, "Error: Could not open final.exe for resource update.", 4, 1);
        return 0;
    }

    // Update payload resource
    if (!UpdateResource(buildCtx->hUpdateRes, RT_RCDATA, MAKEINTRESOURCE(PAYLOAD_RESOURCE_ID),
        MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL), buildCtx->encryptedPayload, (DWORD)buildCtx->fileLen))
    {
        consoleCtx->errorCode = PrintMessage(consoleCtx->hCon, "Error: Could not add payload-resource to final.exe.", 4, 1);
        EndUpdateResource(buildCtx->hUpdateRes, TRUE);
        return 0;
    }

    // Update key resource
    if (!UpdateResource(buildCtx->hUpdateRes, RT_RCDATA, MAKEINTRESOURCE(KEY_RESOURCE_ID),
        MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL), cryptoCtx->obfuscatedKey, KEY_SIZE))
    {
        consoleCtx->errorCode = PrintMessage(consoleCtx->hCon, "Error: Could not add key-resource to final.exe.", 4, 1);
        EndUpdateResource(buildCtx->hUpdateRes, TRUE);
        return 0;
    }

    // Update nonce resource
    if (!UpdateResource(buildCtx->hUpdateRes, RT_RCDATA, MAKEINTRESOURCE(NONCE_RESOURCE_ID),
        MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL), cryptoCtx->obfuscatedNonce, NONCE_SIZE))
    {
        consoleCtx->errorCode = PrintMessage(consoleCtx->hCon, "Error: Could not add nonce-resource to final.exe.", 4, 1);
        EndUpdateResource(buildCtx->hUpdateRes, TRUE);
        return 0;
    }

    if (!EndUpdateResource(buildCtx->hUpdateRes, FALSE))
    {
        consoleCtx->errorCode = PrintMessage(consoleCtx->hCon, "Error: Could not finalize resource update.", 4, 1);
        return 0;
    }

    PrintMessage(consoleCtx->hCon, "Added encrypted resources.", 2, 0);
    return 1;
}

int main(int argc, char* argv[])
{
    ConsoleContext consoleCtx = 
    { 
        .hCon = GetStdHandle(STD_OUTPUT_HANDLE),
        .errorCode = 0
    };

    BuildContext buildCtx =
    {
        .inputFile = argv[1],
        .success = true
    };
   
    CryptoContext cryptoCtx = {0};

    PrintMessage(consoleCtx.hCon, "Checking input arguments...", 7, 0);
    if (argc < 4)
    {
        consoleCtx.errorCode = PrintMessage(consoleCtx.hCon, "Error: Start this program with valid arguments. ./packer.exe your.exe KEY64_IN_HEX NONCE24_IN_HEX", 4, ERROR_BAD_ARGUMENTS);
        return consoleCtx.errorCode;
    }
    PrintMessage(consoleCtx.hCon, "Arguments are valid.", 2, 0);

    cryptoCtx.obfuscatedKey = (uint8_t*)malloc(KEY_SIZE);
    cryptoCtx.obfuscatedNonce = (uint8_t*)malloc(NONCE_SIZE);

    const char* keyHex = argv[2];
    const char* nonceHex = argv[3];

    if (strlen(keyHex) != KEY_SIZE * 2 || strlen(nonceHex) != NONCE_SIZE * 2)
    {
        consoleCtx.errorCode = PrintMessage(consoleCtx.hCon, "Error: Invalid key or nonce length. Key must be 64 hex chars, nonce 48 hex chars.", 4, ERROR_INVALID_DATA);
        goto cleanup;
    }

    // Convert hex strings to bytes
    if (HexcharToBytes(keyHex, cryptoCtx.key, KEY_SIZE) != 0)
    {
        consoleCtx.errorCode = PrintMessage(consoleCtx.hCon, "Error: Invalid characters in key.", 4, ERROR_INVALID_DATA);
        goto cleanup;
    }
    if (HexcharToBytes(nonceHex, cryptoCtx.nonce, NONCE_SIZE) != 0)
    {
        consoleCtx.errorCode = PrintMessage(consoleCtx.hCon, "Error: Invalid characters in nonce.", 4, ERROR_INVALID_DATA);
        goto cleanup;
    }

    // Read and validate input file
    if (!ReadInputFile(&buildCtx, &consoleCtx) || !ValidatePE(&buildCtx, &consoleCtx))
    {
        goto cleanup;
    }

    PrintMessage(consoleCtx.hCon, "Encrypting data...", 7, 0);
    buildCtx.encryptedPayload = (uint8_t*)malloc(buildCtx.fileLen);
    if (!buildCtx.encryptedPayload) {
        consoleCtx.errorCode = PrintMessage(consoleCtx.hCon, "Error: Memory allocation failed for encryption.", 4, ERROR_NOT_ENOUGH_MEMORY);
        goto cleanup;
    }

    // Encrypt payload
    chacha20poly1305_ctx encCtx;
    xchacha20poly1305_init(&encCtx, cryptoCtx.key, cryptoCtx.nonce);
    chacha20poly1305_encrypt(&encCtx, (uint8_t*)buildCtx.fileBuff, buildCtx.encryptedPayload, buildCtx.fileLen);
    PrintMessage(consoleCtx.hCon, "Encryption ended successfully.", 2, 0);

    // Copy stub template
    PrintMessage(consoleCtx.hCon, "Copying stub template... ", 7, 0);
    if (!CopyFileA("unpacker.exe", "final.exe", FALSE)) {
        consoleCtx.errorCode = PrintMessage(consoleCtx.hCon, "Error: Could not copy stub.exe to final.exe. Make sure stub.exe exists!", 4, ERROR_FILE_NOT_FOUND);
        goto cleanup;
    }
    PrintMessage(consoleCtx.hCon, "Copying stub template ended successfully.", 2, 0);

    // Compute hash and derive keys
    SHA256Context shaCTX;
    SHA256Reset(&shaCTX);
    SHA256Input(&shaCTX, buildCtx.encryptedPayload, buildCtx.fileLen);
    SHA256Result(&shaCTX, cryptoCtx.hash);
    memcpy(cryptoCtx.salt, cryptoCtx.hash, SALT_SIZE);

    // HKDF key derivation
    HKDFContext hkdfCTX;
    memset(&hkdfCTX, 0, sizeof(hkdfCTX));
    
    int hkdf_r1 = hkdfReset(&hkdfCTX, SHA256, cryptoCtx.salt, SALT_SIZE);
    int hkdf_r2 = hkdfInput(&hkdfCTX, cryptoCtx.hash, KEY_SIZE);
    int hkdf_r3 = hkdfResult(&hkdfCTX, cryptoCtx.prk, (const uint8_t*)"obfuscation-context", 
                    (int)strlen("obfuscation-context"), cryptoCtx.okm, OKM_SIZE);

    char debugMsg[128];
    snprintf(debugMsg, sizeof(debugMsg), "HKDF: reset=%d input=%d result=%d. HKDF ended as expected.", hkdf_r1, hkdf_r2, hkdf_r3);
    PrintMessage(consoleCtx.hCon, debugMsg, 6, 0);

    if (hkdf_r1 != 0 || hkdf_r2 != 0 || hkdf_r3 != 0)
    {
        consoleCtx.errorCode = PrintMessage(consoleCtx.hCon, "Error: HKDF derivation failed.", 4, ERROR_INTERNAL_ERROR);
        goto cleanup;
    }

    // Encrypt key and nonce
    chacha20poly1305_ctx obfuscationCtx;
    xchacha20poly1305_init(&obfuscationCtx, cryptoCtx.okm, cryptoCtx.okm + 56);
    chacha20poly1305_encrypt(&obfuscationCtx, cryptoCtx.key, cryptoCtx.obfuscatedKey, KEY_SIZE);
    chacha20poly1305_encrypt(&obfuscationCtx, cryptoCtx.nonce, cryptoCtx.obfuscatedNonce, NONCE_SIZE);

    // Update resources in final.exe
    if (!UpdateResources(&buildCtx, &cryptoCtx, &consoleCtx))
    {
        goto cleanup;
    }

    PrintMessage(consoleCtx.hCon, "Packing completed successfully! Output file: final.exe.", 10, 0);
    CleanupResources(&buildCtx, &cryptoCtx);
    return 0;

cleanup:
    CleanupResources(&buildCtx, &cryptoCtx);
    return consoleCtx.errorCode;
}