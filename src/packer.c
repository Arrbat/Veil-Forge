#include <stdio.h>
#include <stdbool.h>
#include <windows.h>
#include "crypto/hashing/sha.h"
#include "crypto/chacha20-poly1305/chacha20poly1305.h"
#include "headers/packer.h"

static int PrintMessage(HANDLE hCon, const char* text, int consoleColorCode, int errorCode)
{
    SetConsoleTextAttribute(hCon, consoleColorCode);
    fprintf(stderr, "%s\n", text);
    SetConsoleTextAttribute(hCon, 7);
    return errorCode;
}

static int HexcharToInt(char c)
{
    if ('0' <= c && c <= '9') return c - '0';
    if ('a' <= c && c <= 'f') return c - 'a' + 10;
    if ('A' <= c && c <= 'F') return c - 'A' + 10;
    return -1;
}

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

static void CleanupResources(BuildContext* ctx, CryptoContext* crypto)
{
    if (ctx->fileBuff) free(ctx->fileBuff);
    if (ctx->encryptedPayload) free(ctx->encryptedPayload);
    if (crypto->obfuscatedKey) free(crypto->obfuscatedKey);
    if (crypto->obfuscatedNonce) free(crypto->obfuscatedNonce);
}

static int ValidatePE(BuildContext* ctx, ConsoleContext* console)
{
    PrintMessage(console->hCon, "Validate input file as x64 PE... ", 7, 0);
    IMAGE_DOS_HEADER* _dosHeader = (PIMAGE_DOS_HEADER)ctx->fileBuff;
    IMAGE_NT_HEADERS64* _ntHeader = (IMAGE_NT_HEADERS64*)((char*)ctx->fileBuff + _dosHeader->e_lfanew);

    bool is64 = _ntHeader->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64;
    if (!is64)
    {
        console->errorCode = PrintMessage(console->hCon, "Error. Input file is not a valid x64 PE", 4, ERROR_BAD_FORMAT);
        return 0;
    }
    
    PrintMessage(console->hCon, "File is valid x64 PE.", 2, 0);
    return 1;
}

static int ReadInputFile(BuildContext* ctx, ConsoleContext* console)
{
    PrintMessage(console->hCon, "Reading input file... ", 7, 0);
    FILE* filePtr = fopen(ctx->inputFile, "rb");
    if (!filePtr)
    {
        console->errorCode = PrintMessage(console->hCon, "Error: Could not open input file.", 4, ERROR_FILE_NOT_FOUND);
        return 0;
    }

    fseek(filePtr, 0, SEEK_END);
    ctx->fileLen = ftell(filePtr);
    rewind(filePtr);

    ctx->fileBuff = (char*)malloc(ctx->fileLen);
    if (!ctx->fileBuff)
    {
        console->errorCode = PrintMessage(console->hCon, "Error: Memory allocation failed.", 4, ERROR_NOT_ENOUGH_MEMORY);
        fclose(filePtr);
        return 0;
    }

    size_t bytesRead = fread(ctx->fileBuff, 1, ctx->fileLen, filePtr);
    fclose(filePtr);
    
    if (bytesRead != (size_t)ctx->fileLen)
    {
        console->errorCode = PrintMessage(console->hCon, "Error: Could not read input file.", 4, ERROR_FILE_NOT_FOUND);
        return 0;
    }

    PrintMessage(console->hCon, "Read file successfully.", 2, 0);
    return 1;
}

static int UpdateResources(BuildContext* ctx, CryptoContext* crypto, ConsoleContext* console)
{
    PrintMessage(console->hCon, "Adding encrypted resource to final.exe... ", 7, 0);
    
    ctx->hUpdateRes = BeginUpdateResource("final.exe", FALSE);
    if (!ctx->hUpdateRes) {
        console->errorCode = PrintMessage(console->hCon, "Error: Could not open final.exe for resource update.", 4, 1);
        return 0;
    }

    // Update payload resource
    if (!UpdateResource(ctx->hUpdateRes, RT_RCDATA, MAKEINTRESOURCE(PAYLOAD_RESOURCE_ID),
        MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL), ctx->encryptedPayload, (DWORD)ctx->fileLen))
    {
        console->errorCode = PrintMessage(console->hCon, "Error: Could not add payload-resource to final.exe.", 4, 1);
        EndUpdateResource(ctx->hUpdateRes, TRUE);
        return 0;
    }

    // Update key resource
    if (!UpdateResource(ctx->hUpdateRes, RT_RCDATA, MAKEINTRESOURCE(KEY_RESOURCE_ID),
        MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL), crypto->obfuscatedKey, KEY_SIZE))
    {
        console->errorCode = PrintMessage(console->hCon, "Error: Could not add key-resource to final.exe.", 4, 1);
        EndUpdateResource(ctx->hUpdateRes, TRUE);
        return 0;
    }

    // Update nonce resource
    if (!UpdateResource(ctx->hUpdateRes, RT_RCDATA, MAKEINTRESOURCE(NONCE_RESOURCE_ID),
        MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL), crypto->obfuscatedNonce, NONCE_SIZE))
    {
        console->errorCode = PrintMessage(console->hCon, "Error: Could not add nonce-resource to final.exe.", 4, 1);
        EndUpdateResource(ctx->hUpdateRes, TRUE);
        return 0;
    }

    if (!EndUpdateResource(ctx->hUpdateRes, FALSE))
    {
        console->errorCode = PrintMessage(console->hCon, "Error: Could not finalize resource update", 4, 1);
        return 0;
    }

    PrintMessage(console->hCon, "Added encrypted resources.", 2, 0);
    return 1;
}

int main(int argc, char* argv[])
{
    ConsoleContext console = 
    { 
        .hCon = GetStdHandle(STD_OUTPUT_HANDLE),
        .errorCode = 0
    };

    PrintMessage(console.hCon, "Checking input arguments...", 7, 0);
    if (argc < 4)
    {
        console.errorCode = PrintMessage(console.hCon, "Error: Start this program with valid arguments.", 4, ERROR_BAD_ARGUMENTS);
        return console.errorCode;
    }
    PrintMessage(console.hCon, "Arguments are valid.", 2, 0);

    BuildContext ctx =
    {
        .inputFile = argv[1],
        .success = true
    };
    
    CryptoContext crypto = {0};
    crypto.obfuscatedKey = (uint8_t*)malloc(KEY_SIZE);
    crypto.obfuscatedNonce = (uint8_t*)malloc(NONCE_SIZE);

    const char* keyHex = argv[2];
    const char* nonceHex = argv[3];

    if (strlen(keyHex) != KEY_SIZE * 2 || strlen(nonceHex) != NONCE_SIZE * 2)
    {
        console.errorCode = PrintMessage(console.hCon, "Error: Invalid key or nonce length. Key must be 64 hex chars, nonce 48 hex chars.", 4, ERROR_INVALID_DATA);
        goto cleanup;
    }

    // Convert hex strings to bytes
    if (HexcharToBytes(keyHex, crypto.key, KEY_SIZE) != 0)
    {
        console.errorCode = PrintMessage(console.hCon, "Error: Invalid characters in key.", 4, ERROR_INVALID_DATA);
        goto cleanup;
    }
    if (HexcharToBytes(nonceHex, crypto.nonce, NONCE_SIZE) != 0)
    {
        console.errorCode = PrintMessage(console.hCon, "Error: Invalid characters in nonce.", 4, ERROR_INVALID_DATA);
        goto cleanup;
    }

    // Read and validate input file
    if (!ReadInputFile(&ctx, &console) || !ValidatePE(&ctx, &console))
    {
        goto cleanup;
    }

    PrintMessage(console.hCon, "Encrypting data...", 7, 0);
    ctx.encryptedPayload = (uint8_t*)malloc(ctx.fileLen);
    if (!ctx.encryptedPayload) {
        console.errorCode = PrintMessage(console.hCon, "Error: Memory allocation failed for encryption.", 4, ERROR_NOT_ENOUGH_MEMORY);
        goto cleanup;
    }

    // Encrypt payload
    chacha20poly1305_ctx encCtx;
    xchacha20poly1305_init(&encCtx, crypto.key, crypto.nonce);
    chacha20poly1305_encrypt(&encCtx, (uint8_t*)ctx.fileBuff, ctx.encryptedPayload, ctx.fileLen);
    PrintMessage(console.hCon, "Encryption ended successfully", 2, 0);

    // Copy stub template
    PrintMessage(console.hCon, "Copying stub template... ", 7, 0);
    if (!CopyFileA("unpacker.exe", "final.exe", FALSE)) {
        console.errorCode = PrintMessage(console.hCon, "Error: Could not copy stub.exe to final.exe. Make sure stub.exe exists!", 4, ERROR_FILE_NOT_FOUND);
        goto cleanup;
    }
    PrintMessage(console.hCon, "Copying stub template ended successfully", 2, 0);

    // Compute hash and derive keys
    SHA256Context shaCTX;
    SHA256Reset(&shaCTX);
    SHA256Input(&shaCTX, ctx.encryptedPayload, ctx.fileLen);
    SHA256Result(&shaCTX, crypto.hash);
    memcpy(crypto.salt, crypto.hash, SALT_SIZE);

    // HKDF key derivation
    HKDFContext hkdfCTX;
    memset(&hkdfCTX, 0, sizeof(hkdfCTX));
    
    int hkdf_r1 = hkdfReset(&hkdfCTX, SHA256, crypto.salt, SALT_SIZE);
    int hkdf_r2 = hkdfInput(&hkdfCTX, crypto.hash, KEY_SIZE);
    int hkdf_r3 = hkdfResult(&hkdfCTX, crypto.prk, (const uint8_t*)"obfuscation-context", 
                    (int)strlen("obfuscation-context"), crypto.okm, OKM_SIZE);

    char debugMsg[128];
    snprintf(debugMsg, sizeof(debugMsg), "HKDF: reset=%d input=%d result=%d", hkdf_r1, hkdf_r2, hkdf_r3);
    PrintMessage(console.hCon, debugMsg, 6, 0);

    if (hkdf_r1 != 0 || hkdf_r2 != 0 || hkdf_r3 != 0)
    {
        console.errorCode = PrintMessage(console.hCon, "Error: HKDF derivation failed.", 4, ERROR_INTERNAL_ERROR);
        goto cleanup;
    }

    // Encrypt key and nonce
    chacha20poly1305_ctx obfuscationCtx;
    xchacha20poly1305_init(&obfuscationCtx, crypto.okm, crypto.okm + 56);
    chacha20poly1305_encrypt(&obfuscationCtx, crypto.key, crypto.obfuscatedKey, KEY_SIZE);
    chacha20poly1305_encrypt(&obfuscationCtx, crypto.nonce, crypto.obfuscatedNonce, NONCE_SIZE);

    // Update resources in final.exe
    if (!UpdateResources(&ctx, &crypto, &console))
    {
        goto cleanup;
    }

    PrintMessage(console.hCon, "Packing completed successfully! Output file: final.exe", 10, 0);
    CleanupResources(&ctx, &crypto);
    return 0;

cleanup:
    CleanupResources(&ctx, &crypto);
    return console.errorCode;
}