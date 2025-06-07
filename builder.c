#include <stdio.h>
#include <stdbool.h>
#include <windows.h>
#include "salsa20.h"
#include "SHA1.h"

int hex_char_to_int(char c)
{
    if ('0' <= c && c <= '9') return c - '0';
    if ('a' <= c && c <= 'f') return c - 'a' + 10;
    if ('A' <= c && c <= 'F') return c - 'A' + 10;
    return -1;
}

int hex_to_bytes(const char *hexStr, uint8_t *output, size_t expectedLen)
{
    size_t i;
    for (i = 0; i < expectedLen; i++)
    {
        int hi = hex_char_to_int(hexStr[2 * i]);
        int lo = hex_char_to_int(hexStr[2 * i + 1]);
        if (hi == -1 || lo == -1)
        {
            return -1; 
        }
        output[i] = (hi << 4) | lo;
    }
    return 0;
}

int main(int argc, char* argv[])
{
    HANDLE hCon = GetStdHandle(STD_OUTPUT_HANDLE);  
    printf("Checking input arguments... ");

    if (argc < 4) 
    {
        SetConsoleTextAttribute( hCon, 4 );
        printf("Error: Start this program with valid arguments.");
        SetConsoleTextAttribute( hCon, 7 );
        system("pause");
        return 0;
    }
    SetConsoleTextAttribute( hCon, 2 );
    printf("Success\n");
    SetConsoleTextAttribute( hCon, 7 );

    const char *inputFile = argv[1];
    const char *keyHex = argv[2];
    const char *nonceHex = argv[3];

    if (strlen(keyHex) != 64 || strlen(nonceHex) != 16)
    {
        SetConsoleTextAttribute( hCon, 4 );
        printf("Error: Invalid key or nonce length. Key must be 64 hex chars, nonce 16 hex chars.\n");
        SetConsoleTextAttribute( hCon, 7 );
        system("pause");
        return 0;
    }

    // Read the input PE file that we want to pack
    printf("Reading input file... ");
    FILE *filePtr;
    char *fileBuff;
    long fileLen;

    filePtr = fopen(inputFile, "rb");
    if (filePtr == NULL)
    {
        SetConsoleTextAttribute( hCon, 4 );
        printf("Error: Could not open input file.");
        SetConsoleTextAttribute( hCon, 7 );
        system("pause");
        return 0;
    }

    fseek(filePtr, 0, SEEK_END);
    fileLen = ftell(filePtr);
    rewind(filePtr);

    fileBuff = (char *)malloc(fileLen);
    if (fileBuff == NULL)
    {
        SetConsoleTextAttribute( hCon, 4 );
        printf("Error: Memory allocation failed.");
        SetConsoleTextAttribute( hCon, 7 );
        fclose(filePtr);
        system("pause");
        return 0;
    }

    size_t bytesRead = fread(fileBuff, 1, fileLen, filePtr);
    fclose(filePtr);
    if (bytesRead != (size_t)fileLen)
    {
        SetConsoleTextAttribute( hCon, 4 );
        printf("Error: Could not read input file.");
        SetConsoleTextAttribute( hCon, 7 );
        free(fileBuff);
        system("pause");
        return 0;
    }

    SetConsoleTextAttribute( hCon, 2 );
    printf("Success\n");
    SetConsoleTextAttribute( hCon, 7 );

    // Validate that input is x64 PE
    printf("Validate input file as x64 PE... ");
    IMAGE_DOS_HEADER* _dosHeader = (PIMAGE_DOS_HEADER) fileBuff;
    IMAGE_NT_HEADERS64* _ntHeader = (IMAGE_NT_HEADERS64*)((char*)fileBuff + _dosHeader->e_lfanew);
    bool is64 = _ntHeader->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64;
    if (!is64)
    {
        SetConsoleTextAttribute( hCon, 4 );
        printf("Error. Input file is not a valid x64 PE");
        SetConsoleTextAttribute( hCon, 7 );
        free(fileBuff);
        system("pause");
        return 0;
    }
    SetConsoleTextAttribute( hCon, 2 );
    printf("Success\n");
    SetConsoleTextAttribute( hCon, 7 );

    // Encrypt the input file data
    uint8_t key[32];
    uint8_t nonce[8];
    uint32_t counter = 0;
    if (hex_to_bytes(keyHex, key, 32) != 0)
    {
        SetConsoleTextAttribute( hCon, 4 );
        printf("Error: Invalid characters in key.\n");
        SetConsoleTextAttribute( hCon, 7 );
        system("pause");
        return 0;
    }
    if (hex_to_bytes(nonceHex, nonce, 8) != 0)
    {
        SetConsoleTextAttribute( hCon, 4 );
        printf("Error: Invalid characters in nonce.\n");
        SetConsoleTextAttribute( hCon, 7 );
        system("pause");
        return 1;
    }

    printf("Encrypting data... ");
    salsa20_crypt((uint8_t*)fileBuff, (uint32_t)fileLen, key, nonce, counter);
    SetConsoleTextAttribute( hCon, 2 );
    printf("Success\n");
    SetConsoleTextAttribute( hCon, 7 );

    // Copy the pre-compiled stub as base for final.exe
    printf("Copying stub template... ");
    if (!CopyFileA("stub.exe", "final.exe", FALSE))
    {
        SetConsoleTextAttribute( hCon, 4 );
        printf("Error: Could not copy stub.exe to final.exe. Make sure stub.exe exists!");
        SetConsoleTextAttribute( hCon, 7 );
        free(fileBuff);
        system("pause");
        return 0;
    }
    SetConsoleTextAttribute( hCon, 2 );
    printf("Success\n");
    SetConsoleTextAttribute( hCon, 7 );

    // Add encrypted data as resource to final.exe
    printf("Adding encrypted resource to final.exe... ");
    HANDLE hUpdateRes;
    BOOL result;

    // Making hash 
    unsigned char *data = (unsigned char*)fileBuff;
    unsigned char hash[SHA1_BLOCK_SIZE];
    SHA1(data, fileLen, hash);

    // init state for lcg
    unsigned long state = 
        ((unsigned long)hash[0]) |
        ((unsigned long)hash[1] << 8) |
        ((unsigned long)hash[2] << 16) |
        ((unsigned long)hash[3] << 24);

    // LCG call
    unsigned long LCG_Result = lcg_rand(&state);

    uint8_t *obfuscatedKey = (uint8_t *)malloc(32);
    uint8_t *obfuscatedNonce = (uint8_t *)malloc(8);

    if (!obfuscatedKey || !obfuscatedNonce)
    {
        SetConsoleTextAttribute(hCon, 4);
        printf("Error: Memory allocation failed for obfuscation.");
        SetConsoleTextAttribute(hCon, 7);
        free(fileBuff);
        if (obfuscatedKey) free(obfuscatedKey);
        if (obfuscatedNonce) free(obfuscatedNonce);
        system("pause");
        return 0;
    }

    for (int i = 0; i < 32; i++)
    {
        obfuscatedKey[i] = key[i] ^ ((LCG_Result >> ((i % 4) * 8)) & 0xFF);
    }

    for (int i = 0; i < 8; i++)
    {
        obfuscatedNonce[i] = nonce[i] ^ ((LCG_Result >> ((i % 4) * 8)) & 0xFF);
    }

    hUpdateRes = BeginUpdateResource("final.exe", FALSE);
    if (hUpdateRes == NULL)
    {
        SetConsoleTextAttribute( hCon, 4 );
        printf("Error: Could not open final.exe for resource update");
        SetConsoleTextAttribute( hCon, 7 );
        free(fileBuff);
        system("pause");
        return 0;
    }

    // Add the encrypted payload as a resource
    result = UpdateResource(hUpdateRes,
                            RT_RCDATA,                   // resource type
                            MAKEINTRESOURCE(132),        // resource ID
                            MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL),
                            fileBuff,                    // encrypted data
                            (DWORD)fileLen);             // size of encrypted data
    
    if (result == FALSE)
    {
        SetConsoleTextAttribute( hCon, 4 );
        printf("Error: Could not add payload-resource to final.exe");
        SetConsoleTextAttribute( hCon, 7 );
        EndUpdateResource(hUpdateRes, TRUE);
        free(fileBuff);
        system("pause");
        return 0;
    }

    result = UpdateResource(hUpdateRes,
                            RT_RCDATA,
                            MAKEINTRESOURCE(133),
                            MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL),
                            obfuscatedKey,
                            32);
    
    if (result == FALSE)
    {
        SetConsoleTextAttribute( hCon, 4 );
        printf("Error: Could not add key-resource to final.exe");
        SetConsoleTextAttribute( hCon, 7 );
        EndUpdateResource(hUpdateRes, TRUE);
        free(fileBuff);
        system("pause");
        return 0;
    }
    
    result = UpdateResource(hUpdateRes,
                            RT_RCDATA,
                            MAKEINTRESOURCE(134),
                            MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL),
                            obfuscatedNonce,
                            8);

    if (result == FALSE)
    {
        SetConsoleTextAttribute( hCon, 4 );
        printf("Error: Could not add nonce-resource to final.exe");
        SetConsoleTextAttribute( hCon, 7 );
        EndUpdateResource(hUpdateRes, TRUE);
        free(fileBuff);
        system("pause");
        return 0;
    }

    if (!EndUpdateResource(hUpdateRes, FALSE))
    {
        SetConsoleTextAttribute( hCon, 4 );
        printf("Error: Could not finalize resource update");
        SetConsoleTextAttribute( hCon, 7 );
        free(fileBuff);
        system("pause");
        return 0;
    }

    SetConsoleTextAttribute( hCon, 2 );
    printf("Success\n");
    SetConsoleTextAttribute( hCon, 7 );

    printf("\n");
    SetConsoleTextAttribute( hCon, 10 );
    printf("Packing completed successfully! Output file: final.exe\n");
    SetConsoleTextAttribute( hCon, 7 );

    free(fileBuff);
    free(obfuscatedKey);
    free(obfuscatedNonce);
    system("pause");
    return 0;
}
