#include <stdio.h>
#include <stdbool.h>
#include <windows.h>
#include "salsa20.h"

int main(int argc, char* argv[])
{
    HANDLE hCon = GetStdHandle(STD_OUTPUT_HANDLE);  
    printf("Checking input arguments... ");

    if (argc < 2) 
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

    // Read the input PE file that we want to pack
    printf("Reading input file... ");
    FILE *fileptr;
    char *fileBuff;
    long filelen;

    fileptr = fopen(inputFile, "rb");
    if (fileptr == NULL)
    {
        SetConsoleTextAttribute( hCon, 4 );
        printf("Error: Could not open input file.");
        SetConsoleTextAttribute( hCon, 7 );
        system("pause");
        return 0;
    }

    fseek(fileptr, 0, SEEK_END);
    filelen = ftell(fileptr);
    rewind(fileptr);

    fileBuff = (char *)malloc(filelen);
    if (fileBuff == NULL)
    {
        SetConsoleTextAttribute( hCon, 4 );
        printf("Error: Memory allocation failed.");
        SetConsoleTextAttribute( hCon, 7 );
        fclose(fileptr);
        system("pause");
        return 0;
    }

    size_t bytesRead = fread(fileBuff, 1, filelen, fileptr);
    fclose(fileptr);
    if (bytesRead != (size_t)filelen)
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
    if (!is64) {
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

    printf("Encrypting data... ");
    salsa20_crypt((uint8_t*)fileBuff, (uint32_t)filelen, key, nonce, counter);
    SetConsoleTextAttribute( hCon, 2 );
    printf("Success\n");
    SetConsoleTextAttribute( hCon, 7 );

    // Copy the pre-compiled stub as base for final.exe
    printf("Copying stub template... ");
    if (!CopyFileA("stub.exe", "final.exe", FALSE)) {
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

    // Add the encrypted payload as a resource with ID 132 and type RT_RCDATA
    result = UpdateResource(hUpdateRes,
                            RT_RCDATA,                   // resource type
                            MAKEINTRESOURCE(132),        // resource ID
                            MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL),
                            fileBuff,                    // encrypted data
                            (DWORD)filelen);             // size of encrypted data

    if (result == FALSE)
    {
        SetConsoleTextAttribute( hCon, 4 );
        printf("Error: Could not add resource to final.exe");
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
    system("pause");
    return 0;
}