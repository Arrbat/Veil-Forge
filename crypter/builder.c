//takes payload and ecnrypts it
//returns ecnrypted .exe into stub in form of bytes array

#include <windows.h>
#include <stdint.h>
#include "salsa20.h"

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        return ERROR_BAD_ARGUMENTS;
    }

    HANDLE hFile = CreateFileA(argv[1], GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    DWORD fileSize = GetFileSize(hFile, NULL);
    BYTE* bytes = HeapAlloc(GetProcessHeap(), 0, fileSize);
    DWORD read;
    ReadFile(hFile, bytes, fileSize, &read, NULL);
    CloseHandle(hFile);

    const uint8_t key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };
    const uint8_t nonce[8] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
    };

    salsa20_encrypt(bytes, fileSize, key, nonce, 0);

    HANDLE hOut = CreateFileA("encrypted.exe", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hOut == INVALID_HANDLE_VALUE) {
        HeapFree(GetProcessHeap(), 0, bytes);
        return 1;
    }

    DWORD written;
    WriteFile(hOut, bytes, fileSize, &written, NULL);
    CloseHandle(hOut);

    HeapFree(GetProcessHeap(), 0, bytes);
    return 0;
}
