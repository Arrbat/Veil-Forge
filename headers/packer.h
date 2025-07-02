#ifndef PACKER_H
#define PACKER_H

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
 * @brief Holds cryptographic context and keys
 */
typedef struct
{
    uint8_t key[KEY_SIZE];
    uint8_t nonce[NONCE_SIZE];
    uint8_t metaNonce[METANONCE_SIZE];
    uint8_t salt[SALT_SIZE];
    uint8_t okm[OKM_SIZE]; 
    uint8_t hash[SHA256HashSize];
    uint8_t prk[USHAMaxHashSize];
    uint8_t* obfuscatedKey;
    uint8_t* obfuscatedNonce;
}   CryptoContext;

/** 
 * @brief Holds information about the file being packed
 */
typedef struct
{
    const char* inputFile;
    char* fileBuff;
    long fileLen;
    uint8_t* encryptedPayload;
    HANDLE hUpdateRes;
    bool success;
}   BuildContext;

/**
 * @brief Holds console handle and error-code for messaging
 */
typedef struct
{
    HANDLE hCon;
    int errorCode;
}   ConsoleContext;

#endif /* PACKER_H */