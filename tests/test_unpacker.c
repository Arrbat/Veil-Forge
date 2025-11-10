#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "minunit.h"
#include "../src/unpacker.c"


/* Check that a memory region is freed (MEM_FREE) after VirtualFree(MEM_RELEASE).
   VirtualQuery on a freed address should return information indicating MEM_FREE.

   TL;DR: Free function
*/
static int is_region_free(void* addr) {
    MEMORY_BASIC_INFORMATION mbi = {0};
    SIZE_T r = VirtualQuery(addr, &mbi, sizeof(mbi));
    if (r == 0) return 0;
    return (mbi.State == MEM_FREE);
}

MU_TEST(test_AddJunkCode_returns_zero)
{
    int r = AddJunkCode();
    mu_assert_int_eq(r, 0);
    printf("[PASSED] AddJunkCode returns 0\n");
}

MU_TEST(test_GetResource_returns_null_for_missing)
{
    unsigned long size = 0;
    unsigned char* res = GetResource(0xDEADBEEF, RT_RCDATA, &size); // Such ID is not used, so good to test
    mu_check(res == NULL);
    mu_assert_int_eq((int)size, 0);
    printf("[PASSED] GetResource returned NULL and size 0 for absent resource\n");
}

MU_TEST(test_CleanupResources_zeroes_and_frees)
{
    CryptoContext crypto = {0};
    // zeroing
    for (int i = 0; i < KEY_SIZE; ++i) { crypto.key[i] = (uint8_t)(i + 1); }
    for (int i = 0; i < NONCE_SIZE; ++i) { crypto.nonce[i] = (uint8_t)(i + 0xA); }

    SIZE_T payloadSize = 4096;
    uint8_t* decrypted = (uint8_t*)VirtualAlloc(NULL, payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    mu_check(decrypted != NULL);

    // Fill decrypted buffer with non-zero pattern
    memset(decrypted, 0x5A, payloadSize);
    CleanupResources(&crypto, decrypted, (unsigned long)payloadSize);

    // Check crypto fields zeroed
    int key_zero = 1;
    for (int i = 0; i < KEY_SIZE; ++i) 
    {
        if (crypto.key[i] != 0) { key_zero = 0; break; }
    }
    mu_assert_int_eq(key_zero, 1);

    int nonce_zero = 1;
    for (int i = 0; i < NONCE_SIZE; ++i) 
    {
        if (crypto.nonce[i] != 0) { nonce_zero = 0; break; }
    }
    mu_assert_int_eq(nonce_zero, 1);

    // allocated region is released (MEM_FREE) ?
    int freed = is_region_free(decrypted);
    mu_assert_int_eq(freed, 1);

    printf("[PASSED] CleanupResources zeroed secrets and released memory\n");
}

MU_TEST_SUITE(unpacker_suite)
{
    MU_RUN_TEST(test_AddJunkCode_returns_zero);
    MU_RUN_TEST(test_GetResource_returns_null_for_missing);
    MU_RUN_TEST(test_CleanupResources_zeroes_and_frees);
}

int main(void)
{
    printf("=== Running unpacker unit tests ===\n\n");
    MU_RUN_SUITE(unpacker_suite);
    MU_REPORT();
    printf("\n=== Unpacker tests completed ===\n");
    return (minunit_fail ? 1 : 0);
}
