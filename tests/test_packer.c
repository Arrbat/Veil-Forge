#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "minunit.h"
#include "../src/packer.c"

static void print_result(const char* msg, bool success) {
    if (success)
        printf("[PASSED] %s\n", msg);
    else
        printf("[FAILED] %s\n", msg);
}

MU_TEST(test_PrintMessage_return_code)
{
    HANDLE hCon = GetStdHandle(STD_ERROR_HANDLE);
    int ret = PrintMessage(hCon, "Test Message", 4, 42);
    mu_assert_int_eq(ret, 42);
    print_result("PrintMessage returns correct code", true);
}

MU_TEST(test_HexcharToInt_valid)
{
    mu_assert_int_eq(HexcharToInt('0'), 0);
    mu_assert_int_eq(HexcharToInt('9'), 9);
    mu_assert_int_eq(HexcharToInt('a'), 10);
    mu_assert_int_eq(HexcharToInt('F'), 15);
    print_result("HexcharToInt returns correct int for valid chars", true);
}

MU_TEST(test_HexcharToInt_invalid)
{
    mu_assert_int_eq(HexcharToInt('g'), -1);
    mu_assert_int_eq(HexcharToInt(' '), -1);
    mu_assert_int_eq(HexcharToInt('/'), -1);
    print_result("HexcharToInt returns -1 for invalid chars", true);
}

MU_TEST(test_HexcharToBytes_valid)
{
    uint8_t out[4];
    const char* hex = "0A1B2C3D";
    int ret = HexcharToBytes(hex, out, 4);
    mu_assert_int_eq(ret, 0);
    mu_assert_int_eq(out[0], 0x0A);
    mu_assert_int_eq(out[1], 0x1B);
    mu_assert_int_eq(out[2], 0x2C);
    mu_assert_int_eq(out[3], 0x3D);
    print_result("HexcharToBytes converts correctly", true);
}

MU_TEST(test_HexcharToBytes_invalid)
{
    uint8_t out[2];
    const char* hex = "ZZZZ";
    int ret = HexcharToBytes(hex, out, 2);
    mu_assert_int_eq(ret, -1);
    print_result("HexcharToBytes fails on invalid input", true);
}

MU_TEST(test_CleanupResources_frees_memory)
{
    BuildContext b = {0};
    CryptoContext c = {0};

    b.fileBuff = malloc(16);
    b.encryptedPayload = malloc(16);
    c.obfuscatedKey = malloc(16);
    c.obfuscatedNonce = malloc(16);

    CleanupResources(&b, &c);

    print_result("CleanupResources freed all without crash", true);
}

MU_TEST_SUITE(packer_suite)
{
    MU_RUN_TEST(test_PrintMessage_return_code);
    MU_RUN_TEST(test_HexcharToInt_valid);
    MU_RUN_TEST(test_HexcharToInt_invalid);
    MU_RUN_TEST(test_HexcharToBytes_valid);
    MU_RUN_TEST(test_HexcharToBytes_invalid);
    MU_RUN_TEST(test_CleanupResources_frees_memory); 
}

int main(void)
{
    printf("=== Running packer unit tests ===\n\n");
    MU_RUN_SUITE(packer_suite);
    MU_REPORT();
    printf("\n=== All tests completed ===\n");
    return (minunit_fail ? 1 : 0);
}
