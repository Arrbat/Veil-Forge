#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "minunit.h"    
#include "../src/packer.c"

MU_TEST(test_PrintMessage_return_code)
{
    printf("[RUNNING] test_PrintMessage_return_code\n");
    HANDLE hCon = GetStdHandle(STD_ERROR_HANDLE);
    int ret = PrintMessage(hCon, "Test Message", 4, 42);
    mu_assert_int_eq(ret, 42);
    printf("[PASSED] test_PrintMessage_return_code\n");
}

MU_TEST_SUITE(packer_suite) {
    MU_RUN_TEST(test_PrintMessage_return_code);
}

int main(void)
{
    MU_RUN_SUITE(packer_suite);
    MU_REPORT();
    return (minunit_fail ? 1 : 0);
}