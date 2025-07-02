#include "headers/anti_debug.h"

DWORD64 BeginDetectRDTSCBasedDelay(void)
{
    uint32_t low, high;
    __asm__ __volatile__ (
        "rdtsc"
        : "=a"(low), "=d"(high)
    );
    return ((DWORD64)high << 32) | low;
}

bool EndDetectRDTSCBasedDelay(DWORD64 qwStart, DWORD64 qwNativeElapsed)
{
    uint32_t low, high;
    __asm__ __volatile__ (
        "rdtsc"
        : "=a"(low), "=d"(high)
    );
    DWORD64 end = ((DWORD64)high << 32) | low;
    return (end - qwStart) > qwNativeElapsed;
}