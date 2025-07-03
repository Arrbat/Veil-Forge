#include "headers/anti_debug.h"

int PatchDbgBreakPoint()
{
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll)
    {
        return 1;
    }

    FARPROC pDbgBreakPoint = GetProcAddress(hNtdll, "DbgBreakPoint");
    if (!pDbgBreakPoint)
    {
        return 1;
    }

    DWORD dwOldProtect;
    if (!VirtualProtect(pDbgBreakPoint, 1, PAGE_EXECUTE_READWRITE, &dwOldProtect));

    *(PBYTE)pDbgBreakPoint = (BYTE)0xc3;
    VirtualProtect(pDbgBreakPoint, 1, dwOldProtect, &dwOldProtect);
    return 0;
}