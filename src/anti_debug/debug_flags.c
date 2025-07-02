#include "headers/anti_debug.h"

int _IsDebuggerPresent()
{
    BOOL DebuggerPresent;

    if (IsDebuggerPresent())
    {
        ExitProcess(1);
    }

    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &DebuggerPresent) == TRUE && DebuggerPresent == TRUE)
    {
        ExitProcess(1);
    }

    return 0;
}

int _ProcessDebugPort()
{
    HMODULE hNtdll = LoadLibrary("ntdll.dll");
    auto pfnNtQueryInformationProcess = (TNtQueryInformationProcess)(void*)GetProcAddress(hNtdll, "NtQueryInformationProcess");

    if (pfnNtQueryInformationProcess)
    {
        DWORD dwProcessDebugPort, dwReturned;
        NTSTATUS status =  pfnNtQueryInformationProcess(
            GetCurrentProcess(),
            ProcessDebugPort,
            &dwProcessDebugPort,
            sizeof(DWORD),
            &dwReturned
        );

        if (NT_SUCCESS(status) && (-1 == dwProcessDebugPort))
        {
            ExitProcess(1);
        }

    }
    
    return 0;
}

int _ProcessDebugFlags()
{
    HMODULE hNtdll = LoadLibrary("ntdll.dll");
    if (hNtdll)
    {
        auto pfnNtQueryInformationProcess = (TNtQueryInformationProcess)(void*)GetProcAddress(hNtdll, "NtQueryInformationProcess");

        if (pfnNtQueryInformationProcess)
        {
            DWORD dwProcessDebugFlags, dwReturned;
            const DWORD ProcessDebugFlags = 0x1f; // // Info class ID for NtQueryInformationProcess to query process debug flags
            NTSTATUS status = pfnNtQueryInformationProcess(
                GetCurrentProcess(),
                ProcessDebugFlags,
                &dwProcessDebugFlags,
                sizeof(DWORD),
                &dwReturned
            );

            if (NT_SUCCESS(status) && (0 == dwProcessDebugFlags))
            {
                ExitProcess(1);
            }
        }
    }

    return 0;
}