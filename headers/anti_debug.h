#ifndef ANTI_DEBUG_H
#define ANTI_DEBUG_H

#include <stdint.h>
#include <stdbool.h>
#include <windows.h>
#include <winternl.h> 

typedef NTSTATUS (NTAPI* TNtQueryInformationProcess)
(
    IN HANDLE ProcessHandle,
    IN PROCESSINFOCLASS PROCESS_INFORMATION_CLASS,
    OUT PVOID PROCESS_INFORMATION,
    IN ULONG ProcessInformationLength,
    OUT PULONG ReturnLength
);

// Underscore used to clearly derive API calls from implementations here
// ----------- DEBUG FLAGS -----------

/**
 * @brief By using API call isDebuggerPresent() and CheckRemoteDebuggerPresent() checks if debugger is present
 */
int _IsDebuggerPresent();

/**
 * @brief Checks DWORD value in class ProcessDebugPort, if equals to -1 then Debugger is present
 */
int _ProcessDebugPort();

/**
 * Checks the field NoDebugInherit of kernel structure EPROCESS. If the return valuse is 0 - debugger is present
 */
int _ProcessDebugFlags();

// ----------- OBJECT HANDLES -----------

// ----------- EXCEPTIONS -----------

// ----------- TIMING -----------

// ----------- PROCESS MEMORY -----------

// ----------- ASSEMBLY INSTRUCTIONS -----------

// ----------- INTERACTIVE CHECKS -----------

// ----------- MISC -----------


#endif /* ANTI_DEBUG_H */