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
 * @brief Checks BeingDebugged flag in PEB structure and checks if there is debugger attached to this process.
 */
int _IsDebuggerPresent();

/**
 * @brief Checks if the current process is being debugged by querying the ProcessDebugPort.
 */
int _ProcessDebugPort();

/**
 * Checks the field NoDebugInherit of kernel structure EPROCESS. If the return valuse is 0 - debugger is present.
 */
int _ProcessDebugFlags();

// ----------- EXCEPTIONS -----------

// ----------- TIMING -----------

// ----------- PROCESS MEMORY -----------

// ----------- ASSEMBLY INSTRUCTIONS -----------

// ----------- INTERACTIVE CHECKS -----------

// ----------- MISC -----------


#endif /* ANTI_DEBUG_H */