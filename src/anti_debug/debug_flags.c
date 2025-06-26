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
}

int _ProcessDebugPort()
{
    
}

int _ProcessDebugFlags()
{

}