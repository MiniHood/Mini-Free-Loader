
#include <Windows.h>
#include <String.h>
#include <fstream>
#include "obfuscate.h"
#include "antidbg.h"
#include <iostream>
#include <tchar.h> // For _T
#include "Auth.h"

#pragma comment(lib, "urlmon.lib") // For downloading from URLS







// Bools N Shit
bool antivpnenabled = true;
bool antidebugenabled = true;
#define DLL_NAME "dll path here"











void DBG_MSG(WORD dbg_code, const char* message)
{
#ifdef SHOW_DEBUG_MESSAGES
    printf("[MSG-0x%X]: %s\n", dbg_code, message);
    MessageBoxA(NULL, message, "GAME OVER!", 0);
#endif
}

bool auth()
{
    // https://support.glitch.com/t/how-to-create-your-own-auth-system-with-glitch-and-c-for-your-desktop-app/7196 <--- Read This

    string hostfile = "https://name-here/auth/authexploit?hid=";
	string hwid = a_gethid();

	if (hwid == "NULL")
	{
		return false;
	}

	string result = a_DownloadURL(hostfile + hwid);

	if (result == "1") {
		return true;
	}
	else {
		return false;
	}
};

// DONT WANT ALL THE CODE IN YOUR FACE? CLICK THE - BUTTON UNDER THIS

#pragma region All Debug Finders

void adbg_NtQueryInformationProcess(void)
{
    HANDLE hProcess = INVALID_HANDLE_VALUE;
    PROCESS_BASIC_INFORMATION pProcBasicInfo = { 0 };
    ULONG returnLength = 0;

    // Get a handle to ntdll.dll so we can import NtQueryInformationProcess
    HMODULE hNtdll = LoadLibraryW(L"ntdll.dll");
    if (hNtdll == INVALID_HANDLE_VALUE || hNtdll == NULL)
    {
        return;
    }

    // Dynamically acquire the addres of NtQueryInformationProcess
    _NtQueryInformationProcess  NtQueryInformationProcess = NULL;
    NtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");

    if (NtQueryInformationProcess == NULL)
    {
        return;
    }

    hProcess = GetCurrentProcess();

    // Note: There are many options for the 2nd parameter NtQueryInformationProcess
    // (ProcessInformationClass) many of them are opaque. While we use ProcessBasicInformation (0), 
    // we could also use:
    //      ProcessDebugPort (7)
    //      ProcessDebugObjectHandle (30)
    //      ProcessDebugFlags (31)
    // There are likely others. You can find many other options for ProcessInformationClass over at PINVOKE:
    //      https://www.pinvoke.net/default.aspx/ntdll/PROCESSINFOCLASS.html
    // Keep in mind that NtQueryInformationProcess will return different things depending on the ProcessInformationClass used.
    // Many online articles using NtQueryInformationProcess for anti-debugging will use DWORD types for NtQueryInformationProcess 
    // paramters. This is fine for 32-builds with some ProcessInformationClass values, but it will cause some to fail on 64-bit builds.
    // In the event of a failure NtQueryInformationProcess will likely return STATUS_INFO_LENGTH_MISMATCH (0xC0000004). 

    // Query ProcessDebugPort
    NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pProcBasicInfo, sizeof(pProcBasicInfo), &returnLength);
    if (NT_SUCCESS(status)) {
        PPEB pPeb = pProcBasicInfo.PebBaseAddress;
        if (pPeb)
        {
            if (pPeb->BeingDebugged)
            {
                cout << AY_OBFUSCATE("Debugger Found | Developer Code 0x166f") << endl;
                DBG_MSG(DBG_NTQUERYINFORMATIONPROCESS, "Caught by NtQueryInformationProcess (ProcessDebugPort)!");
                std::ofstream file{ AY_OBFUSCATE("C:\\Users\\Public\\banned.txt") };
                exit(DBG_NTQUERYINFORMATIONPROCESS);
            }
        }
    }
}


void adbg_NtSetInformationThread(void)
{
    THREAD_INFORMATION_CLASS ThreadHideFromDebugger = (THREAD_INFORMATION_CLASS)0x11;

    // Get a handle to ntdll.dll so we can import NtSetInformationThread
    HMODULE hNtdll = LoadLibraryW(L"ntdll.dll");
    if (hNtdll == INVALID_HANDLE_VALUE || hNtdll == NULL)
    {
        return;
    }

    // Dynamically acquire the addres of NtSetInformationThread and NtQueryInformationThread
    _NtSetInformationThread NtSetInformationThread = NULL;
    NtSetInformationThread = (_NtSetInformationThread)GetProcAddress(hNtdll, "NtSetInformationThread");

    if (NtSetInformationThread == NULL)
    {
        return;
    }

    // There is nothing to check here after this call.
    NtSetInformationThread(GetCurrentThread(), ThreadHideFromDebugger, 0, 0);
}


void adbg_NtGlobalFlagPEB(void)
{
    BOOL found = FALSE;

#ifdef _WIN64
    found = adbg_NtGlobalFlagPEBx64();
#else
    _asm
    {
        xor eax, eax;			// clear eax
        mov eax, fs: [0x30] ;	// Reference start of the PEB
        mov eax, [eax + 0x68];	// PEB+0x68 points to NtGlobalFlag
        and eax, 0x00000070;	// check three flags:
                                //   FLG_HEAP_ENABLE_TAIL_CHECK   (0x10)
                                //   FLG_HEAP_ENABLE_FREE_CHECK   (0x20)
                                //   FLG_HEAP_VALIDATE_PARAMETERS (0x40)
        mov found, eax;			// Copy result into 'found'
    }
#endif

    if (found)
    {
        cout << AY_OBFUSCATE("Debugger Found | Developer Code 0x15151") << endl;
        Sleep(2000);
        DBG_MSG(DBG_NTGLOBALFLAGPEB, "Caught by NtGlobalFlag PEB check!");
        std::ofstream file{ AY_OBFUSCATE("C:\\Users\\Public\\banned.txt") };
        exit(DBG_NTGLOBALFLAGPEB);
    }
}

void adbg_CheckWindowClassName(void)
{
    BOOL found = FALSE;
    HANDLE hWindow = NULL;
    const char* WindowClassNameOlly = _T("OLLYDBG");		// OllyDbg
    const char* WindowClassNameImmunity = _T("ID");			// Immunity Debugger

    // Check for OllyDBG class name
    hWindow = FindWindow(WindowClassNameOlly, NULL);
    if (hWindow)
    {
        found = TRUE;
    }

    // Check for Immunity class name
    hWindow = FindWindow(WindowClassNameImmunity, NULL);
    if (hWindow)
    {
        found = TRUE;
    }

    if (found)
    {
        cout << AY_OBFUSCATE("Debugger Found | Developer Code 162351") << endl;
        DBG_MSG(DBG_FINDWINDOW, "Caught by FindWindow (ClassName)!");
        std::ofstream file{ AY_OBFUSCATE("C:\\Users\\Public\\banned.txt") };
        exit(DBG_FINDWINDOW);
    }
}

void adbg_IsDebuggerPresent(void)
{
    BOOL found = FALSE;
    found = IsDebuggerPresent();

    if (found)
    {
        cout << AY_OBFUSCATE("Debugger Found | Developer Code 0x1561") << endl;
        Sleep(2000);
        DBG_MSG(DBG_ISDEBUGGERPRESENT, "Caught by IsDebuggerPresent!");
        std::ofstream file{ AY_OBFUSCATE("C:\\Users\\Public\\banned.txt") };
        exit(DBG_ISDEBUGGERPRESENT);
    }
}

void adbg_CheckWindowName(void)
{
    BOOL found = FALSE;
    HANDLE hWindow = NULL;
    const char* WindowNameOlly = _T("OllyDbg - [CPU]");
    const char* WindowNameImmunity = _T("Immunity Debugger - [CPU]");

    // Check for OllyDBG class name
    hWindow = FindWindow(NULL, WindowNameOlly);
    if (hWindow)
    {
        found = TRUE;
    }

    // Check for Immunity class name
    hWindow = FindWindow(NULL, WindowNameImmunity);
    if (hWindow)
    {
        found = TRUE;
    }

    if (found)
    {
        cout << AY_OBFUSCATE("Debugger Found | Developer Code 0x112") << endl;
        Sleep(2000);
        DBG_MSG(DBG_FINDWINDOW, "Caught by FindWindow (WindowName)!");
        std::ofstream file{ AY_OBFUSCATE("C:\\Users\\Public\\banned.txt") };
        exit(DBG_FINDWINDOW);
    }
}

void adbg_CheckRemoteDebuggerPresent(void)
{
    HANDLE hProcess = INVALID_HANDLE_VALUE;
    BOOL found = FALSE;

    hProcess = GetCurrentProcess();
    CheckRemoteDebuggerPresent(hProcess, &found);

    if (found)
    {
        cout << AY_OBFUSCATE("Debugger Found | Developer Code 0x551") << endl;
        Sleep(2000);
        DBG_MSG(DBG_CHECKREMOTEDEBUGGERPRESENT, "Caught by CheckRemoteDebuggerPresent!");
        std::ofstream file{ AY_OBFUSCATE("C:\\Users\\Public\\banned.txt") };
        exit(DBG_CHECKREMOTEDEBUGGERPRESENT);
    }
}


void ChangeTitleThread()
{
    srand(time(0)); //Helps the rand() function out so it won't produce the same number every time.
    while (1) //Enter our loop.
    {
        int random1 = rand() % 999999 + 100000; //Pick a random number between these two
        int random2 = rand() % 52999 + 1510; //...
        int random3 = rand() % 614613455 + 513;
        int random4 = rand() % 613463176 + 3146662;
        std::string title; //Declare our title string
        title.append(std::to_string(random1)); //Append each number to our title
        title.append(std::to_string(random2)); //...
        title.append(std::to_string(random3));
        title.append(std::to_string(random4));
        SetConsoleTitleA(title.c_str()); //Set our console title to our string, use .c_str() to turn it into a LPCSTR.
        Sleep(500); //Sleep for half a second.
    }
}

void adbg_BeingDebuggedPEB(void)
{
    BOOL found = FALSE;

#ifdef _WIN64
    found = adbg_BeingDebuggedPEBx64();
#else
    _asm
    {
        xor eax, eax;			// clear eax
        mov eax, fs: [0x30] ;	// Reference start of the PEB
        mov eax, [eax + 0x02];	// PEB+2 points to BeingDebugged
        and eax, 0xFF;			// only reference one byte
        mov found, eax;			// Copy BeingDebugged into 'found'
    }
#endif

    if (found)
    {
        cout << AY_OBFUSCATE("Debugger Found | Developer Code 5615") << endl;
        Sleep(2000);
        DBG_MSG(DBG_BEINGEBUGGEDPEB, "Caught by BeingDebugged PEB check!");
        std::ofstream file{ AY_OBFUSCATE("C:\\Users\\Public\\banned.txt") };
        exit(DBG_BEINGEBUGGEDPEB);
    }
}

void adbg_ProcessFileName(void)
{
    // detect debugger by process file (for example: ollydbg.exe)
    const wchar_t* debuggersFilename[7] = {
        L"cheatengine-x86_64.exe",
        L"ollydbg.exe",
        L"ida.exe",
        L"ida64.exe",
        L"radare2.exe",
        L"x64dbg.exe",
        L"dnSpy.exe"
    };

    wchar_t* processName;
    PROCESSENTRY32W processInformation{ sizeof(PROCESSENTRY32W) };
    HANDLE processList;

    processList = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    processInformation = { sizeof(PROCESSENTRY32W) };
    if (!(Process32FirstW(processList, &processInformation)))
        printf("[Warning] It is impossible to check process list.");
    else
    {
        do
        {
            for (const wchar_t* debugger : debuggersFilename)
            {
                processName = processInformation.szExeFile;
                if (_wcsicmp(debugger, processName) == 0) {
                    DBG_MSG(DBG_PROCESSFILENAME, "Debugger Found!");
                    Sleep(2000);
                    std::ofstream file{ AY_OBFUSCATE("C:\\Users\\Public\\banned.txt") };
                    exit(DBG_PROCESSFILENAME);
                }
            }
        } while (Process32NextW(processList, &processInformation));
    }
    CloseHandle(processList);
}

void AntiVPN()
{
    LPCSTR DetectedWindows[] = { AY_OBFUSCATE("PrivateVPN", "NordVPN", "StealthVPN", "ProtoVPN", "Proto VPN", "VPN", "OpenVPN")}; 

    for (int i = 0; i < 7; i++) 
    {
        if (FindWindowA(0, DetectedWindows[i]) != 0) 
        {
            system("cls"); // Dangerous please use flush or sum shit
            printf(AY_OBFUSCATE("VPN Found Please Close It\n"));
            Sleep(2000);
            std::ofstream file{ AY_OBFUSCATE("C:\\Users\\Public\\banned.txt") };
            Sleep(1500);
            exit(0);
        }
    }
}

void DetectDebuggerThread()
{
    BOOL result; //Create a result boolean for our result to be stored.
    LPCSTR DetectedWindows[] = { AY_OBFUSCATE("x64dbg", "IDA: Quick start", "IDA v6.8.150423", "dnSpy", "Microsoft Visual Studio", "Visual Studio", "Dumper", "FileDumper", "Process Hacker", "Task Manager") }; //Add your own debuggers!
    //Just finding windows may not be enough, so try to include your own process checker.

    while (1) //Enter our loop.
    {
        if (IsDebuggerPresent()) //Our first check, probably the simpliest.
        {
            system("cls"); // Dangerous please use flush or sum shit
            printf(AY_OBFUSCATE("Debugger Found Present!\n"));
            Sleep(2000);
            std::ofstream file{ AY_OBFUSCATE("C:\\Users\\Public\\banned.txt") };
            Sleep(1500);
            exit(0);
        }
        CheckRemoteDebuggerPresent(GetCurrentProcess(), &result); //Get a handle to our current process and send our result to the our boolean.
        if (result || result == 1) //Check to see if our result is true.
        {
            system("cls"); // Dangerous please use flush or sum shit
            printf(AY_OBFUSCATE("Remote Debugger Found!\n"));
            Sleep(2000);
            std::ofstream file{ AY_OBFUSCATE("C:\\Users\\Public\\banned.txt") };
            Sleep(1500);
            exit(0);
        }
        SetLastError(0); //Set last error to 0 so it won't conflict with our check.
        OutputDebugStringA(AY_OBFUSCATE("Fuck off you wont find anything lmao?\n")); //Send a little message to the debugger.
        if (GetLastError() != 0) //If the message passed without error (Meaning it was sent to the debugger)
        {
            system("cls"); // Dangerous please use flush or sum shit
            printf(AY_OBFUSCATE("Debuging Software Found!\n"));
            Sleep(2000);
            std::ofstream file{ AY_OBFUSCATE("C:\\Users\\Public\\banned.txt") };
            Sleep(1500);
            exit(0);
        }

        for (int i = 0; i < 10; i++) //Loop thru our array of detected debugger windows.
        {
            if (FindWindowA(0, DetectedWindows[i]) != 0) //Check to see if FindWindow found a debugger that matches our name.
            {
                system("cls"); // Dangerous please use flush or sum shit
                printf(AY_OBFUSCATE("Detected Debugger Found!\n"));
                Sleep(2000);
                std::ofstream file{ AY_OBFUSCATE("C:\\Users\\Public\\banned.txt") };
                Sleep(1500);
                exit(0);
            }
        }
    }
}

void adbg_GetTickCount(void)
{
    BOOL found = FALSE;
    DWORD t1;
    DWORD t2;

    t1 = GetTickCount();

#ifdef _WIN64
    adbg_GetTickCountx64();
#else
    // Junk or legit code.
    _asm
    {
        xor eax, eax;
        push eax;
        push ecx;
        pop eax;
        pop ecx;
        sub ecx, eax;
        shl ecx, 4;
    }
#endif

    t2 = GetTickCount();

    // 30 milliseconds is an empirical value
    if ((t2 - t1) > 30)
    {
        found = TRUE;
    }

    if (found)
    {
        cout << AY_OBFUSCATE("Debugger Found | Developer Code 001") << endl;
        Sleep(2000);
        DBG_MSG(DBG_GETTICKCOUNT, "Caught by GetTickCount!");
        std::ofstream file{ AY_OBFUSCATE("C:\\Users\\Public\\banned.txt") };
        exit(DBG_GETTICKCOUNT);
    }
}

void adbg_HardwareDebugRegisters(void)
{
    BOOL found = FALSE;
    CONTEXT ctx = { 0 };
    HANDLE hThread = GetCurrentThread();

    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(hThread, &ctx))
    {
        if ((ctx.Dr0 != 0x00) || (ctx.Dr1 != 0x00) || (ctx.Dr2 != 0x00) || (ctx.Dr3 != 0x00) || (ctx.Dr6 != 0x00) || (ctx.Dr7 != 0x00))
        {
            found = TRUE;
        }
    }

    if (found)
    {
        cout << AY_OBFUSCATE("Debugger Found | Developer Code 612") << endl;
        Sleep(2000);
        DBG_MSG(DBG_HARDWAREDEBUGREGISTERS, "Caught by a Hardware Debug Register Check!");
        std::ofstream file{ AY_OBFUSCATE("C:\\Users\\Public\\banned.txt") };
        exit(DBG_HARDWAREDEBUGREGISTERS);
    }
}

void adbg_CloseHandleException(void)
{
    HANDLE hInvalid = (HANDLE)0xBEEF; // an invalid handle
    DWORD found = FALSE;

    __try
    {
        CloseHandle(hInvalid);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        found = TRUE;
    }

    if (found)
    {
        cout << AY_OBFUSCATE("Debugger Found | Developer Code 1055") << endl;
        Sleep(2000);
        DBG_MSG(DBG_CLOSEHANDLEEXCEPTION, "Caught by an CloseHandle exception!");
        exit(DBG_CLOSEHANDLEEXCEPTION);
    }
}


void adbg_SingleStepException(void)
{
    DWORD found = TRUE;

    // In this method we force an exception to occur. If it occurs
    // outside of a debugger, the __except() handler is called setting
    // found to FALSE. If the exception occurs inside of a debugger, the
    // __except() will not be called (in certain cases) leading to
    // found being TRUE.

    __try
    {
#ifdef _WIN64
        adbg_SingleStepExceptionx64();
#else
        _asm
        {
            pushfd;						// save EFFLAGS register
            or byte ptr[esp + 1], 1;	// set trap flag in EFFLAGS
            popfd;						// restore EFFLAGS register
        }
#endif
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        found = FALSE;
    }

    if (found)
    {
        cout << AY_OBFUSCATE("Debugger Found | Developer Code 512") << endl;
        Sleep(2000);
        DBG_MSG(DBG_SINGLESTEPEXCEPTION, "Caught by a Single Step Exception!");
        exit(DBG_SINGLESTEPEXCEPTION);
    }
}


void adbg_Int3(void)
{
    BOOL found = TRUE;

    __try
    {
#ifdef _WIN64
        adbg_Int3x64();
#else
        _asm
        {
            int 3;	// 0xCC standard software breakpoint
        }
#endif
    }

    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        found = FALSE;
    }

    if (found)
    {
        cout << AY_OBFUSCATE("Debugger Found | Developer Code 251") << endl;
        Sleep(2000);
        DBG_MSG(DBG_INT3CC, "Caught by a rogue INT 3!");
        exit(DBG_INT3CC);
    }
}


void adbg_PrefixHop(void)
{
    BOOL found = TRUE;

    __try
    {
#ifdef _WIN64
        // TODO: Not yet implemented in x64
        found = FALSE;
#else
        _asm
        {
            __emit 0xF3;	// 0xF3 0x64 is the prefix 'REP'
            __emit 0x64;
            __emit 0xCC;	// this gets skipped over if being debugged
        }
#endif
    }

    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        found = FALSE;
    }

    if (found)
    {
        cout << AY_OBFUSCATE("Debugger Found | Developer Code 821") << endl;
        Sleep(2000);
        DBG_MSG(DBG_PREFIXHOP, "Caught by a Prefix Hop!");
        exit(DBG_PREFIXHOP);
    }
}


void adbg_Int2D(void)
{
    BOOL found = TRUE;

    __try
    {
#ifdef _WIN64
        adbg_Int2Dx64();
#else
        _asm
        {
            int 0x2D;
            nop;
        }
#endif
    }

    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        found = FALSE;
    }

    if (found)
    {
        cout << AY_OBFUSCATE("Debugger Found | Developer Code 924") << endl;
        Sleep(2000);
        DBG_MSG(DBG_NONE, "Caught by a rogue INT 2D!");
        exit(DBG_NONE);
    }
}

// =======================================================================
// Other Checks
// Other kinds of checks that don't fit into the normal categories.
// =======================================================================

void adbg_CrashOllyDbg(void)
{
    // crash OllyDbg v1.x by exploit
    __try {
        OutputDebugString(TEXT("%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s"));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { ; }
}

#pragma endregion


#pragma region Custom Functions
/////////////////////////////////////////////////////////////////////////////////////
//                                 INJECTOR CODE                                   //
/////////////////////////////////////////////////////////////////////////////////////

#define JUNKS \
__asm _emit 0x10 \
__asm _emit 0x48 \
__asm _emit 0x57 \
__asm _emit 0x28 \
__asm _emit 0x83 \
__asm _emit 0x68 \
__asm _emit 0x25 \
__asm _emit 0x41 \
__asm _emit 0x58 \
__asm _emit 0x58 \
__asm _emit 0x73 \
__asm _emit 0x27 \
__asm _emit 0x47 \
__asm _emit 0x36 \
__asm _emit 0x96 \
__asm _emit 0x31 \
__asm _emit 0x18 \
__asm _emit 0x07 \
__asm _emit 0x99 \
__asm _emit 0x31 \
__asm _emit 0x79 \
__asm _emit 0x74 \
__asm _emit 0x67 \
__asm _emit 0x44 \
__asm _emit 0x66 \
__asm _emit 0x52 \
__asm _emit 0x79 \
__asm _emit 0x70 \
__asm _emit 0x44 \
__asm _emit 0x12 \
__asm _emit 0x91 \
__asm _emit 0x97 \
__asm _emit 0x98 \
__asm _emit 0x75 \
__asm _emit 0x35 \
__asm _emit 0x15 \
__asm _emit 0x98 \
__asm _emit 0x21 \
__asm _emit 0x76 \
__asm _emit 0x24 \
__asm _emit 0x44 \
__asm _emit 0x15 \
__asm _emit 0x91 \
__asm _emit 0x88 \
__asm _emit 0x18 \
__asm _emit 0x08 \
__asm _emit 0x03 \
__asm _emit 0x52 \
__asm _emit 0x95 \
__asm _emit 0x56 \
__asm _emit 0x90 \
__asm _emit 0x78 \
__asm _emit 0x39 \
__asm _emit 0x44 \
__asm _emit 0x56 \
__asm _emit 0x29 \
__asm _emit 0x14 \
__asm _emit 0x51 \
__asm _emit 0x13 \
__asm _emit 0x71 \
__asm _emit 0x47 \
__asm _emit 0x38 \
__asm _emit 0x18 \
__asm _emit 0x86 \
__asm _emit 0x38 \
__asm _emit 0x81 \
__asm _emit 0x32 \
__asm _emit 0x59 \
__asm _emit 0x52 \
__asm _emit 0x75 \
__asm _emit 0x84 \
__asm _emit 0x69 \
__asm _emit 0x21 \
__asm _emit 0x60 \
__asm _emit 0x48 \
__asm _emit 0x80 \
__asm _emit 0x40 \
__asm _emit 0x34 \
__asm _emit 0x32 \
__asm _emit 0x42 \
__asm _emit 0x57 \
__asm _emit 0x19 \
__asm _emit 0x09 \
__asm _emit 0x06 \
__asm _emit 0x15 \
__asm _emit 0x93 \
__asm _emit 0x93 \
__asm _emit 0x72 \
__asm _emit 0x97 \
__asm _emit 0x60 \
__asm _emit 0x76 \
__asm _emit 0x64 \
__asm _emit 0x43 \
__asm _emit 0x61 \
__asm _emit 0x34 \
__asm _emit 0x63 \
__asm _emit 0x80 \
__asm _emit 0x99 \
__asm _emit 0x89 \
__asm _emit 0x20 \
__asm _emit 0x85 \
__asm _emit 0x05 \
__asm _emit 0x06 \
__asm _emit 0x09 \
__asm _emit 0x16 \
__asm _emit 0x89 \
__asm _emit 0x65 \
__asm _emit 0x81 \
__asm _emit 0x94 \
__asm _emit 0x83 \
__asm _emit 0x75 \
__asm _emit 0x15 \
__asm _emit 0x63 \
__asm _emit 0x67 \
__asm _emit 0x40 \
__asm _emit 0x10 \
__asm _emit 0x15 \
__asm _emit 0x54 \
__asm _emit 0x40 \
__asm _emit 0x14 \
__asm _emit 0x37 \
__asm _emit 0x05 \
__asm _emit 0x94 \
__asm _emit 0x99 \
__asm _emit 0x58 \
__asm _emit 0x30 \
__asm _emit 0x25 \
__asm _emit 0x07 \
__asm _emit 0x73 \
__asm _emit 0x70 \
__asm _emit 0x26 \
__asm _emit 0x46 \
__asm _emit 0x59 \
__asm _emit 0x44 \
__asm _emit 0x88 \
__asm _emit 0x57 \
__asm _emit 0x40 \
__asm _emit 0x78 \
__asm _emit 0x86 \
__asm _emit 0x26 \
__asm _emit 0x87 \
__asm _emit 0x07 \
__asm _emit 0x52 \
__asm _emit 0x60 \
__asm _emit 0x53 \
__asm _emit 0x92 \
__asm _emit 0x50 \
__asm _emit 0x70 \
__asm _emit 0x92 \
__asm _emit 0x78 \
__asm _emit 0x02 \
__asm _emit 0x34 \
__asm _emit 0x27 \
__asm _emit 0x02 \
__asm _emit 0x35 \
__asm _emit 0x74 \
__asm _emit 0x69 \
__asm _emit 0x26 \
__asm _emit 0x69 \
__asm _emit 0x72 \
__asm _emit 0x69 \
__asm _emit 0x38 \
__asm _emit 0x82 \
__asm _emit 0x34 \
__asm _emit 0x78 \
__asm _emit 0x56 \
__asm _emit 0x36 \
__asm _emit 0x12 \
__asm _emit 0x02 \
__asm _emit 0x78 \
__asm _emit 0x66 \
__asm _emit 0x83 \
__asm _emit 0x55 \
__asm _emit 0x65 \
__asm _emit 0x27 \
__asm _emit 0x48 \
__asm _emit 0x40 \
__asm _emit 0x87 \
__asm _emit 0x43 \
__asm _emit 0x63 \
__asm _emit 0x73 \
__asm _emit 0x46 \
__asm _emit 0x77 \
__asm _emit 0x81 \
__asm _emit 0x80 \
__asm _emit 0x05 \
__asm _emit 0x99 \
__asm _emit 0x18 \
__asm _emit 0x81 \
__asm _emit 0x01 \
__asm _emit 0x31 \
__asm _emit 0x27 \
__asm _emit 0x50 \
__asm _emit 0x40 \
__asm _emit 0x63 \
__asm _emit 0x78 \
__asm _emit 0x28 \
__asm _emit 0x73 \
__asm _emit 0x83 \
__asm _emit 0x11 \
__asm _emit 0x49 \
__asm _emit 0x56 \
__asm _emit 0x79 \
__asm _emit 0x93 \
__asm _emit 0x34 \
__asm _emit 0x34 \
__asm _emit 0x61 \
__asm _emit 0x40 \
__asm _emit 0x48 \
__asm _emit 0x13 \
__asm _emit 0x81 \
__asm _emit 0x94 \
__asm _emit 0x63 \
__asm _emit 0x33 \
__asm _emit 0x73 \
__asm _emit 0x03 \
__asm _emit 0x66 \
__asm _emit 0x80 \
__asm _emit 0x03 \
__asm _emit 0x54 \
__asm _emit 0x16 \
__asm _emit 0x76 \
__asm _emit 0x31 \
__asm _emit 0x46 \
__asm _emit 0x66 \
__asm _emit 0x77 \
__asm _emit 0x62 \
__asm _emit 0x57 \
__asm _emit 0x49 \
__asm _emit 0x66 \
__asm _emit 0x40 \
__asm _emit 0x55 \
__asm _emit 0x80 \
__asm _emit 0x96 \
__asm _emit 0x09 \
__asm _emit 0x43 \
__asm _emit 0x22 \
__asm _emit 0x75 \
__asm _emit 0x87 \
__asm _emit 0x12 \
__asm _emit 0x32 \
__asm _emit 0x19 \
__asm _emit 0x17 \
__asm _emit 0x71 \
__asm _emit 0x32 \
__asm _emit 0x13 \
__asm _emit 0x46 \
__asm _emit 0x60 \
__asm _emit 0x79 \
__asm _emit 0x32 \
__asm _emit 0x02 \
__asm _emit 0x46 \
__asm _emit 0x86 \
__asm _emit 0x37 \
__asm _emit 0x63 \
__asm _emit 0x27 \
__asm _emit 0x71 \
__asm _emit 0x32 \
__asm _emit 0x34 \
__asm _emit 0x80 \
__asm _emit 0x26 \
__asm _emit 0x72 \
__asm _emit 0x94 \
__asm _emit 0x10 \
__asm _emit 0x01 \
__asm _emit 0x54 \
__asm _emit 0x67 \
__asm _emit 0x45 \
__asm _emit 0x82 \
__asm _emit 0x37 \
__asm _emit 0x32 \
__asm _emit 0x87 \
__asm _emit 0x25 \
__asm _emit 0x11 \
__asm _emit 0x71 \
__asm _emit 0x16 \
__asm _emit 0x26 \
__asm _emit 0x47 \
__asm _emit 0x21 \
__asm _emit 0x03 \
__asm _emit 0x73 \
__asm _emit 0x82 \
__asm _emit 0x83 \
__asm _emit 0x57 \
__asm _emit 0x85 \
__asm _emit 0x81 \
__asm _emit 0x81 \
__asm _emit 0x82 \
__asm _emit 0x82 \
__asm _emit 0x07 \
__asm _emit 0x03 \
__asm _emit 0x26 \
__asm _emit 0x64 \
__asm _emit 0x91 \
__asm _emit 0x81 \
__asm _emit 0x84 \
__asm _emit 0x82 \
__asm _emit 0x71 \
__asm _emit 0x08 \
__asm _emit 0x80 \
__asm _emit 0x96 \
__asm _emit 0x03 \
__asm _emit 0x71 \
__asm _emit 0x56 \
__asm _emit 0x19 \
__asm _emit 0x53 \
__asm _emit 0x53 \
__asm _emit 0x95 \
__asm _emit 0x22 \
__asm _emit 0x11 \
__asm _emit 0x68 \
__asm _emit 0x84 \
__asm _emit 0x77 \
__asm _emit 0x39 \
__asm _emit 0x07 \
__asm _emit 0x91 \
__asm _emit 0x46 \
__asm _emit 0x63 \
__asm _emit 0x83 \
__asm _emit 0x31 \
__asm _emit 0x29 \
__asm _emit 0x83 \
__asm _emit 0x80 \
__asm _emit 0x71 \
__asm _emit 0x11 \
__asm _emit 0x02 \
__asm _emit 0x54 \
__asm _emit 0x69 \
__asm _emit 0x81 \
__asm _emit 0x25 \
__asm _emit 0x37 \
__asm _emit 0x01 \
__asm _emit 0x20 \
__asm _emit 0x98 \
__asm _emit 0x76 \
__asm _emit 0x08 \
__asm _emit 0x38 \
__asm _emit 0x43 \
__asm _emit 0x03 \
__asm _emit 0x37 \
__asm _emit 0x04 \
__asm _emit 0x96 \
__asm _emit 0x07 \
__asm _emit 0x73 \
__asm _emit 0x38 \
__asm _emit 0x70 \
__asm _emit 0x73 \
__asm _emit 0x41 \
__asm _emit 0x69 \
__asm _emit 0x83 \
__asm _emit 0x31 \
__asm _emit 0x47 \
__asm _emit 0x75 \
__asm _emit 0x23 \
__asm _emit 0x68 \
__asm _emit 0x66 \
__asm _emit 0x27 \
__asm _emit 0x41 \
__asm _emit 0x57 \
__asm _emit 0x10 \
__asm _emit 0x15 \
__asm _emit 0x23 \
__asm _emit 0x95 \
__asm _emit 0x01 \
__asm _emit 0x16 \
__asm _emit 0x47 \
__asm _emit 0x61 \
__asm _emit 0x91 \
__asm _emit 0x92 \
__asm _emit 0x98 \
__asm _emit 0x70 \
__asm _emit 0x08 \
__asm _emit 0x35 \
__asm _emit 0x11 \
__asm _emit 0x90 \
__asm _emit 0x30 \
__asm _emit 0x01 \
__asm _emit 0x95 \
__asm _emit 0x81 \
__asm _emit 0x74 \
__asm _emit 0x74 \
__asm _emit 0x58 \
__asm _emit 0x48 \
__asm _emit 0x77 \
__asm _emit 0x15 \
__asm _emit 0x75 \
__asm _emit 0x25 \
__asm _emit 0x44 \
__asm _emit 0x40 \
__asm _emit 0x19 \
__asm _emit 0x68 \
__asm _emit 0x02 \
__asm _emit 0x64 \
__asm _emit 0x75 \
__asm _emit 0x07 \
__asm _emit 0x74 \
__asm _emit 0x26 \
__asm _emit 0x19 \
__asm _emit 0x35 \
__asm _emit 0x87 \
__asm _emit 0x23 \
__asm _emit 0x73 \
__asm _emit 0x66 \
__asm _emit 0x99 \
__asm _emit 0x61 \
__asm _emit 0x77 \
__asm _emit 0x95 \
__asm _emit 0x15 \
__asm _emit 0x47 \
__asm _emit 0x83 \
__asm _emit 0x38 \
__asm _emit 0x09 \
__asm _emit 0x69 \
__asm _emit 0x89 \
__asm _emit 0x57 \
__asm _emit 0x76 \
__asm _emit 0x05 \
__asm _emit 0x10 \
__asm _emit 0x61 \
__asm _emit 0x66 \
__asm _emit 0x60 \
__asm _emit 0x94 \
__asm _emit 0x79 \
__asm _emit 0x29 \
__asm _emit 0x08 \
__asm _emit 0x69 \
__asm _emit 0x85 \
__asm _emit 0x10 \
__asm _emit 0x21 \
__asm _emit 0x31 \
__asm _emit 0x58 \
__asm _emit 0x59 \
__asm _emit 0x15 \
__asm _emit 0x29 \
__asm _emit 0x33 \
__asm _emit 0x25 \
__asm _emit 0x47 \
__asm _emit 0x85 \
__asm _emit 0x54 \
__asm _emit 0x40 \
__asm _emit 0x65 \
__asm _emit 0x62 \
__asm _emit 0x12 \
__asm _emit 0x50 \
__asm _emit 0x13 \
__asm _emit 0x72 \
__asm _emit 0x02 \
__asm _emit 0x81 \
__asm _emit 0x52 \
__asm _emit 0x84 \
__asm _emit 0x62 \
__asm _emit 0x33 \
__asm _emit 0x59 \
__asm _emit 0x21 \
__asm _emit 0x02 \
__asm _emit 0x31 \
__asm _emit 0x27 \
__asm _emit 0x38 \
__asm _emit 0x35 \
__asm _emit 0x65 \
__asm _emit 0x89 \
__asm _emit 0x55 \
__asm _emit 0x71 \
__asm _emit 0x57 \
__asm _emit 0x17 \
__asm _emit 0x58 \
__asm _emit 0x42 \
__asm _emit 0x19 \
__asm _emit 0x33 \
__asm _emit 0x10 \
__asm _emit 0x02 \
__asm _emit 0x64 \
__asm _emit 0x29 \
__asm _emit 0x37 \
__asm _emit 0x51 \
__asm _emit 0x11 \
__asm _emit 0x73 \
__asm _emit 0x66 \
__asm _emit 0x20 \
__asm _emit 0x22 \
__asm _emit 0x95 \
__asm _emit 0x05 \
__asm _emit 0x25 \
__asm _emit 0x44 \
__asm _emit 0x20 \
__asm _emit 0x19 \
__asm _emit 0x12 \
__asm _emit 0x59 \
__asm _emit 0x75 \
__asm _emit 0x91 \
__asm _emit 0x94 \
__asm _emit 0x92 \
__asm _emit 0x23 \
__asm _emit 0x47 \
__asm _emit 0x93 \
__asm _emit 0x29 \
__asm _emit 0x68 \
__asm _emit 0x06 \
__asm _emit 0x68 \
__asm _emit 0x54 \


// Don't change this!
#define _JUNK_BLOCK(s) __asm jmp s JUNKS __asm s:

int Process(string ProcessName)
{
    _JUNK_BLOCK(jmp_label1)
        HANDLE hPID = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    _JUNK_BLOCK(jmp_label2)
        PROCESSENTRY32 ProcEntry;

    _JUNK_BLOCK(jmp_label3)
        ProcEntry.dwSize = sizeof(ProcEntry);

    _JUNK_BLOCK(jmp_label4)
        do
        {
            _JUNK_BLOCK(jmp_label5)
                if (!strcmp(ProcEntry.szExeFile, ProcessName.c_str()))
                {
                    _JUNK_BLOCK(jmp_label6)
                        DWORD dwPID = ProcEntry.th32ProcessID;

                    _JUNK_BLOCK(jmp_label7)
                        CloseHandle(hPID);

                    _JUNK_BLOCK(jmp_label8)
                        return dwPID;
                }

            _JUNK_BLOCK(jmp_label9)
        } while (Process32Next(hPID, &ProcEntry));

            _JUNK_BLOCK(jmp_label10)
}




bool is_file_exist(const char* fileName) // Returns true if a file exists
{
    std::ifstream infile(fileName);
    return infile.good();
}

void RunAllAnitDebug()
{
    // Running all anti debugs one of the adbg crashes the exe not sure which one cba checking each one
    CreateThread(0, 0, (LPTHREAD_START_ROUTINE)DetectDebuggerThread, 0, 0, 0);
    CreateThread(0, 0, (LPTHREAD_START_ROUTINE)ChangeTitleThread, 0, 0, 0);
    adbg_BeingDebuggedPEB();
    adbg_CheckRemoteDebuggerPresent();
    //adbg_CheckWindowClassName();
    //adbg_CheckWindowName();
    //adbg_CrashOllyDbg();
    //adbg_GetTickCount();
    adbg_IsDebuggerPresent();
    //adbg_ProcessFileName();
    //adbg_HardwareDebugRegisters();
    //adbg_CloseHandleException();
    //adbg_SingleStepException();
    //adbg_Int3();
   //adbg_PrefixHop();
    //adbg_Int2D();
    //adbg_CrashOllyDbg();
    // Running all anti debugs
}
#pragma endregion

int inject()
{
    cout << AY_OBFUSCATE("[x] injecting\n");
    _JUNK_BLOCK(jmp_label11)
        DWORD dwProcess;

    _JUNK_BLOCK(jmp_label12)
        char myDLL[MAX_PATH];

    _JUNK_BLOCK(jmp_label13)
        GetFullPathName(DLL_NAME, MAX_PATH, myDLL, 0);

    _JUNK_BLOCK(jmp_label4)
        dwProcess = Process("csgo.exe");

    _JUNK_BLOCK(jmp_label15)
        HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, dwProcess);

    LPVOID ntOpenFile = GetProcAddress(LoadLibraryW(L"ntdll"), "NtOpenFile");
    if (ntOpenFile) {
        char originalBytes[5];
        memcpy(originalBytes, ntOpenFile, 5);
        WriteProcessMemory(hProcess, ntOpenFile, originalBytes, 5, NULL);
    }

    _JUNK_BLOCK(jmp_label16)
        LPVOID allocatedMem = VirtualAllocEx(hProcess, NULL, sizeof(myDLL), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    _JUNK_BLOCK(jmp_label17)
        WriteProcessMemory(hProcess, allocatedMem, myDLL, sizeof(myDLL), NULL);

    _JUNK_BLOCK(jmp_label18)
        CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibrary, allocatedMem, 0, 0);

    _JUNK_BLOCK(jmp_label19)
        CloseHandle(hProcess);

    _JUNK_BLOCK(jmp_label20)
        return 0;
         cout << AY_OBFUSCATE("[x] injected\n");
         Sleep(2000);

    _JUNK_BLOCK(jmp_label21)
}

int main()
{
    if (antidebugenabled)
    {
        RunAllAnitDebug();
    }

    if (antivpnenabled)
    {
        AntiVPN();
    }

    if (is_file_exist(AY_OBFUSCATE("C:\\Users\\Public\\banned.txt"))) // Checking if user is banned from anti debug
    {
        cout << AY_OBFUSCATE("[x] you're banned\n");
        Sleep(2000);
        exit(0);
    }   

    if (auth())
    {
        cout << AY_OBFUSCATE("[x] whitelisted\n");
        Sleep(2000);
        inject(); // inject the dll with the dll name and process
        Sleep(2000);
    }
    else {
        cout << AY_OBFUSCATE("[x] incorrect hwid\n");
        Sleep(1000);
        exit(10);
    }

}
