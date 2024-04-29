typedef struct IUnknown IUnknown;

#include <Windows.h>
#include <dbghelp.h>
#include <psapi.h>
#include <iostream>
#include <TlHelp32.h>
#include "dplay.h"
#include "dplobby.h"

#include "include/MinHook.h"
#include "Hooks.h"

#pragma comment(lib,"user32.lib") 
#pragma comment(lib,"libs\\libMinHook.x86.lib")
#pragma comment(lib, "dbghelp.lib")

GUID IID_IDirectPlayLobby3AGuid = { 0x2db72491, 0x652c, 0x11d1, 0xa7, 0xa8, 0x0, 0x0, 0xf8, 0x3, 0xab, 0xfc };

GUID IID_IDirectPlay4AGuid = { 0xab1c531, 0x4745, 0x11d1, 0xa7, 0xa1, 0x0, 0x0, 0xf8, 0x3, 0xab, 0xfc };

// {DF394860-E19E-11D0-805F-444553540000} Worms 2 game
GUID worms2_GUID = { 3745073248, 57758, 4560, 128, 95, 68, 69, 83, 84, 0, 0 };

GUID DP4_IPX_SP = { 1750844416, 40236, 4559, 169, 205, 0, 170, 0, 104, 134, 227 };

IDirectPlay4* lpDP = nullptr;

bool isTextSection(const BYTE* arr, size_t size) {
    const char* textSection = ".text";
    return size >= strlen(textSection) && memcmp(arr, textSection, strlen(textSection)) == 0;
}

bool isDataSection(const BYTE* arr, size_t size) {
    const char* textSection = ".data";
    return size >= strlen(textSection) && memcmp(arr, textSection, strlen(textSection)) == 0;
}

void PatchMemory(uintptr_t targetAddress, BYTE jmpOpcode[], int codeSize)
{
    // Write the modified instruction to the process
    SIZE_T bytesWritten;

    WriteProcessMemory(GetCurrentProcess(), reinterpret_cast<LPVOID>(targetAddress), jmpOpcode, codeSize, &bytesWritten);
}

void PatchMemory(uintptr_t targetAddress, void* value, int codeSize)
{
    // Write the modified instruction to the process
    SIZE_T bytesWritten;

    WriteProcessMemory(GetCurrentProcess(), reinterpret_cast<LPVOID>(targetAddress), value, codeSize, &bytesWritten);
}

BOOL FAR PASCAL DPConnect_EnumSessionsCallback(LPCDPSESSIONDESC2 lpThisSD,
    LPDWORD lpdwTimeOut,
    DWORD dwFlags,
    LPVOID lpContext)
{
    if (lpThisSD != NULL && lpThisSD->lpszSessionNameA != NULL)
    {
        //we got a game!
        return FALSE;
    }
    return TRUE;
}

//Function that hooks to the DirectPlayLobbyCreateA method
typedef HRESULT(WINAPI* DirectPlayLobbyCreateAType)(LPGUID, LPDIRECTPLAYLOBBYA*, IUnknown*, LPVOID, DWORD);
DirectPlayLobbyCreateAType pDirectPlayLobbyCreateA = nullptr; //original function pointer after hook
DirectPlayLobbyCreateAType pDirectPlayLobbyCreateATarget; //original function pointer BEFORE hook do not call this!
HRESULT WINAPI detourDirectPlayLobbyCreateA(LPGUID guid, LPDIRECTPLAYLOBBYA* lobby, IUnknown* unk, LPVOID ptr, DWORD word) {
    auto returnVal = pDirectPlayLobbyCreateA(guid, lobby, unk, ptr, word);

    if (SUCCEEDED(returnVal) && *lobby != nullptr) {
        IDirectPlayLobby3A* lpDP2 = nullptr;
        HRESULT queryResult = (*lobby)->QueryInterface(IID_IDirectPlayLobby3AGuid, (LPVOID*)&lpDP2);
        if (SUCCEEDED(queryResult) && lpDP2 != nullptr) {
            //Successfully obtained the IDirectPlayLobby3A interface

            //Create a buffer to hold the connection settings
            DWORD dwSize = 0;
            //Get the size of the connection settings
            queryResult = lpDP2->GetConnectionSettings(NULL, NULL, &dwSize);  // Pass NULL to get the required size

            if (queryResult == DPERR_BUFFERTOOSMALL) {
                //Allocate memory for the connection settings
                auto* pConnectionSettings = (DPLCONNECTION*)malloc(dwSize);

                //Now retrieve the connection settings
                queryResult = lpDP2->GetConnectionSettings(NULL, pConnectionSettings, &dwSize);
                if (SUCCEEDED(queryResult)) {
                    // Successfully got the connection settings
                    if (pConnectionSettings->dwFlags == 1 && pConnectionSettings->guidSP == DP4_IPX_SP)
                    {
                        //Get directplay object
                        LPDIRECTPLAY* lobby = (LPDIRECTPLAY*)malloc(sizeof(LPDIRECTPLAY));

                        HRESULT result = DirectPlayCreate(&DP4_IPX_SP, lobby, NULL);

                        if (SUCCEEDED(result)) {
                            //Get interface
                            result = (*lobby)->QueryInterface(IID_IDirectPlay4AGuid, (LPVOID*)&lpDP);

                            if (SUCCEEDED(result)) 
                            {
                                //Check for sessions
                                DPSESSIONDESC2 dpsd;
                                ZeroMemory(&dpsd, sizeof(dpsd));
                                dpsd.dwSize = sizeof(dpsd);
                                dpsd.guidApplication = worms2_GUID;

                                HRESULT hr = lpDP->EnumSessions(&dpsd, 0, DPConnect_EnumSessionsCallback,
                                    NULL, DPENUMSESSIONS_ALL);

                                std::cout << "wkDNet: Obtained DirectPlay object";

                                lpDP->Release();
                                lpDP = NULL;
                            }

                            (*lobby)->Release();
                            free(lobby);
                        }
                    }

                    std::cout << "wkDNet: GetConnectionSettings success";
                }
                else {
                    std::cerr << "wkDNet: Failed to get connection settings: " << std::hex << queryResult << std::endl;
                }

                free(pConnectionSettings);
            }
            else {
                std::cerr << "wkDNet: Failed to get connection settings size: " << std::hex << queryResult << std::endl;
            }

            lpDP2->Release();
        }
    }

    return returnVal;
}

void shutdown() {

    MH_Uninitialize();
}

bool Initialized = false;

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        MH_STATUS status = MH_Initialize();

        if (status != MH_OK)
        {
            std::string sStatus = MH_StatusToString(status);
            shutdown();
            return 0;
        }

        if (MH_CreateHookApiEx(L"dplayx", "DirectPlayLobbyCreateA", &detourDirectPlayLobbyCreateA, reinterpret_cast<void**>(&pDirectPlayLobbyCreateA), reinterpret_cast<void**>(&pDirectPlayLobbyCreateATarget)) != MH_OK) {
            shutdown();
            return 1;
        }

        if (MH_EnableHook(reinterpret_cast<void**>(pDirectPlayLobbyCreateATarget)) != MH_OK) {
            shutdown();
            return 1;
        }

        Initialized = true;
    }
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        if (Initialized && lpReserved)
            shutdown();
        break;
    }
    return TRUE;
}

