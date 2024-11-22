//================================================\\ NEW PROJECT KR ORIGINAL BYPASS NPROTECT //================================================\\

#include <iostream>
#include "stdafx.h"
#include "lostsaga.h"
#include <psapi.h> 
#include <stdio.h>
#include <windows.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string>
#include <map>
#define MOB_H
#define MOB_H
using namespace std;
#define MAX_PROCESSES 1024 


bool verifyLicense(const std::string& licenseKey) {
	const std::string validLicenseKey = "PRJCT-LOSTSAGA-2024";

	return licenseKey == validLicenseKey;
}

void* DetourFunction(BYTE* src, DWORD dst, const int len)
{
	BYTE* jmp = (BYTE*)malloc(len + 5);
	DWORD dwBack;
	VirtualProtect(src, len, PAGE_EXECUTE_READWRITE, &dwBack);
	memcpy(jmp, src, len);
	jmp += len;
	jmp[0] = 0xE9;
	*(DWORD*)(jmp + 1) = (DWORD)(src + len - jmp) - 5;
	src[0] = 0xE9;
	*(DWORD*)(src + 1) = (DWORD)(dst - (DWORD)src) - 5;
	for (int i = 5; i < len; i++)  src[i] = 0x90;
	VirtualProtect(src, len, dwBack, &dwBack);
	return (jmp - len);
}


DWORD FindProcess(__in_z LPCTSTR lpcszFileName)
{
	LPDWORD lpdwProcessIds;
	LPTSTR  lpszBaseName;
	HANDLE  hProcess;
	DWORD   i, cdwProcesses, dwProcessId = 0;



	lpdwProcessIds = (LPDWORD)HeapAlloc(GetProcessHeap(), 0, MAX_PROCESSES * sizeof(DWORD));
	if (lpdwProcessIds != NULL)
	{
		if (EnumProcesses(lpdwProcessIds, MAX_PROCESSES * sizeof(DWORD), &cdwProcesses))
		{
			lpszBaseName = (LPTSTR)HeapAlloc(GetProcessHeap(), 0, MAX_PATH * sizeof(TCHAR));
			if (lpszBaseName != NULL)
			{
				cdwProcesses /= sizeof(DWORD);
				for (i = 0; i < cdwProcesses; i++)
				{
					hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, lpdwProcessIds[i]);
					if (hProcess != NULL)
					{
						if (GetModuleBaseName(hProcess, NULL, lpszBaseName, MAX_PATH) > 0)
						{
							if (!lstrcmpi(lpszBaseName, lpcszFileName))
							{
								dwProcessId = lpdwProcessIds[i];
								CloseHandle(hProcess);
								break;
							}
						}
						CloseHandle(hProcess);
					}
				}
				HeapFree(GetProcessHeap(), 0, (LPVOID)lpszBaseName);
			}
		}
		HeapFree(GetProcessHeap(), 0, (LPVOID)lpdwProcessIds);
	}
	return dwProcessId;
}

DWORD GetGameStart = (DWORD)GetModuleHandleA("lostsaga.exe");

DWORD InitStart = GetGameStart + 0x103C0C6;//0x1033BA6;
DWORD InitComplete = GetGameStart + 0x103C2D1;//0x1033DB1;
DWORD Exit23 = GetGameStart + 0x1D5DD85; //0x1D552A5;
DWORD Exit23JMP = Exit23 + 0xF1;
DWORD Exit24 = GetGameStart + 0x1D5DED8; //0x1D553F8;
DWORD Exit24JMP = Exit24 + 0x225;

void NProtectBypass()
{
	while (1)
	{
		DetourFunction((PBYTE)InitStart, (DWORD)InitComplete, 5);
		DetourFunction((PBYTE)Exit23, (DWORD)Exit23JMP, 5);
		DetourFunction((PBYTE)Exit24, (DWORD)Exit24JMP, 5);
		memcpy((void*)(0x02431D1C), (void*)(PBYTE)"Task", 4);
		memcpy((void*)(GetGameStart + 0x203237C), (void*)(PBYTE)"Daily (%d) ", 12);
		memcpy((void*)(GetGameStart + 0x203236C), (void*)(PBYTE)"Weekly (%d)", 13);
		memcpy((void*)(GetGameStart + 0x203235C), (void*)(PBYTE)"Monthly (%d) ", 12);
		memcpy((void*)(GetGameStart + 0x212BDE0), (void*)(PBYTE)"Event Shop", 11);
		memcpy((void*)(GetGameStart + 0x212BE00), (void*)(PBYTE)"Upgrade Hero", 13);
		memcpy((void*)(GetGameStart + 0x212BE10), (void*)(PBYTE)"Check Gift", 11);
		memcpy((void*)(GetGameStart + 0x213F30C), (void*)(PBYTE)"Scrap Hero", 11);
		//memcpy((void*)(GetGameStart + 0x213EDF6), (void*)(PBYTE)"Setelah masuk, klik Pecah Hero", 52);
		//==========================\\ QUEST MENU MAIN //==========================//
		memcpy((void*)(GetGameStart + 0x2032430), (void*)(PBYTE)"HiddenLS", 11);
		memcpy((void*)(GetGameStart + 0x2032424), (void*)(PBYTE)"Waiting . .", 11);
		//==========================\\ BATTLE MEMEKOS //==========================//
		memcpy((void*)(GetGameStart + 0x210F004), (void*)(PBYTE)"Train ", 6);
		memcpy((void*)(GetGameStart + 0x210EFF8), (void*)(PBYTE)"Exercise ", 8);
		//==========================\\ CHAMPIONSHIP //==========================//
		memcpy((void*)(GetGameStart + 0x205BC9C), (void*)(PBYTE)"LS CUP", 7);
		memcpy((void*)(GetGameStart + 0x210EFE8), (void*)(PBYTE)"Recruit", 7);
		memcpy((void*)(GetGameStart + 0x210EFCC), (void*)(PBYTE)"Tournamen", 10);
		memcpy((void*)(GetGameStart + 0x205EC10), (void*)(PBYTE)"Eclipsed Cup", 14);
		//==========================\\ CLOVER & FRIEND //==========================//
		memcpy((void*)(GetGameStart + 0x21345E8), (void*)(PBYTE)"Clover", 7);
		memcpy((void*)(GetGameStart + 0x21345C4), (void*)(PBYTE)"Send Clover", 13);
		memcpy((void*)(GetGameStart + 0x212BE24), (void*)(PBYTE)"Buddy/Guild", 12);
		//==========================\\ JUAL KOSTUME //==========================//
		memcpy((void*)(GetGameStart + 0x213ED38), (void*)(PBYTE)"Sell Costume", 12);
		//memcpy((void*)(GetGameStart + 0x213EDDA), (void*)(PBYTE)"Setelah masuk, klik Jual Costume", 26);
				//======================\\ BANEFIF //==========================//
		memcpy((void*)(GetGameStart + 0x202A550), (void*)(PBYTE)"Rare", 4);
		memcpy((void*)(GetGameStart + 0x202A558), (void*)(PBYTE)"Unqiue", 6);
		memcpy((void*)(GetGameStart + 0x202A560), (void*)(PBYTE)"Normal", 6);
		//======================\\ MORE TRANSLATOR GAME //==========================//
		memcpy((void*)(GetGameStart + 0x213ED64), (void*)(PBYTE)"Sell Medal", 10);
		memcpy((void*)(GetGameStart + 0x213EDDA), (void*)(PBYTE)"Click sell", 25);
		//======================\\ MORE TRANSLATOR GAME //==========================//
		memcpy((void*)(GetGameStart + 0x20338AC), (void*)(PBYTE)"HiddenLS Title Select", 25);

			if (FindProcess("GameGuard.des"))
			{
				TerminateProcessByName("GameGuard.des");
				TerminateProcessByName("GameMon.des");
				TerminateProcessByName("GameMon64.des");


			}
	}
}
// Potong lah 
DWORD Pantekbapaknya(DWORD Base, DWORD Ofs1, DWORD Ofs2, DWORD Ofs3, PBYTE String, int size)
{
	DWORD Temp = NULL;

	if (IsBadReadPtr((PDWORD)Base, 4) == 0) {
		Temp = *(PDWORD)((DWORD)(Base)) + Ofs1;
		if (IsBadReadPtr((PDWORD)Temp, 4) == 0) {
			Temp = *(PDWORD)((DWORD)(Temp)) + Ofs2;
			if (IsBadReadPtr((PDWORD)Temp, 4) == 0) {
				Temp = *(PDWORD)((DWORD)(Temp)) + Ofs3;
				if (IsBadReadPtr((PDWORD)Temp, 4) == 0) {
					memcpy((void*)(Temp), (void*)(PBYTE)String, size);

				}
			}
		}
	}

	return (0);
}

// Potong lah 
DWORD BaseString(DWORD Base, PBYTE String, int size)
{
	DWORD Temp = NULL;

	if (IsBadReadPtr((PDWORD)Base, 4) == 0) {
		
					memcpy((void*)(Temp), (void*)(PBYTE)String, size);
		
	}

	return (0);
}
BOOL APIENTRY DllMain(HMODULE hModule,


	DWORD  ul_reason_for_call,
	LPVOID lpReserved)

	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		DisableThreadLibraryCalls(hModule);

		LPSTR cmdLine = GetCommandLineA();
		if (!strstr(cmdLine, "YOUR_GAMESERVERID")) return FALSE;
		if (!(DWORD)GetModuleHandleA("lostsaga.exe")) return FALSE;
		CreateThread(0, 0, (LPTHREAD_START_ROUTINE)&NProtectBypass, 0, 0, 0);
		break;
	}

	return TRUE;
}


