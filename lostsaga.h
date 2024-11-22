//================================================\\ NOIRINFINTE PROJECT //================================================\\

#pragma once
#include "stdafx.h"
#include <TlHelp32.h>
#include <stdio.h>
#include <windows.h>
#include <iostream>

//#include <LSLog.cpp>

#define MAX_PROCESSES 1024 

HANDLE GetHandleByName(LPCTSTR module)
{
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);
	PROCESSENTRY32 pEntry;
	pEntry.dwSize = sizeof(pEntry);
	BOOL hRes = Process32First(hSnapShot, &pEntry);
	while (hRes)
	{
		if (lstrcmp(pEntry.szExeFile, module) == 0) {
			HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, 0, (DWORD)pEntry.th32ProcessID);
			if (hProcess != INVALID_HANDLE_VALUE) {
				return hProcess;
			}
		}
		hRes = Process32Next(hSnapShot, &pEntry);
	}
	CloseHandle(hSnapShot);
	return INVALID_HANDLE_VALUE;

}

DWORD GetProcIDz(LPCTSTR module)
{
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);
	PROCESSENTRY32 pEntry;
	pEntry.dwSize = sizeof(pEntry);
	BOOL hRes = Process32First(hSnapShot, &pEntry);
	while (hRes)
	{
		if (lstrcmp(pEntry.szExeFile, module) == 0) {
			return pEntry.th32ProcessID;
		}
		hRes = Process32Next(hSnapShot, &pEntry);
	}
	CloseHandle(hSnapShot);
	return 0;
}


bool TerminateProcessByName(LPCTSTR module)
{
	DWORD myProcID = GetProcIDz(module);
	if (myProcID)
	{
		PROCESSENTRY32 pe;

		memset(&pe, 0, sizeof(PROCESSENTRY32));
		pe.dwSize = sizeof(PROCESSENTRY32);

		HANDLE hSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

		if (::Process32First(hSnap, &pe))
		{
			BOOL bCONtinue = TRUE;

			// kill child processes
			while (bCONtinue)
			{
				// ONly kill child processes
				if (pe.th32ParentProcessID == myProcID)
				{
					HANDLE hChildProc = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe.th32ProcessID);

					if (hChildProc)
					{
						::TerminateProcess(hChildProc, 1);
						::CloseHandle(hChildProc);
					}
				}

				bCONtinue = ::Process32Next(hSnap, &pe);
			}

			// kill the main process
			HANDLE hProc = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, myProcID);

			if (hProc)
			{
				::TerminateProcess(hProc, 1);
				::CloseHandle(hProc);
				return true;
			}
		}
	}
	return false;
}