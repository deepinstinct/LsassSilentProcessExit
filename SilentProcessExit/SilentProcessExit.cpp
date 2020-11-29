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
	RtlReportSilentProcessExit_func RtlReportSilentProcessExit = (RtlReportSilentProcessExit_func)GetProcAddress(hNtdll, "RtlReportSilentProcessExit");

	int pid = atoi(argv[1]);

	HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);

	if (hProcess == INVALID_HANDLE_VALUE)
	{
		int lastError = GetLastError();


		std::cout << "ERROR OpenProcess() failed with error: " << lastError << "\n";
		return -1;
	}

	NTSTATUS ntstatus = RtlReportSilentProcessExit(hProcess, 0);

	std::cout << "RtlReportSilentProcessExit() NTSTATUS: " << std::hex << ntstatus << "\n";
}
