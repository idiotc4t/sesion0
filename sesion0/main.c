#include <Windows.h>
#include <stdio.h>

#ifdef _WIN64
typedef DWORD(WINAPI* typedef_ZwCreateThreadEx)(
	PHANDLE ThreadHandle,
	ACCESS_MASK DesiredAccess,
	LPVOID ObjectAttributes,
	HANDLE ProcessHandle,
	LPTHREAD_START_ROUTINE lpStartAddress,
	LPVOID lpParameter,
	ULONG CreateThreadFlags,
	SIZE_T ZeroBits,
	SIZE_T StackSize,
	SIZE_T MaximumStackSize,
	LPVOID pUnkown);
#else
typedef DWORD(WINAPI* typedef_ZwCreateThreadEx)(
	PHANDLE ThreadHandle,
	ACCESS_MASK DesiredAccess,
	LPVOID ObjectAttributes,
	HANDLE ProcessHandle,
	LPTHREAD_START_ROUTINE lpStartAddress,
	LPVOID lpParameter,
	BOOL CreateSuspended,
	DWORD dwStackSize,
	DWORD dw1,
	DWORD dw2,
	LPVOID pUnkown);
#endif

typedef DWORD(WINAPI* typedef_LoadLibraryA)(char* path);
/*
BOOL EnbalePrivileges(HANDLE hProcess, char* pszPrivilegesName)
{
	HANDLE hToken = NULL;
	LUID luidValue = { 0 };
	TOKEN_PRIVILEGES tokenPrivileges = { 0 };
	BOOL bRet = FALSE;

	bRet = OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &hToken);

	bRet = LookupPrivilegeValue(NULL, pszPrivilegesName, &luidValue);

	tokenPrivileges.PrivilegeCount = 1;
	tokenPrivileges.Privileges[0].Luid = luidValue;
	tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	bRet = AdjustTokenPrivileges(hToken, FALSE, &tokenPrivileges, 0, NULL, NULL);


	return TRUE;
}*/

int main(int argc, char* argv[]) {
	//EnbalePrivileges(GetCurrentProcess(), SE_DEBUG_NAME);

	char DllPath[] = "C:\\Users\\Black Sheep\\source\\repos\\sesion0\\x64\\Debug\\TestDll.dll";

	HANDLE hRemoteThread;

	HANDLE hNtModule = GetModuleHandleA("ntdll.dll");

	HANDLE hKeModule = GetModuleHandleA("Kernel32.dll");

	typedef_ZwCreateThreadEx ZwCreateThreadEx = GetProcAddress(hNtModule, "ZwCreateThreadEx");

	typedef_LoadLibraryA myLoadLibraryA = GetProcAddress(hKeModule, "LoadLibraryA");

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, 1516);

	LPVOID lpBaseAddress = VirtualAllocEx(hProcess, NULL, sizeof(DllPath)+1, MEM_COMMIT, PAGE_READWRITE);

	WriteProcessMemory(hProcess, lpBaseAddress, DllPath, sizeof(DllPath), 0);

	ZwCreateThreadEx(&hRemoteThread, PROCESS_ALL_ACCESS, NULL, hProcess, (LPTHREAD_START_ROUTINE)myLoadLibraryA, lpBaseAddress, 0, 0, 0, 0, NULL);

	CloseHandle(hRemoteThread);
	CloseHandle(hProcess);
	FreeLibrary(hKeModule);
	FreeLibrary(hNtModule);
	return 0;

}