/*
Chido Nguyen
931-50-6965
CS373: Defense Against the Dark Arts
Program Purpose:
1) Load all processes
2) Load threads within process boundaries
3) Enumerate loaded modules in process
4) Show executable pages in process
5) read memory
*/
#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <psapi.h>
#include <iostream>

//https://docs.microsoft.com/en-us/windows/desktop/psapi/process-status-helper// Process Status API

/*
ALL CREDITS TO MICROSOFT: https://docs.microsoft.com/en-us/windows/desktop/psapi/enumerating-all-processes
I took their template and attempted to see what was happening and renamed stuff to make it more clear to myself!!
*/

void PrintProcessNameAndID(DWORD processID)	// pass in PID to dissect
{
	TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");	// https://www.dreamincode.net/forums/topic/51241-what-is-char-and-tchar-and-char/ TCHAR is used over CHAR for unicode purposes and seems to handle foreign symbols better
														// makes this more real life language agnostic(?) possibly

	// Get a handle to the process.
	//https://stackoverflow.com/questions/1303123/what-is-a-handle-in-c
	// A handle to an object is meant to be Vague as the user defines what and how to use the object(?)
	// Open Process : https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-openprocess
	// Seems the function returns a handle ( or address) to the object in question aka our process.
	// We pass it rights to access everything , FALSE flag to prevent inheiriting handles(?), and the process ID itself.

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS,FALSE, processID);

	// Get the process name.

	if (NULL != hProcess)
	{
		HMODULE hMod; // just a place holder for grabbing name will need to make this an array when we enumerate for loaded  modules similar to handle but for modules
		DWORD cbNeeded; // place holder, but if used we can store size of bytes of loaded modules later for hMod

		if (EnumProcessModulesEx(hProcess, &hMod, sizeof(hMod),
			&cbNeeded,LIST_MODULES_ALL)) //load a random single module to hmod
		{
			GetModuleBaseName(hProcess, hMod, szProcessName,
				sizeof(szProcessName) / sizeof(TCHAR)); // extract name of module
		}
	}

	// Print the process name and identifier.

	_tprintf(TEXT("%s  (PID: %u)\n"), szProcessName, processID); // _tprintf is like a 2 bird 1 stone incase we get unicode characters or 2 byte stuff  that printf cant handle it'll redirect to something that can
	// https://www.quora.com/What-is-the-difference-between-printf-and-tprintf //

	// Release the handle to the process.

	CloseHandle(hProcess);
}




int main() {
	DWORD process_list[1024]; // "list" of our processes to be stored to DWORD unsigned 32bit unit of data
	DWORD process_bytes; // bytes size of all processes
	DWORD process_count; // number of processes
		/*
		https://docs.microsoft.com/en-us/windows/desktop/api/Psapi/nf-psapi-enumprocesses
		Documentation for enumerating processes on my computer with c++ through EnumProcesses()
		Adds processes information into the array, and saves up the bytes in process_bytes
		We can figure out the number of processes by taking total bytes dividing it by size of DWORD
		*/
	EnumProcesses(process_list, sizeof(process_list), &process_bytes);
	process_count = process_bytes / sizeof(DWORD);
	for (int i = 0; i < process_count; i++) {
		if (process_list[i] != 0) {
			PrintProcessNameAndID(process_list[i]);
		}
	}
	return 0;
}