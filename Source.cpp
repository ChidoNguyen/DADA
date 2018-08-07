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
#include <tchar.h> // Text mapping (?) mainly used to be more language tolerant with 2 bytes per  char
#include <psapi.h> // https://docs.microsoft.com/en-us/windows/desktop/psapi/psapi-functions
#include <tlhelp32.h> // Need this for snapping a process state
#include <iostream>

//https://docs.microsoft.com/en-us/windows/desktop/psapi/process-status-helper// Process Status API

/*
ALL CREDITS TO MICROSOFT: https://docs.microsoft.com/en-us/windows/desktop/psapi/enumerating-all-processes
I took their template and attempted to see what was happening and renamed stuff to make it more clear to myself!!
Added  int listing so that it'll print out the correlating index of the PID for user to select for further analysis
*/

void PrintProcessNameAndID(DWORD processID, int listing)	// pass in PID to dissect
{
	TCHAR name_buffer[MAX_PATH] = TEXT("<unknown>");	// https://www.dreamincode.net/forums/topic/51241-what-is-char-and-tchar-and-char/ TCHAR is used over CHAR for unicode purposes and seems to handle foreign symbols better
														// makes this more real life language agnostic(?) possibly
														// MAX_PATH is equivalent to a big buffer I'm assuming
														// TEXT() is a macro but for our purposes just puts unknown into the process name unless otherwise populated (https://docs.microsoft.com/en-us/windows/desktop/api/winnt/nf-winnt-text)

	// Get a handle to the process.
	//https://stackoverflow.com/questions/1303123/what-is-a-handle-in-c
	// A handle to an object is meant to be Vague as the user defines what and how to use the object(?)
	// Open Process : https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-openprocess
	// Seems the function returns a handle ( or address) to the object in question aka our process.
	// We pass it rights to access everything , FALSE flag to prevent inheiriting handles(?), and the process ID itself.

	HANDLE Process = OpenProcess(PROCESS_ALL_ACCESS,FALSE, processID); // open a process from our process_list array PID and attach a handle to it to look for a name

	// Get the process name.

	if (NULL != Process)
	{
		HMODULE Mod; // just a place holder for grabbing name will need to make this an array when we enumerate for loaded  modules similar to handle but for modules
		DWORD bytes_Needed; // place holder, but if used we can store size of bytes of loaded modules later for hMod

		// Changed to EnumProcessModulesEX thinking it'd fix the  "unknown" problem but it didnt
		//if (EnumProcessModulesEx(hProcess, &hMod, sizeof(hMod), &cbNeeded,LIST_MODULES_ALL)) //load a random single module to hmod
		if (EnumProcessModules(Process, &Mod, sizeof(Mod), &bytes_Needed))
		{
			GetModuleBaseName(Process, Mod, name_buffer,sizeof(name_buffer) / sizeof(TCHAR)); // extract name of module
		}
	}

	// Print the process name and identifier.

	_tprintf(TEXT("%i\t%s  (PID: %u)\n"),listing, name_buffer, processID); // _tprintf is like a 2 bird 1 stone incase we get unicode characters or 2 byte stuff  that printf cant handle it'll redirect to something that can
	// https://www.quora.com/What-is-the-difference-between-printf-and-tprintf //

	// Release the handle to the process.

	CloseHandle(Process);
}

/*
Same as above all credit to microsoft API documentation I'm just trying to figure out what its doing and using it correctly
https://docs.microsoft.com/en-us/windows/desktop/toolhelp/traversing-the-thread-list
Function takes a process ID , and attempts to grab a snapshot and print out the threads running in it.
*/

bool ThreadListing(DWORD processID) {
	HANDLE ThreadSnapShot = INVALID_HANDLE_VALUE; //handle declared equivalent to a "Null Pointer"
	THREADENTRY32 one_instance; // https://docs.microsoft.com/en-us/windows/desktop/api/tlhelp32/ns-tlhelp32-tagthreadentry32 
								// structured data which stores various thread related info


	//Grab a snap of all running threads//
	ThreadSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0); // First arg is flag for what we want snapthread  takes a snap of all system thread, Second Arg is usually for processID 
																	// https://docs.microsoft.com/en-us/windows/desktop/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot
	//Error Check since our CTH32SS function returns "Invalid handle value" if failed.
	if (ThreadSnapShot == INVALID_HANDLE_VALUE) {
		return 0; // false
	}

	/*
	Similar to traversing a linked list we grab the first item make sure it isn't "bad", if its parent PID is equal to what we passed in print the info
	if not we go "next" until the end.
	*/

	one_instance.dwSize = sizeof(THREADENTRY32); // size of our data structure

	// grab first thread //
	if (!Thread32First(ThreadSnapShot, &one_instance)) {
		std::cout << "Error thread snapping" << std::endl;
		CloseHandle(ThreadSnapShot); // Similar to free'ing new memory we close the handle
		return 0;
	}
	//Here is our walk through, if parent ID = processID we print if not we iterate to next thread till we have  no more//
	do
	{
		if (one_instance.th32OwnerProcessID == processID) {
			//printf("Thread ID: \t0x%08X", one_instance.th32ThreadID);
			_tprintf(TEXT("\n     THREAD ID      = %i"), one_instance.th32ThreadID);
		}
	} while (Thread32Next(ThreadSnapShot, &one_instance));
	std::cout << std::endl;
	CloseHandle(ThreadSnapShot);
	return 1;
}

/*
Enumerating all loaded modules of a  process
https://docs.microsoft.com/en-us/windows/desktop/api/Psapi/nf-psapi-enumprocessmodules
Function acts very similiar to Enumerating all the processes. Except this time we're loading all the modules into an array holder
then printing it  out
*/
void ModuleListing(DWORD processID) {
	HMODULE mod_handle[1024];// Similar to other handles for a process this is for modules
	HANDLE process_handle;
	DWORD sum_bytes_hmod;
	
	std::cout << "Process ID we are examining <" << processID << ">\n";

	process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID); // open the process and throw a handle on it
	MODULEINFO testing;
	if (EnumProcessModulesEx(process_handle, mod_handle, sizeof(mod_handle), &sum_bytes_hmod,LIST_MODULES_ALL)) {
		int x = sizeof(mod_handle);
		for (int i = 0; i < (sum_bytes_hmod / sizeof(HMODULE)); i++) {
			TCHAR modName[MAX_PATH];
			if (GetModuleFileNameEx(process_handle,mod_handle[i], modName, sizeof(modName) / sizeof(TCHAR))) {
				printf("Module Name:     %s\n", modName);
				GetModuleInformation(process_handle, mod_handle[i], &testing, sizeof(MODULEINFO)); // https://docs.microsoft.com/en-us/windows/desktop/api/Psapi/nf-psapi-getmoduleinformation
				std::cout << "\n\tEntry Point Address: 0x" << testing.EntryPoint << " \n\t" << "Load Address of: 0x" << testing.lpBaseOfDll << " \n\t" << "Image Size: " << testing.SizeOfImage << std::endl << std::endl;
			}
		}
	}
	else
		std::cout << GetLastError() << std::endl;


}

//Someone else in class slacks indicated that entry points of DLL and what not were preferred so I commented out this section of  function as it didn't seemm needed in main //
/*
Attempt at popullating memory pages of a process
https://stackoverflow.com/questions/3313581/runtime-process-memory-patching-for-restoring-state/3313700#3313700
Found an article with some guy dissecting how to use virtualqueryex to populate memory pages.
https://msdn.microsoft.com/en-us/library/windows/desktop/aa366907(v=vs.85).aspx
*/
void MemoryPages(DWORD processID) {

	MEMORY_BASIC_INFORMATION status; // data structure that holds information about the memory region private/free/commit/exec etc
	unsigned long *p = NULL; // We use this to keep track of our progress along the virtual memory space. Like the "END OF THE LINE" guy during black friday
	HANDLE process = OpenProcess(PROCESS_VM_READ| PROCESS_QUERY_INFORMATION, FALSE, processID); // grabbing our process handle 


	for (p = NULL; VirtualQueryEx(process, p, &status, sizeof(status)) == sizeof(status); p += status.RegionSize)
	{
			/*P starts at null, when we call VirtualQueryEx we look at the process we're passing into it
			The second argument is usually where we "start" looking at. Status is the data structure where our function stores all
			the information about the memory region too. Each section queried is equivalent to the size of our datastructure "status". It'll break
			when the returned byte sizes don't match up. After each iteration we update our "HERE I AM FLAG" p with to its new location.
			*/

		//printf("Base Address: %i\t Size: %i Kb\t", status.BaseAddress, status.RegionSize/1024);
		//Using stackoverflow authors printf since its formatted for hex
		printf("%#8.8x (%6uK)\t", status.BaseAddress, status.RegionSize / 1024);

		// Switch check for Committed Reserved or Free memory. Microsoft page shows Macros or Hex checks MEM_COMMIT or 0x1000
		//https://docs.microsoft.com/en-us/windows/desktop/api/winnt/ns-winnt-_memory_basic_information
		//we can poll the State of the memory region and switch accordingly
		//https://stackoverflow.com/questions/3313581/runtime-process-memory-patching-for-restoring-state/3313700#3313700
		switch (status.State) {
		case MEM_COMMIT:
			printf("Commit");
			break;
		case MEM_FREE:
			printf("Free");
			break;
		case MEM_RESERVE:
			printf("Reserve");
			break;
		}
		printf("\t");

		//Check for image/mapped/ private memory status types
		switch(status.Type) {
			case MEM_IMAGE:
				printf("Image");
				break;
			case MEM_MAPPED:
				printf("Mapped");
				break;
			case MEM_PRIVATE:
				printf("Private");
				break;
		}

		//RWX check
		//https://docs.microsoft.com/en-us/windows/desktop/Memory/memory-protection-constants
		printf("\t");
		switch (status.AllocationProtect) {
		case PAGE_READONLY:
			printf("Read Only");
			break;
		case PAGE_READWRITE:
			printf("Read/Write");
			break;

		case PAGE_EXECUTE:
			printf("Execute only");
			break;
		case PAGE_EXECUTE_READ:
			printf("Execute/Read");
			break;
		case PAGE_EXECUTE_READWRITE:
			printf("Execute/Read/Write");
			break;
		}
		printf("\n");
	}

}



/*
Winging the read memory part not a lot ofstructured code out there
https://msdn.microsoft.com/en-us/library/windows/desktop/ms680553%28v=vs.85%29.aspx?f=255&MSPPError=-2147217396
From the parameters it requires, the usual process ID, the base address you want to start reading at, the buffer array to
store the memory too how many bytes  you want to read, and how many bytes were actually read.
ReadProcessmemory(Handle, base, buffer, size, read)
*/

void memory_read_maybe(unsigned long base, int  bytes, DWORD processID) {
	HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
	TCHAR arr[1024];
	SIZE_T read_ret;
	std::cout << std::hex; 
	ReadProcessMemory(process, (LPCVOID)base, (LPVOID)arr, bytes, &read_ret);
	for (int i = 0; i < bytes; i++) {
		std::cout << arr[i];
	}
	std::cout <<std::endl;
	std::cout << std::dec;
}


int main() {
	DWORD process_list[1024]; // "list" of our processes to be stored to DWORD unsigned 32bit unit of data
	DWORD process_bytes; // bytes size of all processes
	DWORD process_count; // number of processes
	//DWORD mod_handle[1024];// Similar to other handles for a process this is for modules
	int user_PID; // user choice of which PID to look at

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
			PrintProcessNameAndID(process_list[i], i);
		}
	}

	std::cout << "Enter the listing number corresponding to the PID you wish to look at , not the PID it self\n";
	std::cin >> user_PID;
	while (user_PID < 0 || user_PID >process_count) {
		std::cout << "Entry Error, Try Again" << std::endl;
		std::cin >> user_PID;
	}
	system("CLS"); // clears console
	std::cout << "Thread Information for: ";
	// Prints out Threads //
	PrintProcessNameAndID(process_list[user_PID], user_PID);
	std::cout << std::endl;
	int status = ThreadListing(process_list[user_PID]);
	if (!status) {
		std::cout << "error " << std::endl;
	}

	// Prints Modules Loaded //
	//Using EnumProcessModules : https://docs.microsoft.com/en-us/windows/desktop/api/Psapi/nf-psapi-enumprocessmodules //
	ModuleListing(process_list[user_PID]);
	// Printing out Memory Info 
	//MemoryPages(process_list[user_PID]);

	//What parts to read//
	std::cout << "Please indicate the base address listed above of where you want to start examining the memory leave the 0x out (AAAAAAAA).\n MAX 500 BYTES!!!" << std::endl;
	unsigned long baseAddy=10;
	int memory_read = 0;
	std::cin.clear();
	std::cin>> std::hex >> baseAddy; // http://www.cplusplus.com/reference/ios/hex/ taking in hex user input
	std::cin.clear();
	std::cout << "How many bytes of memory do you want to read?" << std::endl;
	std::cin >>std::dec>> memory_read;
	memory_read_maybe(baseAddy, memory_read*2, process_list[user_PID]);
	std::cin.clear();
	std::cout << "Press Enter When You're Ready." << std::endl;
	std::cin.ignore();
	std::cin.ignore();
	//Printing out Memory Info 
	// MAJOR ISSUES HERE//
	// MAJOR ISSUES HERE//
	// MAJOR ISSUES HERE//
	// MAJOR ISSUES HERE//
	/*
	MY SYSTEM IS 64 bit which will map correctly, but if I build in 32bit it'll infinite loop 
	*/
	/*system("CLS");
	std::cout << "Really unsure if this is correct but hopefully this is what the 5th requirement is:" << std::endl;
	MemoryPages(process_list[user_PID]);
*/

	std::cout << "Press Enter When You're Ready To Quit." << std::endl;
	std::cin.ignore();
	std::cin.ignore();

	return 0;
}