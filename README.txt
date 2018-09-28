Chido Nguyen
hw5 Program.


My system is a windows 10 64bit system. The memory mapping function I have added in there "MemoryPages()" works fine on my pc under 64bit build mode. When I tried to develop for 32bit system it  couldn't map properly and would infinite loop. I have 2 versions submitted. the 64 will have that function enabled, in the 32 bit version I have it turned off. 
***** Whole solution file was too big to upload to canvas possibly ~50mb, canvas was stalling will provide solution to project (VS2017 files) if needed*****

To test build your own open my solution, right click project1 -> properties -> configuration manager -> pick x86 for 32bit mode, and uncomment out the code after // MAY CAUSE  MAJOR ISSUES// comment spam at bottom of main().

	/*system("CLS");
	std::cout << "Really unsure if this is correct but hopefully this is what the 5th requirement is:" << std::endl;
	MemoryPages(process_list[user_PID]);
*/

Also lots of this project was googled , I tried to document all my sources as best as I can and comment to show that  I tried my best to understand what was going on with the code and not just re-hashing to submit.

Majority of the work done was thanks to Microsoft documentation https://docs.microsoft.com/en-us/windows/desktop/psapi/psapi-functions



