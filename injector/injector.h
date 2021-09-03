#pragma once
#include <iostream>
#include <cstdio> 
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <cstdint>
#include <filesystem>

#include <windows.h> 
#include <TlHelp32.h>
#include <Dbghelp.h>


namespace util 
{

	inline DWORD get_pid(const char* process_name)
	{
		HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

		PROCESSENTRY32 pe32;
		pe32.dwSize = sizeof(pe32);

		if (!Process32First(hSnap, &pe32))
			return NULL;

		do {

			if (!strcmp(pe32.szExeFile, process_name))
			{
				CloseHandle(hSnap);
				return pe32.th32ProcessID;
			}

		} while (Process32Next(hSnap, &pe32));

		CloseHandle(hSnap);
		return NULL;
	}

	std::string random_string(const size_t length)
	{
		std::string r;
		static const char bet[] = { "ABCDEFGHIJKLMNOPQRSTUVWXYabcdefghijklmnopqrstuvwxyzZ1234567890" };
		srand((unsigned)time(NULL) * 5);
		for (int i = 0; i < length; ++i)
			r += bet[rand() % (sizeof(bet) - 1)];
		return r;
	}

}


class Injector
{

public:
	Injector(DWORD pid, const char* dllpath);
	~Injector();

public:
	void* inject();
	bool file_exists(const char* sz_path);

	auto resolve_function(std::string, std::string);
	HANDLE entry(std::uintptr_t);

private:
	void* alloc_base;
	HANDLE target_handle;
	DWORD pid;
	const char* dllpath;

	void write(void* addr, const char* buffer, std::size_t size);

};

Injector::Injector(DWORD processID, const char* path)
{
	this->pid = processID;
	this->dllpath = path;
};


Injector::~Injector() 
{
	VirtualFreeEx(target_handle, alloc_base, strlen(dllpath) + 1, MEM_RELEASE);
	CloseHandle(target_handle);
};

bool Injector::file_exists(const char* sz_path)
{
	DWORD dwAttrib = GetFileAttributes(sz_path);

	return (dwAttrib != INVALID_FILE_ATTRIBUTES and
		not(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

auto Injector::resolve_function(std::string module_base, std::string module_name)
{
	return reinterpret_cast<std::uintptr_t>(GetProcAddress(GetModuleHandle(module_base.c_str()), module_name.c_str()));
}

void* Injector::inject()
{
	if ((dllpath != NULL) and (dllpath[0] == '\0')) 
	{
		std::printf("[-] Don't receive DLLpath\n");

	}
	
	std::printf("[+] DLL PATH : %s\n", dllpath);
	std::printf("[+] SIZE : %i\n", strlen(dllpath) + 1);
	
	std::printf("[+] pid : %i\n", pid);

	target_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid); // change permissions

	if (!target_handle)
	{
		return NULL;
	}

	alloc_base = VirtualAllocEx(
		target_handle, 
		NULL, 
		strlen(dllpath) + 1, 
		MEM_RESERVE | MEM_COMMIT, 
		PAGE_READWRITE
		);

	if (alloc_base) 
	{
		std::printf("Allocated memory in : %p\n", alloc_base);
	}

	write(alloc_base, dllpath, strlen(dllpath) + 1 );
	auto ep = resolve_function("kernel32.dll", "LoadLibraryA");

	HANDLE load_thread = entry(ep);
	if (!load_thread) 
	{
		std::printf("[+] Problem handle thread: %i\n", GetLastError());
		return 0;
	}

	else
	{
		std::printf("Handle: %p\n", load_thread);
	}

	WaitForSingleObject(load_thread, INFINITE);

}

HANDLE Injector::entry(std::uintptr_t const entry_point)
{
	SECURITY_ATTRIBUTES sec_attr{};

	return CreateRemoteThread(
		target_handle, &sec_attr, NULL, (LPTHREAD_START_ROUTINE)(entry_point), alloc_base, NULL, 0);

}

void Injector::write(void* addr, const char* buffer, std::size_t size)
{
	SIZE_T bytes_written;
	::WriteProcessMemory(
		target_handle,
		addr,
		buffer,
		size,
		&bytes_written
	);
}
