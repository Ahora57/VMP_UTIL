#ifndef INIT_ADDRESS
#define INIT_ADDRESS

#include "struct.h"
#include "minhook.h" 
#include "dump_syscall.h"


#define WOW64_SYSCALL_FLAG 0x03010000

namespace init_info
{
	PROC_INFO inf_proc;

	auto WINAPI init_syscall_id(PSYSCALL_ID sys_id) -> BOOLEAN
	{ 
		dump_syscall_util::syscall_help_map mapped_dll;
		 
		
		sys_id->proc_query = mapped_dll.map_get_syscall(L"ntdll.dll", FNV("NtQueryInformationProcess"));
		sys_id->set_thread = mapped_dll.map_get_syscall(L"ntdll.dll", FNV("NtSetInformationThread"));
		sys_id->create_file = mapped_dll.map_get_syscall(L"ntdll.dll", FNV("NtCreateFile"));
		sys_id->query_virt_mem = mapped_dll.map_get_syscall(L"ntdll.dll", FNV("NtQueryVirtualMemory"));
		sys_id->system_info  = mapped_dll.map_get_syscall(L"ntdll.dll", FNV("NtQuerySystemInformation")); 
		sys_id->close_handle = mapped_dll.map_get_syscall(L"ntdll.dll", FNV("NtClose"));
		sys_id->virt_prot = mapped_dll.map_get_syscall(L"ntdll.dll", FNV("NtProtectVirtualMemory"));
		
		  
		//Unmap from memory
		mapped_dll.de_map_get_syscall();
		return sys_id->proc_query;
	}

	auto WINAPI init_address(PVOID module_address, uint32_t rva_sec_first) -> BOOLEAN
	{ 
		init_info::inf_proc.target_base = module_address;
		init_info::inf_proc.size_mod = reinterpret_cast<PIMAGE_NT_HEADERS>(static_cast<CHAR*>(init_info::inf_proc.target_base) + static_cast<PIMAGE_DOS_HEADER>(init_info::inf_proc.target_base)->e_lfanew)->OptionalHeader.SizeOfImage;
		return init_syscall_id(&init_info::inf_proc.syscall); 
	}

	auto NO_INLINE WINAPI is_syscall(uint32_t mem, bool anti_debug = FALSE) -> BOOLEAN
	{
#ifndef _WIN64

		if (anti_debug)
		{
			if (  
				(WOW64_SYSCALL_FLAG + init_info::inf_proc.syscall.proc_query) == mem || 
				(WOW64_SYSCALL_FLAG + init_info::inf_proc.syscall.set_thread) == mem ||
				(WOW64_SYSCALL_FLAG + init_info::inf_proc.syscall.system_info) == mem  
				)
			{

				return TRUE;
			}
	
		}
		else
		{
			if (
				(WOW64_SYSCALL_FLAG + init_info::inf_proc.syscall.close_handle) == mem ||
				(WOW64_SYSCALL_FLAG + init_info::inf_proc.syscall.create_file) == mem ||
				(WOW64_SYSCALL_FLAG + init_info::inf_proc.syscall.proc_query) == mem ||
				(WOW64_SYSCALL_FLAG + init_info::inf_proc.syscall.query_virt_mem) == mem ||
				(WOW64_SYSCALL_FLAG + init_info::inf_proc.syscall.set_thread) == mem ||
				(WOW64_SYSCALL_FLAG + init_info::inf_proc.syscall.system_info) == mem ||
				(WOW64_SYSCALL_FLAG + init_info::inf_proc.syscall.virt_prot) == mem
				)
			{

				return TRUE;
			}
	}
#else 
		if (anti_debug)
		{
			if ( 
				init_info::inf_proc.syscall.proc_query == mem || 
				init_info::inf_proc.syscall.set_thread == mem ||
				init_info::inf_proc.syscall.system_info == mem  
				)
			{

				return TRUE;
			}
		}
		else
		{
			if (
				init_info::inf_proc.syscall.close_handle == mem ||
				init_info::inf_proc.syscall.create_file == mem ||
				init_info::inf_proc.syscall.proc_query == mem ||
				init_info::inf_proc.syscall.query_virt_mem == mem ||
				init_info::inf_proc.syscall.set_thread == mem ||
				init_info::inf_proc.syscall.system_info == mem ||
				init_info::inf_proc.syscall.virt_prot == mem
				)
			{

				return TRUE;
			}
		}
#endif // !_WIN64
		return FALSE;
	}
}
#endif // !INIT_ADDRESS
