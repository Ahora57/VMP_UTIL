#ifndef ANTI_DEBUG
#define ANTI_DEBUG 1


#include "init_address.h" 
#include "nt_api_def.h"
#include "minhook.h"


#define MAX_LDR_INIT_THUNK  0x100

//https://github.com/x64dbg/ScyllaHide/blob/baa5c8e853ace2bee752631f27fdfe5b271d92f6/HookLibrary/HookedFunctions.cpp#L27
#define BACKUP_RETURNLENGTH() \
    ULONG TempReturnLength = 0; \
    if(ReturnLength != nullptr) \
        TempReturnLength = *ReturnLength

#define RESTORE_RETURNLENGTH() \
    if(ReturnLength != nullptr) \
        (*ReturnLength) = TempReturnLength

//Write for only VMP and meh
namespace anti_debug
{
	class anti_debug
	{

	private:

		 
	

		

	public:

		NO_INLINE static auto WINAPI toupper(INT c) -> INT
		{
			if (c >= 'a' && c <= 'z') return c - 'a' + 'A';
			return c;
		}

		NO_INLINE static auto WINAPI  strlen(CONST CHAR* string) -> INT
		{
			INT cnt = NULL;
			if (string)
			{
				for (; *string != NULL; ++string) ++cnt;
			}
			return cnt;
		}


		NO_INLINE static auto WINAPI memicmp(CONST PVOID s1, CONST PVOID s2, uint64_t n) -> INT
		{
			if (n != NULL)
			{
				const uint8_t* p1 = (uint8_t*)s1, * p2 = (uint8_t*)s2;
				do
				{
					if (toupper(*p1) != toupper(*p2)) return (*p1 - *p2);
					p1++;
					p2++;
				} while (--n != NULL);
			}
			return NULL;
		}

		NO_INLINE static auto WINAPI remove_bad_string(PVOID buffer, uint32_t buf_len) -> VOID
		{
			uint32_t bad_str_len = NULL;

			CONST CHAR* fake_str =
			{
				"Femboy"
			};

			uint32_t fake_str_len = sizeof("Femboy") - 1;
			

			CONST CHAR* bad_string[]
			{
				"VMWare",
				"VirtualBox",
				"Parallel"
			};

			uint32_t bad_string_len[] =
			{
				sizeof("VMWare") - 1,
				sizeof("VirtualBox") - 1,
				sizeof("Parallel") - 1,
			};

			//Lazy present bad buffer len
			if (buf_len > sizeof("VirtualBox") - 1)
			{
				buf_len -= sizeof("VirtualBox") - 1;
			}

			for (size_t i = NULL; i < buf_len; i++)
			{
				for (size_t i = NULL; i < _countof(bad_string); i++)
				{
					bad_str_len = bad_string_len[i];
					if (memicmp(reinterpret_cast<CHAR*>(buffer) + i, (PVOID)bad_string[i], bad_str_len) == NULL)
					{
						memset(reinterpret_cast<CHAR*>(buffer) + i, NULL, bad_str_len);
						memcpy(reinterpret_cast<CHAR*>(buffer) + i, fake_str, fake_str_len);
					}
				}
			}
		}

		NO_INLINE static auto WINAPI enable_hwbp(PCONTEXT p_ctx = NULL) -> BOOLEAN
		{
			BOOLEAN is_set = TRUE;
			ULONG ret_lenght = NULL;
			uint32_t process_id = NULL;
			NTSTATUS nt_status = STATUS_UNSUCCESSFUL;
			PVOID buffer = NULL;
			HANDLE thread_access = NULL;
			PSYSTEM_PROCESS_INFORMATION process_info = NULL;
			thread_info thread_cur;

			nt_status = LI_FN(NtQuerySystemInformation).nt_cached()(SystemProcessInformation, &ret_lenght, ret_lenght, &ret_lenght);

			while (nt_status == STATUS_INFO_LENGTH_MISMATCH)
			{
				if (buffer != NULL)
					VirtualFree(buffer, NULL, MEM_RELEASE);
				buffer = VirtualAlloc(NULL, ret_lenght, MEM_COMMIT, PAGE_READWRITE);
				nt_status = LI_FN(NtQuerySystemInformation).nt_cached()(SystemProcessInformation, buffer, ret_lenght, &ret_lenght);
			}

			if (!NT_SUCCESS(nt_status))
			{
				VirtualFree(buffer, NULL, MEM_RELEASE);
				return NULL;
			}

			process_info = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(buffer);
			while (process_info->NextEntryOffset)
			{
				if ((DWORD)process_info->UniqueProcessId == GetCurrentProcessId())
				{
					for (ULONG id_thread = NULL; id_thread < process_info->NumberOfThreads; id_thread++)
					{
						thread_access = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, (DWORD)process_info->Threads[id_thread].ClientId.UniqueThread);
						if (thread_access)
						{
							thread_cur.ctx_dr.ContextFlags = CONTEXT_DEBUG_REGISTERS;
							if (GetThreadContext(thread_access, &thread_cur.ctx_dr))
							{
								thread_cur.thread_id = process_info->Threads[id_thread].ClientId.UniqueThread;
								init_info::inf_proc.vec_inf.thread_list.push_back(thread_cur);


								memset(&thread_cur.ctx_dr, NULL, sizeof(thread_cur.ctx_dr));

								thread_cur.ctx_dr.Dr0 = reinterpret_cast<DWORD64>(&NtCurrentPeb()->BeingDebugged);

								thread_cur.ctx_dr.Dr7 = 0x1; //Only Dr0 enable
								thread_cur.ctx_dr.Dr7 |= 0x10000; //Dr0 read
								thread_cur.ctx_dr.Dr7 |= 0x20000; //Dr0 byte 1 lenght

								if (p_ctx)
								{
									p_ctx->ContextFlags |= CONTEXT_DEBUG_REGISTERS;

									p_ctx->Dr0 = thread_cur.ctx_dr.Dr0;
									p_ctx->Dr7 = thread_cur.ctx_dr.Dr7;
								}

								thread_cur.ctx_dr.ContextFlags = CONTEXT_DEBUG_REGISTERS;
								if (!SetThreadContext(thread_access, &thread_cur.ctx_dr))
								{
									is_set = FALSE;
								}

							}

						}

					}
				}
				process_info = (PSYSTEM_PROCESS_INFORMATION)((LPBYTE)process_info + process_info->NextEntryOffset); // Calculate the address of the next entry.
			}
			VirtualFree(buffer, NULL, MEM_RELEASE);
			return is_set;
		}
		static   NTSTATUS WINAPI hooked_nt_continue
		(
			PCONTEXT             ThreadContext,
			BOOLEAN              RaiseAlert
		)
		{

			if (ThreadContext && init_info::inf_proc.single_removed == FALSE)
			{
				if (_ReturnAddress() >= init_info::inf_proc.orig_addr.orig_ldr_initialize_thunk &&
					reinterpret_cast<CHAR*>(init_info::inf_proc.orig_addr.orig_ldr_initialize_thunk) + MAX_LDR_INIT_THUNK > _ReturnAddress()
					)
				{
					if (ThreadContext->ContextFlags & CONTEXT_DEBUG_REGISTERS)
					{
						ThreadContext->ContextFlags ^= CONTEXT_DEBUG_REGISTERS;
						init_info::inf_proc.single_removed = TRUE;
					}
				}
			}
			return reinterpret_cast<decltype(&NtContinue)>(init_info::inf_proc.orig_addr.orig_nt_continue)(ThreadContext, RaiseAlert);
		}

		static   NTSTATUS WINAPI hooked_nt_query_proc
		(
			HANDLE ProcessHandle,
			PROCESSINFOCLASS ProcessInformationClass,
			PVOID ProcessInformation,
			ULONG ProcessInformationLength,
			PULONG ReturnLength
		)
		{
			NTSTATUS nt_status = -1;
			ULONG old_ret_lenght = NULL;
			 


			if (
				ProcessHandle == NtCurrentProcess &&
				(ProcessInformationClass == ProcessDebugPort || ProcessInformationClass == ProcessDebugObjectHandle) &&
				ProcessInformationLength == sizeof(HANDLE) &&
				ProcessInformation 
				)
			{
				nt_status = reinterpret_cast<decltype(&NtQueryInformationProcess)>(init_info::inf_proc.orig_addr.orig_nt_query_proc)(ProcessHandle, ProcessDebugPort, ProcessInformation, ProcessInformationLength, ReturnLength);

				if (NT_SUCCESS(nt_status))
				{
					BACKUP_RETURNLENGTH();

					*reinterpret_cast<HANDLE*>(ProcessInformation) = NULL;

					RESTORE_RETURNLENGTH();

					if (ProcessInformationClass == ProcessDebugObjectHandle)
					{
						return STATUS_PORT_NOT_SET;
					}
					else
					{
						return nt_status;
					}

				}
				else
				{
					return nt_status;
				}
			}
			return reinterpret_cast<decltype(&NtQueryInformationProcess)>(init_info::inf_proc.orig_addr.orig_nt_query_proc)(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);

		}

		static   NTSTATUS WINAPI hooked_nt_set_thread
		(
			HANDLE ThreadHandle,
			THREADINFOCLASS ThreadInformationClass,
			PVOID ThreadInformation,
			ULONG ThreadInformationLength
		)
		{

			if (
				ThreadHandle == NtCurrentThread &&
				ThreadInformationClass == ThreadHideFromDebugger &&
				ThreadInformationLength == NULL

				)
			{
				return STATUS_SUCCESS;
			}
			return reinterpret_cast<decltype(&NtSetInformationThread)>(init_info::inf_proc.orig_addr.orig_nt_set_thread)(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);

		}

		 
		//I hope you don't use SoftICE xd
		static   NTSTATUS WINAPI hooked_nt_quey_sys
		(
			SYSTEM_INFORMATION_CLASS SystemInformationClass,
			PVOID					 SystemInformation,
			ULONG					 SystemInformationLength,
			PULONG					 ReturnLength 
		)
		{
			NTSTATUS nt_status = -1;
			ULONG cur_lenght = NULL;   
			 

			if (!ReturnLength) //Get buffer size
			{ 
				nt_status = reinterpret_cast<decltype(&NtQuerySystemInformation)>(init_info::inf_proc.orig_addr.orig_nt_query_sys)(SystemInformationClass, SystemInformation, SystemInformationLength, &cur_lenght);
			}
			else
			{
				nt_status = reinterpret_cast<decltype(&NtQuerySystemInformation)>(init_info::inf_proc.orig_addr.orig_nt_query_sys)(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
			}

			if (NT_SUCCESS(nt_status) && SystemInformation)
			{
				if (SystemInformationClass == SystemKernelDebuggerInformation)
				{
					BACKUP_RETURNLENGTH();

					reinterpret_cast<PSYSTEM_KERNEL_DEBUGGER_INFORMATION>(SystemInformation)->KernelDebuggerEnabled = FALSE;
					reinterpret_cast<PSYSTEM_KERNEL_DEBUGGER_INFORMATION>(SystemInformation)->KernelDebuggerNotPresent = TRUE;

					RESTORE_RETURNLENGTH();

				}
				if (SystemInformationClass == SystemFirmwareTableInformation) //Anti-vm
				{ 
					//We don't change buffer pointer and it's ok
					if (cur_lenght)
					{ 
						remove_bad_string(SystemInformation, cur_lenght);
					} 
					else
					{
						remove_bad_string(SystemInformation, *ReturnLength);
					}
					 
				}
			}
			return nt_status;

		}

		static   NTSTATUS WINAPI hooked_nt_close
		(
			HANDLE handle
		)
		{
			NTSTATUS nt_status = -1;
			OBJECT_HANDLE_FLAG_INFORMATION handle_flag;

			
			nt_status = NtQueryObject(handle, ObjectHandleFlagInformation, &handle_flag, sizeof(handle_flag), NULL);
			if (NT_SUCCESS(nt_status))
			{
				if (handle_flag.ProtectFromClose)
				{
					return STATUS_HANDLE_NOT_CLOSABLE;
				}
				return reinterpret_cast<decltype(&NtClose)>(init_info::inf_proc.orig_addr.orig_nt_close)(handle);
			}
			else
			{
				return STATUS_INVALID_HANDLE;
			}
		}

		NO_INLINE  auto WINAPI create_hook_proc() -> BOOLEAN
		{
			PVOID target_hook = NULL;
			MH_STATUS mh_status;

			if (!init_info::inf_proc.ntdll_base)
			{
				init_info::inf_proc.ntdll_base = GetModuleHandleW(L"ntdll.dll");
			}

			if (!init_info::inf_proc.ntdll_base)
			{
				return FALSE;
			}

			target_hook = GetProcAddress(reinterpret_cast<HMODULE>(init_info::inf_proc.ntdll_base), "NtQueryInformationProcess");

			mh_status = MH_Initialize();
			if (mh_status != MH_OK && mh_status != MH_ERROR_ALREADY_INITIALIZED)
			{
				return FALSE;
			}

			if (
				MH_CreateHook(target_hook, &hooked_nt_query_proc, &init_info::inf_proc.orig_addr.orig_nt_query_proc) != MH_OK
				)
			{
				return FALSE;
			}
			if (MH_EnableHook(target_hook) != MH_OK)
			{
				return FALSE;
			}

			return TRUE;
		}

		NO_INLINE  auto WINAPI create_hook_system_info() -> BOOLEAN
		{
			PVOID target_hook = NULL;
			MH_STATUS mh_status;

			if (!init_info::inf_proc.ntdll_base)
			{
				init_info::inf_proc.ntdll_base = GetModuleHandleW(L"ntdll.dll");
			}

			if (!init_info::inf_proc.ntdll_base)
			{
				return FALSE;
			}

			target_hook = GetProcAddress(reinterpret_cast<HMODULE>(init_info::inf_proc.ntdll_base), "NtQuerySystemInformation");

			mh_status = MH_Initialize();
			if (mh_status != MH_OK && mh_status != MH_ERROR_ALREADY_INITIALIZED)
			{
				return FALSE;
			}

			if (
				MH_CreateHook(target_hook, &hooked_nt_quey_sys, &init_info::inf_proc.orig_addr.orig_nt_query_sys) != MH_OK
				)
			{
				return FALSE;
			}
			if (MH_EnableHook(target_hook) != MH_OK)
			{
				return FALSE;
			}

			return TRUE;
		}



		NO_INLINE  auto WINAPI create_hook_thread() -> BOOLEAN
		{
			PVOID target_hook = NULL;
			MH_STATUS mh_status;

			if (!init_info::inf_proc.ntdll_base)
			{
				init_info::inf_proc.ntdll_base = GetModuleHandleW(L"ntdll.dll");
			}

			if (!init_info::inf_proc.ntdll_base)
			{
				return FALSE;
			}

			target_hook = GetProcAddress(reinterpret_cast<HMODULE>(init_info::inf_proc.ntdll_base), "NtSetInformationThread");

			mh_status = MH_Initialize();
			if (mh_status != MH_OK && mh_status != MH_ERROR_ALREADY_INITIALIZED)
			{
				return FALSE;
			}

			if (
				MH_CreateHook(target_hook, &hooked_nt_set_thread, &init_info::inf_proc.orig_addr.orig_nt_set_thread) != MH_OK
				)
			{
				return FALSE;
			}
			if (MH_EnableHook(target_hook) != MH_OK)
			{
				return FALSE;
			}

			return TRUE;
		}

		NO_INLINE  auto WINAPI create_hook_nt_close() -> BOOLEAN
		{
			PVOID target_hook = NULL;
			MH_STATUS mh_status;

			if (!init_info::inf_proc.ntdll_base)
			{
				init_info::inf_proc.ntdll_base = GetModuleHandleW(L"ntdll.dll");
			}

			if (!init_info::inf_proc.ntdll_base)
			{
				return FALSE;
			}

			target_hook = GetProcAddress(reinterpret_cast<HMODULE>(init_info::inf_proc.ntdll_base), "NtClose");

			mh_status = MH_Initialize();
			if (mh_status != MH_OK && mh_status != MH_ERROR_ALREADY_INITIALIZED)
			{
				return FALSE;
			}

			if (
				MH_CreateHook(target_hook, &hooked_nt_close, &init_info::inf_proc.orig_addr.orig_nt_close) != MH_OK
				)
			{
				return FALSE;
			}
			if (MH_EnableHook(target_hook) != MH_OK)
			{
				return FALSE;
			}

			return TRUE;
		}


		//Presen't remove HWBP by LdrInitializeThunk
		NO_INLINE  auto WINAPI create_hook_nt_contin() -> BOOLEAN
		{
			PVOID target_hook = NULL;
			MH_STATUS mh_status;

			if (!init_info::inf_proc.ntdll_base)
			{
				init_info::inf_proc.ntdll_base = GetModuleHandleW(L"ntdll.dll");
			}

			if (!init_info::inf_proc.ntdll_base)
			{
				return FALSE;
			}

			target_hook = GetProcAddress(reinterpret_cast<HMODULE>(init_info::inf_proc.ntdll_base), "NtContinue");
			init_info::inf_proc.orig_addr.orig_ldr_initialize_thunk = GetProcAddress(reinterpret_cast<HMODULE>(init_info::inf_proc.ntdll_base), "LdrInitializeThunk");

			mh_status = MH_Initialize();
			if (mh_status != MH_OK && mh_status != MH_ERROR_ALREADY_INITIALIZED)
			{
				return FALSE;
			}

			if (
				MH_CreateHook(target_hook, &hooked_nt_continue, &init_info::inf_proc.orig_addr.orig_nt_continue) != MH_OK
				)
			{
				return FALSE;
			}
			if (MH_EnableHook(target_hook) != MH_OK)
			{
				return FALSE;
			}

			return TRUE;
		}
	};
}
#endif // !ANTI_DEBUG
