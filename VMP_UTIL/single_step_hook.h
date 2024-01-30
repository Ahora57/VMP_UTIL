#ifndef SINGLE_STEP_HOOK
#define SINGLE_STEP_HOOK 1 

#include  "init_address.h" 
#include "nt_api_def.h"
#include "minhook.h"

#define STATUS_BAD_PAGE 0 
#define STATUS_CURRENT_PAGE 1 
#define STATUS_OTHER_PAGE 2 

#define OPCODE_NOP 0x90
#define OPCODE_INT3 0xCC
#define LEN_OPCODE_INT3 0x1

#define TRAP_FLAG 0x100
#define MAX_SCAN_OFFSET 0x5500

#define BYTE_PTR 0x8
#define WORD_PTR 0x10

namespace single_step
{
	class single_step_hook
	{
	private:

		//Check for movzx...
		NO_INLINE static  auto WINAPI  get_size_reg(uint8_t size_elem) -> uint8_t
		{
			if (size_elem == BYTE_PTR)
			{
				return sizeof(uint8_t);
			}
			else if (size_elem == WORD_PTR)
			{
				return sizeof(uint8_t);
			}
			/*
				if (reg >= ZYDIS_REGISTER_RAX && ZYDIS_REGISTER_R15 >= reg)
				{
					*len = sizeof(PVOID);
				}
				else if (reg >= ZYDIS_REGISTER_EAX && ZYDIS_REGISTER_R15D >= reg)
				{
					*len = sizeof(uint32_t);
				}
				if (reg >= ZYDIS_REGISTER_AX && ZYDIS_REGISTER_R15W >= reg)
				{
					*len = sizeof(uint16_t);
				}
				if (reg >= ZYDIS_REGISTER_AL && ZYDIS_REGISTER_R15B >= reg)
				{
					*len = sizeof(uint8_t);
				}
			*/
			return NULL;
		}


		NO_INLINE static  auto WINAPI get_reg(PEXCEPTION_POINTERS exception_info, ZydisRegister reg, PVOID* addr_reg = NULL) -> CHAR*
		{
			PVOID addr_reg_copy = NULL;


			if (!addr_reg)
			{
				addr_reg = &addr_reg_copy;
			}

			/*
				Its code is fiasco(use offset, meh)
			*/
			switch (reg)
			{
			case ZYDIS_REGISTER_RAX:
			case ZYDIS_REGISTER_EAX:
			{
				*addr_reg = &exception_info->ContextRecord->Rax;
				return reinterpret_cast<CHAR*>(exception_info->ContextRecord->Rax);
			}
			case ZYDIS_REGISTER_RBX:
			case ZYDIS_REGISTER_EBX:
			{
				*addr_reg = &exception_info->ContextRecord->Rbx;
				return reinterpret_cast<CHAR*>(exception_info->ContextRecord->Rbx);
			}
			case ZYDIS_REGISTER_RCX:
			case ZYDIS_REGISTER_ECX:
			{
				*addr_reg = &exception_info->ContextRecord->Rcx;
				return reinterpret_cast<CHAR*>(exception_info->ContextRecord->Rcx);
			}
			case ZYDIS_REGISTER_RDX:
			case ZYDIS_REGISTER_EDX:
			{				
				*addr_reg = &exception_info->ContextRecord->Rdx;
				return reinterpret_cast<CHAR*>(exception_info->ContextRecord->Rdx);
			}
			case ZYDIS_REGISTER_RBP:
			case ZYDIS_REGISTER_EBP:
			{
				*addr_reg = &exception_info->ContextRecord->Rbp;
				return reinterpret_cast<CHAR*>(exception_info->ContextRecord->Rbp);
			}
			case ZYDIS_REGISTER_RSI:
			case ZYDIS_REGISTER_ESI:
			{
				*addr_reg = &exception_info->ContextRecord->Rsi;
				return reinterpret_cast<CHAR*>(exception_info->ContextRecord->Rsi);
			}
			case ZYDIS_REGISTER_RDI:
			case ZYDIS_REGISTER_EDI:
			{
				*addr_reg = &exception_info->ContextRecord->Rdi;
				return reinterpret_cast<CHAR*>(exception_info->ContextRecord->Rdi);
			}
			case ZYDIS_REGISTER_R8:
			case ZYDIS_REGISTER_R8D:
			{
				*addr_reg = &exception_info->ContextRecord->R8;
				return reinterpret_cast<CHAR*>(exception_info->ContextRecord->R8);
			}
			case ZYDIS_REGISTER_R9:
			case ZYDIS_REGISTER_R9D:
			{
				*addr_reg = &exception_info->ContextRecord->R9;
				return reinterpret_cast<CHAR*>(exception_info->ContextRecord->R9);
			}
			case ZYDIS_REGISTER_R10:
			case ZYDIS_REGISTER_R10D:
			{
				*addr_reg = &exception_info->ContextRecord->R10;
				return reinterpret_cast<CHAR*>(exception_info->ContextRecord->R10);
			}
			case ZYDIS_REGISTER_R11:
			case ZYDIS_REGISTER_R11D: 
			{
				*addr_reg = &exception_info->ContextRecord->R11;
				return reinterpret_cast<CHAR*>(exception_info->ContextRecord->R11);
			}
			case ZYDIS_REGISTER_R12:
			case ZYDIS_REGISTER_R12D: 
			{
				*addr_reg = &exception_info->ContextRecord->R12;
				return reinterpret_cast<CHAR*>(exception_info->ContextRecord->R12);
			}
			case ZYDIS_REGISTER_R13:
			case ZYDIS_REGISTER_R13D:
			{
				*addr_reg = &exception_info->ContextRecord->R13;
				return reinterpret_cast<CHAR*>(exception_info->ContextRecord->R13);
			}
			case ZYDIS_REGISTER_R14:
			case ZYDIS_REGISTER_R14D:
			{
				*addr_reg = &exception_info->ContextRecord->R14;
				return reinterpret_cast<CHAR*>(exception_info->ContextRecord->R14);
			}
			case ZYDIS_REGISTER_R15:
			case ZYDIS_REGISTER_R15D:
			{
				*addr_reg = &exception_info->ContextRecord->R15;
				return reinterpret_cast<CHAR*>(exception_info->ContextRecord->R15);
			}

			default:
				break;
			}
			return NULL;
		}

		static  auto WINAPI is_exepthion_vmp(PEXCEPTION_POINTERS exception_info) -> BOOLEAN
		{
			CHAR* inst_addr = NULL;
			ZydisDisassembledInstruction info_instr;

			if (*reinterpret_cast<uint8_t*>(exception_info->ExceptionRecord->ExceptionAddress) == OPCODE_NOP)
			{
				inst_addr = reinterpret_cast<CHAR*>(reinterpret_cast<ULONGLONG>(exception_info->ExceptionRecord->ExceptionAddress) - sizeof(uint16_t));

				if (ZYAN_SUCCESS(dis::get_dis(&info_instr, inst_addr)))
				{
					return info_instr.info.mnemonic == ZYDIS_MNEMONIC_CPUID || info_instr.info.mnemonic == ZYDIS_MNEMONIC_RDTSC;
				}
			}
			return FALSE;
		}

		NO_INLINE static  auto WINAPI is_hook_ins_false(PVOID address) -> BOOLEAN
		{
			for (size_t i = NULL; i < init_info::inf_proc.vec_inf.hook_ret_false.size(); i++)
			{
				if (address == init_info::inf_proc.vec_inf.hook_ret_false[i].address_hook)
				{
					return TRUE;
				}
			}
			return FALSE;
		}



		 
		NO_INLINE static  auto WINAPI is_hook_ins_true(PVOID address) -> BOOLEAN
		{
			for (size_t i = NULL; i < init_info::inf_proc.vec_inf.hook_ret_true.size(); i++)
			{
				if (address == init_info::inf_proc.vec_inf.hook_ret_true[i].address_hook)
				{
					return TRUE;
				}
			}
			return FALSE;
		}

		/*
		NO_INLINE static  auto WINAPI is_hook_read_crc_calc(PVOID address) -> BOOLEAN
		{
			for (size_t i = NULL; i < init_info::inf_proc.patch_crc_calc.size(); i++)
			{
				if (address == init_info::inf_proc.patch_crc_calc[i].hook_mov.address_hook)
				{
					return TRUE;
				}
			}
			return FALSE;
		}

		NO_INLINE static  auto WINAPI is_hook_end_crc_calc(PVOID address) -> BOOLEAN
		{
			for (size_t i = NULL; i < init_info::inf_proc.patch_crc_calc.size(); i++)
			{
				if (address == init_info::inf_proc.patch_crc_calc[i].hook_not.address_hook)
				{
					return TRUE;
				}
			}
			return FALSE;
		}
		*/
		NO_INLINE static  auto WINAPI fix_read_copy(PEXCEPTION_POINTERS exception_info, PHOOK_CRC_INFO crc_calc) -> VOID
		{
			CHAR* base = NULL; 

			CHAR* index = NULL; 
			PVOID reg_write = NULL;
			PVOID reg_write_addr = NULL;  

 
			base = get_reg(exception_info, crc_calc->reg_read.base);
			 
			if (crc_calc->reg_read.index != ZYDIS_REGISTER_NONE)
			{
				index = get_reg(exception_info, crc_calc->reg_read.index);
				if (crc_calc->reg_read.scale)
				{
					index = reinterpret_cast<CHAR*>(reinterpret_cast<ULONGLONG>(index) * crc_calc->reg_read.scale);
				} 
				base = reinterpret_cast<CHAR*>(reinterpret_cast<ULONGLONG>(base) + index);
			}
			if (crc_calc->reg_read.disp.has_displacement)
			{ 
				base += crc_calc->reg_read.disp.value;
			}
 
 			//Is CRC current module(not file and other...)?
			if (
				static_cast<CHAR*>(init_info::inf_proc.target_base) <= base &&
				static_cast<CHAR*>(init_info::inf_proc.target_base) + init_info::inf_proc.size_mod > base
				)
			{ 
				base = base - reinterpret_cast<CHAR*>(init_info::inf_proc.target_base) + reinterpret_cast<CHAR*>(init_info::inf_proc.coped_targer_base);
				
				 
				reg_write = get_reg(exception_info, crc_calc->reg_write, &reg_write_addr);

				if (crc_calc->size_elem == WORD_PTR)
				{
					*reinterpret_cast<PULONG>(reg_write_addr) = *reinterpret_cast<uint16_t*>(base);
				}
				else
				{
					*reinterpret_cast<PULONG>(reg_write_addr) = *reinterpret_cast<uint8_t*>(base);
				}  
			} 
			else
			{
				if (crc_calc->size_elem == WORD_PTR)
				{
					*reinterpret_cast<PULONG>(reg_write_addr) = *reinterpret_cast<uint16_t*>(base);
				}
				else
				{
					*reinterpret_cast<PULONG>(reg_write_addr) = *reinterpret_cast<uint8_t*>(base);
				}
			}
		}

		NO_INLINE static  auto WINAPI is_hook_crc_calc(PEXCEPTION_POINTERS exception_info) -> BOOLEAN
		{
			for (size_t i = NULL; i < init_info::inf_proc.vec_inf.patch_crc_calc.size(); i++)
			{
				if (exception_info->ExceptionRecord->ExceptionAddress == init_info::inf_proc.vec_inf.patch_crc_calc[i].addr)
				{ 
 					fix_read_copy(exception_info, &init_info::inf_proc.vec_inf.patch_crc_calc[i]);
					return TRUE;
				}
			}
			return FALSE;
		}

		NO_INLINE static  auto WINAPI get_current_except_false(PEXCEPTION_POINTERS exception_info) -> PHOOK_INFO
		{
			for (size_t i = NULL; i < init_info::inf_proc.vec_inf.hook_ret_false.size(); i++)
			{
				if (exception_info->ExceptionRecord->ExceptionAddress == init_info::inf_proc.vec_inf.hook_ret_false[i].address_hook)
				{
					return &init_info::inf_proc.vec_inf.hook_ret_false[i];
				}
			}
			return NULL;
		}

		NO_INLINE static  auto WINAPI get_current_except_true(PEXCEPTION_POINTERS exception_info) -> PHOOK_INFO
		{
			for (size_t i = NULL; i < init_info::inf_proc.vec_inf.hook_ret_true.size(); i++)
			{
				if (exception_info->ExceptionRecord->ExceptionAddress == init_info::inf_proc.vec_inf.hook_ret_true[i].address_hook)
				{
					return &init_info::inf_proc.vec_inf.hook_ret_true[i];
				}
			}
			return NULL;
		}


		 



		NO_INLINE static auto WINAPI inside_sec(PVOID alloce_base, PVOID addr_1, PVOID addr_2) -> BOOLEAN
		{
			bool is_crc_good = TRUE;
			uint8_t orig_byte = NULL;
			uint32_t size_sec = NULL;
			PIMAGE_NT_HEADERS  headers = NULL;
			PIMAGE_SECTION_HEADER sections = NULL;

			if (static_cast<PIMAGE_DOS_HEADER>(alloce_base)->e_lfanew != IMAGE_DOS_SIGNATURE)
				FALSE;
			headers = reinterpret_cast<PIMAGE_NT_HEADERS>(static_cast<CHAR*>(alloce_base) + static_cast<PIMAGE_DOS_HEADER>(alloce_base)->e_lfanew);
			if (headers->Signature != IMAGE_NT_SIGNATURE)
			{
				return FALSE;
			}
			sections = IMAGE_FIRST_SECTION(headers);

			for (size_t i = NULL; i < headers->FileHeader.NumberOfSections; i++)
			{
				if ((sections[i].Characteristics & IMAGE_SCN_MEM_READ) && (sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE))
				{
					if (
						(addr_1 >= static_cast<CHAR*>(alloce_base) + sections[i].VirtualAddress &&
							addr_1 < static_cast<CHAR*>(alloce_base) + sections[i].VirtualAddress + sections[i].Misc.VirtualSize) &&
						(addr_2 >= static_cast<CHAR*>(alloce_base) + sections[i].VirtualAddress &&
							addr_2 < static_cast<CHAR*>(alloce_base) + sections[i].VirtualAddress + sections[i].Misc.VirtualSize)
						)
					{
						return TRUE;
					}

				}
			}
			return FALSE;
		}

		static auto WINAPI copy_instr(ZydisDisassembledInstruction* info_instr, BOOLEAN is_false = TRUE) -> PVOID
		{
			BOOLEAN is_fix = FALSE;
			JitRuntime rt;
			CodeHolder code;
			PVOID cg_intstr_address = NULL;
			PVOID alloce_mem = NULL;

			alloce_mem = VirtualAlloc(NULL, PAGE_SIZE, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			if (!alloce_mem)
				return NULL;

			code.init(rt.environment(), rt.cpuFeatures());

			x86::Assembler ass(&code);


			for (uint8_t i = NULL; i < info_instr->info.operand_count_visible; i++)
			{
				if ((info_instr->operands[i].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && info_instr->operands[i].imm.is_relative == ZYAN_TRUE) || info_instr->operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY)
				{
					is_fix = TRUE;
				}
			}
			if (is_fix)
			{
				if (info_instr->info.mnemonic == ZYDIS_MNEMONIC_CALL)
				{
					//emul push stack by call and jmp 
					ass.sub(x86::rsp, sizeof(PVOID));
					ass.push(x86::rax);
					ass.mov(x86::rax, reinterpret_cast<CHAR*>(info_instr->runtime_address) + info_instr->info.length);
					ass.mov(x86::qword_ptr(x86::rsp, sizeof(PVOID)), x86::rax);
					ass.pop(x86::rax);

					if (is_false)
					{
						ass.mov(x86::al, FALSE);
					} 

					ass.jmp(dis::get_absolute_address(info_instr, info_instr->runtime_address));
				}
				else if (info_instr->info.mnemonic == ZYDIS_MNEMONIC_JMP)
				{
					if (is_false)
					{
						ass.mov(x86::al, FALSE);
					} 
					ass.jmp(dis::get_absolute_address(info_instr, info_instr->runtime_address));
				}
				if (rt.add(&cg_intstr_address, &code))//cg_alloce - alloceted code
				{
					if (alloce_mem)
						VirtualFree(alloce_mem, NULL, MEM_RELEASE);
					return NULL;
				}

				memcpy(reinterpret_cast<CHAR*>(alloce_mem), cg_intstr_address, code.codeSize());

			}
			else
			{
				memcpy(reinterpret_cast<CHAR*>(alloce_mem), reinterpret_cast<CHAR*>(info_instr->runtime_address), info_instr->info.length);
				
				if (is_false)
				{
					ass.mov(x86::al, FALSE);
				}

				ass.jmp(reinterpret_cast<CHAR*>(info_instr->runtime_address) + info_instr->info.length);
				if (rt.add(&cg_intstr_address, &code))//cg_alloce - alloceted code
				{
					if (alloce_mem)
						VirtualFree(alloce_mem, NULL, MEM_RELEASE);
					return NULL;
				}

				memcpy(reinterpret_cast<CHAR*>(alloce_mem) + info_instr->info.length, cg_intstr_address, code.codeSize());

			}

			code.~CodeHolder();
			ass.~Assembler();

			if (alloce_mem)
			{
				VirtualProtect(alloce_mem, PAGE_SIZE, PAGE_EXECUTE_READ, NULL);
			}
			return alloce_mem;
		}



		NO_INLINE static  auto WINAPI is_correct_mem(PVOID mem, MEMORY_BASIC_INFORMATION* mbi_cur) -> BOOLEAN
		{
			MEMORY_BASIC_INFORMATION mbi = { NULL };
			if (VirtualQuery(mem, &mbi, sizeof(mbi)))
			{
				if (
					mbi_cur->AllocationBase != mbi.AllocationBase ||
					(mbi.Type & MEM_IMAGE) == FALSE ||
					((mbi.Protect & PAGE_EXECUTE_READWRITE) ||
						(mbi.Protect & PAGE_EXECUTE_READ)) == FALSE
					)
				{
					return STATUS_BAD_PAGE;
				} 

				//stuped check for fix bug in mbi.BaseAddress
				if (
					(
						reinterpret_cast<CHAR*>(mbi.BaseAddress) + mbi.RegionSize == reinterpret_cast<CHAR*>(mbi_cur->BaseAddress) + mbi_cur->RegionSize ||
						inside_sec(mbi.AllocationBase, mbi.BaseAddress, mbi_cur->BaseAddress)
						) &&
					((mbi.Protect & PAGE_EXECUTE_READWRITE) ||
						(mbi.Protect & PAGE_EXECUTE_READ)))
				{
					return STATUS_CURRENT_PAGE;
				}
				else
				{
					return STATUS_OTHER_PAGE;
				}
			}
			return STATUS_BAD_PAGE;
		}

		NO_INLINE static  auto WINAPI is_read_pointer(PVOID pointer) -> BOOLEAN
		{
			MEMORY_BASIC_INFORMATION mbi = { NULL };
			if (VirtualQuery(pointer, &mbi, sizeof(mbi)))
			{
				return
					(mbi.Protect & PAGE_EXECUTE_READWRITE) ||
					(mbi.Protect & PAGE_EXECUTE_READ) ||
					(mbi.Protect & PAGE_READONLY);
			}
			return FALSE;
		}

		NO_INLINE static  auto WINAPI is_execute_pointer(PVOID pointer) -> BOOLEAN
		{
			MEMORY_BASIC_INFORMATION mbi = { NULL };
			if (VirtualQuery(pointer, &mbi, sizeof(mbi)))
			{
				return
					(mbi.Protect & PAGE_EXECUTE_READWRITE) ||
					(mbi.Protect & PAGE_EXECUTE_READ);
			}
			return FALSE;
		}

		NO_INLINE static  auto WINAPI scan_stack(PEXCEPTION_POINTERS exception_info) -> PVOID
		{
			uint8_t page_status = NULL;
			uint32_t max_scan = NULL;
			ULONGLONG rsp_addr = NULL;
			PULONGLONG pointer_stack = NULL;
			MEMORY_BASIC_INFORMATION mbi = { NULL };
			MEMORY_BASIC_INFORMATION mbi_excp = { NULL };

			ZydisDisassembledInstruction dis_instr = { NULL };

#ifndef _WIN64
			rsp_addr = exception_info->ContextRecord->Esp;

#else
			rsp_addr = exception_info->ContextRecord->Rsp;

#endif // !_WIN64


			if (VirtualQuery(reinterpret_cast<CHAR*>(rsp_addr), &mbi, sizeof(mbi)) && VirtualQuery(exception_info->ExceptionRecord->ExceptionAddress, &mbi_excp, sizeof(mbi_excp)))
			{
				max_scan = mbi.RegionSize - (reinterpret_cast<CHAR*>(rsp_addr) - mbi.BaseAddress);
				for (uint32_t i = NULL; i < PAGE_SIZE && max_scan > i; i += sizeof(PVOID))
				{
					pointer_stack = *reinterpret_cast<PULONGLONG*>(reinterpret_cast<CHAR*>(rsp_addr) + i);
					if (reinterpret_cast<ULONGLONG>(pointer_stack) > PAGE_SIZE && is_execute_pointer(pointer_stack))
					{
						//Present scan and set bad hook
						if (is_hook_ins_false(pointer_stack))
						{
							return FALSE;
						}

						page_status = is_correct_mem(pointer_stack, &mbi_excp);
						if (page_status == STATUS_OTHER_PAGE)
						{
							return reinterpret_cast<PVOID>(pointer_stack);
						}
						else if (page_status == STATUS_CURRENT_PAGE)
						{
							if (ZYAN_SUCCESS(dis::get_dis(&dis_instr, reinterpret_cast<CHAR*>(pointer_stack))))
							{
								if (dis_instr.info.mnemonic == ZYDIS_MNEMONIC_PUSH ||
#ifndef _WIN64
									dis_instr.info.mnemonic == ZYDIS_MNEMONIC_PUSHFD ||
#else
									dis_instr.info.mnemonic == ZYDIS_MNEMONIC_PUSHFQ ||
#endif // !_WIN64
									dis_instr.info.mnemonic == ZYDIS_MNEMONIC_CALL ||
									dis_instr.info.mnemonic == ZYDIS_MNEMONIC_JMP
									)
								{
									return reinterpret_cast<PVOID>(pointer_stack);
								}
							}

						}
					}

				}
			}
			return NULL;
		}

		static NO_INLINE auto WINAPI set_bp_hook(PVOID addr) -> VOID
		{

			DWORD old_prot = NULL;
			HANDLE access = NULL;
			ZydisDisassembledInstruction dis_instr = { NULL };

			if (ZYAN_SUCCESS(dis::get_dis(&dis_instr, reinterpret_cast<CHAR*>(addr))))
			{
				access = OpenProcess(PROCESS_VM_OPERATION, FALSE, (DWORD)NtCurrentProcessId());
				if (access && VirtualProtectEx(access, addr, PAGE_SIZE, PAGE_EXECUTE_READWRITE, &old_prot))
				{
					memset(addr, OPCODE_NOP, dis_instr.info.length);
					*reinterpret_cast<CHAR*>(addr) = OPCODE_INT3;

					VirtualProtectEx(access, addr, PAGE_SIZE, old_prot, &old_prot);
					CloseHandle(access);

				}
			}
		}

		static   auto WINAPI copy_byte_mem(PVOID addr, uint8_t* copy_byte, uint32_t lenght) -> VOID
		{

			DWORD old_prot = NULL;
			HANDLE access = NULL; 
			 
			access = OpenProcess(PROCESS_VM_OPERATION, FALSE, (DWORD)NtCurrentProcessId());
			if (access && VirtualProtectEx(access, addr, PAGE_SIZE, PAGE_EXECUTE_READWRITE, &old_prot))
			{
				memcpy(addr, copy_byte, lenght);

				VirtualProtectEx(access, addr, PAGE_SIZE, old_prot, &old_prot);
				CloseHandle(access);
			}
		}
		static auto   NO_INLINE WINAPI remove_syscall_id(PEXCEPTION_POINTERS exception_info, BOOLEAN is_neg, BOOLEAN is_anti_debug = FALSE) -> BOOLEAN
		{
			BOOLEAN is_find = FALSE;
			uint32_t max_scan = NULL;
			ULONGLONG rsp_addr = NULL;
			ULONG point_mem = NULL;
			PULONGLONG pointer_stack = NULL;
			MEMORY_BASIC_INFORMATION mbi = { NULL };

 
#ifndef _WIN64
			rsp_addr = exception_info->ContextRecord->Esp;

#else
			rsp_addr = exception_info->ContextRecord->Rsp;

#endif // !_WIN64


			if (VirtualQuery(reinterpret_cast<CHAR*>(rsp_addr), &mbi, sizeof(mbi)))
			{
				max_scan = mbi.RegionSize - (reinterpret_cast<CHAR*>(rsp_addr) - mbi.BaseAddress) - sizeof(PVOID);
 				for (uint32_t i = NULL;   max_scan > i; i += sizeof(ULONG))
				{

					point_mem = *reinterpret_cast<PULONG>(rsp_addr + i);
					if (init_info::is_syscall(point_mem, is_anti_debug))
					{ 
						*reinterpret_cast<PULONG>(rsp_addr + i) = NULL;
						is_find = TRUE;
					}
				}

			}   

			if (is_neg)
			{ 
				max_scan = MAX_SCAN_OFFSET;
				for (uint32_t i = NULL; max_scan > i; i += sizeof(ULONG))
				{
					if (!IsBadReadPtr(reinterpret_cast<CHAR*>(reinterpret_cast<CHAR*>(rsp_addr) - i), sizeof(PVOID)))
					{
						point_mem = *reinterpret_cast<uint32_t*>(reinterpret_cast<CHAR*>(rsp_addr) - i);
						if (init_info::is_syscall(point_mem, is_anti_debug))
						{
							*reinterpret_cast<PULONG>(rsp_addr - i) = NULL;
							is_find = TRUE;
						}
					}
					else
					{
						return is_find;
					}
				}
				
			}
			return is_find;
		}

		NO_INLINE static BOOLEAN WINAPI rem_beg_deb_hwbp(PCONTEXT p_ctx, BOOLEAN full)
		{
			BOOLEAN is_preset = TRUE;
			NTSTATUS nt_status = -1;
			HANDLE thread_access = NULL;
			CONTEXT ctx = { NULL };
			THREAD_BASIC_INFORMATION tbi = { NULL };


			if (init_info::inf_proc.vec_inf.thread_list.size()  == NULL)
			{
				return TRUE;
			}
			nt_status = LI_FN(NtQueryInformationThread).nt_cached()(NtCurrentThread, ThreadBasicInformation, &tbi, sizeof(THREAD_BASIC_INFORMATION), NULL);

			if (!NT_SUCCESS(nt_status))
			{
				return FALSE;
			}

			for (size_t i = NULL; i < init_info::inf_proc.vec_inf.thread_list.size(); i++)
			{
				if (tbi.ClientId.UniqueThread == init_info::inf_proc.vec_inf.thread_list[i].thread_id)
				{
					if (full)
					{
						thread_access = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, (DWORD)init_info::inf_proc.vec_inf.thread_list[i].thread_id);
						if (thread_access)
						{

							 

							//Safe remove by RtlRestoreContext and copy
							p_ctx->Dr0 = init_info::inf_proc.vec_inf.thread_list[i].ctx_dr.Dr0;
							p_ctx->Dr1 = init_info::inf_proc.vec_inf.thread_list[i].ctx_dr.Dr1;
							p_ctx->Dr2 = init_info::inf_proc.vec_inf.thread_list[i].ctx_dr.Dr2;
							p_ctx->Dr3 = init_info::inf_proc.vec_inf.thread_list[i].ctx_dr.Dr3;
							p_ctx->Dr7 = init_info::inf_proc.vec_inf.thread_list[i].ctx_dr.Dr7;

							//Safe remove by SetThreadContext
							ctx.Dr0 = init_info::inf_proc.vec_inf.thread_list[i].ctx_dr.Dr0;
							ctx.Dr1 = init_info::inf_proc.vec_inf.thread_list[i].ctx_dr.Dr1;
							ctx.Dr2 = init_info::inf_proc.vec_inf.thread_list[i].ctx_dr.Dr2;
							ctx.Dr3 = init_info::inf_proc.vec_inf.thread_list[i].ctx_dr.Dr3;
							ctx.Dr7 = init_info::inf_proc.vec_inf.thread_list[i].ctx_dr.Dr7;

							ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
							if (!SetThreadContext(thread_access, &ctx))
							{
								is_preset = FALSE;
							}
						}

					}
					else
					{
						p_ctx->Dr0 = init_info::inf_proc.vec_inf.thread_list[i].ctx_dr.Dr0;
						p_ctx->Dr1 = init_info::inf_proc.vec_inf.thread_list[i].ctx_dr.Dr1;
						p_ctx->Dr2 = init_info::inf_proc.vec_inf.thread_list[i].ctx_dr.Dr2;
						p_ctx->Dr3 = init_info::inf_proc.vec_inf.thread_list[i].ctx_dr.Dr3;
						p_ctx->Dr7 = init_info::inf_proc.vec_inf.thread_list[i].ctx_dr.Dr7;
					}
				}
			}
			return is_preset;
		}

	public:


		 

		static auto WINAPI veh_hook(PEXCEPTION_POINTERS exception_info) -> LONG
		{
			BOOLEAN is_setup = TRUE;

			uint32_t len_write = NULL;
			uint32_t len_read_1 = NULL;
			uint32_t len_read_2 = NULL; 



			uint32_t ret_execute = EXCEPTION_CONTINUE_SEARCH;
			PVOID scan_hook_do = NULL;
			ZydisDisassembledInstruction info_instr;
			HOOK_INFO hook_inf = { NULL };

			if (exception_info->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP)
			{
				if (
					exception_info->ContextRecord->Dr0 == reinterpret_cast<DWORD64>(&NtCurrentPeb()->BeingDebugged) &&
					(exception_info->ContextRecord->Dr6 & 1)
					)
				{
					//Remove syscall_id for Present syscall manual only anti-debug
					remove_syscall_id(exception_info, TRUE, TRUE);
					if (exception_info->ContextRecord->EFlags & TRAP_FLAG)
					{
						exception_info->ContextRecord->EFlags ^= TRAP_FLAG;
					}
					ret_execute = EXCEPTION_CONTINUE_EXECUTION;
#ifndef _WIN64
					rem_beg_deb_hwbp(exception_info->ContextRecord, TRUE);

#else
					rem_beg_deb_hwbp(exception_info->ContextRecord, TRUE); 
#endif // !_WIN64

 
				}
				else if (is_exepthion_vmp(exception_info))
				{
					//Bypass check dr for VMP
					if (exception_info->ContextRecord->ContextFlags & CONTEXT_DEBUG_REGISTERS)
					{
						exception_info->ContextRecord->ContextFlags ^= CONTEXT_DEBUG_REGISTERS;
					}					
					remove_syscall_id(exception_info,FALSE);
					//exception_info->ContextRecord->Dr0 = NULL;

					//Remove syscall_id for Present syscall manual
					//remove_syscall_id(exception_info);
					//rem_beg_deb_hwbp(exception_info->ContextRecord, FALSE);
				}

				/*
#ifdef _WIN64


					//rdtsc/cpud and nop
					if (is_exepthion_vmp(exception_info))
					{
						scan_hook_do = scan_stack(exception_info);

						if (scan_hook_do)
						{
							if (is_hook_ins_false(scan_hook_do))
							{
								is_setup = FALSE;
							}

						}


						if (scan_hook_do && is_setup)
						{

							dis::get_dis(&info_instr, reinterpret_cast<CHAR*>(scan_hook_do));

							if (info_instr.info.mnemonic == ZYDIS_MNEMONIC_NOP)
							{
								scan_hook_do = reinterpret_cast<CHAR*>(scan_hook_do) + info_instr.info.length;

								//Update info
								dis::get_dis(&info_instr, reinterpret_cast<CHAR*>(scan_hook_do));
							}

							hook_inf.address_hook = scan_hook_do;

							memcpy(&hook_inf.info_instr, &info_instr, sizeof(info_instr));

							hook_inf.rip_fixer = copy_instr(&info_instr);

							set_bp_hook(scan_hook_do); //only in end set hook!
							init_info::inf_proc.hook_ret_false.push_back(hook_inf);
#ifndef _WIN64
							exception_info->ContextRecord->Eip += 1;
#else
							exception_info->ContextRecord->Rip += 1;
#endif // !_WIN64
						}

					}

#endif // _WIN64
					*/

			}
			else if (exception_info->ExceptionRecord->ExceptionCode == STATUS_BREAKPOINT)
			{
				if (is_hook_ins_false(exception_info->ExceptionRecord->ExceptionAddress))
				{
#ifndef _WIN64
					exception_info->ContextRecord->Eip = reinterpret_cast<DWORD>(get_current_except_false(exception_info)->rip_fixer);
#else
					exception_info->ContextRecord->Rip = reinterpret_cast<DWORD64>(get_current_except_false(exception_info)->rip_fixer);
#endif // !_WIN64

					ret_execute = EXCEPTION_CONTINUE_EXECUTION;
					return ret_execute;
				}
				if (is_hook_ins_true(exception_info->ExceptionRecord->ExceptionAddress))
				{
#ifndef _WIN64
					exception_info->ContextRecord->Eip = reinterpret_cast<DWORD>(get_current_except_true(exception_info)->rip_fixer);

#else
					exception_info->ContextRecord->Rip = reinterpret_cast<DWORD64>(get_current_except_true(exception_info)->rip_fixer);
#endif // !_WIN64

					ret_execute = EXCEPTION_CONTINUE_EXECUTION;
					return ret_execute;
				}

				if (is_hook_crc_calc(exception_info))
				{  

					exception_info->ContextRecord->Rip += LEN_OPCODE_INT3;//len = 0x1(0xCC)
 					ret_execute = EXCEPTION_CONTINUE_EXECUTION;
					return ret_execute;
				}
				 
			}

			return ret_execute;
		}

		NO_INLINE auto WINAPI rva_hook(uint32_t rva) -> BOOLEAN
		{
			CHAR* address_hook = NULL;
			ZydisDisassembledInstruction info_instr;
			HOOK_INFO hook_inf = { NULL };

			if (rva)
			{
				address_hook = static_cast<CHAR*>(init_info::inf_proc.target_base) + rva;
				if (!is_hook_ins_false(address_hook))
				{
					dis::get_dis(&info_instr, address_hook);
					hook_inf.address_hook = address_hook;

					memcpy(&hook_inf.info_instr, &info_instr, sizeof(info_instr));

					hook_inf.rip_fixer = copy_instr(&info_instr);

					set_bp_hook(address_hook); //only in end set hook!

					init_info::inf_proc.vec_inf.hook_ret_false.push_back(hook_inf);
					return TRUE;
				}
			}
			return FALSE;
		}
		 
		  

	};

}
#endif // !SINGLE_STEP_HOOK
