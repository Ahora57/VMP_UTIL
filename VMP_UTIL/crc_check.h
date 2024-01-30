#ifndef CRC_CHECK
#define CRC_CHECK 1


#include  "init_address.h" 
#include "nt_api_def.h"
#include "minhook.h"


#define OPCODE_NOP 0x90
#define OPCODE_INT3 0xCC
#define OPCODE_POP_RAX  0x58

#define HIGHT_DIS_OFFSET_CRC 0x500

#define CRC_NEXT_OFFSET 0x4 
#define MAX_DIS_COUNT_CRC 0x500
#define CRC_AND_VALUE 0xFF
#define MAX_REP_REG 0x1
#define CRC_MAX_JMP 0x8 * 2
#define MAX_COUNT_REC 0x10

namespace crc_check
{
	class alloce_base_hook
	{
	private:

		NO_INLINE static  auto WINAPI is_hook_ins(PVOID address) -> BOOLEAN
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
		NO_INLINE static  auto WINAPI is_hook_crc_calc(PVOID address) -> BOOLEAN
		{
			for (size_t i = NULL; i < init_info::inf_proc.patch_crc_calc.size(); i++)
			{
				if (address == init_info::inf_proc.patch_crc_calc[i].hook_not.address_hook ||
					address == init_info::inf_proc.patch_crc_calc[i].hook_mov.address_hook)
				{
					return TRUE;
				}
			}
			return FALSE;
		}
		*/ 

		NO_INLINE static  auto WINAPI is_hook_crc_calc(PVOID address) -> BOOLEAN
		{
			for (size_t i = NULL; i < init_info::inf_proc.vec_inf.patch_crc_calc.size(); i++)
			{
				if (address == init_info::inf_proc.vec_inf.patch_crc_calc[i].addr)
				{
					return TRUE;
				}
			}
			return FALSE;
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
				/*
				printf("[mbi] AllocationBase ->\t%p\n", mbi.AllocationBase);
				printf("[mbi_excp] AllocationBase ->\t%p\n", mbi_cur->AllocationBase);


				printf("[mbi] BaseAddress ->\t%p\n", mbi.BaseAddress);
				printf("[mbi_excp] BaseAddress ->\t%p\n", mbi_cur->BaseAddress);


				printf("[mbi] RegionSize ->\t%p\n", mbi.RegionSize);
				printf("[mbi_excp] RegionSize ->\t%p\n", mbi_cur->RegionSize);
				*/
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

		static auto WINAPI copy_instr(ZydisDisassembledInstruction* info_instr) -> PVOID
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

					

					ass.jmp(dis::get_absolute_address(info_instr, info_instr->runtime_address));
				}
				else if (info_instr->info.mnemonic == ZYDIS_MNEMONIC_JMP)
				{
					
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

		NO_INLINE static   auto WINAPI set_bp_hook(PVOID addr) -> VOID
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
					//*reinterpret_cast<CHAR*>(addr) = OPCODE_INT3;

					VirtualProtectEx(access, addr, PAGE_SIZE, old_prot, &old_prot);
					CloseHandle(access);

				}
			}
		}

		NO_INLINE static   auto WINAPI set_nop(PVOID addr) -> VOID
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

					VirtualProtectEx(access, addr, PAGE_SIZE, old_prot, &old_prot);
					CloseHandle(access);

				}
			}
		}
		static NO_INLINE auto WINAPI wrap_virt_query(PVOID addr, PMEMORY_BASIC_INFORMATION mbi) -> SIZE_T
		{
			return VirtualQuery(addr, mbi, sizeof(MEMORY_BASIC_INFORMATION));
		}

		static  auto NO_INLINE WINAPI scan_string(PVOID  rsp_point) -> BOOLEAN
		{
			uint8_t page_status = NULL;
			uint32_t max_scan = NULL;
			PULONGLONG pointer_stack = NULL;
			MEMORY_BASIC_INFORMATION mbi = { NULL };
			MEMORY_BASIC_INFORMATION mbi_str = { NULL };

			ZydisDisassembledInstruction dis_instr = { NULL };

			if (wrap_virt_query(rsp_point, &mbi) != NULL)
			{
				max_scan = (reinterpret_cast<CHAR*>(rsp_point) - mbi.BaseAddress);
				for (uint32_t i = NULL; PAGE_SIZE > i && max_scan > i; i += sizeof(PVOID))
				{
					pointer_stack = *reinterpret_cast<PULONGLONG*>(reinterpret_cast<CHAR*>(rsp_point) - i);
					if (wrap_virt_query(pointer_stack, &mbi_str) != NULL)
					{
						if (
							(mbi_str.Type & MEM_PRIVATE) &&
							(mbi.Protect & PAGE_READWRITE) &&
							(mbi.Protect & PAGE_GUARD) == FALSE

							)
						{
							if (*reinterpret_cast<uint8_t*>(pointer_stack) == 'N' &&
								*(reinterpret_cast<uint8_t*>(pointer_stack) + 1) == 't'
								)
							{
								if (strcmp(reinterpret_cast<CHAR*>(pointer_stack), "NtQueryVirtualMemory") == NULL)
								{
									return TRUE;
								}
							}
						}
					}

				}
			}
			return FALSE;
		}
		static  auto NO_INLINE WINAPI scan_stack(PVOID  rsp_point, PVOID ret_address) -> PVOID
		{
			uint8_t page_status = NULL;
			uint32_t max_scan = NULL;
			PULONGLONG pointer_stack = NULL;
			MEMORY_BASIC_INFORMATION mbi = { NULL };
			MEMORY_BASIC_INFORMATION mbi_ret = { NULL };

			ZydisDisassembledInstruction dis_instr = { NULL };

			if (wrap_virt_query(rsp_point, &mbi) != NULL && wrap_virt_query(ret_address, &mbi_ret) != NULL)
			{
				max_scan = mbi.RegionSize - (reinterpret_cast<CHAR*>(rsp_point) - mbi.BaseAddress);
				for (uint32_t i = NULL; i < PAGE_SIZE && max_scan > i; i += sizeof(PVOID))
				{
					pointer_stack = *reinterpret_cast<PULONGLONG*>(reinterpret_cast<CHAR*>(rsp_point) + i);
					if (reinterpret_cast<ULONGLONG>(pointer_stack) > PAGE_SIZE && is_execute_pointer(pointer_stack))
					{
						page_status = is_correct_mem(pointer_stack, &mbi_ret);
						if (page_status == STATUS_OTHER_PAGE)
						{
							if (*reinterpret_cast<uint8_t*>(pointer_stack) != OPCODE_INT3)
							{
								return reinterpret_cast<PVOID>(pointer_stack);
							}

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
								else if (dis_instr.info.mnemonic == ZYDIS_MNEMONIC_INT3)
								{
									if (is_hook_ins(pointer_stack))
									{
										return NULL;// Present re-set hook in bade page
									}
								}

							}

						}
					}

				}
			}
			return NULL;
		}

		NO_INLINE static auto WINAPI get_crc_read(CHAR* mem, REC_CRC_INFO* crc_info) -> PVOID
		{
			CHAR* pos_jmp = NULL;
			uint32_t size_mod = NULL;
			PVOID crc_read = NULL;

			ZydisDisassembledInstruction info_instr;
			REC_CRC_INFO crc_coped = { NULL };

			size_mod = init_info::inf_proc.size_mod;

			for (size_t len = NULL; len < HIGHT_DIS_OFFSET_CRC; len++)
			{

				if (ZYAN_SUCCESS(dis::get_dis(&info_instr, reinterpret_cast<CHAR*>(mem))))
				{
					crc_info->dis_count++;
					if (crc_info->dis_count >= MAX_DIS_COUNT_CRC)
					{
						return NULL;
					}

					switch (info_instr.info.mnemonic)
					{
						//case ZYDIS_MNEMONIC_MOV:
					case ZYDIS_MNEMONIC_MOVZX:
					{
						if (info_instr.info.operand_count_visible == 0x2)
						{
							if (info_instr.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
								info_instr.operands[0].reg.value >= ZYDIS_REGISTER_EAX &&
								info_instr.operands[0].reg.value <= ZYDIS_REGISTER_R15D &&
								info_instr.operands[0].reg.value == crc_info->xor_hash.reg &&
								info_instr.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
								info_instr.operands[1].mem.base == crc_info->inc_count_cur_mem.reg &&
								crc_info->inc_count_cur_mem.count == 1 &&
								crc_info->shr_count.count == 1 &&
								crc_info->xor_hash.count == 1
								)
							{
								crc_info->movzx_count_p.count++;
								crc_info->movzx_count_p.reg = info_instr.operands[0].reg.value;
								crc_info->movzx_p = reinterpret_cast<CHAR*>(info_instr.runtime_address);
							}
						}

						mem += info_instr.info.length;
						break;
					}

					case ZYDIS_MNEMONIC_AND:
					{
						if (info_instr.info.operand_count_visible == 0x2)
						{
							if (info_instr.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
								info_instr.operands[0].reg.value >= ZYDIS_REGISTER_EAX &&
								info_instr.operands[0].reg.value <= ZYDIS_REGISTER_R15D &&
								info_instr.operands[0].reg.value == crc_info->xor_hash.reg &&
								info_instr.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
								info_instr.operands[1].imm.value.u == CRC_AND_VALUE &&
								crc_info->inc_count_cur_mem.count == 1 &&
								crc_info->shr_count.count == 1 &&
								crc_info->xor_hash.count == 1 &&
								crc_info->movzx_count_p.count == 1 &&
								crc_info->pos_jmp_count >= 1
								)
							{
								return crc_info->movzx_p;
							}
						}
						mem += info_instr.info.length;
						break;
					}
					case ZYDIS_MNEMONIC_SHR:
					{

						if (info_instr.info.operand_count_visible == 0x2)
						{
							if (info_instr.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
								info_instr.operands[0].reg.value >= ZYDIS_REGISTER_EAX &&
								info_instr.operands[0].reg.value <= ZYDIS_REGISTER_R15D &&
								info_instr.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
								info_instr.operands[1].imm.value.u == sizeof(ULONG) * 2
								)
							{
								crc_info->shr_count.count++;
								crc_info->shr_count.reg = info_instr.operands[0].reg.value;
								//printf("crc calc shr ->\t%p\n", reinterpret_cast<CHAR*>(info_instr.runtime_address));
							}
						}
						mem += info_instr.info.length;

						break;
					}


					case ZYDIS_MNEMONIC_XOR:
					{

						if (info_instr.info.operand_count_visible == 0x2)
						{
							if (info_instr.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
								info_instr.operands[0].reg.value >= ZYDIS_REGISTER_EAX &&
								info_instr.operands[0].reg.value <= ZYDIS_REGISTER_R15D &&
								info_instr.operands[0].reg.value == crc_info->shr_count.reg &&
								info_instr.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
								crc_info->shr_count.count
								)
							{
								crc_info->xor_hash.count++;
								crc_info->xor_hash.reg = info_instr.operands[1].reg.value;

							}
						}
						mem += info_instr.info.length;

						break;
					}

					case ZYDIS_MNEMONIC_INC:
					{
						if (info_instr.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&

							info_instr.operands[0].reg.value >= ZYDIS_REGISTER_RAX &&
							info_instr.operands[0].reg.value <= ZYDIS_REGISTER_R15

							)
						{
							crc_info->inc_count_cur_mem.count++;
							crc_info->inc_count_cur_mem.reg = info_instr.operands[0].reg.value;

						}

						mem += info_instr.info.length;
						break;
					}
					case ZYDIS_MNEMONIC_JMP:
					case ZYDIS_MNEMONIC_CALL:
					{
						mem = reinterpret_cast<CHAR*>(dis::get_absolute_address(&info_instr, info_instr.runtime_address));
						if ((static_cast<CHAR*>(init_info::inf_proc.target_base) <= mem &&
							(static_cast<CHAR*>(init_info::inf_proc.target_base) + size_mod) > mem) == FALSE
							)
						{
							return NULL;
						}
						break;
					}
					case ZYDIS_MNEMONIC_JB:
					case ZYDIS_MNEMONIC_JBE:
					case ZYDIS_MNEMONIC_JCXZ:
					case ZYDIS_MNEMONIC_JECXZ:
					case ZYDIS_MNEMONIC_JKNZD:
					case ZYDIS_MNEMONIC_JKZD:
					case ZYDIS_MNEMONIC_JL:
					case ZYDIS_MNEMONIC_JLE:
					case ZYDIS_MNEMONIC_JNB:
					case ZYDIS_MNEMONIC_JNBE:
					case ZYDIS_MNEMONIC_JNL:
					case ZYDIS_MNEMONIC_JNLE:
					case ZYDIS_MNEMONIC_JNO:
					case ZYDIS_MNEMONIC_JNP:
					case ZYDIS_MNEMONIC_JNS:
					case ZYDIS_MNEMONIC_JNZ:
					case ZYDIS_MNEMONIC_JO:
					case ZYDIS_MNEMONIC_JP:
					case ZYDIS_MNEMONIC_JRCXZ:
					case ZYDIS_MNEMONIC_JS:
					case ZYDIS_MNEMONIC_JZ:
					{



						if (crc_info->pos_jmp_count >= 4)
						{
							return NULL;
						}

						crc_info->pos_jmp_count++;
						pos_jmp = reinterpret_cast<CHAR*>(dis::get_absolute_address(&info_instr, info_instr.runtime_address));
						if ((static_cast<CHAR*>(init_info::inf_proc.target_base) <= pos_jmp &&
							(static_cast<CHAR*>(init_info::inf_proc.target_base) + size_mod) > pos_jmp) == FALSE
							)
						{
							//Not correct jmp
							mem += info_instr.info.length;
						}
						else
						{


							//Possible correct JNN
							memcpy(&crc_coped, crc_info, sizeof(REC_CRC_INFO));
							if (get_crc_read(pos_jmp, &crc_coped))
							{
								memcpy(crc_info, &crc_coped, sizeof(REC_CRC_INFO));
								return crc_info->movzx_p;

							}
							else
							{
								mem += info_instr.info.length;
							}

							memset(&crc_coped, NULL, sizeof(crc_coped));
						}


						break;
					}
					default:
					{
						mem += info_instr.info.length;
						break;
					}

					}
				}
			}
			return 	NULL;

		}
		NO_INLINE static auto WINAPI get_crc_read_safe(CHAR* mem, REC_CRC_INFO* crc_info) -> PVOID
		{
			CHAR* pos_jmp = NULL;
			uint32_t size_mod = NULL;
			PVOID crc_read = NULL;

			ZydisDisassembledInstruction info_instr;
			REC_CRC_INFO crc_coped = { NULL };

			size_mod = init_info::inf_proc.size_mod;

			for (size_t len = NULL; len < HIGHT_DIS_OFFSET_CRC; len++)
			{

				if (ZYAN_SUCCESS(dis::get_dis(&info_instr, reinterpret_cast<CHAR*>(mem))))
				{
					crc_info->dis_count++;
					if (crc_info->dis_count >= MAX_DIS_COUNT_CRC)
					{
						return NULL;
					}

					switch (info_instr.info.mnemonic)
					{
						//case ZYDIS_MNEMONIC_MOV:
					case ZYDIS_MNEMONIC_MOVZX:
					{
						if (info_instr.info.operand_count_visible == 0x2)
						{
							if (info_instr.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
								info_instr.operands[0].reg.value >= ZYDIS_REGISTER_EAX &&
								info_instr.operands[0].reg.value <= ZYDIS_REGISTER_R15D &&
								info_instr.operands[0].reg.value == crc_info->xor_hash.reg &&
								info_instr.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
								info_instr.operands[1].mem.base == crc_info->inc_count_cur_mem.reg &&
								crc_info->inc_count_cur_mem.count == 1 &&
								crc_info->shr_count.count == 1 &&
								crc_info->xor_hash.count == 1 &&
								!crc_info->movzx_count_p.count
								)
							{
								crc_info->movzx_count_p.count++;
								crc_info->movzx_p = reinterpret_cast<CHAR*>(info_instr.runtime_address);
							}
						}

						mem += info_instr.info.length;
						break;
					}

					case ZYDIS_MNEMONIC_AND:
					{
						if (info_instr.info.operand_count_visible == 0x2)
						{
							if (info_instr.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
								info_instr.operands[0].reg.value >= ZYDIS_REGISTER_EAX &&
								info_instr.operands[0].reg.value <= ZYDIS_REGISTER_R15D &&
								info_instr.operands[0].reg.value == crc_info->xor_hash.reg &&
								info_instr.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
								info_instr.operands[1].imm.value.u == CRC_AND_VALUE &&
								crc_info->inc_count_cur_mem.count == MAX_REP_REG &&
								crc_info->shr_count.count == MAX_REP_REG &&
								crc_info->xor_hash.count == MAX_REP_REG &&
								crc_info->movzx_count_p.count == MAX_REP_REG &&
								crc_info->pos_jmp_count >= 1
								)
							{
								crc_info->and_count.count++;
								if (crc_info->not_hash.count)
								{
									return crc_info->movzx_p;
								}
							}
						}
						mem += info_instr.info.length;
						break;
					}
					case ZYDIS_MNEMONIC_SHR:
					{

						if (info_instr.info.operand_count_visible == 0x2)
						{
							if (info_instr.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
								info_instr.operands[0].reg.value >= ZYDIS_REGISTER_EAX &&
								info_instr.operands[0].reg.value <= ZYDIS_REGISTER_R15D &&
								info_instr.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
								info_instr.operands[1].imm.value.u == sizeof(ULONG) * 2 &&
								!crc_info->shr_count.count
								)
							{
								crc_info->shr_count.count++;
								crc_info->shr_count.reg = info_instr.operands[0].reg.value;
								//printf("crc calc shr ->\t%p\n", reinterpret_cast<CHAR*>(info_instr.runtime_address));
							}
						}
						mem += info_instr.info.length;

						break;
					}


					case ZYDIS_MNEMONIC_XOR:
					{

						if (info_instr.info.operand_count_visible == 0x2)
						{
							if (info_instr.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
								info_instr.operands[0].reg.value >= ZYDIS_REGISTER_EAX &&
								info_instr.operands[0].reg.value <= ZYDIS_REGISTER_R15D &&
								info_instr.operands[0].reg.value == crc_info->shr_count.reg &&
								info_instr.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
								crc_info->shr_count.count &&
								!crc_info->xor_hash.count
								)
							{
								crc_info->xor_hash.count++;
								crc_info->xor_hash.reg = info_instr.operands[1].reg.value;

							}
						}
						mem += info_instr.info.length;

						break;
					}

					case ZYDIS_MNEMONIC_INC:
					{
						if (info_instr.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
#ifndef _WIN64
							info_instr.operands[0].reg.value >= ZYDIS_REGISTER_EAX &&
							info_instr.operands[0].reg.value <= ZYDIS_REGISTER_R15D

#else
							info_instr.operands[0].reg.value >= ZYDIS_REGISTER_RAX &&
							info_instr.operands[0].reg.value <= ZYDIS_REGISTER_R15 &&
							!crc_info->inc_count_cur_mem.count &&
							crc_info->shr_count.count //present recursion 
#endif // !_WIN64

							)
						{
							crc_info->inc_count_cur_mem.count++;
							crc_info->inc_count_cur_mem.reg = info_instr.operands[0].reg.value;

						}

						mem += info_instr.info.length;
						break;
					}

					case ZYDIS_MNEMONIC_NOT:
					{
						if (
							info_instr.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
							info_instr.operands[0].reg.value >= ZYDIS_REGISTER_EAX &&
							info_instr.operands[0].reg.value <= ZYDIS_REGISTER_R15D &&
							info_instr.operands[0].reg.value == crc_info->shr_count.reg &&
							!crc_info->not_hash.count

							)
						{
							crc_info->not_hash.count++;
							crc_info->not_hash.reg == crc_info->shr_count.reg;
							crc_info->not_hash_p = reinterpret_cast<CHAR*>(info_instr.runtime_address);
							if (crc_info->and_count.count)
							{
								return crc_info->movzx_p;
							}
						}

						mem += info_instr.info.length;
						break;
					}
					case ZYDIS_MNEMONIC_JMP:
					case ZYDIS_MNEMONIC_CALL:
					{
						mem = reinterpret_cast<CHAR*>(dis::get_absolute_address(&info_instr, info_instr.runtime_address));
						if ((static_cast<CHAR*>(init_info::inf_proc.target_base) <= mem &&
							(static_cast<CHAR*>(init_info::inf_proc.target_base) + size_mod) > mem) == FALSE
							)
						{
							return NULL;
						}
						break;
					}
					case ZYDIS_MNEMONIC_JB:
					case ZYDIS_MNEMONIC_JBE:
					case ZYDIS_MNEMONIC_JCXZ:
					case ZYDIS_MNEMONIC_JECXZ:
					case ZYDIS_MNEMONIC_JKNZD:
					case ZYDIS_MNEMONIC_JKZD:
					case ZYDIS_MNEMONIC_JL:
					case ZYDIS_MNEMONIC_JLE:
					case ZYDIS_MNEMONIC_JNB:
					case ZYDIS_MNEMONIC_JNBE:
					case ZYDIS_MNEMONIC_JNL:
					case ZYDIS_MNEMONIC_JNLE:
					case ZYDIS_MNEMONIC_JNO:
					case ZYDIS_MNEMONIC_JNP:
					case ZYDIS_MNEMONIC_JNS:
					case ZYDIS_MNEMONIC_JNZ:
					case ZYDIS_MNEMONIC_JO:
					case ZYDIS_MNEMONIC_JP:
					case ZYDIS_MNEMONIC_JRCXZ:
					case ZYDIS_MNEMONIC_JS:
					case ZYDIS_MNEMONIC_JZ:
					{


						if (crc_info->pos_jmp_count >= CRC_MAX_JMP)
						{
							return NULL;
						}

						crc_info->pos_jmp_count++;
						pos_jmp = reinterpret_cast<CHAR*>(dis::get_absolute_address(&info_instr, info_instr.runtime_address));
						if ((static_cast<CHAR*>(init_info::inf_proc.target_base) <= pos_jmp &&
							(static_cast<CHAR*>(init_info::inf_proc.target_base) + size_mod) > pos_jmp) == FALSE
							)
						{
							//Not correct jmp
							mem += info_instr.info.length;
						}
						else
						{
							if (crc_info->rec_count == MAX_COUNT_REC)
							{
								return NULL;
							}
							crc_info->rec_count++;

							//Possible correct JNN
							memcpy(&crc_coped, crc_info, sizeof(REC_CRC_INFO));
							if (get_crc_read_safe(pos_jmp, &crc_coped))
							{
								memcpy(crc_info, &crc_coped, sizeof(REC_CRC_INFO));
								return crc_info->movzx_p;

							}
							else
							{
								crc_info->rec_count--;
								if (crc_coped.not_hash.count)
								{
									crc_info->not_hash.count = crc_coped.not_hash.count;
									crc_info->not_hash.reg = crc_coped.not_hash.reg;
									crc_info->not_hash_p = crc_coped.not_hash_p;
								}
								mem += info_instr.info.length;
							}

							memset(&crc_coped, NULL, sizeof(crc_coped));
						}


						break;
					}
					default:
					{
						mem += info_instr.info.length;
						break;
					}

					}
				}
			}
			return 	NULL;

		}

		//and reg32,0xFF
		static auto WINAPI is_crc_calc(uint8_t* addr) -> BOOLEAN
		{
			return
				*(addr) == 0xFF &&
				*(addr + 1) == NULL &&
				*(addr + 2) == NULL &&
				* (addr + 3) == NULL;
		}

		NO_INLINE static auto WINAPI scan_crc_calc(PVOID module_address, BOOLEAN is_safe) -> uint32_t
		{
			uint32_t is_found = FALSE;
			uint32_t size_sec = NULL;
			uint32_t crc_calc_num = NULL;
			CHAR* memory_sec = NULL;
			PVOID patch_mem = NULL;
			REC_CRC_INFO crc_info = { NULL };
			HOOK_CRC_INFO hook_crc = { NULL };
			ZydisDisassembledInstruction info_instr;
			PIMAGE_NT_HEADERS  headers = NULL;
			PIMAGE_SECTION_HEADER sections = NULL;

			if (static_cast<PIMAGE_DOS_HEADER>(module_address)->e_lfanew != IMAGE_DOS_SIGNATURE)
				FALSE;
			headers = reinterpret_cast<PIMAGE_NT_HEADERS>(static_cast<CHAR*>(module_address) + static_cast<PIMAGE_DOS_HEADER>(module_address)->e_lfanew);
			if (headers->Signature != IMAGE_NT_SIGNATURE)
			{
				return FALSE;
			}
			sections = IMAGE_FIRST_SECTION(headers);

			for (size_t sec_cur = NULL; sec_cur < headers->FileHeader.NumberOfSections; sec_cur++)
			{
				if ((sections[sec_cur].Characteristics & IMAGE_SCN_MEM_READ) && (sections[sec_cur].Characteristics & IMAGE_SCN_MEM_EXECUTE))
				{
					memory_sec = static_cast<CHAR*>(module_address) + sections[sec_cur].VirtualAddress;
					size_sec = sections[sec_cur].SizeOfRawData ? sections[sec_cur].SizeOfRawData : sections[sec_cur].Misc.VirtualSize;

					for (uint32_t i = NULL; i < size_sec; i++)
					{
						if (is_crc_calc(reinterpret_cast<uint8_t*>(memory_sec) + i))
						{
							if (is_safe)
							{
								patch_mem = get_crc_read_safe(reinterpret_cast<CHAR*>(memory_sec) + i + CRC_NEXT_OFFSET, &crc_info);
							}
							else
							{
								patch_mem = get_crc_read(reinterpret_cast<CHAR*>(memory_sec) + i + CRC_NEXT_OFFSET, &crc_info);
							}

							if (patch_mem && !is_hook_crc_calc(patch_mem))
							{
								crc_calc_num++;


								hook_crc.addr = crc_info.movzx_p;
								if (!ZYAN_SUCCESS(dis::get_dis(&info_instr, reinterpret_cast<CHAR*>(crc_info.movzx_p))))
								{
									return NULL;
								}
								hook_crc.reg_write = info_instr.operands[0].reg.value;
								hook_crc.size_elem = info_instr.operands[1].size;

								memcpy(&hook_crc.reg_read, &info_instr.operands[1].mem, sizeof(hook_crc.reg_read));


								init_info::inf_proc.vec_inf.patch_crc_calc.push_back(hook_crc);
								set_bp_hook(hook_crc.addr);

								memset(&hook_crc, NULL, sizeof(hook_crc));
							}
							memset(&crc_info, NULL, sizeof(crc_info));


						}
					}
				}
			}
			printf("Find calc crc ->\t%d\n", crc_calc_num);
			return crc_calc_num;
		}

		NO_INLINE static auto WINAPI alloc_copy(PVOID module_address) -> PVOID
		{
			uint32_t virtual_size = NULL;
			uint32_t size_mod = NULL;
			uint32_t sec_alignment = NULL;
			PVOID coped_mem = NULL;

			PIMAGE_NT_HEADERS  headers = NULL;
			PIMAGE_SECTION_HEADER sections = NULL;
			MEMORY_BASIC_INFORMATION mbi = { NULL };
			if (static_cast<PIMAGE_DOS_HEADER>(module_address)->e_lfanew != IMAGE_DOS_SIGNATURE)
				NULL;
			headers = reinterpret_cast<PIMAGE_NT_HEADERS>(static_cast<CHAR*>(module_address) + static_cast<PIMAGE_DOS_HEADER>(module_address)->e_lfanew);

			if (headers->Signature != IMAGE_NT_SIGNATURE)
				return FALSE;

			sections = IMAGE_FIRST_SECTION(headers);

			coped_mem = VirtualAlloc(NULL, headers->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_READWRITE);
			if (!coped_mem)
				return FALSE;
			sec_alignment = headers->OptionalHeader.SectionAlignment;

			if(!sec_alignment)
				sec_alignment = PAGE_SIZE;

			//Coped PE
			memcpy(static_cast<CHAR*>(coped_mem) , static_cast<CHAR*>(module_address), sec_alignment);

			for (size_t i = NULL; i < headers->FileHeader.NumberOfSections; i++)
			{
				 
				if (sections[i].Characteristics & IMAGE_SCN_MEM_READ)
				{
					//page rounding(actually this code is not needed)
					virtual_size = sections[i].Misc.VirtualSize;
					virtual_size += (sec_alignment - virtual_size % sec_alignment);

					memcpy(static_cast<CHAR*>(coped_mem) + sections[i].VirtualAddress, static_cast<CHAR*>(module_address) + sections[i].VirtualAddress, virtual_size);
				}
			}
			return coped_mem;
		}

	public:

		static   NTSTATUS WINAPI hooked_nt_virt
		(
			HANDLE ProcessHandle,
			PVOID BaseAddress,
			MEMORY_INFORMATION_CLASS MemoryInformationClass,
			PVOID MemoryInformation,
			SIZE_T MemoryInformationLength,
			PSIZE_T ReturnLength
		)
		{
			BOOLEAN is_setup = TRUE;
			ULONG size_mod = NULL;
			NTSTATUS nt_status = STATUS_UNSUCCESSFUL;
			PVOID ret_address = NULL;
			PVOID rsp_point = NULL;
			PVOID scan_hook_do = NULL;
			MH_STATUS mh_status;
			HOOK_INFO hook_inf = { NULL };

			ZydisDisassembledInstruction info_instr;

			ret_address = _ReturnAddress();
			nt_status = reinterpret_cast<decltype(&NtQueryVirtualMemory)>(init_info::inf_proc.orig_addr.orig_nt_virt)(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength);

			size_mod = init_info::inf_proc.size_mod;

			if (static_cast<CHAR*>(init_info::inf_proc.target_base) <= ret_address &&
				(static_cast<CHAR*>(init_info::inf_proc.target_base) + size_mod) > ret_address
				)
			{
				if (NT_SUCCESS(nt_status) && ProcessHandle == NtCurrentProcess && MemoryInformationClass == MemoryBasicInformation)
				{

					rsp_point = &MemoryInformationLength;

					if (scan_string(reinterpret_cast<CHAR*>(rsp_point) - 0x30))
					{

						scan_hook_do = scan_stack(rsp_point, ret_address);

						if (scan_hook_do)
						{
							if (is_hook_ins(scan_hook_do))
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

							init_info::inf_proc.vec_inf.hook_ret_true.push_back(hook_inf);

						}
					}


				}
			}
			return nt_status;
		}


		NO_INLINE static auto WINAPI create_hook_virt_mem() -> BOOLEAN
		{
			PVOID target_hook = NULL;
			MH_STATUS mh_status;

			init_info::inf_proc.ntdll_base = GetModuleHandleW(L"ntdll.dll");

			if (!init_info::inf_proc.ntdll_base)
			{
				return FALSE;
			}

			target_hook = GetProcAddress(reinterpret_cast<HMODULE>(init_info::inf_proc.ntdll_base), "NtQueryVirtualMemory");

			mh_status = MH_Initialize();
			if (mh_status != MH_OK && mh_status != MH_ERROR_ALREADY_INITIALIZED)
			{
				return FALSE;
			}

			if (
				MH_CreateHook(target_hook, &hooked_nt_virt, &init_info::inf_proc.orig_addr.orig_nt_virt) != MH_OK
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

		//На бумаге положение данной фунции было вполне надежным
		NO_INLINE static auto WINAPI is_patch_crc_calc(PVOID mod_addr, BOOLEAN is_safe = FALSE) -> uint32_t
		{
			uint32_t is_scan = NULL;
			PVOID coped_mem = NULL;

			coped_mem = alloc_copy(mod_addr);

			init_info::inf_proc.coped_targer_base = coped_mem;

			is_scan = scan_crc_calc(mod_addr, is_safe);
			 

			return coped_mem && is_scan;
		}

		NO_INLINE static auto WINAPI add_hook_calc(uint32_t rva) -> VOID
		{
			PVOID base_mem = NULL;
			HOOK_CRC_INFO hook_crc = { NULL };
			ZydisDisassembledInstruction info_instr;

			base_mem = init_info::inf_proc.target_base;

			if (!init_info::inf_proc.coped_targer_base)
			{
				init_info::inf_proc.coped_targer_base = alloc_copy(base_mem); 
			}

			hook_crc.addr = reinterpret_cast<CHAR*>(base_mem) + rva;
			if (!ZYAN_SUCCESS(dis::get_dis(&info_instr, reinterpret_cast<CHAR*>(hook_crc.addr))))
			{
				return;
			}
			hook_crc.reg_write = info_instr.operands[0].reg.value;
			hook_crc.size_elem = info_instr.operands[1].size;

			memcpy(&hook_crc.reg_read, &info_instr.operands[1].mem, sizeof(hook_crc.reg_read));


			init_info::inf_proc.vec_inf.patch_crc_calc.push_back(hook_crc);
			set_bp_hook(hook_crc.addr);

 		}


	};

}
#endif // !CRC_CHECK
