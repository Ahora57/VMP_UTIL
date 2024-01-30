#ifndef IMPORT_HELP
#define IMPORT_HELP

#include  "init_address.h" 
#include "nt_api_def.h"
#include "minhook.h"

#define HIGHT_DIS_OFFSET_API PAGE_SIZE
#define HIGHT_DIS_OFFSET_API_OBF_CALL 0X100

#define HIGHT_DIS_OFFSET_STRCMP PAGE_SIZE
#define HIGHT_SUB_OFFSET_STRCMP 0x70
  

namespace import_hook
{

	class import_hook
	{
	private:

		static  auto is_hook_imp_ins(PVOID address) -> BOOLEAN
		{
			for (size_t i = NULL; i < init_info::inf_proc.vec_inf.patch_import.size(); i++)
			{
				if (address == init_info::inf_proc.vec_inf.patch_import[i])
				{
					return TRUE;
				}
			}
			return FALSE;
		}

		static  auto is_hook_strcmp_ins(PVOID address) -> BOOLEAN
		{
			for (size_t i = NULL; i < init_info::inf_proc.vec_inf.patch_import.size(); i++)
			{
				if (address == init_info::inf_proc.vec_inf.patch_import[i])
				{
					return TRUE;
				}
			}
			return FALSE;
		}

		NO_INLINE static auto WINAPI printf_api(CHAR* mod_address, PVOID api_res) -> BOOLEAN
		{
			uint32_t rva_api = NULL;
			PIMAGE_DOS_HEADER dos_head = NULL;
			PIMAGE_NT_HEADERS nt_head = NULL;
			PIMAGE_EXPORT_DIRECTORY export_dir = NULL;

			rva_api = reinterpret_cast<CHAR*>(api_res) - mod_address;

			if (!mod_address)
				return FALSE;
			dos_head = reinterpret_cast<PIMAGE_DOS_HEADER>(mod_address);
			if (dos_head->e_magic != IMAGE_DOS_SIGNATURE)
				return FALSE;
			nt_head = reinterpret_cast<PIMAGE_NT_HEADERS>(mod_address + dos_head->e_lfanew);
			if (nt_head->Signature != IMAGE_NT_SIGNATURE)
				return FALSE;
			export_dir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(mod_address + nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
			if (!export_dir)
				return FALSE;

			auto names = (PDWORD)(mod_address + export_dir->AddressOfNames);
			auto ordinals = (PWORD)(mod_address + export_dir->AddressOfNameOrdinals);
			auto functions = (PDWORD)(mod_address + export_dir->AddressOfFunctions);

			for (uint32_t i = NULL; i < export_dir->NumberOfFunctions; ++i)
			{
				if (functions[ordinals[i]] == rva_api)
				{
					printf("Name ->\t%s\n", reinterpret_cast<CHAR*>(mod_address + names[i]));
					return TRUE;
				}
			}
			return FALSE;

		}

		NO_INLINE static auto WINAPI printf_str_api(CHAR* cur_imp) -> BOOLEAN
		{
			uint8_t count_null = NULL;
			for (uint32_t i = NULL; i < HIGHT_SUB_OFFSET_STRCMP; i++)
			{
				if (*(reinterpret_cast<uint8_t*>(cur_imp) - i) == NULL)
				{
					count_null++;
					if (count_null == 2)
					{
						printf("[strcmp] -> %s\n", cur_imp - i + 1);
						return TRUE;
					}
				}
			}
			return FALSE;

		}

		static auto  hooked_get_import(PVOID module_addr, PVOID crypt_imp, BOOLEAN b) -> PVOID
		{
			PVOID addr_import = NULL;
			PVOID stack_module_addr = module_addr;
			PVOID stack_crypt_imp = crypt_imp;
			BOOLEAN stack_b = b;

			addr_import = reinterpret_cast<decltype(&VMP_Get_Import)>(init_info::inf_proc.orig_addr.orig_impr_vmp)(stack_module_addr, stack_crypt_imp, stack_b);
			printf_api((CHAR*)module_addr, addr_import);
			if (!addr_import)
			{
				printf("Bad import mod ->\t%p\n", module_addr);
				printf("crypt imp ->\t%p\n", crypt_imp);
			}
			return addr_import;

		}

		static auto  hooked_strcmp(CHAR* crypt_imp, CHAR* str_imp, BOOLEAN b) -> INT
		{
			INT res_str = NULL;
			CHAR* stack_crypt_imp = crypt_imp;
			CHAR* stack_crypt_str = str_imp;
			BOOLEAN stack_b = b;

			res_str = reinterpret_cast<decltype(&VMP_STR_CMP)>(init_info::inf_proc.orig_addr.orig_impr_vmp)(stack_crypt_imp, stack_crypt_str, stack_b);
			if (str_imp && res_str == NULL)
			{
				printf("[import] ->\t%s\n", str_imp);
			}
			return res_str;

		}




		static NO_INLINE auto WINAPI get_is_patch_import(CHAR* mem) -> BOOLEAN
		{
#ifndef _WIN64

			BOOLEAN ignore_add = FALSE;
			uint32_t size_mod = NULL;
			uint32_t count_jmp = NULL;
			uint32_t count_sub_esp = NULL;
			uint32_t count_mov_ebp_esp = NULL;

			size_mod = init_info::inf_proc.size_mod;
#else  
			uint32_t count_ret = NULL;
			uint32_t value_rsp = NULL;
			uint32_t count_mov_rsp_rdx = NULL;

#endif // !_WIN64
			ZydisDisassembledInstruction info_instr;

			for (size_t len = NULL; len < HIGHT_DIS_OFFSET_API; len++)
			{

				if (ZYAN_SUCCESS(dis::get_dis(&info_instr, reinterpret_cast<CHAR*>(mem))))
				{
#ifndef _WIN64
					switch (info_instr.info.mnemonic)
					{

					case ZYDIS_MNEMONIC_CPUID:
					case ZYDIS_MNEMONIC_SYSCALL:
					case ZYDIS_MNEMONIC_RDTSC:
					{
						return FALSE;
					}

					case ZYDIS_MNEMONIC_MOV:
					{
						if (info_instr.info.operand_count_visible == 0x2)
						{
							if
								(
									info_instr.operands[0].reg.value == ZYDIS_REGISTER_EBP &&
									info_instr.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
									info_instr.operands[1].reg.value == ZYDIS_REGISTER_ESP &&
									info_instr.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER
									)
							{
								if (count_mov_ebp_esp)
								{
									return FALSE;
								}
								count_mov_ebp_esp++;
							}

							else if
								(
									info_instr.operands[0].reg.value == ZYDIS_REGISTER_EAX &&
									info_instr.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
									info_instr.operands[1].imm.value.u == 'ZM' &&
									info_instr.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
									count_sub_esp &&
									count_mov_ebp_esp
									)
							{
								return TRUE;
							}

						}
						break;
					}

					case ZYDIS_MNEMONIC_SUB:
					{
						if (info_instr.info.operand_count_visible == 0x2)
						{
							if
								(
									info_instr.operands[0].reg.value == ZYDIS_REGISTER_ESP &&
									info_instr.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
									info_instr.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
									info_instr.operands[1].imm.value.u >= sizeof(PVOID) * 20 &&
									count_mov_ebp_esp
									)
							{
								if (count_sub_esp)
								{
									return FALSE;
								}
								count_sub_esp++;
							}
						}
						break;
					}

					case ZYDIS_MNEMONIC_JMP:
					{
						if (count_jmp > 2)
						{
							return FALSE;
						}
						mem = reinterpret_cast<CHAR*>(dis::get_absolute_address(&info_instr, info_instr.runtime_address));
						if (static_cast<CHAR*>(init_info::inf_proc.target_base) < mem &&
							(static_cast<CHAR*>(init_info::inf_proc.target_base) + size_mod) >= mem
							)
						{

							ignore_add = TRUE;
							if (dis::get_absolute_address(&info_instr, info_instr.runtime_address) !=
								info_instr.runtime_address + info_instr.info.length
								)
							{
								//ignoe next instr jmp
								count_jmp++;
							}
							break;
						}
						else
						{
							return FALSE; //ha-ha
						}
					}

					default:
					{
						break;
					}
					}
#else  

					switch (info_instr.info.mnemonic)
					{

					case ZYDIS_MNEMONIC_CPUID:
					case ZYDIS_MNEMONIC_SYSCALL:
					case ZYDIS_MNEMONIC_RDTSC:
					{
						return FALSE;
					}

					case ZYDIS_MNEMONIC_MOV:
					{
						if (info_instr.info.operand_count_visible == 0x2)
						{
							if
								(
									info_instr.operands[0].mem.base == ZYDIS_REGISTER_RSP &&
									info_instr.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
									info_instr.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
									info_instr.operands[1].reg.value == ZYDIS_REGISTER_RDX
									)
							{
								count_mov_rsp_rdx++;
							}
						}
						break;
					}
					case ZYDIS_MNEMONIC_SUB:
					{
						if (info_instr.info.operand_count_visible == 0x2)
						{
							if
								(
									info_instr.operands[0].reg.value == ZYDIS_REGISTER_RSP &&
									info_instr.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
									info_instr.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
									info_instr.operands[1].imm.value.u >= sizeof(PVOID) * 20
									)
							{
								value_rsp = info_instr.operands[1].imm.value.u;
							}
						}
						break;
					}
					case ZYDIS_MNEMONIC_ADD:
					{
						if (info_instr.info.operand_count_visible == 0x2)
						{
							if
								(
									info_instr.operands[0].reg.value == ZYDIS_REGISTER_RSP &&
									info_instr.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
									info_instr.operands[1].imm.value.u == value_rsp &&
									info_instr.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
									count_mov_rsp_rdx &&
									count_ret == 1
									)
							{
								return TRUE;
							}
							else if
								(
									info_instr.operands[0].reg.value == ZYDIS_REGISTER_RSP &&
									info_instr.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
									info_instr.operands[1].imm.value.u != value_rsp &&
									info_instr.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE
									)
							{
								return FALSE;
							}
						}
						break;
					}
					case ZYDIS_MNEMONIC_RET:
					{
						if (count_ret)
						{
							return FALSE;
						}
						count_ret++;
					}
					default:
					{
						break;
					}

					}

#endif // !_WIN64

#ifndef _WIN64

					if (!ignore_add)
					{
						mem += info_instr.info.length;
					}
					ignore_add = FALSE;
#else
					mem += info_instr.info.length;
#endif // !_WIN64

				}
				else
				{
					return FALSE;
				}
			}
			return FALSE;
		}


		static NO_INLINE auto WINAPI get_is_patch_strcmp(CHAR* mem) -> BOOLEAN
		{
			uint32_t count_ret = NULL; 
			uint32_t count_mov = NULL;
			uint32_t count_or = NULL;
			uint32_t count_rol = NULL;
			uint32_t count_stack_add = NULL;
			uint32_t count_stack_sub = NULL;

			ZydisDisassembledInstruction info_instr;

			for (size_t len = NULL; len < HIGHT_DIS_OFFSET_STRCMP; len++)
			{

				if (ZYAN_SUCCESS(dis::get_dis(&info_instr, reinterpret_cast<CHAR*>(mem))))
				{
					switch (info_instr.info.mnemonic)
					{

					case ZYDIS_MNEMONIC_MOV:
					{
						if (info_instr.info.operand_count_visible == 2)
						{
							if (info_instr.operands[0].mem.base == ZYDIS_REGISTER_RSP &&
								info_instr.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
								info_instr.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
								info_instr.operands[1].reg.value == ZYDIS_REGISTER_RDI)
							{
 								count_mov++;
							}
						}
						mem += info_instr.info.length;
						break;
					}


					case ZYDIS_MNEMONIC_CPUID:
					case ZYDIS_MNEMONIC_SYSCALL:
					case ZYDIS_MNEMONIC_RDTSC:
					{
						return FALSE;
					}

					case ZYDIS_MNEMONIC_SUB:
					{
						if (info_instr.info.operand_count_visible == 2)
						{
							if (info_instr.operands[0].reg.value == ZYDIS_REGISTER_RSP &&
								info_instr.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
								info_instr.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
								info_instr.operands[1].imm.value.u >= sizeof(PVOID) * 4)
							{ 
								count_stack_sub++;
								if (count_stack_sub >= 2)
								{
									return FALSE;
								}
							}
						}
						mem += info_instr.info.length;
						break;
					}

					
					case ZYDIS_MNEMONIC_ADD:
					{
						if (info_instr.info.operand_count_visible == 2)
						{
							if (info_instr.operands[0].reg.value == ZYDIS_REGISTER_RSP &&
								info_instr.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
								info_instr.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
								info_instr.operands[1].imm.value.u >= sizeof(PVOID) * 4 && 
								count_stack_sub != NULL &&
								count_stack_add == NULL)
							{ 
								count_stack_add++;
								if (count_stack_add >= 2 )
								{
									return FALSE;
								}
							}
						}
						mem += info_instr.info.length;
						break;
					}
					case ZYDIS_MNEMONIC_OR:
					{
						if (info_instr.info.operand_count_visible == 2)
						{
							if (
								info_instr.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
								info_instr.operands[0].reg.value >= ZYDIS_REGISTER_EAX &&
								info_instr.operands[0].reg.value <= ZYDIS_REGISTER_R15D &&
								info_instr.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
								(info_instr.operands[1].imm.value.u == 0xffffffffffffffff) && //0xFFFFFFFF
								count_rol == 1
								)
							{ 
								count_or++;
							}

						}
						mem += info_instr.info.length;
						break;
					}

					case ZYDIS_MNEMONIC_ROL:
					{
						if (info_instr.info.operand_count_visible == 2)
						{
							if (
								info_instr.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
								info_instr.operands[0].reg.value >= ZYDIS_REGISTER_EAX &&
								info_instr.operands[0].reg.value <= ZYDIS_REGISTER_R15D &&
								info_instr.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
								count_mov == 1
								)
							{ 
								count_rol++;
							}
						}
						mem += info_instr.info.length;
						break;
					}

					case ZYDIS_MNEMONIC_RET:
					{
						if
						(
								count_mov == 1 &&
								count_rol == 1 &&
								count_or == 1 && 
								((count_stack_add == 1 && count_stack_sub == 1) || count_ret == 1)
							
						)
						{
 							return TRUE;
						}
						count_ret++;
						mem += info_instr.info.length;
						break;
					}

					default:
					{
						mem += info_instr.info.length;
						break;
					}
					}
				}
				else
				{
					return FALSE;
				}
			}
			return FALSE;
		}


		 
		// 44 88 44 24 18 / 55 +  8B EC  
		static NO_INLINE auto WINAPI is_import_get(uint8_t* addr) -> BOOLEAN
		{
#ifndef _WIN64

			if (*(addr) == 0x55)
			{
				for (uint8_t i = NULL; i < 22; i++)
				{
					//mov     ebp, esp
					if (*(addr + i) == 0x8B && *(addr + i + 1) == 0xEC)
						return TRUE;

				}
			}
			return FALSE;

#else
			return
				*(addr) == 0x44 &&
				*(addr + 1) == 0x88 &&
				*(addr + 2) == 0x44 &&
				*(addr + 3) == 0x24 &&
				*(addr + 4) == 0x18;
#endif

		}

		//48 89 5C 24 08
		static NO_INLINE auto WINAPI is_strcmp_get(uint8_t* addr) -> BOOLEAN
		{
#ifndef _WIN64

			return FALSE;

#else
			return
				*(addr) == 0x48 &&
				*(addr + 1) == 0x89 &&
				*(addr + 2) == 0x5C &&
				*(addr + 3) == 0x24 &&
				*(addr + 4) == 0x08;
#endif

		}
		 

	public:
		NO_INLINE static auto WINAPI patch_import_find(PVOID module_address) -> BOOLEAN
		{
			BOOLEAN is_found = FALSE;
			uint32_t size_sec = NULL;
			CHAR* memory_sec = NULL;
			PVOID patch_mem = NULL;
			MH_STATUS mh_status;
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
						if (is_import_get(reinterpret_cast<uint8_t*>(memory_sec + i)))
						{


							patch_mem = reinterpret_cast<uint8_t*>(memory_sec + i);

							if (get_is_patch_import(reinterpret_cast<CHAR*>(memory_sec + i)))
							{
								if (is_hook_imp_ins(patch_mem) == FALSE)
								{
									mh_status = MH_Initialize();
									if (mh_status != MH_OK && mh_status != MH_ERROR_ALREADY_INITIALIZED)
									{
										return FALSE;
									}
									if (
										MH_CreateHook(patch_mem, &hooked_get_import, &init_info::inf_proc.orig_addr.orig_impr_vmp) != MH_OK
										)
									{
										return FALSE;
									}
									if (MH_EnableHook(patch_mem) != MH_OK)
									{
										return FALSE;
									}
 
									is_found = TRUE;
									init_info::inf_proc.vec_inf.patch_import.push_back(patch_mem);

								}
								patch_mem = NULL;
							}

						}
					}
				}
			}
			return is_found;
		}


		NO_INLINE static auto WINAPI patch_strcmp(PVOID module_address) -> BOOLEAN
		{
			BOOLEAN is_found = FALSE;
			uint32_t size_sec = NULL;
			CHAR* memory_sec = NULL;
			PVOID patch_mem = NULL;
			MH_STATUS mh_status;
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
						if (is_strcmp_get(reinterpret_cast<uint8_t*>(memory_sec + i)))
						{
							patch_mem = reinterpret_cast<uint8_t*>(memory_sec + i);

							if (get_is_patch_strcmp(reinterpret_cast<CHAR*>(memory_sec + i)))
							{
								if (is_hook_strcmp_ins(patch_mem) == FALSE)
								{
									mh_status = MH_Initialize();
									if (mh_status != MH_OK && mh_status != MH_ERROR_ALREADY_INITIALIZED)
									{
										return FALSE;
									}
									if (
										MH_CreateHook(patch_mem, &hooked_strcmp, &init_info::inf_proc.orig_addr.orig_impr_vmp) != MH_OK
										)
									{
										return FALSE;
									}
									if (MH_EnableHook(patch_mem) != MH_OK)
									{
										return FALSE;
									}
									printf("strcmp hook ->\t%p\n", patch_mem);
									is_found = TRUE;
									init_info::inf_proc.vec_inf.patch_import.push_back(patch_mem);

								}
								patch_mem = NULL;
							}
						}
					}
				}
			}
			return is_found;
		} 
	};
}
#endif // !IMPORT_HELP
