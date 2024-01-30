#ifndef ANTI_VM
#define ANTI_VM

#include "init_address.h" 
#include "nt_api_def.h"
#include "minhook.h"

#define PATTERN_SIZE_STR_VM 0x5
#define HIGHT_DIS_OFFSET_VM_STR 0x75
#define HIGHT_DIS_OFFSET_API PAGE_SIZE

namespace anti_vm
{

	class ret_vm_str
	{
	private:

		NO_INLINE static  auto is_patch_ins(PVOID address) -> BOOLEAN
		{
			for (size_t i = NULL; i < init_info::inf_proc.vec_inf.patch_vm_str.size(); i++)
			{
				if (address == init_info::inf_proc.vec_inf.patch_vm_str[i])
				{
					return TRUE;
				}
			}
			return FALSE;
		}
		//48:8B5C24 08  mov rbx,qword ptr ss:[rsp+8]
		static auto is_vm_str_pat(uint8_t* addr) -> BOOLEAN
		{
			return
				*(addr) == 0x48 &&
				*(addr + 1) == 0x8B &&
				*(addr + 2) == 0x5C &&
				*(addr + 3) == 0x24 &&
				*(addr + 4) == 0x08;

		}


		static  auto is_hook_ins(PVOID address) -> BOOLEAN
		{
			for (size_t i = NULL; i < init_info::inf_proc.vec_inf.patch_vm_str.size(); i++)
			{
				if (address == init_info::inf_proc.vec_inf.patch_vm_str[i])
				{
					return TRUE;
				}
			}
			return FALSE;
		}

		static auto get_patch_vm_str(CHAR* mem) -> PVOID
		{
			uint8_t count_mov_rbx = NULL;
			uint8_t count_mov_rdi = NULL;
			uint8_t count_mov_ret = NULL;

			ZydisDisassembledInstruction info_instr;

			for (size_t len = NULL; len < HIGHT_DIS_OFFSET_VM_STR; len++)
			{

				if (ZYAN_SUCCESS(dis::get_dis(&info_instr, reinterpret_cast<CHAR*>(mem))))
				{
					switch (info_instr.info.mnemonic)
					{
					case ZYDIS_MNEMONIC_MOV:
					{
						if (info_instr.info.operand_count_visible == 0x2)
						{
							if (
								info_instr.operands[0].reg.value == ZYDIS_REGISTER_RBX &&
								info_instr.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
								info_instr.operands[1].mem.base == ZYDIS_REGISTER_RSP &&
								info_instr.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
								info_instr.operands[1].mem.type == ZYDIS_MEMOP_TYPE_MEM &&
								info_instr.operands[1].mem.disp.value == sizeof(PVOID)
								)
							{
								count_mov_rbx++;
							}
							else if
								(
									info_instr.operands[0].reg.value == ZYDIS_REGISTER_RDI &&
									info_instr.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
									info_instr.operands[1].mem.base == ZYDIS_REGISTER_RSP &&
									info_instr.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
									info_instr.operands[1].mem.type == ZYDIS_MEMOP_TYPE_MEM &&
									info_instr.operands[1].mem.disp.value == sizeof(PVOID) * 0x02
									)

							{
								count_mov_rdi++;
							}
							if (count_mov_rbx == 2 && count_mov_rdi == 2 && count_mov_ret == 1 && info_instr.info.length == 0x02)
							{
								if (
									info_instr.operands[0].reg.value == ZYDIS_REGISTER_AL &&
									info_instr.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
									info_instr.operands[1].imm.value.u == TRUE &&
									info_instr.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE

									)
								{
									return mem;
								}
							}
						}


						break;
					}
					case ZYDIS_MNEMONIC_RET:
					{
						count_mov_ret++;
						break;
					}
					default:
					{
						break;
					}

					}

					mem += info_instr.info.length;
				}
				else
				{
					return NULL;
				}
			}
			return NULL;
		}

		static   auto set_path_instr(PVOID addr) -> VOID
		{

			DWORD old_prot = NULL;
			HANDLE access = NULL;
			ZydisDisassembledInstruction dis_instr = { NULL };

			if (ZYAN_SUCCESS(dis::get_dis(&dis_instr, reinterpret_cast<CHAR*>(addr))))
			{
				access = OpenProcess(PROCESS_VM_OPERATION, FALSE, (DWORD)NtCurrentProcessId());
				if (access && VirtualProtectEx(access, addr, PAGE_SIZE, PAGE_EXECUTE_READWRITE, &old_prot))
				{
					*(reinterpret_cast<CHAR*>(addr) + 1) = NULL; //change OPCODE to 0 or mov al,1(B0 01) -> mov al,0 (B0 00)

					VirtualProtectEx(access, addr, PAGE_SIZE, old_prot, &old_prot);
					CloseHandle(access);

				}
			}
		}
	public:


		NO_INLINE static auto patch_str_find(PVOID module_address) -> BOOLEAN
		{
			uint32_t size_sec = NULL;
			CHAR* memory_sec = NULL;
			PVOID patch_mem = NULL;
			PVOID old_pattern = NULL;
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

					size_sec -= HIGHT_DIS_OFFSET_VM_STR;

					for (uint32_t i = NULL; i < size_sec - PATTERN_SIZE_STR_VM; i++)
					{
						if (is_vm_str_pat(reinterpret_cast<uint8_t*>(memory_sec) + i))
						{

							patch_mem = get_patch_vm_str(memory_sec + i);
							if (patch_mem && is_patch_ins(patch_mem) == FALSE)
							{
								if (is_patch_ins(patch_mem) == FALSE)
								{
									set_path_instr(patch_mem);
									init_info::inf_proc.vec_inf.patch_vm_str.push_back(patch_mem);
								}
								patch_mem = NULL;
							}
						}
					}
				}
			}
			return FALSE;
		}
	};

}
#endif // !ANTI_VM
