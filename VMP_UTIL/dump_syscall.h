#ifndef SYSCALL_DUMPER_ENABLE
#define SYSCALL_DUMPER_ENABLE 1

#include "struct.h"
#include <cstdint>
#include "nt_api_def.h"
#include "lazy_importer.h" 
#include <cstddef>

namespace detail
{
	template <typename Type, Type OffsetBasis, Type Prime>
	struct size_dependant_data
	{
		using type = Type;
		constexpr static auto k_offset_basis = OffsetBasis;
		constexpr static auto k_prime = Prime;
	};

	template <size_t Bits>
	struct size_selector;

	template <>
	struct size_selector<32>
	{
		using type = size_dependant_data<std::uint32_t, 0x811c9dc5ul - __TIME__[7] - __TIME__[4], 16777619ul - __TIME__[7] - __TIME__[4] >;
	};

	template <>
	struct size_selector<64>
	{
		using type = size_dependant_data<std::uint64_t, 0xcbf29ce484222325ull - __TIME__[7] - __TIME__[4], 1099511628211ull - __TIME__[7] - __TIME__[4]>;
	};

	// Implements FNV-1a hash algorithm
	template <std::size_t Size>
	class fnv_hash
	{
	private:
		using data_t = typename size_selector<Size>::type;

	public:
		using hash = typename data_t::type;

	private:
		constexpr static auto k_offset_basis = data_t::k_offset_basis;
		constexpr static auto k_prime = data_t::k_prime;

	public:
		template <std::size_t N>
		static __forceinline constexpr auto hash_constexpr(const char(&str)[N], const std::size_t size = N) -> hash
		{
			return static_cast<hash>(1ull * (size == 1
				? (k_offset_basis ^ str[0])
				: (hash_constexpr(str, size - 1) ^ str[size - 1])) * k_prime);
		}

		static auto __forceinline hash_runtime(const char* str) -> hash
		{
			auto result = k_offset_basis;
			do
			{
				result ^= *str++;
				result *= k_prime;
			} while (*(str - 1) != '\0');

			return result;
		}

		template <std::size_t N>
		static __forceinline constexpr auto hash_constexpr(const wchar_t(&str)[N], const std::size_t size = N) -> hash
		{
			return static_cast<hash>(1ull * (size == 1
				? (k_offset_basis ^ str[0])
				: (hash_constexpr(str, size - 1) ^ str[size - 1])) * k_prime);
		}

		static auto __forceinline WINAPI hash_runtime(const wchar_t* str) -> hash
		{
			auto result = k_offset_basis;
			do
			{
				result ^= *str++;
				result *= k_prime;
			} while (*(str - 1) != '\0');

			return result;
		}
	};
}

using fnv = ::detail::fnv_hash<sizeof(PVOID) * 8>;

#define FNV(str) (std::integral_constant<fnv::hash, fnv::hash_constexpr(str)>::value)

namespace dump_syscall_util
{


	namespace crt_wrapper
	{
		INLINE auto WINAPI malloc(size_t size) -> PVOID
		{
			return VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_READWRITE);
		}

		INLINE auto WINAPI free(PVOID ptr) -> VOID
		{
			if (nullptr != ptr)
				VirtualFree(ptr, NULL, MEM_RELEASE);
		}

		INLINE auto WINAPI memset(PVOID dest, CHAR c, UINT len) -> PVOID
		{
			UINT i;
			UINT fill;
			UINT chunks = len / sizeof(fill);
			CHAR* char_dest = (CHAR*)dest;
			unsigned int* uint_dest = (UINT*)dest;
			fill = (c << 24) + (c << 16) + (c << 8) + c;

			for (i = len; i > chunks * sizeof(fill); i--) {
				char_dest[i - 1] = c;
			}

			for (i = chunks; i > NULL; i--) {
				uint_dest[i - 1] = fill;
			}

			return dest;
		}

		INLINE auto WINAPI str_cat_w(WCHAR* dest, CONST WCHAR* src) -> WCHAR*
		{
			if ((dest == NULL) || (src == NULL))
				return dest;

			while (*dest != NULL)
				dest++;

			while (*src != NULL)
			{
				*dest = *src;
				dest++;
				src++;
			}

			*dest = NULL;
			return dest;
		}

		INLINE auto WINAPI wstrlen(CONST WCHAR* s) -> INT
		{
			INT cnt = NULL;
			if (!s)
				return NULL;
			for (; *s != NULL; ++s)
				++cnt;
			return cnt * sizeof(WCHAR);
		}

		INLINE auto WINAPI wtolower(INT c) -> INT
		{
			if (c >= L'A' && c <= L'Z') return c - L'A' + L'a';
			return c;
		}


		INLINE auto WINAPI wstricmp(CONST WCHAR* cs, CONST WCHAR* ct) -> INT
		{
			if (cs && ct)
			{
				while (wtolower(*cs) == wtolower(*ct))
				{
					if (*cs == NULL && *ct == NULL) return NULL;
					if (*cs == NULL || *ct == NULL) break;
					cs++;
					ct++;
				}
				return wtolower(*cs) - wtolower(*ct);
			}
			return -1;
		}

		INLINE auto WINAPI init_unicode_str(CONST WCHAR* string_to_init) -> UNICODE_STRING
		{

			UNICODE_STRING string_init;
			if (string_to_init)
			{
				string_init.Length = wstrlen(string_to_init);
				string_init.MaximumLength = string_init.Length + sizeof(WCHAR);
				string_init.Buffer = (WCHAR*)string_to_init;
			}
			return string_init;
		}

		INLINE auto WINAPI strcmp(CONST CHAR* cs, CONST CHAR* ct) -> INT
		{
			if (cs && ct)
			{
				while (*cs == *ct)
				{
					if (*cs == NULL && *ct == NULL) return NULL;
					if (*cs == NULL || *ct == NULL) break;
					cs++;
					ct++;
				}
				return *cs - *ct;
			}
			return -1;
		}

		INLINE auto WINAPI get_module_address(uint64_t hash_module) -> PVOID
		{
			LDR_DATA_TABLE_ENTRY* modEntry = nullptr;

#ifdef _WIN64
			PEB* peb = (PEB*)__readgsqword(0x60);

#else
			PEB* peb = (PEB*)__readfsdword(0x30);
#endif

			LIST_ENTRY head = peb->Ldr->InMemoryOrderModuleList;

			LIST_ENTRY curr = head;

			for (auto curr = head; curr.Flink != &peb->Ldr->InMemoryOrderModuleList; curr = *curr.Flink)
			{
				LDR_DATA_TABLE_ENTRY* mod = (LDR_DATA_TABLE_ENTRY*)CONTAINING_RECORD(curr.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

				if (mod->BaseDllName.Buffer)
				{
					if (!hash_module)
					{
						modEntry = mod;
						break;
					}
					if (hash_module == fnv::hash_runtime(mod->BaseDllName.Buffer))
					{
						modEntry = mod;
						break;
					}
				}
			}
			if (modEntry)
				return reinterpret_cast<PVOID>(modEntry->DllBase);
			return NULL;
		}

		INLINE auto WINAPI  get_proc_address(PVOID base_module, uint64_t hash_str) -> PVOID
		{
			DWORD64 base = (DWORD64)base_module;
			if (!base)
				return NULL;

			auto image_dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
			if (image_dos->e_magic != IMAGE_DOS_SIGNATURE)
				return NULL;

			auto image_nt_head = reinterpret_cast<PIMAGE_NT_HEADERS>(base + image_dos->e_lfanew);
			if (image_nt_head->Signature != IMAGE_NT_SIGNATURE)
				return NULL;

			auto pExport = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(base + image_nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
			if (!pExport)
				return NULL;

			//reinterpret_cast break this
			auto names = (PDWORD)(base + pExport->AddressOfNames);
			auto ordinals = (PWORD)(base + pExport->AddressOfNameOrdinals);
			auto functions = (PDWORD)(base + pExport->AddressOfFunctions);

			if (!names || !ordinals || !functions)
				return NULL;

			for (uint32_t i = NULL; i < pExport->NumberOfFunctions; ++i)
			{
				auto name = reinterpret_cast<CHAR*>(base + names[i]);
				if (hash_str == fnv::hash_runtime(name))
					return  reinterpret_cast<PVOID>(base + functions[ordinals[i]]);
			}
			return NULL;
		}

		//SharrOD bypass if map file
		NO_INLINE auto WINAPI get_address_by_rva(CONST WCHAR* name_module, PVOID mapped_base, uint64_t hash_str) -> PVOID
		{
			bool is_pe_machine_correct = FALSE;
			uint64_t rva_offset = NULL;
			uint64_t address_api = NULL;

			DWORD64 base = (DWORD64)get_module_address(fnv::hash_runtime(name_module));
			if (!base || !mapped_base)
				return NULL;

			auto image_dos_map = reinterpret_cast<PIMAGE_DOS_HEADER>(mapped_base);
			if (image_dos_map->e_magic != IMAGE_DOS_SIGNATURE)
				return NULL;

			auto image_dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
			if (image_dos->e_magic != IMAGE_DOS_SIGNATURE)
				return NULL;

			auto image_nt_head_map = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<uint64_t>(mapped_base) + image_dos_map->e_lfanew);
			if (image_nt_head_map->Signature != IMAGE_NT_SIGNATURE)
				return NULL;

			auto image_nt_head = reinterpret_cast<PIMAGE_NT_HEADERS>(base + image_dos->e_lfanew);
			if (image_nt_head->Signature != IMAGE_NT_SIGNATURE)
				return NULL;

			auto pExport = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(base + image_nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
			if (!pExport)
				return NULL;

			auto names = (PDWORD)(base + pExport->AddressOfNames);
			auto ordinals = (PWORD)(base + pExport->AddressOfNameOrdinals);
			auto functions = (PDWORD)(base + pExport->AddressOfFunctions);

			if (!names || !ordinals || !functions)
				return NULL;

			for (uint32_t i = NULL; i < pExport->NumberOfFunctions; ++i)
			{
				auto name = reinterpret_cast<CHAR*>(base + names[i]);
				if ((name[0] == 'N' && name[1] == 't') || (name[0] == 'Z' && name[1] == 'w'))
				{
					if (hash_str == fnv::hash_runtime(name))
						address_api = base + functions[ordinals[i]];
				}
			}

			is_pe_machine_correct = image_nt_head->FileHeader.Machine == image_nt_head_map->FileHeader.Machine;
			if (is_pe_machine_correct && address_api && address_api > base && base + image_nt_head->OptionalHeader.SizeOfImage > address_api)
			{
				rva_offset = address_api - base;
				return  reinterpret_cast<PVOID>(reinterpret_cast<uint64_t>(mapped_base) + rva_offset);
			}
			return NULL;
		}

	}


	class syscall_help_map
	{
	private:

		//map module
		PVOID mapped_module = NULL;


		INLINE auto WINAPI get_syscall_id(ZyanU64 address_fun) -> uint32_t
		{
			ZyanU64 runtime_address = address_fun;
			ZydisDisassembledInstruction instruction = { NULL };

#ifndef _WIN64
			if (ZYAN_SUCCESS(ZydisDisassembleIntel
			(
				dis_mode,
				runtime_address,
				reinterpret_cast<uint8_t*>(runtime_address),
				MAX_LENGHT_INSTR,
				&instruction
			)))
			{
				if (
					instruction.info.mnemonic == ZYDIS_MNEMONIC_MOV &&
					instruction.info.operand_count_visible == 2 &&
					instruction.operands->type == ZYDIS_OPERAND_TYPE_REGISTER &&
					instruction.operands->reg.value == ZYDIS_REGISTER_EAX &&
					instruction.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE
					)
				{
					return instruction.operands[1].imm.value.u;
				}
			}
#else


			if (ZYAN_SUCCESS(ZydisDisassembleIntel
			(
				dis_mode,
				runtime_address,
				reinterpret_cast<uint8_t*>(runtime_address),
				MAX_LENGHT_INSTR,
				&instruction
			)))
			{
				runtime_address += instruction.info.length;
				if (instruction.info.mnemonic == ZYDIS_MNEMONIC_MOV &&
					instruction.info.operand_count_visible == 2 &&
					instruction.operands->type == ZYDIS_OPERAND_TYPE_REGISTER &&
					instruction.operands->reg.value == ZYDIS_REGISTER_R10 &&
					instruction.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
					instruction.operands[1].reg.value == ZYDIS_REGISTER_RCX &&
					ZYAN_SUCCESS(ZydisDisassembleIntel
					(
						dis_mode,
						runtime_address,
						reinterpret_cast<uint8_t*>(runtime_address),
						MAX_LENGHT_INSTR,
						&instruction
					)))
				{
					if (
						instruction.info.mnemonic == ZYDIS_MNEMONIC_MOV &&
						instruction.info.operand_count_visible == 2 &&
						instruction.operands->type == ZYDIS_OPERAND_TYPE_REGISTER &&
						instruction.operands->reg.value == ZYDIS_REGISTER_EAX &&
						instruction.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE
						)
					{
						return instruction.operands[1].imm.value.u;
					}

				}
			}

#endif // !_WIN64
			return NULL;
		}

	public:

		NO_INLINE auto WINAPI map_get_syscall(CONST WCHAR* name_module, uint64_t hahs_str) -> INT
		{
			INT syscall_number = NULL;
			SIZE_T viewSize = NULL;
			HANDLE secthion_handle = NULL;
			PVOID functhion_address = NULL; 
			UNICODE_STRING secthion_name = { NULL };
			OBJECT_ATTRIBUTES obj_attribut = { NULL };
			NTSTATUS nt_status = STATUS_UNSUCCESSFUL;
			WCHAR buffer[MAX_PATH];

		crt_wrapper:memset(buffer, NULL, MAX_PATH);

#ifdef _WIN64
			crt_wrapper::str_cat_w(buffer, L"\\KnownDlls\\");
#else 
			crt_wrapper::str_cat_w(buffer, L"\\KnownDlls32\\");
			/*
			if (process_platrorm == PROCESS_WOW64)
				crt_wrapper::str_cat_w(buffer, L"\\KnownDlls32\\");
			else
				crt_wrapper::str_cat_w(buffer, L"\\KnownDlls\\");
			*/
#endif   
			if (!mapped_module)
			{
				crt_wrapper::str_cat_w(buffer, name_module);

				secthion_name = crt_wrapper::init_unicode_str(buffer);

				InitializeObjectAttributes(&obj_attribut, &secthion_name, OBJ_CASE_INSENSITIVE, NULL, NULL);

				nt_status = LI_FN(NtOpenSection).nt_cached()(&secthion_handle, SECTION_MAP_READ, &obj_attribut);

				if (!NT_SUCCESS(nt_status))
					return NULL;

				nt_status = LI_FN(NtMapViewOfSection).nt_cached()(secthion_handle, NtCurrentProcess, &mapped_module, NULL, NULL, nullptr,
					&viewSize, (SECTION_INHERIT)1, NULL, PAGE_READONLY);

				if (!NT_SUCCESS(nt_status))
				{
					if (secthion_handle)
						CloseHandle(secthion_handle);
					return NULL;
				}
			}
			if (mapped_module)
			{
				functhion_address = crt_wrapper::get_address_by_rva(name_module, mapped_module, hahs_str);

				if (functhion_address)
				{
					syscall_number = get_syscall_id(reinterpret_cast<ZyanU64>(functhion_address));
				}

				if (secthion_handle)
				{
					CloseHandle(secthion_handle);
					secthion_handle = NULL;
				}

			}
			return syscall_number;
		}

		INLINE auto WINAPI de_map_get_syscall() -> VOID
		{
			if (mapped_module)
				LI_FN(NtUnmapViewOfSection).nt_cached()(NtCurrentProcess, mapped_module);
			mapped_module = NULL;
		}
	};

}
#endif // !SYSCALL_DUMPER_ENABLE