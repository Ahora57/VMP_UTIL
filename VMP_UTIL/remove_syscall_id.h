#ifndef REMOVE_SYSCALL_ID
#define REMOVE_SYSCALL_ID 1

#include "init_address.h" 
#include "nt_api_def.h"
#include "minhook.h"

#define FAKE_VER_INT 0x1

#define STR(x) #x
#define VERSTR(x) STR(x)
#define FAKE_VERSION_WCHAR L"1" //VERSTR(FAKE_VER_INT)


#define ORIG_NAME (L"OriginalFilename")
#define REM_SIZE sizeof(ORIG_NAME) + sizeof(L"ntdll.dll") + sizeof(WCHAR)

namespace syscall_remove
{
	class remove_id
	{ 

	private:
 
        NO_INLINE static auto wtolower(INT c) -> INT
        {
            if (c >= L'A' && c <= L'Z') return c - L'A' + L'a'; 
            return c;
        }

          NO_INLINE static auto wstricmp(const WCHAR* cs, const WCHAR* ct) -> INT
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
        NO_INLINE static auto WINAPI wstrstr(const WCHAR* s, const WCHAR* find) -> WCHAR*
        {
            WCHAR c, sc;
            if ((c = *find++) != NULL)
            {
                do
                {
                    do
                    {
                        if ((sc = *s++) == NULL)
                            return 0;
                    } while (sc != c);
                } while (wstricmp(s, find) != 0);
                s--;
            }
            return (wchar_t*)s;
        }
        //https://github.com/x64dbg/ScyllaHide/blob/baa5c8e853ace2bee752631f27fdfe5b271d92f6/Scylla/VersionPatch.cpp#L14
        NO_INLINE static auto WINAPI  PatchFixedFileInfoVersion(PVOID Address, ULONG Size) -> BOOLEAN
        {
            BOOL found = FALSE;
            PUCHAR P;
            for (P = (PUCHAR)Address; P < (PUCHAR)Address + Size; ++P)
            {
                if (*(PDWORD)P == 0xFEEF04BD) // VS_FIXEDFILEINFO signature
                {
                    found = TRUE;
                    break;
                }
            }
            if (!found)
            {
                return FALSE;
            }

            P += 14; // Skip to FileVersion build number
            ULONG OldProtect;
            if (VirtualProtect(P, 10, PAGE_READWRITE, &OldProtect))
            {
                WORD Version = FAKE_VER_INT;
                WriteProcessMemory(NtCurrentProcess, P, &Version, 2, nullptr); // FileVersion
                WriteProcessMemory(NtCurrentProcess, P + 8, &Version, 2, nullptr); // ProductVersion
                VirtualProtect(P, 10, OldProtect, &OldProtect);
                return TRUE;
            }
            else
            {
                return FALSE;
            }
        }

        NO_INLINE static auto WINAPI   PatchVersionString(PVOID Address, ULONG Size, const WCHAR* Property) -> BOOLEAN
        {
            // VS_VERSIONINFO is a mess to navigate because it is a nested struct of variable size with (grand)children all of variable sizes
            // See: https://docs.microsoft.com/en-gb/windows/win32/menurc/vs-versioninfo
            // Instead of finding VS_VERSIONINFO -> StringFileInfo[] -> StringTable[] -> String (-> WCHAR[]) properly, just do it the memcmp way
            size_t propertyLen = (wcslen(Property) + 1) * 2;
            PUCHAR P = (PUCHAR)Address;
            BOOL found = FALSE;
            for (; P < (PUCHAR)Address + Size - propertyLen; ++P)
            {
                if (memcmp(P, Property, propertyLen) == 0)
                {
                    found = TRUE;
                    break;
                }
            }
            if (!found)
            {
                return FALSE;
            }

            // Skip to the version number and discard extra nulls
            P += propertyLen;
            while (*(PWCHAR)P == L'\0')
            {
                P += sizeof(WCHAR);
            }
             
            // P now points at e.g. 6.1.xxxx.yyyy or 10.0.xxxxx.yyyy. Skip the major and minor version numbers to get to the build number xxxx
            const ULONG Skip = init_info::inf_proc.syscall_rem.old_OSMajorVersion >= 10 ? 5 * sizeof(WCHAR) : 4 * sizeof(WCHAR);
            P += Skip;

            // Write a new bogus build number
            WCHAR NewBuildNumber[] = FAKE_VERSION_WCHAR;
            ULONG OldProtect;
            if (VirtualProtect(P, sizeof(NewBuildNumber) - sizeof(WCHAR), PAGE_READWRITE, &OldProtect))
            {
                SIZE_T NumWritten;
                WriteProcessMemory(NtCurrentProcess, P, NewBuildNumber, sizeof(NewBuildNumber) - sizeof(WCHAR), &NumWritten);
                VirtualProtect(P, sizeof(NewBuildNumber) - sizeof(WCHAR), OldProtect, &OldProtect);
                return TRUE;
            }
            return FALSE;
        }

        NO_INLINE static auto WINAPI ApplyNtdllVersionPatch(PVOID Ntdll) -> BOOLEAN
        {
            // Get the resource data entry for VS_VERSION_INFO
            LDR_RESOURCE_INFO ResourceIdPath;
            ResourceIdPath.Type = (ULONG_PTR)RT_VERSION;
            ResourceIdPath.Name = VS_VERSION_INFO;
            ResourceIdPath.Language = MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL);
            PIMAGE_RESOURCE_DATA_ENTRY ResourceDataEntry = nullptr;
            NTSTATUS Status = LI_FN(LdrFindResource_U).nt_cached()(Ntdll, &ResourceIdPath, 3, &ResourceDataEntry);
            if (!NT_SUCCESS(Status))
            {
                return FALSE;
            }

            // Get the address and size of VS_VERSION_INFO
            PVOID Address = nullptr;
            ULONG Size = 0;
            Status = LI_FN(LdrAccessResource).nt_cached()(Ntdll, ResourceDataEntry, &Address, &Size);
            if (!NT_SUCCESS(Status))
            {
                return FALSE;
            }
            if (Address == nullptr || Size == 0)
            {
                return FALSE;
            }

            return PatchFixedFileInfoVersion(Address, Size)  && PatchVersionString(Address, Size, L"FileVersion") && PatchVersionString(Address, Size, L"ProductVersion");
        }

        NO_INLINE static auto WINAPI  is_ntdll_original_name(PVOID Address) -> BOOLEAN
        {
            uint32_t size_res = NULL;
            DWORD64 base = (DWORD64)Address;
            CHAR* addr_res = NULL;

            if (!base)
                return FALSE;


            auto image_dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
            if (image_dos->e_magic != IMAGE_DOS_SIGNATURE)
                return FALSE;
            

            auto image_nt_head = reinterpret_cast<PIMAGE_NT_HEADERS>(base + image_dos->e_lfanew);
            if (image_nt_head->Signature != IMAGE_NT_SIGNATURE)
                return FALSE;

            addr_res = reinterpret_cast<CHAR*>(base + image_nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress);
            size_res = base + image_nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size;

            if (addr_res && size_res && size_res > sizeof(ORIG_NAME))
            {
                size_res -= REM_SIZE;
                for (uint32_t i = NULL;  size_res > i; i++)
                {
                    if (memcmp(reinterpret_cast<CHAR*>(base +i), ORIG_NAME,sizeof(ORIG_NAME)) == NULL)
                    {
                        return memcmp(reinterpret_cast<CHAR*>(base + i) + sizeof(ORIG_NAME), L"ntdll.dll", sizeof(L"ntdll.dll")) == NULL;
                    }
                }
            } 
            return FALSE;
        }
        NO_INLINE static auto WINAPI  is_correct_syscall(ZyanU64 address_fun) -> uint32_t
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
                    return TRUE;
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
                        return TRUE;
                    }

                }
            }

#endif // !_WIN64
            return FALSE;
        }
        NO_INLINE static auto WINAPI set_fake_syscall(PVOID api_addr)->BOOLEAN
        {
            DWORD old_prot = NULL;
            HANDLE access = NULL;

            uint8_t patch_syscall_wow[] =
            {
                0xB8, 0x00, 0x00, 0x00, 0x00 //mov eax, NULL
            };
            uint8_t patch_syscall_64[] =
            {
                0x4C, 0x8B, 0xD1,               //mov r10, rcx
                0xB8, 0x01, 0x00, 0x00, 0x00    //mov eax, NULL
            };

            if (is_correct_syscall(reinterpret_cast<ZyanU64>(api_addr)))
            {

                access = OpenProcess(PROCESS_VM_OPERATION, FALSE, (DWORD)NtCurrentProcessId());
                if (access && VirtualProtectEx(access, api_addr, PAGE_SIZE, PAGE_READWRITE, &old_prot))
                {
#ifndef _WIN64
                    memcpy(api_addr, patch_syscall_wow, sizeof(patch_syscall_wow));

#else
                    //memset(api_addr, NULL, sizeof(patch_syscall_64));

                   memcpy(api_addr, patch_syscall_64, sizeof(patch_syscall_64));
#endif // !_WIN64

                    VirtualProtectEx(access, api_addr, PAGE_SIZE, old_prot, &old_prot);
                    CloseHandle(access);
                    return TRUE;
                }
            }
            return FALSE;
        }

        NO_INLINE static auto WINAPI remove_syscall(PVOID base_ntdll) -> BOOLEAN
        {
            BOOLEAN is_success = TRUE;
            uint32_t rva_cur = NULL;
            HMODULE ntdll_base = NULL;
            uint32_t rva_api[12] = { NULL }; 
            CONST CHAR* list_api_patch[] =
            {
                "NtClose",
                "NtProtectVirtualMemory",
                "NtOpenFile",
                "NtCreateSection",
                "NtMapViewOfSection",
                "NtUnmapViewOfSection",
                "NtQueryInformationProcess",
                "NtSetInformationThread",
                "NtQueryVirtualMemory",
                "NtQuerySystemInformation",
                "NtOpenSection",
                "NtSetInformationProcess" //if we do correct we just can don't patch
            };
            if (!init_info::inf_proc.ntdll_base)
            {
                init_info::inf_proc.ntdll_base = GetModuleHandleW(L"ntdll.dll");
            }
            if (!ntdll_base)
                return FALSE;
            
            for (uint32_t i = NULL; i < _countof(list_api_patch); i++)
            {
                rva_api[i] = reinterpret_cast<CHAR*>(GetProcAddress(reinterpret_cast<HMODULE>(init_info::inf_proc.ntdll_base), list_api_patch[i])) - reinterpret_cast<CHAR*>(init_info::inf_proc.ntdll_base);
                if (!rva_api[i]  || !set_fake_syscall(reinterpret_cast<CHAR*>(base_ntdll) + rva_api[i]))
                {
                    is_success = FALSE;
                }
                else
                {
                    printf("remoce syscall id ->\t%s\n", list_api_patch[i]);
                }
            }
            return is_success && rva_api[NULL] != NULL;
        }

        
        static auto   NO_INLINE WINAPI remove_syscall_id(PVOID rsp_addr, BOOLEAN is_neg) -> BOOLEAN
        {
            BOOLEAN is_find = FALSE;
            uint32_t max_scan = NULL;
            ULONG point_mem = NULL;
            PULONGLONG pointer_stack = NULL;
            MEMORY_BASIC_INFORMATION mbi = { NULL };
             


            if (VirtualQuery(reinterpret_cast<CHAR*>(rsp_addr), &mbi, sizeof(mbi)))
            {
                max_scan = mbi.RegionSize - (reinterpret_cast<CHAR*>(rsp_addr) - mbi.BaseAddress) - sizeof(PVOID);
                for (uint32_t i = NULL; max_scan > i; i += sizeof(ULONG))
                {

                    point_mem = *reinterpret_cast<PULONG>(reinterpret_cast<CHAR*>(rsp_addr) + i);
                    if (init_info::is_syscall(point_mem))
                    {
                        *reinterpret_cast<PULONG>(reinterpret_cast<CHAR*>(rsp_addr) + i) = NULL;
                        is_find = TRUE;
                    }
                }

            }

            if (is_neg)
            {
                max_scan = 0x5500;
                for (uint32_t i = NULL; max_scan > i; i += sizeof(ULONG))
                {
                    if (!IsBadReadPtr(reinterpret_cast<CHAR*>(reinterpret_cast<CHAR*>(rsp_addr) - i), sizeof(PVOID)))
                    {
                        point_mem = *reinterpret_cast<uint32_t*>(reinterpret_cast<CHAR*>(rsp_addr) - i);
                        if (init_info::is_syscall(point_mem))
                        {
                            *reinterpret_cast<PULONG>(reinterpret_cast<CHAR*>(rsp_addr) - i) = NULL;
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
 

	public:
 
        static NTSTATUS NTAPI hooked_nt_unmap_sec
        (
            HANDLE ProcessHandle,
            PVOID  BaseAddress,
            PVOID p1,
            PVOID p2,
            PVOID p3// x64 - rsp + 0x28
        )
        {
            NTSTATUS nt_status = STATUS_UNSUCCESSFUL;
            PVOID rsp_addr = NULL;
            nt_status = reinterpret_cast<decltype(&NtUnmapViewOfSection)>(init_info::inf_proc.syscall_rem.orig_nt_unamp_sec)(ProcessHandle, BaseAddress);
            
            if (
                NT_SUCCESS(nt_status) && 
                ProcessHandle == NtCurrentProcess &&
                !init_info::inf_proc.syscall_rem.is_present
                )
            {
                if (BaseAddress == init_info::inf_proc.syscall_rem.map_addr)
                {
                    rsp_addr = &p3;
#ifndef _WIN64
                    remove_syscall_id(reinterpret_cast<CHAR*>(rsp_addr) - sizeof(PVOID) * 2, FALSE);

#else
                    remove_syscall_id(reinterpret_cast<CHAR*>(rsp_addr) - sizeof(PVOID) * 4 , TRUE);

#endif // !_WIN64

                    init_info::inf_proc.syscall_rem.is_present = TRUE;
                }
            }
            return nt_status;
        }
 
        static NTSTATUS NTAPI hooked_nt_map_sec
        (
            HANDLE          SectionHandle,
            HANDLE          ProcessHandle,
            PVOID*          BaseAddress,
            ULONG_PTR       ZeroBits,
            SIZE_T          CommitSize,
            PLARGE_INTEGER  SectionOffset,
            PSIZE_T         ViewSize,
            SECTION_INHERIT InheritDisposition,
            ULONG           AllocationType,
            ULONG           Win32Protect
        )
        {
            PIMAGE_NT_HEADERS  headers = NULL;
            NTSTATUS nt_status = STATUS_UNSUCCESSFUL;  
            nt_status =  reinterpret_cast<decltype(&NtMapViewOfSection)>(init_info::inf_proc.syscall_rem.orig_nt_map_sec)(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect);

             if (
                 NT_SUCCESS(nt_status) && 
                 ProcessHandle == NtCurrentProcess &&
                 !init_info::inf_proc.syscall_rem.is_present
                 )
             { 
                 if (is_ntdll_original_name(*BaseAddress))
                 {
                     init_info::inf_proc.syscall_rem.map_addr = *BaseAddress;

                     remove_syscall(*BaseAddress);
                     ApplyNtdllVersionPatch(*BaseAddress);
                 }
             }
             return  nt_status;
        }
        
       

        NO_INLINE  auto WINAPI create_hook_map_sec() -> BOOLEAN
        {
            PVOID target_hook = NULL;
            MH_STATUS mh_status;
             
            init_info::inf_proc.syscall_rem.is_present = FALSE;

            if (!init_info::inf_proc.ntdll_base)
            {
                init_info::inf_proc.ntdll_base = GetModuleHandleW(L"ntdll.dll");
            }

            if (!init_info::inf_proc.ntdll_base)
            {
                return FALSE;
            }

            target_hook = GetProcAddress(reinterpret_cast<HMODULE>(init_info::inf_proc.ntdll_base), "NtMapViewOfSection");

            mh_status = MH_Initialize();
            if (mh_status != MH_OK && mh_status != MH_ERROR_ALREADY_INITIALIZED)
            {
                return FALSE;
            }

            if (
                MH_CreateHook(target_hook, &hooked_nt_map_sec, &init_info::inf_proc.syscall_rem.orig_nt_map_sec) != MH_OK
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

        NO_INLINE  auto WINAPI create_hook_unmap_sec() -> BOOLEAN
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

            target_hook = GetProcAddress(reinterpret_cast<HMODULE>(init_info::inf_proc.ntdll_base), "NtUnmapViewOfSection");

            mh_status = MH_Initialize();
            if (mh_status != MH_OK && mh_status != MH_ERROR_ALREADY_INITIALIZED)
            {
                return FALSE;
            }

            if (
                MH_CreateHook(target_hook, &hooked_nt_unmap_sec, &init_info::inf_proc.syscall_rem.orig_nt_unamp_sec) != MH_OK
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
        NO_INLINE static auto WINAPI  patch_info()->BOOLEAN
        { 
            init_info::inf_proc.syscall_rem.old_OSMajorVersion = NtCurrentPeb()->OSMajorVersion;

            NtCurrentPeb()->OSMajorVersion = 1;
            NtCurrentPeb()->OSMinorVersion = 1; 
            NtCurrentPeb()->OSBuildNumber = FAKE_VER_INT; 
            
            if (!init_info::inf_proc.ntdll_base)
            {
                init_info::inf_proc.ntdll_base = GetModuleHandleW(L"ntdll.dll");
            }

            return  ApplyNtdllVersionPatch(init_info::inf_proc.ntdll_base);
        }
	};
	 
}

#endif // !REMOVE_SYSCALL_ID
