#include <Windows.h>
#include "anti_vm.h"
#include "single_step_hook.h"
#include "crc_check.h"
#include "import_help.h"
#include "remove_syscall_id.h"
#include "anti_debug.h"
 

BOOL APIENTRY DllMain
( 
    HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
                     
)
{
    FILE* file = NULL;
    PVOID cur_mod = NULL;

    single_step::single_step_hook single_step;
    anti_vm::ret_vm_str vm_str_patch;
    import_hook::import_hook import_vmp; 
    crc_check::alloce_base_hook crc_path;
    syscall_remove::remove_id rem_syscall;
    anti_debug::anti_debug hide_debug;
 
    switch (ul_reason_for_call)
    {



    case DLL_PROCESS_ATTACH:

    case DLL_THREAD_ATTACH:
    {
        cur_mod = GetModuleHandleW(NULL);
        AllocConsole(); 
        if (cur_mod && init_info::init_address(cur_mod, NULL) && !freopen_s(&file,"CONOUT$", "w", stdout))
        {
           
            NtCurrentPeb()->BeingDebugged = FALSE;
            init_info::inf_proc.single_removed = FALSE;

            
             

            
            if (crc_path.is_patch_crc_calc(cur_mod))
            {
                printf("find!\n");
            }
             

            
            if (!crc_path.create_hook_virt_mem())
            {
                printf("Bad Patch enable ret NtQueryVirtualMemory!\n");
            }
            

           vm_str_patch.patch_str_find(cur_mod);


            
             if (!import_vmp.patch_import_find(cur_mod))
             {
                 if (!import_vmp.patch_strcmp(cur_mod))
                 {
                     printf("Don't hook get import!\n");
                 }
             }
             
             
            
            
             if (rem_syscall.create_hook_map_sec() && rem_syscall.create_hook_unmap_sec() && rem_syscall.patch_info())
             {
                 printf("Enable remove syscall!\n");
             }
             
             
            if (!hide_debug.create_hook_proc() || !hide_debug.create_hook_thread() || !hide_debug.create_hook_nt_close())
            {
                printf("Bad enable anti-debug hook!\n");
            }
            
            
            
            

            
            if (hide_debug.create_hook_nt_contin())
            {
                if (hide_debug.enable_hwbp(NULL))
                {
                    printf("Enable HWBP Success!\n"); 
                }
                else
                {
                    printf("Bad HWBP enable!\n"); 
                }
             }
            else
            {
                printf("Bad create hook in NtContinue!\n");
            }
            
            AddVectoredExceptionHandler(TRUE, single_step.veh_hook);
            
        }
        break;
    }
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        RemoveVectoredExceptionHandler(single_step.veh_hook);

        break;
    }
    return TRUE;
}

