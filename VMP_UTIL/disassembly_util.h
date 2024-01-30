#ifndef ZYDIS_DISASSEMBLY_UTIL
#define ZYDIS_DISASSEMBLY_UTIL
#include <Zydis/Zydis.h>

#define MAX_LENGHT_INSTR 15

#ifndef _WIN64
#define dis_mode ZYDIS_MACHINE_MODE_LONG_COMPAT_32
#else
#define dis_mode ZYDIS_MACHINE_MODE_LONG_64
#endif // !_WIN64

namespace dis
{
    auto get_dis(ZydisDisassembledInstruction* instruction, CHAR* runtime_address) -> ZyanStatus
    {
        return ZydisDisassembleIntel
        (
            dis_mode,
            reinterpret_cast<ZyanU64>(runtime_address),
            runtime_address,
            MAX_LENGHT_INSTR,
            instruction
        );
    }
    auto is_jmp(ZydisDisassembledInstruction* instr) -> bool
    {
        switch (instr->info.mnemonic)
        {
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
        case ZYDIS_MNEMONIC_JMP:
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
            return ZYAN_TRUE;
        default:
            break;
        }
        return ZYAN_FALSE;
    }

    auto is_call(ZydisDisassembledInstruction* instr) -> bool
    {
        switch (instr->info.mnemonic)
        {
        case ZYDIS_MNEMONIC_CALL:
            return ZYAN_TRUE;
        default:
            break;
        }
        return ZYAN_FALSE;
    }

    bool is_selector(ZydisDisassembledInstruction* instr)
    {
        switch (instr->operands->reg.value)
        {
        case ZYDIS_REGISTER_SS:
        case ZYDIS_REGISTER_GS:
        case ZYDIS_REGISTER_FS:
        case ZYDIS_REGISTER_DS:
        case ZYDIS_REGISTER_ES:
        case ZYDIS_REGISTER_CS:
            return ZYAN_TRUE;
        default:
            break;
        }
        return ZYAN_FALSE;
    }
    ZyanU64 get_absolute_address(ZydisDisassembledInstruction* instruction,ZyanU64 runtime_address)
    {
        
        ZyanU64 destination = 0ULL;

        for (UINT i = NULL; i < instruction->info.operand_count; i++)
        {
            if ((instruction->operands[i].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && instruction->operands[i].imm.is_relative == TRUE) || instruction->operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                ZydisCalcAbsoluteAddress(&instruction->info, &instruction->operands[i], runtime_address, &destination);
                break;
            }

            if (instruction->operands[i].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && instruction->operands[i].imm.is_relative == FALSE)
            {
                destination = instruction->operands[i].imm.value.u;
                break;
            }
        }

        return destination;
    }

}
 
#endif 