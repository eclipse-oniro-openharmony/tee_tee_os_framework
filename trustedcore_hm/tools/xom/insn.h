/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: xom rewrite tool header.
 * Create: 2020-09-11
 */
#ifndef INSN_H
#define INSN_H

#define ERROR_XOM(...) fprintf(stderr, __VA_ARGS__)
#define WARN_XOM(...)  fprintf(stderr, __VA_ARGS__)
#ifdef CONFIG_DEBUG_XOM
#define DEBUG_XOM(...) fprintf(stdout, __VA_ARGS__)
#else
#define DEBUG_XOM(...)
#endif

#define XOM32_REWRITE_FAIL (-1)
#define XOM32_SUCCESS 0
#define RECORD_ZONE_NUM 2

#define NOP_INSN 0xe320f000
#define ALIGN_MASK 3
#define is_align(addr) (((addr) & ALIGN_MASK) == 0)

#define PC_ADJUST 8

typedef unsigned int insntype;
typedef unsigned int entrytype;
#define ENTRY_SIZE_BYTE sizeof(entrytype);

#define GENERAL_REG_MIN 0
#define GENERAL_REG_MAX 14

#define A32_COND_MASK 0xF0000000
#define A32_COND_SHIFT 28

#define A32_RD_MASK 0x0000F000
#define A32_RD_SHIFT 12
#define A32_RM_MASK 0x0000000F
#define A32_RM_SHIFT 0
#define A32_RN_MASK 0x000F0000
#define A32_RN_SHIFT 16

#define A32_GET_RD(ins) (insntype)(((ins) & A32_RD_MASK) >> A32_RD_SHIFT)
#define A32_GET_RM(ins) (insntype)(((ins) & A32_RM_MASK) >> A32_RM_SHIFT)
#define A32_GET_RN(ins) (insntype)(((ins) & A32_RN_MASK) >> A32_RN_SHIFT)

#define A32_VLDR_D_MASK 0x00400000
#define A32_VLDR_D_SHIFT 22
#define A32_VMOV_N_SHIFT 7
#define A32_VMOV_D_M_SHIFT 5

#define A32_VLDR_LITERAL_IMM8_MASK 0x000000FF

#define A32_INSTR_VLDR_LITERAL_MASK 0x0F3F0F00
#define A32_INSTR_VLDR_LITERAL 0x0D1F0A00

#define A32_INSTR_VLDR_DOUBLE_LITERAL_MASK 0x0F3F0F00
#define A32_INSTR_VLDR_DOUBLE_LITERAL 0x0D1F0B00

#define A32_LDR_LITERAL_IMM12_MASK 0x00000FFF
#define A32_JUMP_RELATIVE_IMM24_MASK 0x00FFFFFF

#define A32_INSTR_LDR_LITERAL_MASK 0x0F7F0000
#define A32_INSTR_LDR_LITERAL 0x051F0000
#define A32_INSTR_LDR_LITERAL_SYM_MASK 0x00800000
#define A32_INSTR_LDR_LITERAL_SYM_SHIFT 23

#define A32_INSTR_LDRSTR_PC_REGOFF_MASK 0x0FFF0FF0
#define A32_INSTR_LDR_PC_REGOFF 0x079F0000
#define A32_INSTR_STR_PC_REGOFF 0x078F0000

#define A32_INSTR_ADR_MASK 0x0FFF0000
#define A32_INSTR_ADR_ADD 0x028F0000
#define A32_INSTR_ADR_SUB 0x024F0000

#define A32_INSTR_LDRD_IMM_MASK 0x0FF00FFF
#define A32_INSTR_LDRD_IMM  0x01C000D0

#define A32_INSTR_LDRD_LITERAL_MASK 0x0F7F00F0
#define A32_INSTR_LDRD_LITERAL 0x014F00D0

#define A32_INSTR_LDR_IMM_MASK 0x0FF00FFF
#define A32_INSTR_LDR_IMM 0x05900000

#define A32_INSTR_LDM_MASK 0x0FF00000
#define A32_INSTR_LDM   0x08900000

#define A32_INSTR_ADD_PC_LITERAL_REGISTER_MASK 0x0FFF0FF0
#define A32_INSTR_ADD_PC_LITERAL_REGISTER 0x008F0000

#define A32_INSTR_JUMP_RELATIVE_ISBL_MASK 0x01000000
#define A32_INSTR_JUMP_RELATIVE_MASK 0x0E000000
#define A32_INSTR_JUMP_RELATIVE 0x0A000000

#define A32_INSTR_MOVW 0x03000000
#define A32_INSTR_MOVT 0x03400000
#define A32_MOV_IMM12_SHIFT 0
#define A32_MOV_IMM4_SHIFT 16

#define GET_HIGH_HALFWORD(x)    ((((insntype)(x)) >> 16) & 0x0000FFFF)
#define GET_LOW_HALFWORD(x) (((insntype)(x)) & 0x0000FFFF)
#define GET_MOV_IMM12(x)    ((insntype)(((insntype)(x) & 0x00000FFF) << A32_MOV_IMM12_SHIFT))
#define GET_MOV_IMM4(x)     ((insntype)(((insntype)(x) & 0x0000F000) << (A32_MOV_IMM4_SHIFT - 12)))

#define gen_a32_instr_movw(cond, imm16, rd) (insntype)((A32_INSTR_MOVW) | (insntype)(cond) | ((rd) << A32_RD_SHIFT) \
                        | GET_MOV_IMM4(imm16) | GET_MOV_IMM12(imm16))
#define gen_a32_instr_movt(cond, imm16, rd) (insntype)((A32_INSTR_MOVT) | (insntype)(cond) | ((rd) << A32_RD_SHIFT) \
                        | GET_MOV_IMM4(imm16) | GET_MOV_IMM12(imm16))
#define A32_R_NUM 16

enum xom_instr_type {
    A32_OTHER,
    LDR_LITERAL,
    ADD_LITERAL_REG_TO_PC,
    A32_JUMP,
    A32_JUMP_DST,
    A32_LITERAL,
    A32_LDR_IMM,
    A32_LDRD_IMM,
    A32_ADR_ADD,
    A32_ADR_SUB,
    A32_LDRD_LITERAL,
    A32_LDM,
    A32_VLDR_LITERAL,
    A32_VLDR_DOUBLE_LITERAL,
    TYPE_MAX
};

int ins_type(insntype instr)
{
    if ((instr & A32_INSTR_JUMP_RELATIVE_MASK) == A32_INSTR_JUMP_RELATIVE)
        return A32_JUMP;
    if ((instr & A32_INSTR_LDR_LITERAL_MASK) == A32_INSTR_LDR_LITERAL)
        return LDR_LITERAL;
    if ((instr & A32_INSTR_ADD_PC_LITERAL_REGISTER_MASK) == A32_INSTR_ADD_PC_LITERAL_REGISTER)
        return ADD_LITERAL_REG_TO_PC;
    if ((instr & A32_INSTR_LDRSTR_PC_REGOFF_MASK) == A32_INSTR_LDR_PC_REGOFF)
        return ADD_LITERAL_REG_TO_PC;
    if ((instr & A32_INSTR_LDRSTR_PC_REGOFF_MASK) == A32_INSTR_STR_PC_REGOFF)
        return ADD_LITERAL_REG_TO_PC;
    if ((instr & A32_INSTR_ADR_MASK) == A32_INSTR_ADR_ADD)
        return A32_ADR_ADD;
    if ((instr & A32_INSTR_ADR_MASK) == A32_INSTR_ADR_SUB)
        return A32_ADR_SUB;
    if ((instr & A32_INSTR_LDRD_IMM_MASK) == A32_INSTR_LDRD_IMM)
        return A32_LDRD_IMM;
    if ((instr & A32_INSTR_LDM_MASK) == A32_INSTR_LDM)
        return A32_LDM;
    if ((instr & A32_INSTR_LDRD_LITERAL_MASK) == A32_INSTR_LDRD_LITERAL)
        return A32_LDRD_LITERAL;
    if ((instr & A32_INSTR_VLDR_LITERAL_MASK) == A32_INSTR_VLDR_LITERAL)
        return A32_VLDR_LITERAL;
    if ((instr & A32_INSTR_VLDR_DOUBLE_LITERAL_MASK) == A32_INSTR_VLDR_DOUBLE_LITERAL)
        return A32_VLDR_DOUBLE_LITERAL;
    return A32_OTHER;
}

uint64_t get_literal_addr(insntype ins, uint64_t addr)
{
    insntype delta = (ins & A32_LDR_LITERAL_IMM12_MASK);
    insntype add = (ins & A32_INSTR_LDR_LITERAL_SYM_MASK) >> A32_INSTR_LDR_LITERAL_SYM_SHIFT;
    if (add == 1)
        return (addr + PC_ADJUST + delta);
    else
        return (addr + PC_ADJUST - delta);
}

static insntype lsr_c(insntype x, insntype n, insntype shift)
{
    (void)(n);
    return x >> shift;
}
static insntype lsr(insntype x, insntype n, insntype shift)
{
    if (shift == 0)
        return x;
    else
        return lsr_c(x, n, shift);
}

static insntype lsl_c(insntype x, insntype n, insntype shift)
{
    (void)(n);
    return x << shift;
}
static insntype lsl(insntype x, insntype n, insntype shift)
{
    if (shift == 0)
        return x;
    else
        return lsl_c(x, n, shift);
}

static insntype ror_c(insntype x, insntype n, insntype shift)
{
    insntype m = shift % n;
    return lsr(x, n, m) | lsl(x, n, n - m);
}
static insntype shift_c(insntype value, insntype n, insntype amount)
{
    if (amount == 0)
        return value;
    return ror_c(value, n, amount);
}

#define VALUE_MASK 0xFF
#define AMOUNT_MASK 0xF00
#define AMOUNT_SHIFT 8
#define SHIFT_NUM 32
#define MUL_VAL 2
static insntype armexpandimm_c(insntype imm32)
{
    insntype value = imm32 & VALUE_MASK;
    insntype amount = ((imm32 & AMOUNT_MASK) >> AMOUNT_SHIFT) * MUL_VAL;
    return shift_c(value, SHIFT_NUM, amount);
}

uint64_t get_literal_addr_adr(insntype ins, uint64_t addr, bool add)
{
    insntype imm32 = (ins & A32_LDR_LITERAL_IMM12_MASK);
    insntype delta = armexpandimm_c(imm32);
    if (add)
        return (addr + PC_ADJUST + delta);
    else
        return (addr + PC_ADJUST - delta);
}

#endif
