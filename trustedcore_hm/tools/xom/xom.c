/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: xom rewrite tool source.
 * Create: 2020-09-11
 */
#include <sys/mman.h>
#include <sys/stat.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdbool.h>
#include <malloc.h>
#include <elf.h>
#include <securec.h>
#include "insn.h"

void *g_file_start;
void *g_file_end;
entrytype g_text_start;
entrytype g_text_end;
void *g_text_ptr_start;
void *g_text_ptr_end;

entrytype g_xtext_start;
entrytype g_xtext_end;
void *g_copy_xtext_ptr_start;
void *g_xtext_ptr_start;
void *g_xtext_ptr_end;
entrytype g_xom32loc_start;
entrytype g_xom32loc_end;
void *g_xom32loc_ptr_start;
void *g_xom32loc_ptr_end;
bool g_xom32loc_find;
bool g_xtext_find;

static int check_arch(const Elf32_Ehdr *ehdr)
{
    if (ehdr->e_ident[EI_CLASS] == ELFCLASS32) {
        if (ehdr->e_ehsize != sizeof(Elf32_Ehdr) || ehdr->e_shentsize != sizeof(Elf32_Shdr)) {
            ERROR_XOM("error: unrecognized ET_EXEC/ET_DYN file:\n");
            return XOM32_REWRITE_FAIL;
        }
        return XOM32_SUCCESS;
    }
    ERROR_XOM("error: not a 32 ELF class %d\n", ehdr->e_ident[EI_CLASS]);
    return XOM32_REWRITE_FAIL;
}

static int check_type(Elf32_Ehdr *elf_head)
{
    if ((memcmp(ELFMAG, elf_head->e_ident, SELFMAG) != 0) ||
        (elf_head->e_type != ET_EXEC && elf_head->e_type != ET_DYN) ||
        (elf_head->e_ident[EI_VERSION] != EV_CURRENT)) {
        ERROR_XOM("xom32 error: unrecognized ET_EXEC/ET_DYN file\n");
        return XOM32_REWRITE_FAIL;
    }
    return XOM32_SUCCESS;
}

static int elf_file_check(void *map_address)
{
    Elf32_Ehdr *elf_head = (Elf32_Ehdr *)(map_address);
    if (check_arch(elf_head) != XOM32_SUCCESS)
        return XOM32_REWRITE_FAIL;
    if (check_type(elf_head) != XOM32_SUCCESS)
        return XOM32_REWRITE_FAIL;
    return XOM32_SUCCESS;
}

static inline Elf32_Shdr *elf32_get_section_table(Elf32_Ehdr *file)
{
    return (Elf32_Shdr *)(((char *)file) + file->e_shoff);
}
static inline char *elf32_get_string_table(Elf32_Ehdr *elf_file)
{
    Elf32_Shdr *sections = elf32_get_section_table(elf_file);
    return (char *)elf_file + sections[elf_file->e_shstrndx].sh_offset;
}
static inline char *elf32_get_segment_string_table(Elf32_Ehdr *elf_file)
{
    const Elf32_Ehdr *file_header = elf_file;

    return (file_header->e_shstrndx == 0) ? NULL : elf32_get_string_table(elf_file);
}

static inline char *elf32_get_section_name(Elf32_Ehdr *elf_file, uint32_t i)
{
    Elf32_Shdr *sections = elf32_get_section_table(elf_file);
    char *str_table      = elf32_get_segment_string_table(elf_file);

    return (str_table == NULL) ? "<corrupted>" : (str_table + sections[i].sh_name);
}
static inline uint16_t elf32_get_num_sections(Elf32_Ehdr *elf_file)
{
    return elf_file->e_shnum;
}
static inline uint32_t elf32_get_section_offset(Elf32_Ehdr *elf_file, uint32_t i)
{
    Elf32_Shdr *sections = elf32_get_section_table(elf_file);
    return sections[i].sh_offset;
}
static inline uint32_t elf32_get_section_size(Elf32_Ehdr *elf_file, uint32_t i)
{
    Elf32_Shdr *sections = elf32_get_section_table(elf_file);
    return sections[i].sh_size;
}
static inline uint32_t elf32_get_section_addr(Elf32_Ehdr *elf_file, uint32_t i)
{
    Elf32_Shdr *sections = elf32_get_section_table(elf_file);
    return sections[i].sh_addr;
}

static bool checkr(entrytype start, entrytype end, const void *start_ptr, const void *end_ptr)
{
    bool res;
    res = (end < start || end_ptr < start_ptr ||
           start_ptr < g_file_start || end_ptr > g_file_end);
    return !res;
}

static int get_info(void *map_address)
{
    Elf32_Ehdr *elf_file  = map_address;
    uint32_t num_sections = elf32_get_num_sections(elf_file);
    uint32_t i;
    for (i = 0; i < num_sections; i++) {
        char *s_name = elf32_get_section_name(elf_file, i);
        if (s_name == NULL)
            continue;
        entrytype off = (entrytype)elf32_get_section_offset(elf_file, i);
        entrytype len = (entrytype)elf32_get_section_size(elf_file, i);
        entrytype addr = (entrytype)elf32_get_section_addr(elf_file, i);
        if (strcmp(".xtext", s_name) == 0) {
            g_xtext_start = addr;
            g_xtext_end = addr + len;
            g_xtext_ptr_start = map_address + off;
            g_xtext_ptr_end = g_xtext_ptr_start + len;
            if (!checkr(g_xtext_start, g_xtext_end, g_xtext_ptr_start, g_xtext_ptr_end)) {
                ERROR_XOM("error: illegal xtext section range\n");
                return XOM32_REWRITE_FAIL;
            }
            g_xtext_find = true;
        }
        if (strcmp(".xomloc", s_name) == 0) {
            g_xom32loc_start = addr;
            g_xom32loc_end = addr + len;
            g_xom32loc_ptr_start = map_address + off;
            g_xom32loc_ptr_end = g_xom32loc_ptr_start + len;
            if (!checkr(g_xom32loc_start, g_xom32loc_end, g_xom32loc_ptr_start, g_xom32loc_ptr_end)) {
                ERROR_XOM("error: illegal xom32loc section range\n");
                return XOM32_REWRITE_FAIL;
            }
            g_xom32loc_find = true;
        }
        if (strcmp(".text", s_name) == 0) {
            g_text_start = addr;
            g_text_end = addr + len;
            g_text_ptr_start = map_address + off;
            g_text_ptr_end = g_text_ptr_start + len;
            if (!checkr(g_text_start, g_text_end, g_text_ptr_start, g_text_ptr_end)) {
                ERROR_XOM("error: illegal text section range\n");
                return XOM32_REWRITE_FAIL;
            }
            g_xtext_find = true;
        }
    }
    return XOM32_SUCCESS;
}

static bool range_check_ok()
{
    entrytype total = (g_xom32loc_end - g_xom32loc_start) / ENTRY_SIZE_BYTE;
    entrytype cur   = 0;
    entrytype *now  = g_xom32loc_ptr_start;
    while (cur < total) {
        DEBUG_XOM("xom record entry num %lu\n", total);
        entrytype num32 = *((now));
        DEBUG_XOM("xom32 record entry num %lu\n", num32);
        entrytype *tmptr = now + num32 + 1;
        entrytype tmp = cur + num32 + 1;
        if (tmptr < now || tmptr > (entrytype *)g_xom32loc_ptr_end || tmp < cur)
                return false;
        now = tmptr;
        cur = tmp;
        entrytype num64 = *now;
        DEBUG_XOM("xom64 record entry num %lu\n", num64);
        tmptr = now + num64 + 1;
        tmp = cur + num64 + 1;
        if (tmptr < now || tmptr > (entrytype *)g_xom32loc_ptr_end || tmp < cur)
                return false;
        now = tmptr;
        cur = tmp;
    }
    if (cur == total)
        return true;
    else
        return false;
}
static void xom32_init()
{
    g_xtext_find = false;
    g_xtext_start = g_xtext_end = 0;
    g_xtext_ptr_start = g_xtext_ptr_end = NULL;
    g_copy_xtext_ptr_start = NULL;

    g_xom32loc_find = false;
    g_xom32loc_start = g_xom32loc_end = 0;
    g_xom32loc_ptr_start = g_xom32loc_ptr_end = NULL;

    g_text_start = g_text_end = 0;
    g_text_ptr_start = g_text_ptr_end = NULL;
}


#define CODE64_OFFSET 2
#define CODE32_OFFSET 1
static insntype *get_code64_ptr(entrytype inaddr, insntype *ptr, entrytype *addr)
{
    ptr -= CODE64_OFFSET;
    inaddr -= sizeof(insntype) * CODE64_OFFSET;
    *addr = inaddr;
    DEBUG_XOM("code64 %x at %x\n", *ptr, *addr);
    return ptr;
}
static insntype *get_code32_ptr(entrytype inaddr, insntype *ptr, entrytype *addr)
{
    ptr -= CODE32_OFFSET;
    inaddr -= sizeof(insntype);
    *addr = inaddr;
    DEBUG_XOM("code32 %x at %x\n", *ptr, *addr);
    return ptr;
}
static inline insntype *get_data_ptr(entrytype inaddr, insntype *ptr, entrytype *addr)
{
    *addr = inaddr;
    DEBUG_XOM("data %x at %x\n", *ptr, *addr);
    return ptr;
}

static bool insn_valid(insntype insn, bool ldr32)
{
    int type = ins_type(insn);
    bool res = false;
    if (ldr32)
        res = (type == LDR_LITERAL);
    else
        res = (type == A32_ADR_ADD || type == A32_ADR_SUB);
    if (res == false) {
        ERROR_XOM("error: illegal 32 insn seq");
        return false;
    } else {
        return true;
    }
}

static int xtext_rewrite32_one(entrytype addr)
{
    DEBUG_XOM("rewrite xtext32 addr %x(%x-%x)\n", addr, g_xtext_start, g_xtext_end);
    if (!is_align(addr)) {
        ERROR_XOM("error: unalign insn addr %x\n", addr);
        return XOM32_REWRITE_FAIL;
    }
    entrytype code_addr = 0;
    entrytype data_addr = 0;
    insntype* ptr = (insntype *)(g_copy_xtext_ptr_start + (addr - g_xtext_start));
    insntype* data_ptr = get_data_ptr(addr, ptr, &data_addr);
    insntype* code_ptr = get_code32_ptr(addr, ptr, &code_addr);
    insntype insn = *code_ptr;
    if (!insn_valid(insn, true)) {
        ERROR_XOM("error: illegal 32 insn seq at %x, insn is %x\n", addr, insn);
        return XOM32_REWRITE_FAIL;
    }
    entrytype literal_addr = (entrytype)get_literal_addr(insn, code_addr);
    if (literal_addr != data_addr) {
        ERROR_XOM("error: record and insn32 seq unmatch %x, %x\n", data_addr, literal_addr);
        return XOM32_REWRITE_FAIL;
    }
    if (A32_GET_RD(insn) > GENERAL_REG_MAX) {
        ERROR_XOM("error: illegal rd reg index for ldr literal instr %x\n", addr);
        return XOM32_REWRITE_FAIL;
    }
    *code_ptr = gen_a32_instr_movw((insn & A32_COND_MASK), GET_LOW_HALFWORD((*data_ptr)), A32_GET_RD(insn));
    *(code_ptr + 1) = gen_a32_instr_movt((insn & A32_COND_MASK), GET_HIGH_HALFWORD((*data_ptr)), A32_GET_RD(insn));
    code_ptr++;
    code_ptr++;
    while (code_ptr <= data_ptr) {
        *code_ptr = NOP_INSN;
        code_ptr++;
    }
    return XOM32_SUCCESS;
}

static int xtext_rewrite64_one(entrytype addr)
{
    entrytype code_addr = 0;
    entrytype data_addr = 0;
    insntype* data_ptr = get_data_ptr(addr, (insntype *)(g_copy_xtext_ptr_start + (addr - g_xtext_start)), &data_addr);
    insntype* code_ptr = get_code64_ptr(addr, (insntype *)(g_copy_xtext_ptr_start
                                        + (addr - g_xtext_start)), &code_addr);
    insntype insn = *code_ptr;
    if (!insn_valid(*code_ptr, false))
        return XOM32_REWRITE_FAIL;
    insntype ins_next = *(code_ptr + 1);
    if (ins_type(ins_next) == A32_LDRD_IMM) {
        if (A32_GET_RD(insn) == A32_GET_RN(ins_next)) {
            entrytype literal_addr = 0;
            if (ins_type(insn) == A32_ADR_ADD)
                literal_addr = (entrytype)get_literal_addr_adr(insn, code_addr, true);
            else if (ins_type(insn) == A32_ADR_SUB)
                literal_addr = (entrytype)get_literal_addr_adr(insn, code_addr, false);
            if (literal_addr != data_addr) {
                ERROR_XOM("error: record & insn64 seq unmatch %x, %x\n", data_addr, literal_addr);
                return XOM32_REWRITE_FAIL;
            }
            if ((insn & A32_COND_MASK) != (ins_next & A32_COND_MASK)) {
                ERROR_XOM("error: illegal adr ldrd pair cond at %x\n", code_addr);
                return XOM32_REWRITE_FAIL;
            }
            *(code_ptr++) = gen_a32_instr_movw((insn & A32_COND_MASK), GET_LOW_HALFWORD(*data_ptr),
                                               A32_GET_RD(ins_next));
            *(code_ptr++) = gen_a32_instr_movt((insn & A32_COND_MASK), GET_HIGH_HALFWORD(*data_ptr),
                                               A32_GET_RD(ins_next));
            *(code_ptr++) = gen_a32_instr_movw((insn & A32_COND_MASK),
                                               GET_LOW_HALFWORD(*(data_ptr + 1)),
                                               A32_GET_RD(ins_next) + 1);
            *(code_ptr++) = gen_a32_instr_movt((insn & A32_COND_MASK),
                                               GET_HIGH_HALFWORD(*(data_ptr + 1)),
                                               A32_GET_RD(ins_next) + 1);
        } else {
            ERROR_XOM("error: unmatched reg index\n");
            return XOM32_REWRITE_FAIL;
        }
    } else {
        ERROR_XOM("error: illegal xom32 ldr64 insn req\n");
        return XOM32_REWRITE_FAIL;
    }
    return XOM32_SUCCESS;
}

static int xtext_rewrite()
{
    entrytype total = (g_xom32loc_end - g_xom32loc_start) / ENTRY_SIZE_BYTE;
    entrytype cur   = 0;
    entrytype *now  = g_xom32loc_ptr_start;
    entrytype i;
    while (cur < total) {
        entrytype num32 = *now;
        now++;
        i = 0;
        while (i < num32) {
            entrytype xtext_ptr = *now;
            if ((xtext_ptr < g_xtext_start || xtext_ptr >= g_xtext_end)
                && (xtext_ptr < g_text_start || xtext_ptr >= g_text_end)) {
                WARN_XOM("warn: xtext32 ptr addr not in range %x\n", xtext_ptr);
                now++;
                i++;
                continue;
            }
            if (xtext_rewrite32_one(xtext_ptr) != XOM32_SUCCESS)
                return XOM32_REWRITE_FAIL;
            now++;
            i++;
        }
        cur += num32 + 1;

        entrytype num64 = *now;
        now++;
        i = 0;
        while (i < num64) {
            entrytype xtext_ptr = (*now);
            if ((xtext_ptr < g_xtext_start || xtext_ptr >= g_xtext_end)
                && (xtext_ptr < g_text_start || xtext_ptr >= g_text_end)) {
                WARN_XOM("warn: xtext32 ptr addr not in range %x\n", xtext_ptr);
                now++;
                i++;
                continue;
            }
            if (xtext_rewrite64_one(xtext_ptr) != XOM32_SUCCESS)
                return XOM32_REWRITE_FAIL;
            now++;
            i++;
        }
        cur += num64 + 1;
    }
    return XOM32_SUCCESS;
}

static void freeptr(void **ptr)
{
    if (ptr != NULL && *ptr != NULL) {
        free(*ptr);
        *ptr = NULL;
    }
}

static int xom32_rewrite(void* elf_file)
{
    xom32_init();
    if (elf_file_check(elf_file) != XOM32_SUCCESS)
        return XOM32_REWRITE_FAIL;
    if (get_info(elf_file) != XOM32_SUCCESS)
        return XOM32_REWRITE_FAIL;
    if (g_xom32loc_find == true && g_xtext_find == false) {
        ERROR_XOM("error: xtext section not find\n");
        return XOM32_REWRITE_FAIL;
    }
    DEBUG_XOM("xtext: %lx - %lx, xom32loc: %lx - %lx\n",
        g_xtext_start, g_xtext_end, g_xom32loc_start, g_xom32loc_end);
    if (g_xom32loc_find != true) {
        DEBUG_XOM("no xom32loc record, return directly\n");
        return XOM32_SUCCESS;
    }
    if (!range_check_ok()) {
        ERROR_XOM("error: xom32loc record range_check_ok fail\n");
        return XOM32_REWRITE_FAIL;
    }
    g_copy_xtext_ptr_start = malloc(g_xtext_end - g_xtext_start);
    if (g_copy_xtext_ptr_start == NULL) {
        ERROR_XOM("error: alloc xtext copy mem fail\n");
        return XOM32_REWRITE_FAIL;
    }
    errno_t ret;
    ret = memcpy_s(g_copy_xtext_ptr_start, g_xtext_end - g_xtext_start,
                   g_xtext_ptr_start, g_xtext_end - g_xtext_start);
    if (ret != EOK) {
        ERROR_XOM("error: copy mem from src fail\n");
        freeptr(&g_copy_xtext_ptr_start);
        return XOM32_REWRITE_FAIL;
    }
    if (xtext_rewrite() != XOM32_SUCCESS) {
        freeptr(&g_copy_xtext_ptr_start);
        return XOM32_REWRITE_FAIL;
    }
    ret = memcpy_s(g_xtext_ptr_start, g_xtext_end - g_xtext_start,
                   g_copy_xtext_ptr_start, g_xtext_end - g_xtext_start);
    if (ret != EOK) {
        ERROR_XOM("error: copy mem to dst fail\n");
        freeptr(&g_copy_xtext_ptr_start);
        return XOM32_REWRITE_FAIL;
    }
    freeptr(&g_copy_xtext_ptr_start);
    return XOM32_SUCCESS;
}

int main(int argc, char* argv[])
{
    if (argc <= 1) {
        ERROR_XOM("error: too few input parameters\n");
        return XOM32_REWRITE_FAIL;
    }
    int fd = open(argv[1], O_RDWR);
    if (fd == -1) {
        ERROR_XOM("error: Could not open input file: %s\n", argv[1]);
        return XOM32_REWRITE_FAIL;
    }
    DEBUG_XOM("xom32 rewrite file %s\n", argv[1]);
    struct stat st;
    size_t fsz;
    if (fstat (fd, &st) == 0) {
        fsz = (size_t)st.st_size;
    } else {
        close(fd);
        ERROR_XOM("error: get file size fail\n");
        return XOM32_REWRITE_FAIL;
    }
    DEBUG_XOM("file size %d\n", fsz);
    void *map_address = mmap(NULL, fsz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (map_address == MAP_FAILED) {
        close(fd);
        ERROR_XOM("error: map elf failed\n");
        return XOM32_REWRITE_FAIL;
    }
    close(fd);
    g_file_start = map_address;
    g_file_end = g_file_start + fsz;
    return xom32_rewrite(map_address);
}
