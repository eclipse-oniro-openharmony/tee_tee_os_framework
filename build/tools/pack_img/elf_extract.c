/*
 * Copyright (C) 2022 Huawei Technologies Co., Ltd.
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define EI_NIDENT  16
#define SHT_SYMTAB 2
#define SHT_STRTAB 3

#define MAX_ALLOC_SIZE 0xa000000
#define MAX_EH_SHNUM   0xfff0

/* refer to elf manpage */
#define EI_MAG0 0
#define ELFMAG0 0x7f
#define EI_MAG1 1
#define ELFMAG1 'E'
#define EI_MAG2 2
#define ELFMAG2 'L'
#define EI_MAG3 3
#define ELFMAG3 'F'

#define EI_CLASS   4
#define ELFCLASS32 1
#define ELFCLASS64 2

struct elf_shdr {
    uint32_t sh_name;      /* Section name (string tbl index) */
    uint32_t sh_type;      /* Section type */
#ifdef aarch64
    uint64_t sh_flags;     /* Section flags */
    uint64_t sh_addr;      /* Section virtual addr at execution */
    uint64_t sh_offset;    /* Section file offset */
    uint64_t sh_size;      /* Section size in bytes */
#else
    uint32_t    sh_flags;
    uint32_t    sh_addr;
    uint32_t    sh_offset;
    uint32_t    sh_size;
#endif
    uint32_t sh_link;      /* Link to another section */
    uint32_t sh_info;      /* Additional section information */
#ifdef aarch64
    uint64_t sh_addralign; /* Section alignment */
    uint64_t sh_entsize;   /* Entry size if section holds table */
#else
    uint32_t    sh_addralign;    /* Section alignment */
    uint32_t    sh_entsize;      /* Entry size if section holds table */
#endif
};

struct elf_ehdr {
    uint8_t eh_ident[EI_NIDENT]; /* Magic number and other info */
    uint16_t eh_type;            /* Object file type */
    uint16_t eh_machine;         /* Architecture */
    uint32_t eh_version;         /* Object file version */
#ifdef aarch64
    uint64_t eh_entry;           /* Entry point virtual address */
    uint64_t eh_phoff;           /* Program header table file offset */
    uint64_t eh_shoff;           /* Section header table file offset */
#else
    uint32_t    eh_entry;              /* Entry point32_t virtual address */
    uint32_t    eh_phoff;              /* Program header table file offset */
    uint32_t    eh_shoff;              /* Section header table file offset */
#endif
    uint32_t eh_flags;           /* Processor-specific flags */
    uint16_t eh_ehsize;          /* ELF header size in bytes */
    uint16_t eh_phentsize;       /* Program header table entry size */
    uint16_t eh_phnum;           /* Program header table entry count */
    uint16_t eh_shentsize;       /* Section header table entry size */
    uint16_t eh_shnum;           /* Section header table entry count */
    uint16_t eh_shstrndx;        /* Section header string table index */
};

static struct elf_ehdr *g_elf_head = NULL;
static struct elf_shdr *g_sec_head = NULL;
static FILE *g_infile = NULL;
static FILE *g_outfile = NULL;

static void out_clean(void)
{
    /* free all file and alloced mem */
    if (g_elf_head != NULL) {
        free(g_elf_head);
        g_elf_head = NULL;
    }

    if (g_sec_head != NULL) {
        free(g_sec_head);
        g_sec_head = NULL;
    }

    if (g_infile != NULL) {
        fclose(g_infile);
        g_infile = NULL;
    }

    if (g_outfile != NULL) {
        fclose(g_outfile);
        g_outfile = NULL;
    }
}

#define OPEN_FILE_ERROR_RET (-2)
#define ELF_HEAD_ERROR_RET  (-3)
#define ELF_TAB_ERROR_RET   (-4)

#define ELF_TYPE_INDEX   1
#define IN_FILE_INDEX    2
#define OUT_FILE_INDEX   3
#define PARAMS_NUM       4

static int32_t check_input_param(int32_t argc, char *argv[])
{
    if ((argc != PARAMS_NUM) || (argv == NULL)) {
        printf("Usage: \"elf_extract type infile outfile\"!!!\n");
        return -1;
    }

    /* check the input type */
    char *type = argv[ELF_TYPE_INDEX];
    if (strncmp(type, "rtosck", (strlen("rtosck") + 1))) {
        printf("Error:wrong type input\n");
        return -1;
    }

    /* open the infile rtosck elf */
    g_infile = fopen(argv[IN_FILE_INDEX], "rb");
    if (g_infile == NULL) {
        printf("Error:can't open file\n");
        return OPEN_FILE_ERROR_RET;
    }

    /* open the outfile rtosck image */
    g_outfile = fopen(argv[OUT_FILE_INDEX], "ab");
    if (g_outfile == NULL) {
        printf("Error:can't open file\n");
        return OPEN_FILE_ERROR_RET;
    }

    return 0;
}

static int32_t check_head_magic(void)
{
    if ((g_elf_head->eh_ident[EI_MAG0] != ELFMAG0) || (g_elf_head->eh_ident[EI_MAG1] != ELFMAG1) ||
        (g_elf_head->eh_ident[EI_MAG2] != ELFMAG2) || (g_elf_head->eh_ident[EI_MAG3] != ELFMAG3)) {
        printf("invalid elf magic\n");
        return ELF_HEAD_ERROR_RET;
    }
#ifdef aarch64
    if (g_elf_head->eh_ident[EI_CLASS] != ELFCLASS64) {
        printf("Error:elf class is not ELFCLASS64!\n");
        return ELF_HEAD_ERROR_RET;
    }
#else
    if (g_elf_head->eh_ident[EI_CLASS] != ELFCLASS32) {
        printf("Error:elf class is not ELFCLASS32!\n");
        return ELF_HEAD_ERROR_RET;
    }
#endif
    return 0;
}

static int32_t check_elf_head(void)
{
    int32_t ret;
    /* parse the elf header to get the elf detail */
    g_elf_head = malloc(sizeof(*g_elf_head));
    if (g_elf_head == NULL) {
        printf("Error:elf head read error!\n");
        return ELF_HEAD_ERROR_RET;
    }

    /* read count is 1, so should return 1 if it is succ */
    ret = (int32_t)fread(g_elf_head, sizeof(*g_elf_head), 1, g_infile);
    if (ret != 1) {
        printf("Error:elf head read error!\n");
        return ELF_HEAD_ERROR_RET;
    }

    ret = check_head_magic();
    if (ret != 0)
        return ret;

    if (g_elf_head->eh_shnum == 0) {
        printf("Error:elf head shnum is invalid!\n");
        return ELF_HEAD_ERROR_RET;
    }

    if (g_elf_head->eh_ehsize != sizeof(*g_elf_head) || g_elf_head->eh_shentsize != sizeof(*g_sec_head)) {
        printf("Error:elf head is invalid\n");
        return ELF_HEAD_ERROR_RET;
    }

    return 0;
}

static int32_t read_elf_section_head(void)
{
    int32_t ret;

    ret = check_elf_head();
    if (ret != 0)
        return ret;

    if (g_elf_head->eh_shnum > MAX_EH_SHNUM) {
        printf("Error:large shnum\n");
        return ELF_HEAD_ERROR_RET;
    }

    if (fseek(g_infile, g_elf_head->eh_shoff, SEEK_SET) != 0) {
        printf("Error:elf head read error!\n");
        return ELF_HEAD_ERROR_RET;
    }

    /* parse the section header to get the elf's section detail */
    if (g_elf_head->eh_shnum == 0) {
        printf("Error:elf head eh_shnum is zero!\n");
        return ELF_HEAD_ERROR_RET;
    }
    g_sec_head = malloc(sizeof(*g_sec_head) * g_elf_head->eh_shnum);
    if (g_sec_head == NULL) {
        printf("Error:elf head read error!\n");
        return ELF_HEAD_ERROR_RET;
    }

    /* read count is eh_shnum, so it should return eh_shnum when it is succ */
    ret = (int32_t)fread(g_sec_head, sizeof(*g_sec_head), g_elf_head->eh_shnum, g_infile);
    if (ret != g_elf_head->eh_shnum) {
        printf("Error:section head read error!\n");
        return ELF_HEAD_ERROR_RET;
    }

    return 0;
}

static int32_t read_sym_tab(const struct elf_shdr *sec_entry)
{
    int32_t ret;
    uint32_t symtab_offset = (uint32_t)sec_entry->sh_offset;
    uint32_t sym_tab_size  = (uint32_t)sec_entry->sh_size;

    if (sym_tab_size > MAX_ALLOC_SIZE || sym_tab_size == 0) {
        printf("symtab size is invalid\n");
        return ELF_TAB_ERROR_RET;
    }

    if (fseek(g_infile, symtab_offset, SEEK_SET) != 0) {
        printf("symtab fseek failed\n");
        return ELF_TAB_ERROR_RET;
    }
    if (sec_entry->sh_size == 0) {
        printf("ERROR:sec_entry sh_size is zero\n");
        return ELF_TAB_ERROR_RET;
    }
    char *sym_tab = malloc(sec_entry->sh_size);
    if (sym_tab == NULL) {
        printf("ERROR:malloc failed for sym_tab\n");
        return ELF_TAB_ERROR_RET;
    }

    /* read count is 1, so should return 1 if it is succ */
    if (fread(sym_tab, sec_entry->sh_size, 1, g_infile) != 1) {
        printf("symtab fread failed\n");
        ret = ELF_TAB_ERROR_RET;
        goto free_out;
    }

    /* write into out image file */
    if (fseek(g_outfile, 0, SEEK_END) != 0) {
        printf("symtab fseek outfile failed\n");
        ret = ELF_TAB_ERROR_RET;
        goto free_out;
    }

    /* write count is 1, so should return 1 if it is succ */
    if (fwrite(sym_tab, sym_tab_size, 1, g_outfile) != 1) {
        printf("symtab fwrite failedn");
        ret = ELF_TAB_ERROR_RET;
        goto free_out;
    }

    ret = 0;

free_out:
    free(sym_tab);
    sym_tab = NULL;
    return ret;
}

static int32_t read_str_tab(const struct elf_shdr *sec_entry)
{
    int32_t ret;
    /* read the rtosck strtab out */
    uint32_t strtab_offset = (uint32_t)sec_entry->sh_offset;

    if (sec_entry->sh_size > MAX_ALLOC_SIZE || sec_entry->sh_size == 0) {
        printf("strtab size is invalid\n");
        return ELF_TAB_ERROR_RET;
    }

    if (fseek(g_infile, strtab_offset, SEEK_SET) != 0) {
        printf("str fseek failed\n");
        return  ELF_TAB_ERROR_RET;
    }

    char *str_tab = malloc(sec_entry->sh_size);
    if (str_tab == NULL) {
        printf("ERROR:malloc failed for str_tab\n");
        return  ELF_TAB_ERROR_RET;
    }

    /* read count is 1, should return 1 if it is succ */
    if (fread(str_tab, sec_entry->sh_size, 1, g_infile) != 1) {
        printf("str fread failed\n");
        ret =  ELF_TAB_ERROR_RET;
        goto free_out;
    }

    /* write into out image file */
    if (fseek(g_outfile, 0, SEEK_END) != 0) {
        printf("str fseek failed\n");
        ret =  ELF_TAB_ERROR_RET;
        goto free_out;
    }

    /* write count is 1, should return 1 if it is succ */
    if (fwrite(str_tab, sec_entry->sh_size, 1, g_outfile) != 1) {
        printf("str fwrite failed\n");
        ret =  ELF_TAB_ERROR_RET;
        goto free_out;
    }

    ret = 0;

free_out:
    free(str_tab);
    str_tab = NULL;
    return ret;
}

int32_t main(int32_t argc, char *argv[])
{
    int32_t ret;
    int32_t i;
    int32_t j = 0;

    ret = check_input_param(argc, argv);
    if (ret != 0)
        goto out;

    ret = read_elf_section_head();
    if (ret != 0)
        goto out;

    struct elf_shdr *sec_entry = g_sec_head;
    /* traverse all section and get the symtab and strtab of elf */
    for (i = 0; i < g_elf_head->eh_shnum; i++) {
        if (sec_entry->sh_size == 0) {
            sec_entry++;
            continue;
        }

        /* read the symtab out */
        if (sec_entry->sh_type == SHT_SYMTAB) {
            ret = read_sym_tab(sec_entry);
            if (ret != 0) {
                printf("Error: read sym failed\n");
                goto out;
            }
        } else if (sec_entry->sh_type == SHT_STRTAB) {
            if (j != 0)
                continue;
            ret = read_str_tab(sec_entry);
            if (ret != 0) {
                printf("Error: read str failed\n");
                goto out;
            }
            j++;
        }
        sec_entry++;
    }

    /* ret should be success now */
    ret = 0;
out:
    out_clean();
    return ret;
}
