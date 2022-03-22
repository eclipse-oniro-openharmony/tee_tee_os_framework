/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: tee scramb_syms
 * Create: 2019-12-20
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>
#include <endian.h>
#include <openssl/evp.h>
#include <securec.h>

#define FUNC_NAME_LEN        256
#define SUB_BYTE_LENGTH      8
#define SHA256_DIGEST_LENGTH 32
#define TEE_TASK_ENTRY       "tee_task_entry"
#define FALSE 0
#define TRUE 1
#define SCRAMB_ERR_GENERIC   (-2)
#define SCRAMB_ERR_ELF_HEAD  (-3)
#define ELF_ST_TYPE ELF32_ST_TYPE
#define CHIP_CHOOSE_LEN    16
#define STR_SUB_LEN    (SUB_BYTE_LENGTH * 2 + 1)

struct sym_info {
    Elf32_Sym *symtab;
    uint64_t symsz;
    uint64_t symoff;
    uint32_t symsec_idx;
};

struct str_info {
    char *strtab;
    uint64_t strsz;
    uint64_t stroff;
    uint32_t strsec_idx;
};

struct file_info {
    FILE *file;
    FILE *tb_file;
};

struct hdr_info {
    Elf32_Ehdr *ehdr;
    Elf32_Shdr *shdr;
};

struct mix_hash_params_t {
    char str_sub[STR_SUB_LEN];
    uint8_t hash_l[SHA256_DIGEST_LENGTH];
    uint8_t hash_f[SHA256_DIGEST_LENGTH];
};

struct mix_st_params_t {
    uint64_t index;
    uint64_t st_shndx;
    uint64_t st_info;
};

struct mix_name_params_t {
    char str_out[FUNC_NAME_LEN];
    char name_mix[FUNC_NAME_LEN];
    char *func_name;
};

struct mix_val_params_t {
    uint32_t name_val32;
    uint64_t name_val64;
};

struct sh_params_t {
    uint32_t symsize_val32;
    uint32_t symoff_val32;
    uint32_t strsize_val32;
    uint32_t stroff_val32;
    uint64_t symsize_val64;
    uint64_t symoff_val64;
    uint64_t strsize_val64;
    uint64_t stroff_val64;
};

struct hdr_info_t {
    Elf32_Shdr *shdr;
    Elf32_Sym *symtab;
    uint32_t symsec_idx;
    uint32_t strsec_idx;
    uint32_t sec_num;
    char *strtab;
};

#define DEFINE_ENDIAN_CONVERT_TO_HOST(w, e) \
    uint##w##_t _##e##w##toh(uint##w##_t input) \
    { \
        return e##w##toh(input); \
    } \
    uint##w##_t _hto##e##w(uint##w##_t input) \
    { \
        return hto##e##w(input); \
    }

DEFINE_ENDIAN_CONVERT_TO_HOST(16, le)
DEFINE_ENDIAN_CONVERT_TO_HOST(16, be)
DEFINE_ENDIAN_CONVERT_TO_HOST(32, le)
DEFINE_ENDIAN_CONVERT_TO_HOST(32, be)
DEFINE_ENDIAN_CONVERT_TO_HOST(64, le)
DEFINE_ENDIAN_CONVERT_TO_HOST(64, be)

#define LEN_OF_64_BITS    8
#define LEN_OF_32_BITS    4
#define LEN_OF_16_BITS    2
#define LEN_OF_8_BITS     1

static uint32_t mix_func_name(char *func_name_mix, uint32_t mix_len, char *chip_choose, const char *func_name,
                              uint32_t chip_len);
static void byte_to_string(char *str, const uint8_t *data, int32_t len);
static uint16_t (*r16)(uint16_t t16bits);
static uint32_t (*r32)(uint32_t t32bits);
static uint64_t (*r64)(uint64_t t64bits);
static uint16_t (*w16)(uint16_t h16bits);
static uint32_t (*w32)(uint32_t h32bits);
static uint64_t (*w64)(uint64_t h64bits);

static uint64_t get_64_shdr(uint64_t value64, int32_t *ret)
{
    uint64_t tmp = 0;
    switch (sizeof(value64)) {
    case LEN_OF_64_BITS:
        tmp = r64(value64);
        break;
    case LEN_OF_32_BITS:
        tmp = r32(value64);
        break;
    case LEN_OF_16_BITS:
        tmp = r16(value64);
        break;
    case LEN_OF_8_BITS:
        tmp = value64;
        break;
    default:
        *ret = SCRAMB_ERR_GENERIC;
        break;
    }
    return tmp;
}

static uint64_t get_32_shdr(uint32_t value32, int32_t *ret)
{
    uint64_t tmp = 0;
    switch (sizeof(value32)) {
    case LEN_OF_64_BITS:
        tmp = r64(value32);
        break;
    case LEN_OF_32_BITS:
        tmp = r32(value32);
        break;
    case LEN_OF_16_BITS:
        tmp = r16(value32);
        break;
    case LEN_OF_8_BITS:
        tmp = value32;
        break;
    default:
        *ret = SCRAMB_ERR_GENERIC;
        break;
    }
    return tmp;
}
static uint64_t get_shdr(uint32_t value32, uint64_t value64, char is_64, int32_t *ret)
{
    uint64_t tmp;
    if (is_64 == TRUE)
        tmp = get_64_shdr(value64, ret);
    else
        tmp = get_32_shdr(value32, ret);
    return tmp;
}

#define G_EHDR(field, width) ((is_64 == TRUE) ? r##width(ehdr_64->field) : r##width(ehdr->field))

#define S_EHDR(field, width, value) \
    ((is_64 == TRUE) ? (ehdr_64->field = w##width(value)) : (ehdr->field = w##width(value)))

static void set_64_shdr(Elf32_Sym *shdr, int32_t *ret, uint64_t value, uint32_t idx)
{
    switch (sizeof(((Elf64_Sym *)shdr + idx)->st_name)) {
    case LEN_OF_64_BITS:
        ((Elf64_Sym *)shdr + idx)->st_name = w64((uint64_t)value);
        break;
    case LEN_OF_32_BITS:
        ((Elf64_Sym *)shdr + idx)->st_name = w32((uint32_t)value);
        break;
    case LEN_OF_16_BITS:
        ((Elf64_Sym *)shdr + idx)->st_name = w16((uint16_t)value);
        break;
    case LEN_OF_8_BITS:
        ((Elf64_Sym *)shdr + idx)->st_name = (uint8_t)value;
        break;
    default:
        *ret = SCRAMB_ERR_GENERIC;
        break;
    }
}
static void set_32_shdr(Elf32_Sym *shdr, int32_t *ret, uint64_t value, uint32_t idx)
{
    switch (sizeof((shdr + idx)->st_name)) {
    case LEN_OF_64_BITS:
        (shdr + idx)->st_name = w64((uint64_t)value);
        break;
    case LEN_OF_32_BITS:
        (shdr + idx)->st_name = w32((uint32_t)value);
        break;
    case LEN_OF_16_BITS:
        (shdr + idx)->st_name = w16((uint16_t)value);
        break;
    case LEN_OF_8_BITS:
        (shdr + idx)->st_name = (uint8_t)value;
        break;
    default:
        *ret = SCRAMB_ERR_GENERIC;
        break;
    }
}
static void set_shdr(Elf32_Sym *shdr, char is_64, int32_t *ret, uint64_t value, uint32_t idx)
{
    if (is_64 == TRUE)
        set_64_shdr(shdr, ret, value, idx);
    else
        set_32_shdr(shdr, ret, value, idx);
}

static int32_t check_endian(const Elf32_Ehdr *ehdr)
{
    switch (ehdr->e_ident[EI_DATA]) {
    case ELFDATA2LSB:
        r16 = _le16toh;
        r32 = _le32toh;
        r64 = _le64toh;
        w16 = _htole16;
        w32 = _htole32;
        w64 = _htole64;
        break;
    case ELFDATA2MSB:
        r16 = _be16toh;
        r32 = _be32toh;
        r64 = _be64toh;
        w16 = _htobe16;
        w32 = _htobe32;
        w64 = _htobe64;
        break;
    default:
        fprintf(stderr, "unrecognized Elf data encoding %d\n", ehdr->e_ident[EI_DATA]);
        return -1;
    }
    return 0;
}

char g_chip_choose[CHIP_CHOOSE_LEN]     = "hikey_970";

static int32_t get_st_val(char is_64, const struct sym_info *sym_i, uint32_t i,
                          uint64_t *st_shndx, uint64_t *st_info)
{
        int32_t result = 0;
        uint32_t shndx_val32 = (sym_i->symtab + i)->st_shndx;
        uint64_t shndx_val64 = (is_64 == TRUE) ? ((Elf64_Sym*)sym_i->symtab + i)->st_shndx : 0;
        uint32_t info_val32 = (sym_i->symtab + i)->st_info;
        uint64_t info_val64 = (is_64 == TRUE) ? ((Elf64_Sym*)sym_i->symtab + i)->st_info : 0;
        *st_shndx = get_shdr(shndx_val32, shndx_val64, is_64, &result);
        if (result == SCRAMB_ERR_GENERIC)
            return result;
        *st_info = get_shdr(info_val32, info_val64, is_64, &result);
        if (result == SCRAMB_ERR_GENERIC)
            return result;
        return 0;
}


static int32_t do_mix_function_table(char is_64, struct sym_info *sym_i, const struct str_info *str_i,
                                     uint64_t *new_len, const struct file_info *file_i)
{
    int32_t result = 0;
    uint64_t i;
    struct mix_st_params_t  mix_st_params = { 0 };
    struct mix_hash_params_t mix_hash_params = { { 0 }, { 0 }, { 0 } };
    struct mix_val_params_t  mix_val_params = { 0 };
    struct mix_name_params_t mix_name_params = { { 0 }, { 0 }, NULL };
    uint32_t symnum = (is_64 == TRUE) ? (sym_i->symsz / sizeof(Elf64_Sym)) : (sym_i->symsz / sizeof(Elf32_Sym));
    for (i = 0; i < symnum; i++) {
        mix_val_params.name_val32 = (sym_i->symtab + i)->st_name;
        mix_val_params.name_val64 = (is_64 == TRUE) ? ((Elf64_Sym*)sym_i->symtab + i)->st_name : 0;
        mix_st_params.index = get_shdr(mix_val_params.name_val32, mix_val_params.name_val64, is_64, &result);
        if (mix_st_params.index >= str_i->strsz)
            return -1;
        result = get_st_val(is_64, sym_i, i, &mix_st_params.st_shndx, &mix_st_params.st_info);
        if (result == SCRAMB_ERR_GENERIC)
            return result;
        if ((mix_st_params.st_shndx != SHN_UNDEF) && (STT_FUNC == ELF_ST_TYPE(mix_st_params.st_info))) {
            mix_name_params.func_name = (char *)(str_i->strtab + mix_st_params.index);
            if (strcmp(mix_name_params.func_name, TEE_TASK_ENTRY) == 0)
                continue;
            /* use mix_func_name get name_mix_len */
            result = EVP_Digest(mix_name_params.name_mix, mix_func_name(mix_name_params.name_mix, FUNC_NAME_LEN,
                g_chip_choose, (const char*)mix_name_params.func_name, strlen(g_chip_choose)),
                mix_hash_params.hash_f, NULL, EVP_sha256(), NULL);
            if (result == 0)
                return -1;
            result = EVP_Digest(mix_hash_params.hash_f, SHA256_DIGEST_LENGTH, mix_hash_params.hash_l, NULL,
                                EVP_sha256(), NULL);
            if (result == 0)
                return -1;
            byte_to_string(mix_hash_params.str_sub, mix_hash_params.hash_l, SUB_BYTE_LENGTH);
            fwrite(mix_hash_params.str_sub, STR_SUB_LEN, 1, file_i->file);
            result = snprintf_s(mix_name_params.str_out, FUNC_NAME_LEN, FUNC_NAME_LEN - 1, "%s %s\n",
                                mix_hash_params.str_sub, mix_name_params.func_name);
            if (result == -1) {
                fprintf(stderr, "Error:Seek shdr error!\n");
                return result;
            }
            fputs(mix_name_params.str_out, file_i->tb_file);
            set_shdr(sym_i->symtab, is_64, &result, *new_len, i);
            if (result == SCRAMB_ERR_GENERIC)
                return result;
            *new_len += STR_SUB_LEN;
        }
    }
    return result;
}

static int32_t rewrite_shdr_32(const struct str_info *str_i, const struct hdr_info *hdr_i,
                               const struct file_info *file_i, const uint64_t *new_len, const uint64_t *new_str_off)
{
    uint64_t new_sech;
    int32_t ret = 0;
    Elf64_Ehdr *ehdr_64                   = (Elf64_Ehdr *)hdr_i->ehdr;
    Elf32_Ehdr *ehdr                      = hdr_i->ehdr;
    char is_64 = FALSE;
    uint64_t sec_off                      = G_EHDR(e_shoff, 32);

    Elf32_Shdr *sech = (Elf32_Shdr *)hdr_i->shdr + str_i->strsec_idx;
    sech->sh_size = w32(*new_len);
    sech->sh_offset = w32(*new_str_off);
    /* seek at the new position of sechs */
    new_sech = (sec_off + sizeof(Elf32_Shdr) * str_i->strsec_idx);
    if (new_sech < sec_off) {
        ret = -1;
        return ret;
    }

    if (fseek(file_i->file, (long)new_sech, SEEK_SET) < 0) {
        ret = SCRAMB_ERR_GENERIC;
        fprintf(stderr, "Error:Seek shdr error!\n");
        return ret;
    }
    fwrite(sech, sizeof(Elf32_Shdr), 1, file_i->file);
    return ret;
}

static int32_t rewrite_shdr_64(const struct str_info *str_i, const struct hdr_info *hdr_i,
                               const struct file_info *file_i, const uint64_t *new_len, const uint64_t *new_str_off)
{
    uint64_t new_sech;
    int32_t ret                           = 0;
    Elf64_Ehdr *ehdr_64                   = (Elf64_Ehdr *)hdr_i->ehdr;
    Elf32_Ehdr *ehdr                      = hdr_i->ehdr;
    char is_64                            = TRUE;
    uint64_t sec_off                      = G_EHDR(e_shoff, 64);
    /* rewrite shdr */
    Elf64_Shdr *sech = (Elf64_Shdr *)hdr_i->shdr + str_i->strsec_idx;
    sech->sh_size = w64(*new_len);
    sech->sh_offset = w64(*new_str_off);
    /* seek the position of strsec */
    new_sech = (sec_off + sizeof(Elf64_Shdr) * str_i->strsec_idx);
    if (new_sech < sec_off) {
        ret = -1;
        return ret;
    }

    if (fseek(file_i->file, (long)new_sech, SEEK_SET) < 0) {
        ret = SCRAMB_ERR_GENERIC;
        fprintf(stderr, "Error:Seek shdr error!\n");
        return ret;
    }
    fwrite(sech, sizeof(Elf64_Shdr), 1, file_i->file);
    return ret;
}
int32_t append_strtab(char is_64, struct sym_info *sym_i, struct str_info *str_i,
                      struct file_info *file_i, struct hdr_info *hdr_i)
{
    uint64_t new_len                       = str_i->strsz;
    uint64_t new_str_off;
    int32_t ret;

    fseek(file_i->tb_file, 0, SEEK_END);
    fseek(file_i->file, 0, SEEK_END);
    new_str_off = (uint64_t)ftell(file_i->file);
    if (new_str_off == (uint64_t)-1) {
        fprintf(stderr, "Error:ftell error!\n");
        ret = SCRAMB_ERR_GENERIC;
        return ret;
    }
    /* write the strtab to the end first */
    fwrite(str_i->strtab, str_i->strsz, 1, file_i->file);

    fputs(g_chip_choose, file_i->tb_file);

    if (is_64 == TRUE)
        fputs("\n=====================HMKERNEL FUNCTION TABLE BEGIN========================\n", file_i->tb_file);
    else
        fputs("\n=====================GLOBALTASK FUNCTION TABLE BEGIN========================\n", file_i->tb_file);

    ret = do_mix_function_table(is_64, sym_i, (const struct str_info *)str_i, &new_len,
                                (const struct file_info *)file_i);
    if (ret < 0)
        return ret;

    if (fseek(file_i->file, (long)sym_i->symoff, SEEK_SET) < 0) {
        ret = SCRAMB_ERR_GENERIC;
        fprintf(stderr, "Error:Seek shdr error!\n");
        return ret;
    }
    /* rewrite symtab */
    fwrite(sym_i->symtab, sym_i->symsz, 1, file_i->file);

    /* rewrite shdr */
    if (is_64 == TRUE)
        ret = rewrite_shdr_64(str_i, (const struct hdr_info *)hdr_i, (const struct file_info *)file_i,
                              &new_len, &new_str_off);
    else
        ret = rewrite_shdr_32(str_i, (const struct hdr_info *)hdr_i, (const struct file_info *)file_i,
                              &new_len, &new_str_off);

    return ret;
}

static int32_t prepare_append_strtab(char is_64, const Elf32_Shdr *shdr, struct sym_info *sym_i,
                                     struct str_info *str_i, FILE *file)
{
    int32_t ret = 0;
    struct sh_params_t params = { 0 };
    params.symsize_val32      = (shdr + sym_i->symsec_idx)->sh_size;
    params.symsize_val64      = (is_64 == TRUE) ? ((Elf64_Shdr*)shdr + sym_i->symsec_idx)->sh_size : 0;
    sym_i->symsz              = get_shdr(params.symsize_val32, params.symsize_val64, is_64, &ret);
    params.symoff_val32       = (shdr + sym_i->symsec_idx)->sh_offset;
    params.symoff_val64       = (is_64 == TRUE) ? ((Elf64_Shdr*)shdr + sym_i->symsec_idx)->sh_offset : 0;
    sym_i->symoff             = get_shdr(params.symoff_val32, params.symoff_val64, is_64, &ret);
    params.strsize_val32      = (shdr + str_i->strsec_idx)->sh_size;
    params.strsize_val64      = (is_64 == TRUE) ? ((Elf64_Shdr*)shdr + str_i->strsec_idx)->sh_size : 0;
    str_i->strsz              = get_shdr(params.strsize_val32, params.strsize_val64, is_64, &ret);
    params.stroff_val32       = (shdr + str_i->strsec_idx)->sh_offset;
    params.stroff_val64       = (is_64 == TRUE) ? ((Elf64_Shdr*)shdr + str_i->strsec_idx)->sh_offset : 0;
    str_i->stroff             = get_shdr(params.stroff_val32, params.stroff_val64, is_64, &ret);
    if (ret == SCRAMB_ERR_GENERIC)
        return ret;

    sym_i->symtab = malloc((size_t)sym_i->symsz);
    if (sym_i->symtab == NULL) {
        ret = SCRAMB_ERR_GENERIC;
        return ret;
    }
    if (fseek(file, (long)sym_i->symoff, SEEK_SET) < 0) {
        ret = SCRAMB_ERR_GENERIC;
        fprintf(stderr, "Error:Seek shdr error!\n");
        return ret;
    }
    if (fread(sym_i->symtab, (size_t)sym_i->symsz, 1, file) == 0) {
        ret = SCRAMB_ERR_GENERIC;
        fprintf(stderr, "Error read shdr error!\n");
        return ret;
    }

    str_i->strtab = malloc(str_i->strsz);
    if (str_i->strtab == NULL) {
        ret = SCRAMB_ERR_GENERIC;
        return ret;
    }
    if (fseek(file, (long)str_i->stroff, SEEK_SET) < 0) {
        ret = SCRAMB_ERR_GENERIC;
        fprintf(stderr, "Error:Seek shdr error!\n");
        return ret;
    }
    if (fread(str_i->strtab, (size_t)str_i->strsz, 1, file) == 0) {
        ret = SCRAMB_ERR_GENERIC;
        return ret;
    }
    return 0;
}

static int32_t init_shdr(char is_64, Elf32_Shdr **shdr, const Elf32_Ehdr *ehdr,
                         uint32_t sec_num, FILE *file)
{
    int32_t ret = 0;
    Elf64_Ehdr *ehdr_64 = NULL;
    ehdr_64             = (Elf64_Ehdr *)ehdr;
    if (is_64 == TRUE) {
        *shdr = malloc(sizeof(Elf64_Shdr) * sec_num);
        if (fseek(file, G_EHDR(e_shoff, 64), SEEK_SET) < 0) {
            fprintf(stderr, "Error:Seek shdr error!\n");
            ret = SCRAMB_ERR_GENERIC;
            return ret;
        }
        if (*shdr != NULL) {
            if (fread(*shdr, sizeof(Elf64_Shdr), sec_num, file) == 0) {
                fprintf(stderr, "Error read shdr error!\n");
                ret = SCRAMB_ERR_GENERIC;
                return ret;
            }
        } else {
            ret = SCRAMB_ERR_GENERIC;
            return ret;
        }
    } else {
        if (sec_num <= 0) {
            fprintf(stderr, "Error: zero-length or negative number allocation!\n");
            ret = SCRAMB_ERR_GENERIC;
            return ret;
        }
        *shdr = malloc(sizeof(Elf32_Shdr) * sec_num);
        if (fseek(file, G_EHDR(e_shoff, 32), SEEK_SET) < 0) {
            ret = SCRAMB_ERR_GENERIC;
            fprintf(stderr, "Error:Seek shdr error!\n");
            return ret;
        }
        if (*shdr != NULL) {
            if (fread(*shdr, sizeof(Elf32_Shdr), sec_num, file) == 0) {
                fprintf(stderr, "Error read shdr error!\n");
                ret = SCRAMB_ERR_GENERIC;
                return ret;
            }
        } else {
            ret = SCRAMB_ERR_GENERIC;
            return ret;
        }
    }
    return ret;
}

static int32_t init_sec_idx(char is_64, const Elf32_Shdr *shdr, const Elf32_Ehdr *ehdr,
                            uint32_t *symsec_idx, uint32_t *strsec_idx)
{
    uint32_t i;
    int32_t ret = 0;
    uint32_t sec_num;
    uint32_t secstr_idx;
    uint64_t sh_type;
    struct mix_val_params_t val_params = { 0 };
    Elf64_Ehdr *ehdr_64 = NULL;
    ehdr_64             = (Elf64_Ehdr *)ehdr;
    sec_num = G_EHDR(e_shnum, 16);
    secstr_idx = G_EHDR(e_shstrndx, 16);

    for (i = 0; i < sec_num; i++) {
        val_params.name_val32 = (shdr + i)->sh_type;
        val_params.name_val64 = (is_64 == TRUE) ? ((Elf64_Shdr*)shdr + i)->sh_type : 0;
        sh_type = get_shdr(val_params.name_val32, val_params.name_val64, is_64, &ret);
        if (ret == SCRAMB_ERR_GENERIC)
            return ret;
        if (sh_type == SHT_SYMTAB)
            *symsec_idx = i;
        if ((sh_type == SHT_STRTAB) && (i != secstr_idx))
            *strsec_idx = i;
    }
    return 0;
}

int32_t _scrab_syms(char is_64, const Elf32_Ehdr *ehdr, FILE *file, FILE *tb_file)
{
    struct hdr_info_t hdr_info = { 0 };
    Elf64_Ehdr *ehdr_64        = (Elf64_Ehdr *)ehdr;
    hdr_info.sec_num           = G_EHDR(e_shnum, 16);
    int32_t ret;

    if (hdr_info.sec_num == 0) {
        fprintf(stderr, "Error:elf head shnum is zero!\n");
        ret = SCRAMB_ERR_ELF_HEAD;
        goto out;
    }

    ret = init_shdr(is_64, &hdr_info.shdr, ehdr, hdr_info.sec_num, file);
    if (ret == SCRAMB_ERR_GENERIC)
        goto out;

    ret = init_sec_idx(is_64, hdr_info.shdr, ehdr, &hdr_info.symsec_idx, &hdr_info.strsec_idx);
    if (ret == SCRAMB_ERR_GENERIC)
        goto out;

    struct sym_info sym_i = { hdr_info.symtab, 0, 0, hdr_info.symsec_idx };
    struct str_info str_i = { hdr_info.strtab, 0, 0, hdr_info.strsec_idx };
    ret = prepare_append_strtab(is_64, hdr_info.shdr, &sym_i, &str_i, file);
    if (ret == SCRAMB_ERR_GENERIC)
        goto out;

    hdr_info.strtab = str_i.strtab;
    hdr_info.symtab = sym_i.symtab;

    struct file_info file_i = { file, tb_file };
    struct hdr_info hdr_i = { (Elf32_Ehdr *)ehdr, hdr_info.shdr };
    ret = append_strtab(is_64, &sym_i, &str_i, &file_i, &hdr_i);

out:
    if (hdr_info.strtab != NULL) {
        free(hdr_info.strtab);
        hdr_info.strtab = NULL;
        str_i.strtab = NULL;
    }

    if (hdr_info.symtab != NULL) {
        free(hdr_info.symtab);
        hdr_info.symtab = NULL;
        sym_i.symtab = NULL;
    }

    if (hdr_info.shdr != NULL) {
        free(hdr_info.shdr);
        hdr_info.shdr = NULL;
    }

    return ret;
}

int32_t scrab_sym(const Elf32_Ehdr *ehdr, FILE *file, FILE *tb_file)
{
    char is_64             = FALSE;
    Elf64_Ehdr * const ghdr = (Elf64_Ehdr *)ehdr;

    switch (ehdr->e_ident[EI_CLASS]) {
    case ELFCLASS32:
        if (r16(ehdr->e_ehsize) != sizeof(Elf32_Ehdr) || r16(ehdr->e_shentsize) != sizeof(Elf32_Shdr))
            fprintf(stderr, "unrecognized ET_EXEC/ET_DYN file:\n");
        break;
    case ELFCLASS64:
        if (r16(ghdr->e_ehsize) != sizeof(Elf64_Ehdr) || r16(ghdr->e_shentsize) != sizeof(Elf64_Shdr))
            fprintf(stderr, "unrecognized ET_EXEC/ET_DYN file\n");
        is_64 = TRUE;
        break;
    default:
        fprintf(stderr, "unrecognized ELF class %d\n", ehdr->e_ident[EI_CLASS]);
        return -1;
    }
    return _scrab_syms(is_64, ehdr, file, tb_file);
}

#define BYTE_TO_HEX_OFFSET    4
static void byte_to_hex(char *buf, uint8_t data)
{
    if (buf == NULL)
        return;

    const char str[] = "0123456789abcdef";
    uint8_t index    = (uint8_t)((data >> BYTE_TO_HEX_OFFSET) & 0x0F);
    *buf++           = (str[index]);
    *buf++           = str[data & 0x0F];
}

#define BYTE_TO_STRING_OFFSET 2
static void byte_to_string(char *str, const uint8_t *data, int32_t len)
{
    if (str == NULL || data == NULL)
        return;

    int32_t i;
    char *pbuf  = str;
    uint8_t *pdata = (uint8_t *)data;

    for (i = 0; i < len; i++) {
        byte_to_hex(pbuf, *pdata++);
        pbuf += BYTE_TO_STRING_OFFSET;
    }
}

static void revstr(char *str, uint32_t str_len)
{
    char *start = str;
    char *end   = str + str_len - 1;
    char ch;

    while (start < end) {
        ch       = *start;
        *start++ = *end;
        *end--   = ch;
    }
}

static uint32_t mix_func_name(char *func_name_mix, uint32_t mix_len, char *chip_choose, const char *func_name,
                              uint32_t chip_len)
{
    if (func_name_mix == NULL || func_name == NULL || chip_choose == NULL || mix_len == 0)
        return 0;

    /* reverse the chip_choose string */
    revstr(chip_choose, chip_len);
    char *pbuf     = func_name_mix;
    char *in_buf   = (char *)func_name;
    uint32_t i;
    uint32_t name_mix_len = 0;
    uint32_t n = 0;

    /* mix function name string */
    for (i = strlen(func_name); i != 0; i--) {
        if (name_mix_len > (mix_len - 1))
            break;

        pbuf[name_mix_len] = (char)(in_buf[i - 1] + i);
        name_mix_len++;

        if (n < strlen(chip_choose)) {
            if (name_mix_len > (mix_len - 1))
                break;
            pbuf[name_mix_len] = chip_choose[n];
            n++;
            name_mix_len++;
        }
    }
    pbuf[name_mix_len + 1] = '\0';
    revstr(chip_choose, chip_len);
    return name_mix_len;
}

static int32_t parse_elf_header(Elf32_Ehdr **elf_head, FILE *infile)
{
    /* parse the elf header to get the elf detail */
    *elf_head = (Elf32_Ehdr *)malloc(sizeof(Elf64_Ehdr));
    if (*elf_head == NULL) {
        fprintf(stderr, "Error:elf head read error!.\n");
        return SCRAMB_ERR_ELF_HEAD;
    }

    size_t len = fread(*elf_head, sizeof(Elf64_Ehdr), 1, infile);
    if (len == 0) {
        fprintf(stderr, "Error:elf head read error!.\n");
        return SCRAMB_ERR_ELF_HEAD;
    }

    if (check_endian(*elf_head) != 0) {
        return SCRAMB_ERR_ELF_HEAD;
    }

    return 0;
}
#define ARG_NUM    3
#define INFILE_ARG_INDEX    1
#define TBFILE_ARG_INDEX    2
int32_t main(int32_t argc, char *argv[])
{
    int32_t ret;
    Elf32_Ehdr *elf_head = NULL;
    FILE *infile         = NULL;
    FILE *tb_file        = NULL;

    if (argc < ARG_NUM) {
        fprintf(stderr, "Error:Incorrect parameters\n");
        ret = SCRAMB_ERR_GENERIC;
        goto out;
    }

    /* open the infile which globaltask or rtosck elf */
    infile = fopen(argv[INFILE_ARG_INDEX], "r+");
    if (infile == NULL) {
        fprintf(stderr, "Error:can't open file\n");
        ret = SCRAMB_ERR_GENERIC;
        goto out;
    }

    /* for release version, open the tb_file for func table output */
    tb_file = fopen(argv[TBFILE_ARG_INDEX], "a+");
    if (tb_file == NULL) {
        fprintf(stderr, "Error:can't open tb file\n");
        ret = SCRAMB_ERR_GENERIC;
        goto out;
    }

    ret = parse_elf_header(&elf_head, infile);
    if (ret != 0)
        goto out;

    if ((memcmp(ELFMAG, elf_head->e_ident, SELFMAG) != 0) ||
        ((r16(elf_head->e_type) != ET_EXEC && r16(elf_head->e_type) != ET_DYN)) ||
        (elf_head->e_ident[EI_VERSION] != EV_CURRENT))
        fprintf(stderr, "unrecognized ET_EXEC/ET_DYN file\n");

    ret = scrab_sym(elf_head, infile, tb_file);
    if (ret < 0)
        goto out;

    /* ret should be success now */
    ret = 0;
out:
    /* free all file and alloced mem */
    if (elf_head != NULL)
        free(elf_head);
    if (infile != NULL)
        fclose(infile);
    /* for release version should close func table file */
    if (tb_file != NULL)
        fclose(tb_file);
    return ret;
}
