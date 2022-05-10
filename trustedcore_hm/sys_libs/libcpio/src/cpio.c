/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: TEE environment's agent manager of framework Implemention
 * Create: 2020-06-05
 */

#include "cpio/cpio.h"

#ifndef ALIGN_UP
#define ALIGN_UP(val, al) (((val) + ((al) - 1)) & (~((al) - 1)))
#endif

#define HEX_NUMS                   8
#define DEC_NUMS                   10
#define HEX_MULTIPLY               4
#define CMP_NAME_FOOTER_FAILED     1
#define CMP_FAILED                 0
#define CPIO_PARSE_HEADER_INVALIED (-1)
#define CPIO_PARSE_SUCCESS         0
#define INVALIED_STR               0
#define EQUAL                      0
/*
 * Parse an ASCII hex string into an unsigned int integer
 *
 * @s: the hex string
 * @len: the length of the string
 *
 * Return unsigned int integer of the given string
 */
static uint32_t hex_to_uint(const char *str, uint32_t len)
{
    if (str == NULL)
        return INVALIED_STR;

    if (len > HEX_NUMS)
        len = HEX_NUMS;

    uint32_t ret = 0;
    uint32_t i;

    for (i = 0; i < len && str[i] != '\0'; i++) {
        ret <<= HEX_MULTIPLY;

        if (str[i] >= '0' && str[i] <= '9')
            ret += str[i] - '0';
        else if (str[i] >= 'a' && str[i] <= 'f')
            ret += str[i] - 'a' + DEC_NUMS;
        else if (str[i] >= 'A' && str[i] <= 'F')
            ret += str[i] - 'A' + DEC_NUMS;
        else
            return ret;
    }

    return ret;
}

/* Compare two strings in 'n' characters is equal or not */
static int32_t _strncmp(const char *str1, const char *str2, uint64_t str_len)
{
    if (str1 == NULL || str2 == NULL || str_len == 0)
        return CMP_FAILED;

    uint64_t i;

    for (i = 0; i < str_len; i++) {
        if (str1[i] != str2[i])
            return str1[i] - str2[i];
        if (str1[i] == 0)
            return EQUAL;
    }

    return EQUAL;
}

/*
 * Parse the header of the given CPIO entry
 *
 * @archive: The location of the CPIO archive
 * @filename: File name parsed
 * @filesize: File size parsed
 * @filedata: File data parsed
 * @next: Point to next CPIO entry
 *
 * Return 0 if success, -1 if the header is not valid, 1 if EOF.
 */
int32_t cpio_parse_entry(const struct cpio_header *archive, const char **filename, uint32_t *filesize,
                         void **filedata, struct cpio_header **next)
{
    uint32_t name_len;
    uint32_t size;
    uint32_t str_len;

    if (archive == NULL || next == NULL)
        return CPIO_PARSE_HEADER_INVALIED;

    if (_strncmp(archive->c_magic, CPIO_HEADER_MAGIC, CPIO_HEADER_MAGIC_LEN) != EQUAL)
        return CPIO_PARSE_HEADER_INVALIED;

    /* Parse header file name */
    const char *name = (char *)archive + sizeof(*archive);
    name_len = hex_to_uint(archive->c_namesize, sizeof(archive->c_namesize));
    if ((uintptr_t)name + name_len < (uintptr_t)name)
        return CPIO_PARSE_HEADER_INVALIED;

    /* Reach EOF */
    str_len = (name_len > CPIO_FOOTER_MAGIC_LEN) ? CPIO_FOOTER_MAGIC_LEN : name_len;
    if (_strncmp(name, CPIO_FOOTER_MAGIC, str_len) == CMP_FAILED)
        return CMP_NAME_FOOTER_FAILED;

    /* Parse header file data */
    size = hex_to_uint(archive->c_filesize, sizeof(archive->c_filesize));
    void *data = (void *)(uintptr_t)ALIGN_UP(((uintptr_t)name + name_len), CPIO_ALIGNMENT);
    if ((uintptr_t)data < (uintptr_t)name + name_len)
        return CPIO_PARSE_HEADER_INVALIED;

    if (filename != NULL)
        *filename = name;
    if (filesize != NULL)
        *filesize = size;
    if (filedata != NULL)
        *filedata = data;

    /* Get next entry header */
    uintptr_t next_addr = (uintptr_t)ALIGN_UP(((uintptr_t)data + size), CPIO_ALIGNMENT);
    if (((uintptr_t)data + size < (uintptr_t)data) ||
        (next_addr < (uintptr_t)data + size))
        return CPIO_PARSE_HEADER_INVALIED;

    *next = (struct cpio_header *)next_addr;

    return CPIO_PARSE_SUCCESS;
}
