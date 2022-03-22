/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: TEE environment's agent manager of framework Implemention
 * Create: 2019-12-20
 */

#ifndef LIBCPIO_CPIO_H
#define LIBCPIO_CPIO_H

#include <stdint.h>
#include <stddef.h>

/* Magic identifiers for the CPIO entry format */
#define CPIO_HEADER_MAGIC     "070701"
#define CPIO_HEADER_MAGIC_LEN 6
#define CPIO_MEMBOR_LEN       8

/* File name for EOF of CPIO archive */
#define CPIO_FOOTER_MAGIC     "TRAILER!!!"
#define CPIO_FOOTER_MAGIC_LEN 10

/* Alignment for filename and data */
#ifdef __aarch64__
#define CPIO_ALIGNMENT 8
#else
#define CPIO_ALIGNMENT 4
#endif

struct cpio_header {
    char c_magic[CPIO_HEADER_MAGIC_LEN]; /* Magic header '070701' for files */
    char c_ino[CPIO_MEMBOR_LEN];         /* Inode number */
    char c_mode[CPIO_MEMBOR_LEN];        /* File type and mode */
    char c_uid[CPIO_MEMBOR_LEN];         /* User ID of owner */
    char c_gid[CPIO_MEMBOR_LEN];         /* Group ID of owner */
    char c_nlink[CPIO_MEMBOR_LEN];       /* Number of hard links */
    char c_mtime[CPIO_MEMBOR_LEN];       /* Time of last modification */
    char c_filesize[CPIO_MEMBOR_LEN];    /* Total size of file, in bytes */
    char c_devmajor[CPIO_MEMBOR_LEN];    /* Major device number */
    char c_devminor[CPIO_MEMBOR_LEN];    /* Minor device number */
    char c_rdevmajor[CPIO_MEMBOR_LEN];   /* Major device ID */
    char c_rdevminor[CPIO_MEMBOR_LEN];   /* Minor device ID */
    char c_namesize[CPIO_MEMBOR_LEN];    /* Length of filename, in bytes */
    char c_check[CPIO_MEMBOR_LEN];       /* Checksum */
};

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
int32_t cpio_parse_entry(const struct cpio_header *archive, const char **filename,
                         uint32_t *filesize, void **filedata, struct cpio_header **next);

#endif
