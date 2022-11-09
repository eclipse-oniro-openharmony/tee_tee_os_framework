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

#define _XOPEN_SOURCE 700
#define ARG_COUNTER 2

/*
 * We deliberately use HM's CPIO library rather than libarchive or similar so
 * we have the same interpretation of CPIO files as HM. This isn't strictly
 * essential, but it's nice for testing the robustness of this library.
 */
#include <cpio/cpio.h>

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <securec.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

/*
 * Synthesise an i-node number, inode number 0-10 may reserved by
 * some filesystem.
 */
#define INODE_RESERVED 11

static void clear_file_name_stuff(char *name)
{
    if (name == NULL)
        return;

    unsigned int sz = strlen(name);
    if (sz == 0)
        return;

    name += (--sz);
    while (sz) {
        if (*name == '#') {
            *name = '\0';
            name--;
            sz--;
        } else {
            break;
        }
    }
}

static int clean_cpio_header(struct cpio_header *header, const char *c_ino, int c_ino_len)
{
    errno_t ret_s = memcpy_s(header->c_ino, sizeof(header->c_ino), c_ino, c_ino_len);
    if (ret_s != EOK) {
        perror("ino memory copy failed\n");
        return -1;
    }

    /* Set the file owned by 'root' */
    ret_s = memset_s(header->c_uid, sizeof(header->c_uid), 0, sizeof(header->c_uid));
    if (ret_s != EOK) {
        perror("uid memory set failed\n");
        return -1;
    }
    ret_s = memset_s(header->c_gid, sizeof(header->c_gid), 0, sizeof(header->c_gid));
    if (ret_s != EOK) {
        perror("gid memory set failed\n");
        return -1;
    }

    /* Clean the modified time */
    ret_s = memset_s(header->c_mtime, sizeof(header->c_mtime), 0, sizeof(header->c_mtime));
    if (ret_s != EOK) {
        perror("mtime memory set failed\n");
        return -1;
    }

    /* Clean the dev num */
    ret_s = memset_s(header->c_devmajor, sizeof(header->c_devmajor), 0, sizeof(header->c_devmajor));
    if (ret_s != EOK) {
        perror("devmajor memory set failed\n");
        return -1;
    }
    ret_s = memset_s(header->c_devminor, sizeof(header->c_devminor), 0, sizeof(header->c_devminor));
    if (ret_s != EOK) {
        perror("devminor memory set failed\n");
        return -1;
    }

    return 0;
}

static int strip_cpio_entry(void *archive)
{
    struct cpio_header *next   = NULL;
    struct cpio_header *header = archive;
    const char *filename       = NULL;
    unsigned idx               = 0;

    while (header) {
        char c_ino[sizeof(header->c_ino) + 1] = { 0 };
        int ret;

        /* Get the header location */
        ret = cpio_parse_entry(header, &filename, NULL, NULL, &next);
        if (ret < 0) {
            errno = -EINVAL;
            perror("failed to locate entry");
            return -1;
        }

        /* Reach EOF */
        if (ret == 1)
            return 0;

        /* Set the file inode number */
        ret = snprintf_s(c_ino, sizeof(c_ino), sizeof(c_ino) - 1, "%08x", INODE_RESERVED + idx);
        if (ret < 0) {
            perror("the file inode number set failed\n");
            return -1;
        }

        ret = clean_cpio_header(header, c_ino, sizeof(header->c_ino));
        if (ret < 0) {
            perror("failed to clean cpio header\n");
            return -1;
        }

        /* clear filename suffix "##..." */
        clear_file_name_stuff((char *)filename);

        header = next;
        idx++;
    }

    return 0;
}

int main(int argc, char **argv)
{
    void *archive = NULL;
    int fd = -1;
    struct stat stat;
    int ret;

    if (argc != ARG_COUNTER) {
        fprintf(stderr,
                "Usage: %s file\n"
                " Strip meta data from a CPIO file\n",
                argv[0]);
        return -1;
    }

    fd = open(argv[1], O_RDWR);
    if (fd < 0) {
        perror("failed to open archive");
        return -1;
    }

    ret = fstat(fd, &stat);
    if (ret) {
        perror("failed to get stat of archive");
        goto fail;
    }

    /* Mmap the file */
    archive = mmap(NULL, stat.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (archive == MAP_FAILED) {
        perror("failed to mmap archive");
        archive = NULL;
        goto fail;
    }

    /* Strip each file entry */
    ret = strip_cpio_entry(archive);
    if (ret)
        goto fail2;

    if (munmap(archive, stat.st_size) != EOK)
        perror("munmap failed\n");

    close(fd);
    return 0;

fail2:
    if (munmap(archive, stat.st_size) != EOK)
        perror("strip failed and munmap failed\n");
fail:
    close(fd);
    return -1;
}
