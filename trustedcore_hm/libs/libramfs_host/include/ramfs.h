/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: ramfs header
 * Create: 2018-05-18
 */
#ifndef RAMFS_H
#define RAMFS_H

#include <autoconf.h>
#include <stdbool.h>

#include <sys/hm_fcntl.h>
#include <sys/libvfs.h>
#ifndef VFS_DATA_DEBUG
#warning VFS_DATA_DEBUG not defined
#endif

#include <limits.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define RAMFS_MAX_FDS CONFIG_RAMFS_MAX_FILES_OPEN

#define RAMFS_INODE_SIZE      128
#define RAMFS_INODE_DATA_SIZE 20
#define RAMFS_SUPER_SIZE      RAMFS_INODE_SIZE
#define RAMFS_SUPER_DATA_SIZE 12

#define RAMFS_MAGIC      "HMFS"
#define RAMFS_MAGIC_SIZE 4
#define RAMFS_VERSION    1

#define RAMFS_MAX_FILE_SIZE (16 * 1024 * 1024)

struct ramfs_super {
    unsigned char magic[RAMFS_MAGIC_SIZE];
    uint32_t version;
    uint32_t nr_files;
    uint8_t padding[RAMFS_INODE_SIZE - RAMFS_SUPER_DATA_SIZE];
};

struct ramfs_inode {
    char filename[RAMFS_INODE_SIZE - RAMFS_INODE_DATA_SIZE];
    uint32_t offset;
    uint32_t size;
    uint32_t uid;
    uint32_t gid;
    uint32_t mode;
};

struct ramfs_metadata {
    struct ramfs_super super;
    struct ramfs_inode inodes[];
};

#define ramfs_align_up(val, al) (((val) + ((al)-1)) & ~((al)-1))

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

static inline uintptr_t ramfs_calc_metadata_size(uint32_t nr_files)
{
    return ramfs_align_up(sizeof(struct ramfs_metadata) + (sizeof(struct ramfs_inode) * nr_files), PAGE_SIZE);
}

/*
 * CODEREVIEW CHECKLIST
 * caller: process_files
 *       ramfs_inode_data <- ramfs_file_general_read
 *                   <- ramfs_file_read
 *       ramfs_inode_data <- ramfs_file_general_read
 *                   <- ramfs_file_xip_map
 *
 * ARG:
 *     metadata: is not checked
 * RET: return of ramfs_calc_metadata_size is returned directly
 */
static inline uintptr_t ramfs_metadata_size(const struct ramfs_metadata *metadata)
{
    return ramfs_calc_metadata_size(metadata->super.nr_files);
}

/*
 * CODEREVIEW CHECKLIST
 * caller: process_files
 *        ramfs_inode_data <- process_file
 *        ramfs_inode_data <- ramfs_search
 *                 <- ramfs_file_open
 *        ramfs_inode_data <- ramfs_search
 *                 <- ramfs_stat
 *
 * ARG:
 *     metadata: guaranteed by the caller
 *     nr: checked
 */
static inline struct ramfs_inode *ramfs_metadata_inode(struct ramfs_metadata *metadata, uint32_t nr)
{
    if (nr >= metadata->super.nr_files)
        return NULL;
    return &(metadata->inodes[nr]);
}

static const char *extract_basename(const char *filename)
{
    if (filename == NULL)
        return NULL;
    uint32_t len = strnlen(filename, MAX_FILENAME_LENGTH);
    if (len >= MAX_FILENAME_LENGTH)
        return NULL;
    const char *ptr = filename + len;
    for (; ptr >= filename && *ptr != '/'; ptr--);
    return ptr + 1;
}

/*
 * CODEREVIEW CHECKLIST
 * ARG:
 *     filename: checked:
 *       NULL, empty and long string
 */
static inline const char *ramfs_extract_basename(const char *filename)
{
    return extract_basename(filename);
}


struct fd_state {
    volatile int32_t lock;
    bool used;
    uint32_t inum;
    uint32_t cidx;
};

struct ramfs_fd_state {
    volatile int32_t lock;
    bool used;
    struct ramfs_inode *inode;
    uint32_t cidx;
};

struct vfs_ramfs_data {
    struct vfs_data data;
    void *img;
    struct ramfs_metadata *metadata;
    struct ramfs_fd_state fd_state[RAMFS_MAX_FDS];
};

extern struct vfs_ops g_vfs_ramfs_ops;
extern void ramfs_cleanup_fd(uint32_t cidx, const struct vfs_data *vfs_data);
void ramfs_init(struct vfs_ramfs_data *ramfs_data, const char *root, void *img, size_t img_size);
int32_t ramfs_fini(const struct vfs_ramfs_data *ramfs_data);

#endif /* RAMFS_H_ */
