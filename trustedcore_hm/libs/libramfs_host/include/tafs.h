/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: tafs header
 * Create: 2018-05-18
 */
#ifndef _TAFS_H_
#define _TAFS_H_

#include <sys/libvfs.h>
#include <ramfs.h>

/*
 * struct vfs_tafs_data - TA filesystem core structure
 *
 * @vfs_data        Common data structure for VFS users
 * @fd_state:        Array to keep track of the per-file descriptor
 *            information
 */
struct vfs_tafs_data {
    struct vfs_data data;
    struct fd_state fd_state[RAMFS_MAX_FDS];
};

extern bool tafs_init(struct vfs_tafs_data *data);
void tafs_cleanup_fd(uint32_t cidx, const struct vfs_data *vfs_data);

#endif
