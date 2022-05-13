/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: ramfs implementation
 * Create: 2018-05-18
 */

#include "ramfs.h"
#include <stdarg.h>
#include <errno.h>
#include <uidgid.h>
#include <securec.h>
#include <hm_stdint.h>
#include <hmlog.h>
#include "lock_ops.h"

/*
 * CODEREVIEW CHECKLIST
 * caller: ramfs_file_general_read <- ramfs_file_read
 *       ramfs_file_general_read <- ramfs_file_xip_map
 * ARG:
 *     ramfs_metadata, inode: guaranteed by the caller
 *     off: checked
 */
static void *ramfs_inode_data(const struct ramfs_metadata *metadata, const struct ramfs_inode *inode, uintptr_t off)
{
    uintptr_t file_base_ptr = (uintptr_t)(metadata) + ramfs_metadata_size(metadata);
    uintptr_t file_ptr      = file_base_ptr + inode->offset;

    if (off >= inode->size)
        return NULL;
    return (void *)(file_ptr + off);
}

/*
 * CODEREVIEW CHECKLIST
 * caller:  ramfs_file_open <- API
 * ARG:  inode: always valid
 */
#define UID_OFFSET 6
#define GID_OFFSET 3
static int32_t check_inode_permission(const struct ramfs_inode *inode, uint32_t mask, const cred_t *cred)
{
    mode_t mode;

    if (cred->uid == 0)
        return 0;
    mask = mask & (S_IXOTH | S_IWOTH | S_IROTH);
    if (inode->uid == cred->uid)
        mode = inode->mode >> UID_OFFSET;
    else if (inode->gid == cred->gid)
        mode = inode->mode >> GID_OFFSET;
    else
        mode = inode->mode;
    if (mask != (mode & mask))
        return -EPERM;
    return 0;
}

/*
 * CODEREVIEW CHECKLIST
 * caller: fd_free, ramfs_file_open
 * ARG:    ramfs: from API, always valid
 *         fd_state: this function checks if fd_state is valid
 *         this function is impossible to fail in all test cases
 */
static int32_t fd_of(const struct vfs_ramfs_data *ramfs, const struct ramfs_fd_state *fd_state)
{
    if ((fd_state < &(ramfs->fd_state[0])) || (fd_state >= &(ramfs->fd_state[RAMFS_MAX_FDS])))
        return -1;
    return (fd_state - &(ramfs->fd_state[0]));
}

/*
 * CODEREVIEW CHECKLIST
 * caller: ramfs_file_close, ramfs_file_general_read <- API functions
 * ARG:    ramfs: from vfs framework, always valid
 *         fd: user input. Checked at beginning
 *         cidx: from API, always valid
 * RIGHTS: Only the one open the fd can use fd_state_of
 */
struct ramfs_fd_state *fd_state_of(struct vfs_ramfs_data *ramfs, int32_t fd, uint32_t cidx)
{
    if ((fd < 0) || (fd >= RAMFS_MAX_FDS))
        return NULL;

    struct ramfs_fd_state *fd_state = &ramfs->fd_state[fd];
    if (!fd_state->used)
        return NULL;
    if (fd_state->cidx != cidx)
        return NULL;
    return fd_state;
}

/*
 * CODEREVIEW CHECKLIST
 * caller: ramfs_file_open
 * ARG:    ramfs: from framework, always valid
 *         cidx: from msginfo, always
 */
static struct ramfs_fd_state *fd_alloc(struct vfs_ramfs_data *ramfs, uint32_t cidx)
{
    uint32_t i;
    for (i = 0; i < array_size(ramfs->fd_state); i++) {
        if (!trylockw(&ramfs->fd_state[i].lock))
            continue;
        if (!ramfs->fd_state[i].used) {
            ramfs->fd_state[i].used = true;
            ramfs->fd_state[i].cidx = cidx;
            unlock(&ramfs->fd_state[i].lock);
            return &ramfs->fd_state[i];
        }
        unlock(&ramfs->fd_state[i].lock);
    }

    return NULL;
}

/*
 * CODEREVIEW CHECKLIST
 * caller: ramfs_file_close
 * ARG:   ramfs: from framework, always valid
 *        fd_state: from fd_state_of, always valid
 * LOG: checked
 * RET: error return from fd_of is considered:
 *      should panic
 */
static void fd_free(struct vfs_ramfs_data *ramfs, struct ramfs_fd_state *fd_state)
{
    if (fd_of(ramfs, fd_state) < 0)
        hm_panic("fd_free: fd_of returns error\n");
    fd_state->used = false;
}

void ramfs_init(struct vfs_ramfs_data *ramfs_data, const char *root, void *img, size_t img_size)
{
    if (ramfs_data == NULL || root == NULL)
        hm_panic("ramfs_init: ramfs_data is null\n");

    (void)img_size;
    if (memset_s(ramfs_data, sizeof(*ramfs_data), 0, sizeof(*ramfs_data)) != 0)
        hm_panic("ramfs_init: memset_s failed\n");
    vfs_data_init(&ramfs_data->data, root, &g_vfs_ramfs_ops);

    ramfs_data->img = img;
}

/*
 * CODEREVIEW CHECKLIST
 * caller: teardown (filemgr)
 */
int32_t ramfs_fini(const struct vfs_ramfs_data *ramfs_data)
{
    (void)ramfs_data;
    return 0;
}

/*
 * caller: cleanup_fd <- ac_exit_callback <- ac_invalidate_scontext ..
 *                           <- HM_MSG_ID_ACMGR_PUSH_INVALIDATE_SCONTEXT
 *                                 <- acmgr_push_invalidate_scontext
 *                                      <- acmgr_security_fini
 *                                          <- process_fini
 * CODEREVIEW CHECKLIST
 * ARG:    cidx: from sysmgr
 *         vfs_data: set in cleanup_fd, always valid
 * RIGHTS: only sysmgr can trigger this action
 */
void ramfs_cleanup_fd(uint32_t cidx, const struct vfs_data *vfs_data)
{
    struct vfs_ramfs_data *ramfs = container_of(vfs_data, struct vfs_ramfs_data, data);
    for (uint32_t i = 0; i < array_size(ramfs->fd_state); i++) {
        if (ramfs->fd_state[i].used && (ramfs->fd_state[i].cidx == cidx))
            ramfs->fd_state[i].used = false;
    }
}

/*
 * CODEREVIEW CHECKLIST
 * caller: setup in main of filemgr
 * ARG:    vfs_data: always valid
 *         pathname: always valid
 */
static int32_t ramfs_mount(struct vfs_data *vfs_data, const char *pathname)
{
    (void)pathname;
    struct vfs_ramfs_data *ramfs = container_of(vfs_data, struct vfs_ramfs_data, data);
    ramfs->metadata              = ramfs->img;
    if (memcmp(ramfs->metadata->super.magic, RAMFS_MAGIC, sizeof(ramfs->metadata->super.magic)) != 0) {
        hm_error("ramfs format error\n");
        return -EIO;
    }
    if (ramfs->metadata->super.version != RAMFS_VERSION) {
        hm_error("ramfs version error\n");
        return -EIO;
    }
    return 0;
}

/*
 * CODEREVIEW CHECKLIST
 * caller: API
 * ARG:    always valid
 */
static int32_t ramfs_umount(struct vfs_data *vfs_data, const char *pathname)
{
    (void)vfs_data;
    (void)pathname;
    return 0;
}

/*
 * CODEREVIEW CHECKLIST
 * caller: API open and stat
 * ARG:   metadata: always valid
 *        basename: checked by ramfs_extract_basename,
 *        NULL and too long name is impossible
 * RET: failure from ramfs_metadata_inode is processed
 */
static struct ramfs_inode *ramfs_search(struct ramfs_metadata *metadata, const char *basename)
{
    uint32_t i;

    for (i = 0; i < metadata->super.nr_files; i++) {
        struct ramfs_inode *inode = ramfs_metadata_inode(metadata, i);

        if (inode == NULL)
            return NULL;
        /* skip leading '/' */
        if (strncmp(&inode->filename[1], basename, sizeof(inode->filename) - 1) == 0)
            return inode;
    }
    return NULL;
}

/*
 * CODEREVIEW CHECKLIST
 * caller: this is API func
 * ARG:    vfs_data: from framework
 *         pathname: checked by ramfs_extract_basename
 *         flags: checked
 *         mode: checked in check_inode_permission
 *         cred: used in check_inode_permission, from framework
 *         cidx: from kernel
 *         memid: unused
 * RIGHTS: checked by check_inode_permission
 * LOG: checked
 * RET: error return from ramfs_extract_basename is processed (2 cases)
 *      error of ramfs_search is processed
 *      error of check_inode_permission is processed
 *      error of fd_alloc is processed     <-- state change
 *    error of fd_of is processed (panic)
 */
static int32_t ramfs_file_open(struct vfs_ensemble_open *ensemble, const char *pathname, int32_t flags, mode_t mode)
{
    const char *basename            = ramfs_extract_basename(pathname);
    struct vfs_ramfs_data *ramfs    = container_of(ensemble->vfs_data, struct vfs_ramfs_data, data);
    struct ramfs_metadata *metadata = ramfs->metadata;

    if (((uint32_t)flags & (~O_RDWR)) != 0)
        return -EINVAL;
    if ((basename == NULL) || (basename[0] == '\0'))
        return -EINVAL;
    struct ramfs_inode *inode = ramfs_search(metadata, basename);
    if (inode == NULL)
        return -ENOENT;
    if (check_inode_permission(inode, mode, ensemble->cred) != 0)
        return -EPERM;
    struct ramfs_fd_state *fd_state = fd_alloc(ramfs, ensemble->cidx);
    if (fd_state == NULL)
        return -ENFILE;

    fd_state->inode = inode;
    int32_t fd      = fd_of(ramfs, fd_state);
    if (fd < 0)
        hm_panic("fd_of fail when opening '%s'\n", basename);
    return fd;
}

static int32_t ramfs_print_fsinfo(struct vfs_data *vfs_data)
{
    struct vfs_ramfs_data *ramfs    = container_of(vfs_data, struct vfs_ramfs_data, data);
    struct ramfs_metadata *metadata = ramfs->metadata;
    uint32_t i;
    int32_t ramfs_total_size = 0;

    for (i = 0; i < metadata->super.nr_files; i++) {
        struct ramfs_inode *inode = ramfs_metadata_inode(metadata, i);

        if (inode == NULL)
            return 0;
        ramfs_total_size += (int32_t)inode->size;
        hm_error("ramfs name=%s,size=%u\n", inode->filename, inode->size);
    }
    return ramfs_total_size;
}

/*
 * CODEREVIEW CHECKLIST
 * caller: this is API func
 * ARG:    vfs_data: from framework
 *         pathname: checked by ramfs_extract_basename
 *         stat: Always valid in vfs layer
 *         cred: used in check_inode_permission
 * RET: error of ramfs_extract_basename is processed (2 cases)
 *      error of ramfs_search is processed
 */
static int32_t ramfs_stat(struct vfs_data *vfs_data, const char *pathname, struct stat *stat, const cred_t *cred)
{
    (void)cred;
    const char *basename            = ramfs_extract_basename(pathname);
    struct vfs_ramfs_data *ramfs    = container_of(vfs_data, struct vfs_ramfs_data, data);
    struct ramfs_metadata *metadata = ramfs->metadata;

    if ((basename == NULL) || (basename[0] == '\0'))
        return -EINVAL;
    struct ramfs_inode *inode = ramfs_search(metadata, basename);
    if (inode == NULL)
        return -ENOENT;

    stat->uid  = inode->uid;
    stat->gid  = inode->gid;
    stat->mode = inode->mode;
    stat->size = inode->size;
    return 0;
}

/*
 * CODEREVIEW CHECKLIST
 * caller: this is API func
 * ARG:    vfs_data: from framework
 *         fd: can be anything, checked by fd_state_of
 *         cidx: from msginfo, always valid
 * RET: error of fd_state_of is processed
 */
static int32_t ramfs_file_close(struct vfs_data *vfs_data, int32_t fd, uint32_t cidx)
{
    struct vfs_ramfs_data *ramfs    = container_of(vfs_data, struct vfs_ramfs_data, data);
    struct ramfs_fd_state *fd_state = fd_state_of(ramfs, fd, cidx);
    if (fd_state == NULL)
        return -EINVAL;

    fd_free(ramfs, fd_state);
    return 0;
}

enum ramfs_read_op {
    RAMFS_XIP_READ,
    RAMFS_NORMAL_READ,
};

/*
 * CODEREVIEW CHECKLIST
 * caller: ramfs_file_general_read <- ramfs_file_xip_map
 * ARG:    arg: from ramfs_file_xip_map (vaddr), always valid (by vfs)
 *         count: from ramfs_file_xip_map, can be anything,
 *                0 and negative is impossible (checked in ramfs_file_general_read)
 *                verifiedin consume
 *         data_addr: from ramfs_inode_data, checked, always valid
 *         left: inode->size - *off, *off is checked
 * RIGHTS: N/A (protected by fd_state_of in ramfs_file_general_read)
 * BUFOVF: consume is maintained correctly, never overflow
 */
static size_t read_ops_xip(void *arg, size_t count, const void *data_addr, size_t left)
{
    uint64_t *vaddr = arg;
    size_t consume  = count;
    size_t page_left;

    *vaddr    = ptr_to_uint64(data_addr);
    page_left = PAGE_SIZE - ((uintptr_t)(data_addr) & (PAGE_SIZE - 1));
    if (consume > page_left)
        consume = page_left;
    if (consume > left)
        consume = left;
    return consume;
}

/*
 * CODEREVIEW CHECKLIST
 * caller: ramfs_file_general_read <- ramfs_file_read
 * ARG:    arg: from ramfs_file_read (buf), always valid (by vfs)
 *         count: from ramfs_file_xip_map, not 0 or negative
 *         data_addr: from ramfs_inode_data, checked, always valid
 *         left: inode->size - *off, *off is checked
 * RIGHTS: N/A (protected by fd_state_of in ramfs_file_general_read)
 * BUFOVF: consume is maintained correctly, never overflow
 * RET: error from memcpy_s is checked
 */
static size_t read_ops_normal(void *arg, size_t count, const void *data_addr, size_t left)
{
    void *buf      = arg;
    size_t consume = count;

    if (consume > left)
        consume = left;

    if (memcpy_s(buf, count, data_addr, consume) != 0)
        hm_panic("read ops normal: memcpy_s failed\n");
    return consume;
}

/*
 * CODEREVIEW CHECKLIST
 * caller: ramfs_file_read, ramfs_file_xip_map
 * ARG:    data: from vfs, always valid
 *         fd: can be anything, checked by fd_state_of
 *         off: always valid, but *off can be anything
 *         count: can be anything. checked before calling
 *                worker: 0 and negative should return 0
 *         cidx: from msginfo, always valid
 *         arg: directly passed to workers
 *         op: const
 * RET: error of fd_state_of is checked
 *      error of ramfs_inode_data is checked
 *      workers never error
 */
static ssize_t ramfs_file_general_read(struct vfs_ensemble_read *ensemble, int32_t fd, size_t count, void *arg,
                                       enum ramfs_read_op op)
{
    size_t left, consume;

    if (*(ensemble->off) < 0)
        return -EINVAL;

    struct vfs_ramfs_data *ramfs    = container_of(ensemble->vfs_data, struct vfs_ramfs_data, data);
    struct ramfs_fd_state *fd_state = fd_state_of(ramfs, fd, ensemble->cidx);
    if (fd_state == NULL)
        return -EINVAL;

    struct ramfs_inode *inode = fd_state->inode;
    if (*(ensemble->off) >= inode->size)
        return 0;

    left = (size_t)(inode->size - *(ensemble->off));

    void *data_addr = ramfs_inode_data(ramfs->metadata, inode, (uintptr_t)(*(ensemble->off)));
    if (data_addr == NULL)
        return 0;

    if (count <= 0)
        return 0;

    switch (op) {
    case RAMFS_XIP_READ:
        consume = read_ops_xip(arg, count, data_addr, left);
        break;
    case RAMFS_NORMAL_READ:
        /* fall-through */
    default:
        consume = read_ops_normal(arg, count, data_addr, left);
        break;
    }

    *(ensemble->off) += consume;
    return consume;
}

/*
 * CODEREVIEW CHECKLIST
 * ARG:    see ramfs_file_general_read
 * RIGHTS: see ramfs_file_general_read
 * BUFOVF: see ramfs_file_general_read
 * LOG:    see ramfs_file_general_read
 * RET:    see ramfs_file_general_read
 * RACING: see ramfs_file_general_read
 * LEAK:   see ramfs_file_general_read
 * ARITHOVF: see ramfs_file_general_read
 */
static ssize_t ramfs_file_read(struct vfs_ensemble_read *ensemble, int32_t fd, void *buf, size_t count)
{
    return ramfs_file_general_read(ensemble, fd, count, buf, RAMFS_NORMAL_READ);
}

/*
 * CODEREVIEW CHECKLIST
 * ARG:    see ramfs_file_general_read
 * RIGHTS: see ramfs_file_general_read
 * BUFOVF: see ramfs_file_general_read
 * LOG:    see ramfs_file_general_read
 * RET:    see ramfs_file_general_read
 * RACING: see ramfs_file_general_read
 * LEAK:   see ramfs_file_general_read
 * ARITHOVF: see ramfs_file_general_read
 */
static ssize_t ramfs_file_xip_map(struct vfs_ensemble_xip_map *ensemble, int32_t fd, size_t count, uint64_t *vaddr,
                                  uint64_t *vspace)
{
    (void)vspace;
    return ramfs_file_general_read((struct vfs_ensemble_read *)ensemble, fd, count, vaddr, RAMFS_XIP_READ);
}

struct vfs_ops g_vfs_ramfs_ops = {
    .name         = "vfs_ramfs_ops",
    .mkfs         = NULL,
    .mount        = ramfs_mount,
    .umount       = ramfs_umount,
    .open         = ramfs_file_open,
    .openat       = NULL,
    .creat        = NULL,
    .close        = ramfs_file_close,
    .unlink       = NULL,
    .truncate     = NULL,
    .ftruncate    = NULL,
    .read         = ramfs_file_read,
    .write        = NULL,
    .lseek        = NULL,
    .getdents     = NULL,
    .mkdirat      = NULL,
    .xip_map      = ramfs_file_xip_map,
    .setattr      = NULL,
    .stat         = ramfs_stat,
    .print_fsinfo = ramfs_print_fsinfo,
    .rename       = NULL,
    .mmap         = NULL,
};
