/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: tafs implementation
 * Create: 2018-05-18
 */

#include "tafs.h"
#include <stdarg.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/hm_syscall.h>
#include <api/errno.h>
#include <securec.h>
#include <hmlog.h>
#include <mem_page_ops.h>
#include <mmgrapi.h>
#include <mm_kcall.h>
#include "lock_ops.h"

/* We support 4 state of tafs inode at present. */
/* state of a tafs inode: created->filling->ready->dead */
enum tafs_inode_state {
    TAFS_INODE_DEAD,
    TAFS_INODE_CREATED,
    TAFS_INODE_FILLING,
    TAFS_INODE_READY,
};

enum tafs_inode_xip_state {
    XIP_NOT_ALLOW,
    XIP_PREPARE,
    XIP_ALLOW
};

#define TAFS_NAME_LEN           64
#define TAFS_INVALID_FD         (-1)
#define TAFS_INVALID_INODE_NUM  (-1)

struct tafs_inode {
    char filename[TAFS_NAME_LEN];
    enum tafs_inode_state state;
    enum tafs_inode_xip_state xip_state;
    size_t data_len;
    uid_t uid;
    void **pages;
    uint64_t memid;
    volatile int32_t lock;
};

#define TAFS_INODE_NR CONFIG_RAMFS_MAX_FILES_OPEN
static struct tafs_inode g_inodes[TAFS_INODE_NR];
void *hm_mapfile(uint64_t vaddr_filemgr, uint64_t task_vs, uint64_t size);

/*
 * caller: tafs_file_open
 * CODEREVIEW CHECKLIST
 * ARG:     inode: return from inode_find, error is checked by caller
 * BUFOVF:  inode position is clamped
 */
/* return the index of *inode in array inode[] */
static inline int32_t inode_no(const struct tafs_inode *inode)
{
    if ((inode < &g_inodes[0]) || (inode >= &g_inodes[TAFS_INODE_NR]))
        return TAFS_INVALID_INODE_NUM;
    return inode - &g_inodes[0];
}

/*
 * caller: all API functions
 * CODEREVIEW CHECKLIST
 * ARG:    ino is filestat->inum
 */
/* get the tafs_inode by array index @ino */
static inline struct tafs_inode *inode_of(uint32_t ino)
{
    if (ino >= TAFS_INODE_NR)
        return NULL;
    return &g_inodes[ino];
}

/*
 * caller: tafs_file_open
 * CODEREVIEW CHECKLIST
 * ARG:    tafs: always valid
 *         cidx: from tafs_file_open <- ... <- vfs_do_op
 *               from kernel. always valid
 */
/* alloc a new inode, rfree in fd_free, use .used to store if valid */
static struct fd_state *fd_alloc(struct vfs_tafs_data *tafs, uint32_t cidx)
{
    for (uint32_t i = 0; i < array_size(tafs->fd_state); i++) {
        if (!trylockw(&tafs->fd_state[i].lock))
            continue;
        if (!tafs->fd_state[i].used) {
            tafs->fd_state[i].used = true;
            tafs->fd_state[i].cidx = cidx;
            unlock(&tafs->fd_state[i].lock);
            return &tafs->fd_state[i];
        }
        unlock(&tafs->fd_state[i].lock);
    }

    return NULL;
}

/*
 * caller: fd_check
 * CODEREVIEW CHECKLIST
 * ARG: tafs: always valid (from vfs framework)
 */
/* check if fd is in valid range */
static bool fd_valid(const struct vfs_tafs_data *tafs, int32_t fd)
{
    return ((fd >= 0) && ((uint32_t)fd < array_size(tafs->fd_state)));
}

/*
 * caller: vfs framework
 * CODEREVIEW CHECKLIST
 * ARG: tafs: always valid (from vfs framework)
 *        fd: checked by fd_valid
 *        cidx: always valid or return -EINVAL if not fit
 * RET: all cases of fd_valid are considered
 */
/*
 * Check a file descriptor for validity
 *
 * Returns 0 if the file descriptor is valid, otherwise a negative errno value
 */
static int32_t fd_check(const struct vfs_tafs_data *tafs, int32_t fd, uint32_t cidx)
{
    if (!fd_valid(tafs, fd))
        return -EINVAL;

    const struct fd_state *fd_state = &tafs->fd_state[fd];
    if (!fd_state->used || cidx != fd_state->cidx)
        return -EINVAL;

    return 0;
}

/*
 * call: only tafs_file_close
 * CODEREVIEW CHECKLIST
 * ARG: fd_state: always valid: when calling tafs_file_close,
 *                fd_state is checked before calling fd_free
 */
/*
 * Set the @used to false to indicate that this file descriptor is **NOT** in use.
 */
static void __attribute__((unused)) fd_free(struct fd_state *fd_state)
{
    fd_state->used = false;
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
void tafs_cleanup_fd(uint32_t cidx, const struct vfs_data *vfs_data)
{
    struct vfs_tafs_data *tafs = container_of(vfs_data, struct vfs_tafs_data, data);

    for (uint32_t i = 0; i < array_size(tafs->fd_state); i++) {
        if (tafs->fd_state[i].used && (tafs->fd_state[i].cidx == cidx)) {
            struct tafs_inode *inode = inode_of(tafs->fd_state[i].inum);
            if (inode != NULL)
                unlock(&inode->lock);
            tafs->fd_state[i].used = false;
        }
    }
}

/*
 * caller: file operations
 * CODEREVIEW CHECKLIST
 * ARG:   tafs: from container_of, always valid
 *        fd: can be anything
 *          all callsites of fd_state_of are protected by fd_check.
 *        cidx: from framework
 */
static struct fd_state *fd_state_of(struct vfs_tafs_data *tafs, int32_t fd)
{
    if ((fd < 0) || (fd >= RAMFS_MAX_FDS))
        return NULL;
    struct fd_state *fd_state = &tafs->fd_state[fd];
    return fd_state;
}

static struct tafs_inode *get_inode_from_vfs(struct vfs_tafs_data *tafs,  int32_t fd, uint32_t cidx)
{
    int32_t ret = fd_check(tafs, fd, cidx);
    if (ret != 0) {
        hm_error("fd is not valid\n");
        return NULL;
    }
    struct fd_state *fd_state = fd_state_of(tafs, fd);
    if (fd_state == NULL) {
        hm_error("fd state is not valid\n");
        return NULL;
    }
    return inode_of(fd_state->inum);
}

/*
 * caller: only tafs_file_open
 * CODEREVIEW CHECKLIST
 * ARG:   tafs: ensured by caller
 *        fd_state: ensured by caller (NULL case is prevent)
 */
/* return the index of *fd_state in array fd_state[] */
static inline int32_t fd_of(const struct vfs_tafs_data *tafs, const struct fd_state *fd_state)
{
    if ((fd_state < &tafs->fd_state[0]) || (fd_state >= &tafs->fd_state[RAMFS_MAX_FDS]))
        return TAFS_INVALID_FD;
    return fd_state - &tafs->fd_state[0];
}

/*
 * caller: API, inode_alloc
 * CODEREVIEW CHECKLIST
 * ARG:     path: A valid path or "" (for inode_alloc)
 *            expect inode_alloc, path is checked by
 *            is_path_valid before calling inode_find
 * RET:     strncmp all cases are considered
 */
/*
 * Find the tafs_inode via filename.
 *
 * Return the corresponding tafs_inode or NULL if there was not such
 * a tafs_inode with that name.
 */
static struct tafs_inode *inode_find(const char *path, bool write)
{
    hm_debug("find name is '%s'\n", path);
    for (uint32_t i = 0; i < array_size(g_inodes); i++) {
        /*
         * Compare before trylock, skip if it is not our target to avoid
         * making a concurrent real user fail. Race condition that it becomes
         * our target shortly afterwards is less critical.
         */
        if (strncmp(g_inodes[i].filename, path, TAFS_NAME_LEN) != 0)
            continue;
        if (write) {
            if (!trylockw(&g_inodes[i].lock))
                continue;
        } else {
            if (!trylockr(&g_inodes[i].lock))
                continue;
        }
        if (strncmp(g_inodes[i].filename, path, TAFS_NAME_LEN) == 0)
            return &g_inodes[i];
        unlock(&g_inodes[i].lock);
    }
    return NULL;
}

/*
 * CODEREVIEW CHECKLIST
 * ARG:    path: can be anything
 * RET: NULL ptr, empty string and no '\0' termination all checked.
 */
static bool is_path_valid(const char *path)
{
    if (path == NULL)
        return false;
    if (path[0] == '\0')
        return false;
    if (strnlen(path, TAFS_NAME_LEN) == TAFS_NAME_LEN)
        return false;
    return true;
}

/*
 * caller: tafs_file_open (when creating a new file)
 * CODEREVIEW CHECKLIST
 * ARG:    pathname: checked by is_path_valid() before alloc
 */
/*
 * Alloc for a tafs_inode with @pathname.
 *
 * This function will first retrieve an unused tafs_inode(whose filename is "")
 * and then do the manipulation things.
 */
static struct tafs_inode *inode_alloc(const char *pathname, uint64_t memid)
{
    struct tafs_inode *inode = inode_find("", true);
    if (inode == NULL)
        return NULL;
    if (strncpy_s(inode->filename, TAFS_NAME_LEN, pathname, TAFS_NAME_LEN - 1) != 0)
        hm_panic("strncpy_s failed");
    inode->filename[TAFS_NAME_LEN - 1] = '\0';
    inode->state                       = TAFS_INODE_CREATED;
    inode->xip_state                   = XIP_NOT_ALLOW;
    inode->memid                       = memid;
    inode->uid                         = 0;
    return inode;
}

/*
 * caller: tafs_file_open (failure processing)
 *         tafs_file_unlink
 * CODEREVIEW CHECKLIST
 * ARG:    inode: always valid, ensured by caller
 */
/*
 * Not free the memory, just mark the node as unused by clearing the
 * filename field and update the state.
 */
static inline void inode_free(struct tafs_inode *inode)
{
    inode->filename[0] = '\0';
    inode->state       = TAFS_INODE_DEAD;
}

/*
 * CODEREVIEW CHECKLIST
 * caller: API
 * ARG:    vfs_data: from vfs framework, always valid
 *         pathname: User input, checked by is_path_valid
 *         flags: user input: checked by flags & ~(O_RDWR | O_CREAT)
 *         mode: useless
 * RIGHTS: checked by SECURITY_HOOK_CALL fops in filemgr
 * RET:
 *   error of is_path_valid is processed
 *   all cases of inode_find are processed
 *   all cases of inode_alloc are processed <-- state change
 *      roll back: inode_free of tafs_file_unlink
 *   error return from fd_alloc is processed <-- state change 2
 *      roll back: tafs_file_close
 *   failure of inode_no is impossible
 *   failure of fd_of is impossible
 */
/*
 * opens the file whose name is the string pointed to by @pathname
 * and associates a stream with it.
 *
 * Upon successful completion tafs_file_open() return a FILE pointer.
 * Otherwise, errno is returned appropriately.
 */
static int32_t tafs_file_open(struct vfs_ensemble_open *ensemble, const char *pathname, int32_t flags, mode_t mode)
{
    (void)mode;
    int32_t fd, inode_num;
    bool new_inode = false;

    if (!is_path_valid(pathname))
        return -EINVAL;

    struct vfs_tafs_data *tafs = container_of(ensemble->vfs_data, struct vfs_tafs_data, data);
    if (((uint32_t)flags & ~(O_RDWR | O_CREAT | O_XIP)) != 0)
        return -EINVAL;

    hm_debug("TAFS: try open '%s'\n", pathname);

    struct tafs_inode *inode = inode_find(pathname, flags != O_RDONLY);
    if (inode == NULL) {
        if (((uint32_t)flags & O_CREAT) != 0) {
            inode     = inode_alloc(pathname, ensemble->memid);
            new_inode = true;
        } else {
            return -ENOENT;
        }
    }
    if (inode == NULL)
        return -ENOMEM;

    if (inode->state == TAFS_INODE_DEAD)
        hm_panic("TAFS: inode of '%s' is DEAD\n", pathname);

    struct fd_state *fd_state = fd_alloc(tafs, ensemble->cidx);
    if (fd_state == NULL) {
        /* Don't free existing inode */
        if (new_inode)
            inode_free(inode);
        unlock(&inode->lock);
        return -ENFILE;
    }

    inode_num = inode_no(inode);
    if (inode_num < 0)
        hm_panic("inode_no returns error\n");
    fd_state->inum = (uint32_t)(inode_num);
    fd             = fd_of(tafs, fd_state);
    if (fd < 0)
        hm_panic("fd_of returns -1\n");
    hm_debug("TAFS: return fd %d\n", fd);

    if (new_inode && ((uint32_t)flags & O_XIP) != 0)
        inode->xip_state = XIP_PREPARE;

    /* Open succeeds, keep inode lock till close */
    return fd;
}

static int32_t tafs_print_fsinfo(struct vfs_data *vfs_data)
{
    int32_t tafs_total_size = 0;
    (void)(vfs_data);
    for (uint32_t i = 0; i < array_size(g_inodes); i++) {
        if (strnlen(g_inodes[i].filename, TAFS_NAME_LEN) > 0) {
            tafs_total_size += g_inodes[i].data_len;
            hm_error("tafs name=%s size=%zu xip_state=%d\n", g_inodes[i].filename, g_inodes[i].data_len,
                g_inodes[i].xip_state);
        }
    }
    return tafs_total_size;
}

/*
 * caller: API
 * CODEREVIEW CHECKLIST
 * ARG:  vfs_data: from framework, always valid
 *       fd: user input, checked by fd_state_of
 *       cidx: from kernel, always valid
 * RIGHTS: only a cnode can close fds owned by itself
 * RET:
 *   failure of fd_check is processed
 *   failure of fd_state_of is processed
 *   failure of inode_of: panic: this failure indicate internal
 *                        inconsistent
 */
/*
 * Close a stream.
 */
static int32_t tafs_file_close(struct vfs_data *vfs_data, int32_t fd, uint32_t cidx)
{
    struct vfs_tafs_data *tafs = container_of(vfs_data, struct vfs_tafs_data, data);
    int32_t rc                 = fd_check(tafs, fd, cidx);
    if (rc != 0)
        return rc;
    struct fd_state *fd_state = fd_state_of(tafs, fd);

    if (fd_state == NULL)
        return -EINVAL;
    struct tafs_inode *inode = inode_of(fd_state->inum);
    if (inode == NULL)
        hm_panic("NULL from inode_of\n");

    if (inode->state == TAFS_INODE_FILLING)
        inode->state = TAFS_INODE_READY;
    if (inode->xip_state == XIP_PREPARE)
        inode->xip_state = XIP_ALLOW;
    unlock(&inode->lock);

    fd_free(fd_state);
    return 0;
}

/*
 * CODEREVIEW CHECKLIST
 * caller: tafs_file_unlink
 * ARG:   inode: always valid
 * LOG: all checked
 * RET: return from munmap is reported (unable to process)
 */
static void inode_reset(struct tafs_inode *inode)
{
    size_t pagevec_len;
    size_t n_pages;
    size_t clrsz;

    if ((SIZE_MAX - inode->data_len) < PAGE_SIZE) {
        hm_error("invalid inode data length %zx\n", inode->data_len);
        return;
    }
    n_pages     = PAGE_ALIGN_UP(inode->data_len) / PAGE_SIZE;
    pagevec_len = PAGE_ALIGN_UP(n_pages * sizeof(void *));

    if (inode->pages != NULL) {
        if (munmap(inode->pages[0], (size_t)n_pages * PAGE_SIZE) != 0)
            hm_error("TAFS munmap pages fail\n");
        if (munmap(inode->pages, pagevec_len) != 0)
            hm_error("TAFS munmap pagevec fail\n");
    }

    /* Avoid touching lock */
    clrsz = (size_t)(&((struct tafs_inode *)0)->lock);
    if (memset_s(inode, sizeof(*inode), 0, clrsz) != EOK)
        hm_panic("memset_s failed\n");
}

/*
 * caller: API
 * CODEREVIEW CHECKLIST
 * ARG:   vfs_data: from vfs framework
 * RIGHTS: ensured by fsmgr
 * RET: error case from is_path_valid is processed
 *      error from inode_find is processed
 */
static int32_t tafs_file_unlink(struct vfs_data *vfs_data, const char *pathname)
{
    (void)vfs_data;
    if (!is_path_valid(pathname))
        return -EINVAL;

    struct tafs_inode *inode = inode_find(pathname, true);
    if (inode == NULL)
        return -EINVAL;

    if (inode->pages != NULL)
        inode_reset(inode);
    inode_free(inode);
    unlock(&inode->lock);
    return 0;
}

/*
 * CODEREVIEW CHECKLIST
 * caller: tafs_file_ftruncate <- API
 * ARG:    inode: from vfs framework, always valid
 * RIGHTS: ensured by filemgr
 * RET:   failure return of mmap is processed <- state change
 *        failure return of mmap(2) is processed <- state change
 *        failure return from memset_s are processed (panic)
 *
 * currently use 2 mmaps to alloc pagevec and pages, but it is not good.
 * 1. we can use 1 mmap for pagevec and 1 mmaps for each page, so the
 *    vspace don't require continous space
 * 2. we can also use 1 mmap for all, so when cleanup we only 1 munmap
 */
static int32_t tafs_inode_prepare_mem(struct tafs_inode *inode, size_t data_len)
{
    size_t pagevec_len;
    size_t n_pages, n;

    if ((SIZE_MAX - data_len) < PAGE_SIZE) {
        hm_error("invalid inode data length %zx\n", data_len);
        return -EINVAL;
    }
    n_pages     = PAGE_ALIGN_UP(data_len) / PAGE_SIZE;
    pagevec_len = PAGE_ALIGN_UP(n_pages * sizeof(void *));

    set_this_memid((int32_t)(uint32_t)inode->memid);
    inode->pages =
        mmap(0, pagevec_len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0); /* don't use malloc here */
    if (inode->pages == MAP_FAILED) {
        inode->pages = NULL;
        set_this_memid(0);
        return -ENOMEM;
    }

    char *ppages = mmap(0, n_pages * PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    set_this_memid(0);
    if (ppages == MAP_FAILED)
        goto err;

    for (n = 0; n < n_pages; n++)
        inode->pages[n] = ppages + n * PAGE_SIZE;

    inode->data_len = data_len;

    return 0;
err:
    if (munmap(inode->pages, pagevec_len) != 0)
        hm_error("TAFS: unmap pagevec failed\n");
    inode->pages = NULL;
    return -ENOMEM;
}

/*
 * caller: API
 * CODEREVIEW CHECKLIST
 * ARG:  vfs_data: from framework
 *       fd: can be anything, checked by fd_check
 *       length: can be anything
 *       cidx: cnode_idx, always valid
 * RIGHTS: ensured by filemgr
 * RET:
 *  error from fd_check is processed
 *  error from fd_state_of is processed
 *  error from inode_of is processed
 * RACING: two caller can open one new inode, but only one can truncate
 *         the other one will fail because inode become filling.
 */
static int32_t tafs_file_ftruncate(struct vfs_data *vfs_data, int32_t fd, int64_t length, uint32_t cidx)
{
    struct vfs_tafs_data *tafs = container_of(vfs_data, struct vfs_tafs_data, data);
    struct tafs_inode *inode = get_inode_from_vfs(tafs, fd, cidx);
    if (inode == NULL)
        hm_panic("error: fd %d have invalid inode\n", fd);
    if (inode->state != TAFS_INODE_CREATED)
        return -EINVAL;
    if (inode->xip_state == XIP_ALLOW) {
        hm_error("can not change file that allows XIP\n");
        return -EFAULT;
    }

    if (tafs_inode_prepare_mem(inode, (size_t)length) != 0) {
        hm_error("tafs_inode_prepare_mem failed\n");
        return -ENOMEM;
    }

    inode->state = TAFS_INODE_FILLING;
    return 0;
}

/*
 * CODEREVIEW CHECKLIST
 * caller: tafs_file_xip_map (API)
 * ARG:   inode: always valid (ensured by caller)
 *        off: vfs framework ensure off not null
 *        p_ptr: always valid (vfs framework)
 * RIGHTS: protected by filemgr
 * BUFOVF: *off is compared with inode->data_len
 * ARITHOVF: all arith operations are checks. overflow is impossible.
 */
static ssize_t tafs_inode_xip_map(struct tafs_inode *inode, int64_t *off, uint64_t *p_ptr)
{
    size_t rest, handled, page_idx, page_off;

    if (*off < 0)
        return -EINVAL;
    if ((size_t)(*off) >= inode->data_len)
        return 0;

    page_idx = (size_t)((*off) / PAGE_SIZE);
    page_off = (size_t)((uint64_t)(*off) & PAGE_OFFSET_MASK);

    rest    = (size_t)(inode->data_len - *off);
    handled = PAGE_SIZE - page_off;
    if (handled > rest)
        handled = rest;

    *p_ptr = (uint64_t)((uintptr_t)(inode->pages[page_idx])) + (uint64_t)page_off;
    *off += handled;

    return handled;
}

/*
 * caller: tafs read and write
 * CODEREVIEW CHECKLIST
 * ARG:   inode state is checked in caller
 *        is_read: const
 *        off: never NULL (ensured by vfs framework)
 *        *off is checked at beginning
 *        bytes is checked at beginning (<= 0)
 *        buf and size are from vfs framework
 *           see fileio_dispatch.c, overflow is impossible
 *
 *        access range is valid:
 *          *off must inside range:
 *            *off < 0 or *off too large are processed.
 *            *off + bytes won't too large
 * RIGHTS: ensured by caller
 * BUFOVF: buffer accessing is constrained in a page
 * RET: error from memcpy_s is processed
 * ARITHOVF: bytes from user space is clamped: overflow is checked.
 *           buf + bytes should not overflow because tafs_inode_rw
 *             is called by filemgr, buf is a filemgr internal buf.
 */
/*
 * Read from or write to a file descriptor.
 *
 * @is_read indicates read or write.
 */
static ssize_t tafs_inode_rw(struct tafs_inode *inode, int32_t is_read, int64_t *off, void *buf, size_t bytes)
{
    size_t rc, rest, page_idx, page_off;

    if ((bytes <= 0) || (*off < 0) || ((size_t)(*off) >= inode->data_len))
        return 0;

    if (bytes > (size_t)(INT64_MAX - *off))
        bytes = (size_t)(INT64_MAX - *off);

    if ((*off + bytes) > inode->data_len) {
        rest = inode->data_len - *off;
        rc = inode->data_len - *off;
    } else {
        rest = bytes;
        rc = bytes;
    }

    page_idx = (size_t)((*off) / PAGE_SIZE);
    page_off = (size_t)((uint64_t)(*off) & PAGE_OFFSET_MASK);
    for (; rest > 0; page_idx++) {
        size_t to_copy;
        void *from = NULL;
        void *to   = NULL;

        to_copy = (rest > (PAGE_SIZE - page_off)) ? (PAGE_SIZE - page_off) : rest;
        if (is_read != 0) {
            from = (char *)(inode->pages[page_idx]) + page_off;
            to   = (char *)buf + rc - rest;
        } else {
            from = (char *)buf + rc - rest;
            to   = (char *)(inode->pages[page_idx]) + page_off;
        }

        if (memcpy_s(to, to_copy, from, to_copy) != EOK)
            return -EFAULT;

        page_off = 0;
        rest -= to_copy;
        (*off) += to_copy;
    }

    return rc;
}

/*
 * CODEREVIEW CHECKLIST
 * caller: API
 * ARG: vfs_data: always valid (by vfs framework)
 *      fd: user input, checked by fd_check
 *      off: not null, but *off can be anything
 *      buf and size are from vfs framework
 *           see fileio_dispatch.c, overflow is impossible
 * RIGHTS: controlled by filemgr
 * RET: error from fd_check is processed
 *      error from fd_state_of is processed
 *      error from inode_of is processed
 *      error from tafs_inode_rw is processed
 */
/*
 * Read from a file descriptor.
 *
 * On success, the number of bytes read is returned.
 * On error, errno is returned appropriately.
 */
static ssize_t tafs_file_read(struct vfs_ensemble_read *ensemble, int32_t fd, void *buf, size_t count)
{
    struct vfs_tafs_data *tafs = container_of(ensemble->vfs_data, struct vfs_tafs_data, data);
    struct tafs_inode *inode = get_inode_from_vfs(tafs, fd, ensemble->cidx);
    if (inode == NULL)
        return -EINVAL;
    if (inode->state == TAFS_INODE_FILLING)
        inode->state = TAFS_INODE_READY;
    if (inode->state != TAFS_INODE_READY)
        return -EIO;
    ssize_t rc = tafs_inode_rw(inode, 1, ensemble->off, buf, count);
    if (rc < 0)
        return -EIO;
    return rc;
}

/*
 * caller: tafs_file_write
 * CODEREVIEW CHECKLIST
 * ARG:   vfs_data: from framework, always valid
 *        fd: user input, checked by fd_check
 *        off: never null, *off can be invalid.
 *             checked in tafs_inode_rw
 *        buf and count: always valid (part of reply message)
 *        cidx: from caller
 * RIGHTS: ensureed by filemgr
 * RET:
 *   error of fd_check is processed
 *   error of fd_state_of is processed
 *   error of inode_of is processed (only inode in filling state can write)
 *   error of tafs_inode_rw is processed.
 */
/*
 * Write to a file descriptor.
 *
 * The underlying function of tafs_file_write with the @buf be non-const.
 *
 * On success, the number of bytes that has been written.
 * On error, errno is returned appropriately.
 */
static ssize_t tafs_file_write_internal(const struct vfs_ensemble_write *ensemble, int32_t fd, void *buf, size_t count)
{
    struct vfs_tafs_data *tafs = container_of(ensemble->vfs_data, struct vfs_tafs_data, data);
    struct tafs_inode *inode = get_inode_from_vfs(tafs, fd, ensemble->cidx);
    if ((inode == NULL) || (inode->state != TAFS_INODE_FILLING))
        return -EINVAL;
    if (inode->xip_state == XIP_ALLOW) {
        hm_error("can not change file that allows XIP\n");
        return -EFAULT;
    }

    ssize_t rc = tafs_inode_rw(inode, 0, ensemble->off, buf, count);
    if (rc < 0)
        return -EIO;

    return rc;
}

/*
 * CODEREVIEW CHECKLIST
 * ARG:   vfs_data: from framework, always valid
 *        fd: user input, checked by fd_check
 *        off: never null, *off can be invalid.
 *             checked in tafs_inode_rw
 *        buf and count: always valid (part of reply message)
 *        cidx: from caller
 */
/* Get rid of const */
static ssize_t tafs_file_write(struct vfs_ensemble_write *ensemble, int32_t fd, const void *buf, size_t count)
{
    return tafs_file_write_internal(ensemble, fd, (void *)buf, count);
}

/*
 * caller: API (do_xip_map)
 * CODEREVIEW CHECKLIST
 * ARG:   vfs_data: from framework, always valid
 *        fd: user input, checked by fd_check
 *        off: never null, *off can be invalid. ??
 *        vaddr: always non-null
 *        vspace: always non-null
 *        cidx: from kernel (msg info)
 * RIGHTS: with filemgr
 * RET:
 *   error of fd_check is processed
 *   error of fd_state_of is processed
 *   error of inode_of is processed
 *   error of tafs_inode_xip_map is directly return
 */
static ssize_t tafs_file_xip_map(struct vfs_ensemble_xip_map *ensemble, int32_t fd, size_t count, uint64_t *vaddr,
                                 uint64_t *vspace)
{
    (void)count;
    (void)vspace;
    struct vfs_tafs_data *tafs = container_of(ensemble->vfs_data, struct vfs_tafs_data, data);
    struct tafs_inode *inode = get_inode_from_vfs(tafs, fd, ensemble->cidx);
    if (inode == NULL)
        return -EINVAL;
    if (inode->state == TAFS_INODE_FILLING)
        inode->state = TAFS_INODE_READY;
    if (inode->state != TAFS_INODE_READY)
        return -EIO;

    return tafs_inode_xip_map(inode, ensemble->off, vaddr);
}

static ssize_t tafs_file_rename(struct vfs_ensemble_rename *ensemble, int32_t fd, const char *new_name)
{
    struct vfs_tafs_data *tafs = container_of(ensemble->vfs_data, struct vfs_tafs_data, data);
    if (!is_path_valid(new_name)) {
        hm_error("path is not valid\n");
        return -EINVAL;
    }
    struct tafs_inode *inode = get_inode_from_vfs(tafs, fd, ensemble->cidx);
    if (inode == NULL) {
        hm_error("inode not found\n");
        return -EINVAL;
    }
    if (memcpy_s(inode->filename, sizeof(inode->filename), new_name, TAFS_NAME_LEN) != 0) {
        hm_error("change filename failed\n");
        return -EFAULT;
    }
    return 0;
}

static ssize_t tafs_file_mmap(struct vfs_ensemble_mmap *ensemble, int32_t fd, uint64_t size, uint64_t off,
                              uint64_t task_vsroot, uint64_t *vaddr)
{
    struct vfs_tafs_data *tafs = container_of(ensemble->vfs_data, struct vfs_tafs_data, data);
    struct tafs_inode *inode = get_inode_from_vfs(tafs, fd, ensemble->cidx);
    if (inode == NULL) {
        hm_error("inode not found\n");
        return -EINVAL;
    }

    if ((off + size) < size || (off + size > inode->data_len)) {
        hm_error("size overflow\n");
        return -EINVAL;
    }

    uint64_t vaddr_filemgr = (uint64_t)(uintptr_t)inode->pages[0] + off;

    if (vaddr == NULL) {
        hm_error("address is null\n");
        return -EFAULT;
    }

    *vaddr = (uint64_t)(uintptr_t)hm_mapfile(vaddr_filemgr, task_vsroot, size);
    if (*vaddr == (uint64_t)MAP_FAILED) {
        hm_error("map file failed\n");
        return -EFAULT;
    }

    return 0;
}

/*
 * caller: do_stat
 * CODEREVIEW CHECKLIST
 * ARG:    vfs_data: vfs framework, always valid
 *         pathname: userinput, checked by is_path_valid
 *         stat: see do_stat, always valid
 *         cred: unused
 * RIGHTS: filemgr
 * RET:
 *   error of is_path_valid is processed
 *   error of inode_find is processed
 * RACING:
 * LEAK:
 */
/* dummy stat, only for eliminate error log */
#define XIP_ALLOW_STATE     00000
#define NOT_XIP_ALLOW_STATE 00640
static int32_t tafs_stat(struct vfs_data *vfs_data, const char *pathname, struct stat *stat, const cred_t *cred)
{
    (void)vfs_data;
    (void)cred;
    if (!is_path_valid(pathname))
        return -EINVAL;

    struct tafs_inode *inode = inode_find(pathname, false);
    if (inode == NULL)
        return -ENOENT;
    if (inode->state == TAFS_INODE_DEAD) {
        unlock(&inode->lock);
        return -ENOENT;
    }

    stat->uid = inode->uid;
    stat->gid = 0;
    if (inode->xip_state == XIP_ALLOW)
        stat->mode = XIP_ALLOW_STATE;
    else
        stat->mode = NOT_XIP_ALLOW_STATE;
    stat->size = (off_t)(inode->data_len);

    unlock(&inode->lock);

    return 0;
}

static int32_t tafs_set_uid(struct vfs_data *vfs_data, const char *pathname, uid_t uid)
{
    (void)vfs_data;
    struct tafs_inode *inode = NULL;
    int32_t inode_num;

    if (!is_path_valid(pathname))
        return -EINVAL;
    inode = inode_find(pathname, true);
    if (inode == NULL)
        return -ENOENT;
    if (inode->state == TAFS_INODE_DEAD)
        hm_panic("TAFS: inode of '%s' is DEAD\n", pathname);
    inode->uid = uid;
    inode_num  = inode_no(inode);
    if (inode_num < 0)
        hm_panic("inode_no returns error\n");
    unlock(&inode->lock); /* release the lock of inode for getlabel */
    return 0;
}

/*
 * What we already support are:
 * - open
 * - create
 * - close
 * - unlink
 * - ftruncate
 * - read
 * - write
 * - xip_map
 * - stat
 *
 * What we lack of for now are:
 * - mkfs
 * - mount
 * - unmount
 * - openat
 * - truncate
 * - lseek
 * - getdents
 * - mkdirat
 */
struct vfs_ops g_vfs_tafs_ops = {
    .name         = "vfs_tafs_ops",
    .mkfs         = NULL,
    .mount        = NULL,
    .umount       = NULL,
    .open         = tafs_file_open,
    .openat       = NULL,
    .creat        = NULL,
    .close        = tafs_file_close,
    .unlink       = tafs_file_unlink,
    .truncate     = NULL,
    .ftruncate    = tafs_file_ftruncate,
    .read         = tafs_file_read,
    .write        = tafs_file_write,
    .lseek        = NULL,
    .getdents     = NULL,
    .mkdirat      = NULL,
    .xip_map      = tafs_file_xip_map,
    .setattr      = NULL,
    .stat         = tafs_stat,
    .print_fsinfo = tafs_print_fsinfo,
    .set_uid      = tafs_set_uid,
    .rename       = tafs_file_rename,
    .mmap         = tafs_file_mmap,
};

/*
 * caller: main of filemgr (init stage)
 * CODEREVIEW CHECKLIST
 * ARG:   always valid (ensured by caller)
 * RET:  memset_s never fail
 *       vfs_data_init is void
 */
/* Setup TA filesystem metatdata */
bool tafs_init(struct vfs_tafs_data *data)
{
    if (memset_s(&data->fd_state, sizeof(data->fd_state), 0, sizeof(data->fd_state)) != EOK)
        hm_panic("memset_s failed\n");
    if (memset_s(g_inodes, sizeof(g_inodes), 0, sizeof(g_inodes)) != EOK)
        hm_panic("memset_s failed\n");
    vfs_data_init(&data->data, "/tafs/", &g_vfs_tafs_ops);
    return true;
}
