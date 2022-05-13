/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: vfs functions to make virtual filesystem
 * Create: 2019-05-18
 */

#include <pthread.h>
#include <kernel/cspace.h>
#include <cs.h>
#include <sys/libvfs.h>
#include <dlist.h>
#include <tee_bitmap.h>

/* Not sure why O_TMPFILE is not showing, so this is a temporary work-around */
#ifndef O_TMPFILE
#define O_TMPFILE 0
#endif

#ifdef USE_IN_SYSMGR
static inline int32_t vfs_entry(void)
{
        return HM_OK;
}

static int32_t vfs_exit(void)
{
        return HM_OK;
}

static int32_t vfs_set_errno_ret(int32_t err)
{
        (void)err;
            return HM_ERROR;
}

#else
static pthread_mutex_t g_vfs_mutex = PTHREAD_MUTEX_INITIALIZER;

static int32_t vfs_entry(void)
{
    if (pthread_mutex_lock(&g_vfs_mutex) != HM_OK) {
        errno = EIO;
        hm_error("fail to lock vfs mutex\n");
        return HM_ERROR;
    }

    return HM_OK;
}

static int32_t vfs_exit(void)
{
    if (pthread_mutex_unlock(&g_vfs_mutex) != HM_OK) {
        errno = EIO;
        hm_error("fail to unlock vfs mutex\n");
        return HM_ERROR;
    }

    return HM_OK;
}

static int32_t vfs_set_errno_ret(int32_t err)
{
    errno = err;

    if (pthread_mutex_unlock(&g_vfs_mutex) != HM_OK)
        hm_error("fail to unlock vfs mutex\n");

    return HM_ERROR;
}
#endif

static int32_t vfs_set_errno_ret_if_fail(int32_t err)
{
    if (err < 0)
        return vfs_set_errno_ret(err);

    return HM_OK;
}

#define VFS_MAX_FD_CNT 50
#define OFFSET         7
#define INVALID_BIT    (-1)

/*
 * Information for vfs file descriptors
 * @in_use:    True if this file descriptor is in use, false otherwise
 * @fd:        File descriptor for the particular type of file for this vfs
 *             file descriptor
 * @type:      Type of filesystem server
 * @off:       Current file pointer
 */
typedef struct process_fds {
    int32_t fd;
    struct vfs_data *vfs_data;
    off_t offset;
    int32_t vfs_fd;
    struct dlist_node list_node;
} process_fds_t;

static dlist_head(g_process_fds);
static uint8_t g_process_fds_bitmap[(VFS_MAX_FD_CNT + OFFSET) >> MOVE_BIT] = { 0 };
static dlist_head(g_fss_head);

/* Find one unused fd from the pool and mark it as being in use */
static int32_t fd_alloc(void)
{
    int32_t idx;

    idx = get_valid_bit(g_process_fds_bitmap, VFS_MAX_FD_CNT);
    if (idx == INVALID_BIT) {
        hm_error("max fd limited\n");
        return -EMFILE;
    }

    return idx;
}

/* a sanity check */
static bool fd_valid(int32_t fd)
{
    return ((fd >= 0) && ((uint32_t)fd < VFS_MAX_FD_CNT));
}

static process_fds_t *find_process_fds(int32_t fd)
{
    process_fds_t *process_fd = NULL;
    dlist_for_each_entry(process_fd, &g_process_fds, process_fds_t, list_node) {
        if (process_fd->vfs_fd == fd)
            return process_fd;
    }

    return NULL;
}

static void fd_free(int32_t fd)
{
    process_fds_t *process_fd = NULL;
    process_fd = find_process_fds(fd);
    if (process_fd != NULL) {
        clear_bitmap(g_process_fds_bitmap, VFS_MAX_FD_CNT, fd);
        dlist_delete(&process_fd->list_node);
        free(process_fd);
    }
}

/* Setup vfs metatdata */
void vfs_data_init(struct vfs_data *data, const char *path, const struct vfs_ops *ops)
{
    if (data == NULL || path == NULL || ops == NULL || *path != '/')
        return;

    data->fs_root = path;
    data->ops     = ops;
}

/*
 * Add a filesystem
 * @data:    Pointer to a &struct vfs_data.
 *
 * This should be called with the deepest pathnames first, i.e. "/abc/def"
 * before "/abc".
 */
int32_t vfs_add_fs(struct vfs_data *data)
{
    struct dlist_node *pos = NULL;

    /* Verify that things are reasonable */
    if (data == NULL)
        return -EINVAL;

    if (data->fs_root == NULL || *data->fs_root != '/') {
        hm_error("paths must begin with slash (/)\n");
        return -EINVAL;
    }

    if (data->ops == NULL) {
        hm_error("invalid vfs ops\n");
        return -EINVAL;
    }

    dlist_for_each(pos, &g_fss_head) {
        struct vfs_data *cur = dlist_entry(pos, struct vfs_data, fss);
        if (strncmp(data->fs_root, cur->fs_root, strlen(cur->fs_root)) >= 0) {
            hm_error("paths must be in reverse lexographic order\n");
            hm_error("i.e. %s should proceed %s\n", cur->fs_root, data->fs_root);
            return -EINVAL;
        }
    }

    dlist_insert_tail(&data->fss, &g_fss_head);

    return HM_OK;
}

/*
 * Figures out which filesystem to which an operation should be directed
 * @at_fd: File discriptor for default directory for relative pathnames,
 *         -1 if there isn't a default directory.
 * @pathname: Name of the pathname for whicha search is being done
 */
static struct vfs_data *vfs_data_find(int32_t at_fd, const char *pathname)
{
    struct dlist_node *pos          = NULL;
    struct vfs_data *last_vfs_data = NULL;
    process_fds_t *process_fd = NULL;
    /*
     * If this is a relative pathname, we use the file descriptor to
     * locate the appropriate vfs_data
     */
    if (*pathname != '/') {
        /* HM_NOTE: should use CWD */
        if (at_fd == -1 || !fd_valid(at_fd))
            return NULL;

        process_fd = find_process_fds(at_fd);
        if (process_fd != NULL) {
            last_vfs_data = process_fd->vfs_data;
            return last_vfs_data;
        }
    }

    last_vfs_data = NULL;

    dlist_for_each(pos, &g_fss_head) {
        struct vfs_data *vfs_data = dlist_entry(pos, struct vfs_data, fss);
        size_t len = strlen(vfs_data->fs_root);
        if (strncmp(vfs_data->fs_root, pathname, len) == HM_OK && (pathname[len] == '/' || pathname[len] == '\0'))
            return vfs_data;

        last_vfs_data = vfs_data;
    }

    if (last_vfs_data == NULL)
        hm_error("No match for \"%s\"\n", pathname);

    return last_vfs_data;
}

/*
 * Clip off the leading part of the pathname that corresponds to the virtual
 * filesystem.
 */
static const char *adjust_path(const struct vfs_data *vfs_data, const char *pathname)
{
    if (vfs_data == NULL)
        return NULL;

    if (strncmp(vfs_data->fs_root, "/", strlen("/")) == HM_OK) /* Just the root */
        return pathname;

    if (*pathname != '/') /* Relative */
        return pathname;

    size_t len           = strlen(vfs_data->fs_root); /* Clip the path */
    const char *adjusted = pathname + len;
    if (*adjusted == '\0') /* Too short! */
        adjusted = "/";

    return adjusted;
}

static int32_t entry_and_init_vfs(const char *path, struct vfs_data **vfs_data, const struct vfs_ops **ops)
{
    if (vfs_entry() != HM_OK)
        return HM_ERROR;

    if (path == NULL)
        return vfs_set_errno_ret(EINVAL);
    /*
     * fd is -1, which means there isn't a default directory
     * in vfs_data_find(), if we use relative path, means
     * we can find file in default directory, but we cannot
     */
    *vfs_data = vfs_data_find(-1, path);
    if (*vfs_data == NULL) {
        hm_error("vfs data find failed\n");
        return vfs_set_errno_ret(ENOENT);
    }

    *ops = (*vfs_data)->ops;

    return HM_OK;
}

/*
 * mkfs: make a filesystem at given path. Just a fake interface
 * attention: vfs_tafs_ops/vfs_ramfs_ops.mkfs = NULL now
 */
int32_t VFS(mkfs)(const char *path)
{
    struct vfs_data *vfs_data = NULL;
    const struct vfs_ops *ops = NULL;

    if (entry_and_init_vfs(path, &vfs_data, &ops) != HM_OK)
        return HM_ERROR;

    if (ops->mkfs == NULL)
        return vfs_set_errno_ret(ENOSYS);

    int32_t rc = ops->mkfs(vfs_data, path);
    if (rc < 0) {
        hm_error("mkfs failed: %d\n", rc);
        return vfs_set_errno_ret(-rc);
    }

    return (vfs_exit() == HM_OK) ? (rc) : (HM_ERROR);
}

/* mount: mount a fs to root. */
int32_t VFS(mount)(const char *path)
{
    struct vfs_data *vfs_data = NULL;
    const struct vfs_ops *ops = NULL;

    if (entry_and_init_vfs(path, &vfs_data, &ops) != HM_OK)
        return HM_ERROR;

    if (ops->mount == NULL)
        return vfs_set_errno_ret(ENOSYS);

    int32_t rc = ops->mount(vfs_data, path);
    if (rc < 0) {
        hm_error("mount failed: %d\n", rc);
        return vfs_set_errno_ret(-rc);
    }

    return (vfs_exit() == HM_OK) ? (rc) : (HM_ERROR);
}

/* umount: umount a fs. Now it's commnly an empty func or NULL. */
int32_t VFS(umount)(const char *path)
{
    struct vfs_data *vfs_data = NULL;
    const struct vfs_ops *ops = NULL;

    if (entry_and_init_vfs(path, &vfs_data, &ops) != HM_OK)
        return HM_ERROR;

    if (ops->umount == NULL)
        return vfs_set_errno_ret(ENOSYS);

    int32_t rc = ops->umount(vfs_data, path);
    if (rc < 0) {
        hm_error("mount failed: %d\n", rc);
        return vfs_set_errno_ret(-rc);
    }

    return (vfs_exit() == HM_OK) ? (rc) : (HM_ERROR);
}

static int32_t add_process_fd(struct vfs_data *vfs_data, int32_t vfs_fd, int32_t fd)
{
    process_fds_t *process_fd = NULL;

    if (vfs_data == NULL)
        return HM_ERROR;

    process_fd = malloc(sizeof(process_fds_t));
    if (process_fd == NULL)
        return HM_ERROR;

    process_fd->vfs_data = vfs_data;
    process_fd->fd       = fd;
    process_fd->vfs_fd   = vfs_fd;
    process_fd->offset   = 0;

    dlist_insert_tail(&process_fd->list_node, &g_process_fds);
    set_bitmap(g_process_fds_bitmap, VFS_MAX_FD_CNT, vfs_fd);
    return HM_OK;
}

/* open: open a file, return a file handle. */
static int32_t vopen(const char *pathname, const cred_t *cred, int32_t flags, va_list ap)
{
    mode_t mode;
    uint64_t memid = 0;

    if (pathname == NULL)
        return vfs_set_errno_ret(EINVAL);

    int32_t vfs_fd = fd_alloc();
    if (vfs_fd < 0)
        return vfs_set_errno_ret(-vfs_fd);

    /* If it was required to be passed, get the mode argument */
    if (((uint32_t)flags & (O_CREAT | O_TMPFILE)) != 0) {
        mode = va_arg(ap, mode_t);
        if (strncmp(pathname, "/tafs/", strlen("/tafs/")) == HM_OK)
            memid = va_arg(ap, uint64_t);
    } else {
        mode = 0;
    }

    /*
     * fd is -1, which means there isn't a default directory
     * in vfs_data_find(), if we use relative path, means
     * we can find file in default directory, but we cannot
     */
    struct vfs_data *vfs_data = vfs_data_find(-1, pathname);
    if (vfs_data == NULL) {
        hm_error("vfs data find failed\n");
        fd_free(vfs_fd);
        return vfs_set_errno_ret(ENOENT);
    }

    if (vfs_data->ops->open == NULL) {
        fd_free(vfs_fd);
        return vfs_set_errno_ret(ENOSYS);
    }

    const char *adjusted_pathname = adjust_path(vfs_data, pathname);
    if (adjusted_pathname == NULL) {
        fd_free(vfs_fd);
        return vfs_set_errno_ret(EINVAL);
    }

    struct vfs_ensemble_open ensemble = { vfs_data, cred, 0, memid };
    int32_t fd = vfs_data->ops->open(&ensemble, adjusted_pathname, flags, mode);
    if (fd < 0) {
        hm_error("open(\"%s\" (adjusted \"%s\")) failed: %d\n", pathname, adjusted_pathname, fd);
        fd_free(vfs_fd);
        return vfs_set_errno_ret(-fd);
    }

    if (add_process_fd(vfs_data, vfs_fd, fd) != HM_OK) {
        fd_free(vfs_fd);
        return vfs_set_errno_ret(ENOSYS);
    }
    return vfs_fd;
}

int32_t VFS(_open)(const char *pathname, const cred_t *cred, int32_t flags, ...)
{
    if (vfs_entry() != HM_OK)
        return HM_ERROR;

    va_list va;
    va_start(va, flags);
    int32_t rc = vopen(pathname, cred, flags, va);
    va_end(va);

    return (vfs_exit() == HM_OK) ? (rc) : (HM_ERROR);
}

/*
 * Given a pathname for a file, open() returns a file descriptor
 * or -1 if an error occurred (in which case, errno is set appropriately).
 */
int32_t VFS(open)(const char *pathname, int32_t flags, ...)
{
    if (vfs_entry() != HM_OK)
        return HM_ERROR;

    va_list va;
    va_start(va, flags);
    int32_t rc = vopen(pathname, NULL, flags, va);
    va_end(va);

    return (vfs_exit() == HM_OK) ? (rc) : (HM_ERROR);
}

int32_t VFS(print_fsinfo)(const char *pathname)
{
    if (vfs_entry() != HM_OK)
        return HM_ERROR;

    const struct vfs_ops *ops = NULL;
    struct vfs_data *vfs_data = NULL;

    if (pathname == NULL)
        return vfs_set_errno_ret(EINVAL);

    vfs_data = vfs_data_find(-1, pathname);
    if (vfs_data == NULL) {
        hm_error("vfs data find failed\n");
        return vfs_set_errno_ret(ENOENT);
    }

    ops = vfs_data->ops;
    if (ops == NULL || ops->print_fsinfo == NULL)
        return vfs_set_errno_ret(ENOSYS);

    int32_t rc = ops->print_fsinfo(vfs_data);
    if (rc < 0) {
        hm_error("print(\"%s\" ) failed: %d\n", pathname, rc);
        return vfs_set_errno_ret(-rc);
    }

    return (vfs_exit() == HM_OK) ? (rc) : (HM_ERROR);
}

int32_t VFS(set_uid)(const char *pathname, uid_t uid)
{
    if (vfs_entry() != HM_OK)
        return HM_ERROR;

    const struct vfs_ops *ops     = NULL;
    struct vfs_data *vfs_data     = NULL;
    const char *adjusted_pathname = NULL;

    if (pathname == NULL)
        return vfs_set_errno_ret(EINVAL);
    /*
     * fd is -1, which means there isn't a default directory
     * in vfs_data_find(), if we use relative path, means
     * we can find file in default directory, but we cannot
     */
    vfs_data = vfs_data_find(-1, pathname);
    if (vfs_data == NULL) {
        hm_error("vfs data find failed\n");
        return vfs_set_errno_ret(ENOENT);
    }

    ops = vfs_data->ops;
    if (ops == NULL || ops->set_uid == NULL)
        return vfs_set_errno_ret(ENOSYS);

    adjusted_pathname = adjust_path(vfs_data, pathname);
    if (adjusted_pathname == NULL)
        return vfs_set_errno_ret(EINVAL);

    int32_t rc = ops->set_uid(vfs_data, adjusted_pathname, uid);
    if (rc < 0) {
        hm_error("set_label(\"%s\" (adjusted \"%s\")) failed: %d\n", pathname, adjusted_pathname, rc);
        return vfs_set_errno_ret(-rc);
    }

    return (vfs_exit() == HM_OK) ? (rc) : (HM_ERROR);
}

/*
 * creates a new open file description, an entry in the system-wide table of open files.
 * The open file description records the file offset and the file status flags.
 */
int32_t VFS(_creat)(const char *pathname, mode_t mode, const cred_t *cred)
{
    int32_t ret;
    if (vfs_entry() != HM_OK)
        return HM_ERROR;

    if (pathname == NULL)
        return vfs_set_errno_ret(EINVAL);

    int32_t vfs_fd = fd_alloc();
    if (vfs_fd < 0)
        return vfs_set_errno_ret(-vfs_fd);
    /*
     * fd is -1, which means there isn't a default directory
     * in vfs_data_find(), if we use relative path, means
     * we can find file in default directory, but we cannot
     */
    struct vfs_data *vfs_data = vfs_data_find(-1, pathname);
    if (vfs_data == NULL) {
        hm_error("vfs data find failed\n");
        fd_free(vfs_fd);
        return vfs_set_errno_ret(ENOENT);
    }

    const struct vfs_ops *ops = vfs_data->ops;
    if (ops->creat == NULL) {
        fd_free(vfs_fd);
        return vfs_set_errno_ret(ENOSYS);
    }

    const char *adjusted_pathname = adjust_path(vfs_data, pathname);
    if (adjusted_pathname == NULL) {
        fd_free(vfs_fd);
        return vfs_set_errno_ret(EINVAL);
    }

    int32_t fd = ops->creat(vfs_data, adjusted_pathname, mode, cred, 0);
    if (fd < 0) {
        hm_error("creat(\"%s\" (adjusted \"%s\")) failed: %d\n", pathname, adjusted_pathname, fd);
        fd_free(vfs_fd);
        return vfs_set_errno_ret(-fd);
    }

    ret = add_process_fd(vfs_data, vfs_fd, fd);
    if (ret != HM_OK) {
        fd_free(vfs_fd);
        return vfs_set_errno_ret(ENOSYS);
    }
    return (vfs_exit() == HM_OK) ? (vfs_fd) : (HM_ERROR);
}

/* wrapper of _creat */
int32_t VFS(creat)(const char *pathname, mode_t mode)
{
    return VFS(_creat)(pathname, mode, NULL);
}

static int32_t init_vfs_and_ops_and_pathname(const char *pathname, struct vfs_data **vfs_data,
                                             const struct vfs_ops **ops, const char **adjusted_pathname)
{
    /*
     * fd is -1, which means there isn't a default directory
     * in vfs_data_find(), if we use relative path, means
     * we can find file in default directory, but we cannot
     */
    *vfs_data = vfs_data_find(-1, pathname);
    if (*vfs_data == NULL) {
        hm_error("vfs data find failed\n");
        return vfs_set_errno_ret(ENOENT);
    }

    *ops = (*vfs_data)->ops;
    if ((*ops)->setattr == NULL)
        return vfs_set_errno_ret(ENOSYS);

    *adjusted_pathname = adjust_path(*vfs_data, pathname);
    if (*adjusted_pathname == NULL)
        return vfs_set_errno_ret(EINVAL);

    return HM_OK;
}

static int32_t init_vfs_and_setattr(const char *pathname, const struct iattr *ia, const cred_t *cred)
{
    struct vfs_data *vfs_data = NULL;
    const struct vfs_ops *ops = NULL;
    const char *adjusted_pathname = NULL;
    if (init_vfs_and_ops_and_pathname(pathname, &vfs_data, &ops, &adjusted_pathname) != HM_OK)
        return HM_ERROR;

    int32_t rc = ops->setattr(vfs_data, adjusted_pathname, ia, cred);
    if (vfs_set_errno_ret_if_fail(rc) != HM_OK)
        return HM_ERROR;

    return HM_OK;
}

/* Change the owner and/or group of the FILE to OWNER and/or GROUP. */
int32_t VFS(_chown)(const char *pathname, uid_t uid, gid_t gid, const cred_t *cred)
{
    if (vfs_entry() != HM_OK)
        return HM_ERROR;

    if (pathname == NULL)
        return vfs_set_errno_ret(EINVAL);

    /* HM_NOTE: only allow root user to do this for now, any check? */
    struct iattr ia = {0};
    ia.ia_valid = ATTR_UID | ATTR_GID;
    ia.cred.uid = uid;
    ia.cred.gid = gid;

    if (init_vfs_and_setattr(pathname, &ia, cred) != HM_OK)
        return HM_ERROR;

    return vfs_exit();
}

/* wrapper of chown */
int32_t VFS(chown)(const char *pathname, uid_t uid, gid_t gid)
{
    return VFS(_chown)(pathname, uid, gid, NULL);
}

/* change file mode bits */
int32_t VFS(_chmod)(const char *pathname, mode_t mode, const cred_t *cred)
{
    if (vfs_entry() != HM_OK)
        return HM_ERROR;

    if (pathname == NULL || (mode & S_IALLUGO) != mode)
        return vfs_set_errno_ret(EINVAL);

    /*
     * vfs layer can not touch the generic inode and the
     * attributes, so we can only do the permission check in lower
     * ops.
     */
    struct iattr ia = {0};
    ia.ia_valid = ATTR_MODE;
    ia.mode     = mode;

    if (init_vfs_and_setattr(pathname, &ia, cred) != HM_OK)
        return HM_ERROR;

    return vfs_exit();
}

/* wrapper of chmod */
int32_t VFS(chmod)(const char *pathname, mode_t mode)
{
    return VFS(_chmod)(pathname, mode, NULL);
}

/*
 * Display file or file system status.
 *
 * For instance, the tafs would like to show:
 * - uid
 * - gid
 * - mode
 */
int32_t VFS(_stat)(const char *pathname, struct stat *stat, const cred_t *cred)
{
    if (vfs_entry() != HM_OK)
        return HM_ERROR;

    if (pathname == NULL || stat == NULL)
        return vfs_set_errno_ret(EINVAL);

    struct vfs_data *vfs_data = vfs_data_find(-1, pathname);
    if (vfs_data == NULL) {
        hm_error("vfs data find failed\n");
        return vfs_set_errno_ret(ENOENT);
    }

    const struct vfs_ops *ops = vfs_data->ops;
    if (ops->stat == NULL)
        return vfs_set_errno_ret(ENOSYS);

    const char *adjusted_pathname = adjust_path(vfs_data, pathname);
    if (adjusted_pathname == NULL)
        return vfs_set_errno_ret(EINVAL);

    int32_t rc = ops->stat(vfs_data, adjusted_pathname, stat, cred);
    if (vfs_set_errno_ret_if_fail(rc) != HM_OK)
        return HM_ERROR;

    return vfs_exit();
}

/* wrapper of stat */
int32_t VFS(stat)(const char *pathname, struct stat *stat)
{
    return VFS(_stat)(pathname, stat, NULL);
}

/* closes a file descriptor, so that it no longer refers to any file and may be reused. */
int32_t VFS(close)(int32_t vfs_fd)
{
    struct vfs_data *vfs_data = NULL;
    process_fds_t *process_fd = NULL;
    if (vfs_entry() != HM_OK)
        return HM_ERROR;

    int32_t fd = -1;

    if (!fd_valid(vfs_fd))
        return vfs_set_errno_ret(EINVAL);

    process_fd = find_process_fds(vfs_fd);
    if (process_fd == NULL)
        return vfs_set_errno_ret(ENOSYS);

    fd = process_fd->fd;
    vfs_data = process_fd->vfs_data;
    const struct vfs_ops *ops = vfs_data->ops;
    if (ops->close == NULL)
        return vfs_set_errno_ret(ENOSYS);

    int32_t rc = ops->close(vfs_data, fd, 0);
    if (rc < 0) {
        hm_error("close failed: %d\n", rc);
        return vfs_set_errno_ret(-rc);
    }

    fd_free(vfs_fd);

    return vfs_exit();
}

/* Call the unlink function to remove the specified FILE. */
int32_t VFS(unlink)(const char *pathname)
{
    if (vfs_entry() != HM_OK)
        return HM_ERROR;

    if (pathname == NULL)
        return vfs_set_errno_ret(EINVAL);
    struct vfs_data *vfs_data = vfs_data_find(-1, pathname);
    if (vfs_data == NULL) {
        hm_error("vfs data find file failed\n");
        return vfs_set_errno_ret(ENOENT);
    }

    const struct vfs_ops *ops = vfs_data->ops;
    if (ops->unlink == NULL)
        return vfs_set_errno_ret(ENOSYS);

    const char *adjusted_pathname = adjust_path(vfs_data, pathname);
    if (adjusted_pathname == NULL)
        return vfs_set_errno_ret(EINVAL);

    int32_t rc = ops->unlink(vfs_data, adjusted_pathname);
    if (rc < 0) {
        hm_error("unlink(\"%s\" (adjusted \"%s\")) failed: %d\n", pathname, adjusted_pathname, rc);
        return vfs_set_errno_ret(-rc);
    }

    return vfs_exit();
}

/* shrink the size of a file to the specified size. */
int32_t VFS(truncate)(const char *pathname, off_t length)
{
    if (vfs_entry() != HM_OK)
        return HM_ERROR;

    if (pathname == NULL || length < 0)
        return vfs_set_errno_ret(EINVAL);

    struct vfs_data *vfs_data = vfs_data_find(-1, pathname);
    if (vfs_data == NULL) {
        hm_error("vfs data find file failed\n");
        return vfs_set_errno_ret(ENOENT);
    }

    const struct vfs_ops *ops = vfs_data->ops;
    if (ops->truncate == NULL)
        return vfs_set_errno_ret(ENOSYS);

    const char *adjusted_pathname = adjust_path(vfs_data, pathname);
    if (adjusted_pathname == NULL)
        return vfs_set_errno_ret(EINVAL);

    int32_t rc = ops->truncate(vfs_data, adjusted_pathname, length);
    if (rc < 0) {
        hm_error("truncate(\"%s\" (adjusted \"%s\")) failed: %d\n", pathname, adjusted_pathname, rc);
        return vfs_set_errno_ret(-rc);
    }

    return vfs_exit();
}

int32_t VFS(ftruncate)(int32_t vfs_fd, off_t length)
{
    struct vfs_data *vfs_data = NULL;
    process_fds_t *process_fd = NULL;
    if (vfs_entry() != HM_OK)
        return HM_ERROR;

    int32_t fd = -1;

    if (!fd_valid(vfs_fd) || length < 0)
        return vfs_set_errno_ret(EINVAL);

    process_fd = find_process_fds(vfs_fd);
    if (process_fd == NULL)
        return vfs_set_errno_ret(ENOSYS);

    fd = process_fd->fd;
    vfs_data = process_fd->vfs_data;
    const struct vfs_ops *ops = vfs_data->ops;
    if (ops->ftruncate == NULL)
        return vfs_set_errno_ret(ENOSYS);

    int32_t rc = ops->ftruncate(vfs_data, fd, length, 0);
    if (rc < 0) {
        hm_error("ftruncate failed: %d\n", rc);
        return vfs_set_errno_ret(-rc);
    }

    return vfs_exit();
}

static int32_t get_ops_by_fd(int32_t vfs_fd, int32_t *fd, struct vfs_data **vfs_data,
                             const void *buf, off_t **offset)
{
    if (vfs_entry() != HM_OK || buf == NULL)
        return HM_ERROR;

    process_fds_t *process_fd = NULL;

    if (!fd_valid(vfs_fd))
        return vfs_set_errno_ret(EINVAL);

    process_fd = find_process_fds(vfs_fd);
    if (process_fd == NULL)
        return vfs_set_errno_ret(ENOSYS);

    *fd = process_fd->fd;
    *vfs_data = process_fd->vfs_data;
    *offset = &process_fd->offset;

    return HM_OK;
}

/*
 * read from a file descriptor.
 *
 * On success, the number of bytes read is returned (zero indicates end of file).
 * On error, -1 is returned, and errno is set appropriately.
 */
ssize_t VFS(read)(int32_t vfs_fd, void *buf, size_t size)
{
    off_t *offset = NULL;
    struct vfs_data *vfs_data = NULL;
    int32_t fd = -1;

    int32_t ret = get_ops_by_fd(vfs_fd, &fd, &vfs_data, buf, &offset);
    if (ret != HM_OK)
        return ret;

    const struct vfs_ops *ops = vfs_data->ops;
    if (ops->read == NULL)
        return vfs_set_errno_ret(ENOSYS);

    struct vfs_ensemble_read ensemble = { vfs_data, offset, 0 };
    ssize_t zrc = ops->read(&ensemble, fd, buf, size);
    if (zrc < 0) {
        hm_error("read failed: %d\n", (int)(-zrc));
        return vfs_set_errno_ret((int)(-zrc));
    }

    return (vfs_exit() == HM_OK) ? (zrc) : (HM_ERROR);
}

/*
 * Write to a file descriptor.
 *
 * On success, the number of bytes that has been written.
 * On error, -1 is returned and errno is set to indicate the error.
 */
ssize_t VFS(write)(int32_t vfs_fd, const void *buf, size_t size)
{
    off_t *offset = NULL;
    struct vfs_data *vfs_data = NULL;
    int32_t fd = -1;

    int32_t ret = get_ops_by_fd(vfs_fd, &fd, &vfs_data, buf, &offset);
    if (ret != HM_OK)
        return ret;

    const struct vfs_ops *ops = vfs_data->ops;
    if (ops->write == NULL)
        return vfs_set_errno_ret(ENOSYS);

    struct vfs_ensemble_write ensemble = { vfs_data, offset, 0 };
    ssize_t zrc = ops->write(&ensemble, fd, buf, size);
    if (zrc < 0) {
        hm_error("write failed: %d\n", (int)(-zrc));
        return vfs_set_errno_ret((int)(-zrc));
    }

    return (vfs_exit() == HM_OK) ? (zrc) : (HM_ERROR);
}

/* xip feature for memory save and reuse tafs occupied memory */
ssize_t VFS(xip_map)(int32_t vfs_fd, off_t *off, size_t size, uint64_t *vaddr, uint64_t *vspace)
{
    off_t *offset = NULL;
    struct vfs_data *vfs_data = NULL;
    process_fds_t *process_fd = NULL;

    if (vfs_entry() != HM_OK)
        return HM_ERROR;

    int32_t fd = -1;

    if (!fd_valid(vfs_fd) || off == NULL || vaddr == NULL || vspace == NULL)
        return vfs_set_errno_ret(EINVAL);

    process_fd = find_process_fds(vfs_fd);
    if (process_fd == NULL)
        return vfs_set_errno_ret(ENOSYS);

    fd = process_fd->fd;
    vfs_data = process_fd->vfs_data;
    offset = &process_fd->offset;
    const struct vfs_ops *ops = vfs_data->ops;
    if (ops->xip_map == NULL)
        return vfs_set_errno_ret(ENOSYS);

    struct vfs_ensemble_xip_map ensemble = { vfs_data, offset, 0 };
    ssize_t zrc = ops->xip_map(&ensemble, fd, size, vaddr, vspace);
    if (zrc < 0) {
        hm_error("xip_map failed: %d\n", (int)(-zrc));
        return vfs_set_errno_ret((int)(-zrc));
    }

    *off = *offset;

    return (vfs_exit() == HM_OK) ? (zrc) : (HM_ERROR);
}

int32_t VFS(vfs_rename)(int32_t vfs_fd, const char *new_name)
{
    int32_t fd = -1;
    process_fds_t *process_fd = NULL;
    struct vfs_data *vfs_data = NULL;

    if (vfs_entry() != HM_OK)
        return HM_ERROR;

    if (!fd_valid(vfs_fd) || new_name == NULL)
        return vfs_set_errno_ret(EINVAL);

    process_fd = find_process_fds(vfs_fd);
    if (process_fd == NULL)
        return vfs_set_errno_ret(ENOSYS);

    fd = process_fd->fd;
    vfs_data = process_fd->vfs_data;
    const struct vfs_ops *ops = vfs_data->ops;
    if (ops->rename == NULL)
        return vfs_set_errno_ret(ENOSYS);

    struct vfs_ensemble_rename ensemble = { vfs_data, 0 };
    ssize_t zrc = ops->rename(&ensemble, fd, new_name);
    if (zrc < 0) {
        hm_error("rename failed: %d\n", (int32_t)(-zrc));
        return vfs_set_errno_ret((int32_t)(-zrc));
    }

    return (vfs_exit() == HM_OK) ? (zrc) : (HM_ERROR);
}

void *VFS(vfs_mmap)(int32_t vfs_fd, uint64_t size, uint64_t off)
{
    process_fds_t *process_fd = NULL;
    struct vfs_data *vfs_data = NULL;

    if (vfs_entry() != HM_OK)
        return NULL;

    int32_t fd = -1;

    if (!fd_valid(vfs_fd)) {
        hm_error("invalid fd\n");
        return NULL;
    }

    process_fd = find_process_fds(vfs_fd);
    if (process_fd == NULL)
        return NULL;

    fd = process_fd->fd;
    vfs_data = process_fd->vfs_data;
    const struct vfs_ops *ops = vfs_data->ops;
    if (ops->mmap == NULL) {
        hm_error("no struct member\n");
        return NULL;
    }

    struct vfs_ensemble_mmap ensemble = { vfs_data, 0 };
    uint64_t vaddr;
    ssize_t zrc = ops->mmap(&ensemble, fd, size, off, 0, &vaddr);
    if (zrc < 0) {
        hm_error("file map failed: %d\n", (int32_t)(-zrc));
        return NULL;
    }

    return (vfs_exit() == HM_OK) ? ((void *)(uintptr_t)vaddr) : (NULL);
}

/*
 * Now underlying filesystems have not support lseek yet, so only handle
 * it in vfs and doesn't dive into the underlying filesystems.
 */
off_t VFS(lseek)(int32_t vfs_fd, off_t off, int32_t whence)
{
    process_fds_t *process_fd = NULL;
    if (vfs_entry() != HM_OK)
        return HM_ERROR;

    off_t orc;

    if (!fd_valid(vfs_fd))
        return vfs_set_errno_ret(EINVAL);

    switch (whence) {
    case SEEK_SET:
        if (off >= 0) {
            process_fd = find_process_fds(vfs_fd);
            if (process_fd == NULL)
                return vfs_set_errno_ret(ENOSYS);

            process_fd->offset = off;
            orc = off;
        } else {
            errno = EINVAL;
            orc   = HM_ERROR;
        }
        break;
    case SEEK_CUR:
    case SEEK_END:
        hm_error("lseek: %d not yet supported\n", whence);
        errno = ENOSYS;
        orc   = HM_ERROR;
        break;
    default:
        errno = EINVAL;
        orc   = HM_ERROR;
        break;
    }

    return (vfs_exit() == HM_OK) ? (orc) : (HM_ERROR);
}

/*
 * get directory entries.
 *
 * Reads several dirent structures from the directory referred to by the
 * open file descriptor @vfd_fd into the buffer pointed to by @dirents.
 * The argument count specifies the size of that buffer.
 */
ssize_t VFS(getdents)(int32_t vfs_fd, struct dirent *dirents, size_t count)
{
    off_t *offset = NULL;
    struct vfs_data *vfs_data = NULL;
    process_fds_t *process_fd = NULL;
    if (vfs_entry() != HM_OK)
        return HM_ERROR;

    int32_t fd = -1;

    if (!fd_valid(vfs_fd) || dirents == NULL)
        return vfs_set_errno_ret(EINVAL);

    process_fd = find_process_fds(vfs_fd);
    if (process_fd == NULL)
        return vfs_set_errno_ret(ENOSYS);

    fd = process_fd->fd;
    vfs_data = process_fd->vfs_data;
    offset = &process_fd->offset;
    const struct vfs_ops *ops = vfs_data->ops;
    if (ops->getdents == NULL)
        return vfs_set_errno_ret(ENOSYS);

    struct vfs_ensemble_getdents ensemble = { vfs_data, offset, 0 };
    ssize_t zrc = ops->getdents(&ensemble, fd, dirents, count);
    if (zrc < 0) {
        hm_error("getdents failed: %d\n", (int)(-zrc));
        return vfs_set_errno_ret((int)(-zrc));
    }

    return (vfs_exit() == HM_OK) ? (zrc) : (HM_ERROR);
}

/*
 * mkdirat attempts to create a directory named pathname.
 * Just a fake interface right now!! mkdirat is NULL for all fs.
 */
int32_t VFS(mkdirat)(int32_t vfs_fd, const char *pathname, mode_t mode)
{
    struct vfs_data *vfs_data = NULL;
    process_fds_t *process_fd = NULL;

    if (vfs_entry() != HM_OK)
        return HM_ERROR;

    int32_t fd = -1;

    if (!fd_valid(vfs_fd) || pathname == NULL)
        return vfs_set_errno_ret(EINVAL);

    process_fd = find_process_fds(vfs_fd);
    if (process_fd == NULL)
        return vfs_set_errno_ret(ENOSYS);

    fd = process_fd->fd;
    vfs_data = process_fd->vfs_data;
    const struct vfs_ops *ops = vfs_data->ops;
    if (ops->mkdirat == NULL)
        return vfs_set_errno_ret(ENOSYS);

    int32_t rc = ops->mkdirat(vfs_data, fd, pathname, mode, 0);
    if (rc < 0) {
        hm_error("mkdirat failed: %d\n", rc);
        return vfs_set_errno_ret(-rc);
    }

    return vfs_exit();
}
