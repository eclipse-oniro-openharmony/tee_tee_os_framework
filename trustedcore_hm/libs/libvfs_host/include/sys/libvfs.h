/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: Interfaces for a virtual file system, which provides a structure for
 * binding together filesystems via mounts.
 * Create: 2019-05-18
 */

#ifndef SYSLIB_LIBVFS_H
#define SYSLIB_LIBVFS_H

#define VFS_DATA_DEBUG

#include <stddef.h>
#include <stdint.h>
#include <sys/hm_fcntl.h>

#if defined(__aarch64__) || defined(__arm__)
#include <sys/types.h>
#include <sys/hm_types.h>
#else
#include <unistd.h>
#endif

#include <list.h>
#include <uidgid.h>
#include <hm_stat.h>

/* Forward declarations */
struct vfs_data;

/*
 * Generic inumber size. Individual filesystems can use smaller inode numbers
 * These are negative so errno values can be returned.
 */
#define VFS_INUM_FMT "%lld"

/*
 * Applications and libraries using Hong Meng file interfaces on host systems
 * should use the VFS macro to call the Hong Meng file I/O functions because.
 * So, calling VFS(open) will call vfs_open() on the host and open() on Hong
 * Meng, the same application. This allows the same application or library
 * to work as expected whether running on the host system or Hong Meng.
 */
#if defined(__aarch64__) || defined(__arm__)
#define VFS(name) name
#else
#define VFS(name) vfs_##name
#endif

#define MAX_FILENAME_LENGTH 256

/*
 * Information returned by getdents for a single directory entry
 * @d_ino:    Inode number
 * @d_off:    Number of bytes from the start of a dirent structure
 *            to the start of the next dirent structure
 * @d_reclen: Number of bytes in this dirent structure, up to and
 *            including the NUL character that terminates the d_name
 *            string.
 * @d_type:   Enum procfs_dirent_type specifying the type of this directory
 *            entry
 * @d_name:   NUL-terminated name for this directory entry
 */
struct dirent {
    int64_t d_ino;
    uint64_t d_off; /* should be ptrdiff_t */
    uint64_t d_reclen;
    unsigned char d_type;
    char d_name[];
};

/* Structure passed to vfs operations to set attributes of files */
struct iattr {
    uint32_t ia_valid;
    cred_t cred;
    mode_t mode;
};

#define ATTR_MODE (1U << 0U)
#define ATTR_UID  (1U << 1U)
#define ATTR_GID  (1U << 2U)

#define MAY_EXEC  S_IXOTH
#define MAY_WRITE S_IWOTH
#define MAY_READ  S_IROTH

struct vfs_ensemble_open {
    struct vfs_data *vfs_data;
    const cred_t *cred;
    uint32_t cidx;
    uint64_t memid;
};

struct vfs_ensemble_openat {
    struct vfs_data *vfs_data;
    cred_t *cred;
    uint32_t cidx;
};

struct vfs_ensemble_read {
    struct vfs_data *vfs_data;
    off_t *off;
    uint32_t cidx;
};

struct vfs_ensemble_write {
    struct vfs_data *vfs_data;
    off_t *off;
    uint32_t cidx;
};

struct vfs_ensemble_getdents {
    struct vfs_data *vfs_data;
    off_t *offset;
    uint32_t cidx;
};

struct vfs_ensemble_xip_map {
    struct vfs_data *vfs_data;
    off_t *off;
    uint32_t cidx;
};

struct vfs_ensemble_rename {
    struct vfs_data *vfs_data;
    uint32_t cidx;
};

struct vfs_ensemble_mmap {
    struct vfs_data *vfs_data;
    uint32_t cidx;
};

struct vfs_ops {
    const char *name;
    int32_t (*mkfs)(struct vfs_data *vfs_data, const char *pathname);
    int32_t (*mount)(struct vfs_data *vfs_data, const char *pathname);
    int32_t (*umount)(struct vfs_data *vfs_data, const char *pathname);
    int32_t (*open)(struct vfs_ensemble_open *ensemble, const char *pathname, int32_t flags, mode_t mode);
    int32_t (*openat)(struct vfs_ensemble_openat *ensemble, int32_t fd, const char *pathname, int32_t flags,
                      mode_t mode);
    int32_t (*creat)(struct vfs_data *vfs_data, const char *pathname, mode_t mode, const cred_t *cred, uint32_t cidx);
    int32_t (*close)(struct vfs_data *vfs_data, int32_t fd, uint32_t cidx);
    int32_t (*unlink)(struct vfs_data *vfs_data, const char *pathname);
    int32_t (*truncate)(struct vfs_data *vfs_data, const char *pathname, off_t length);
    int32_t (*ftruncate)(struct vfs_data *vfs_data, int32_t fd, off_t length, uint32_t cidx);
    ssize_t (*read)(struct vfs_ensemble_read *ensemble, int32_t fd, void *buf, size_t count);
    ssize_t (*write)(struct vfs_ensemble_write *ensemble, int32_t fd, const void *buf, size_t size);
    off_t (*lseek)(struct vfs_data *vfs_data, int32_t fd, off_t off, int32_t whence, uint32_t cidx);
    ssize_t (*getdents)(struct vfs_ensemble_getdents *ensemble, int32_t dir_fd, struct dirent *dirents, size_t count);
    int32_t (*mkdirat)(struct vfs_data *vfs_data, int32_t dir_fd, const char *pathname, mode_t mode, uint32_t cidx);
    int32_t (*unlinkat)(struct vfs_data *vfs_data, int32_t dir_fd, const char *pathname,
                        int32_t flags, uint32_t cidx);
    ssize_t (*xip_map)(struct vfs_ensemble_xip_map *ensemble, int32_t fd, size_t count,
                       uint64_t *vaddr, uint64_t *vspace);
    int32_t (*setattr)(struct vfs_data *vfs_data, const char *pathname, const struct iattr *ia, const cred_t *cur_cred);
    int32_t (*stat)(struct vfs_data *vfs_data, const char *pathname, struct stat *stat, const cred_t *cred);
    int32_t (*print_fsinfo)(struct vfs_data *data);
    int32_t (*set_uid)(struct vfs_data *data, const char *pathname, uid_t uid);
    ssize_t (*rename)(struct vfs_ensemble_rename *ensemble, int32_t fd, const char *new_name);
    ssize_t (*mmap)(struct vfs_ensemble_mmap *ensemble, int32_t fd, uint64_t size, uint64_t off, uint64_t task_vs,
                    uint64_t *vaddr);
};

/*
 * Common data structure for VFS users
 * @fss:     Link in list of filesystems
 * @fs_root: Path to root of the filesystems, which must start with "/".
 * @ops:     Pointer to filesystem functions
 */
struct vfs_data {
    struct list_head fss;
    const char *fs_root;
    const struct vfs_ops *ops;
};

void vfs_data_init(struct vfs_data *data, const char *path, const struct vfs_ops *ops);
int32_t vfs_add_fs(struct vfs_data *data);

int32_t VFS(print_fsinfo)(const char *pathname);

#if !defined(__aarch64__) && !defined(__arm__)
int32_t VFS(mkfs)(const char *pathname);
int32_t VFS(mount)(const char *pathname);
int32_t VFS(umount)(const char *pathname);
int32_t VFS(_open)(const char *pathname, const cred_t *cred, int32_t flags, ...);
int32_t VFS(open)(const char *pathname, int32_t flags, ...);
int32_t VFS(_creat)(const char *pathname, mode_t mode, const cred_t *cred);
int32_t VFS(creat)(const char *pathname, mode_t mode);
int32_t VFS(close)(int32_t fd);
int32_t VFS(unlink)(const char *pathname);
int32_t VFS(truncate)(const char *pathname, off_t length);
int32_t VFS(ftruncate)(int32_t fd, off_t length);
ssize_t VFS(read)(int32_t fd, void *buf, size_t count);
ssize_t VFS(write)(int32_t fd, const void *buf, size_t size);
off_t VFS(lseek)(int32_t fd, off_t off, int32_t whence);
ssize_t VFS(getdents)(int32_t dir_fd, struct dirent *dirents, size_t count);
int32_t VFS(mkdirat)(int32_t dir_fd, const char *pathname, mode_t mode);
int32_t VFS(unlinkat)(int32_t dir_fd, const char *pathname, int32_t flags);
ssize_t VFS(xip_map)(int32_t fd, off_t *off, size_t count, uint64_t *vaddr, uint64_t *vspace);
int32_t VFS(chown)(const char *pathname, uid_t uid, gid_t gid);
int32_t VFS(_chown)(const char *pathname, uid_t uid, gid_t gid, const cred_t *cur_cred);
int32_t VFS(chmod)(const char *pathname, mode_t mode);
int32_t VFS(_chmod)(const char *pathname, mode_t mode, const cred_t *cur_cred);
int32_t VFS(stat)(const char *pathname, struct stat *stat);
int32_t VFS(_stat)(const char *pathname, struct stat *stat, const cred_t *cred);
int32_t VFS(set_uid)(const char *pathname, uid_t uid);
int32_t VFS(vfs_rename)(int32_t fd, const char *new_name);
void *VFS(vfs_mmap)(int32_t fd, uint64_t size, uint64_t off);
#endif

#endif
