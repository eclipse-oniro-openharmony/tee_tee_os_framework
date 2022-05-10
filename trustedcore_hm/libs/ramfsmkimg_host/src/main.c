/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: main function of ramfs
 * Create: 2019-08-20
 */
#include <stdint.h>
#include <string.h>
#include <libc/sys/stat.h>
#include <libc/unistd.h>
#include <libc/stdio.h>
#include <libc/stdlib.h>
#include <limits.h>
#include <errno.h>
#include <securec.h>
#include "ramfs.h"

struct file_stat_entry {
    const char *filename;
    uint32_t uid;
    uint32_t gid;
    uint32_t mode;
} g_file_stat_entries[] = {
    { "/picosh.elf", 0, 1001, 07005 },
    { "/picosh", 0, 1001, 07005 },
    { "/teesmcmgr.elf", 1, 1001, 07005 },
    { "/taloader.elf", 2, 1001, 07005 },
    { "/tarunner_a32.elf", 2, 1001, 07005 },
    { "/tarunner.elf", 2, 1001, 07005 },
    { "/gtask.elf", 3, 1000, 07005 },
    { "/rpmb.elf", 9, 1001, 00040 },
    { "/ssa.elf", 10, 1001, 00040 },
    { "/platdrv.elf", 4, 1001, 07005 },
    { "/drv_timer.elf", 5, 1001, 07005 },
    { "/keymaster.elf", 7, 1001, 00040 },
    { "/gatekeeper.elf", 8, 1001, 00040 },
    { "/storage.elf", 11, 1001, 00040 },
    { "/antiroot.elf", 12, 1001, 00040 },
    { "/secboot.elf", 13, 1001, 00040 },
    { "/sem.elf", 15, 1001, 00040 },
    { "/README", 16, 16, 00000 },
    { "/hm_qemu_test_a32", 0, 1001, 07005 },
    { "/hm_qemu_test", 0, 1001, 07005 },
    { "/kernel_debugger", 0, 1001, 07005 },
    { "/perf.elf", 17, 1001, 07005 },
    { "/perf", 17, 1001, 07005 },
    { "/vdec.elf", 18, 1001, 00040 },
    { "/secmem.elf", 19, 1001, 00040 },
    { "/hivcodec.elf", 20, 1001, 00040 },
    { "/kds.elf", 21, 21, 00040 },
    { "/file_encry.elf", 22, 22, 00040 },
    /*
     * gtask spawn tee_drv_server
     * tee_drv_server spawn tarunner
     * gtask gid is 1000, tarunner and other ta gid is 1001
     * so set tee_drv_server gid to 1002
     * otherwise it will be failed in check_file_permission when spawn tarunner
     * if the parent process gid equal with the child process gid
     */
    { "/tee_drv_server.elf", 23, 1002, 07005 },
    { "/libc_shared.so", 0, 1001, 00040 },
    { "/libc_shared_a32.so", 0, 1001, 00040 },
    { "/libtee_shared.so", 0, 1001, 00040 },
    { "/libtee_shared_a32.so", 0, 1001, 00040 },
    { "/libbase_shared.so", 0, 1001, 00040 },
    { "/libbase_shared_a32.so", 0, 1001, 00040 },
    { "/libtui_internal_shared.so", 0, 1001, 00040 },
    { "/libtui_internal_shared_a32.so", 0, 1001, 00040 },
    { "/libc++_shared.so", 0, 1001, 00040 },
    { "/libc++_shared_a32.so", 0, 1001, 00040 },
    { "/libtest_shared.so", 0, 1001, 00040 },
    { "/libtest_shared_a32.so", 0, 1001, 00040 },
    { "/tui.elf", 22, 1001, 00040 },
    { "/attestation_ta.elf", 24, 1001, 00040 },
    { "/sec_flash.elf", 25, 1001, 00040 },
    { "/se_service.elf", 26, 1001, 00040 },
    { "/bio_service.elf", 27, 1001, 00040 },
    { "/rot_service.elf", 28, 1001, 00040 },
    { "/art_service.elf", 29, 1001, 00040 },
#ifdef CONFIG_ASCEND_PLATFORM
    { "/hsm.elf", 30, 1001, 00040 },
    { "/hsm_bbox.elf", 31, 1001, 00040 },
#endif
    { "/huk_service.elf", 32, 1001, 00040 },
    { "/crypto_mgr.elf", 33, 1002, 07005 },
    { "/tcmgr_service.elf", 33, 1001, 00040 },
};

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

#ifndef RAM_STATIC_ASSERT
#define RAM_STATIC_ASSERT(condition, name) extern int g_STATIC_ASSERT_##name[1 - 2 * (int)((condition) == false)]
#endif

#define RAMFS_ERROR  (-1)
#define SIZE_K       1024U
#define SIZE_M       (1024 * 1024)
#define ARGC_0       0U
#define ARGC_1       1U
#define SHIFT_OFFSET 30U
#define ARGC_MAX     1024U
#define INODE_GID    1001U
#define INODE_MODE   00040U

RAM_STATIC_ASSERT(sizeof(struct ramfs_super) == RAMFS_SUPER_SIZE, ramfs_super_size_correct);
RAM_STATIC_ASSERT(sizeof(struct ramfs_inode) == RAMFS_INODE_SIZE, ramfs_inode_size_correct);

static void usage(const char *name)
{
    (void)fprintf(stderr,
        "usage: %s -n size imgfile infile...\n"
        "where:\tsize   Size of the resulting image, optionally\n"
        "\t\tfollowed by:\n"
        "\t\tK\tSize is in kibibytes\n"
        "\t\tM\tSize is mebibytes\n",
        name);
    exit(EXIT_FAILURE);
}

static int ramfs_set_stat(struct ramfs_inode *inode)
{
    uint32_t i;
    static uint32_t other_uid;
    other_uid = (uint32_t)ARRAY_SIZE(g_file_stat_entries);

    for (i = 0; i < ARRAY_SIZE(g_file_stat_entries); i++) {
        struct file_stat_entry *e = &g_file_stat_entries[i];
        if (strncmp(inode->filename, e->filename, sizeof(inode->filename)) == 0) {
            inode->uid  = e->uid;
            inode->gid  = e->gid;
            inode->mode = e->mode;
            return 0;
        }
    }
    inode->uid  = other_uid;
    inode->gid  = INODE_GID;
    inode->mode = INODE_MODE;
    other_uid++;
    (void)perror("ramfs_set_stat: filename not found, new internal ta\n");
    return 0;
}

static struct ramfs_metadata *ramfs_metadata_alloc_init(int32_t nr_files)
{
    int32_t metadata_size;
    metadata_size = (int32_t)ramfs_calc_metadata_size((uint32_t)nr_files);
    struct ramfs_metadata *metadata = NULL;
    int32_t ret_s;

    metadata = calloc(metadata_size, ARGC_1);
    if (metadata == NULL) {
        perror("alloc super block failed\n");
        return NULL;
    }

    ret_s = memcpy_s(metadata->super.magic, sizeof(metadata->super.magic), RAMFS_MAGIC, sizeof(metadata->super.magic));
    if (ret_s != EOK) {
        perror("memcpy_s failed\n");
        free(metadata);
        return NULL;
    }

    metadata->super.version  = RAMFS_VERSION;
    metadata->super.nr_files = (uint32_t)nr_files;
    return metadata;
}

static void ramfs_metadata_destroy(struct ramfs_metadata *metadata)
{
    free(metadata);
}

static int32_t set_inode_info(struct ramfs_inode *inode, const char *filename,
                              int32_t *bytes, struct stat *stat_buf, uint32_t offset)
{
    int32_t err;
    const char *basename = NULL;

    if (inode == NULL)
        return RAMFS_ERROR;

    basename = ramfs_extract_basename(filename);
    if (basename == NULL || basename[0] == '\0') {
        (void)printf("wrong file name: '%s'\n", filename);
        return RAMFS_ERROR;
    }

    *bytes = snprintf_s(inode->filename, sizeof(inode->filename), sizeof(inode->filename) - ARGC_1, "/%s", basename);
    if (*bytes == -1) {
        (void)printf("wrong file name: '%s'\n", filename);
        return RAMFS_ERROR;
    }

    err = stat(filename, stat_buf);
    if (err < 0) {
        perror("stat failed");
        return RAMFS_ERROR;
    }

    if (stat_buf->st_size > RAMFS_MAX_FILE_SIZE) {
        (void)printf("file '%s' too large\n", filename);
        return RAMFS_ERROR;
    }

    inode->offset = offset;
    inode->size   = (uint32_t)stat_buf->st_size;

    if (ramfs_set_stat(inode) < 0) {
        perror("ramfs_set_stat error\n");
        return RAMFS_ERROR;
    }

    return 0;
}

/* return negative when failure */
static long process_file(struct ramfs_metadata *metadata, FILE *img_fp, uint32_t num, uint32_t offset,
                         const char *filename)
{
    struct ramfs_inode *inode = NULL;
    uint8_t buffer[PAGE_SIZE];
    struct stat stat_buf;
    int32_t bytes;
    long written;
    FILE *fp = NULL;
    int32_t err;

    inode = ramfs_metadata_inode(metadata, num);
    err = set_inode_info(inode, filename, &bytes, &stat_buf, offset);
    if (err < 0) {
        perror("set inode info failed\n");
        return RAMFS_ERROR;
    }

    fp = fopen(filename, "rb");
    if (fp == NULL) {
        perror("open file error\n");
        return RAMFS_ERROR;
    }

    written = 0;
    do {
        bzero(buffer, PAGE_SIZE);
        bytes = (int32_t)fread(buffer, ARGC_1, PAGE_SIZE, fp);
        if (bytes == 0)
            break;

        bytes = (int32_t)fwrite(buffer, ARGC_1, PAGE_SIZE, img_fp);
        if (bytes != PAGE_SIZE) {
            perror("write file error");
            (void)fclose(fp);
            return RAMFS_ERROR;
        }
        written += PAGE_SIZE;
    } while (bytes != 0);

    (void)fclose(fp);
    return written;
}

static int32_t process_files_check_params(unsigned long size, int32_t argc)
{
    unsigned long size_max;
    size_max = (ARGC_1 << SHIFT_OFFSET);
    if (size > size_max) {
        perror("size too large\n");
        return RAMFS_ERROR;
    }

    if ((argc > (int32_t)ARGC_MAX) || (argc < (int32_t)ARGC_1)) {
        perror("too many or too less files");
        return RAMFS_ERROR;
    }

    return 0;
}

static int32_t fill_files(FILE *img_fp, struct ramfs_metadata *metadata,
                          unsigned long size, int32_t argc, char * const argv[])
{
    int32_t err;
    uint32_t i;
    uint32_t offset;

    err = fseeko(img_fp, (off_t)ramfs_metadata_size(metadata), SEEK_SET);
    if (err != 0) {
        perror("fseeko error\n");
        return RAMFS_ERROR;
    }

    /* start filling files */
    if (size <= ramfs_metadata_size(metadata)) {
        perror("size is less than size of metadata\n");
        return RAMFS_ERROR;
    }
    size -= ramfs_metadata_size(metadata);

    for (i = 0, offset = 0; i < (uint32_t)argc; i++) {
        long filled_size = process_file(metadata, img_fp, i, offset, argv[i]);
        if (filled_size < 0) {
            perror("process_file failed\n");
            return RAMFS_ERROR;
        }

        if (size < (unsigned long)filled_size) {
            perror("size is too small\n");
            return RAMFS_ERROR;
        }

        offset += (uint32_t)filled_size;
    }

    err = fseeko(img_fp, 0, SEEK_SET);
    if (err != 0) {
        perror("fseeko error");
        return RAMFS_ERROR;
    }

    if (fwrite(metadata, ramfs_metadata_size(metadata), ARGC_1, img_fp) != ARGC_1) {
        perror("Write metadata failed\n");
        return RAMFS_ERROR;
    }

    return 0;
}

static void process_files(unsigned long size, const char *imgfile, int32_t argc, char * const argv[])
{
    int32_t err;
    FILE *img_fp = NULL;
    struct ramfs_metadata *metadata = NULL;

    if (process_files_check_params(size, argc) != 0)
        exit(EXIT_FAILURE);

    metadata = ramfs_metadata_alloc_init(argc);
    if (metadata == NULL) {
        perror("ramfs metadata alloc failed\n");
        exit(EXIT_FAILURE);
    }

    img_fp = fopen(imgfile, "w");
    if (img_fp == NULL) {
        perror(imgfile);
        ramfs_metadata_destroy(metadata);
        exit(EXIT_FAILURE);
    }

    err = fill_files(img_fp, metadata, size, argc, argv);
    if (err != 0) {
        (void)fclose(img_fp);
        ramfs_metadata_destroy(metadata);
        exit(EXIT_FAILURE);
    }

    (void)fclose(img_fp);
    ramfs_metadata_destroy(metadata);
}

static void handle_opt(int32_t argc, char *argv[], unsigned long *size)
{
    int32_t opt;
    char *endptr = NULL;
    char modifier;
    opt = getopt(argc, argv, "n:f:");
    while (opt != RAMFS_ERROR) {
        switch (opt) {
        case 'n':
            if (*optarg == '\0') {
                (void)fprintf(stderr, "Zero-length size not allowed\n");
                usage(argv[0]);
            }

            *size = strtoul(optarg, &endptr, 0);
            modifier = *endptr;
            if (modifier == '\0')
                break;
            unsigned long msize = 0;
            if (modifier == 'K')
                msize = SIZE_K;
            if (modifier == 'M')
                msize = SIZE_M;
            if (msize != 0 && *size > UINT64_MAX / msize) {
                (void)fprintf(stderr, "size is too large\n");
                usage(argv[0]);
            }
            if (msize != 0)
                *size *= msize;
            endptr++;
            if (*endptr != '\0')
                usage(argv[0]);
            break;

        case 'f':
            if (*optarg == '\0') {
                (void)fprintf(stderr, "Not a correct file name\n");
                usage(argv[0]);
            }
            (void)printf("doesn't support .ini file\n");
            break;

        default:
            usage(argv[0]);
            break;
        }
        opt = getopt(argc, argv, "n:f:");
    }
}

int32_t main(int32_t argc, char *argv[])
{
    unsigned long size;
    int32_t n_args;
    size = 0;

    handle_opt(argc, argv, &size);

    n_args = argc - optind;

    switch (n_args) {
    case ARGC_0:
    case ARGC_1:
        usage(argv[0]);
        break;
    default:
        if (size == 0) {
            usage(argv[0]);
            break;
        }
        process_files(size, argv[optind], n_args - (int32_t)ARGC_1, &argv[optind + ARGC_1]);
        break;
    }
    return 0;
}
