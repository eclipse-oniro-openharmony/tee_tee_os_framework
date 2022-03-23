/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: main function of ramfs
 * Create: 2019-08-20
 */
#include <libc/stdio.h>
#include <libc/stdlib.h>
#include <libc/sys/stat.h>
#include <libc/fcntl.h>
#include "ramfs.h"

#define CRED_LEN      8
#define ARGC_3        3
#define ARGV_OFFSET_2 2
#define FILE_LEN      1
#define DUMP_ERROR    (-1)
#define READ_SIZE     512
#define DUMP_BUF_SIZE 4096

static bool setup(struct vfs_ramfs_data *ramfs_data, void *img, size_t img_size)
{
    int32_t rc;

    ramfs_init(ramfs_data, "/", img, img_size);

    rc = vfs_add_fs(&ramfs_data->data);
    if (rc != 0) {
        printf("failed to add RAMFS root \"/\"\n");
        return false;
    }

    rc = VFS(mount)("/");
    if (rc != 0) {
        printf("failed to open ramfs filesystem: %d\n", rc);
        return false;
    }

    return true;
}

static bool teardown(struct vfs_ramfs_data *ramfs_data)
{
    int32_t rc;

    rc = VFS(umount)("/");
    if (rc != 0) {
        printf("ramfs_close failed after open: %d\n", rc);
        return false;
    }

    rc = ramfs_fini(ramfs_data);
    if (rc != 0) {
        printf("failed finish work: %d\n", rc);
        return false;
    }

    return true;
}

static void dump_save(int32_t in_fd, const char *out_path)
{
    FILE *fp = NULL;
    ssize_t in_zrc;
    char buf[DUMP_BUF_SIZE] = {0};
    size_t read_size = READ_SIZE;

    fp = fopen(out_path, "w");
    if (fp == NULL) {
        perror("fopen");
        return;
    }

    in_zrc = VFS(read)(in_fd, buf, read_size);
    while (in_zrc > 0) {
        if (in_zrc > DUMP_BUF_SIZE)
            break;
        ssize_t out_zrc;
        out_zrc = (ssize_t)fwrite(buf, FILE_LEN, in_zrc, fp);
        if (out_zrc != in_zrc) {
            printf("fwrite failed: %s\n", strerror(-out_zrc));
            break;
        }
        in_zrc = VFS(read)(in_fd, buf, read_size);
    }

    if (in_zrc < 0)
        printf("ramfs_file_read failed: %s\n", strerror(-in_zrc));

    if (fclose(fp) == DUMP_ERROR)
        perror("fclose");
}

static void dump_to(const char *in_path, const char *out_path)
{
    int32_t in_fd;
    int32_t rc;
    cred_t cred = { CRED_LEN, CRED_LEN };

    in_fd = VFS(_open)(in_path, &cred, O_WRONLY);
    if (in_fd < 0) {
        printf("ramfs_open failed: %s\n", strerror(-in_fd));
        return;
    }

    dump_save(in_fd, out_path);

    rc = VFS(close)(in_fd);
    if (rc < 0)
        printf("ramfs_close failed: %s\n", strerror(-rc));
}

static void dump_file(const char *imgfile, const char *in_path, const char *out_path)
{
    struct vfs_ramfs_data ramfs_data;
    FILE *img_fp = NULL;
    struct stat buf;
    size_t img_size;
    void *img = NULL;
    size_t zrc;
    int32_t rc;

    img_fp = fopen(imgfile, "r");
    if (img_fp == NULL) {
        perror(imgfile);
        exit(EXIT_FAILURE);
    }

    rc = fstat(fileno(img_fp), &buf);
    if (rc == DUMP_ERROR) {
        perror("fstat");
        exit(EXIT_FAILURE);
    }

    img_size = (size_t)buf.st_size;
    img      = malloc(img_size);
    if (img == NULL) {
        fprintf(stderr, "Unable to allocate %zu bytes\n", img_size);
        exit(EXIT_FAILURE);
    }

    printf("Reading %zu\n", img_size);
    zrc = fread(img, img_size, FILE_LEN, img_fp);
    if (zrc != FILE_LEN) {
        perror("fread");
        exit(EXIT_FAILURE);
    }

    if (!setup(&ramfs_data, img, img_size)) {
        fprintf(stderr, "Failed to set up filesystem\n");
        exit(EXIT_FAILURE);
    }

    dump_to(in_path, out_path);

    if (!teardown(&ramfs_data)) {
        fprintf(stderr, "Failed while trying to tear down filesystem\n");
        exit(EXIT_FAILURE);
    }

    if (fclose(img_fp) == DUMP_ERROR) {
        perror("fclose");
        exit(EXIT_FAILURE);
    }

    free(img);
}

static void usage(const char *name)
{
    fprintf(stderr, "usage: %s img_file in_file out_file\n", name);
    exit(EXIT_FAILURE);
}

int32_t main(int32_t argc, char *argv[])
{
    int32_t opt;
    int32_t n_args;
    opt = getopt(argc, argv, "");
    if (opt != DUMP_ERROR)
        usage(argv[0]);

    n_args = argc - optind;

    switch (n_args) {
    case ARGC_3:
        printf("RAMFS dumper started\n");
        dump_file(argv[optind], argv[optind + FILE_LEN], argv[optind + ARGV_OFFSET_2]);
        break;
    default:
        usage(argv[0]);
        break;
    }

    printf("exited successfully\n");

    return 0;
}
