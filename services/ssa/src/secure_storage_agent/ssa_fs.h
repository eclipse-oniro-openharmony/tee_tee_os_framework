/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: tee fs implementation
 * Author: Dizhe Mao maodizhe1@huawei.com
 * Create: 2018-05-18
 */
#ifndef __SSA_FS_H
#define __SSA_FS_H

#include "tee_defines.h"

#define TRANS_BUFF_SIZE AGENT_BUFF_SIZE /* transfer buffer size, equal to teecd's buffer size */

TEE_Result tee_fs_init(void *control);
void tee_fs_exit(void);

TEE_Result check_file_name(const char *name);
TEE_Result check_name_by_storageid(const char *obj_id, uint32_t obj_len, uint32_t storage_id);

void fs_set_serr(uint32_t ns_errno);
TEE_Result fs_get_serr(void);
int32_t ssa_fs_fopen(const char *name, uint32_t flags, uint32_t storage_id);
int32_t ssa_fs_fclose(int32_t fd);
uint32_t ssa_fs_fread(void *out_buf, uint32_t count, int32_t fd, int32_t *error);
uint32_t ssa_fs_fwrite(const void *content, uint32_t count, int32_t fd);
int32_t ssa_fs_fseek(int32_t fd, int32_t offset, uint32_t whence);
int32_t ssa_fs_fremove(const char *r_pth, uint32_t storage_id);
int32_t ssa_fs_ftruncate(const char *name, uint32_t len, uint32_t storage_id);
int32_t ssa_fs_frename(const char *old_name, const char *new_name, uint32_t storage_id);
int32_t ssa_fs_fcreate(const char *name, uint32_t flag, uint32_t storage_id);
int32_t ssa_fs_finfo(int32_t fd, uint32_t *pos, uint32_t *len);
int32_t ssa_fs_faccess(const char *name, int mode, uint32_t storage_id);
int32_t ssa_fs_faccess2(const char *name, int mode);
int32_t ssa_fs_fcopy(const char *from_path, const char *to_path, uint32_t storage_id);
int32_t ssa_fs_fsync(int32_t fd);
uint32_t get_fs_meta_size();
int32_t ssa_fs_delete_all(const char *path, uint32_t path_len);
int32_t ssa_fs_disk_usage(uint32_t *secure_remain, uint32_t *data_secure_remain);
#endif
