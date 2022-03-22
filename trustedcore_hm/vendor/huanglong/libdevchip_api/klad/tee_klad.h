/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: define API about key ladder driver
 * Author: linux SDK team
 * Create: 2019-6-26
 */
#ifndef __MPI_KLAD_H__
#define __MPI_KLAD_H__

#include "hi_type_dev.h"
#include "tee_drv_ioctl_klad.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

hi_s32 hi_mpi_klad_init(hi_void);
hi_s32 hi_mpi_klad_deinit(hi_void);
hi_s32 hi_mpi_klad_create(hi_handle *handle);
hi_s32 hi_mpi_klad_destroy(hi_handle handle);
hi_s32 hi_mpi_klad_attach(hi_handle handle, hi_handle target);
hi_s32 hi_mpi_klad_detach(hi_handle handle, hi_handle target);
hi_s32 hi_mpi_klad_set_attr(hi_handle handle, const hi_klad_attr *attr);
hi_s32 hi_mpi_klad_get_attr(hi_handle handle, hi_klad_attr *attr);
hi_s32 hi_mpi_klad_set_rootkey_attr(hi_handle handle, const hi_rootkey_attr *rootkey_attr);
hi_s32 hi_mpi_klad_get_rootkey_attr(hi_handle handle, hi_rootkey_attr *rootkey_attr);
hi_s32 hi_mpi_klad_set_session_key(hi_handle handle, const hi_klad_session_key *key);
hi_s32 hi_mpi_klad_set_content_key(hi_handle handle, const hi_klad_content_key *key);
hi_s32 hi_mpi_klad_set_clear_key(hi_handle handle, const hi_klad_clear_key *key);
hi_s32 hi_mpi_klad_generate_key(hi_handle handle, hi_klad_gen_key *key);
hi_s32 hi_mpi_klad_generate_nonce(hi_handle handle, hi_klad_nonce_key *key);
hi_s32 hi_mpi_klad_async_set_content_key(hi_handle handle, const hi_klad_content_key *key,
                                         const klad_callback *call_back);
hi_s32 hi_mpi_klad_set_fp_key(hi_handle handle, hi_klad_fp_key *key);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif /* __MPI_KLAD_H__ */

