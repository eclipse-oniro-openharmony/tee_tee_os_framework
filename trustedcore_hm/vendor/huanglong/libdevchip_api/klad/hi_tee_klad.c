/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description:
 * Author: Hisilicon hisecurity team
 * Create: 2019-06-26
 */

#include "hi_tee_klad.h"
#include "tee_klad.h"
#include "tee_klad_define.h"

hi_s32 hi_tee_klad_init(hi_void)
{
    return hi_mpi_klad_init();
}

hi_s32 hi_tee_klad_deinit(hi_void)
{
    return hi_mpi_klad_deinit();
}

hi_s32 hi_tee_klad_create(hi_handle *handle)
{
    if (handle == HI_NULL) {
        print_err_code(HI_ERR_KLAD_INVALID_PARAM);
        return HI_ERR_KLAD_INVALID_PARAM;
    }
    return hi_mpi_klad_create(handle);
}

hi_s32 hi_tee_klad_destroy(hi_handle handle)
{
    return hi_mpi_klad_destroy(handle);
}

hi_s32 hi_tee_klad_attach(hi_handle handle, hi_handle target)
{
    return hi_mpi_klad_attach(handle, target);
}

hi_s32 hi_tee_klad_detach(hi_handle handle, hi_handle target)
{
    return hi_mpi_klad_detach(handle, target);
}

hi_s32 hi_tee_klad_set_attr(hi_handle handle, const hi_tee_klad_attr *attr)
{
    if (attr == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }
    if (sizeof(hi_klad_attr) != sizeof(hi_tee_klad_attr)) {
        print_err_hex2(sizeof(hi_klad_attr), sizeof(hi_tee_klad_attr));
        return HI_ERR_KLAD_INVALID_PARAM;
    }

    return hi_mpi_klad_set_attr(handle, (const hi_klad_attr *)attr);
}

hi_s32 hi_tee_klad_get_attr(hi_handle handle, hi_tee_klad_attr *attr)
{
    if (attr == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }
    if (sizeof(hi_klad_attr) != sizeof(hi_tee_klad_attr)) {
        print_err_hex2(sizeof(hi_klad_attr), sizeof(hi_tee_klad_attr));
        return HI_ERR_KLAD_INVALID_PARAM;
    }
    return hi_mpi_klad_get_attr(handle, (hi_klad_attr *)attr);
}

hi_s32 hi_tee_klad_set_root_key_attr(hi_handle handle, const hi_tee_rootkey_attr *rootkey_attr)
{
    if (rootkey_attr == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }
    if (sizeof(hi_rootkey_attr) != sizeof(hi_tee_rootkey_attr)) {
        print_err_hex2(sizeof(hi_rootkey_attr), sizeof(hi_tee_rootkey_attr));
        return HI_ERR_KLAD_INVALID_PARAM;
    }
    return hi_mpi_klad_set_rootkey_attr(handle, (hi_rootkey_attr *)rootkey_attr);
}

hi_s32 hi_tee_klad_get_root_key_attr(hi_handle handle, hi_tee_rootkey_attr *rootkey_attr)
{
    if (rootkey_attr == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }
    if (sizeof(hi_rootkey_attr) != sizeof(hi_tee_rootkey_attr)) {
        print_err_hex2(sizeof(hi_rootkey_attr), sizeof(hi_tee_rootkey_attr));
        return HI_ERR_KLAD_INVALID_PARAM;
    }
    return hi_mpi_klad_get_rootkey_attr(handle, (hi_rootkey_attr *)rootkey_attr);
}

hi_s32 hi_tee_klad_set_session_key(hi_handle handle, const hi_tee_klad_session_key *key)
{
    if (key == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }
    if (sizeof(hi_klad_session_key) != sizeof(hi_tee_klad_session_key)) {
        print_err_hex2(sizeof(hi_klad_session_key), sizeof(hi_tee_klad_session_key));
        return HI_ERR_KLAD_INVALID_PARAM;
    }
    return hi_mpi_klad_set_session_key(handle, (hi_klad_session_key *)key);
}

hi_s32 hi_tee_klad_set_content_key(hi_handle handle, const hi_tee_klad_content_key *key)
{
    if (key == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }
    if (sizeof(hi_klad_content_key) != sizeof(hi_tee_klad_content_key)) {
        print_err_hex2(sizeof(hi_klad_content_key), sizeof(hi_tee_klad_content_key));
        return HI_ERR_KLAD_INVALID_PARAM;
    }
    return hi_mpi_klad_set_content_key(handle, (hi_klad_content_key *)key);
}

hi_s32 hi_tee_klad_set_clear_key(hi_handle handle, const hi_tee_klad_clear_key *key)
{
    if (key == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }
    if (sizeof(hi_klad_clear_key) != sizeof(hi_tee_klad_clear_key)) {
        print_err_hex2(sizeof(hi_klad_clear_key), sizeof(hi_tee_klad_clear_key));
        return HI_ERR_KLAD_INVALID_PARAM;
    }
    return hi_mpi_klad_set_clear_key(handle, (hi_klad_clear_key *)key);
}

hi_s32 hi_tee_klad_async_set_content_key(hi_handle handle, const hi_tee_klad_content_key *key,
                                         const hi_tee_klad_done_callback *call_back)
{
    if (key == HI_NULL || call_back == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }
    if (sizeof(hi_klad_content_key) != sizeof(hi_tee_klad_content_key) ||
        sizeof(klad_callback) != sizeof(hi_tee_klad_done_callback)) {
        print_err_hex2(sizeof(hi_klad_content_key), sizeof(hi_tee_klad_content_key));
        print_err_hex2(sizeof(klad_callback), sizeof(hi_tee_klad_done_callback));
        return HI_ERR_KLAD_INVALID_PARAM;
    }
    return hi_mpi_klad_async_set_content_key(handle, (hi_klad_content_key *)key, (const klad_callback *)call_back);
}


hi_s32 hi_tee_klad_generate_key(hi_handle handle, hi_tee_klad_gen_key *key)
{
    if (key == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }
    return HI_SUCCESS;
}

hi_s32 hi_tee_klad_generate_nonce(hi_handle handle, hi_tee_klad_nonce_key *key)
{
    if (key == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }
    return HI_SUCCESS;
}

