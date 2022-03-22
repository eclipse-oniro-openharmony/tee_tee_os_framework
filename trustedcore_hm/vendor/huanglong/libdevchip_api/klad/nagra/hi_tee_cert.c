/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description:Define API about key ladder driver
 * Author: Hisilicon hisecurity team
 * Create: 2019-08-22
 */

#include "hi_tee_cert.h"
#include "tee_cert.h"

hi_s32 hi_tee_cert_init(hi_void)
{
    return hi_mpi_cert_init();
}

hi_s32 hi_tee_cert_deinit(hi_void)
{
    return hi_mpi_cert_deinit();
}

hi_s32 hi_tee_cert_use_key(hi_tee_cert_key_data *ctl_data)
{
    hi_s32 ret;
    if (ctl_data == HI_NULL) {
        print_err_code(HI_ERR_CERT_INVALID_PTR);
        ret = HI_ERR_CERT_INVALID_PTR;
        goto out;
    }

    if (sizeof(hi_cert_key_data) != sizeof(hi_tee_cert_key_data)) {
        print_err_hex(sizeof(hi_cert_key_data));
        print_err_hex(sizeof(hi_tee_cert_key_data));
        ret = HI_ERR_CERT_INVALID_PARA;
        goto out;
    }

    ret = hi_mpi_cert_usekey((hi_cert_key_data*)ctl_data);

out:
    return ret;
}

hi_s32 hi_tee_cert_get_metadata(hi_u32 *metadata)
{
    return hi_mpi_cert_get_metadata(metadata);
}

hi_s32 hi_tee_cert_reset(hi_void)
{
    return hi_mpi_cert_reset();
}

hi_s32 hi_tee_cert_lock(hi_tee_cert_res_handle **handle)
{
    hi_s32 ret;

    if (handle == HI_NULL) {
        print_err_code(HI_ERR_CERT_INVALID_PTR);
        ret = HI_ERR_CERT_INVALID_PTR;
        goto out;
    }

    if (sizeof(hi_tee_cert_res_handle) != sizeof(hi_cert_res_handle)) {
        print_err_hex(sizeof(hi_cert_res_handle));
        print_err_hex(sizeof(hi_tee_cert_res_handle));
        ret = HI_ERR_CERT_INVALID_PARA;
        goto out;
    }

    ret = hi_mpi_cert_lock((hi_cert_res_handle **)handle);

out:
    return ret;
}

hi_s32 hi_tee_cert_unlock(hi_tee_cert_res_handle *handle)
{
    hi_s32 ret;

    if (handle == HI_NULL) {
        print_err_code(HI_ERR_CERT_INVALID_PTR);
        ret = HI_ERR_CERT_INVALID_PTR;
        goto out;
    }

    if (sizeof(hi_tee_cert_res_handle) != sizeof(hi_cert_res_handle)) {
        print_err_hex(sizeof(hi_cert_res_handle));
        print_err_hex(sizeof(hi_tee_cert_res_handle));
        ret = HI_ERR_CERT_INVALID_PARA;
        goto out;
    }

    ret = hi_mpi_cert_unlock((hi_cert_res_handle *)handle);

out:
    return ret;
}

hi_s32 hi_tee_cert_exchange(hi_tee_cert_res_handle *handle, hi_size_t num_of_commands,
                            const hi_tee_cert_command *command, hi_size_t *num_of_processed_commands)
{
    hi_s32 ret;

    if (handle == HI_NULL || command == HI_NULL) {
        print_err_code(HI_ERR_CERT_INVALID_PTR);
        ret = HI_ERR_CERT_INVALID_PTR;
        goto out;
    }

    if (num_of_commands == 0) {
        print_err_code(HI_ERR_CERT_INVALID_PARA);
        ret = HI_ERR_CERT_INVALID_PARA;
        goto out;
    }

    if (sizeof(hi_tee_cert_res_handle) != sizeof(hi_cert_res_handle)) {
        print_err_hex(sizeof(hi_cert_res_handle));
        print_err_hex(sizeof(hi_tee_cert_res_handle));
        ret = HI_ERR_CERT_INVALID_PARA;
        goto out;
    }

    if (sizeof(hi_tee_cert_command) != sizeof(hi_cert_command)) {
        print_err_hex(sizeof(hi_cert_command));
        print_err_hex(sizeof(hi_tee_cert_command));
        ret = HI_ERR_CERT_INVALID_PARA;
        goto out;
    }

    return hi_mpi_cert_exchange((hi_cert_res_handle *)handle, (hi_size_t)num_of_commands,
                                (hi_cert_command *)command, (hi_size_t *)num_of_processed_commands);

out:
    return ret;
}


