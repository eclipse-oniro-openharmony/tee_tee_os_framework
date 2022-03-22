/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: keyladder mpi driver.
 * Author: Hisilicon hisecurity team
 * Create: 2019-08-13
 */

#include "tee_klad.h"

#include "hi_tee_tsr2rcipher.h"
#include "hi_tee_cipher.h"
#include "tee_klad_func.h"
#include "tee_klad_mgmt.h"
#include "tee_klad_syscall.h"

hi_s32 hi_mpi_klad_init(hi_void)
{
    return ctl_klad_init();
}

hi_s32 hi_mpi_klad_deinit(hi_void)
{
    return ctl_klad_deinit();
}

hi_void hi_klad_dump_buffer(const hi_char *buf, hi_u32 len)
{
    const hi_u32 lwidth = 0x200;
    hi_char str_buf[0x200];
    hi_char *p = str_buf;
    hi_char *q = str_buf + lwidth;
    hi_u32 i;

    p = str_buf;
    if (buf == NULL) {
        snprintf_s(p, q - p, q - p - 1, "*NULL*\n");
    } else if (len < (lwidth / 0x2)) {
        for (i = 0; i < len; i++, p += 0x2) {
            snprintf_s(p, q - p, q - p - 1, "%02x", buf[i]);
        }
        *p = '\n';
        p++;
        *p = 0; /* end string with null char */
    } else {
        for (i = 0; i < (lwidth / 0x4) - 1; i++, p += 0x2) {
            snprintf_s(p, q - p, q - p - 1, "%02x", buf[i]);
        }
        snprintf_s(p, q - p, q - p - 1, " ... ");
        p += 0x5;
        for (i = len - (lwidth / 0x4) + 1; i < len; i++, p += 0x2) {
            snprintf_s(p, q - p, q - p - 1, "%02x", buf[i]);
        }
        *p = '\n';
        p++;
        *p = 0; /* end string with null char */
    }
    hi_dbg_klad("%s", str_buf);
    return;
}

hi_s32 hi_mpi_klad_create(hi_handle *create_handle)
{
    hi_s32 ret;
    struct time_ns time_b = {0};

    if (create_handle == HI_NULL) {
        ret = HI_ERR_KLAD_NULL_PTR;
        goto out;
    }

    get_time(&time_b);
    ret = klad_slot_mgmt_create_slot(create_handle);
    if (ret != HI_SUCCESS) {
        print_err_func(klad_slot_mgmt_create_slot, ret);
        goto out;
    }
    ret = klad_slot_mgmt_create_instance(*create_handle);
    if (ret != HI_SUCCESS) {
        print_err_func(klad_slot_mgmt_create_instance, ret);
        goto out1;
    }
    get_curr_cost("mpi_create", &time_b);
    return HI_SUCCESS;

out1:
    ret = klad_slot_mgmt_destroy_slot(*create_handle);
    if (ret != HI_SUCCESS) {
        print_err_func(klad_slot_mgmt_destroy_slot, ret);
    }
out:
    get_curr_cost("mpi_create", &time_b);
    return ret;
}

hi_s32 hi_mpi_klad_destroy(hi_handle handle)
{
    hi_s32 ret;
    struct time_ns time_b = {0};

    get_time(&time_b);

    if (klad_slot_instance_initialzed(handle) == HI_TRUE) {
        ret = klad_slot_instance_stop(handle);
        if (ret != HI_SUCCESS) {
            print_err_func(klad_slot_instance_stop, ret);
            goto out;
        }
    }

    ret = klad_slot_mgmt_destroy_instance(handle);
    if (ret != HI_SUCCESS) {
        print_err_func(klad_slot_mgmt_destroy_instance, ret);
        goto out;
    }
    ret = klad_slot_mgmt_destroy_slot(handle);
    if (ret != HI_SUCCESS) {
        print_err_func(klad_slot_mgmt_destroy_slot, ret);
    }
out:
    get_curr_cost("mpi_destroy", &time_b);
    return ret;
}

static hi_s32 __sw_klad_set_attr(hi_handle handle, const hi_klad_attr *attr)
{
    hi_s32 ret;

    if (klad_slot_instance_initialzed(handle) == HI_FALSE) {
        ret = klad_slot_instance_init(handle, get_klad_type(attr->klad_cfg.klad_type));
        if (ret != HI_SUCCESS) {
            print_err_func(klad_slot_instance_set_attr, ret);
            goto out;
        }
    }

    ret = klad_slot_instance_set_attr(handle, attr);
    if (ret != HI_SUCCESS) {
        print_err_func(klad_slot_instance_set_attr, ret);
        goto out;
    }
    ret = HI_SUCCESS;
out:
    return ret;
}

static hi_s32 __sw_klad_get_attr(hi_handle handle, hi_klad_attr *attr)
{
    return klad_slot_instance_get_attr(handle, attr);
}

hi_s32 hi_mpi_klad_set_attr(hi_handle handle, const hi_klad_attr *attr)
{
    hi_s32 ret;
    struct time_ns time_b = {0};

    if (attr == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }

    get_time(&time_b);
    ret = __sw_klad_set_attr(handle, attr);

    get_curr_cost("mpi_setattr", &time_b);
    return ret;
}

hi_s32 hi_mpi_klad_get_attr(hi_handle handle, hi_klad_attr *attr)
{
    hi_s32 ret;
    struct time_ns time_b = {0};

    if (attr == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }

    get_time(&time_b);
    ret =  __sw_klad_get_attr(handle, attr);

    get_curr_cost("mpi_getattr", &time_b);
    return ret;
}

hi_s32 hi_mpi_klad_set_rootkey_attr(hi_handle handle, const hi_rootkey_attr *rootkey_attr)
{
    hi_s32 ret;
    struct time_ns time_b = {0};

    if (rootkey_attr == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }

    get_time(&time_b);

    if (klad_slot_instance_initialzed(handle) == HI_FALSE) {
        ret = klad_slot_instance_init(handle, HI_KLAD_COM);
        if (ret != HI_SUCCESS) {
            print_err_func(klad_slot_instance_set_attr, ret);
            goto out;
        }
    }

    ret = klad_slot_instance_set_rootkey_attr(handle, rootkey_attr);
    if (ret != HI_SUCCESS) {
        print_err_func(klad_slot_instance_set_rootkey_attr, ret);
        goto out;
    }
    ret = HI_SUCCESS;
out:
    get_curr_cost("mpi_setrk", &time_b);
    return ret;
}

hi_s32 hi_mpi_klad_get_rootkey_attr(hi_handle handle, hi_rootkey_attr *rootkey_attr)
{
    hi_s32 ret;
    struct time_ns time_b = {0};

    if (rootkey_attr == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }

    get_time(&time_b);
    if (klad_slot_instance_initialzed(handle) == HI_FALSE) {
        return HI_ERR_KLAD_NOT_FIND_SESSION;
    }

    ret = klad_slot_instance_get_rootkey_attr(handle, rootkey_attr);

    get_curr_cost("mpi_getrk", &time_b);
    return ret;
}

static hi_s32 mpi_get_ks_handle(hi_handle target, hi_handle *ks)
{
    hi_s32 mod;
    hi_s32 ret = HI_SUCCESS;

    mod = HI_HANDLE_GET_MODID(target);
    if (mod == HI_ID_CIPHER) {
        ret = hi_tee_cipher_get_keyslot_handle(target, ks);
    } else if (mod == HI_ID_TSR2RCIPHER) {
#ifdef HI_TEE_TSR2RCIPHER_SUPPORT
        ret = hi_tee_tsr2rcipher_get_keyslot_handle(target, ks);
#else
        ret = HI_ERR_KLAD_NOT_SUPPORT;
#endif
    } else if (mod == HI_ID_DEMUX) {
        ret = HI_ERR_KLAD_NOT_SUPPORT;
    } else {
        *ks = target;
    }
    if (ret != HI_SUCCESS) {
        print_err_hex2(target, mod);
    }

    return ret;
}

hi_s32 hi_mpi_klad_attach(hi_handle handle, hi_handle target)
{
    hi_s32 ret;
    hi_handle ks = 0;
    struct time_ns time_b = {0};

    get_time(&time_b);
    ret = mpi_get_ks_handle(target, &ks);
    if (ret != HI_SUCCESS) {
        print_err_hex(ret);
        return ret;
    }

    ret = klad_slot_instance_attach(handle, ks);

    get_curr_cost("mpi_attach", &time_b);
    return ret;
}

hi_s32 hi_mpi_klad_detach(hi_handle handle, hi_handle target)
{
    hi_s32 ret;
    hi_handle ks = 0;
    struct time_ns time_b = {0};

    get_time(&time_b);
    ret = mpi_get_ks_handle(target, &ks);
    if (ret != HI_SUCCESS) {
        print_err_hex(ret);
        return ret;
    }

    ret = klad_slot_instance_detach(handle, ks);

    get_curr_cost("mpi_detach", &time_b);
    return ret;
}

hi_s32 hi_mpi_klad_set_session_key(hi_handle handle, const hi_klad_session_key *session_key)
{
    hi_s32 ret;
    struct time_ns time_b = {0};

    if (session_key == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }

    get_time(&time_b);
    ret = klad_slot_instance_set_session_key(handle, session_key);

    get_curr_cost("mpi_sessionkey", &time_b);
    return ret;
}

hi_s32 hi_mpi_klad_set_content_key(hi_handle handle, const hi_klad_content_key *content_key)
{
    hi_s32 ret;
    struct time_ns time_b = {0};

    if (content_key == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }

    get_time(&time_b);
    ret = klad_slot_instance_set_content_key(handle, content_key);
    if (ret != HI_SUCCESS) {
        print_err_func(klad_slot_instance_set_content_key, ret);
        goto out;
    }
    ret = klad_slot_instance_start(handle);
    if (ret != HI_SUCCESS) {
        print_err_func(klad_slot_instance_start, ret);
    }
out:
    get_curr_cost("mpi_contentkey", &time_b);
    return ret;
}

hi_s32 hi_mpi_klad_set_clear_key(hi_handle handle, const hi_klad_clear_key *clear_key)
{
    hi_s32 ret;
    struct time_ns time_b = {0};

    if (clear_key == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }

    get_time(&time_b);
    ret = klad_slot_clr_set_key(handle, clear_key);
    if (ret != HI_SUCCESS) {
        print_err_func(klad_slot_instance_set_content_key, ret);
        goto out;
    }
    ret = klad_slot_clr_start(handle);
    if (ret != HI_SUCCESS) {
        print_err_func(klad_slot_clr_start, ret);
    }
out:
    get_curr_cost("mpi_clrkey", &time_b);
    return ret;
}

hi_s32 hi_mpi_klad_async_set_content_key(hi_handle handle, const hi_klad_content_key *key,
                                         const klad_callback *call_back)
{
    hi_s32 ret;
    struct time_ns time_b = {0};

    if (key == HI_NULL || call_back == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }

    get_time(&time_b);
    ret = klad_slot_instance_set_content_key(handle, key);
    if (ret != HI_SUCCESS) {
        print_err_func(klad_slot_instance_set_content_key, ret);
        goto out;
    }
    ret = klad_slot_instance_async_start(handle, call_back);
    if (ret != HI_SUCCESS) {
        print_err_func(klad_slot_instance_async_start, ret);
    }
out:
    get_curr_cost("mpi_async contentkey", &time_b);
    return ret;
}

hi_s32 hi_mpi_klad_set_fp_key(hi_handle handle, hi_klad_fp_key *key)
{
    hi_s32 ret;
    struct time_ns time_b = {0};

    if (key == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }

    get_time(&time_b);
    ret = klad_slot_fp_set_fp_key(handle, key);
    if (ret != HI_SUCCESS) {
        print_err_func(klad_slot_fp_set_fp_key, ret);
        goto out;
    }
    if (key->operation == HI_KLAD_FP_OPT_ROUTE) {
        ret = klad_slot_fp_route(handle);
        if (ret != HI_SUCCESS) {
            print_err_func(klad_slot_fp_route, ret);
        }
    } else if (key->operation == HI_KLAD_FP_OPT_DECRYPT) {
        ret = klad_slot_fp_start(handle);
        if (ret != HI_SUCCESS) {
            print_err_func(klad_slot_fp_start, ret);
        }
    } else {
        key->enc_key_size = key->key_size;
        ret = klad_slot_fp_enc(handle, key->enc_key, key->enc_key_size);
        if (ret != HI_SUCCESS) {
            print_err_func(klad_slot_fp_enc, ret);
        }
    }
out:
    get_curr_cost("mpi_set_fp contentkey", &time_b);
    return ret;
}
