/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: This file is the source file of the otp driver.
 * Author: Hisilicon hisecurity group
 * Create: 2019-12-08
 */
#include "hi_tee_otp_nagra.h"

#include "hi_tee_errcode.h"
#include "tee_otp.h"
#include "otp_data.h"
#include "tee_otp_define.h"

#define PRIVILEGED_MODE_ENABLE  0xf
#define PRIVILEGED_MODE_DISABLE 0xa

hi_s32 hi_tee_otp_nagra_enable_privileged_mode(hi_void)
{
    struct pv_item pv = {
        0x01, {0xf},
    };
    struct hi_otp_field_name *field = __get_otp_field_name();

    return otp_pv_item_write((const hi_char *)field->privilegedmodeactivation, pv.value, pv.value_len);
}

hi_s32 hi_tee_otp_nagra_get_privileged_mode(hi_bool *privilege_mode)
{
    hi_s32 ret;
    struct pv_item pv = {
        0x01, {0x0},
    };
    struct hi_otp_field_name *field = __get_otp_field_name();

    if (privilege_mode == HI_NULL) {
        ret = HI_ERR_OTP_PTR_NULL;
        goto out;
    }

    ret = otp_pv_item_read((const hi_char *)field->privilegedmodeactivation, pv.value, &pv.value_len);
    if (ret != HI_SUCCESS) {
        print_err_func(otp_pv_item_read, ret);
        goto out;
    }

    *privilege_mode = (pv.value[0] & PRIVILEGED_MODE_ENABLE) == PRIVILEGED_MODE_DISABLE ? HI_FALSE : HI_TRUE;

out:
    return ret;
}

