/*$$$!!Warning: Huawei key information asset. No spread without permission.$$$*/
/*CODEMARK:mJSkoqPZ5FEeD8fzH9bAQfhyPrkcI5cbzjotjI99J9PTkCMNHMtR+8Ejd3mKEkWbMFYmuIhV
lw/je6uplRzXM4SMvhun8vRGD9mNqO2kY4/aQFDUiG2CG+z+BR1XavYOLbgQ6mxl4mdMDMUc
pTTvsgNnGY+uGDhrcSrYT/yiWUcPU+7hHj/1z+1w4sei8NKrE5YtD4ycmPizGfaNhWQY5YvG
yUQ4I+iaikKhay3gs3gbvr2F/fo9kmuK6WNlljMWqZQckvm//k0TiyJFZq4NZA==#*/
/*$$$!!Warning: Deleting or modifying the preceding information is prohibited.$$$*/
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: tee app image version3 load service
 * Create: 2022.8.10
 */
#include "load_v3_app.h"
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <procmgr_ext.h>
#include <sys/mman.h>
#include <mem_mode.h>
#include <dyn_conf_dispatch_inf.h>
#include "tee_log.h"

#ifdef DYN_TA_SUPPORT_V3
static bool overflow_check(uint32_t a, uint32_t b)
{
    if (a > UINT32_MAX_VALUE - b)
        return true;
    return false;
}


TEE_Result tee_secure_get_img_size_v3(const uint8_t *share_buf, uint32_t buf_len, uint32_t *size)
{
    ta_image_hdr_v3_t image_hdr_v3;

    if (share_buf == NULL || size == NULL) {
        tloge("bad parameters\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (buf_len <= sizeof(ta_image_hdr_v3_t)) {
        tloge("img buf len is 0x%x too small\n", buf_len);
        return TEE_ERROR_GENERIC;
    }
    errno_t rc = memcpy_s(&image_hdr_v3, sizeof(image_hdr_v3), share_buf, sizeof(ta_image_hdr_v3_t));
    if (rc != EOK) {
        tloge("copy is failed\n");
        return TEE_ERROR_SECURITY;
    }

    if (overflow_check(image_hdr_v3.context_len, sizeof(ta_image_hdr_v3_t)))
        return TEE_ERROR_GENERIC;
    if (image_hdr_v3.context_len + sizeof(ta_image_hdr_v3_t) > MAX_IMAGE_LEN) {
        tloge("image hd error context len: 0x%x\n", image_hdr_v3.context_len);
        tloge("image hd error ta hd len: 0x%x\n", sizeof(ta_image_hdr_v3_t));
        return TEE_ERROR_GENERIC;
    }

    *size = image_hdr_v3.context_len + sizeof(ta_image_hdr_v3_t);
    return TEE_SUCCESS;
}
#endif