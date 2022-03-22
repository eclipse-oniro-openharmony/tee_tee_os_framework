/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: hsm firmware safety upgrade internal file
 * Author: chenyao
 * Create: 2020-06-30
 */
#include "tee_ext_api.h"
#include "tee_log.h"
#include "securec.h"

#include "firmware_upgrade_ta.h"
#include "firmware_upgrade_api.h"
#include "firmware_upgrade.h"
#include "hsm_update_lib_api.h"
#include "hsm_verify_api.h"
#include "efuse_lib_api.h"

uint32_t firmware_dev_id_verify(uint32_t dev_id)
{
    if (dev_id > g_dev_id_max) {
        tloge("dev id invaild %d.\n", dev_id);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

STATIC uint32_t image_id_verify(uint32_t img_id)
{
    if (((img_id < DSMI_COMPONENT_TYPE_HBOOT1_A) || (img_id > DSMI_COMPONENT_TYPE_HILINK)) &&
        (img_id != DSMI_COMPONENT_TYPE_SYS_BASE_CONFIG)) {
        tloge("img id invaild %d.\n", img_id);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

/*
 * buf_len - (min_len, max_len]
 */
STATIC int32_t general_buffer_verify(const uint8_t *buf, uint32_t buf_len,
    uint32_t min_wrong_len, uint32_t max_len)
{
    if (buf == NULL) {
        tloge("buffer invalid.\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if ((buf_len == min_wrong_len) || (buf_len > max_len)) {
        tloge("buffer len invalid[0x%x-0x%x], 0x%x.\n", min_wrong_len, max_len, buf_len);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

/*
 * buf_len == fix_len
 */
STATIC int32_t general_buffer_fixlen_verify(const uint8_t *buf, uint32_t buf_len,
    uint32_t fix_len)
{
    if (buf == NULL) {
        tloge("buffer invalid.\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if ((buf_len != fix_len)) {
        tloge("buffer len invalid 0x%x, 0x%x.\n", buf_len, fix_len);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

uint32_t soc_img_verify_para_check(uint64_t nsecure_addr, uint32_t length,
    uint32_t dev_id, uint32_t img_id, uint32_t pss_cfg)
{
    uint32_t ret;

    ret = firmware_dev_id_verify(dev_id);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    ret = image_id_verify(img_id);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    if (pss_cfg > PSS_FLAG) {
        tloge("pss flag in verify failed, %d.\n", pss_cfg);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (nsecure_addr < NSECURE_IMAGE_PADDR_START) {
        tloge("error nsecure address in verify\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if ((length > SECURE_IMAGE_MAX_SIZE) || (length <= SECURE_IMAGE_MIN_SIZE)) {
        tloge("length is invalid, 0x%x.\n", length);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

uint32_t soc_img_update_para_check(uint32_t dev_id, uint32_t img_index)
{
    uint32_t ret;

    ret = firmware_dev_id_verify(dev_id);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    if (img_index > SECURE_IMAGE_INDEX_MAX_SIZE) {
        tloge("error img index in update\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

uint32_t rim_update_para_check(uint32_t dev_id, uint8_t *rim_info, uint32_t rim_len)
{
    uint32_t ret;

    ret = firmware_dev_id_verify(dev_id);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    ret = general_buffer_fixlen_verify(rim_info, rim_len, SECURE_RIM_INFO_LEN);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    return TEE_SUCCESS;
}

uint32_t img_info_get_para_check(uint32_t dev_id, uint32_t flash_index,
    uint8_t *buffer, uint32_t buffer_size)
{
    uint32_t ret;

    ret = firmware_dev_id_verify(dev_id);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    if (flash_index > FLASH_INDEX_MAX) {
        tloge("error flash_index in img info get\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (buffer == NULL) {
        tloge("error buffer in img info get\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (buffer_size == 0) {
        tloge("error buffer_size in img info get\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

uint32_t img_version_get_para_check(uint32_t dev_id, uint32_t img_id, uint8_t *buffer,
    uint32_t buffer_size, uint32_t area_check)
{
    uint32_t ret;

    ret = firmware_dev_id_verify(dev_id);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    ret = image_id_verify(img_id);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    ret = general_buffer_verify(buffer, buffer_size, 0, IMG_VERSION_LEN);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    if (area_check > 1) {
        tloge("error area_check in version get\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}
