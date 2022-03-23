/*
* Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
* Description: update firmware source file
* Author: chenyao
* Create: 2020/4/6
*/
#include <register_ops.h>
#include <tee_defines.h>
#include "drv_module.h"
#include "sre_access_control.h"
#include "sre_syscalls_id_ext.h"
#include "hmdrv_stub.h"
#include "tee_log.h"
#include "tee_bit_ops.h"
#include "drv_mem.h"

#include "securec.h"

#include "driver_common.h"
#include "sfc_driver.h"
#include "sfc_api.h"
#include "efuse_api.h"
#include "hsm_update_api.h"
#include "hsm_dev_id.h"
#include "hsm_secure_rw.h"

static uint64_t g_secure_paddr[DEV_NUM_MAX] =  { HISS_SEC_DDR, HISS_SEC_DDR + SFC_CHIPOFFSET };

static FLASH_IMAGE_INFO g_flash_info[DEV_NUM_MAX][FLASH_INFO_TYPE_NUM] = {
    {
        {DSMI_COMPONENT_TYPE_HBOOT1_A, HBOOT1_A_M, HBOOT1_A_B, HBOOT1_A_SIZE, 0, 0, 0, 0, 0, { 0 }},
        {DSMI_COMPONENT_TYPE_HILINK, HILINK_M, HILINK_B, HILINK_SIZE, 0, 0, 0, 0, 0, { 0 }},
        {DSMI_COMPONENT_TYPE_HBOOT1_B, HBOOT1_B_M, HBOOT1_B_B, HBOOT1_B_SIZE, 0, 0, 0, 0, 0, { 0 }},
        {DSMI_COMPONENT_TYPE_HBOOT2, HBOOT2_M, HBOOT2_B, HBOOT2_SIZE, 0, 0, 0, 0, 0, { 0 }},
        {DSMI_COMPONENT_TYPE_DDR, DDR_IMG_M, DDR_IMG_B, DDR_IMG_SIZE, 0, 0, 0, 0, 0, { 0 }},
        {DSMI_COMPONENT_TYPE_LP, LP_IMG_M, LP_IMG_B, LP_IMG_SIZE, 0, 0, 0, 0, 0, { 0 }},
        {DSMI_COMPONENT_TYPE_HSM, HSM_IMG_M, HSM_IMG_B, HSM_IMG_SIZE, 0, 0, 0, 0, 0, { 0 }},
        {DSMI_COMPONENT_TYPE_SAFETY_ISLAND, SI_IMG_M, SI_IMG_B, SI_IMG_SIZE, 0, 0, 0, 0, 0, { 0 }},
        {DSMI_COMPONENT_TYPE_SYS_BASE_CONFIG, SC_IMG_M, SC_IMG_B, SC_IMG_SIZE, 0, 0, 0, 0, 0, { 0 }},
        {SLICE_HBOOT2_0, HBOOT2_0_M, HBOOT2_0_B, HBOOT2_S_SIZE, 0, 0, 0, 0, 0, { 0 }},
        {SLICE_HBOOT2_1, HBOOT2_1_M, HBOOT2_1_B, HBOOT2_S_SIZE, 0, 0, 0, 0, 0, { 0 }},
        {SLICE_HBOOT2_2, HBOOT2_2_M, HBOOT2_2_B, HBOOT2_S_SIZE, 0, 0, 0, 0, 0, { 0 }},
        {SLICE_HBOOT2_3, HBOOT2_3_M, HBOOT2_3_B, HBOOT2_S_SIZE, 0, 0, 0, 0, 0, { 0 }},
        {SLICE_HBOOT2_4, HBOOT2_4_M, HBOOT2_4_B, HBOOT2_S_SIZE, 0, 0, 0, 0, 0, { 0 }},
        {SLICE_HBOOT2_5, HBOOT2_5_M, HBOOT2_5_B, HBOOT2_S_SIZE, 0, 0, 0, 0, 0, { 0 }},
    },
    {
        {DSMI_COMPONENT_TYPE_HBOOT1_A, HBOOT1_A_M, HBOOT1_A_B, HBOOT1_A_SIZE, 0, 0, 0, 0, 0, { 0 }},
        {DSMI_COMPONENT_TYPE_HILINK, HILINK_M, HILINK_B, HILINK_SIZE, 0, 0, 0, 0, 0, { 0 }},
        {DSMI_COMPONENT_TYPE_HBOOT1_B, HBOOT1_B_M, HBOOT1_B_B, HBOOT1_B_SIZE, 0, 0, 0, 0, 0, { 0 }},
        {DSMI_COMPONENT_TYPE_HBOOT2, HBOOT2_M, HBOOT2_B, HBOOT2_SIZE, 0, 0, 0, 0, 0, { 0 }},
        {DSMI_COMPONENT_TYPE_DDR, DDR_IMG_M, DDR_IMG_B, DDR_IMG_SIZE, 0, 0, 0, 0, 0, { 0 }},
        {DSMI_COMPONENT_TYPE_LP, LP_IMG_M, LP_IMG_B, LP_IMG_SIZE, 0, 0, 0, 0, 0, { 0 }},
        {DSMI_COMPONENT_TYPE_HSM, HSM_IMG_M, HSM_IMG_B, HSM_IMG_SIZE, 0, 0, 0, 0, 0, { 0 }},
        {DSMI_COMPONENT_TYPE_SAFETY_ISLAND, SI_IMG_M, SI_IMG_B, SI_IMG_SIZE, 0, 0, 0, 0, 0, { 0 }},
        {DSMI_COMPONENT_TYPE_SYS_BASE_CONFIG, SC_IMG_M, SC_IMG_B, SC_IMG_SIZE, 0, 0, 0, 0, 0, { 0 }},
        {SLICE_HBOOT2_0, HBOOT2_0_M, HBOOT2_0_B, HBOOT2_S_SIZE, 0, 0, 0, 0, 0, { 0 }},
        {SLICE_HBOOT2_1, HBOOT2_1_M, HBOOT2_1_B, HBOOT2_S_SIZE, 0, 0, 0, 0, 0, { 0 }},
        {SLICE_HBOOT2_2, HBOOT2_2_M, HBOOT2_2_B, HBOOT2_S_SIZE, 0, 0, 0, 0, 0, { 0 }},
        {SLICE_HBOOT2_3, HBOOT2_3_M, HBOOT2_3_B, HBOOT2_S_SIZE, 0, 0, 0, 0, 0, { 0 }},
        {SLICE_HBOOT2_4, HBOOT2_4_M, HBOOT2_4_B, HBOOT2_S_SIZE, 0, 0, 0, 0, 0, { 0 }},
        {SLICE_HBOOT2_5, HBOOT2_5_M, HBOOT2_5_B, HBOOT2_S_SIZE, 0, 0, 0, 0, 0, { 0 }},
    },
};

STATIC void set_img_verify_status(uint32_t chip_id, uint32_t array_index, uint32_t val)
{
    g_flash_info[chip_id][array_index].verify_status = val;
}

STATIC uint32_t check_img_verify_status(uint32_t chip_id, uint32_t array_index, uint32_t val)
{
    if (g_flash_info[chip_id][array_index].verify_status != val) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

STATIC uint32_t secure_img_index_set(uint32_t chip_id)
{
    uint32_t loop_times = sizeof(g_flash_info[0]) / sizeof(FLASH_IMAGE_INFO);
    uint32_t index_init = 0;

    for (uint32_t i = 0; i < loop_times; i++) {
        index_init += g_flash_info[chip_id][i].verify_status;
    }

    return index_init;
}

STATIC uint32_t get_array_index_by_img_id(uint32_t chip_id, uint32_t img_id,
    uint32_t *array_index)
{
    uint32_t i;
    uint32_t loop_times = sizeof(g_flash_info[0]) / sizeof(FLASH_IMAGE_INFO);

    for (i = 0; i < loop_times; i++) {
        if (g_flash_info[chip_id][i].img_id == img_id) {
            break;
        }
    }

    if (i == loop_times) {
        tloge("img id is invalid, 0x%x.\n", img_id);
        return TEE_ERROR_NOT_SUPPORTED;
    }

    *array_index = i;

    return TEE_SUCCESS;
}

STATIC uint32_t get_array_index_by_img_index(uint32_t chip_id, uint32_t img_index,
    uint32_t *array_index)
{
    uint32_t i;
    uint32_t loop_times = sizeof(g_flash_info[0]) / sizeof(FLASH_IMAGE_INFO);

    for (i = 0; i < loop_times; i++) {
        if (g_flash_info[chip_id][i].img_index == img_index) {
            uint32_t ret = check_img_verify_status(chip_id, i, 1);
            if (ret == TEE_SUCCESS) {
                break;
            }
        }
    }

    if (i == loop_times) {
        tloge("img index is invalid, 0x%x.\n", img_index);
        return TEE_ERROR_NOT_SUPPORTED;
    }

    *array_index = i;

    return TEE_SUCCESS;
}

STATIC uint32_t verify_para_check(uint32_t chip_id, uint32_t array_index, uint64_t nonsecure_addr,
    uint64_t storage_addr)
{
    uint32_t ret;

    if (nonsecure_addr < NSECURE_IMAGE_PADDR_START) {
        tloge("img info para check failed.\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = check_img_verify_status(chip_id, array_index, 0x0);
    if (ret != TEE_SUCCESS) {
        tloge("verify status is disorder.\n");
        return ret;
    }

    if ((storage_addr > HISS_MAX_DDR + (chip_id * SFC_CHIP_OFFSET)) ||
        (storage_addr < HISS_SEC_DDR + (chip_id * SFC_CHIP_OFFSET))) {
        tloge("ddr %d is invalid.\n", chip_id);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

STATIC uint32_t verify_mode_compared(uint32_t chip_id, uint64_t secure_vaddr, uint32_t pss_cfg)
{
    SE_IMAGE_HEAD *img_head = (SE_IMAGE_HEAD *)(uintptr_t)secure_vaddr;
    SUB_KEY_CERT *subkey_cert;
    uint32_t rsa_sign_alg;
    uint32_t ret;

    ret = efuse_check_ns_forbid(chip_id);
    if (ret != TEE_SUCCESS) {
        SLogTrace("Now is non secure boot.\n");
        return TEE_SUCCESS;
    }

    if (img_head->subkey_cert_offset != SCB_SUBKEY_CERT_OFFSET) {
        tloge("subkey cert offset invalid, 0x%x.\n", img_head->subkey_cert_offset);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    subkey_cert = (SUB_KEY_CERT *)((uintptr_t)img_head + (uintptr_t)(img_head->subkey_cert_offset));
    rsa_sign_alg = ((subkey_cert->subkey_sign_alg >> SCB_SIGN_RSA_ALG_SHIFT) & SCB_SIGN_RSA_ALG_MASK);

    if ((rsa_sign_alg != SCB_SIGN_RSA_PKCS_MODE) &&
        (rsa_sign_alg != SCB_SIGN_RSA_PSS_MODE)) {
        tloge("rsa sign alg id invalid, 0x%x.\n", rsa_sign_alg);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* psson: pss_cfg is 1. pssoff:pss_cfg is 0 */
    if ((pss_cfg ==  SCB_SIGN_RSA_PSS_MODE) && (rsa_sign_alg != pss_cfg)) {
        tloge("psscfg is pss mode and sign alg is pkcs mode\n");
    } else if ((pss_cfg ==  SCB_SIGN_RSA_PKCS_MODE) && (rsa_sign_alg != pss_cfg)) {
        tloge("psscfg is pkcs mode and sign alg is pss mode\n");
    }

    return UPDATE_SUCCESS;
}

STATIC uint32_t img_info_storage(uint32_t chip_id, uint32_t img_id, uint64_t nonsecure_addr,
    uint32_t length, uint64_t img_addr, uint32_t pss_cfg)
{
    uint32_t partition_size;
    uint32_t state = TEE_ERROR_BAD_STATE;
    uint64_t nonsecure_vaddr = 0;
    uint64_t secure_vaddr = 0;
    uint32_t ret;
    uint32_t array_index = 0;

    ret = get_array_index_by_img_id(chip_id, img_id, &array_index);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    ret = verify_para_check(chip_id, array_index, nonsecure_addr, g_secure_paddr[chip_id]);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    partition_size = g_flash_info[chip_id][array_index].part_size;
    if (length == 0 || length > partition_size) {
        tloge("invalid len, 0x%x, 0x%x.\n", length, partition_size);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = (int)sre_mmap(nonsecure_addr, length, (uintptr_t *)&nonsecure_vaddr, non_secure, non_cache);
    if (ret != TEE_SUCCESS) {
        tloge("mmap nonsecure addr failed, 0x%x\n", ret);
        return ret;
    }

    ret = (int)sre_mmap(g_secure_paddr[chip_id], partition_size, (uintptr_t *)&secure_vaddr,
                        secure, non_cache);
    if (ret != TEE_SUCCESS) {
        tloge("mmap nonsecure addr failed, 0x%x\n", ret);
        goto exit1;
    }

    ret = (int)memcpy_s((void *)(uintptr_t)secure_vaddr, partition_size,
                        (void *)(uintptr_t)nonsecure_vaddr, length);
    if (ret != EOK) {
        tloge("memcpys data failed, 0x%x\n", length);
        goto exit2;
    }

    ret = verify_mode_compared(chip_id, secure_vaddr, pss_cfg);
    if (ret != UPDATE_SUCCESS) {
        tloge("verify mode compared fail, 0x%x\n", ret);
        goto exit2;
    }

    g_flash_info[chip_id][array_index].img_len = length;
    g_flash_info[chip_id][array_index].img_index = secure_img_index_set(chip_id);
    g_flash_info[chip_id][array_index].secure_img_vaddr = g_secure_paddr[chip_id];

    *(uint64_t *)(uintptr_t)img_addr = g_secure_paddr[chip_id];
    g_secure_paddr[chip_id] += length;
    g_secure_paddr[chip_id] = ALIGN_UP(g_secure_paddr[chip_id], FOUR_BYTE_ALIGN);

    state = TEE_SUCCESS;

exit2:
    if (sre_unmap(secure_vaddr, partition_size) != 0) {
        state = TEE_ERROR_BAD_STATE;
        tloge("unmmap addr failed, 0x%x.\n", ret);
    }
exit1:
    if (sre_unmap(nonsecure_vaddr, length) != 0) {
        state = TEE_ERROR_BAD_STATE;
        tloge("unmmap addr failed, 0x%x.\n", ret);
    }

    return state;
}

STATIC uint32_t img_status_update(uint32_t chip_id, uint32_t img_id)
{
    uint32_t array_index = 0;
    uint32_t ret;

    ret = drv_dev_id_verify(chip_id);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    ret = get_array_index_by_img_id(chip_id, img_id, &array_index);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    set_img_verify_status(chip_id, array_index, 0x1);

    return TEE_SUCCESS;
}

STATIC uint32_t img_info_get(uint32_t chip_id, uint32_t img_index, uint64_t *secure_addr,
    uint32_t *flash_addr, uint32_t *length, uint32_t *slice)
{
    uint32_t array_index = 0;
    uint32_t img_id;
    uint32_t ret;

    if (*slice >= SLICE_MAX_SIZE) {
        tloge("invalid input param slice \n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = get_array_index_by_img_index(chip_id, img_index, &array_index);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    *secure_addr = g_flash_info[chip_id][array_index].secure_img_vaddr;
    *flash_addr = g_flash_info[chip_id][array_index].flash_offset;
    *length = g_flash_info[chip_id][array_index].img_len;
    img_id = g_flash_info[chip_id][array_index].img_id;

    /* Seperate HBOOT2 area to 512K size blocks */
    if (img_id == DSMI_COMPONENT_TYPE_HBOOT2) {
        uint64_t offset = *slice * HBOOT2_S_SIZE;
        if (offset > g_flash_info[chip_id][array_index].img_len) {
            tloge("invalid img offset slice\n");
            return TEE_ERROR_BAD_PARAMETERS;
        }

        if (offset > (g_flash_info[chip_id][array_index].img_len - HBOOT2_S_SIZE)) {
            *length = g_flash_info[chip_id][array_index].img_len - offset;
            *slice = 0;
        } else {
            *length = HBOOT2_S_SIZE;
            *slice += 1;
        }

        *secure_addr = g_flash_info[chip_id][array_index].secure_img_vaddr + offset;
        *flash_addr = g_flash_info[chip_id][array_index].flash_offset + offset;
    }
    return TEE_SUCCESS;
}

STATIC void clear_flash_img_info(uint32_t chip_id)
{
    uint32_t i;
    uint32_t loop_times = sizeof(g_flash_info[0]) / sizeof(FLASH_IMAGE_INFO);

    for (i = 0; i < loop_times; i++) {
        g_flash_info[chip_id][i].img_index = 0;
        g_flash_info[chip_id][i].img_len = 0;
        g_flash_info[chip_id][i].secure_img_vaddr = 0;
        g_flash_info[chip_id][i].verify_status = 0;
        g_flash_info[chip_id][i].update_status = 0;
    }

    g_secure_paddr[chip_id] = HISS_SEC_DDR + (chip_id * SFC_CHIP_OFFSET);
}

uint32_t secure_img_verify(uint32_t chip_id, uint32_t img_id,
    uint64_t nonsecure_addr, uint32_t length,
    uint64_t img_addr, uint32_t pss_cfg)
{
    uint32_t ret;

    ret = drv_dev_id_verify(chip_id);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    return img_info_storage(chip_id, img_id, nonsecure_addr, length, img_addr, pss_cfg);
}

STATIC uint32_t secure_img_set_update_status(uint32_t chip_id, uint32_t img_index)
{
    uint32_t array_index = 0;
    uint32_t ret;

    ret = get_array_index_by_img_index(chip_id, img_index, &array_index);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    g_flash_info[chip_id][array_index].update_status = 1;

    return TEE_SUCCESS;
}

STATIC uint32_t image_hash_compare(uint32_t chip_id,
    uint8_t *buffer, uint32_t buf_len,
    uint32_t offset)
{
    int res;
    uint32_t ret;
    uintptr_t flash_buf = 0;
    uint8_t flash_hash[SHA256_LEN] = {0};
    uint8_t buffer_hash[SHA256_LEN] = {0};
    uintptr_t base_addr = HISS_SYNC_DDR + (chip_id * SFC_CHIP_OFFSET);

    if (buf_len > IMAGE_MAX_SIZE) {
        tloge("wrong image len!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = sre_mmap(base_addr, IMAGE_MAX_SIZE, (uintptr_t *)&flash_buf, secure, non_cache);
    if (ret != TEE_SUCCESS) {
        tloge("mmap update buffer addr failed, 0x%x.\n", ret);
        return ret;
    }

    ret = flash_read(offset, (uint8_t *)flash_buf, buf_len, chip_id);
    if (ret != TEE_SUCCESS) {
        tloge("flash read fail, 0x%x.\n", ret);
        goto exit;
    }

    ret = secure_cal_hash((uint8_t *)flash_buf, buf_len, flash_hash);
    if (ret != TEE_SUCCESS) {
        tloge("cal hash fail, 0x%x.\n", ret);
        goto exit;
    }

    ret = secure_cal_hash(buffer, buf_len, buffer_hash);
    if (ret != TEE_SUCCESS) {
        tloge("cal hash fail, 0x%x.\n", ret);
        goto exit;
    }

    ret = memcmp(buffer_hash, flash_hash, SHA256_LEN);
    if (ret != TEE_SUCCESS) {
        tlogw("update image hash compare not same\n");
        goto exit;
    }

exit:
    res = sre_unmap(flash_buf, IMAGE_MAX_SIZE);
    if (res != TEE_SUCCESS) {
        tloge("sre unmap failed, 0x%x.\n", res);
        return res;
    }

    return ret;
}

STATIC uint32_t secure_img_update(uint32_t chip_id, uint32_t img_index, uint32_t *slice)
{
    int res;
    uint32_t ret;
    uint32_t length;
    uint32_t flash_addr = 0;
    uintptr_t secure_paddr = 0;
    uintptr_t secure_vaddr = 0;

    ret = drv_dev_id_verify(chip_id);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    /* 1.Obtaining image information */
    ret = img_info_get(chip_id, img_index, &secure_paddr, &flash_addr, &length, slice);
    if (ret != TEE_SUCCESS) {
        tloge("img info get in update fail, 0x%x.\n", ret);
        return ret;
    }

    /* 2.Mapping image secure memory */
    ret = sre_mmap(secure_paddr, length, (uintptr_t *)&secure_vaddr, secure, non_cache);
    if (ret != TEE_SUCCESS) {
        tloge("mmap nonsecure addr failed, 0x%x.\n", ret);
        return ret;
    }
    /* 3.Same image, no update required */
    ret = image_hash_compare(chip_id, (uint8_t *)secure_vaddr, length, flash_addr);
    if (ret == TEE_SUCCESS) {
        tlogw("image is same\n");
        goto set_flag_exit;
    }
    /* 4.Burn to the specified flash area. */
    ret = flash_write(flash_addr, (uint8_t *)secure_vaddr, length, chip_id);
    if (ret != TEE_SUCCESS) {
        tloge("flash write in update fail, 0x%x.\n", ret);
        goto exit;
    }

set_flag_exit:
    ret = secure_img_set_update_status(chip_id, img_index);
    if (ret != TEE_SUCCESS) {
        tloge("set update status fail\n");
    }

exit:
    res = sre_unmap(secure_vaddr, length);
    if (res != TEE_SUCCESS) {
        tloge("sre unmap secure addr failed, 0x%x.\n", res);
        return res;
    }

    return ret;
}

uint32_t secure_update_finish(uint32_t chip_id)
{
    uint64_t secure_vaddr = 0;
    uint32_t res;
    int ret;
    uintptr_t base_addr = HISS_SEC_DDR + (chip_id * SFC_CHIP_OFFSET);

    res = drv_dev_id_verify(chip_id);
    if (res != TEE_SUCCESS) {
        return res;
    }

    clear_flash_img_info(chip_id);

    ret = sre_mmap(base_addr, UPDATE_MAX_SIZE, (uintptr_t *)&secure_vaddr, secure, non_cache);
    if (ret != TEE_SUCCESS) {
        tloge("mmap secure addr failed, 0x%x.\n", ret);
        return ret;
    }

    ret = memset_s((void *)(uintptr_t)secure_vaddr, UPDATE_MAX_SIZE, 0, UPDATE_MAX_SIZE);
    if (ret != EOK) {
        tloge("memset failed, 0x%x.\n", ret);
        res = TEE_ERROR_BAD_STATE; /* return val */
        goto exit;
    }

exit:
    ret = sre_unmap(secure_vaddr, UPDATE_MAX_SIZE);
    if (ret != TEE_SUCCESS) {
        tloge("sre unmap secure addr failed, 0x%x.\n", ret);
        return ret;
    }

    return res;
}

STATIC uint32_t secure_img_sync_calhash(uint32_t chip_id, uint32_t img_id,
    IMG_PART_DS *img_part_s)
{
    uint32_t ret;

    ret = flash_read(img_part_s->flash_offset_m, (uint8_t *)(uintptr_t)img_part_s->buf_m_va,
                     img_part_s->length, chip_id);
    if (ret != TEE_SUCCESS) {
        tloge("read m part flash fail, img_id: 0x%x\n", img_id);
        return ret;
    }

    img_part_s->buf_b_va = img_part_s->buf_m_va + img_part_s->length;
    ret = flash_read(img_part_s->flash_offset_b, (uint8_t *)(uintptr_t)img_part_s->buf_b_va,
                     img_part_s->length, chip_id);
    if (ret != TEE_SUCCESS) {
        tloge("read b part flash fail, img_id: 0x%x\n", img_id);
        return ret;
    }

    ret = secure_cal_hash((uint8_t *)(uintptr_t)img_part_s->buf_m_va, img_part_s->length,
                          img_part_s->hash_m);
    if (ret != TEE_SUCCESS) {
        tloge("secure cal hash m part fail\n");
        return ret;
    }
    ret = secure_cal_hash((uint8_t *)(uintptr_t)img_part_s->buf_b_va, img_part_s->length,
                          img_part_s->hash_b);
    if (ret != TEE_SUCCESS) {
        tloge("secure cal hash b part fail\n");
        return ret;
    }

    ret = secure_cal_hash((uint8_t *)(uintptr_t)img_part_s->buf_va, img_part_s->length,
                          img_part_s->hash_d);
    if (ret != TEE_SUCCESS) {
        tloge("secure cal hash ddr part fail\n");
        return ret;
    }

    return TEE_SUCCESS;
}


STATIC uint32_t secure_img_sync_select(uint32_t chip_id, uint32_t img_id,
    IMG_PART_DS *img_part_s, uint32_t base_part)
{
    int ret;
    uint32_t offset;
    void *hash_temp = NULL;

    NO_USE_PARAMETER(img_id);

    if (base_part == 0) {
        tlogw("sync from m to b, img_id = 0x%x\n", img_id);
        offset = img_part_s->flash_offset_b;
        hash_temp = (void *)img_part_s->hash_m;
    } else {
        tlogw("sync from b to m, img_id = 0x%x\n", img_id);
        offset = img_part_s->flash_offset_m;
        hash_temp = (void *)img_part_s->hash_b;
    }

    ret = memcmp(hash_temp, img_part_s->hash_d, SHA256_LEN);
    if (ret != TEE_SUCCESS) {
        tloge("sync part %d compare failed.\n", base_part);
        return TEE_ERROR_BAD_STATE;
    }

    /* Same Image in the primary and secondary areas */
    ret = memcmp(img_part_s->hash_m, img_part_s->hash_b, SHA256_LEN);
    if (ret == TEE_SUCCESS) {
        tlogw("sync part compare same\n");
        goto exit;
    }

    ret = (int)flash_write(offset, (uint8_t *)(uintptr_t)img_part_s->buf_va, img_part_s->length, chip_id);
    if (ret != TEE_SUCCESS) {
        tloge("sfc write fail, 0x%x.\n", ret);
        return ret;
    }

exit:
    ret = memcpy_s(img_part_s->hash_bl, SHA256_LEN, hash_temp, SHA256_LEN);
    if (ret != TEE_SUCCESS) {
        tloge("set baseline fail, 0x%x.\n", ret);
        return TEE_ERROR_BAD_STATE;
    }

    return TEE_SUCCESS;
}

STATIC uint32_t get_img_part_info(uint32_t chip_id, uint32_t img_id, IMG_PART_DS *img_part_s)
{
    uint32_t array_index = 0;
    uint32_t ret;

    ret = get_array_index_by_img_id(chip_id, img_id, &array_index);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    img_part_s->length = g_flash_info[chip_id][array_index].part_size;
    img_part_s->flash_offset_m = g_flash_info[chip_id][array_index].flash_offset;
    img_part_s->flash_offset_b = g_flash_info[chip_id][array_index].flash_offset_b;
    img_part_s->hash_bl = g_flash_info[chip_id][array_index].bl_hash;

    return TEE_SUCCESS;
}

STATIC uint32_t secure_img_sync_baseline(uint32_t chip_id, uint32_t img_id, IMG_PART_DS *img_part_s)
{
    uint32_t ret;
    uint32_t is_m_match = 0;
    uint32_t is_b_match = 0;
    uint32_t offset;
    uint8_t *buf_va = NULL;

    NO_USE_PARAMETER(img_id);

    if (memcmp(img_part_s->hash_m, img_part_s->hash_bl, SHA256_LEN) == 0) {
        is_m_match = 1;
    }
    if (memcmp(img_part_s->hash_b, img_part_s->hash_bl, SHA256_LEN) == 0) {
        is_b_match = 1;
    }

    if ((is_m_match == 1) && (is_b_match == 1)) {
        tlogw("m and b part is valid\n");
        return TEE_SUCCESS;
    }
    if ((is_m_match == 0) && (is_b_match == 0)) {
        tloge("m and b part is invalid.\n");
        return TEE_ERROR_BAD_STATE;
    }

    if (is_m_match == 1) {
        tlogw("sync from m to b, img_id = 0x%x\n", img_id);
        offset = img_part_s->flash_offset_b;
        buf_va = (uint8_t *)(uintptr_t)img_part_s->buf_m_va;
    } else {
        tlogw("sync from b to m, img_id = 0x%x\n", img_id);
        offset = img_part_s->flash_offset_m;
        buf_va = (uint8_t *)(uintptr_t)img_part_s->buf_b_va;
    }

    ret = flash_write(offset, buf_va, img_part_s->length, chip_id);
    if (ret != TEE_SUCCESS) {
        tloge("sfc write fail, ret = %d\n", ret);
        return ret;
    }

    return TEE_SUCCESS;
}

STATIC uint32_t secure_img_sync(uint32_t chip_id, uint32_t img_id,
    uint32_t base_part, uint32_t baseline_flag)
{
    uint32_t ret;
    uint64_t buf_va = 0;
    uint64_t buf_m_va = 0;
    IMG_PART_DS img_part_s = { 0 };
    uintptr_t sync_base = HISS_SYNC_DDR + (chip_id * SFC_CHIP_OFFSET);
    uintptr_t sync_m_base = HISS_SYNC_M_DDR + (chip_id * SFC_CHIP_OFFSET);

    ret = drv_dev_id_verify(chip_id);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    ret = get_img_part_info(chip_id, img_id, &img_part_s);
    if (ret != TEE_SUCCESS) {
        tloge("get image part info fail\n");
        return ret;
    }

    /* use the image which is verified and save in HISS_SYNC_DDR as the standard image */
    ret = (uint32_t)sre_mmap(sync_base, IMAGE_MAX_SIZE, (uintptr_t *)&buf_va, secure, non_cache);
    if (ret != TEE_SUCCESS) {
        tloge("mmap secure addr failed, 0x%x.\n", ret);
        return ret;
    }
    ret = (uint32_t)sre_mmap(sync_m_base, UPDATE_MAX_SIZE, (uintptr_t *)&buf_m_va, secure, non_cache);
    if (ret != TEE_SUCCESS) {
        tloge("mmap secure addr failed, 0x%x.\n", ret);
        ret = TEE_ERROR_BAD_STATE;
        goto exit0;
    }

    img_part_s.buf_m_va = buf_m_va;
    img_part_s.buf_va = buf_va;

    // hboot2 is seperate to many pieces, point to right piece
    if ((img_id >= SLICE_HBOOT2_1) && (img_id <= SLICE_HBOOT2_5)) {
        img_part_s.buf_va += (img_id - SLICE_HBOOT2_0) * HBOOT2_S_SIZE;
    }

    ret = secure_img_sync_calhash(chip_id, img_id, &img_part_s);
    if (ret != TEE_SUCCESS) {
        tloge("secure img calhash fail\n");
        goto exit1;
    }

    if (baseline_flag == 1) {
        tlogw("sync refer to baseline.\n");
        ret = secure_img_sync_baseline(chip_id, img_id, &img_part_s);
    } else {
        tlogw("sync from select.\n");
        ret = secure_img_sync_select(chip_id, img_id, &img_part_s, base_part);
    }
    if (ret != TEE_SUCCESS) {
        tloge("task sync img fail\n");
    }

exit1:
    if (memset_s((void *)(uintptr_t)img_part_s.buf_m_va, UPDATE_MAX_SIZE, 0, img_part_s.length << 1) != EOK) {
        tloge("memset failed!\n");
        ret = TEE_ERROR_BAD_STATE;
    }

    if (sre_unmap(buf_m_va, UPDATE_MAX_SIZE) != 0) {
        tloge("sre unmap secure addr failed!\n");
        ret = TEE_ERROR_BAD_STATE;
    }

exit0:
    if (sre_unmap(buf_va, IMAGE_MAX_SIZE) != 0) {
        tloge("sre unmap secure addr failed!\n");
        ret = TEE_ERROR_BAD_STATE;
    }

    return ret;
}


/* get img version number, area_check: firmware start from FLASH_MASTER or FLASH_BAK */
uint32_t secure_img_version_get(uint32_t chip_id, uint32_t img_id, uint8_t *buffer,
    uint32_t buffer_size, uint32_t area_check)
{
    uint32_t ret;
    uint32_t flash_offset_value;
    uint32_t array_index = 0;

    ret = drv_dev_id_verify(chip_id);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    if (area_check > 1) {
        tloge("hsm version get input para is wrong!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (buffer_size < SOC_IMAGE_VERSION_LEN) {
        tloge("hsm version get buffer size is wrong!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = get_array_index_by_img_id(chip_id, img_id, &array_index);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    if (area_check == FLASH_MASTER) {
        flash_offset_value = g_flash_info[chip_id][array_index].flash_offset;
    } else {
        flash_offset_value = g_flash_info[chip_id][array_index].flash_offset_b;
    }

    ret = sfc_bus_read(flash_offset_value + SOC_IMAGE_VERSION_OFF,
                       buffer, SOC_IMAGE_VERSION_LEN, chip_id);
    if (ret != TEE_SUCCESS) {
        tloge("sfc bus read in version get fail, 0x%x.\n", ret);
        return ret;
    }

    return TEE_SUCCESS;
}

/* copy img from flash to secure ddr based on img_id */
STATIC uint32_t secure_part_read(uint32_t chip_id, uint32_t img_id,
    uint64_t *img_addr, uint32_t *length, uint32_t base_part)
{
    int res;
    uint32_t ret;
    uintptr_t buf_va = 0;
    uintptr_t sync_base = HISS_SYNC_DDR + (chip_id * SFC_CHIP_OFFSET);
    uint32_t offset;
    IMG_PART_DS img_part_s = { 0 };

    ret = drv_dev_id_verify(chip_id);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    ret = get_img_part_info(chip_id, img_id, &img_part_s);
    if (ret != TEE_SUCCESS) {
        tloge("get image part info fail\n");
        return ret;
    }

    *img_addr = sync_base;
    *length = img_part_s.length;

    ret = sre_mmap(sync_base, *length, (uintptr_t *)&buf_va, secure, non_cache);
    if (ret != TEE_SUCCESS) {
        tloge("mmap secure addr failed, 0x%x.\n", ret);
        return ret;
    }

    if (base_part == 0) {
        offset = img_part_s.flash_offset_m;
    } else {
        offset = img_part_s.flash_offset_b;
    }

    ret = flash_read(offset, (uint8_t *)buf_va, *length, chip_id);
    if (ret != TEE_SUCCESS) {
        tloge("sfc read fail, 0x%x.\n", ret);
        (void)memset_s((void *)buf_va, *length, 0, *length);
        goto exit;
    }

exit:
    res = sre_unmap(buf_va, *length);
    if (res != TEE_SUCCESS) {
        tloge("sre unmap secure addr failed, 0x%x.\n", res);
        return res;
    }

    return ret;
}

STATIC uint32_t secure_hboot1a_trans(uint32_t chip_id, uint32_t *img_addr, uint32_t *len)
{
    uint32_t ret;
    uintptr_t secure_vaddr = 0;
    uint32_t array_index = 0;
    uint64_t base_addr = HISS_SEC_DDR + (chip_id * SFC_CHIP_OFFSET);
    int res;

    ret = drv_dev_id_verify(chip_id);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    ret = get_array_index_by_img_id(chip_id, DSMI_COMPONENT_TYPE_HBOOT1_A, &array_index);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    ret = check_img_verify_status(chip_id, array_index, 0x1);
    if (ret != TEE_SUCCESS) {
        tloge("verify status is disorder.\n");
        return ret;
    }

    ret = sre_mmap(base_addr, HBOOT1_A_SIZE, (uintptr_t *)&secure_vaddr, secure, non_cache);
    if (ret != TEE_SUCCESS) {
        tloge("mmap nonsecure addr failed, 0x%x.\n", ret);
        return ret;
    }

    /* In the hot reset scenario, the image is copied to the sec DDR. */
    ret = flash_read(HBOOT1_A_M, (uint8_t *)secure_vaddr, HBOOT1_A_SIZE, 0);
    if (ret != TEE_SUCCESS) {
        goto exit;
    }

    *img_addr = (uint32_t)base_addr;
    *len = (uint32_t)g_flash_info[chip_id][array_index].img_len;

exit:
    res = sre_unmap(secure_vaddr, HBOOT1_A_SIZE);
    if (res != TEE_SUCCESS) {
        tloge("sre unmap secure addr failed, 0x%x.\n", res);
        return res;
    }

    return ret;
}

STATIC uint32_t secure_is_update_finish(uint32_t chip_id)
{
    uint32_t loop_times = sizeof(g_flash_info[0]) / sizeof(FLASH_IMAGE_INFO);
    uint32_t i;
    uint32_t ret;

    ret = drv_dev_id_verify(chip_id);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    for (i = 0; i < loop_times; i++) {
        if (g_flash_info[chip_id][i].update_status == 1) {
            break;
        }
    }

    if (i == loop_times) {
        return TEE_ERROR_ITEM_NOT_FOUND;
    }

    return TEE_SUCCESS;
}

int firmup_syscall(int swi_id, struct drv_param *params, uint64_t permissions)
{
    uint32_t ret;
    uint32_t offset;
    uint64_t *args = NULL;
    uint64_t nonesecure_addr;
    uint64_t buffer_addr;
    uint64_t buffer_size;
    uint64_t img_addr;
    uint64_t hboot1a_addr;
    uint64_t len_addr;
    uint32_t length;
    uint32_t chip_id;
    uint32_t img_id;
    uint32_t img_index;
    uint32_t flash_index;
    uint32_t in_value;
    uint64_t out_value;
    uint32_t base_part;
    uint32_t baseline_flag;
    uint32_t area_check;

    if ((params == NULL) || (params->args == 0)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    args = (uint64_t *)(uintptr_t)params->args;
    length = args[ARRAY_INDEX3];
    chip_id = args[ARRAY_INDEX4];
    HANDLE_SYSCALL(swi_id) {
        SYSCALL_PERMISSION(SYSCALL_SECURE_FLASH_ERASE, permissions, FLASH_GROUP_PERMISSION)
        offset = args[0];
        ret = secure_flash_erase(offset, length, chip_id);
        args[0] = ret;
        SYSCALL_END

        SYSCALL_PERMISSION(SYSCALL_SECURE_FLASH_READ, permissions, FLASH_GROUP_PERMISSION)
        offset = args[0];
        buffer_addr = args[1];
        ACCESS_CHECK_A64(buffer_addr, args[ARRAY_INDEX3]);
        ACCESS_WRITE_RIGHT_CHECK(buffer_addr, args[ARRAY_INDEX3]);
        ret = secure_flash_read(chip_id, offset, (uint8_t *)(uintptr_t)buffer_addr, length);
        args[0] = ret;
        SYSCALL_END

        SYSCALL_PERMISSION(SYSCALL_SECURE_FLASH_WRITE, permissions, FLASH_GROUP_PERMISSION)
        offset = args[0];
        buffer_addr = args[1];
        ACCESS_CHECK_A64(buffer_addr, args[ARRAY_INDEX3]);
        ACCESS_WRITE_RIGHT_CHECK(buffer_addr, args[ARRAY_INDEX3]);
        ret = secure_flash_write(chip_id, offset, (uint8_t *)(uintptr_t)buffer_addr, length);
        args[0] = ret;
        SYSCALL_END

        SYSCALL_PERMISSION(SYSCALL_SECURE_IMG_VERIFY, permissions, HSM_GROUP_PERMISSION)
        img_id = args[0];
        uint32_t pss_cfg = args[ARRAY_INDEX7];
        nonesecure_addr = GET_64BIT_ADDR(args[1], args[ARRAY_INDEX2]);
        img_addr = GET_64BIT_ADDR(args[ARRAY_INDEX5], args[ARRAY_INDEX6]);
        ACCESS_CHECK_A64(img_addr, sizeof(uint64_t));
        ACCESS_WRITE_RIGHT_CHECK(img_addr, sizeof(uint64_t));
        ret = secure_img_verify(chip_id, img_id, nonesecure_addr, length, img_addr, pss_cfg);
        args[0] = ret;
        SYSCALL_END

        SYSCALL_PERMISSION(SYSCALL_SECURE_VERIFY_STATUS_UPDATE, permissions, HSM_GROUP_PERMISSION)
        img_id = args[0];
        ret = img_status_update(chip_id, img_id);
        args[0] = ret;
        SYSCALL_END

        SYSCALL_PERMISSION(SYSCALL_SECURE_IMG_UPDATE, permissions, HSM_GROUP_PERMISSION)
        img_index = args[0];
        buffer_addr = GET_64BIT_ADDR(args[1], args[ARRAY_INDEX2]);
        ACCESS_CHECK_A64(buffer_addr, sizeof(uint64_t));
        ACCESS_WRITE_RIGHT_CHECK(buffer_addr, sizeof(uint64_t));
        ret = secure_img_update(chip_id, img_index, (uint32_t *)(uintptr_t)buffer_addr);
        args[0] = ret;
        SYSCALL_END

        SYSCALL_PERMISSION(SYSCALL_SECURE_UPDATE_FINISH, permissions, HSM_GROUP_PERMISSION)
        ret = secure_update_finish(chip_id);
        args[0] = ret;
        SYSCALL_END

        SYSCALL_PERMISSION(SYSCALL_SECURE_VERSION_GET, permissions, HSM_GROUP_PERMISSION)
        img_id = args[0];
        area_check = args[ARRAY_INDEX5];
        buffer_addr = GET_64BIT_ADDR(args[1], args[ARRAY_INDEX2]);
        ACCESS_CHECK_A64(buffer_addr, length);
        ACCESS_WRITE_RIGHT_CHECK(buffer_addr, length);
        ret = secure_img_version_get(chip_id, img_id, (uint8_t *)(uintptr_t)buffer_addr, length, area_check);
        args[0] = ret;
        SYSCALL_END

        SYSCALL_PERMISSION(SYSCALL_SECURE_COUNT_GET, permissions, HSM_GROUP_PERMISSION)
        buffer_addr = GET_64BIT_ADDR(args[1], args[ARRAY_INDEX2]);
        ACCESS_CHECK_A64(buffer_addr, sizeof(uint64_t));
        ACCESS_WRITE_RIGHT_CHECK(buffer_addr, sizeof(uint64_t));
        ret = secure_img_count_get(chip_id, (uint32_t *)(uintptr_t)buffer_addr);
        args[0] = ret;
        SYSCALL_END

        SYSCALL_PERMISSION(SYSCALL_SECURE_INFO_GET, permissions, FLASH_GROUP_PERMISSION)
        flash_index = args[0];
        buffer_addr = GET_64BIT_ADDR(args[1], args[ARRAY_INDEX2]);
        buffer_size = GET_64BIT_ADDR(args[ARRAY_INDEX3], args[ARRAY_INDEX5]);
        ACCESS_CHECK_A64(buffer_addr, sizeof(FLASHINFO));
        ACCESS_WRITE_RIGHT_CHECK(buffer_addr, sizeof(FLASHINFO));
        ACCESS_CHECK_A64(buffer_size, sizeof(uint64_t));
        ACCESS_WRITE_RIGHT_CHECK(buffer_size, sizeof(uint64_t));
        ret = secure_img_info_get(chip_id, flash_index, (uint8_t *)(uintptr_t)buffer_addr,
                                  (uint32_t *)(uintptr_t)buffer_size);
        args[0] = ret;
        SYSCALL_END

        SYSCALL_PERMISSION(SYSCALL_SECURE_UFS_CNT_READ, permissions, HSM_GROUP_PERMISSION)
        out_value = GET_64BIT_ADDR(args[1], args[ARRAY_INDEX2]);
        ACCESS_CHECK_A64(out_value, sizeof(uint64_t));
        ACCESS_WRITE_RIGHT_CHECK(out_value, sizeof(uint64_t));
        ret = secure_ufs_reset_cnt_read(chip_id, (uint32_t *)(uintptr_t)out_value);
        args[0] = ret;
        SYSCALL_END

        SYSCALL_PERMISSION(SYSCALL_SECURE_UFS_CNT_WRITE, permissions, HSM_GROUP_PERMISSION)
        in_value = args[0];
        ret = secure_ufs_reset_cnt_write(chip_id, in_value);
        args[0] = ret;
        SYSCALL_END

        SYSCALL_PERMISSION(SYSCALL_UPGRADE_SRAM_READ, permissions, HSM_GROUP_PERMISSION)
        offset = args[0];
        buffer_addr = GET_64BIT_ADDR(args[1], args[ARRAY_INDEX2]);
        ACCESS_CHECK_A64(buffer_addr, length);
        ACCESS_WRITE_RIGHT_CHECK(buffer_addr, length);
        ret = secure_sram_read(chip_id, offset, (uint8_t *)(uintptr_t)buffer_addr, length);
        args[0] = ret;
        SYSCALL_END

        SYSCALL_PERMISSION(SYSCALL_UPGRADE_FLASH_READ, permissions, FLASH_GROUP_PERMISSION)
        offset = args[0];
        buffer_addr = GET_64BIT_ADDR(args[1], args[ARRAY_INDEX2]);
        ACCESS_CHECK_A64(buffer_addr, length);
        ACCESS_WRITE_RIGHT_CHECK(buffer_addr, length);
        ret = secure_flash_read(chip_id, offset, (uint8_t *)(uintptr_t)buffer_addr, length);
        args[0] = ret;
        SYSCALL_END

        SYSCALL_PERMISSION(SYSCALL_UPGRADE_FLASH_WRITE, permissions, FLASH_GROUP_PERMISSION)
        offset = args[0];
        buffer_addr = GET_64BIT_ADDR(args[1], args[ARRAY_INDEX2]);
        ACCESS_CHECK_A64(buffer_addr, length);
        ACCESS_WRITE_RIGHT_CHECK(buffer_addr, length);
        ret = secure_flash_write(chip_id, offset, (uint8_t *)(uintptr_t)buffer_addr, length);
        args[0] = ret;
        SYSCALL_END

        SYSCALL_PERMISSION(SYSCALL_UPGRADE_RESET_CNT_READ, permissions, HSM_GROUP_PERMISSION)
        offset = args[0];
        buffer_addr = GET_64BIT_ADDR(args[1], args[ARRAY_INDEX2]);
        ACCESS_CHECK_A64(buffer_addr, sizeof(uint64_t));
        ACCESS_WRITE_RIGHT_CHECK(buffer_addr, sizeof(uint64_t));
        ret = secure_sysctrl_read(chip_id, offset, (uint32_t *)(uintptr_t)buffer_addr);
        args[0] = ret;
        SYSCALL_END

        SYSCALL_PERMISSION(SYSCALL_UPGRADE_RESET_CNT_WRITE, permissions, HSM_GROUP_PERMISSION)
        offset = args[0];
        buffer_addr = GET_64BIT_ADDR(args[1], args[ARRAY_INDEX2]);
        ACCESS_CHECK_A64(buffer_addr, sizeof(uint64_t));
        ACCESS_WRITE_RIGHT_CHECK(buffer_addr, sizeof(uint64_t));
        ret = secure_sysctrl_write(chip_id, offset, (uint32_t *)(uintptr_t)buffer_addr);
        args[0] = ret;
        SYSCALL_END

        SYSCALL_PERMISSION(SYSCALL_SECURE_IMG_SYNC, permissions, HSM_GROUP_PERMISSION)
        img_id = args[0];
        base_part = args[1];
        baseline_flag = args[ARRAY_INDEX2];
        ret = secure_img_sync(chip_id, img_id, base_part, baseline_flag);
        args[0] = ret;
        SYSCALL_END

        SYSCALL_PERMISSION(SYSCALL_SECURE_ROOTKEY_GET, permissions, HSM_GROUP_PERMISSION)
        buffer_addr = GET_64BIT_ADDR(args[1], args[ARRAY_INDEX2]);
        ACCESS_CHECK_A64(buffer_addr, length);
        ACCESS_WRITE_RIGHT_CHECK(buffer_addr, length);
        ret = secure_root_key_get((uint8_t *)(uintptr_t)buffer_addr, length);
        args[0] = ret;
        SYSCALL_END

        SYSCALL_PERMISSION(SYSCALL_SECURE_CMDLINE_GET, permissions, HSM_GROUP_PERMISSION)
        buffer_addr = GET_64BIT_ADDR(args[1], args[ARRAY_INDEX2]);
        length = args[ARRAY_INDEX3];
        ACCESS_CHECK_A64(buffer_addr, length);
        ACCESS_WRITE_RIGHT_CHECK(buffer_addr, length);
        ret = secure_cmdline_get(args[0], (uint32_t *)(uintptr_t)buffer_addr, length);
        args[0] = ret;
        SYSCALL_END

        SYSCALL_PERMISSION(SYSCALL_REFLASH_HILINK, permissions, HSM_GROUP_PERMISSION)
        ret = secure_reflash_hilink(chip_id);
        args[0] = ret;
        SYSCALL_END

        SYSCALL_PERMISSION(SYSCALL_SECURE_PART_READ, permissions, HSM_GROUP_PERMISSION)
        img_id = args[0];
        base_part = args[ARRAY_INDEX3];
        buffer_size = GET_64BIT_ADDR(args[1], args[ARRAY_INDEX2]);
        ACCESS_CHECK_A64(buffer_size, sizeof(uint64_t));
        ACCESS_WRITE_RIGHT_CHECK(buffer_size, sizeof(uint64_t));
        img_addr = GET_64BIT_ADDR(args[ARRAY_INDEX5], args[ARRAY_INDEX6]);
        ACCESS_CHECK_A64(img_addr, sizeof(uint64_t));
        ACCESS_WRITE_RIGHT_CHECK(img_addr, sizeof(uint64_t));
        ret = secure_part_read(chip_id, img_id, (uint64_t *)(uintptr_t)img_addr,
            (uint32_t *)(uintptr_t)buffer_size, base_part);
        args[0] = ret;
        SYSCALL_END

        SYSCALL_PERMISSION(SYSCALL_SECURE_GET_BLFLAG, permissions, HSM_GROUP_PERMISSION)
        out_value = args[1];
        ACCESS_CHECK_A64(out_value, sizeof(uint64_t));
        ACCESS_WRITE_RIGHT_CHECK(out_value, sizeof(uint64_t));
        ret = secure_get_baseline_flag(chip_id, (uint32_t *)(uintptr_t)out_value);
        args[0] = ret;
        SYSCALL_END

        SYSCALL_PERMISSION(SYSCALL_SECURE_SET_BLFLAG, permissions, HSM_GROUP_PERMISSION)
        ret = secure_set_baseline_flag(chip_id);
        args[0] = ret;
        SYSCALL_END

        SYSCALL_PERMISSION(SYSCALL_SECURE_HBOOT_TRANS, permissions, HSM_GROUP_PERMISSION)
        hboot1a_addr = args[1];
        len_addr = args[ARRAY_INDEX2];
        ACCESS_CHECK_A64(len_addr, HBOOT1_A_LEN_SIZE);
        ACCESS_WRITE_RIGHT_CHECK(len_addr, HBOOT1_A_LEN_SIZE);
        ACCESS_CHECK_A64(hboot1a_addr, HBOOT1_A_ADDR_SIZE);
        ACCESS_WRITE_RIGHT_CHECK(hboot1a_addr, HBOOT1_A_ADDR_SIZE);
        ret = secure_hboot1a_trans(chip_id, (uint32_t *)(uintptr_t)hboot1a_addr,
                                   (uint32_t *)(uintptr_t)len_addr);
        args[0] = ret;
        SYSCALL_END

        SYSCALL_PERMISSION(SYSCALL_SECURE_UPDATE_STATUS, permissions, HSM_GROUP_PERMISSION)
        ret = secure_is_update_finish(chip_id);
        args[0] = ret;
        SYSCALL_END

        SYSCALL_PERMISSION(SYSCALL_GET_EFUSE_NVCNT, permissions, HSM_EFUSE_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[ARRAY_INDEX1], args[ARRAY_INDEX2]);
        ACCESS_WRITE_RIGHT_CHECK(args[ARRAY_INDEX1], args[ARRAY_INDEX2]);
        ret = secure_get_efuse_nvcnt(args[ARRAY_INDEX0], args[ARRAY_INDEX1], args[ARRAY_INDEX2]);
        args[0] = ret;
        SYSCALL_END

        SYSCALL_PERMISSION(SYSCALL_GET_SYNC_FLAG, permissions, HSM_GROUP_PERMISSION)
        out_value = args[ARRAY_INDEX0];
        ACCESS_CHECK_A64(out_value, sizeof(uint64_t));
        ACCESS_WRITE_RIGHT_CHECK(out_value, sizeof(uint64_t));
        ret = secure_get_sync_flag(chip_id, (uint32_t *)(uintptr_t)out_value);
        args[0] = ret;
        SYSCALL_END

        SYSCALL_PERMISSION(SYSCALL_GET_DEV_NUM, permissions, HSM_GROUP_PERMISSION)
        out_value = args[ARRAY_INDEX0];
        ACCESS_CHECK_A64(out_value, sizeof(uint64_t));
        ACCESS_WRITE_RIGHT_CHECK(out_value, sizeof(uint64_t));
        ret = secure_get_dev_num((uint32_t *)(uintptr_t)out_value);
        args[0] = ret;
        SYSCALL_END

        SYSCALL_PERMISSION(SYSCALL_SECURE_RECOVERY_CNT_WRITE, permissions, HSM_GROUP_PERMISSION)
        ret = secure_recovery_reset_cnt_write(chip_id);
        args[0] = ret;
        SYSCALL_END
    default:
        return TEE_ERROR_NOT_SUPPORTED;
    }
    return 0;
}

DECLARE_TC_DRV(
    firmup_driver,
    0,
    0,
    0,
    TC_DRV_MODULE_INIT,
    NULL,
    NULL,
    firmup_syscall,
    NULL,
    NULL
);

