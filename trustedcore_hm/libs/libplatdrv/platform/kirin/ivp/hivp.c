/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: This file implement some api for load ivp bin
 * Author: chenweiyu 00416071
 * Create: 2019-05-24
 */

#include "hivp.h"
#include <stdint.h>
#include <drv_mem.h>
#include <drv_cache_flush.h>
#include "hisi_secureboot.h"
#include "secmem.h"
#include "securec.h"
#include "string.h"
#include "tee_log.h"

#define SEC_IVP_BIN_SIZE     0x200000
#define SEC_IVP_CMA_SIZE     SEC_IVP_BIN_SIZE
#define SIZE_OF_INT          4
#define FILE_HEADER_NAME_LEN 4
#define MAX_TIME_LENGTH      20

#ifdef IVP_DUAL_CORE
#define PMCTRL_BASE_REG         0xFFF01000
#define PMCTRL_IVP_POWER_OFFSET 0x0398
#define IVP_0_BASE_REG          0xE9180000
#define IVP_1_BASE_REG          0xE9780000
#define IVP_RUN_STATUS_OFFSET   0x000C
#define IVP_SEC_SEL_OFFSET      0x0300
#define IVP_0_POWER_MASK        (1 << 1)
#define IVP_1_POWER_MASK        (1 << 6)
#define IVP_RUN_STATUS_MASK     (1 << 0)
#define IVP_SEC_SEL_MASK        ((1 << 0) | (1 << 1))
#define IVP1_RAM_BASE_OFFSET    0x600000
#define IVP_CORE_0_ID           0
#define IVP_CORE_1_ID           1
#endif

struct file_header {
    char name[FILE_HEADER_NAME_LEN];
    char time[MAX_TIME_LENGTH];
    unsigned int image_size;
    unsigned int sect_count;
};

static int g_img_ddr_sect_index = -1; /* The initial value is set to an invalid value -1 */

enum {
    IMAGE_SECTION_TYPE_EXEC = 0,
    IMAGE_SECTION_TYPE_DATA,
    IMAGE_SECTION_TYPE_BSS,
};

unsigned int get_ivp_img_size(void)
{
    return SEC_IVP_BIN_SIZE;
}

unsigned int get_ivp_cma_size(void)
{
    return SEC_IVP_CMA_SIZE;
}

#ifdef IVP_DUAL_CORE
static unsigned int ivp_reg_read(unsigned int base_addr, unsigned int addr_offset)
{
    unsigned int val = *(volatile unsigned int *)(uintptr_t)(base_addr + addr_offset);
    return val;
}

static int query_sec_core_id(unsigned int *core_id)
{
    unsigned int ivp_pwonoff_status = ivp_reg_read(PMCTRL_BASE_REG, PMCTRL_IVP_POWER_OFFSET);

    if ((ivp_pwonoff_status & IVP_0_POWER_MASK) == 0) {
        if (((ivp_reg_read(IVP_0_BASE_REG, IVP_RUN_STATUS_OFFSET) & IVP_RUN_STATUS_MASK) != 0) &&
            ((ivp_reg_read(IVP_0_BASE_REG, IVP_SEC_SEL_OFFSET) & IVP_SEC_SEL_MASK) == 0)) {
            *core_id = IVP_CORE_0_ID;
            return SECBOOT_RET_SUCCESS;
        }
    }

    if ((ivp_pwonoff_status & IVP_1_POWER_MASK) == 0) {
        if (((ivp_reg_read(IVP_1_BASE_REG, IVP_RUN_STATUS_OFFSET) & IVP_RUN_STATUS_MASK) != 0) &&
            ((ivp_reg_read(IVP_1_BASE_REG, IVP_SEC_SEL_OFFSET) & IVP_SEC_SEL_MASK) == 0)) {
            *core_id = IVP_CORE_1_ID;
            return SECBOOT_RET_SUCCESS;
        }
    }
    tloge("%s, no core is ok\n", __func__);
    return SECBOOT_RET_PARAM_ERROR;
}
#endif

static int ivp_get_section_info(unsigned int fw_addr,
        unsigned int count, struct img_sec_info *msec_info)
{
    int offset = sizeof(struct file_header);
    errno_t ret = memcpy_s(msec_info, count * sizeof(struct img_sec_info),
            (void *)(uintptr_t)fw_addr + offset, count * sizeof(struct img_sec_info));
    if (ret != EOK) {
        tloge("%s,memcpy_s fail, ret %d\n", __func__, ret);
        return ret;
    }

    for (unsigned int index = 0; index < count; index++) {
        if (msec_info[index].vaddr == IVP_IMAGE_DDR_ADDRESS) {
            g_img_ddr_sect_index = index;
            break;
        }
    }

    return SECBOOT_RET_SUCCESS;
}

static int ivp_load_section(unsigned int fw_addr, const struct img_sec_info *image_sect,
        unsigned int ivp_ram_base_offset)
{
    unsigned int *source = (unsigned int *)(uintptr_t)(fw_addr + image_sect->offset);

    switch (image_sect->type) {
        case IMAGE_SECTION_TYPE_EXEC:
        case IMAGE_SECTION_TYPE_DATA: {
            if (image_sect->index < g_img_ddr_sect_index) {
                unsigned int *mem_addr = (unsigned int *)(uintptr_t)(image_sect->vaddr + ivp_ram_base_offset);
                for (unsigned int i = 0; i < image_sect->size / SIZE_OF_INT; i++) {
                    *(mem_addr + i) = *(source + i);
                }
            } else {
                unsigned int dst_addr = (fw_addr + (image_sect->vaddr - IVP_IMAGE_DDR_ADDRESS));
                errno_t ret = memmove_s((unsigned int *)(uintptr_t)dst_addr, image_sect->size,
                    source, image_sect->size);
                if (ret != EOK) {
                    tloge("%s,memmove_s fail, ret %d\n", __func__, ret);
                    return (int)ret;
                }
                __asm__ volatile ("isb");
                __asm__ volatile ("dsb sy");
                v7_dma_flush_range(dst_addr, dst_addr + image_sect->size);
            }
        }
        break;

        case IMAGE_SECTION_TYPE_BSS: {
        }
        break;

        default:
            tloge("Unsupported section type %u\n", image_sect->type);
            return SECBOOT_RET_PARAM_ERROR;
    }

    return SECBOOT_RET_SUCCESS;
}

int load_ivp_image(unsigned int fw_addr)
{
    struct file_header m_header;

    errno_t ret = memcpy_s(&m_header, sizeof(m_header), (void *)(uintptr_t)fw_addr, sizeof(m_header));
    if (ret != EOK) {
        tloge("memcpy_s failed, ret:%d\n", ret);
        return (int)ret;
    }
    tlogi("start loading, section counts:0x%x...\n", m_header.sect_count);

    if (m_header.sect_count == 0) {
        return SECBOOT_RET_FAILURE;
    }

    struct img_sec_info *sect_info = (struct img_sec_info *)malloc(m_header.sect_count * sizeof(struct img_sec_info));
    if (sect_info == NULL) {
        tloge("create sect_info buffer failed\n");
        return SECBOOT_RET_FAILURE;
    }

    g_img_ddr_sect_index = m_header.sect_count;
    if (ivp_get_section_info(fw_addr, m_header.sect_count, sect_info)) {
        tloge("get section failed\n");
        free(sect_info);
        return SECBOOT_RET_FAILURE;
    }

    unsigned int ivp_ram_base_offset = 0;
#ifdef IVP_DUAL_CORE
    unsigned int core_id;
    if (query_sec_core_id(&core_id) != SECBOOT_RET_SUCCESS) {
        free(sect_info);
        return SECBOOT_RET_FAILURE;
    }
    tlogi("current sec core is %u\n", core_id);
    if (core_id == IVP_CORE_1_ID) {
        ivp_ram_base_offset = IVP1_RAM_BASE_OFFSET;
    }
#endif
    for (unsigned int index = 0; index < m_header.sect_count; index++) {
        if (ivp_load_section(fw_addr, &sect_info[index], ivp_ram_base_offset)) {
            tloge("load section %u fails ...\n", index);
            free(sect_info);
            return SECBOOT_RET_PARAM_ERROR;
        }
    }

    free(sect_info);
    return SECBOOT_RET_SUCCESS;
}
