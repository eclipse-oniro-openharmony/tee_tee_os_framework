/*
* Copyright (c) Huawei Technologies Co., Ltd. 2012-2020. All rights reserved.
*/
/*lint -e715 -e838 */
#include <stdint.h>
#include <drv_mem.h>
#include <mem_ops.h>
#include <drv_module.h>
#include <register_ops.h>
#include "include/hisi_secboot.h"
#include "hisi_seclock.h"
#include "secboot.h"
#include <drv_cache_flush.h>
#include "bsp_param_cfg.h"
#include <securec.h>
#include "tee_log.h"


struct verify_param_info *hisi_secboot_get_verify_info(uint32_t core_id)
{
#ifdef CONFIG_MLOADER_NO_SHARE_MEM
    struct hisi_secboot_msg_s *msg_info = hisi_secboot_get_msg_st();
    return &(msg_info->verify_info);
#else
    struct SEC_BOOT_MODEM_INFO *modem_info = NULL;
    modem_info = modem_info_base_get();
    return &(modem_info->verify_param.verify_param_info[core_id]);
#endif
}

uint32_t hisi_secboot_verify_comm_imgs(int soc_type, uint32_t core_id)
{
    struct verify_param_info *verify_info = NULL;
    unsigned long long vrl_addr_long;
    unsigned long long image_addr_long;
    unsigned long virt_vrl_addr;
    unsigned long virt_image_addr;
    uint32_t *vrl_buf = NULL;
    uint32_t error = 0;
    uint32_t image_id;
    uint32_t *modem_image_size = NULL;
    uint32_t soc_type_in;

    modem_image_size = hisi_secboot_get_modem_image_size_st();
    if (modem_image_size == NULL) {
        uart_printf_func("hisi_secboot_verify_comm_imgs get modem_image_size failed!\n");
        return SECBOOT_RET_INVALIED_ST_ADDR;
    }

    vrl_buf = hisi_secboot_get_vrl_buf();
    verify_info = hisi_secboot_get_verify_info(core_id);
    data_sync();
    image_id = readl((uint32_t)(uintptr_t)&(verify_info->image_id));

    tloge("secboot_verify_comm_imgs in, soc_type = %d, image_id = %d.\n", soc_type, image_id);

    if (map_from_ns_page((verify_info->image_addr),
                         verify_info->image_size, &virt_image_addr, secure)) {
        tloge("map data buffer addr=0x%x error\n",
                    verify_info->image_addr);
        return SECBOOT_RET_SRC_MAP_FAILED;
    }
    v7_dma_inv_range(virt_image_addr, virt_image_addr + verify_info->image_size);
    image_addr_long = virt_image_addr;

    modem_image_size[soc_type] = verify_info->image_size;

    g_image_info[soc_type].image_addr = virt_image_addr;

    if (map_from_ns_page((uint32_t)(verify_info->vrl_addr), SECBOOT_VRL_SIZE,
                         &virt_vrl_addr, secure)) {
        tloge("map vrl buffer addr=0x%x error\n", verify_info->vrl_addr);
        (void)unmap_from_ns_page(virt_image_addr, verify_info->image_size);
        return SECBOOT_RET_SRC_MAP_FAILED;
    }
    v7_dma_inv_range(virt_vrl_addr, virt_vrl_addr + SECBOOT_VRL_SIZE);

    secboot_copy_vrl_data((void *)vrl_buf, (void *)(uintptr_t)virt_vrl_addr, SECBOOT_VRL_SIZE);

    vrl_addr_long = (unsigned long)(uintptr_t)&vrl_buf[0];

    error = hisi_secboot_verify(vrl_addr_long, image_addr_long, modem_image_size[soc_type]);
    if (error) {
        goto error_out;
    }

    soc_type_in = soc_type;
    g_modem_load.verify_flag = g_modem_load.verify_flag | (1 << soc_type_in);
    tloge("SEB_XloaderVerification ok, soc_type = %d.\n", soc_type);

error_out:
    (void)unmap_from_ns_page(virt_vrl_addr, SECBOOT_VRL_SIZE);
    (void)unmap_from_ns_page(virt_image_addr, verify_info->image_size);
    return error;
}

