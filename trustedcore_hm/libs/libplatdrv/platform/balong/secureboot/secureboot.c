/*
 * Copyright (C), 2013~2020, Hisilicon Technologies Co., Ltd. All rights reserved.
 */
#include <bsp_modem_product_config.h>
#include <stdint.h>

#include <drv_cache_flush.h> // v7_dma_flush_range
#include <register_ops.h> // writel
#include <sre_syscalls_id_ext.h>
#include <sre_syscalls_id.h>
#include <sre_access_control.h>
#include <sre_typedef.h>
#include <timer_export.h>
#include <mem_mode.h>
#include <mem_ops.h>
#include <drv_module.h>
#include "include/hisi_secboot.h"
#include "hisi_seclock.h"
#include "secboot.h"
#include "crys_rnd.h"
#include "bsp_param_cfg.h"
#include "dx_pal_types_plat.h"
#include <securec.h>
#include "tee_log.h"
#include "zlib.h"
#include "hisi_efuse.h"
#include <hi_modem_secboot.h>
#include <hi_modem_set_para.h>

#ifndef UNUSED
#define UNUSED(param) (void)param;
#endif
#define HI_NR_SYSCTRL_BASE_ADDR (0xF8000000)
#define FIRST_PUBKEY_OFFSET  (0x90)
#define SECOND_PUBKEY_OFFSET (0x35c)
#define THIRD_PUBKEY_OFFSET  (0x628)
#define PUBKEY_SIZE (0x100)
unsigned int g_modem_image_size[MAX_SOC];
extern unsigned int SEB_IsSecure(void);
extern unsigned int g_modem_msg_rcv_flag;

uint32_t g_vrl_buffer[SECBOOT_VRL_SIZE / sizeof(uint32_t)] __attribute__((aligned(OS_CACHE_LINE_SIZE)));
unsigned long VRL_ADDR = (uintptr_t)&g_vrl_buffer[0];
uint32_t SECBOOT_DX_WORKSPACE_ADDR[SECBOOT_DX_WORKSPACE_SIZE / sizeof(uint32_t)] __attribute__((aligned(OS_CACHE_LINE_SIZE)));

uint32_t *hisi_secboot_get_vrl_buf(void)
{
    return g_vrl_buffer;
}

uint32_t *hisi_secboot_get_modem_image_size_st(void)
{
    return g_modem_image_size;
}
unsigned long long dx_convert_virt_to_phys(unsigned long long addr)
{
    return virt_mem_to_phys(addr);
}

#ifdef CONFIG_PARAM_CFG_OFFSET
struct SEC_BOOT_MODEM_INFO *modem_info_base_get(void)
{
    struct PARAM_CFG *cfg = NULL;
    cfg = bsp_cfg_base_addr_get();
    return &(cfg->sec_boot_modem_info);
}

uint32_t hisi_secboot_get_aslr_debug_val(unsigned int idx)
{
    struct SEC_BOOT_MODEM_INFO *modem_info = NULL;

    modem_info = modem_info_base_get();
    if (modem_info == NULL) {
        tloge("hisi_secboot_get_aslr_debug_val fail to get aslr val.\n");
        return 0;
    }
    return modem_info->sec_rnd_info.image_offset[idx];
}

void hisi_secboot_set_aslr_info(unsigned int idx, unsigned int image_offset,
                                unsigned int stack_guard, unsigned int heap_offset)
{
    struct SEC_BOOT_MODEM_INFO *modem_info = NULL;

    modem_info = modem_info_base_get();
    if (modem_info == NULL) {
        tloge("hisi_secboot_get_aslr_debug_val fail to get aslr val.\n");
        return ;
    }
    modem_info->sec_rnd_info.image_offset[idx] = image_offset;
    modem_info->sec_rnd_info.stack_guard[idx] = stack_guard;
    modem_info->sec_rnd_info.heap_offset[idx] = heap_offset;
    v7_dma_flush_range((uintptr_t)modem_info, (uintptr_t)modem_info + sizeof(struct SEC_BOOT_MODEM_INFO));
}
#else
unsigned int hisi_secboot_get_aslr_debug_val(unsigned int idx)
{
    UNUSED(idx);
    return 0;
}

void hisi_secboot_set_aslr_info(unsigned int idx, unsigned int image_offset,
                                unsigned int stack_guard, unsigned int heap_offset)
{
    UNUSED(idx);
    UNUSED(image_offset);
    UNUSED(stack_guard);
    UNUSED(heap_offset);
    return ;
}
#endif

int hisi_secboot_copy_soc_data(int soc_type_in, unsigned int offset, const void *src_addr, unsigned int len)
{
    uint32_t tmp_src_addr, tmp_dst_addr, size;
#ifdef CONFIG_PARAM_CFG_OFFSET
    struct SEC_BOOT_MODEM_INFO *modem_info = NULL;
    uint32_t cmd = 0;
#endif
    uint32_t status;
    uint32_t soc_type;

    soc_type = (unsigned int)soc_type_in;

    if (soc_type >= MAX_SOC) {
        tloge("soc type(%d) is not correct\n", soc_type);
        return SECBOOT_RET_INVALIED_SOC_TYPE;
    }

    status = g_modem_load.modem_status;
#ifdef CONFIG_PARAM_CFG_OFFSET
    modem_info = modem_info_base_get();
    cmd = modem_info->dynamic_load.load_cmd;
    modem_info->dynamic_load.verify_flag = modem_info->dynamic_load.verify_flag & (~(1 << soc_type));
#endif
    g_modem_load.verify_flag = g_modem_load.verify_flag & (~(1 << soc_type));

    switch (soc_type) {
        case MODEM:
        case DSP:
        case XDSP:
            if (status) {
                tloge("modem is running,load soc_type(%d) is not permitted!\n", soc_type);
                return SECBOOT_RET_MODEM_IS_UNRESET;
            } else {
            }
            break;
#if (TRUSTEDCORE_CHIP_CHOOSE != WITH_CHIP_HI9510)
        case NVM:
            if (status) {
                tloge("modem is running,load soc_type(%d) is not permitted!\n", soc_type);
                return SECBOOT_RET_MODEM_IS_UNRESET;
            } else {
            }
            break;
#endif
#if (TRUSTEDCORE_CHIP_CHOOSE != WITH_CHIP_HI9510)
        case NVM_S:
        case MBN_R:
        case MBN_A:
            if (!(cmd & (1 << soc_type))) {
                tloge("no commod,load soc_type(%d) is not permitted!cmd=0x%x.\n", soc_type, cmd);
                return SECBOOT_RET_MODEM_IS_UNRESET;
            }
            g_image_info[soc_type].image_size = modem_info->image_info[soc_type].image_size;
            break;
#endif
        default:
            tloge("invalid soc type:%d!\n", soc_type);
            return SECBOOT_RET_INVALIED_SOC_TYPE;
    }
    size = g_image_info[soc_type].image_size;
    if ((offset > size) || (len > size) || ((offset + len) > size)) {
        tloge("offset(0x%x) & len(0x%x) is not correct, size is 0x%x\n", offset, len, size);
        return SECBOOT_RET_INVALIED_OFFSET_OR_LEN;
    }
    if (map_from_ns_page(src_addr, len, &tmp_src_addr, non_secure)) {
        tloge("map data buffer addr=0x%lx error\n", (uintptr_t)src_addr);
        return SECBOOT_RET_SRC_MAP_FAILED;
    }
    tmp_dst_addr = g_image_info[soc_type].virt_addr + offset;

    if (g_image_info[soc_type].image_addr == IMAGE_ADDR_INVALID_VALUE)
        g_image_info[soc_type].image_addr = tmp_dst_addr;

    g_modem_image_size[soc_type] += len;

    memcpy_s((void *)(uintptr_t)tmp_dst_addr, g_image_info[soc_type].image_size, (void *)(uintptr_t)tmp_src_addr, len);
    v7_dma_flush_range(tmp_dst_addr, tmp_dst_addr + len);
    (void)unmap_from_ns_page(tmp_src_addr, len);
    return SECBOOT_RET_SUCCESS;
}

uint32_t secboot_copy_vrl_data(void *dst_addr, const void *src_addr, uint32_t len)
{
    memcpy_s(dst_addr, SECBOOT_VRL_SIZE, src_addr, len);
    v7_dma_flush_range((uintptr_t)dst_addr, (uintptr_t)(dst_addr + len));
    return SECBOOT_RET_SUCCESS;
}

int gzip_header_check(unsigned char *zbuf)
{
    if (zbuf[0] != 0x1f || zbuf[1] != 0x8b || zbuf[2] != 0x08) {
        return 0;
    } else {
        return 1;
    }
}

#ifdef CONFIG_MODEM_BALONG_ASLR
int generate_image_offset(uint32_t *value)
{
    if (CRYS_RND_GenerateVector(sizeof(uint32_t), (uint8_t *)value)) {
        tloge("error:generate iamge_offset failed!\n");
        return -1;
    } else {
        *value = (((*value) % (1024 * 1024 - 0x10000)) & (~0x3F)) + 0x10000;
    }
    return 0;
}

int generate_stack_guard(uint32_t *value)
{
    if (CRYS_RND_GenerateVector(sizeof(uint32_t), (uint8_t *)value)) {
        tloge("error:generate stack_guard failed!\n");
        return -1;
    }

    return 0;
}

int generate_heap_offset(uint32_t *value)
{
    if (CRYS_RND_GenerateVector(sizeof(uint32_t), (uint8_t *)value)) {
        tloge("error:generate stack_guard failed!\n");
        return -1;
    } else {
        *value = (((*value) % 0x1000) & (~0xF));
    }

    return 0;
}

extern u32 g_modem_aslr_flag;
int uncompress_with_aslr(int soc_type, uint32_t virt_img_addr, unsigned long *dst_len, unsigned char *zlib_next_in,
                         unsigned zlib_avail_in)
{
    unsigned image_offset = 0;
    unsigned stack_guard = 0;
    unsigned heap_offset = 0;
    int result;

    if (soc_type == MODEM) {
        /* generate rand for 4G */
        if (g_modem_aslr_flag == 1) {
            if (generate_image_offset(&image_offset)) {
                return SECBOOT_RET_ASLR_RND_FAIL;
            }
        } else if (g_modem_aslr_flag == 2) {
            image_offset = hisi_secboot_get_aslr_debug_val(MODEM_ASLR_4G_IDX);
        } else {
            image_offset = 0;
        }
        if (generate_stack_guard(&stack_guard)) {
            return SECBOOT_RET_ASLR_RND_FAIL;
        }
        if (generate_heap_offset(&heap_offset)) {
            return SECBOOT_RET_ASLR_RND_FAIL;
        }

        result = uncompress((unsigned char *)(uintptr_t)virt_img_addr + image_offset, dst_len, zlib_next_in,
                            zlib_avail_in);
        memmove_s((void *)(uintptr_t)(virt_img_addr), MODEM_REL_COPY_CODE_SIZE,
                  (void *)(uintptr_t)(virt_img_addr + image_offset), MODEM_REL_COPY_CODE_SIZE);
        writel(image_offset, virt_img_addr + MODEM_IMAGE_OFFSET_FOR_4G);
        writel(stack_guard, virt_img_addr + MODEM_STACK_GUARD_OFFSET_FOR_4G);
        writel(heap_offset, virt_img_addr + MODEM_MEM_PT_OFFSET_FOR_4G);

        hisi_secboot_set_aslr_info(MODEM_ASLR_4G_IDX, image_offset, stack_guard, heap_offset);

        image_offset = 0;
        stack_guard = 0;
        heap_offset = 0;

        /* generate rand for 5G */
        if (g_modem_aslr_flag == 1) {
            if (generate_image_offset(&image_offset)) {
                return SECBOOT_RET_ASLR_RND_FAIL;
            }
        } else if (g_modem_aslr_flag == 2) {
            image_offset = hisi_secboot_get_aslr_debug_val(MODEM_ASLR_5G_IDX);
        } else {
            image_offset = 0;
        }
        if (generate_stack_guard(&stack_guard)) {
            return SECBOOT_RET_ASLR_RND_FAIL;
        }
        if (generate_heap_offset(&heap_offset)) {
            return SECBOOT_RET_ASLR_RND_FAIL;
        }

        hisi_secboot_set_aslr_info(MODEM_ASLR_5G_IDX, image_offset, stack_guard, heap_offset);
    } else {
        result = uncompress((unsigned char *)(uintptr_t)virt_img_addr, dst_len, zlib_next_in, zlib_avail_in);
    }
    return result;
}
#endif

#ifdef CONFIG_CHECK_PUBKEY
uint32_t hisi_cert_check(unsigned long long vrl_addr)
{
    if (memcmp((void *)(uintptr_t)(vrl_addr + FIRST_PUBKEY_OFFSET), (void *)(uintptr_t)(vrl_addr + SECOND_PUBKEY_OFFSET), PUBKEY_SIZE) != 0) {
        return SECBOOT_RET_CERT_CHECK_FAIL;
    }

    if (memcmp((void *)(uintptr_t)(vrl_addr + FIRST_PUBKEY_OFFSET), (void *)(uintptr_t)(vrl_addr + THIRD_PUBKEY_OFFSET), PUBKEY_SIZE) != 0) {
        return SECBOOT_RET_CERT_CHECK_FAIL;
    }

    return SECBOOT_RET_SUCCESS;
}
#else
uint32_t hisi_cert_check(unsigned long long vrl_addr)
{
    UNUSED(vrl_addr);
    return SECBOOT_RET_SUCCESS;
}
#endif

uint32_t hisi_secboot_verify(unsigned long long vrl_addr_long, unsigned long long image_addr_long, unsigned image_size)
{
    unsigned error = 0;
    SB_CertPkg_DataStruct SB_CertPkg;
    unsigned content_size = 0;

#ifndef CONFIG_MODEM_CHECK_IMAGE_SIZE
    UNUSED(content_size);
    UNUSED(image_size);
#endif

    error = hisi_cert_check(vrl_addr_long);
    if (error) {
        tloge("cert check error!!!\n");
        return error;
    }

    error = SEB_FillCertPkg(vrl_addr_long, &SB_CertPkg);
    if (error) {
        tloge("SEB_FillCertPkg error.\n");
        return error;
    }
#ifdef CONFIG_MODEM_CHECK_IMAGE_SIZE
    error = SEB_VRLChangeSwCompStoreAddr((unsigned *)(uintptr_t)(unsigned long)SB_CertPkg.ConCert_FlashAddr, image_addr_long, 0, &content_size);
#else
    error = SEB_VRLChangeSwCompStoreAddr((unsigned *)(uintptr_t)(unsigned long)SB_CertPkg.ConCert_FlashAddr, image_addr_long, 0);
#endif
    if (error) {
        tloge("SEB_BaseVRLChangeSwCompStoreAddr error = 0x%x.\n", error);
        return error;
    }

#ifdef CONFIG_MODEM_CHECK_IMAGE_SIZE
    tloge("hisi_secboot_verify check image size in.\n");
    if ((SEB_IsSecure()) && (image_size != content_size)) {
        tloge("SEB_XloaderVerification image_size(0x%x) != content_size(0x%x).\n", image_size, content_size);
        error = SECBOOT_IMAGE_LEN_NOT_MATCH;
        return error;
    }
#endif

    error = SEB_XloaderVerification(&SB_CertPkg, SECBOOT_DX_WORKSPACE_ADDR, (unsigned)SECBOOT_DX_WORKSPACE_SIZE);
    if (error) {
        tloge("SEB_XloaderVerification error = 0x%x.\n", error);
        return error;
    }
    return 0;
}
int hisi_secboot_verify_comm_and_send(int soc_type, uint32_t core_id)
{
    int rc;
    unsigned int verify_flag;

#ifdef CONFIG_MLOADER_NO_SHARE_MEM
    struct hisi_secboot_msg_s *modem_secboot_msg = hisi_secboot_get_msg_st();
    unsigned int image_id = modem_secboot_msg->verify_info.image_id;
    int count = 1000; // max delay is 1s
    while (g_modem_msg_rcv_flag == 0 && count > 0) {
        __SRE_SwMsleep(1);
        count--;
    }
    if (count == 0) {
        tloge("hisi_secboot_soc_verification get verify info fail, soc_type = 0x%x.\n", soc_type);
        return SECBOOT_RET_FAIL_TO_GET_VERIFY_INFO;
    }
    g_modem_msg_rcv_flag = 0;
#else
    struct verify_param_info *verify_info = hisi_secboot_get_verify_info(core_id);
    unsigned int image_id = verify_info->image_id;
#endif
    rc = hisi_secboot_verify_comm_imgs(soc_type, core_id);
    if (rc != 0) {
        verify_flag = 0;
        tloge("hisi_secboot_soc_verification verify image_id 0x%x fail, rc = 0x%x.\n", image_id, rc);
    } else {
        verify_flag = 1;
        tloge("hisi_secboot_soc_verification verify image_id 0x%x success.\n", image_id);
    }
#ifdef CONFIG_MLOADER_NO_SHARE_MEM
    modem_secboot_msg->verify_result.verify_flag = verify_flag;
    modem_secboot_msg->verify_result.image_id = modem_secboot_msg->verify_info.image_id;
    modem_secboot_msg->verify_result.ret = rc;
    modem_secboot_msg->verify_result.cmd_type = modem_secboot_msg->verify_info.cmd_type;

    rc = hisi_secboot_send_msg_to_cp(&(modem_secboot_msg->verify_result));
    if (rc != 0) {
        tloge("hisi_secboot_soc_verification send msg to cp fail, ret = 0x%x.\n", rc);
    }
#else
    writel(verify_flag, (uint32_t)(uintptr_t)&(verify_info->verify_flag));
#endif
    return rc;
}

static int hisi_secboot_uncompress_image(uint32_t soc_type)
{
    int rc = 0;
    char *zlib_next_in = NULL;
    uint32_t zlib_avail_in = 0;
    uint32_t dst_len;

    if (gzip_header_check((unsigned char *)(uintptr_t)g_image_info[soc_type].image_addr)) {
        /*
         * skip over gzip header (1f,8b,08... 10 bytes total +
         * possible asciz filename)
         */
        zlib_next_in = (char *)(uintptr_t)(g_image_info[soc_type].image_addr);
        zlib_avail_in = (unsigned)(g_image_info[soc_type].virt_addr + g_image_info[soc_type].image_size -
                                   g_image_info[soc_type].image_addr);
        tloge("start decompress.\n");

        dst_len = g_image_info[soc_type].image_size;
#ifdef CONFIG_MODEM_BALONG_ASLR
        rc = uncompress_with_aslr(soc_type, g_image_info[soc_type].virt_addr, (unsigned long *)&dst_len,
                                  (unsigned char *)zlib_next_in, zlib_avail_in);
#else
#endif
        tloge("decompress finished.\n");
        if (rc != 0) {
            tloge("inflate fail. ret = %d\n", rc);
        } else {
            tloge("inflate done. file length = 0x%x\n", dst_len);
        }
    }
    return rc;
}

uint32_t hisi_secboot_soc_verification(int soc_type_in, uint32_t vrl_addr, uint32_t image_addr,
                                     SECBOOT_LOCKSTATE lock_state)
{
    uint32_t error = 0;
    uint32_t soc_type;
#ifdef CONFIG_PARAM_CFG_OFFSET
    struct SEC_BOOT_MODEM_INFO *modem_info = NULL;
#endif
    unsigned long long vrl_addr_long;
    unsigned long long image_addr_long;
    UNUSED(lock_state);

    soc_type = (uint32_t)soc_type_in;
#ifdef CONFIG_PARAM_CFG_OFFSET
    modem_info = modem_info_base_get();
    modem_info->dynamic_load.load_cmd = modem_info->dynamic_load.load_cmd & (~(1 << soc_type));
#endif

#if (TRUSTEDCORE_CHIP_CHOOSE != WITH_CHIP_HI9510)
    /* 这些镜像依赖C核自己的校验，不能放到最前面，虽然不在此校验，但是需要将load cmd清除 */
    if ((soc_type == NVM) || (soc_type == NVM_S) || (soc_type == MBN_R)) {
        return error;
    }
#endif
    if (soc_type == MODEM_COMM_IMG) {
        return hisi_secboot_verify_comm_and_send(soc_type, image_addr);
    } else {
        image_addr_long = g_image_info[soc_type].image_addr;
    }

    secboot_copy_vrl_data((void *)g_vrl_buffer, (void *)(uintptr_t)vrl_addr, SECBOOT_VRL_SIZE);

    vrl_addr_long = (uintptr_t)&g_vrl_buffer[0];

    error = hisi_secboot_verify(vrl_addr_long, image_addr_long, g_modem_image_size[soc_type]);
    if (error) {
        g_modem_image_size[soc_type] = 0;
        return error;
    }
    g_modem_image_size[soc_type] = 0;
    g_modem_load.verify_flag = g_modem_load.verify_flag | (1 << soc_type);
#ifdef CONFIG_PARAM_CFG_OFFSET
    modem_info->dynamic_load.verify_flag = modem_info->dynamic_load.verify_flag | (1 << soc_type);
    v7_dma_flush_range((unsigned long)(uintptr_t)modem_info, (unsigned long)((uintptr_t)modem_info + sizeof(struct SEC_BOOT_MODEM_INFO)));
#endif
    tloge("SEB_XloaderVerification ok.\n");

    error = (uint32_t)hisi_secboot_uncompress_image(soc_type);

    if (error == 0) {
        error = hisi_secboot_set_mem_layout_info(soc_type, g_image_info[soc_type].virt_addr);
    }

    /* using dma cache flush in MP platform instead of flush cache all */
    v7_dma_flush_range(g_image_info[soc_type].virt_addr, g_image_info[soc_type].virt_addr + g_image_info[soc_type].image_size);

    return error;
}

void clear_image_load_addr(void)
{
    g_image_info[MODEM].image_addr = IMAGE_ADDR_INVALID_VALUE;
}

int hisi_secboot_soc_reset(int soc_type)
{
    int ret = SECBOOT_RET_SUCCESS;
    if (soc_type == MODEM) {
        modem_ccore_reset();
        clear_image_load_addr();
    }
    return ret;
}

int hisi_secboot_soc_set(int soc_type_in)
{
    int ret = SECBOOT_RET_SUCCESS;
    uint32_t soc_type;
#ifdef CONFIG_PARAM_CFG_OFFSET
    struct SEC_BOOT_MODEM_INFO *modem_info = NULL;

    modem_info = modem_info_base_get();
#endif
    soc_type = (uint32_t)soc_type_in;

    if (soc_type == MODEM) {
        tloge("hisi_secboot_soc_set modem!\n");
        if (g_image_info[soc_type].unreset_dependcore ==
            (g_image_info[soc_type].unreset_dependcore & g_modem_load.verify_flag)) {
            modem_ccore_unreset();
            /* 成功解复位后清除校验标志，并置modem_status 为1 解复位状态 */
            g_modem_load.verify_flag = g_modem_load.verify_flag &
                                       ((~g_image_info[soc_type].unreset_dependcore) & 0xffffffff);
            g_modem_load.modem_status = 1;
            /* 清除动态加载标志和加载命令，防止modem单独复位时，遗留标志的影响 */
#ifdef CONFIG_PARAM_CFG_OFFSET
            modem_info->dynamic_load.verify_flag = 0;
            modem_info->dynamic_load.load_cmd = 0;
#endif
        } else {
            tloge("modem unreset fail, verify_flag(0x%x), dependcore(0x%x)\n", g_modem_load.verify_flag,
                        g_image_info[soc_type].unreset_dependcore);
        }

    }
    return ret;
}

uint32_t hisi_secboot_process_soc_addr(uint32_t soc_type, const paddr_t soc_addr, uint32_t process_type)
{
    UNUSED(soc_type);
    UNUSED(process_type);
    return 0;
}

#include <hmdrv_stub.h>      // majiuyue: hack for `HANDLE_SYSCALL`
#define DIE_ID_SIZE (5 * 4)  // define in efuse/hisi_efuse.h

int secureboot_syscall(int swi_id, struct drv_param *params, uint64_t permissions)
{
    uint32_t ret = 0;

    if (!params || !params->args)
        return -1;

    uint64_t *args = (uint64_t *)(uintptr_t)params->args;

    HANDLE_SYSCALL(swi_id)
    {
        SYSCALL_PERMISSION(SW_SYSCALL_TEE_HAL_GET_DIEID, permissions, GENERAL_GROUP_PERMISSION)
        ret = (uint32_t)SecBoot_get_secinfo_dieid((unsigned int *)(uintptr_t)args[0]);
        args[0] = ret;
        SYSCALL_END

        SYSCALL_PERMISSION(SW_COPY_SOC_DATA_TYPE, permissions, SECBOOT_GROUP_PERMISSION)
#ifndef ARM_PAE
        ret = hisi_secboot_copy_soc_data(args[0], args[1], (void *)(uintptr_t)(args[2] & 0xFFFFFFFF),
                (uint32_t)((args[2] >> 32) & 0xFFFFFFFF));
#else
        ret = hisi_secboot_copy_soc_data(args[0], args[1], (void *)(uintptr_t)args[2], args[3]);
#endif
        args[0] = ret;
        SYSCALL_END

        SYSCALL_PERMISSION(SW_VERIFY_SOC_DATA_TYPE, permissions, SECBOOT_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[1], SECBOOT_VRL_SIZE);
        ACCESS_READ_RIGHT_CHECK(args[1], SECBOOT_VRL_SIZE);
#ifndef ARM_PAE
        ret = hisi_secboot_soc_verification((int)args[0], (unsigned int)args[1],
                (unsigned int)(args[2] & 0xFFFFFFFF), (int)((args[2] >> BITS32) & 0xFFFFFFFF));
#else
        ret = hisi_secboot_soc_verification(args[0], (unsigned int)args[1], args[2], args[3]);
#endif
        args[0] = ret;
        SYSCALL_END

        SYSCALL_PERMISSION(SW_PROCESS_SOC_ADDR, permissions, SECBOOT_GROUP_PERMISSION)
#ifndef ARM_PAE
        ret = hisi_secboot_process_soc_addr(args[0], (uint32_t)(args[1] & 0xFFFFFFFF),
                (uint32_t)((args[1] >> BITS32) & 0xFFFFFFFF));
#else
        ret = hisi_secboot_process_soc_addr(args[0], args[1], args[2]);
#endif
        args[0] = ret;
        SYSCALL_END

        SYSCALL_PERMISSION(SW_SOC_IMAGE_RESET, permissions, SECBOOT_GROUP_PERMISSION)
        ret = hisi_secboot_soc_reset(args[0]);
        args[0] = ret;
        SYSCALL_END

        SYSCALL_PERMISSION(SW_SOC_IMAGE_SET, permissions, SECBOOT_GROUP_PERMISSION)
        ret = hisi_secboot_soc_set(args[0]);
        args[0] = ret;
        SYSCALL_END

        default:
            return -1;
    }
    return 0;
}

DECLARE_TC_DRV(secboot_driver, 0, 0, 0, TC_DRV_MODULE_INIT, NULL, NULL, secureboot_syscall, NULL, NULL);
