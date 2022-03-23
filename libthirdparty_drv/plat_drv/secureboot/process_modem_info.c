/*
 * hisilicon MODEM process, process_modem_info.c
 * Copyright (c) 2013 Hisilicon Technologies CO., Ltd.
 */
#include <sre_typedef.h>
#include <sre_debug.h> // uart_printf
#include <drv_mem.h> // sre_mmap
#include <drv_cache_flush.h> // v7_dma_flush_range && v7_dma_inv_range
#include <register_ops.h> /* writel */
#include "tee_log.h"
#include <mem_page_ops.h>
#include "bsp_secboot_adp.h"
#include "secboot.h"
#include <securec.h>
#include <hisi_seclock.h>
#include "crys_rnd.h"
#include "process_modem_info.h"
#include <platform.h>
#include "plat_cfg.h"
#include "soc_acpu_baseaddr_interface.h"

extern int uncompress(unsigned char *gunzip_buf, unsigned long *sz, const unsigned char *buf, unsigned long len);

#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3650)
#define HI_CRG_SRSTDIS1_OFFSET (0x64) /* 软复位请求关闭1 */
#endif

#define WDT_UNLOCK (0x1ACCE551)
#define WDT_LOCK (0x0)
#define WDT_RST_INT_EN (0x1)
#define WDT_DEF_CLK_FREQ (32768) /* 32khz */

/********************************************************************************/
/*    wdt 寄存器偏移定义（项目名_模块名_寄存器名_OFFSET)        */
/********************************************************************************/
#define HI_WDG_LOAD_OFFSET (0x0)    /* 计数初值寄存器，配置WatchDog内部计数器的计数初值。 */
#define HI_WDG_CONTROL_OFFSET (0x8) /* 控制寄存器，控制WatchDog的打开/关闭、中断和复位功能。 */
#define HI_WDG_INTCLR_OFFSET \
    (0xC) /* 中断清除寄存器。清除WatchDog中断，使WatchDog重新载入初值进行计数。本寄存器是只写寄存器，写进去任意值，都会引起WatchDog清中断，内部并不记忆写入的值，无复位值。 */
#define HI_WDG_LOCK_OFFSET (0xC00) /* LOCK寄存器，控制WatchDog寄存器的读写权限。 */
#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3650)
#define HI_WDG_SYSCTRL_ENABLE_OFFSET (0x33C) /* 读取系统控制寄存器33c bit[1] ,1打开看门狗，0关闭看门狗 */
#else
#define HI_WDG_SYSCTRL_ENABLE_OFFSET (0x434)
#endif
#define HI_WDG_SYSCTRL_ENABLE_MASK (0x2) /* 读取系统控制寄存器33c bit[1] ,1打开看门狗，0关闭看门狗 */

int gzip_header_check(unsigned char *zbuf)
{
    if (zbuf[0] != 0x1f || zbuf[1] != 0x8b || zbuf[2] != 0x08) {
        return 0;
    } else {
        return 1;
    }
}

#if defined(CONFIG_MODEM_ASLR) || defined(CONFIG_MODEM_BALONG_ASLR)
int generate_image_offset(UINT32 *value)
{
    if (CRYS_RND_GenerateVector(sizeof(UINT32), (UINT8 *)value)) {
        tloge("error:generate iamge_offset failed!\n");
        return -1;
    } else {
        *value = (((*value) % (1024 * 1024 - 0x10000)) & (~0x3F)) + 0x10000;
    }
    return 0;
}

int generate_stack_guard(UINT32 *value)
{
    if (CRYS_RND_GenerateVector(sizeof(UINT32), (UINT8 *)value)) {
        tloge("error:generate stack_guard failed!\n");
        return -1;
    }

    return 0;
}

int generate_heap_offset(UINT32 *value)
{
    if (CRYS_RND_GenerateVector(sizeof(UINT32), (UINT8 *)value)) {
        tloge("error:generate stack_guard failed!\n");
        return -1;
    } else {
        *value = (((*value) % 0x1000) & (~0xF));
    }

    return 0;
}

extern u32 g_modem_aslr_flag;
struct aslr_sec_param g_aslr_sec_param = {0};
struct aslr_sec_param *hisi_secboot_get_aslr_sec_param_st(void)
{
    return &g_aslr_sec_param;
}

int aslr_zlib_inflate_image(UINT32 SoC_Type, UINT32 Inflate_Image_Offset, UINT32 virt_img_addr, unsigned long *dst_len,
                            unsigned char *zlib_next_in, unsigned zlib_avail_in)
{
    unsigned image_offset = 0;
    unsigned stack_guard = 0;
    unsigned heap_offset = 0;
    int result;
/* for platform which have 5G only */
#ifdef CONFIG_MODEM_ASLR_5G_CORE
    struct SEC_BOOT_MODEM_INFO *modem_info = NULL;

    modem_info = modem_info_base_get();
    if (NULL == modem_info) {
        tloge("%s, modem info is null!\n", __func__);
        return SECBOOT_RET_INVALIED_MODEM_INFO_BASE;
    }
#endif

    if (SoC_Type == MODEM) {
        if (g_modem_aslr_flag) {
            if (generate_image_offset(&image_offset)) {
                return SECBOOT_RET_ASLR_RND_FAIL;
            }
        } else {
            image_offset = 0;
        }
        if (generate_stack_guard(&stack_guard)) {
            return SECBOOT_RET_ASLR_RND_FAIL;
        }
        if (generate_heap_offset(&heap_offset)) {
            return SECBOOT_RET_ASLR_RND_FAIL;
        }
#if (defined CONFIG_COLD_PATCH) || (defined CONFIG_MODEM_COLD_PATCH)
        if (g_modem_load.verify_flag & (0x1u << MODEM_COLD_PATCH)) {
            g_aslr_sec_param.image_offset = image_offset;
            g_aslr_sec_param.stack_guard = stack_guard;
            g_aslr_sec_param.heap_offset = heap_offset;
            result = uncompress((unsigned char *)(uintptr_t)(virt_img_addr + Inflate_Image_Offset), dst_len,
                                zlib_next_in, zlib_avail_in);
        } else {
            result = uncompress((unsigned char *)(uintptr_t)(virt_img_addr + Inflate_Image_Offset + image_offset),
                                dst_len, zlib_next_in, zlib_avail_in);
            memmove_s((void *)(uintptr_t)(virt_img_addr + Inflate_Image_Offset), MODEM_REL_COPY_CODE_SIZE,
                      (void *)(uintptr_t)(virt_img_addr + Inflate_Image_Offset + image_offset),
                      MODEM_REL_COPY_CODE_SIZE);

            writel(image_offset, virt_img_addr + MODEM_IMAGE_OFFSET);
            writel(stack_guard, virt_img_addr + MODEM_STACK_GUARD_OFFSET);
            writel(heap_offset, virt_img_addr + MODEM_MEM_PT_OFFSET);
        }
#else
        result = uncompress((unsigned char *)(uintptr_t)(virt_img_addr + Inflate_Image_Offset + image_offset), dst_len,
                            zlib_next_in, zlib_avail_in);
        memmove_s((void *)(virt_img_addr + Inflate_Image_Offset), MODEM_REL_COPY_CODE_SIZE,
                  (void *)(virt_img_addr + Inflate_Image_Offset + image_offset), MODEM_REL_COPY_CODE_SIZE);

        writel(image_offset, virt_img_addr + MODEM_IMAGE_OFFSET);
        writel(stack_guard, virt_img_addr + MODEM_STACK_GUARD_OFFSET);
        writel(heap_offset, virt_img_addr + MODEM_MEM_PT_OFFSET);
#endif
/* for platform which have 5G only */
#ifdef CONFIG_MODEM_ASLR_5G_CORE
        modem_info->sec_rnd_info.image_offset[0] = image_offset;
        modem_info->sec_rnd_info.stack_guard[0] = stack_guard;
        modem_info->sec_rnd_info.heap_offset[0] = heap_offset;

        image_offset = 0;
        stack_guard = 0;
        heap_offset = 0;

        if (g_modem_aslr_flag) {
            if (generate_image_offset(&image_offset)) {
                return SECBOOT_RET_ASLR_RND_FAIL;
            }
        } else {
            image_offset = 0;
        }
        if (generate_stack_guard(&stack_guard)) {
            return SECBOOT_RET_ASLR_RND_FAIL;
        }
        if (generate_heap_offset(&heap_offset)) {
            return SECBOOT_RET_ASLR_RND_FAIL;
        }

        modem_info->sec_rnd_info.image_offset[1] = image_offset;
        modem_info->sec_rnd_info.stack_guard[1] = stack_guard;
        modem_info->sec_rnd_info.heap_offset[1] = heap_offset;
#endif

    } else {
        result = uncompress((unsigned char *)(uintptr_t)(virt_img_addr + Inflate_Image_Offset), dst_len, zlib_next_in,
                            zlib_avail_in);
    }

    return result;
}
#endif

UINT32 secboot_is_dynamic_load(UINT32 soc_type)
{
    switch (soc_type) {
        case TAS:
        case WAS:
#ifdef CONFIG_HISI_NVIM_SEC
        case NVM_S:
        case MBN_R:
        case MBN_A:
#endif
            return DYNAMIC_LOAD_IMG;
        default:
            return NON_DYNAMIC_LOAD_IMG;
    }
}

UINT32 secboot_config_dynamic_load_addr(UINT32 soc_type)
{
    struct SEC_BOOT_MODEM_INFO *modem_info = NULL;
    UINT32 modem_is_ursted = 0;
    UINT32 cmd = 0;

    if (DYNAMIC_LOAD_IMG == secboot_is_dynamic_load(soc_type)) {
        modem_info = modem_info_base_get();
        if (NULL == modem_info) {
            tloge("%s, modem info is null!\n", __func__);
            return SECBOOT_RET_INVALIED_MODEM_INFO_BASE;
        }
        cmd = modem_info->dynamic_load.load_cmd;
        modem_info->dynamic_load.verify_flag = modem_info->dynamic_load.verify_flag & (~(0x1u << soc_type));
    }
    modem_is_ursted = g_modem_load.modem_is_ursted;
    g_modem_load.verify_flag = g_modem_load.verify_flag & (~(0x1u << soc_type));

    switch (soc_type) {
        case MODEM:
        case DSP:
        case XDSP:
        case MODEM_DTB:
#if (defined CONFIG_COLD_PATCH) || (defined CONFIG_MODEM_COLD_PATCH)
        case MODEM_COLD_PATCH:
        case DSP_COLD_PATCH:
#endif
#ifdef CONFIG_HISI_NVIM_SEC
        case NVM:
#endif
#ifdef CONFIG_RFIC_LOAD
        case RFIC:
#endif
            if (modem_is_ursted) {
                tloge("%s, modem is running,load soc_type(%d) is not permitted!\n", __func__, soc_type);
                return SECBOOT_RET_MODEM_IS_UNRESET;
            }
            break;
        case HIFI:
            // TODO,add soc set code for hifi
            break;
        case TAS:
        case WAS:
#ifdef CONFIG_HISI_NVIM_SEC
        case NVM_S:
        case MBN_R:
        case MBN_A:
#endif
            if (!(cmd & (0x1u << soc_type))) {
                tloge("%s, no commod,load soc_type(%d) is not permitted!\n", __func__, soc_type);
                return SECBOOT_RET_INVALIED_SOC_TYPE;
            }
            if (DYNAMIC_LOAD_IMG == secboot_is_dynamic_load(soc_type)) {
                if (NULL != modem_info) {
                    g_image_info[soc_type].ddr_phy_addr = modem_info->image_info[soc_type].ddr_addr;
                    g_image_info[soc_type].ddr_size = modem_info->image_info[soc_type].ddr_size;
                }
            }
            break;

        default:
            return SECBOOT_RET_SUCCESS;
    }
    return SECBOOT_RET_SUCCESS;
}

UINT32 secboot_clean_dynamic_load_flag(UINT32 soc_type)
{
    struct SEC_BOOT_MODEM_INFO *modem_info = NULL;

    /* clean img dynamic load flag */
    if (DYNAMIC_LOAD_IMG == secboot_is_dynamic_load(soc_type)) {
        modem_info = modem_info_base_get();
        if (NULL == modem_info) {
            tloge("%s, modem info base get failed.\n", __func__);
            return SECBOOT_RET_INVALIED_MODEM_INFO_BASE;
        }
        modem_info->dynamic_load.load_cmd = modem_info->dynamic_load.load_cmd & (~(0x1u << soc_type));
    }
    return SECBOOT_RET_SUCCESS;
}

void secboot_config_modem_verify_flag(UINT32 soc_type, UINT32 need_verify)
{
    struct SEC_BOOT_MODEM_INFO *modem_info = NULL;

    /* config img verity flag except modem_dtb */
    if (NEED_VERIFY_FLAG == need_verify) {
        g_modem_load.verify_flag = g_modem_load.verify_flag | (0x1u << soc_type);
        tlogi("%s, verify flag=0x%x.\n", __func__, g_modem_load.verify_flag);
    }

    if (DYNAMIC_LOAD_IMG == secboot_is_dynamic_load(soc_type)) {
        modem_info = modem_info_base_get();
        if (NULL != modem_info) {
            modem_info->dynamic_load.verify_flag = modem_info->dynamic_load.verify_flag | (0x1u << soc_type);
            tloge("%s, dynamic load verify flag=0x%x.\n", __func__, modem_info->dynamic_load.verify_flag);
        }
    }
    return;
}

UINT32 zlib_inflate_image(UINT32 SoC_Type, UINT32 Inflate_Image_Offset)
{
    UINT32 ret = SECBOOT_RET_SUCCESS;
    int result;
    unsigned char *zlib_next_in = NULL;
    unsigned zlib_avail_in = 0;
    UINT32 virt_img_addr = 0;
    unsigned dst_len;

    if ((SoC_Type != MODEM) && (SoC_Type != MODEM_DTB))
        return SECBOOT_RET_SUCCESS;

    if (sre_mmap(g_image_info[SoC_Type].ddr_phy_addr, g_image_info[SoC_Type].ddr_size, &virt_img_addr, secure, cache)) {
        tloge("%s, map data buffer addr=0x%x size=0x%x error\n", __func__, g_image_info[SoC_Type].ddr_phy_addr,
              g_image_info[SoC_Type].ddr_size);
        return SECBOOT_RET_FAILURE;
    }
    asm volatile("dsb sy");
    v7_dma_inv_range(virt_img_addr, virt_img_addr + g_image_info[SoC_Type].ddr_size);

    zlib_next_in = (unsigned char *)(uintptr_t)(UINT32)(
        (g_image_info[SoC_Type].image_addr - g_image_info[SoC_Type].ddr_phy_addr) + virt_img_addr);

    zlib_avail_in = (unsigned)(g_image_info[SoC_Type].ddr_phy_addr + g_image_info[SoC_Type].ddr_size -
                               g_image_info[SoC_Type].image_addr);

    tlogi("zlib_inflate_image in.\n");
    if (gzip_header_check(zlib_next_in)) {
        /* skip over asciz filename */
        if (zlib_next_in[3] & 0x8) {
            /*
             * skip over gzip header (1f,8b,08... 10 bytes total +
             * possible asciz filename)
             */
            zlib_next_in += 10;
            zlib_avail_in -= 18;
            do {
                /*
                 * If the filename doesn't fit into the buffer,
                 * the file is very probably corrupt. Don't try
                 * to read more data.
                 */
                if (zlib_avail_in == 0) {
                    tloge("%s, gzip header error", __func__);
                    return 0xFFFFFFFF;
                }
                --zlib_avail_in;
            } while (*zlib_next_in++);
        } else {
            /*
             * skip over gzip header (1f,8b,08... 10 bytes total +
             * possible asciz filename)
             */
            zlib_next_in += 10;
            zlib_avail_in -= 18;
        }
        tlogi("start decompress.\n");
        dst_len = g_image_info[SoC_Type].ddr_size;
#if defined(CONFIG_MODEM_ASLR) || defined(CONFIG_MODEM_BALONG_ASLR)
        result = aslr_zlib_inflate_image(SoC_Type, Inflate_Image_Offset, virt_img_addr, (unsigned long *)&dst_len,
                                         zlib_next_in, zlib_avail_in);
        if ((unsigned int)result == SECBOOT_RET_ASLR_RND_FAIL) {
            tloge("aslr inflate image failed\n");
            goto zlib_inlfate_error;
        }
#else
        result = uncompress((unsigned char *)virt_img_addr + Inflate_Image_Offset, (unsigned long *)&dst_len,
                            zlib_next_in, zlib_avail_in);
#endif
        tlogi("decompress finished.\n");
        if (result != 0) {
            tloge("%s, inflate fail. result = %d\n", __func__, result);
            ret = SECBOOT_RET_INVALIED_MODEM_INFLATE;
            goto zlib_inlfate_error;
        } else {
            tlogi("%s, inflate done, image length = 0x%x.\n", __func__, dst_len);
#if (defined CONFIG_COLD_PATCH) || (defined CONFIG_MODEM_COLD_PATCH)
            if (SoC_Type == MODEM && (g_modem_load.verify_flag & (0x1u << MODEM_COLD_PATCH))) {
                g_image_info[MODEM].image_size = dst_len;
            }
#endif
            ret = SECBOOT_RET_SUCCESS;
        }
    }

    /* using dma cache flush in MP platform instead of flush cache all */
    v7_dma_flush_range(virt_img_addr, virt_img_addr + g_image_info[SoC_Type].ddr_size);

zlib_inlfate_error:
    (void)sre_unmap(virt_img_addr, g_image_info[SoC_Type].ddr_size);
    tlogi("zlib_inflate_image out, ret=%d.\n", ret);

    return ret;
}

void bsp_wdt_set_timeout(u32 timeout)
{
    writel(WDT_UNLOCK, HI_WDT_BASE_ADDR_VIRT + HI_WDG_LOCK_OFFSET);
    /* 中断清除 */
    writel(0x0, HI_WDT_BASE_ADDR_VIRT + HI_WDG_INTCLR_OFFSET);
    writel(timeout, HI_WDT_BASE_ADDR_VIRT + HI_WDG_LOAD_OFFSET);  //lint !e835
    writel(WDT_RST_INT_EN, HI_WDT_BASE_ADDR_VIRT + HI_WDG_CONTROL_OFFSET);
    writel(WDT_LOCK, HI_WDT_BASE_ADDR_VIRT + HI_WDG_LOCK_OFFSET);
}

void bsp_wdt_enable(void)
{
    u32 timeout = 1200 * WDT_DEF_CLK_FREQ;
    /* 读取系统控制寄存器0x33c bit[1]为1打开看门狗，0关闭看门狗 */
    if (readl(SOC_ACPU_SCTRL_BASE_ADDR + HI_WDG_SYSCTRL_ENABLE_OFFSET) & HI_WDG_SYSCTRL_ENABLE_MASK) {
        bsp_wdt_set_timeout(timeout);
    }
}

void modem_a9_unreset_tmp(void)
{
    /* 18 unreset a9 */
#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3650)
    writel(0x1 << 15, HI_SYSCTRL_BASE_ADDR + HI_CRG_SRSTDIS1_OFFSET);
    writel(0x1 << 6, HI_SYSCTRL_BASE_ADDR + HI_CRG_SRSTDIS1_OFFSET);
#elif ((TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3670) || (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3680) ||    \
       (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_ORLANDO) || (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_KIRIN990) || \
       (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_BALTIMORE) || (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_DENVER))
    u32 val;

    val = (1 << 15) | (1 << 12) | (1 << 8) | (1 << 6) | (1 << 13);
    writel(val, HI_SYSCTRL_BASE_ADDR + 0x024);
#elif ((TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI6260) || (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_MIAMICW))
    u32 val;

    val = (1 << 15) | (1 << 12) | (1 << 8) | (1 << 6);
    writel(val, HI_SYSCTRL_BASE_ADDR + 0x024);
#else
    writel(0x1 << 15, HI_SYSCTRL_BASE_ADDR + 0x24);
    writel(0x1 << 6, HI_SYSCTRL_BASE_ADDR + 0x24);
#endif
}
/*
 * for lr lr_dtb inflate
 */
UINT32 hisi_modem_inflate(UINT32 soc_type, UINT32 inflate_img_offset)
{
    return zlib_inflate_image(soc_type, inflate_img_offset);
}

UINT32 hisi_modem_disreset(UINT32 soc_type)
{
    struct SEC_BOOT_MODEM_INFO *modem_info = NULL;

    bsp_wdt_enable();
    if (g_image_info[soc_type].unreset_dependcore ==
        (g_image_info[soc_type].unreset_dependcore & g_modem_load.verify_flag)) {
        tlogi("hisi_secboot_soc_set dependcore_%d(0x%x)=verify_flag(0x%x).\n", soc_type,
              g_image_info[soc_type].unreset_dependcore, g_modem_load.verify_flag);
        modem_a9_unreset_tmp();
        /* 成功解复位后清除校验标志，并置modem_status 为1 解复位状态 */
        g_modem_load.verify_flag = g_modem_load.verify_flag &
                                   ((~g_image_info[soc_type].unreset_dependcore) & 0xffffffff);
        g_modem_load.modem_is_ursted = 1;

        /* 清除动态加载标志和加载命令，防止modem单独复位时，遗留标志的影响 */
        modem_info = modem_info_base_get();
        if (NULL == modem_info) {
            tloge("%s, modem info is null!\n", __func__);
            return SECBOOT_RET_INVALIED_MODEM_INFO_BASE;
        }
        modem_info->dynamic_load.verify_flag = 0;
        modem_info->dynamic_load.load_cmd = 0;
    } else {
        tloge(" soc type(%d) dependcore is not ready,dependcore value is 0x%x, verify_flag is 0x%x!\n", soc_type,
              g_image_info[soc_type].unreset_dependcore, g_modem_load.verify_flag);
        return SECBOOT_RET_DEPENDCORE_NOT_READY;
    }

    return SECBOOT_RET_SUCCESS;
}

UINT32 hisi_secboot_verify(UINT32 SoC_Type, UINT32 vrl_addr, paddr_t image_addr, const char *imageNamePtr,
                           SECBOOT_LOCKSTATE lock_state)
{
    UINT32 ret;
#ifdef CONFIG_MLOADER
    UINT32 vrl_addr_virt;
#endif
    UINT32 vrl_addr_in;
#ifdef CONFIG_MLOADER
    UINT32 flag = 0;
#endif

    if ((vrl_addr == 0) || (image_addr == 0)) {
        tloge("%s, %s verify fail vrlAddr=0x%x, imageAddr=0x%llx.\n", __func__, imageNamePtr, vrl_addr, image_addr);
        return SECBOOT_RET_FAILURE;
    }

    vrl_addr_in = vrl_addr;
#ifdef CONFIG_MLOADER
    if (SoC_Type == MODEM_COMM_IMG) {
        if (sre_mmap(vrl_addr, SECBOOT_VRL_SIZE, &(vrl_addr_virt), secure, non_cache)) {
            tloge("%s, SoC_Type:%d map data buffer addr=0x%x size=0x%x error\n", __func__, SoC_Type, vrl_addr,
                  SECBOOT_VRL_SIZE);
            return SECBOOT_RET_INVALIED_ADDR_MAP;
        }
        flag = 1;
        v7_dma_inv_range((unsigned long)vrl_addr_virt, (unsigned long)vrl_addr_virt + SECBOOT_VRL_SIZE);
        vrl_addr_in = vrl_addr_virt;
    }
#endif
    ret = secboot_soc_verification(vrl_addr_in, image_addr, imageNamePtr, TRUE, lock_state);
    if (ret) {
        tloge("%s, %s soc_type=%x verify fail vrlAddr=0x%x, imageAddr=0x%llx.\n", __func__, imageNamePtr, SoC_Type,
              vrl_addr, image_addr);
    }
#ifdef CONFIG_MLOADER
    if (flag == 1) {
        sre_unmap(vrl_addr_virt, SECBOOT_VRL_SIZE);
    }
#endif
    return ret;
}
/*
 * for comm img inflate
 */
UINT32 hisi_secboot_inflate_image(UINT32 image_addr, UINT32 image_size, UINT32 deflate_addr, UINT32 deflate_size)
{
    UINT32 ret = 0;
    unsigned char *zlib_next_in = NULL;
    unsigned zlib_avail_in = 0;
    unsigned dst_len;
    int result;
    UINT32 deflate_addr_virt = 0;
    UINT32 image_addr_virt = 0;

    if (sre_mmap(deflate_addr, deflate_size, &(deflate_addr_virt), secure, non_cache)) {
        tloge("%s, map data buffer addr=0x%x size=0x%x error\n", __func__, deflate_addr, deflate_size);
        return SECBOOT_RET_INVALIED_ADDR_MAP;
    }
    v7_dma_inv_range((unsigned long)deflate_addr_virt, (unsigned long)deflate_addr_virt + SECBOOT_VRL_SIZE);
    if (sre_mmap(image_addr, image_size, &(image_addr_virt), secure, non_cache)) {
        tloge("%s, map data buffer addr=0x%x size=0x%x error\n", __func__, image_addr, image_size);
        (void)sre_unmap(deflate_addr_virt, SECBOOT_VRL_SIZE);
        return SECBOOT_RET_INVALIED_ADDR_MAP;
    }
    v7_dma_inv_range((unsigned long)image_addr_virt, (unsigned long)image_addr_virt + image_size);

    zlib_next_in = (unsigned char *)(uintptr_t)deflate_addr_virt;
    zlib_avail_in = deflate_size;

    if (gzip_header_check(zlib_next_in)) {
        /* skip over asciz filename */
        if (zlib_next_in[3] & 0x8) {
            /*
             * skip over gzip header (1f,8b,08... 10 bytes total +
             * possible asciz filename)
             */
            zlib_next_in += 10;
            zlib_avail_in -= 18;
            do {
                /*
                 * If the filename doesn't fit into the buffer,
                 * the file is very probably corrupt. Don't try
                 * to read more data.
                 */
                if (zlib_avail_in == 0) {
                    tloge("%s, gzip header error", __func__);
                    return 0xFFFFFFFF;
                }
                --zlib_avail_in;
            } while (*zlib_next_in++);
        } else {
            /*
             * skip over gzip header (1f,8b,08... 10 bytes total +
             * possible asciz filename)
             */
            zlib_next_in += 10;
            zlib_avail_in -= 18;
        }
        tlogi("start decompress.\n");
        dst_len = image_size;

        result = uncompress((unsigned char *)(uintptr_t)image_addr_virt, (unsigned long *)&dst_len, zlib_next_in,
                            zlib_avail_in);
        tlogi("decompress finished.\n");
        if (result != 0) {
            tloge("%s, inflate fail. result = %d\n", __func__, result);
            ret = SECBOOT_RET_INVALIED_MODEM_INFLATE;
        } else {
            tloge("%s, inflate done, image length = 0x%x.\n", __func__, dst_len);
            ret = SECBOOT_RET_SUCCESS;
        }
    }
    (void)sre_unmap(deflate_addr_virt, deflate_size);
    (void)sre_unmap(image_addr_virt, image_size);
    return ret;
}

UINT32 hisi_secboot_is_modem_img(UINT32 SoC_Type)
{
    switch (SoC_Type) {
        case MODEM:
        case DSP:
        case XDSP:
        case TAS:
        case WAS:
#ifdef CONFIG_MLOADER
        case MODEM_COMM_IMG:
#endif
        case MODEM_DTB:
#ifdef CONFIG_HISI_NVIM_SEC
        case NVM:
        case NVM_S:
        case MBN_R:
        case MBN_A:
#endif
#if (defined CONFIG_COLD_PATCH) || (defined CONFIG_MODEM_COLD_PATCH)
        case MODEM_COLD_PATCH:
        case DSP_COLD_PATCH:
#endif
#ifdef CONFIG_RFIC_LOAD
        case RFIC:
#endif
            return IS_MODEM_IMG;
            break;
        default:
            return 0;
    }
}

#ifdef CONFIG_MLOADER
/*
 * 使用cmd_type区分是什么安全调用类型；
 * 0:安全校验原镜像
 * 1:安全校验补丁镜像
 * 2:拼接镜像
 * 3:inflate image
 */
UINT32 hisi_secboot_verify_modem_comm_imgs(UINT32 SoC_Type, UINT32 core_id, SECBOOT_LOCKSTATE lock_state)
{
    struct SEC_BOOT_MODEM_INFO *modem_info = NULL;
    const char *imageNamePtr = "modem_fw";
    struct secboot_splicing_info_s splicing_info;

    UINT32 vrl_addr;
    UINT32 cmd_type;
    UINT32 image_addr;
    UINT32 deflate_addr, deflate_size;
    UINT32 image_size;
    UINT32 ret = 0;
    UINT32 img_id;

    if (core_id >= CORE_ID_MAX) {
        tloge("%s, core_id(%d) is not right!\n", __func__, core_id);
        return SECBOOT_RET_INVALIED_MODEM_CORE_ID;
    }

    modem_info = modem_info_base_get();
    if (NULL == modem_info) {
        tloge("%s, modem info is null!\n", __func__);
        return SECBOOT_RET_INVALIED_MODEM_INFO_BASE;
    }

    data_sync();
    cmd_type = modem_info->verify_param.verify_param_info[core_id].cmd_type;
    img_id = modem_info->verify_param.verify_param_info[core_id].image_id;
    tloge("verify_modem_comm_imgs in, cmd_type is %d, image_id is %d!\n", cmd_type, img_id);
    if (cmd_type == VERIFY_IMAGE) {
        vrl_addr = modem_info->verify_param.verify_param_info[core_id].vrl_addr;
        image_addr = modem_info->verify_param.verify_param_info[core_id].image_addr;

        ret = hisi_secboot_verify(SoC_Type, vrl_addr, image_addr, imageNamePtr, lock_state);
        if (ret == SECBOOT_RET_SUCCESS) {
            g_modem_load.verify_flag = g_modem_load.verify_flag | (0x1u << SoC_Type);
            writel(1, (UINT32)(uintptr_t)&(modem_info->verify_param.verify_param_info[core_id].verify_flag));
            tloge("%s, verify flag=0x%x.\n", __func__, g_modem_load.verify_flag);
        }

    } else if (cmd_type == VERIFY_PATCH_IMAGE) {
        SoC_Type = MODEM_COMM_IMG;
        vrl_addr = modem_info->verify_param.verify_param_info[core_id].vrl_addr;
        image_addr = modem_info->verify_param.verify_param_info[core_id].image_addr;

        ret = hisi_secboot_verify(SoC_Type, vrl_addr, image_addr, imageNamePtr, lock_state);
        if (ret == SECBOOT_RET_SUCCESS) {
            g_modem_load.verify_flag = g_modem_load.verify_flag | (0x1u << SoC_Type);
            writel(1, (UINT32)(uintptr_t)&(modem_info->verify_param.verify_param_info[core_id].verify_flag));
            tloge("%s, patch verify flag=0x%x.\n", __func__, g_modem_load.verify_flag);
        }
    } else if (cmd_type == SPLICING_IMAGE) {
        if ((g_modem_load.verify_flag & 0x1u << SoC_Type)) {
            splicing_info.image_addr = modem_info->verify_param.verify_param_info[core_id].image_addr;
            splicing_info.image_size = modem_info->verify_param.verify_param_info[core_id].image_size;
            splicing_info.patch_addr = modem_info->verify_param.verify_param_info[core_id].patch_addr;
            splicing_info.patch_size = modem_info->verify_param.verify_param_info[core_id].patch_size;
            splicing_info.splicing_addr = modem_info->verify_param.verify_param_info[core_id].splicing_addr;
            splicing_info.splicing_size = modem_info->verify_param.verify_param_info[core_id].splicing_size;
            if ((splicing_info.image_addr == 0) || (splicing_info.patch_addr == 0) ||
                (splicing_info.splicing_addr == 0)) {
                tloge("%s, splicing info not right.\n", __func__);
                return SECBOOT_RET_INVALIED_ADDR_CHECK;
            }
            ret = hisi_secboot_splicing_modem_img(SoC_Type, &splicing_info);
            if (ret != 0) {
                tloge("%s, SoC_Type(%d) splicing failed!\n", __func__, SoC_Type);
                writel(0, (UINT32)(uintptr_t)&(modem_info->verify_param.verify_param_info[core_id].verify_flag));
            } else {
                tloge("SoC_Type(%d) splicing succeed!\n", SoC_Type);
                writel(1, (UINT32)(uintptr_t)&(modem_info->verify_param.verify_param_info[core_id].verify_flag));
            }
        }
    } else if (cmd_type == INFLATE_IMAGE) {
        deflate_addr = modem_info->verify_param.verify_param_info[core_id].deflate_addr;
        deflate_size = modem_info->verify_param.verify_param_info[core_id].deflate_size;
        image_addr = modem_info->verify_param.verify_param_info[core_id].image_addr;
        image_size = modem_info->verify_param.verify_param_info[core_id].image_size;
        if ((deflate_addr == 0) || (image_addr == 0)) {
            tloge("%s, deflate info not right.\n", __func__);
            return SECBOOT_RET_INVALIED_ADDR_CHECK;
        }
        ret = hisi_secboot_inflate_image(image_addr, image_size, deflate_addr, deflate_size);
        if (ret != 0) {
            tloge("SoC_Type(%d) inflate failed!\n", SoC_Type);
            writel(0, (UINT32)(uintptr_t)&(modem_info->verify_param.verify_param_info[core_id].verify_flag));
        } else {
            tloge("SoC_Type(%d) inflate succeed!\n", SoC_Type);
            writel(1, (UINT32)(uintptr_t)&(modem_info->verify_param.verify_param_info[core_id].verify_flag));
        }
    } else {
        tloge("%s, cmd_type is %d!\n", __func__, cmd_type);
        return SECBOOT_RET_MODEM_CMD_TYPE_NOT_SUPPORT;
    }
    return ret;
}

UINT32 hisi_secboot_verify_modem_imgs(UINT32 SoC_Type, UINT32 vrlAddress, UINT32 core_id, SECBOOT_LOCKSTATE lock_state)
{
    UINT32 ret;
    paddr_t imageAddressTmp;
    const char *imageNamePtr = "modem_fw";
    UINT32 inflate_img_offset = 0;
    UINT32 modem_ddr_size = 0;
    struct secboot_splicing_info_s splicing_info;
    (void)vrlAddress;

    tlogi("hisi_secboot_soc_verification in,type=%d.\n", SoC_Type);
    uart_printf(
        "g_image_info[SoC_Type].ddr_phy_addr=0x%x%x,g_image_info[SoC_Type].ddr_size=0x%x,g_image_info[SoC_Type].unreset_dependcore=0x%x,type=%d.\n",
        g_image_info[SoC_Type].ddr_phy_addr, g_image_info[SoC_Type].ddr_size, g_image_info[SoC_Type].unreset_dependcore,
        SoC_Type);

#ifdef CONFIG_HISI_NVIM_SEC
    if ((SoC_Type == NVM) || (SoC_Type == NVM_S) || (SoC_Type == MBN_R) || (SoC_Type == MBN_A)) {
        /* clean dynamic load flag */
        ret = secboot_clean_dynamic_load_flag(SoC_Type);
        if (ret) {
            tloge("%s, %s soc_type=%x secboot_clean_dynamic_load_flag error.\n", __func__, SoC_Type);
            return ret;
        }
        /* sec os needn't check, ccore need check */
        tloge("%s, no need to verify modem_NVM and modem_carrier_resum!\n", __func__);
        return 0;
    }
#endif

    if (SoC_Type == MODEM_COMM_IMG) {
        ret = hisi_secboot_verify_modem_comm_imgs(SoC_Type, core_id, lock_state);
        return ret;
    }

    /* verify */
    imageAddressTmp = g_image_info[SoC_Type].image_addr;

    if ((SoC_Type == MODEM_DTB) && ((g_image_info[MODEM].unreset_dependcore & (1 << SoC_Type)) == 0)) {
        /* don't have dtb vrl, needn't check */
        tlogi("%s, no need to verify dtb\n", __func__);
    } else {
        ret = hisi_secboot_verify(SoC_Type, vrlAddress, imageAddressTmp, imageNamePtr, lock_state);
        if (ret == SECBOOT_RET_SUCCESS) {
            g_modem_load.verify_flag = g_modem_load.verify_flag | (0x1u << SoC_Type);
            tloge("%s,SoC_Type(%d) verify flag=0x%x.\n", __func__, SoC_Type, g_modem_load.verify_flag);
        } else {
            tloge("%s, verify failed, flag=0x%x.\n", __func__, g_modem_load.verify_flag);
            return ret;
        }
    }

    /* inflate */
    if (SoC_Type == MODEM && (g_modem_load.verify_flag & (0x1u << MODEM_COLD_PATCH))) {
        modem_ddr_size = g_image_info[MODEM].ddr_size;
        g_image_info[MODEM].ddr_size -= g_image_info[MODEM_COLD_PATCH].image_size;
        inflate_img_offset = (g_image_info[MODEM].ddr_size >> 1) & 0xFFF00000;
    }

    ret = hisi_modem_inflate(SoC_Type, inflate_img_offset);
    if ((SoC_Type == MODEM) && (g_modem_load.verify_flag & (0x1u << MODEM_COLD_PATCH))) {
        g_image_info[SoC_Type].ddr_size = modem_ddr_size;
    }
    if (ret) {
        tloge("%s, SoC_Type:%d modem inflate fail!\n", __func__, SoC_Type);
        return ret;
    }
    tloge("%s, SoC_Type:%d inflate success!\n", __func__, SoC_Type);
    /* splicing */
    if (SoC_Type == MODEM && (g_modem_load.verify_flag & (0x1u << MODEM_COLD_PATCH))) {
        splicing_info.image_addr = g_image_info[MODEM].ddr_phy_addr;
        splicing_info.image_size = g_image_info[MODEM].ddr_size - g_image_info[MODEM_COLD_PATCH].image_size -
                                   g_image_info[MODEM].image_size;
        splicing_info.patch_addr = g_image_info[MODEM_COLD_PATCH].image_addr;
        splicing_info.patch_size = g_image_info[MODEM_COLD_PATCH].image_size;
        splicing_info.splicing_addr = g_image_info[MODEM].ddr_phy_addr + inflate_img_offset;
        splicing_info.splicing_size = g_image_info[MODEM].image_size;
        ret = hisi_secboot_splicing_modem_img(SoC_Type, &splicing_info);
        tloge("%s, SoC_Type:%d splicing success!\n", __func__, SoC_Type);
    }
    tloge("%s, SoC_Type:verify end!\n", __func__);
    return ret;
}
#else
UINT32 hisi_secboot_verify_modem_imgs(UINT32 SoC_Type, UINT32 vrlAddress, UINT32 core_id, SECBOOT_LOCKSTATE lock_state)
{
    UINT32 ret, need_verify;
    paddr_t imageAddressTmp;
    UINT8 imageNamePtr[SECBOOT_IMGNAME_MAXLEN];
    UINT32 inflate_img_offset = 0;
    (void)vrlAddress;
    (void)core_id;
#ifdef CONFIG_COLD_PATCH
    UINT32 soc_type = SoC_Type;
    UINT32 modem_ddr_size = 0;
    /*
     * 如果DSP补丁镜像加载并校验通过，DSP补丁镜像和原DSP镜像都放在MODEM DDR空间中，MODEM DDR空间的最后位置存放DSP补丁镜像，DSP补丁
     * 镜像之上存放原DSP镜像，所以需要将Soc_Type切换为MODEM，原DSP镜像起始位置偏移=MODEM DDR大小 - DSP补丁镜像大小 - 原DSP镜像大小；
     * 如果DSP补丁镜像未加载或未校验通过，DSP镜像起始位置为DSP DDR空间的偏移为0的位置
     */
    if ((SoC_Type == DSP) && (g_modem_load.verify_flag & (0x1u << DSP_COLD_PATCH))) {
        SoC_Type = MODEM;
        inflate_img_offset = g_image_info[MODEM].ddr_size - g_image_info[DSP].image_size -
                             g_image_info[DSP_COLD_PATCH].image_size;
    }
    /*
     * 如果CCORE补丁镜像加载并校验通过，MODEM DDR空间的最后位置存放CCORE补丁镜像，CCORE补丁镜像之上存放原CCORE镜像，所以原镜像的
     * 加载位置=MODEM DDR大小 - CCORE补丁镜像大小 - 原CCORE镜像大小；由于在解压缩算法中需要传入压缩镜像的大小，所以临时改变MODEM DDR
     * 大小（MODEM DDR大小 - CCORE补丁镜像大小），这样通过MODEM DDR大小和原CCORE镜像的起始位置可以计算出原CCORE压缩镜像的大小；
     * CCORE解压缩镜像的起始地址为MODEM DDR空间的1/2处；
     */
    else if (SoC_Type == MODEM && (g_modem_load.verify_flag & (0x1u << MODEM_COLD_PATCH))) {
        modem_ddr_size = g_image_info[MODEM].ddr_size;
        g_image_info[MODEM].ddr_size -= g_image_info[MODEM_COLD_PATCH].image_size;
        inflate_img_offset = (g_image_info[MODEM].ddr_size >> 1) & 0xFFF00000;
    }
#endif
    if (0 == vrlAddress) {
        tlogi("%s, vrladdr is null\n", __func__);
        return SECBOOT_RET_FAILURE;
    }

    tlogi("hisi_secboot_soc_verification in,type=%d.\n", SoC_Type);
    uart_printf(
        "g_image_info[SoC_Type].ddr_phy_addr=0x%x%x,g_image_info[SoC_Type].ddr_size=0x%x,g_image_info[SoC_Type].unreset_dependcore=0x%x,type=%d.\n",
        g_image_info[SoC_Type].ddr_phy_addr, g_image_info[SoC_Type].ddr_size, g_image_info[SoC_Type].unreset_dependcore,
        SoC_Type);

    ret = secboot_clean_dynamic_load_flag(SoC_Type);
    if (ret) {
        tloge("%s, %s soc_type=%x secboot_init_verify_addr error.\n", __func__, imageNamePtr, SoC_Type);
#ifdef CONFIG_COLD_PATCH
        if ((SoC_Type == MODEM) && (g_modem_load.verify_flag & (0x1u << MODEM_COLD_PATCH)))
            g_image_info[SoC_Type].ddr_size = modem_ddr_size;
#endif
        return ret;
    }

    imageAddressTmp = g_image_info[SoC_Type].ddr_phy_addr;

    if ((SoC_Type == MODEM) || (SoC_Type == MODEM_DTB))
        imageAddressTmp = g_image_info[SoC_Type].image_addr;

#ifdef CONFIG_COLD_PATCH
    if ((SoC_Type == MODEM_COLD_PATCH) || (SoC_Type == DSP_COLD_PATCH))
        imageAddressTmp = g_image_info[SoC_Type].image_addr;
#endif

    if ((SoC_Type == MODEM_DTB) && ((g_image_info[MODEM].unreset_dependcore & (1 << MODEM_DTB)) == 0)) {
        /* don't have dtb vrl, needn't check */
        need_verify = 0;
        tlogi("%s, no need to verify modem_dt\n", __func__);
    }
#ifdef CONFIG_HISI_NVIM_SEC
    else if ((SoC_Type == NVM) || (SoC_Type == NVM_S) || (SoC_Type == MBN_R) || (SoC_Type == MBN_A)) {
        /* sec os needn't check, ccore need check */
        tloge("%s, no need to verify modem_NVM and modem_carrier_resum!\n", __func__);
        return 0;
    }
#endif
    else {
        need_verify = 1;
        ret = secboot_get_soc_name(SoC_Type, imageNamePtr, SECBOOT_IMGNAME_MAXLEN);
        if (!ret) {
            if ((vrlAddress != SEB_INVALID_VALUE) && (imageAddressTmp != SEB_INVALID_VALUE)) {
                ret = secboot_soc_verification(vrlAddress, imageAddressTmp, (const char *)imageNamePtr, TRUE,
                                               lock_state);
                if (ret) {
                    tloge("%s, %s soc_type=%x verify fail vrlAddr=0x%x, imageAddr=0x%llx.\n", __func__, imageNamePtr,
                          SoC_Type, vrlAddress, imageAddressTmp);
#ifdef CONFIG_COLD_PATCH
                    if ((SoC_Type == MODEM) && (g_modem_load.verify_flag & (0x1u << MODEM_COLD_PATCH)))
                        g_image_info[SoC_Type].ddr_size = modem_ddr_size;
#endif
                    return ret;
                }
            } else {
                tloge("%s, %s verify fail vrlAddr=0x%x, imageAddr=0x%llx.\n", __func__, imageNamePtr, vrlAddress,
                      imageAddressTmp);
                ret = SECBOOT_RET_FAILURE;
#ifdef CONFIG_COLD_PATCH
                if ((SoC_Type == MODEM) && (g_modem_load.verify_flag & (0x1u << MODEM_COLD_PATCH)))
                    g_image_info[SoC_Type].ddr_size = modem_ddr_size;
#endif
                return ret;
            }
        } else {
            tloge("%s, failed to get soc name %d\n", __func__, SoC_Type);
#ifdef CONFIG_COLD_PATCH
            if ((SoC_Type == MODEM) && (g_modem_load.verify_flag & (0x1u << MODEM_COLD_PATCH)))
                g_image_info[SoC_Type].ddr_size = modem_ddr_size;
#endif
            return ret;
        }
    }

#ifdef CONFIG_COLD_PATCH
    SoC_Type = soc_type;
#endif

    secboot_config_modem_verify_flag(SoC_Type, need_verify);

    ret = hisi_modem_inflate(SoC_Type, inflate_img_offset);

    if (ret) {
        tloge("%s, SoC_Type:%d modem inflate fail!\n", __func__, SoC_Type);
#ifdef CONFIG_COLD_PATCH
        if ((SoC_Type == MODEM) && (g_modem_load.verify_flag & (0x1u << MODEM_COLD_PATCH)))
            g_image_info[SoC_Type].ddr_size = modem_ddr_size;
#endif
        return ret;
    }
#ifdef CONFIG_COLD_PATCH
    if ((SoC_Type == DSP) && (g_modem_load.verify_flag & (0x1u << DSP_COLD_PATCH))) {
        ret = secboot_splicing_img(SoC_Type, inflate_img_offset, g_image_info[SoC_Type].image_size);
        if (ret) {
            tloge("%s, splicing dsp patch imag fail,load old image fail!\n", __func__);
            return ret;
        }
    }

    if ((SoC_Type == MODEM) && (g_modem_load.verify_flag & (0x1u << MODEM_COLD_PATCH))) {
        g_image_info[SoC_Type].ddr_size = modem_ddr_size;
        ret = secboot_splicing_img(SoC_Type, inflate_img_offset, g_image_info[SoC_Type].image_size);
        if (ret) {
            tloge("%s, splicing modem patch imag fail,load old image fail!\n", __func__);
            return ret;
        }
    }
#endif
    tlogi("hisi_secboot_soc_verification out, ret=0x%x.\n", ret);
    return ret;
}
#endif
