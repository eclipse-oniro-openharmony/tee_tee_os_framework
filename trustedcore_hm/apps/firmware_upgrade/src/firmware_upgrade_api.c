/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: hsm firmware safety upgrade
 * Author: chenyao
 * Create: 2020-03-31
 */

#include "tee_ext_api.h"
#include "tee_log.h"
#include "securec.h"
#include "firmware_upgrade_api.h"
#include "firmware_upgrade.h"
#include "hsm_update_lib_api.h"
#include "hsm_verify_api.h"
#include "hsm_efuse_api.h"
#include "efuse_lib_api.h"

static FLASH_PART_INFO g_flash_part_info[DEV_NUM_MAX][FLASH_INFO_TYPE_NUM] = {
    {
        { DSMI_COMPONENT_TYPE_HBOOT1_A, 0 },
        { DSMI_COMPONENT_TYPE_HILINK, 0 },
        { DSMI_COMPONENT_TYPE_HBOOT1_B, 0 },
        { SLICE_HBOOT2_0, 0 }, /* Seperate 3M HBOOT2 area to 6 512K size blocks for sync */
        { SLICE_HBOOT2_1, 0 },
        { SLICE_HBOOT2_2, 0 },
        { SLICE_HBOOT2_3, 0 },
        { SLICE_HBOOT2_4, 0 },
        { SLICE_HBOOT2_5, 0 },
        { DSMI_COMPONENT_TYPE_DDR, 0 },
        { DSMI_COMPONENT_TYPE_LP, 0 },
        { DSMI_COMPONENT_TYPE_HSM, 0 },
        { DSMI_COMPONENT_TYPE_SAFETY_ISLAND, 0 },
        { DSMI_COMPONENT_TYPE_SYS_BASE_CONFIG, 0 },
    },
    {
        { DSMI_COMPONENT_TYPE_HBOOT1_A, 0 },
        { DSMI_COMPONENT_TYPE_HILINK, 0 },
        { DSMI_COMPONENT_TYPE_HBOOT1_B, 0 },
        { SLICE_HBOOT2_0, 0 }, /* Seperate 3M HBOOT2 area to 6 512K size blocks for sync */
        { SLICE_HBOOT2_1, 0 },
        { SLICE_HBOOT2_2, 0 },
        { SLICE_HBOOT2_3, 0 },
        { SLICE_HBOOT2_4, 0 },
        { SLICE_HBOOT2_5, 0 },
        { DSMI_COMPONENT_TYPE_DDR, 0 },
        { DSMI_COMPONENT_TYPE_LP, 0 },
        { DSMI_COMPONENT_TYPE_HSM, 0 },
        { DSMI_COMPONENT_TYPE_SAFETY_ISLAND, 0 },
        { DSMI_COMPONENT_TYPE_SYS_BASE_CONFIG, 0 },
    },
};

STATIC uint32_t sec_get_boot_flag(uint32_t dev_id, BOOT_FLAG *flag_s)
{
    uint32_t offset = SRAM_CTRL_BOOT_ADDR;

    return lib_secure_sram_read(offset, (uint8_t *)flag_s, sizeof(uint32_t), dev_id);
}

STATIC uint32_t sec_get_upgrade_flag(uint32_t dev_id, UPGRADE_FLAG *flag)
{
    uint32_t ret;

    ret = lib_upgrade_flash_read(FIRM_UPGRADE_FLASH_ADDR, (uint8_t *)flag, sizeof(UPGRADE_FLAG), dev_id);
    if (ret != TEE_SUCCESS) {
        tloge("read master upgrade flag fail, 0x%x.\n", ret);
        return ret;
    }

    if (flag->done != TEE_HSM_UPGRADE_DONE) {
        ret = lib_upgrade_flash_read(FIRM_UPGRADE_BAK_FLASH_ADDR, (uint8_t *)flag, sizeof(UPGRADE_FLAG), dev_id);
        if (ret != TEE_SUCCESS) {
            tloge("read bak upgrade flag fail, 0x%x.\n", ret);
            return ret;
        }
    }

    return TEE_SUCCESS;
}

STATIC uint32_t sec_before_upgrade_para_check(uint32_t dev_id, UPGRADE_FLAG *flag)
{
    uint32_t ret;
    uint32_t sync_flag = 0;

    ret = firmware_dev_id_verify(dev_id);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    ret = lib_sync_flag_get(dev_id, &sync_flag);
    if (ret != TEE_SUCCESS) {
        tloge("read sync flag fail, 0x%x.\n", ret);
        return ret;
    }

    flag->sync_done = sync_flag;

    return TEE_SUCCESS;
}

STATIC uint32_t is_mdc(uint32_t *flag)
{
    uint32_t ret;
    uint32_t val = 0;

    ret = lib_secure_sysctrl_read(SC_PAD_INFO_OFFSET, &val, 0);
    if (ret != TEE_SUCCESS) {
        SLogError("read sys reg fail, 0x%x.", ret);
        return ret;
    }

    *flag = (val & BIT15) ? 1 : 0;

    return TEE_SUCCESS;
}

STATIC uint32_t is_img_nvcnt_same(IMG_NVCNT_S *img_cnt_s)
{
    uint32_t is_same;
    uint32_t mdc_flag;
    uint32_t i = UFS_NVCNT_4;
    uint32_t ret;
    uint32_t img_cnt = img_cnt_s->hboot1_a_nvcnt;

    is_same = (img_cnt == img_cnt_s->hilink_nvcnt) &&
              (img_cnt == img_cnt_s->hboot1_b_nvcnt) &&
              (img_cnt == img_cnt_s->nv_cnt_ufs[UFS_NVCNT_0]) &&
              (img_cnt == img_cnt_s->nv_cnt_ufs[UFS_NVCNT_1]) &&
              (img_cnt == img_cnt_s->nv_cnt_ufs[UFS_NVCNT_2]) &&
              (img_cnt == img_cnt_s->nv_cnt_ufs[UFS_NVCNT_3]) &&
              (img_cnt == img_cnt_s->hboot2_nvcnt) &&
              (img_cnt == img_cnt_s->lpddr_nvcnt) &&
              (img_cnt == img_cnt_s->lp_nvcnt) &&
              (img_cnt == img_cnt_s->hiss_nvcnt);

    ret = is_mdc(&mdc_flag);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    if (mdc_flag != 0) {
        is_same = is_same && (img_cnt == img_cnt_s->sil_nvcnt) && (img_cnt == img_cnt_s->syscfg_nvcnt);
        while (i != (NVCNT_UFS_NUMBER - 1) && img_cnt_s->nv_cnt_ufs[i] != IMG_NVCNT_END_MAGIC) {
            is_same = is_same && (img_cnt == img_cnt_s->nv_cnt_ufs[i]);
            i++;
        }
    }

    if (is_same != 0) {
        return TEE_SUCCESS;
    }

    tloge("img cnt: 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x\n",
        img_cnt_s->hboot1_a_nvcnt, img_cnt_s->hilink_nvcnt, img_cnt_s->hboot1_b_nvcnt,
        img_cnt_s->hboot2_nvcnt, img_cnt_s->lpddr_nvcnt, img_cnt_s->lp_nvcnt, img_cnt_s->hiss_nvcnt,
        img_cnt_s->sil_nvcnt, img_cnt_s->syscfg_nvcnt, img_cnt_s->magic);

    for (i = 0; i < NVCNT_UFS_NUMBER; i++) {
        tloge("nv cnt ufs[%d]: 0x%x\n", i, img_cnt_s->nv_cnt_ufs[i]);
    }

    return TEE_ERROR_BAD_STATE;
}

STATIC uint32_t sec_nv_cnt_para_check(uint32_t dev_id, uint32_t *nv_cnt)
{
    uint32_t ret;
    IMG_NVCNT_S img_cnt_s = {{0}, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, {0}};
    uint32_t img_cnt;

    ret = lib_secure_sram_read(SRAM_IMG_NVCNT_OFFSET, (uint8_t *)&img_cnt_s, sizeof(IMG_NVCNT_S), dev_id);
    if (ret != TEE_SUCCESS) {
        tloge("read sram fail, 0x%x.\n", ret);
        return ret;
    }

    if (img_cnt_s.magic != IMG_NVCNT_MAGIC) {
        tloge("img cnt magic check fail, 0x%x.\n", img_cnt_s.magic);
        return TEE_ERROR_BAD_STATE;
    }

    ret = is_img_nvcnt_same(&img_cnt_s);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    img_cnt = img_cnt_s.hboot1_a_nvcnt;
    if (img_cnt >= FIRM_UPGRADE_SHIFT_32) {
        tloge("invalid img cnt, 0x%x.\n", img_cnt);
        return TEE_ERROR_BAD_STATE;
    }

    *nv_cnt = (0x1U << img_cnt) - 1;

    return TEE_SUCCESS;
}

STATIC uint32_t sec_set_clearddr_flag(uint32_t dev_id)
{
    uint32_t ret;
    uint32_t val = 0;

    ret = lib_secure_sysctrl_read(SYSCTRL_UPGRADE_FLAG_OFFSET, &val, dev_id);
    if (ret != TEE_SUCCESS) {
        tloge("read sysctrl reg fail, 0x%x.\n", ret);
        return ret;
    }

    val &= SYSCTRL_UPGRADE_FLAG_MASK;
    val |= SYSCTRL_UPGRADE_FLAG_VAL; /* set BIT8~BIT11 to 0x5 */

    ret = lib_secure_sysctrl_write(SYSCTRL_UPGRADE_FLAG_OFFSET, &val, dev_id);
    if (ret != TEE_SUCCESS) {
        tloge("write sysctrl reg fail, 0x%x.\n", ret);
        return ret;
    }

    return TEE_SUCCESS;
}

STATIC uint32_t sec_write_upgrade_flag(uint32_t dev_id, UPGRADE_FLAG *flag)
{
    uint32_t ret;

    ret = lib_upgrade_flash_write(FIRM_UPGRADE_FLASH_ADDR, (uint8_t *)flag, sizeof(UPGRADE_FLAG), dev_id);
    if (ret != TEE_SUCCESS) {
        tloge("write upgrade flag fail, 0x%x.\n", ret);
        return ret;
    }

    ret = lib_upgrade_flash_write(FIRM_UPGRADE_BAK_FLASH_ADDR, (uint8_t *)flag, sizeof(UPGRADE_FLAG), dev_id);
    if (ret != TEE_SUCCESS) {
        tloge("write bak upgrade flag fail, 0x%x.\n", ret);
        return ret;
    }

    return TEE_SUCCESS;
}

STATIC uint32_t sec_get_reset_count(uint32_t dev_id, uint32_t *boot_cnt)
{
    uint32_t sysctrl_boot_offset = SRAM_CTRL_RESET_CNT_ADDR;

    return lib_secure_sysctrl_read(sysctrl_boot_offset, boot_cnt, dev_id);
}

STATIC uint32_t sec_set_reset_count(uint32_t dev_id, uint32_t *boot_cnt)
{
    uint32_t sysctrl_boot_offset = SRAM_CTRL_RESET_CNT_ADDR;

    return lib_secure_sysctrl_write(sysctrl_boot_offset, boot_cnt, dev_id);
}

STATIC uint32_t sec_burn_efuse_nvcnt(uint32_t nv_cnt, uint32_t dev_id)
{
    uint32_t ret0;
    uint32_t ret1;

    ret0 = TEE_HSM_Power_On(dev_id);
    if (ret0 != TEE_SUCCESS) {
        tloge("efuse power on fail, state is : %x\n", ret0);
        return TEE_ERROR_BAD_STATE;
    }

    ret0 = lib_efuse_nv_cnt_burn(nv_cnt, dev_id);
    if (ret0 != TEE_SUCCESS) {
        tloge("nv_cnt burn fail, ret is : %x\n", ret0);
        goto exit;
    }

exit:
    ret1 = TEE_HSM_Power_Off(dev_id);
    if (ret1 != TEE_SUCCESS) {
        tloge("efuse power off fail, state is : %x\n", ret1);
        return TEE_ERROR_BAD_STATE;
    }

    return ret0; /* return nv burn failed results. */
}

STATIC uint32_t sec_nv_cnt_update(uint32_t dev_id)
{
    uint32_t ret;
    uint32_t nv_cnt = 0;

    ret = lib_efuse_boot_check(dev_id);
    if (ret != TEE_SUCCESS) {
        SLogTrace("Now is not in secure boot, canot update nvcnt.\n");
        return TEE_SUCCESS;
    }

    ret = sec_nv_cnt_para_check(dev_id, &nv_cnt);
    if (ret != TEE_SUCCESS) {
        tloge("nv_cnt para check fail, 0x%x.\n", ret);
        return ret;
    }

    ret = lib_efuse_nv_cnt_check(nv_cnt, dev_id);
    if ((nv_cnt == 0) || (ret == TEE_SUCCESS)) {
        SLogTrace("nv_cnt value is same, bypass update nvcnt.\n");
        return TEE_SUCCESS;
    }

    ret = sec_burn_efuse_nvcnt(nv_cnt, dev_id);
    if (ret != TEE_SUCCESS) {
        tloge("burn efuse nvcnt fail, 0x%x.\n", ret);
        return ret;
    }

    ret = lib_efuse_nv_cnt_check(nv_cnt, dev_id);
    if (ret != TEE_SUCCESS) {
        tloge("nv_cnt value check fail, cnt is : 0x%x\n", nv_cnt);
        return ret;
    }

    return TEE_SUCCESS;
}

uint32_t sec_img_verify(uint64_t nsecure_addr, uint32_t length,
    uint32_t dev_id, uint32_t img_id, uint32_t pss_cfg)
{
    uint32_t ret;
    uint64_t image_addr = 0;

    ret = soc_img_verify_para_check(nsecure_addr, length, dev_id, img_id, pss_cfg);
    if (ret != TEE_SUCCESS) {
        tloge("secure img verify paracheck fail, 0x%x.\n", ret);
        return ret;
    }

    ret = lib_secure_img_verify(nsecure_addr, length, dev_id, img_id, &image_addr, pss_cfg);
    if (ret != TEE_SUCCESS) {
        tloge("secure img info storage fail, 0x%x.\n", ret);
        return ret;
    }

    ret = TEE_HSM_SOC_VERIFY(dev_id, image_addr, length, img_id);
    if (ret != TEE_SUCCESS) {
        tloge("tee hsm soc verify fail, 0x%x.\n", ret);
        return ret;
    }

    ret = lib_secure_verify_status_update(dev_id, img_id);
    if (ret != TEE_SUCCESS) {
        tloge("verify status update fail, 0x%x.\n", ret);
        return ret;
    }

    return TEE_SUCCESS;
}

uint32_t sec_img_update(uint32_t dev_id, uint32_t img_index)
{
    uint32_t ret;
    uint32_t slice = 0;

    ret = soc_img_update_para_check(dev_id, img_index);
    if (ret != TEE_SUCCESS) {
        tloge("secure img update para check fail, 0x%x.\n", ret);
        return ret;
    }

    /* slice is the index of image pieces, multiple write for one image */
    do {
        ret = lib_secure_img_update(img_index, dev_id, &slice);
        if (ret != TEE_SUCCESS) {
            tloge("sec img update fail, 0x%x.\n", ret);
            return ret;
        }
    } while (slice != 0);

    return TEE_SUCCESS;
}

STATIC uint32_t sec_update_finish_action(uint32_t dev_id)
{
    uint32_t boot_cnt = TEE_HSM_MASTER_CNT;
    UPGRADE_FLAG u_flag = {0};
    uint32_t ret;

    // set the resetcnt num to indicate booting from main partition
    ret = sec_set_reset_count(dev_id, &boot_cnt);
    if (ret != TEE_SUCCESS) {
        tloge("set reset cnt fail, 0x%x.\n", ret);
        return ret;
    }

    // write the upgrade done flag to flash area
    u_flag.part_select = TEE_HSM_MASTER_UPGRADE;
    u_flag.done = TEE_HSM_UPGRADE_DONE;

    ret = sec_write_upgrade_flag(dev_id, &u_flag);
    if (ret != TEE_SUCCESS) {
        tloge("write upgrade flag fail, 0x%x.\n", ret);
        return ret;
    }

    ret = sec_set_clearddr_flag(dev_id);
    if (ret != TEE_SUCCESS) {
        tloge("operate sysctrl reg fail, 0x%x.\n", ret);
        return ret;
    }

    // reflash the hilink image in l3sram
    ret = lib_reflash_hilink_ram(dev_id);
    if (ret != TEE_SUCCESS) {
        tloge("reflash hilink fail, 0x%x.\n", ret);
        return ret;
    }

    // reflash the hboot1a image in hiss sram
    ret = TEE_HSM_Hboot1a_Trans(dev_id);
    if (ret != TEE_SUCCESS) {
        tloge("reflash hboot1a fail, 0x%x.\n", ret);
        return ret;
    }

    return TEE_SUCCESS;
}

uint32_t sec_update_finish(uint32_t dev_id)
{
    uint32_t ret;

    ret = firmware_dev_id_verify(dev_id);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    // check if the verify and update status is done
    ret = lib_is_update_finished(dev_id);
    if (ret != TEE_SUCCESS) {
        tlogw("firmware update process is not finished.\n");
        goto exit;
    }

    ret = sec_update_finish_action(dev_id);
    if (ret != TEE_SUCCESS) {
        tloge("update finish action fail, 0x%x.\n", ret);
        return ret;
    }

exit:
    ret = lib_secure_update_finish(dev_id);
    if (ret != TEE_SUCCESS) {
        tloge("update finish fail, 0x%x.\n", ret);
        return ret;
    }

    return TEE_SUCCESS;
}

STATIC uint32_t sec_img_sync_verify(uint32_t dev_id, uint32_t img_id_in, uint32_t base_part,
    uint32_t baseline_flag)
{
    uint32_t ret;
    uint64_t img_addr;
    uint32_t length;
    uint32_t img_id;

    // if baseline flag is set, baseline hash will be check, so bypass verify img
    if (baseline_flag == 1) {
        return TEE_SUCCESS;
    }

    // hboot2 is seperate to many pieces, only verify once
    if (img_id_in == SLICE_HBOOT2_0) {
        img_id = DSMI_COMPONENT_TYPE_HBOOT2;
    } else if ((img_id_in >= SLICE_HBOOT2_1) && (img_id_in <= SLICE_HBOOT2_5)) {
        return TEE_SUCCESS;
    } else {
        img_id = img_id_in;
    }

    ret = lib_secure_part_read(dev_id, img_id, &img_addr, &length, base_part);
    if (ret != TEE_SUCCESS) {
        tloge("read flash part fail, 0x%x.\n", ret);
        return ret;
    }

    ret = TEE_HSM_SOC_VERIFY(dev_id, img_addr, length, img_id);
    if (ret != TEE_SUCCESS) {
        tloge("tee hsm soc verify fail, 0x%x.\n", ret);
        return TEE_ERROR_BAD_STATE;
    }

    return TEE_SUCCESS;
}

/*
 * sync single flash image partition
 * dev_id, which device to sync (master or slave)
 * img_id, which image partition to sync
 * base_part, sync form which partition to another. 0: sync from the master partition,
 * 1: sync from the backup partition
 * baseline_flag, 0: baseline hash flag is not set, 1: baseline hash flag is set
 */
STATIC uint32_t sec_img_sync(uint32_t dev_id, uint32_t img_id, uint32_t base_part,
    uint32_t baseline_flag)
{
    uint32_t ret;

    ret = sec_img_sync_verify(dev_id, img_id, base_part, baseline_flag);
    if (ret != TEE_SUCCESS) {
        tloge("verify img before sync fail, 0x%x.\n", ret);
        return ret;
    }

    ret = lib_secure_img_sync(dev_id, img_id, base_part, baseline_flag);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    return TEE_SUCCESS;
}

STATIC uint32_t check_same_bflag(BOOT_FLAG *b_flag, uint32_t u_flag, uint32_t *is_same)
{
    uint32_t ret;
    uint32_t mdc_flag = 0;

    if ((b_flag->hboot1_a != u_flag) || (b_flag->hilink != u_flag) ||
        (b_flag->hboot1_b != u_flag)) {
        *is_same = 0;
        return TEE_SUCCESS;
    }

    ret = is_mdc(&mdc_flag);
    if (ret != TEE_SUCCESS) {
        SLogError("read dc/mdc sys reg fail");
        return ret;
    }

    if (mdc_flag) {
        if ((b_flag->hboot2 != u_flag) ||
            (b_flag->lpddr != u_flag) || (b_flag->lp != u_flag) ||
            (b_flag->hiss != u_flag) || (b_flag->sil != u_flag) || (b_flag->syscfg != u_flag)) {
            *is_same = 0;
            return TEE_SUCCESS;
        }
    }

    *is_same = 1;

    return TEE_SUCCESS;
}

STATIC uint32_t get_sync_img_count(uint32_t *img_count)
{
    uint32_t ret;
    uint32_t mdc_flag = 0;

    ret = is_mdc(&mdc_flag);
    if (ret != TEE_SUCCESS) {
        SLogError("read dc/mdc sys reg fail, 0x%x.", ret);
        return ret;
    }

    if (mdc_flag) {
        *img_count = sizeof(g_flash_part_info[0]) / sizeof(FLASH_PART_INFO);
    } else {
        *img_count = DC_FLASH_IMAGE_SIZE;
    }

    return TEE_SUCCESS;
}

STATIC uint32_t choose_part_base(uint32_t dev_id, uint32_t upgrade_part, uint32_t *part_base)
{
    uint32_t ret;
    BOOT_FLAG b_flag_s = { 0 };
    uint32_t is_same = 0;

    ret = sec_get_boot_flag(dev_id, &b_flag_s);
    if (ret != TEE_SUCCESS) {
        SLogError("get boot flag fail, 0x%x.", ret);
        return ret;
    }

    // if all the images boot from the upgraded partition side,
    // sync from the upgraded partition side, otherwise sync from another side
    ret = check_same_bflag(&b_flag_s, upgrade_part, &is_same);
    if (ret != TEE_SUCCESS) {
        SLogError("check same bflag fail, 0x%x.", ret);
        return ret;
    }

    if (is_same) {
        *part_base = upgrade_part;
    } else {
        *part_base = upgrade_part ^ 1u;
    }

    return TEE_SUCCESS;
}

// sync operation in boot process after image upgrade
STATIC uint32_t sec_img_sync_upgrade(uint32_t dev_id, uint32_t upgrade_part)
{
    uint32_t ret;
    uint32_t part_base;
    uint32_t i;
    uint32_t img_count;
    UPGRADE_FLAG u_flag = { 0 };

    ret = choose_part_base(dev_id, upgrade_part, &part_base);
    if (ret != TEE_SUCCESS) {
        SLogError("choose part base fail");
        return ret;
    }

    ret = get_sync_img_count(&img_count);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    for (i = 0; i < img_count; i++) {
        SLogTrace("sync img %d", i);
        ret = sec_img_sync(dev_id, g_flash_part_info[dev_id][i].img_id, part_base, 0);
        if (ret != TEE_SUCCESS) {
            SLogError("sec img sync error, img_id: 0x%x", g_flash_part_info[dev_id][i].img_id);
            return ret;
        }
    }

    ret = lib_secure_set_baseline_flag(dev_id);
    if (ret != TEE_SUCCESS) {
        SLogError("set baseline flag fail, 0x%x.", ret);
        return ret;
    }

    ret = sec_nv_cnt_update(dev_id);
    if (ret != TEE_SUCCESS) {
        SLogError("update nvcnt fail, 0x%x.", ret);
        return ret;
    }

    ret = sec_write_upgrade_flag(dev_id, &u_flag);
    if (ret != TEE_SUCCESS) {
        SLogError("clear upgrade flag fail, 0x%x.", ret);
        return ret;
    }

    return TEE_SUCCESS;
}

STATIC void init_img_boot_info(BOOT_FLAG *b_flag, FLASH_PART_INFO *p_info)
{
    int32_t i = 0;
    int32_t j;

    p_info[i++].part_boot = b_flag->hboot1_a;
    p_info[i++].part_boot = b_flag->hilink;
    p_info[i++].part_boot = b_flag->hboot1_b;

    for (j = 0; j < (HBOOT2_SIZE / HBOOT2_S_SIZE); j++) {
        p_info[i++].part_boot = b_flag->hboot2;
    }

    p_info[i++].part_boot = b_flag->lpddr;
    p_info[i++].part_boot = b_flag->lp;
    p_info[i++].part_boot = b_flag->hiss;
    p_info[i++].part_boot = b_flag->sil;
    p_info[i++].part_boot = b_flag->syscfg;
}

/* sync operation in normal boot process */
STATIC uint32_t sec_img_sync_normal(uint32_t dev_id)
{
    uint32_t ret;
    BOOT_FLAG b_flag = {0};
    uint32_t i;
    uint32_t img_count;
    uint32_t img_baseline_flag;

    ret = sec_get_boot_flag(dev_id, &b_flag);
    if (ret != TEE_SUCCESS) {
        SLogError("read boot flag fail");
        return ret;
    }

    init_img_boot_info(&b_flag, g_flash_part_info[dev_id]);

    ret = lib_secure_get_baseline_flag(dev_id, &img_baseline_flag);
    if (ret != TEE_SUCCESS) {
        SLogError("get bl flag fail, 0x%x.", ret);
        return ret;
    }

    ret = get_sync_img_count(&img_count);
    if (ret != TEE_SUCCESS) {
        SLogError("get img count fail, 0x%x.", ret);
        return ret;
    }

    for (i = 0; i < img_count; i++) {
        SLogTrace("sync img %d", i);
        ret = sec_img_sync(dev_id, g_flash_part_info[dev_id][i].img_id,
                           g_flash_part_info[dev_id][i].part_boot, img_baseline_flag);
        if (ret != TEE_SUCCESS) {
            SLogError("img sync %d failed, 0x%x.\n", i, ret);
            return ret;
        }
    }

    // set baseline
    ret = lib_secure_set_baseline_flag(dev_id);
    if (ret != TEE_SUCCESS) {
        SLogError("set baseline flag fail, 0x%x.", ret);
        return ret;
    }

    return TEE_SUCCESS;
}

uint32_t sec_img_sync_entry(uint32_t dev_id)
{
    uint32_t ret;
    UPGRADE_FLAG u_flag = {0};

    ret = firmware_dev_id_verify(dev_id);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    ret = sec_get_upgrade_flag(dev_id, &u_flag);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    if (u_flag.done == TEE_HSM_UPGRADE_DONE) {
        SLogTrace("upgrade boot sync.\n");
        return sec_img_sync_upgrade(dev_id, 0); // Always upgrade major partition
    }

    SLogTrace("normal boot sync.\n");

    return sec_img_sync_normal(dev_id);
}

uint32_t sec_img_sync_before_upgrade(uint32_t dev_id)
{
    uint32_t ret;
    UPGRADE_FLAG u_flag = {0};
    uint32_t img_count;
    uint32_t i;
    uint32_t img_baseline_flag;

    ret = sec_before_upgrade_para_check(dev_id, &u_flag);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    if (u_flag.sync_done == TEE_HSM_SYNC_DONE) {
        return TEE_SUCCESS;
    }

    ret = sec_get_upgrade_flag(dev_id, &u_flag);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    // Bypass sync if upgrade flag is valid
    if (u_flag.done == TEE_HSM_UPGRADE_DONE) {
        return TEE_SUCCESS;
    }

    // sync refer to img baseline
    ret = lib_secure_get_baseline_flag(dev_id, &img_baseline_flag);
    if (ret != TEE_SUCCESS) {
        tloge("get bl flag fail, 0x%x.\n", ret);
        return ret;
    }

    if (img_baseline_flag == 0) {
        tloge("img baseline is invalid.\n");
        return TEE_ERROR_BAD_STATE;
    }

    ret = get_sync_img_count(&img_count);
    if (ret != TEE_SUCCESS) {
        tloge("get img count fail, 0x%x.\n", ret);
        return ret;
    }

    for (i = 0; i < img_count; i++) {
        SLogTrace("sync img %d.\n", i);
        ret = sec_img_sync(dev_id, g_flash_part_info[dev_id][i].img_id, 0, img_baseline_flag);
        if (ret != TEE_SUCCESS) {
            tloge("sec img sync %d failed, 0x%x.\n", i, ret);
            return ret;
        }
    }

    return TEE_SUCCESS;
}

STATIC uint32_t rim_mode_compared(const uint8_t *rim_info)
{
    const CER_RIM_DATA_LIST *rim_data_list = (const CER_RIM_DATA_LIST *)rim_info;
    uint32_t sign_alg = rim_data_list->sign_alg;

    if (((sign_alg >> APPEN_SEL_SHIFT) & APPENSEL_MASK) != SCB_SIGN_RSA_PSS_MODE) {
        tloge("sign_alg is prohibit mode\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

/* apply to HSM for revocation of secondary key */
uint32_t sec_rim_update(uint32_t dev_id, uint8_t *rim_info, uint32_t rim_len)
{
    uint32_t ret;
    uint32_t ret1;
    uint8_t rim_update_info[TEE_HSM_RIM_INFO_LEN] = {0};
    uint8_t root_key[TEE_HSM_ROOTKEY_LEN] = {0};

    ret = rim_update_para_check(dev_id, rim_info, rim_len);
    if (ret != TEE_SUCCESS) {
        tloge("rim update para check fail, 0x%x.\n", ret);
        return ret;
    }

    ret = rim_mode_compared(rim_info);
    if (ret != TEE_SUCCESS) {
        tloge("rim mode compared, 0x%x.\n", ret);
        return ret;
    }

    ret = lib_root_key_get(root_key, TEE_HSM_ROOTKEY_LEN);
    if (ret != TEE_SUCCESS) {
        tloge("rim root key get fail, 0x%x.\n", ret);
        return ret;
    }

    ret = memcpy_s(rim_update_info, TEE_HSM_RIM_INFO_LEN, rim_info, TEE_HSM_RIM_LEN);
    if (ret != EOK) {
        tloge("move rim info fail, 0x%x\n", ret);
        return TEE_ERROR_BAD_STATE;
    }

    ret = memcpy_s(rim_update_info + TEE_HSM_RIM_LEN, TEE_HSM_ROOTKEY_LEN, root_key, TEE_HSM_ROOTKEY_LEN);
    if (ret != EOK) {
        tloge("move root key fail, 0x%x\n", ret);
        return TEE_ERROR_BAD_STATE;
    }

    ret = TEE_HSM_Power_On(dev_id);
    if (ret != TEE_SUCCESS) {
        tloge("efuse power on in rim fail, 0x%x.\n", ret);
        return ret;
    }

    ret = TEE_HSM_RIM_UpDate(dev_id, rim_update_info, TEE_HSM_RIM_INFO_LEN);
    if (ret != TEE_SUCCESS) {
        tloge("tee rim update fail, 0x%x.\n", ret);
        goto exit;
    }

exit:
    ret1 = TEE_HSM_Power_Off(dev_id);
    if (ret1 != TEE_SUCCESS) {
        tloge("efuse power off in rim fail, 0x%x.\n", ret);
        return ret1;
    }

    return ret; /* return nv burn failed results. */
}

/* get flash basic info, such as flash model_name and deviceID */
uint32_t sec_img_info_get(uint32_t dev_id, uint32_t flash_index, uint8_t *buffer, uint32_t buffer_size)
{
    uint32_t ret;

    ret = img_info_get_para_check(dev_id, flash_index, buffer, buffer_size);
    if (ret != TEE_SUCCESS) {
        tloge("img info get para check fail, 0x%x.\n", ret);
        return ret;
    }

    ret = lib_secure_info_get(flash_index, buffer, &buffer_size, dev_id);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    return TEE_SUCCESS;
}

/* get the number of flash, the count is fixed to 1 currently */
uint32_t sec_img_count_get(uint32_t dev_id, uint32_t *count)
{
    uint32_t ret;

    ret = firmware_dev_id_verify(dev_id);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    *count = 1; // current fixed to 0x1

    return TEE_SUCCESS;
}

/* get the version number of the image in flash */
uint32_t sec_img_version_get(uint32_t dev_id, uint32_t img_id, uint8_t *buffer,
    uint32_t buffer_size, uint32_t area_check)
{
    uint32_t ret;

    ret = img_version_get_para_check(dev_id, img_id, buffer, buffer_size, area_check);
    if (ret != TEE_SUCCESS) {
        tloge("img version get para check fail, 0x%x.\n", ret);
        return ret;
    }

    ret = lib_secure_version_get(img_id, buffer, buffer_size, dev_id, area_check);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    return TEE_SUCCESS;
}

/* read the ufs count info in L3 sram */
uint32_t sec_ufs_cnt_read(uint32_t dev_id, uint32_t *out_value)
{
    uint32_t ret;

    ret = firmware_dev_id_verify(dev_id);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    ret = lib_secure_ufs_cnt_read(out_value, dev_id);
    if (ret != TEE_SUCCESS) {
        tloge("ufs cnt write fail, 0x%x.\n", ret);
        return ret;
    }

    return TEE_SUCCESS;
}

/* modify the ufs count info in L3 sram */
uint32_t sec_ufs_cnt_write(uint32_t dev_id, uint32_t in_value)
{
    uint32_t ret;

    ret = firmware_dev_id_verify(dev_id);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    ret = lib_secure_ufs_cnt_write(in_value, dev_id);
    if (ret != TEE_SUCCESS) {
        tloge("ufs cnt write fail, 0x%x.\n", ret);
        return ret;
    }

    return TEE_SUCCESS;
}

/* reset the flash resetcnt count */
uint32_t sec_cnt_clear(uint32_t dev_id)
{
    uint32_t ret;
    uint32_t boot_cnt_get;
    uint32_t boot_cnt_set;

    ret = firmware_dev_id_verify(dev_id);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    ret = sec_get_reset_count(dev_id, &boot_cnt_get);
    if (ret != TEE_SUCCESS) {
        tloge("get flash reset cnt fail, 0x%x.\n", ret);
        return ret;
    }

    boot_cnt_set = ((boot_cnt_get % TEE_HSM_MAX_CNT) < TEE_HSM_BAK_CNT) ? TEE_HSM_MASTER_CNT : TEE_HSM_BAK_CNT;

    ret = sec_set_reset_count(dev_id, &boot_cnt_set);
    if (ret != TEE_SUCCESS) {
        tloge("set reset cnt fail, 0x%x\n", ret);
        return ret;
    }

    return TEE_SUCCESS;
}

/* get boot partitions info of img */
uint32_t get_cmdline_info(uint32_t dev_id, uint32_t *buf, uint32_t len)
{
    uint32_t ret;

    ret = firmware_dev_id_verify(dev_id);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    ret = lib_get_cmdline_info(dev_id, buf, len);
    if (ret != TEE_SUCCESS) {
        tloge("get cmdline failed, 0x%x.\n", ret);
        return ret;
    }

    return TEE_SUCCESS;
}

uint32_t get_efuse_nvcnt(uint32_t dev_id, uint8_t *buf, uint32_t buf_size)
{
    uint32_t ret;
    uint8_t buffer[EFUSE_NVCNT_LEN_4BYTES] = {0};

    ret = firmware_dev_id_verify(dev_id);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    ret = lib_get_efuse_nvcnt((uint32_t *)buffer, EFUSE_NVCNT_LEN_4BYTES, dev_id);
    if (ret != TEE_SUCCESS) {
        tloge("get efuse nvcnt failed, 0x%x.\n", ret);
        return ret;
    }

    ret = (uint32_t)memcpy_s(buf, buf_size, buffer, EFUSE_NVCNT_LEN_4BYTES);
    if (ret != EOK) {
        tloge("copy data back failed, 0x%x\n", ret);
        return TEE_ERROR_BAD_STATE;
    }

    return TEE_SUCCESS;
}

uint32_t sec_recovery_cnt_reset(uint32_t dev_id)
{
    uint32_t ret;

    ret = firmware_dev_id_verify(dev_id);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    ret = lib_secure_recovery_cnt_write(dev_id);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    return TEE_SUCCESS;
}