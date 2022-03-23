/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: tee drv demux function impl
 * Author: SDK
 * Create: 2019-10-11
 */

#include "hi_type_dev.h"
#include "hi_tee_drv_klad.h"
#include "hi_tee_drv_keyslot.h"
#include "hi_tee_drv_ssm.h"

#include "tee_drv_demux_func.h"
#include "tee_drv_demux_config.h"
#include "tee_drv_demux_define.h"
#include "tee_drv_demux_utils.h"
#include "tee_drv_demux_ioctl.h"
#include "tee_hal_demux.h"
#include "tee_drv_demux_index.h"
#include "tee_drv_keyslot_struct.h"
#include "hi_bitmap.h"

static tee_dmx_mgmt *g_tee_dmx_mgmt_ptr = HI_NULL;

static dmx_ioctl_entry g_dmx_func_entry_map[] = {
    { DMX_TEE_IOCTL_GLB_INIT, tee_drv_dmx_init },
    { DMX_TEE_IOCTL_GLB_DEINIT, tee_drv_dmx_deinit },
    { DMX_TEE_IOCTL_GLB_CREATE_RAMPORT, tee_drv_dmx_create_ramport },
    { DMX_TEE_IOCTL_GLB_DESTROY_RAMPORT, tee_drv_dmx_destroy_ramport },
    { DMX_TEE_IOCTL_GLB_SET_RAMPORT_DSC, tee_drv_dmx_set_ramport_dsc },
    { DMX_TEE_IOCTL_GLB_CREATE_PLAY_CHAN, tee_drv_dmx_create_play_chan },
    { DMX_TEE_IOCTL_GLB_DESTROY_PLAY_CHAN, tee_drv_dmx_destroy_play_chan },
    { DMX_TEE_IOCTL_GLB_ATTACH_PLAY_CHAN, tee_drv_dmx_attach_play_chan },
    { DMX_TEE_IOCTL_GLB_DETACH_PLAY_CHAN, tee_drv_dmx_detach_play_chan },
    { DMX_TEE_IOCTL_GLB_CREATE_REC_CHAN, tee_drv_dmx_create_rec_chan },
    { DMX_TEE_IOCTL_GLB_DESTROY_REC_CHAN, tee_drv_dmx_destroy_rec_chan },
    { DMX_TEE_IOCTL_GLB_ATTACH_REC_CHAN, tee_drv_dmx_attach_rec_chan },
    { DMX_TEE_IOCTL_GLB_DETACH_REC_CHAN, tee_drv_dmx_detach_rec_chan },
    { DMX_TEE_IOCTL_GLB_UPDATE_PLAY_READ_IDX, tee_drv_dmx_update_play_read_idx },
    { DMX_TEE_IOCTL_GLB_UPDATE_REC_READ_IDX, tee_drv_dmx_update_rec_read_idx },
    { DMX_TEE_IOCTL_GLB_ACQUIRE_SECBUF_ID, tee_drv_dmx_acquire_buf_id },
    { DMX_TEE_IOCTL_GLB_RELEASE_SECBUF_ID, tee_drv_dmx_release_buf_id },
    { DMX_TEE_IOCTL_GLB_DETACH_RAW_PIDCH, tee_drv_dmx_detach_raw_pidch },
    { DMX_TEE_IOCTL_GLB_CONFIG_SECBUF, tee_drv_dmx_config_sebuf },
    { DMX_TEE_IOCTL_GLB_DECONFIG_SECBUF, tee_drv_dmx_deconfig_secbuf },
    { DMX_TEE_IOCTL_GLB_ENABLE_REC_CHAN, tee_drv_dmx_enable_rec_chan },
    { DMX_TEE_IOCTL_GLB_FIXUP_HEVC_INDEX, tee_drv_dmx_fixup_hevc_index},
    { DMX_TEE_IOCTL_GLB_FLUSH_PES_SEC_DATA, tee_drv_dmx_sec_pes_flush_shadow_buf },
    { DMX_TEE_IOCTL_GLB_FLT_PES_SEC_LOCK, tee_drv_dmx_flt_sec_pes_lock },
    { DMX_TEE_IOCTL_GLB_CONFIG_CC_DROP_INFO, tee_drv_dmx_config_cc_drop_info },

    { DMX_TEE_IOCTL_GLB_DSCFCT_CREATE, tee_drv_dmx_dsc_create },
    { DMX_TEE_IOCTL_GLB_DSCFCT_GETATTRS, tee_drv_dmx_dsc_get_attr },
    { DMX_TEE_IOCTL_GLB_DSCFCT_SETATTRS, tee_drv_dmx_dsc_set_attr },
    { DMX_TEE_IOCTL_GLB_DSCFCT_ATTACH, tee_drv_dmx_dsc_attach_pid_chan },
    { DMX_TEE_IOCTL_GLB_DSCFCT_DETACH, tee_drv_dmx_dsc_detach_pid_chan },
    { DMX_TEE_IOCTL_GLB_DSCFCT_ATTACH_KEYSLOT, tee_drv_dmx_dsc_attach_keyslot },
    { DMX_TEE_IOCTL_GLB_DSCFCT_DETACH_KEYSLOT, tee_drv_dmx_dsc_detach_keyslot },
    { DMX_TEE_IOCTL_GLB_DSCFCT_GET_KS_HANDLE, tee_drv_dmx_dsc_get_keyslot_handle },
    { DMX_TEE_IOCTL_GLB_DSCFCT_SET_KEY, tee_drv_dmx_dsc_set_sys_key },
    { DMX_TEE_IOCTL_GLB_DSCFCT_SET_EVEN_IV, tee_drv_dmx_dsc_set_even_iv_key },
    { DMX_TEE_IOCTL_GLB_DSCFCT_SET_ODD_IV, tee_drv_dmx_dsc_set_odd_iv_key },
    { DMX_TEE_IOCTL_GLB_DSCFCT_DESTROY, tee_drv_dmx_dsc_destroy },
    { DMX_TEE_IOCTL_GLB_DSCFCT_GET_KEY_HANDLE, tee_drv_dmx_dsc_get_handle },
    { DMX_TEE_IOCTL_GLB_DSCFCT_GET_CHAN_HANDLE, tee_drv_dmx_dsc_get_chan_handle }
};

static tee_dmx_mgmt g_tee_dmx_mgmt = {
    .io_base = DMX_REGS_BASE,
    .io_mdsc_base = DMX_REGS_MDSC_BASE,
    .dmx_info = {
        [0 ... (DMX_CNT - 1)] = {
            .ramport_id = DMX_INVALID_PORT_ID,
        },
    },

    .play_ts = {
        [0 ... (DMX_PLAY_TS_CNT - 1)] = {
            .dmx_id = DMX_CNT,
            .key_id = DMX_INVALID_KEY_ID,
            .ts_secbuf = {
                0,
            }
        },
    },

    .play_pes_sec = {
        [0 ... (DMX_PLAY_SEC_PES_CNT - 1)] = {
            .dmx_id = DMX_CNT,
            .key_id = DMX_INVALID_KEY_ID,
            .pes_sec_secbuf = {
                0,
            }
        },
    },

    .play_avpes = {
        [0 ... (DMX_AVR_CNT - 1)] = {
            .dmx_id = DMX_CNT,
            .key_id = DMX_INVALID_KEY_ID,
            .dmx_play_type = DMX_CHAN_TYPE_MAX,
            .avpes_secbuf = {
                0,
            }
        },
    },

    .rec_info = {
        [0 ... (DMX_AVR_CNT - 1)] = {
            .dmx_id = DMX_CNT,
            .rec_secbuf = {
                0,
            }
        },
    },

    .key_info = {
        [0 ... (DMX_KEY_CNT - 1)] = {
            .dmx_id = DMX_CNT,
            .key_id = DMX_INVALID_KEY_ID,
        },
    },

    .ramport_info = {
        [0 ... (DMX_RAMPORT_CNT - 1)] = {
            .tsbuf_secbuf = {
                0,
            }
        },
    },
    .dmx_cnt              = DMX_CNT,
    .ramport_cnt          = DMX_RAMPORT_CNT,
    .play_ts_cnt          = DMX_PLAY_TS_CNT,
    .play_pes_sec_cnt     = DMX_PLAY_SEC_PES_CNT,
    .avr_cnt              = DMX_AVR_CNT,
    .key_cnt              = DMX_KEY_CNT,
    .buf_cnt              = DMX_BUF_CNT,
    .dmx_pid_copy_cnt     = DMX_PID_COPY_CNT,
    .dmx_raw_pidch_cnt    = DMX_RAW_PIDCH_CNT,
    .dmx_scd_cnt          = DMX_SCD_CNT,
    .dmx_ioctl_entry      = HI_NULL,
};

#define TS_PKT_LEN 188
#define TS_PKT_HEADER_LEN 4
#define PES_PKT_HEADER_LENGTH 9

#define HEVC_DATA_OF_SC_OFFSET 4   /* 00 00 01 xx */
#define HEVC_DATA_OF_SC_TOTAL_LEN 256 /* keep sync with new chipset */
#define HEVC_DATA_OF_SC_SAVED_LEN 8  /* this bytes has saved in PVR_SCDDmxIdxToPvrIdx. */

#define HEVC_DUP_DATA_CMP_LEN (HEVC_DATA_OF_SC_OFFSET + HEVC_DATA_OF_SC_SAVED_LEN)
#define HEVC_DUP_DATA_TOTAL_LEN (HEVC_DATA_OF_SC_OFFSET + HEVC_DATA_OF_SC_TOTAL_LEN)
static hi_s32 dmx_get_user_uuid(TEE_UUID *pst_uuid)
{
    dmx_null_pointer_return(pst_uuid);

    return hi_tee_drv_hal_current_uuid(pst_uuid);
}

/* create a ts packet with and a pid of 0x20 */
static void create_ts_packet(hi_u8 *buf, hi_u32 pid)
{
    *(buf++) = TS_SYNC_BYTE; /* Set ts sync byte to 0x47 */
    *(buf++) = (pid >> 0x8U) & 0x1F; /* Set the upper five digits of the PID to 0x00 */
    *(buf++) = pid & 0xFF; /* Set the lower eight bits of the PID to 0x20 */
}

static hi_void _dmx_buf_fill_ts_stream(hi_u8 *buf, hi_u32 len, hi_u32 pid)
{
    hi_s32 ret;
    hi_u32 i;

    ret = memset_s(buf, len, 0x0, len);
    if (ret != EOK) {
        hi_log_err("call memset_s failed. ret = 0x%x\n", ret);
        return;
    }
    for (i = 0x0; i < len / DMX_TS_PKT_SIZE; i++) {
        create_ts_packet(buf + i * DMX_TS_PKT_SIZE, pid);
    }
}

static hi_s32 _dmx_alloc_ts_buf_impl(hi_u32 ram_id, hi_u32 buf_size, dmx_ramport_info *ramport_info,
    dmx_tee_ramport_info *tee_ramport_info)
{
    hi_s32 ret;

    hi_char buf_name[DMX_STR_LEN_16] = {0};
    hi_u8 *buf_vir_addr = HI_NULL;
    hi_ulong buf_phy_addr;

    /* alloc ts buf */
    ret = snprintf_s(buf_name, sizeof(buf_name), sizeof(buf_name) - 1, "dmx_tsbuf[%d]", ram_id);
    if (ret == -1) {
        hi_log_err("snprintf_s failed!\n");
        return HI_TEE_ERR_MEM;
    }

    ret = dmx_alloc_and_map_secbuf(buf_name, DMX_STR_LEN_16, buf_size, &buf_phy_addr, &buf_vir_addr);
    if (ret != HI_SUCCESS) {
        hi_log_err("dmx_alloc_and_map_secbuf failed!\n");
        return HI_TEE_ERR_MEM;
    }
    tee_ramport_info->buf_size = buf_size;
    tee_ramport_info->buf_phy_addr = (hi_u64)buf_phy_addr;
    ramport_info->tsbuf_secbuf.buf_phy_addr = (hi_u64)buf_phy_addr;
    ramport_info->tsbuf_secbuf.buf_vir_addr = buf_vir_addr;
    ramport_info->tsbuf_secbuf.buf_size = buf_size;

    /* tmp for test of secure ramport */
    _dmx_buf_fill_ts_stream(buf_vir_addr, buf_size, 0x20);  /* set pid as 0x20 */

    return ret;
}

static hi_void _dmx_free_ts_buf_impl(const dmx_ramport_info *ramport_info)
{
    hi_s32 ret;

    ret = dmx_unmap_and_free_secbuf(ramport_info->tsbuf_secbuf.buf_size,
                                    ramport_info->tsbuf_secbuf.buf_phy_addr,
                                    ramport_info->tsbuf_secbuf.buf_vir_addr);
    if (ret != HI_SUCCESS) {
        hi_log_err("dmx_unmap_and_free_secbuf failed!\n");
    }

    return;
}

static hi_s32 _dmx_alloc_flush_buf_impl(hi_u32 ram_id, hi_u32 flush_buf_size, dmx_ramport_info *ramport_info,
    dmx_tee_ramport_info *tee_ramport_info)
{
    hi_s32 ret;

    hi_char buf_name[DMX_STR_LEN_16] = {0};
    hi_u8 *flush_buf_vir_addr = HI_NULL;
    hi_ulong flush_buf_phy_addr;

    /* alloc tee flush buf */
    ret = snprintf_s(buf_name, sizeof(buf_name), sizeof(buf_name) - 1, "dmx_flushbuf[%d]", ram_id);
    if (ret == -1) {
        hi_log_err("snprintf_s failed!\n");
        return HI_TEE_ERR_MEM;
    }

    ret = dmx_alloc_and_map_secbuf(buf_name, DMX_STR_LEN_16, flush_buf_size, &flush_buf_phy_addr, &flush_buf_vir_addr);
    if (ret != HI_SUCCESS) {
        hi_log_err("dmx_alloc_and_map_secbuf failed!\n");
        return HI_TEE_ERR_MEM;
    }
    tee_ramport_info->flush_buf_size = flush_buf_size;
    tee_ramport_info->flush_buf_phy_addr = (hi_u64)flush_buf_phy_addr;
    ramport_info->tsbuf_secbuf.flush_buf_phy_addr = (hi_u64)flush_buf_phy_addr;
    ramport_info->tsbuf_secbuf.flush_buf_vir_addr = flush_buf_vir_addr;
    ramport_info->tsbuf_secbuf.flush_buf_size = flush_buf_size;

    /* filled the flush buffer with all 0x47 */
    ret = memset_s(flush_buf_vir_addr, flush_buf_size, 0x47, flush_buf_size);
    if (ret != EOK) {
        hi_log_err("call memset_s failed. ret = 0x%x\n", ret);
        return ret;
    }

    return ret;
}

static hi_void _dmx_free_flush_buf_impl(const dmx_ramport_info *ramport_info)
{
    hi_s32 ret;

    ret = dmx_unmap_and_free_secbuf(ramport_info->tsbuf_secbuf.flush_buf_size,
                                    ramport_info->tsbuf_secbuf.flush_buf_phy_addr,
                                    ramport_info->tsbuf_secbuf.flush_buf_vir_addr);
    if (ret != HI_SUCCESS) {
        hi_log_err("dmx_unmap_and_free_secbuf failed!\n");
    }

    return;
}

static hi_s32 _dmx_alloc_dsc_buf_impl(hi_u32 ram_id, hi_u32 dsc_buf_size, dmx_ramport_info *ramport_info,
    dmx_tee_ramport_info *tee_ramport_info)
{
    hi_s32 ret;

    hi_char buf_name[DMX_STR_LEN_16] = {0};
    hi_u8 *dsc_buf_vir_addr = HI_NULL;
    hi_ulong dsc_buf_phy_addr;

    /* alloc tee dsc buf */
    ret = snprintf_s(buf_name, sizeof(buf_name), sizeof(buf_name) - 1, "dmx_dscbuf[%d]", ram_id);
    if (ret == -1) {
        hi_log_err("snprintf_s failed!\n");
        return HI_TEE_ERR_MEM;
    }

    ret = dmx_alloc_and_map_secbuf(buf_name, DMX_STR_LEN_16, dsc_buf_size, &dsc_buf_phy_addr, &dsc_buf_vir_addr);
    if (ret != HI_SUCCESS) {
        hi_log_err("dmx_alloc_and_map_secbuf failed!\n");
        return HI_TEE_ERR_MEM;
    }

    tee_ramport_info->dsc_buf_size = dsc_buf_size;
    tee_ramport_info->dsc_buf_phy_addr = (hi_u64)dsc_buf_phy_addr;
    ramport_info->tsbuf_secbuf.dsc_buf_phy_addr = (hi_u64)dsc_buf_phy_addr;
    ramport_info->tsbuf_secbuf.dsc_buf_vir_addr = dsc_buf_vir_addr;
    ramport_info->tsbuf_secbuf.dsc_buf_size = dsc_buf_size;

    return ret;
}

hi_s32 dmx_create_ramport_impl(hi_u32 ram_id, hi_u32 buf_size, hi_u32 flush_buf_size, hi_u32 dsc_buf_size,
    dmx_tee_ramport_info *tee_ramport_info)
{
    hi_s32 ret;

    tee_dmx_mgmt *tee_dmx_mgmt_ptr = get_dmx_mgmt();
    dmx_ramport_info *local_ramport_info = HI_NULL;

    dmx_null_pointer_return(tee_ramport_info);

    /* check the ram_id valid */
    if (!(ram_id < tee_dmx_mgmt_ptr->ramport_cnt)) {
        hi_log_err("ram id invalid!\n");
        ret = HI_ERR_DMX_INVALID_PARA;
        goto out;
    }

    local_ramport_info = &tee_dmx_mgmt_ptr->ramport_info[ram_id];
    demux_mutex_lock(&local_ramport_info->lock_ramport);

    ret = _dmx_alloc_ts_buf_impl(ram_id, buf_size, local_ramport_info, tee_ramport_info);
    if (ret != HI_SUCCESS) {
        hi_log_err("tsbuf malloc 0x%x failed\n", buf_size);
        goto unlock;
    }

    ret = _dmx_alloc_flush_buf_impl(ram_id, flush_buf_size, local_ramport_info, tee_ramport_info);
    if (ret != HI_SUCCESS) {
        hi_log_err("flushbuf malloc 0x%x failed\n", flush_buf_size);
        goto free_tsbuf;
    }

    ret = _dmx_alloc_dsc_buf_impl(ram_id, dsc_buf_size, local_ramport_info, tee_ramport_info);
    if (ret != HI_SUCCESS) {
        hi_log_err("dscbuf malloc 0x%x failed\n", dsc_buf_size);
        goto free_flushbuf;
    }

    local_ramport_info->ramport_id = ram_id;
    /* enable the secure attr of ramport */
    tee_dmx_hal_ram_set_sec_attrs(tee_dmx_mgmt_ptr, ram_id, HI_TRUE);
    tee_dmx_hal_ram_port_set_desc(tee_dmx_mgmt_ptr, ram_id, local_ramport_info->tsbuf_secbuf.dsc_buf_phy_addr,
                                  DEFAULT_RAM_DSC_DEPTH);
    tee_dmx_hal_ram_clr_mmu_cache(tee_dmx_mgmt_ptr, ram_id);
    demux_mutex_unlock(&local_ramport_info->lock_ramport);

    demux_mutex_lock(&tee_dmx_mgmt_ptr->lock_all_ramport);
    bitmap_setbit(ram_id, tee_dmx_mgmt_ptr->ramport_bitmap);
    demux_mutex_unlock(&tee_dmx_mgmt_ptr->lock_all_ramport);

    return ret;

free_flushbuf:
    _dmx_free_flush_buf_impl(local_ramport_info);
free_tsbuf:
    _dmx_free_ts_buf_impl(local_ramport_info);
unlock:
    demux_mutex_unlock(&local_ramport_info->lock_ramport);
out:
    return ret;
}

static hi_s32 _dmx_free_all_ramport_buf_impl(const dmx_ramport_info *ramport_info)
{
    hi_s32 ret;

    ret = dmx_unmap_and_free_secbuf(ramport_info->tsbuf_secbuf.buf_size,
                                    ramport_info->tsbuf_secbuf.buf_phy_addr,
                                    ramport_info->tsbuf_secbuf.buf_vir_addr);
    if (ret != HI_SUCCESS) {
        hi_log_err("dmx_unmap_and_free_secbuf failed!\n");
        ret = HI_TEE_ERR_MEM;
        goto out;
    }

    ret = dmx_unmap_and_free_secbuf(ramport_info->tsbuf_secbuf.flush_buf_size,
                                    ramport_info->tsbuf_secbuf.flush_buf_phy_addr,
                                    ramport_info->tsbuf_secbuf.flush_buf_vir_addr);
    if (ret != HI_SUCCESS) {
        hi_log_err("dmx_unmap_and_free_secbuf failed!\n");
        ret = HI_TEE_ERR_MEM;
        goto out;
    }

    ret = dmx_unmap_and_free_secbuf(ramport_info->tsbuf_secbuf.dsc_buf_size,
                                    ramport_info->tsbuf_secbuf.dsc_buf_phy_addr,
                                    ramport_info->tsbuf_secbuf.dsc_buf_vir_addr);
    if (ret != HI_SUCCESS) {
        hi_log_err("dmx_unmap_and_free_secbuf failed!\n");
        ret = HI_TEE_ERR_MEM;
        goto out;
    }

out:
    return ret;
}

hi_s32 dmx_destroy_ramport_impl(hi_u32 ram_id, const dmx_tee_ramport_info *tee_ramport_info)
{
    hi_s32 ret;

    unsigned long mask;
    unsigned long *p = HI_NULL;
    dmx_ramport_info *local_ramport_info = HI_NULL;
    tee_dmx_mgmt *tee_dmx_mgmt_ptr = get_dmx_mgmt();

    dmx_null_pointer_return(tee_ramport_info);

    /* check the ram_id valid */
    if (!(ram_id < tee_dmx_mgmt_ptr->ramport_cnt)) {
        hi_log_err("ram id invalid!\n");
        ret = HI_ERR_DMX_INVALID_PARA;
        goto out;
    }

    /* disable the secure attr of ramport */
    tee_dmx_hal_ram_port_set_desc(tee_dmx_mgmt_ptr, ram_id, 0, DEFAULT_RAM_DSC_DEPTH);
    tee_dmx_hal_ram_set_sec_attrs(tee_dmx_mgmt_ptr, ram_id, HI_FALSE);
    tee_dmx_hal_ram_clr_mmu_cache(tee_dmx_mgmt_ptr, ram_id);

    local_ramport_info = &tee_dmx_mgmt_ptr->ramport_info[ram_id];
    demux_mutex_lock(&local_ramport_info->lock_ramport);

    if (local_ramport_info->ramport_id != ram_id) {
        demux_mutex_unlock(&local_ramport_info->lock_ramport);
        hi_log_err("ram_id[0x%x] invalid!\n", ram_id);
        ret = HI_ERR_DMX_INVALID_PARA;
        goto out;
    }

    ret = _dmx_free_all_ramport_buf_impl(local_ramport_info);
    if (ret != HI_SUCCESS) {
        demux_mutex_unlock(&local_ramport_info->lock_ramport);
        hi_log_err("free ramport secure buffer failed!\n");
        goto out;
    }

    demux_mutex_unlock(&local_ramport_info->lock_ramport);

    /* clear the tam_id bit */
    demux_mutex_lock(&tee_dmx_mgmt_ptr->lock_all_ramport);
    mask = BIT_MASK(ram_id);
    p = ((unsigned long *)tee_dmx_mgmt_ptr->ramport_bitmap) + BIT_WORD(ram_id);
    if (!(*p & mask)) {
        demux_mutex_unlock(&tee_dmx_mgmt_ptr->lock_all_ramport);
        hi_log_err("ram_id(%d) is invalid.\n", ram_id);
        ret = HI_ERR_DMX_INVALID_PARA;
        goto out;
    }
    bitmap_clrbit(ram_id, tee_dmx_mgmt_ptr->ramport_bitmap);

    demux_mutex_unlock(&tee_dmx_mgmt_ptr->lock_all_ramport);

out:
    return ret;
}

static hi_void _dmx_ram_port_set_dsc(hi_u32 *dsc_vir_addr, const dmx_tee_ramport_dsc *tee_ramport_dsc)
{
    U_RAM_DSC_WORD_1 reg;

    reg.u32 = 0;
    reg.bits.iplength = tee_ramport_dsc->buf_len;
    reg.bits.desep = (tee_ramport_dsc->desep ? 1 : 0);            /* interrupt whe finish read the dsc */
    reg.bits.flush = (tee_ramport_dsc->flush_flag ? 1 : 0);        /* flush flag */
    reg.bits.syncdata = (tee_ramport_dsc->sync_data_flag ? 1 : 0);  /* sync 16 ts package flag */
    reg.bits.session = (tee_ramport_dsc->buf_phy_addr >> 32) & 0xF; /* right shift 32 bits get high 4 bit */
    reg.bits.check_data = RAM_DSC_GUIDE_NUMBER;   /* fixed guide number */

    *dsc_vir_addr++ = (hi_u32)(tee_ramport_dsc->buf_phy_addr & 0xFFFFFFFF);  /* RAM port dsc word 0, 32 bit */
    *dsc_vir_addr++ = reg.u32;                    /* RAM port dsc word 1 */
}

hi_s32 dmx_set_ramport_dsc_impl(hi_u32 ram_id, const dmx_tee_ramport_dsc *tee_ramport_dsc)
{
    hi_s32 ret;

    hi_u32 *cur_dsc_addr = HI_NULL;
    dmx_ramport_info *local_ramport_info = HI_NULL;
    tee_dmx_mgmt *tee_dmx_mgmt_ptr = get_dmx_mgmt();
    dmx_null_pointer_return(tee_ramport_dsc);

    /* check the ram_id valid */
    if (!(ram_id < tee_dmx_mgmt_ptr->ramport_cnt)) {
        hi_log_err("ram id invalid!\n");
        ret = HI_ERR_DMX_INVALID_PARA;
        goto out0;
    }

    local_ramport_info = &tee_dmx_mgmt_ptr->ramport_info[ram_id];
    demux_mutex_lock(&local_ramport_info->lock_ramport);

    cur_dsc_addr = (hi_u32 *)(local_ramport_info->tsbuf_secbuf.dsc_buf_vir_addr +
                   tee_ramport_dsc->write_index * DEFAULT_RAM_DSC_SIZE);
    dmx_null_pointer_goto(cur_dsc_addr, out1);

    _dmx_ram_port_set_dsc(cur_dsc_addr, tee_ramport_dsc);

    ret = HI_SUCCESS;

out1:
    demux_mutex_unlock(&local_ramport_info->lock_ramport);
out0:
    return ret;
}

static hi_void _create_play_chan_config_ts(hi_u32 id, const dmx_playbuf_info *mem_info)
{
    tee_dmx_mgmt *tee_dmx_mgmt_ptr = get_dmx_mgmt();

    dmx_err_condition_return(id >= tee_dmx_mgmt_ptr->play_ts_cnt, HI_ERR_DMX_INVALID_PARA);
    tee_dmx_mgmt_ptr->play_ts[id].ts_secbuf.buf_id = mem_info->buf_id;
    tee_dmx_mgmt_ptr->play_ts[id].ts_secbuf.buf_size = mem_info->buf_size;
    tee_dmx_mgmt_ptr->play_ts[id].ts_secbuf.buf_start_addr = mem_info->buf_start_addr;
    tee_dmx_mgmt_ptr->play_ts[id].ts_secbuf.buf_start_vir_addr = mem_info->buf_start_vir_addr;

    demux_mutex_lock(&tee_dmx_mgmt_ptr->lock_all_play_ts);
    bitmap_setbit(id, tee_dmx_mgmt_ptr->play_ts_bitmap);
    demux_mutex_unlock(&tee_dmx_mgmt_ptr->lock_all_play_ts);

    return;
}

static hi_void _create_play_chan_config_sec_pes(hi_u32 id, dmx_chan_type chan_type, const dmx_playbuf_info *mem_info)
{
    tee_dmx_mgmt *tee_dmx_mgmt_ptr = get_dmx_mgmt();

    dmx_err_condition_return(id >= tee_dmx_mgmt_ptr->play_pes_sec_cnt, HI_ERR_DMX_INVALID_PARA);
    tee_dmx_mgmt_ptr->play_pes_sec[id].pes_sec_secbuf.buf_id = mem_info->buf_id;
    tee_dmx_mgmt_ptr->play_pes_sec[id].pes_sec_secbuf.buf_size = mem_info->buf_size;
    tee_dmx_mgmt_ptr->play_pes_sec[id].pes_sec_secbuf.buf_start_addr = mem_info->buf_start_addr;
    tee_dmx_mgmt_ptr->play_pes_sec[id].pes_sec_secbuf.buf_start_vir_addr = mem_info->buf_start_vir_addr;
    tee_dmx_mgmt_ptr->play_pes_sec[id].dmx_play_type = chan_type;
    tee_dmx_mgmt_ptr->play_pes_sec[id].pes_sec_secbuf.shadow_buf_start_addr = mem_info->shadow_buf_start_addr;
    tee_dmx_mgmt_ptr->play_pes_sec[id].pes_sec_secbuf.shadow_buf_start_vir_addr = mem_info->shadow_buf_start_vir_addr;
    tee_dmx_mgmt_ptr->play_pes_sec[id].pes_sec_secbuf.shadow_buf_size = mem_info->shadow_buf_size;

    demux_mutex_lock(&tee_dmx_mgmt_ptr->lock_all_play_pes_sec);
    bitmap_setbit(id, tee_dmx_mgmt_ptr->play_pes_sec_bitmap);
    demux_mutex_unlock(&tee_dmx_mgmt_ptr->lock_all_play_pes_sec);

    return;
}

static hi_void _create_play_chan_config_aud_vid(hi_u32 id, dmx_chan_type chan_type, const dmx_playbuf_info *mem_info)
{
    tee_dmx_mgmt *tee_dmx_mgmt_ptr = get_dmx_mgmt();

    dmx_err_condition_return(id >= tee_dmx_mgmt_ptr->avr_cnt, HI_ERR_DMX_INVALID_PARA);
    tee_dmx_mgmt_ptr->play_avpes[id].avpes_secbuf.buf_id = mem_info->buf_id;
    tee_dmx_mgmt_ptr->play_avpes[id].avpes_secbuf.buf_size = mem_info->buf_size;
    tee_dmx_mgmt_ptr->play_avpes[id].avpes_secbuf.buf_start_addr = mem_info->buf_start_addr;
    tee_dmx_mgmt_ptr->play_avpes[id].avpes_secbuf.buf_start_vir_addr = mem_info->buf_start_vir_addr;
    tee_dmx_mgmt_ptr->play_avpes[id].dmx_play_type = chan_type;

    demux_mutex_lock(&tee_dmx_mgmt_ptr->lock_all_avr);
    bitmap_setbit(id, tee_dmx_mgmt_ptr->play_pes_sec_bitmap);
    demux_mutex_unlock(&tee_dmx_mgmt_ptr->lock_all_avr);

    return;
}

static hi_s32 _create_play_chan(hi_u32 id, dmx_chan_type chan_type, const dmx_playbuf_info *mem_info)
{
    switch (chan_type) {
        case DMX_CHAN_TYPE_TS: {
            _create_play_chan_config_ts(id, mem_info);
            return HI_SUCCESS;
        }

        case DMX_CHAN_TYPE_SEC:
        case DMX_CHAN_TYPE_PES: {
            _create_play_chan_config_sec_pes(id, chan_type, mem_info);
            return HI_SUCCESS;
        }

        case DMX_CHAN_TYPE_AUD:
        case DMX_CHAN_TYPE_VID: {
            _create_play_chan_config_aud_vid(id, chan_type, mem_info);
            return HI_SUCCESS;
        }

        default: {
            hi_log_err("Invalid chan_type[0x%x]\n", chan_type);
            return HI_ERR_DMX_INVALID_PARA;
        }
    }
}

static hi_s32 _dmx_create_play_chan_buf(hi_u32 buf_id, hi_u32 buf_size, hi_ulong *buf_smmu_addr, hi_u8 **buf_vir_addr)
{
    hi_s32 ret;
    hi_char buf_name[16] = {0}; /* 16 bytes size */

    if (snprintf_s(buf_name, sizeof(buf_name), sizeof(buf_name) - 1, "dmx_sec_avr[%d]", buf_id) < 0) {
        hi_log_err("snprintf_s failed!\n");
        return HI_FAILURE;
    }

    ret = dmx_alloc_and_map_secbuf(buf_name, DMX_STR_LEN_16, buf_size, buf_smmu_addr, buf_vir_addr);
    if (ret != HI_SUCCESS) {
        hi_log_err("dmx_alloc_and_map_secbuf failed!\n");
        return ret;
    }

    return HI_SUCCESS;
}

static hi_s32 _dmx_map_shadow_buffer(dmx_chan_type chan_type, dmx_tee_mem_swap_info *mem_info,
    dmx_playbuf_info *playbuf_info)
{
    hi_s32 ret;

    if ((chan_type != DMX_CHAN_TYPE_SEC) && (chan_type != DMX_CHAN_TYPE_PES)) {
        return HI_SUCCESS;
    }

    ret = dmx_map_shadow_buffer((hi_ulong)mem_info->shadow_buf_start_addr, mem_info->shadow_buf_size,
        &(playbuf_info->shadow_buf_start_vir_addr));
    if (ret != HI_SUCCESS) {
        hi_log_err("map shadow buffer failed!\n");
        return ret;
    }

    playbuf_info->shadow_buf_size = mem_info->shadow_buf_size;
    playbuf_info->shadow_buf_start_addr = mem_info->shadow_buf_start_addr;
    playbuf_info->flush_shadow_buf = HI_FALSE;

    return HI_SUCCESS;
}

static hi_s32 _dmx_unmap_shadow_buffer(dmx_chan_type chan_type, dmx_playbuf_info *mem_info)
{
    hi_s32 ret;

    if ((chan_type != DMX_CHAN_TYPE_SEC) && (chan_type != DMX_CHAN_TYPE_PES)) {
        return HI_SUCCESS;
    }

    ret = dmx_unmap_shadow_buffer((hi_ulong)mem_info->shadow_buf_start_addr, mem_info->shadow_buf_size,
        mem_info->shadow_buf_start_vir_addr);
    if (ret != HI_SUCCESS) {
        hi_log_err("unmap shadow buffer failed!\n");
        return ret;
    }

    return HI_SUCCESS;
}

/* feature function */
hi_s32 dmx_create_play_chan_impl(hi_u32 id, dmx_chan_type chan_type, hi_u32 buf_size, dmx_tee_mem_swap_info *mem_info)
{
    hi_s32 ret;
    hi_u32 buf_id;
    dmx_playbuf_info play_mem_info = {0};
    hi_ulong buf_smmu_addr;
    tee_dmx_mgmt *tee_dmx_mgmt_ptr = get_dmx_mgmt();

    dmx_null_pointer_return(mem_info);

    demux_mutex_lock(&tee_dmx_mgmt_ptr->lock_all_buf);
    buf_id = find_first_zero_bit(tee_dmx_mgmt_ptr->buf_bitmap, tee_dmx_mgmt_ptr->buf_cnt);
    if (!(buf_id < tee_dmx_mgmt_ptr->buf_cnt)) {
        demux_mutex_unlock(&tee_dmx_mgmt_ptr->lock_all_buf);
        hi_log_err("there is no available buf id now!\n");
        return HI_ERR_DMX_NO_RESOURCE;
    }

    bitmap_setbit(buf_id, tee_dmx_mgmt_ptr->buf_bitmap);
    demux_mutex_unlock(&tee_dmx_mgmt_ptr->lock_all_buf);

    ret = _dmx_create_play_chan_buf(buf_id, buf_size, &buf_smmu_addr, &play_mem_info.buf_start_vir_addr);
    if (ret != HI_SUCCESS) {
        goto clr_bufbit;
    }

    /* record the play channel */
    play_mem_info.buf_id = buf_id;
    play_mem_info.buf_size = buf_size;
    play_mem_info.buf_start_addr = buf_smmu_addr;

    ret = _dmx_map_shadow_buffer(chan_type, mem_info, &play_mem_info);
    if (ret != HI_SUCCESS) {
        goto free_secbuf;
    }

    ret = _create_play_chan(id, chan_type, &play_mem_info);
    if (ret != HI_SUCCESS) {
        goto umap_shadow_buf;
    }

    /* configure the secure buffer register */
    tee_dmx_hal_buf_config(tee_dmx_mgmt_ptr, buf_id, buf_smmu_addr, buf_size);

    mem_info->buf_id = buf_id;
    mem_info->buf_phy_addr = buf_smmu_addr;
    mem_info->buf_size = buf_size;

    return HI_SUCCESS;
umap_shadow_buf:
    if (_dmx_unmap_shadow_buffer(chan_type, &play_mem_info) != HI_SUCCESS) {
        hi_log_err("unmap shadow buffer failed!\n");
    }
free_secbuf:
    dmx_unmap_and_free_secbuf(buf_size, buf_smmu_addr, play_mem_info.buf_start_vir_addr);
clr_bufbit:
    demux_mutex_lock(&tee_dmx_mgmt_ptr->lock_all_buf);
    bitmap_clrbit(buf_id, tee_dmx_mgmt_ptr->buf_bitmap);
    demux_mutex_unlock(&tee_dmx_mgmt_ptr->lock_all_buf);
    return ret;
}

static hi_s32 _destroy_play_chan_proc_ts_chn(hi_u32 id, dmx_playbuf_info *mem_info)
{
    hi_s32 ret;
    tee_dmx_mgmt *tee_dmx_mgmt_ptr = get_dmx_mgmt();

    dmx_err_condition_return(id >= tee_dmx_mgmt_ptr->play_ts_cnt, HI_ERR_DMX_INVALID_PARA);
    mem_info->buf_id = tee_dmx_mgmt_ptr->play_ts[id].ts_secbuf.buf_id;
    mem_info->buf_size = tee_dmx_mgmt_ptr->play_ts[id].ts_secbuf.buf_size;
    mem_info->buf_start_addr = tee_dmx_mgmt_ptr->play_ts[id].ts_secbuf.buf_start_addr;
    mem_info->buf_start_vir_addr = tee_dmx_mgmt_ptr->play_ts[id].ts_secbuf.buf_start_vir_addr;

    ret = memset_s(&tee_dmx_mgmt_ptr->play_ts[id], sizeof(dmx_playbuf_info), 0x0, sizeof(dmx_playbuf_info));
    if (ret != EOK) {
        hi_log_err("call meset_s failed. ret = 0x%x\n", ret);
        return ret;
    }

    demux_mutex_lock(&tee_dmx_mgmt_ptr->lock_all_play_ts);
    bitmap_clrbit(id, tee_dmx_mgmt_ptr->play_ts_bitmap);
    demux_mutex_unlock(&tee_dmx_mgmt_ptr->lock_all_play_ts);

    return HI_SUCCESS;
}

static hi_s32 _destroy_play_chan_proc_sec_or_pes_chn(hi_u32 id, dmx_playbuf_info *mem_info)
{
    hi_s32 ret;
    tee_dmx_mgmt *tee_dmx_mgmt_ptr = get_dmx_mgmt();

    dmx_err_condition_return(id >= tee_dmx_mgmt_ptr->play_pes_sec_cnt, HI_ERR_DMX_INVALID_PARA);
    mem_info->buf_id = tee_dmx_mgmt_ptr->play_pes_sec[id].pes_sec_secbuf.buf_id;
    mem_info->buf_size = tee_dmx_mgmt_ptr->play_pes_sec[id].pes_sec_secbuf.buf_size;
    mem_info->buf_start_addr = tee_dmx_mgmt_ptr->play_pes_sec[id].pes_sec_secbuf.buf_start_addr;
    mem_info->buf_start_vir_addr = tee_dmx_mgmt_ptr->play_pes_sec[id].pes_sec_secbuf.buf_start_vir_addr;
    mem_info->shadow_buf_start_addr = tee_dmx_mgmt_ptr->play_pes_sec[id].pes_sec_secbuf.shadow_buf_start_addr;
    mem_info->shadow_buf_size = tee_dmx_mgmt_ptr->play_pes_sec[id].pes_sec_secbuf.shadow_buf_size;
    mem_info->shadow_buf_start_vir_addr = tee_dmx_mgmt_ptr->play_pes_sec[id].pes_sec_secbuf.shadow_buf_start_vir_addr;

    ret = memset_s(&tee_dmx_mgmt_ptr->play_pes_sec[id], sizeof(dmx_playbuf_info), 0x0, sizeof(dmx_playbuf_info));
    if (ret != EOK) {
        hi_log_err("call meset_s failed. ret = 0x%x\n", ret);
        return ret;
    }
    tee_dmx_mgmt_ptr->play_pes_sec[id].dmx_play_type = DMX_CHAN_TYPE_MAX;

    demux_mutex_lock(&tee_dmx_mgmt_ptr->lock_all_play_pes_sec);
    bitmap_clrbit(id, tee_dmx_mgmt_ptr->play_pes_sec_bitmap);
    demux_mutex_unlock(&tee_dmx_mgmt_ptr->lock_all_play_pes_sec);

    return HI_SUCCESS;
}

static hi_s32 _destroy_play_chan_proc_vid_or_aud_chn(hi_u32 id, dmx_playbuf_info *mem_info)
{
    hi_s32 ret;
    tee_dmx_mgmt *tee_dmx_mgmt_ptr = get_dmx_mgmt();

    dmx_err_condition_return(id >= tee_dmx_mgmt_ptr->avr_cnt, HI_ERR_DMX_INVALID_PARA);
    mem_info->buf_id = tee_dmx_mgmt_ptr->play_avpes[id].avpes_secbuf.buf_id;
    mem_info->buf_size = tee_dmx_mgmt_ptr->play_avpes[id].avpes_secbuf.buf_size;
    mem_info->buf_start_addr = tee_dmx_mgmt_ptr->play_avpes[id].avpes_secbuf.buf_start_addr;
    mem_info->buf_start_vir_addr = tee_dmx_mgmt_ptr->play_avpes[id].avpes_secbuf.buf_start_vir_addr;

    tee_dmx_mgmt_ptr->play_avpes[id].dmx_play_type = DMX_CHAN_TYPE_MAX;
    ret = memset_s(&tee_dmx_mgmt_ptr->play_avpes[id], sizeof(dmx_playbuf_info), 0x0, sizeof(dmx_playbuf_info));
    if (ret != EOK) {
        hi_log_err("call meset_s failed. ret = 0x%x\n", ret);
        return ret;
    }

    demux_mutex_lock(&tee_dmx_mgmt_ptr->lock_all_avr);
    bitmap_clrbit(id, tee_dmx_mgmt_ptr->avr_bitmap);
    demux_mutex_unlock(&tee_dmx_mgmt_ptr->lock_all_avr);

    return HI_SUCCESS;
}

static hi_s32 _destroy_play_chan(hi_u32 id, dmx_chan_type chan_type, dmx_playbuf_info *mem_info)
{
    if (chan_type == DMX_CHAN_TYPE_TS) {
        return _destroy_play_chan_proc_ts_chn(id, mem_info);
    }

    if ((chan_type == DMX_CHAN_TYPE_SEC) || (chan_type == DMX_CHAN_TYPE_PES)) {
        return _destroy_play_chan_proc_sec_or_pes_chn(id, mem_info);
    }

    if ((chan_type == DMX_CHAN_TYPE_AUD) || (chan_type == DMX_CHAN_TYPE_VID)) {
        return _destroy_play_chan_proc_vid_or_aud_chn(id, mem_info);
    }

    hi_log_err("Invalid chan_type[0x%x]\n", chan_type);
    return HI_ERR_DMX_INVALID_PARA;
}

hi_s32 dmx_destroy_play_chan_impl(hi_u32 id, dmx_chan_type chan_type, const dmx_tee_mem_swap_info *mem_info)
{
    hi_s32 ret;
    dmx_playbuf_info play_mem_info = {0};
    unsigned long mask;
    unsigned long *p = HI_NULL;
    tee_dmx_mgmt *tee_dmx_mgmt_ptr = get_dmx_mgmt();

    dmx_null_pointer_return(mem_info);
    ret = _destroy_play_chan(id, chan_type, &play_mem_info);
    if (ret != HI_SUCCESS) {
        hi_log_err("_destroy_play_chan failed!\n");
        goto out;
    }

    /* configure the secure buffer register */
    tee_dmx_hal_buf_deconfig(tee_dmx_mgmt_ptr, play_mem_info.buf_id);

    /* check the id */
    demux_mutex_lock(&tee_dmx_mgmt_ptr->lock_all_buf);
    mask = BIT_MASK(play_mem_info.buf_id);
    p = ((unsigned long *)tee_dmx_mgmt_ptr->buf_bitmap) + BIT_WORD(play_mem_info.buf_id);
    if (!(*p & mask)) {
        hi_log_err("buf_id(%d) is invalid.\n", play_mem_info.buf_id);
        demux_mutex_unlock(&tee_dmx_mgmt_ptr->lock_all_buf);
        ret = HI_ERR_DMX_INVALID_PARA;
        goto out;
    }

    bitmap_clrbit(play_mem_info.buf_id, tee_dmx_mgmt_ptr->buf_bitmap);
    demux_mutex_unlock(&tee_dmx_mgmt_ptr->lock_all_buf);

    ret = _dmx_unmap_shadow_buffer(chan_type, &play_mem_info);
    if (ret != HI_SUCCESS) {
        hi_log_err("dmx_unmap shadow buffer failed!\n");
        ret = HI_TEE_ERR_MEM;
        goto out;
    }

    ret = dmx_unmap_and_free_secbuf(play_mem_info.buf_size, play_mem_info.buf_start_addr,
                                    play_mem_info.buf_start_vir_addr);
    if (ret != HI_SUCCESS) {
        hi_log_err("dmx_unmap_and_free_secbuf failed!\n");
        ret = HI_TEE_ERR_MEM;
        goto out;
    }

out:
    return ret;
}

static hi_s32 __tee_raw_pidch_attach_ts(tee_dmx_mgmt *mgmt, hi_u32 chan_id,
    hi_u32 buf_id, hi_u32 raw_pidch_id, hi_u32 master_raw_pidch_id)
{
    /* enable pid channel for whole ts */
    tee_dmx_hal_pid_tab_ctl_en_set(mgmt, raw_pidch_id, DMX_PID_CHN_WHOLE_TS_FLAG);

    /* set the whole ts channel id register */
    tee_dmx_hal_pid_tab_set_sub_play_chan_id(mgmt, raw_pidch_id, chan_id);

    /* lock set the whole ts tab register */
    tee_dmx_hal_pid_set_whole_tstab(mgmt, chan_id, buf_id, HI_TRUE, HI_TRUE);

    /* attention: do this in the last step, enable the rawpid channle */
    tee_dmx_hal_pid_tab_flt_en(mgmt, raw_pidch_id);

    /* two step about master rawpidch */
    /* enable the master rawpid_ch as whole ts */
    tee_dmx_hal_pid_tab_ctl_en_set(mgmt, master_raw_pidch_id, DMX_PID_CHN_WHOLE_TS_FLAG);

    /* attention: must do it in the last step, even repeatly. enable the master rawpid channle */
    tee_dmx_hal_pid_tab_flt_en(mgmt, master_raw_pidch_id);

    return HI_SUCCESS;
}

static hi_s32 __tee_raw_pidch_attach_sec(tee_dmx_mgmt *mgmt, hi_u32 chan_id, hi_u32 raw_pidch_id,
    hi_u32 master_raw_pidch_id, hi_u32 buf_id)
{
    /* enable pid channel for pes section */
    tee_dmx_hal_pid_tab_ctl_en_set(mgmt, raw_pidch_id, DMX_PID_CHN_PES_SEC_FLAG);

    /* set the pes section channel id register */
    tee_dmx_hal_pid_tab_set_sub_play_chan_id(mgmt, raw_pidch_id, chan_id);

    /* set the data type as pes, enable the pes head len check */
    tee_dmx_hal_pid_set_pes_sec_tab(mgmt, chan_id, DMX_PID_TYPE_SECTION, HI_FALSE, HI_TRUE);

    tee_dmx_hal_flt_set_sec_default_attr(mgmt, chan_id, buf_id);

    /* attention: do this in the last step, enable the rawpid channle */
    tee_dmx_hal_pid_tab_flt_en(mgmt, raw_pidch_id);

    /* two step about master rawpidch */
    /* enable the master rawpid_ch as pes_sec */
    tee_dmx_hal_pid_tab_ctl_en_set(mgmt, master_raw_pidch_id, DMX_PID_CHN_PES_SEC_FLAG);

    /* attention: must do it in the last step, even repeatly. enable the master rawpid channle */
    tee_dmx_hal_pid_tab_flt_en(mgmt, master_raw_pidch_id);

    return HI_SUCCESS;
}

static hi_s32 __tee_raw_pidch_attach_pes(tee_dmx_mgmt *mgmt, hi_u32 chan_id, hi_u32 raw_pidch_id,
    hi_u32 master_raw_pidch_id, hi_u32 buf_id)
{
    /* enable pid channel for pes section */
    tee_dmx_hal_pid_tab_ctl_en_set(mgmt, raw_pidch_id, DMX_PID_CHN_PES_SEC_FLAG);

    /* set the pes section channel id register */
    tee_dmx_hal_pid_tab_set_sub_play_chan_id(mgmt, raw_pidch_id, chan_id);

    /* set the data type as pes, enable the pes head len check */
    tee_dmx_hal_pid_set_pes_sec_tab(mgmt, chan_id, DMX_PID_TYPE_PES, HI_FALSE, HI_TRUE);

    tee_dmx_hal_flt_set_pes_default_attr(mgmt, chan_id, buf_id);

    /* attention: do this in the last step, enable the rawpid channle */
    tee_dmx_hal_pid_tab_flt_en(mgmt, raw_pidch_id);

    /* two step about master rawpidch */
    /* enable the master rawpid_ch as pes_sec */
    tee_dmx_hal_pid_tab_ctl_en_set(mgmt, master_raw_pidch_id, DMX_PID_CHN_PES_SEC_FLAG);

    /* attention: must do it in the last step, even repeatly. enable the master rawpid channle */
    tee_dmx_hal_pid_tab_flt_en(mgmt, master_raw_pidch_id);

    return HI_SUCCESS;
}

static hi_void __tee_raw_pidch_attach_avpes(tee_dmx_mgmt *mgmt, hi_u32 chan_id,
    hi_u32 buf_id, hi_u32 raw_pidch_id, hi_u32 master_raw_pidch_id)
{
    /* set the avpes tab register, disable drop cc not continue until pusi, set the tee lcck */
    tee_dmx_hal_pid_set_av_pes_tab(mgmt, chan_id, buf_id, HI_FALSE, HI_TRUE);

    /* set the rec scd enable and work on av pes mode */
    /* 0x200 means rec_bufid bit[25] set to 1, enable the mq */
    tee_dmx_hal_scd_set_av_pes_cfg(mgmt, chan_id, HI_TRUE, 1, 0x200);

    /* set the avpes channel id register */
    tee_dmx_hal_pid_tab_set_sub_play_chan_id(mgmt, raw_pidch_id, chan_id);

    /* enable pid channel for avpes */
    tee_dmx_hal_pid_tab_ctl_en_set(mgmt, raw_pidch_id, DMX_PID_CHN_AVPES_FLAG);

    /* attention: do this in the last step, enable the rawpid channle */
    tee_dmx_hal_pid_tab_flt_en(mgmt, raw_pidch_id);

    /* two step about master rawpidch */
    /* enable the master rawpid_ch as whole ts */
    tee_dmx_hal_pid_tab_ctl_en_set(mgmt, master_raw_pidch_id, DMX_PID_CHN_AVPES_FLAG);

    /* attention: must do it in the last step, even repeatly. enable the master rawpid channle */
    tee_dmx_hal_pid_tab_flt_en(mgmt, master_raw_pidch_id);

    return;
}

static hi_void __tee_buf_attach_play_chan(tee_dmx_mgmt *mgmt, hi_u32 buf_id, hi_u64 buf_start_addr, hi_u32 buf_size)
{
    tee_dmx_hal_buf_config(mgmt, buf_id, buf_start_addr, buf_size);

    /* clear the buffer cache */
    tee_dmx_hal_buf_clr_mmu_cache(mgmt, buf_id);
    return;
}

static hi_s32 _attach_play_chan(hi_u32 chan_id, dmx_chan_type chan_type, hi_u32 raw_pidch_id,
    hi_u32 master_raw_pidch_id)
{
    hi_s32 ret = HI_SUCCESS;
    hi_u32 buf_id;
    hi_u64 buf_start_addr;
    hi_u32 buf_size;

    tee_dmx_mgmt *tee_dmx_mgmt_ptr = get_dmx_mgmt();

    if (chan_type == DMX_CHAN_TYPE_TS) {
        dmx_err_condition_return(chan_id >= tee_dmx_mgmt_ptr->play_ts_cnt, HI_ERR_DMX_INVALID_PARA);
        demux_mutex_lock(&tee_dmx_mgmt_ptr->play_ts[chan_id].lock_ts);
        buf_id = tee_dmx_mgmt_ptr->play_ts[chan_id].ts_secbuf.buf_id;
        buf_start_addr = tee_dmx_mgmt_ptr->play_ts[chan_id].ts_secbuf.buf_start_addr;
        buf_size = tee_dmx_mgmt_ptr->play_ts[chan_id].ts_secbuf.buf_size;
        __tee_raw_pidch_attach_ts(tee_dmx_mgmt_ptr, chan_id, buf_id, raw_pidch_id, master_raw_pidch_id);
        demux_mutex_unlock(&tee_dmx_mgmt_ptr->play_ts[chan_id].lock_ts);
    } else if (chan_type == DMX_CHAN_TYPE_SEC) {
        dmx_err_condition_return(chan_id >= tee_dmx_mgmt_ptr->play_pes_sec_cnt, HI_ERR_DMX_INVALID_PARA);
        demux_mutex_lock(&tee_dmx_mgmt_ptr->play_pes_sec[chan_id].lock_pes_sec);
        buf_id = tee_dmx_mgmt_ptr->play_pes_sec[chan_id].pes_sec_secbuf.buf_id;
        buf_start_addr = tee_dmx_mgmt_ptr->play_pes_sec[chan_id].pes_sec_secbuf.buf_start_addr;
        buf_size = tee_dmx_mgmt_ptr->play_pes_sec[chan_id].pes_sec_secbuf.buf_size;
        __tee_raw_pidch_attach_sec(tee_dmx_mgmt_ptr, chan_id, raw_pidch_id, master_raw_pidch_id, buf_id);
        demux_mutex_unlock(&tee_dmx_mgmt_ptr->play_pes_sec[chan_id].lock_pes_sec);
    } else if (chan_type == DMX_CHAN_TYPE_PES) {
        dmx_err_condition_return(chan_id >= tee_dmx_mgmt_ptr->play_pes_sec_cnt, HI_ERR_DMX_INVALID_PARA);
        demux_mutex_lock(&tee_dmx_mgmt_ptr->play_pes_sec[chan_id].lock_pes_sec);
        buf_id = tee_dmx_mgmt_ptr->play_pes_sec[chan_id].pes_sec_secbuf.buf_id;
        buf_start_addr = tee_dmx_mgmt_ptr->play_pes_sec[chan_id].pes_sec_secbuf.buf_start_addr;
        buf_size = tee_dmx_mgmt_ptr->play_pes_sec[chan_id].pes_sec_secbuf.buf_size;
        __tee_raw_pidch_attach_pes(tee_dmx_mgmt_ptr, chan_id, raw_pidch_id, master_raw_pidch_id, buf_id);
        demux_mutex_unlock(&tee_dmx_mgmt_ptr->play_pes_sec[chan_id].lock_pes_sec);
    } else if ((chan_type == DMX_CHAN_TYPE_AUD) || (chan_type == DMX_CHAN_TYPE_VID)) {
        dmx_err_condition_return(chan_id >= tee_dmx_mgmt_ptr->avr_cnt, HI_ERR_DMX_INVALID_PARA);
        demux_mutex_lock(&tee_dmx_mgmt_ptr->play_avpes[chan_id].lock_avpes);
        buf_id = tee_dmx_mgmt_ptr->play_avpes[chan_id].avpes_secbuf.buf_id;
        buf_start_addr = tee_dmx_mgmt_ptr->play_avpes[chan_id].avpes_secbuf.buf_start_addr;
        buf_size = tee_dmx_mgmt_ptr->play_avpes[chan_id].avpes_secbuf.buf_size;
        __tee_raw_pidch_attach_avpes(tee_dmx_mgmt_ptr, chan_id, buf_id, raw_pidch_id, master_raw_pidch_id);
        demux_mutex_unlock(&tee_dmx_mgmt_ptr->play_avpes[chan_id].lock_avpes);
    } else {
        hi_log_err("Invalid chan_type[0x%x]\n", chan_type);
        return HI_ERR_DMX_INVALID_PARA;
    }

    __tee_buf_attach_play_chan(tee_dmx_mgmt_ptr, buf_id, buf_start_addr, buf_size);
    return ret;
}

hi_s32 dmx_attach_play_chan_impl(hi_u32 chan_id, dmx_chan_type chan_type, hi_u32 raw_pidch_id,
    hi_u32 master_raw_pidch_id)
{
    return _attach_play_chan(chan_id, chan_type, raw_pidch_id, master_raw_pidch_id);
}

static hi_void __tee_raw_pidch_detach_ts(tee_dmx_mgmt *mgmt, hi_u32 chan_id, hi_u32 raw_pidch_id)
{
    /* disable the rawpid channle */
    tee_dmx_hal_pid_tab_flt_dis(mgmt, raw_pidch_id);

    /* disable pid channel of whole ts */
    tee_dmx_hal_pid_tab_ctl_dis_set(mgmt, raw_pidch_id, DMX_PID_CHN_WHOLE_TS_FLAG);
    /* unlock clear whole ts buf id register */
    tee_dmx_hal_pid_set_whole_tstab(mgmt, chan_id, 0, HI_FALSE, HI_FALSE);

    return;
}

static hi_void __tee_raw_pidch_detach_pes_sec(tee_dmx_mgmt *mgmt, hi_u32 chan_id, hi_u32 raw_pidch_id)
{
    /* disable the rawpid channle */
    tee_dmx_hal_pid_tab_flt_dis(mgmt, raw_pidch_id);

    /* disable pid channel of  pes section */
    tee_dmx_hal_pid_tab_ctl_dis_set(mgmt, raw_pidch_id, DMX_PID_CHN_PES_SEC_FLAG);

    /* unlock pes_sec_lock */
    tee_dmx_hal_pes_sec_unlock(mgmt, chan_id);

    return;
}

static hi_void __tee_raw_pidch_detach_avpes(tee_dmx_mgmt *mgmt, hi_u32 chan_id, dmx_chan_type chan_type,
    hi_u32 raw_pidch_id)
{
    /* play alone needs to disable the pid_tab, but play&record don't need to */
    if ((chan_type & DMX_CHAN_TYPE_REC) != DMX_CHAN_TYPE_REC) {
        tee_dmx_hal_pid_tab_flt_dis(mgmt, raw_pidch_id);
    }
    /* disable pid channel of avpes */
    tee_dmx_hal_pid_tab_ctl_dis_set(mgmt, raw_pidch_id, DMX_PID_CHN_AVPES_FLAG);

    /* clear the avpes tab register, disable drop cc not continue until pusi, disable the pes head len check */
    tee_dmx_hal_pid_set_av_pes_tab(mgmt, chan_id, 0, HI_FALSE, HI_FALSE);

    /* disable rec scd */
    tee_dmx_hal_scd_set_av_pes_cfg(mgmt, chan_id, HI_FALSE, 0x0, 0x0);

    return;
}

static hi_s32 _detach_play_chan(hi_u32 chan_id, dmx_chan_type chan_type, hi_u32 raw_pidch_id)
{
    tee_dmx_mgmt *tee_dmx_mgmt_ptr = get_dmx_mgmt();

    if (chan_type == DMX_CHAN_TYPE_TS) {
        dmx_err_condition_return(chan_id >= tee_dmx_mgmt_ptr->play_ts_cnt, HI_ERR_DMX_INVALID_PARA);
        demux_mutex_lock(&tee_dmx_mgmt_ptr->play_ts[chan_id].lock_ts);
        __tee_raw_pidch_detach_ts(tee_dmx_mgmt_ptr, chan_id, raw_pidch_id);
        demux_mutex_unlock(&tee_dmx_mgmt_ptr->play_ts[chan_id].lock_ts);
        return HI_SUCCESS;
    } else if ((chan_type == DMX_CHAN_TYPE_SEC) || (chan_type == DMX_CHAN_TYPE_PES)) {
        dmx_err_condition_return(chan_id >= tee_dmx_mgmt_ptr->play_pes_sec_cnt, HI_ERR_DMX_INVALID_PARA);
        demux_mutex_lock(&tee_dmx_mgmt_ptr->play_pes_sec[chan_id].lock_pes_sec);
        __tee_raw_pidch_detach_pes_sec(tee_dmx_mgmt_ptr, chan_id, raw_pidch_id);
        demux_mutex_unlock(&tee_dmx_mgmt_ptr->play_pes_sec[chan_id].lock_pes_sec);
        return HI_SUCCESS;
    } else if ((chan_type == DMX_CHAN_TYPE_AUD) || (chan_type == DMX_CHAN_TYPE_VID) ||
        (chan_type == (DMX_CHAN_TYPE_AUD | DMX_CHAN_TYPE_REC)) ||
        (chan_type == (DMX_CHAN_TYPE_VID | DMX_CHAN_TYPE_REC))) {
        dmx_err_condition_return(chan_id >= tee_dmx_mgmt_ptr->avr_cnt, HI_ERR_DMX_INVALID_PARA);
        demux_mutex_lock(&tee_dmx_mgmt_ptr->play_avpes[chan_id].lock_avpes);
        __tee_raw_pidch_detach_avpes(tee_dmx_mgmt_ptr, chan_id, chan_type, raw_pidch_id);
        demux_mutex_unlock(&tee_dmx_mgmt_ptr->play_avpes[chan_id].lock_avpes);
        return HI_SUCCESS;
    }

    hi_log_err("Invalid chan_type[0x%x]\n", chan_type);
    return HI_ERR_DMX_INVALID_PARA;
}

hi_s32 dmx_detach_play_chan_impl(hi_u32 chan_id, dmx_chan_type chan_type, hi_u32 raw_pidch_id)
{
    return _detach_play_chan(chan_id, chan_type, raw_pidch_id);
}

static hi_s32 __create_index_sec_buf(dmx_rec_info *rec_info)
{
    hi_s32 ret;

    hi_dbg_func_enter();
    /* init the tee hevc index */
    ret = fidx_init(dmx_rec_update_frame_info);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(fidx_init, ret);
        hi_warn_print_info("fidx_init failed\n");
        goto out0;
    }

    /* open */
    if (rec_info->pic_parser < 0) {
        rec_info->pic_parser = fidx_open_instance(VIDSTD_HEVC, STRM_TYPE_ES, (hi_u32*)&rec_info->last_frame_info);
        if (rec_info->pic_parser < 0) {
            hi_warn_print_info("pic_parser is invlid\n");
            ret = HI_FAILURE;
            goto out1;
        }
    }
    hi_dbg_func_exit();
    return HI_SUCCESS;
out1:
    fidx_de_init();
out0:
    hi_dbg_func_exit();

    return ret;
}

static hi_s32 _create_rec_chan(hi_u32 id, const dmx_recbuf_info *mem_info)
{
    tee_dmx_mgmt *tee_dmx_mgmt_ptr = get_dmx_mgmt();

    dmx_err_condition_return(id >= tee_dmx_mgmt_ptr->avr_cnt, HI_ERR_DMX_INVALID_PARA);
    tee_dmx_mgmt_ptr->rec_info[id].rec_secbuf.buf_id = mem_info->buf_id;
    tee_dmx_mgmt_ptr->rec_info[id].rec_secbuf.buf_size = mem_info->buf_size;
    tee_dmx_mgmt_ptr->rec_info[id].rec_secbuf.buf_start_addr = mem_info->buf_start_addr;
    tee_dmx_mgmt_ptr->rec_info[id].rec_secbuf.buf_start_vir_addr = mem_info->buf_start_vir_addr;
    tee_dmx_mgmt_ptr->rec_info[id].pic_parser = -1;

    if (__create_index_sec_buf(&tee_dmx_mgmt_ptr->rec_info[id]) != HI_SUCCESS) {
        return HI_FAILURE;
    }

    demux_mutex_lock(&tee_dmx_mgmt_ptr->lock_all_avr);
    bitmap_setbit(id, tee_dmx_mgmt_ptr->avr_bitmap);
    demux_mutex_unlock(&tee_dmx_mgmt_ptr->lock_all_avr);

    return HI_SUCCESS;
}

hi_s32 dmx_create_rec_chan_impl(hi_u32 id, hi_u32 buf_size, dmx_tee_mem_swap_info *mem_info)
{
    hi_s32 ret;
    hi_u32 buf_id;
    hi_char buf_name[16] = {0}; /* 16 bytes size */
    dmx_recbuf_info rec_mem_info = {0};
    hi_ulong buf_smmu_addr;
    hi_u8 *buf_vir_addr = HI_NULL;

    tee_dmx_mgmt *tee_dmx_mgmt_ptr = get_dmx_mgmt();

    dmx_null_pointer_return(mem_info);

    demux_mutex_lock(&tee_dmx_mgmt_ptr->lock_all_buf);
    buf_id = find_first_zero_bit(tee_dmx_mgmt_ptr->buf_bitmap, tee_dmx_mgmt_ptr->buf_cnt);
    if (!(buf_id < tee_dmx_mgmt_ptr->buf_cnt)) {
        demux_mutex_unlock(&tee_dmx_mgmt_ptr->lock_all_buf);
        return HI_ERR_DMX_NO_RESOURCE;
    }

    bitmap_setbit(buf_id, tee_dmx_mgmt_ptr->buf_bitmap);
    demux_mutex_unlock(&tee_dmx_mgmt_ptr->lock_all_buf);

    if (snprintf_s(buf_name, sizeof(buf_name), sizeof(buf_name) - 1, "dmx_sec_avr[%d]", buf_id) == -1) {
        ret = HI_FAILURE;
        goto clr_bufbit;
    }

    ret = dmx_alloc_and_map_secbuf(buf_name, DMX_STR_LEN_16, buf_size, &buf_smmu_addr, &buf_vir_addr);
    if (ret != HI_SUCCESS) {
        hi_log_err("dmx_alloc_and_map_secbuf failed!\n");
        goto clr_bufbit;
    }

    /* make last 0x2 ts packets size of record buffer empty ts packets(pid 0x1FFF). */
    _dmx_buf_fill_ts_stream(buf_vir_addr + (buf_size - DMX_TS_PKT_SIZE * 0x2), DMX_TS_PKT_SIZE * 0x2, 0x1FFF);

    /* record the rec channel */
    rec_mem_info.buf_id = buf_id;
    rec_mem_info.buf_size = buf_size;
    rec_mem_info.buf_start_addr = buf_smmu_addr;
    rec_mem_info.buf_start_vir_addr = buf_vir_addr;

    ret = _create_rec_chan(id, &rec_mem_info);
    if (ret != HI_SUCCESS) {
        hi_log_err("_create_rec_chan failed!\n");
        goto free_secbuf;
    }

    /* configure the secure buffer register */
    tee_dmx_hal_buf_config(tee_dmx_mgmt_ptr, buf_id, buf_smmu_addr, buf_size);

    mem_info->buf_id = buf_id;
    mem_info->buf_phy_addr = buf_smmu_addr;
    mem_info->buf_size = buf_size;

    return HI_SUCCESS;

free_secbuf:
    dmx_unmap_and_free_secbuf(buf_size, buf_smmu_addr, buf_vir_addr);
clr_bufbit:
    demux_mutex_lock(&tee_dmx_mgmt_ptr->lock_all_buf);
    bitmap_clrbit(buf_id, tee_dmx_mgmt_ptr->buf_bitmap);
    demux_mutex_unlock(&tee_dmx_mgmt_ptr->lock_all_buf);
    return ret;
}

static hi_s32 __destroy_index_sec_buf(dmx_rec_info *rec_info)
{
    hi_s32 ret;
    /* close */
    if (rec_info->pic_parser >= 0) {
        ret = fidx_close_instance(rec_info->pic_parser);
        if (ret != HI_SUCCESS) {
            hi_err_print_call_fun_err(fidx_close_instance, ret);
            hi_warn_print_info("fidx_close_instance failed\n");
            return HI_FAILURE;
        }
        rec_info->pic_parser = -1;
    }

    if (memset_s(rec_info, sizeof(dmx_rec_info), 0x0, sizeof(dmx_rec_info)) != EOK) {
        hi_warn_print_info("memset_s failed.\n");
        return HI_FAILURE;
    }
    /* Deinit the tee hevc index */
    fidx_de_init();

    /* clear the dmxid and bitmap */
    rec_info->dmx_id = DMX_CNT;
    return HI_SUCCESS;
}

static hi_s32 _destroy_rec_chan(hi_u32 id, dmx_recbuf_info *mem_info)
{
    hi_s32 ret;
    tee_dmx_mgmt *tee_dmx_mgmt_ptr = get_dmx_mgmt();

    dmx_err_condition_return(id >= tee_dmx_mgmt_ptr->avr_cnt, HI_ERR_DMX_INVALID_PARA);
    mem_info->buf_id = tee_dmx_mgmt_ptr->rec_info[id].rec_secbuf.buf_id;
    mem_info->buf_size = tee_dmx_mgmt_ptr->rec_info[id].rec_secbuf.buf_size;
    mem_info->buf_start_addr = tee_dmx_mgmt_ptr->rec_info[id].rec_secbuf.buf_start_addr;
    mem_info->buf_start_vir_addr = tee_dmx_mgmt_ptr->rec_info[id].rec_secbuf.buf_start_vir_addr;

    ret = __destroy_index_sec_buf(&tee_dmx_mgmt_ptr->rec_info[id]);
    if (ret != HI_SUCCESS) {
        return ret;
    }

    ret = memset_s(&tee_dmx_mgmt_ptr->rec_info[id], sizeof(dmx_recbuf_info), 0x0, sizeof(dmx_recbuf_info));
    if (ret != EOK) {
        hi_log_err("call memset_s failed. ret = 0x%x\n", ret);
        return ret;
    }

    demux_mutex_lock(&tee_dmx_mgmt_ptr->lock_all_avr);
    bitmap_clrbit(id, tee_dmx_mgmt_ptr->avr_bitmap);
    demux_mutex_unlock(&tee_dmx_mgmt_ptr->lock_all_avr);

    return HI_SUCCESS;
}

hi_s32 dmx_destroy_rec_chan_impl(hi_u32 id, dmx_tee_mem_swap_info *mem_info)
{
    hi_s32 ret;
    dmx_recbuf_info rec_mem_info = {0};
    unsigned long mask;
    unsigned long *p = HI_NULL;
    tee_dmx_mgmt *tee_dmx_mgmt_ptr = get_dmx_mgmt();

    dmx_null_pointer_return(mem_info);

    ret = _destroy_rec_chan(id, &rec_mem_info);
    if (ret != HI_SUCCESS) {
        hi_log_err("__destroy_index_chan failed!\n");
        goto out;
    }

    /* configure the secure buffer register */
    tee_dmx_hal_buf_deconfig(tee_dmx_mgmt_ptr, rec_mem_info.buf_id);

    tee_dmx_hal_scd_set_ts_rec_cfg(tee_dmx_mgmt_ptr, id, HI_FALSE, rec_mem_info.buf_id);

    ret = dmx_unmap_and_free_secbuf(rec_mem_info.buf_size, rec_mem_info.buf_start_addr,
                                    rec_mem_info.buf_start_vir_addr);
    if (ret != HI_SUCCESS) {
        hi_log_err("dmx_unmap_and_free_secbuf failed!\n");
        ret = HI_TEE_ERR_MEM;
        goto out;
    }

    demux_mutex_lock(&tee_dmx_mgmt_ptr->lock_all_buf);
    /* check the id */
    mask = BIT_MASK(rec_mem_info.buf_id);
    p = ((unsigned long *)tee_dmx_mgmt_ptr->buf_bitmap) + BIT_WORD(rec_mem_info.buf_id);
    if (!(*p & mask)) {
        demux_mutex_unlock(&tee_dmx_mgmt_ptr->lock_all_buf);
        hi_log_err("buf_id(%d) is invalid.\n", rec_mem_info.buf_id);
        ret = HI_ERR_DMX_INVALID_PARA;
        goto out;
    }

    bitmap_clrbit(rec_mem_info.buf_id, tee_dmx_mgmt_ptr->buf_bitmap);
    demux_mutex_unlock(&tee_dmx_mgmt_ptr->lock_all_buf);

out:
    return ret;
}

static hi_void __tee_raw_pidch_attach_rec(tee_dmx_mgmt *mgmt, const dmx_rec_attach_info *attach_ptr)
{
    /* enable pid channel for record */
    tee_dmx_hal_pid_tab_ctl_en_set(mgmt, attach_ptr->raw_pidch_id, DMX_PID_CHN_REC_FLAG);
    tee_dmx_hal_pid_set_rec_tab(mgmt, attach_ptr->raw_pidch_id, attach_ptr->chan_id);

    if (attach_ptr->is_descram == HI_TRUE) {
        tee_dmx_hal_pid_set_rec_dsc_mode(mgmt, attach_ptr->raw_pidch_id, HI_TRUE);
    } else {
        tee_dmx_hal_pid_set_rec_dsc_mode(mgmt, attach_ptr->raw_pidch_id, HI_FALSE);
    }

    if (attach_ptr->is_video_index) {
        /* disable scd channel  */
        tee_dmx_hal_scd_en(mgmt, attach_ptr->index_scd_id, HI_FALSE);

        /* scd buffer locked and none secure */
        tee_dmx_hal_buf_set_sec_attrs(mgmt, attach_ptr->scd_buf_id, HI_TRUE, HI_FALSE);

        /* scd channel tee lock locked */
        tee_dmx_hal_scd_set_tee_lock(mgmt, attach_ptr->index_scd_id, HI_TRUE);

        tee_dmx_hal_scd_set_buf_id(mgmt, attach_ptr->index_scd_id, attach_ptr->scd_buf_id);

        /* configure the index, disable tpit */
        tee_dmx_hal_scd_set_rec_tab(mgmt, attach_ptr->index_scd_id, HI_FALSE, HI_TRUE, HI_TRUE);

        /* enable the filter */
        tee_dmx_hal_scd_set_flt_en(mgmt, attach_ptr->index_scd_id, HI_TRUE);

        /* enable scd channel  */
        tee_dmx_hal_scd_en(mgmt, attach_ptr->index_scd_id, HI_TRUE);

        /* enable the ts index */
        tee_dmx_hal_pid_set_scd_tab(mgmt, attach_ptr->raw_pidch_id, attach_ptr->index_scd_id, 0);
        tee_dmx_hal_pid_tab_ctl_en_set(mgmt, attach_ptr->raw_pidch_id, DMX_PID_CHN_TS_SCD_FLAG);
    }

    /* attention: do this in the last step, enable the rawpid channle */
    tee_dmx_hal_pid_tab_flt_en(mgmt, attach_ptr->raw_pidch_id);

    /* two step about master rawpidch */
    /* enable the master rawpid_ch as rec ts */
    tee_dmx_hal_pid_tab_ctl_en_set(mgmt, attach_ptr->master_raw_pidch_id, DMX_PID_CHN_REC_FLAG);

    /* attention: must do it in the last step, even repeatly. enable the master rawpid channle */
    tee_dmx_hal_pid_tab_flt_en(mgmt, attach_ptr->master_raw_pidch_id);

    return;
}

static hi_s32 _attach_rec_chan(const dmx_rec_attach_info *attach_ptr)
{
    hi_u32 chan_id;
    tee_dmx_mgmt *tee_dmx_mgmt_ptr = get_dmx_mgmt();

    chan_id = attach_ptr->chan_id;

    dmx_err_condition_return(chan_id >= tee_dmx_mgmt_ptr->avr_cnt, HI_ERR_DMX_INVALID_PARA);
    demux_mutex_lock(&tee_dmx_mgmt_ptr->rec_info[chan_id].lock_rec);
    __tee_raw_pidch_attach_rec(tee_dmx_mgmt_ptr, attach_ptr);
    demux_mutex_unlock(&tee_dmx_mgmt_ptr->rec_info[chan_id].lock_rec);

    return HI_SUCCESS;
}

hi_s32 dmx_attach_rec_chan_impl(const dmx_rec_attach_info *attach_ptr)
{
    dmx_null_pointer_return(attach_ptr);
    return _attach_rec_chan(attach_ptr);
}

static hi_void __tee_raw_pidch_detach_rec(tee_dmx_mgmt *mgmt, const dmx_rec_detach_info *detach_ptr)
{
    /* record alone needs to disable the pid_tab, but play&record don't need to */
    if (detach_ptr->is_rec_only == HI_TRUE) {
        /* disable the rawpid channle */
        tee_dmx_hal_pid_tab_flt_dis(mgmt, detach_ptr->raw_pidch_id);
    }

    /* disable pid channel of ts record */
    tee_dmx_hal_pid_tab_ctl_dis_set(mgmt, detach_ptr->raw_pidch_id, DMX_PID_CHN_REC_FLAG);

    /* disable the ts index */
    if (detach_ptr->is_video_index == HI_TRUE) {
        tee_dmx_hal_pid_tab_ctl_dis_set(mgmt, detach_ptr->raw_pidch_id, DMX_PID_CHN_TS_SCD_FLAG);
    }

    tee_dmx_hal_scd_en(mgmt, detach_ptr->index_scd_id, HI_FALSE);
    tee_dmx_hal_scd_set_tee_lock(mgmt, detach_ptr->index_scd_id, HI_FALSE);

    /* configure the index, disable tpit */
    tee_dmx_hal_scd_set_rec_tab(mgmt, detach_ptr->index_scd_id, HI_FALSE, HI_FALSE, HI_FALSE);
    /* enable the filter */
    tee_dmx_hal_scd_set_flt_en(mgmt, detach_ptr->index_scd_id, HI_FALSE);

    return;
}

static hi_s32 _detach_rec_chan(const dmx_rec_detach_info *detach_ptr)
{
    tee_dmx_mgmt *tee_dmx_mgmt_ptr = get_dmx_mgmt();
    hi_u32 chan_id = detach_ptr->chan_id;

    dmx_err_condition_return(chan_id >= tee_dmx_mgmt_ptr->avr_cnt, HI_ERR_DMX_INVALID_PARA);
    demux_mutex_lock(&tee_dmx_mgmt_ptr->rec_info[chan_id].lock_rec);
    __tee_raw_pidch_detach_rec(tee_dmx_mgmt_ptr, detach_ptr);
    demux_mutex_unlock(&tee_dmx_mgmt_ptr->rec_info[chan_id].lock_rec);

    return HI_SUCCESS;
}

hi_s32 dmx_detach_rec_chan_impl(const dmx_rec_detach_info *detach_ptr)
{
    dmx_null_pointer_return(detach_ptr);
    return _detach_rec_chan(detach_ptr);
}

hi_s32 dmx_update_play_read_idx_impl(hi_u32 buf_id, dmx_chan_type chan_type, hi_u32 read_idx)
{
    tee_dmx_mgmt *tee_dmx_mgmt_ptr = get_dmx_mgmt();
    tee_dmx_hal_buf_set_read_idx(tee_dmx_mgmt_ptr, buf_id, read_idx);

    HI_UNUSED(chan_type);
    return HI_SUCCESS;
}

hi_s32 dmx_update_rec_read_idx_impl(hi_u32 buf_id, hi_u32 read_idx)
{
    tee_dmx_mgmt *tee_dmx_mgmt_ptr = get_dmx_mgmt();
    tee_dmx_hal_buf_set_read_idx(tee_dmx_mgmt_ptr, buf_id, read_idx);

    return HI_SUCCESS;
}

hi_s32 dmx_acquire_buf_id_impl(hi_u32 *buf_id_ptr)
{
    hi_s32 ret;
    hi_u32 buf_id;

    tee_dmx_mgmt *tee_dmx_mgmt_ptr = get_dmx_mgmt();

    dmx_null_pointer_return(buf_id_ptr);

    demux_mutex_lock(&tee_dmx_mgmt_ptr->lock_all_buf);
    buf_id = find_first_zero_bit(tee_dmx_mgmt_ptr->buf_bitmap, tee_dmx_mgmt_ptr->buf_cnt);
    if (!(buf_id < tee_dmx_mgmt_ptr->buf_cnt)) {
        demux_mutex_unlock(&tee_dmx_mgmt_ptr->lock_all_buf);
        hi_log_err("there is no available buf id now!\n");
        ret = HI_ERR_DMX_NO_RESOURCE;
        goto out;
    }

    bitmap_setbit(buf_id, tee_dmx_mgmt_ptr->buf_bitmap);
    demux_mutex_unlock(&tee_dmx_mgmt_ptr->lock_all_buf);

    *buf_id_ptr = buf_id;
    ret = HI_SUCCESS;
out:
    return ret;
}

hi_s32 dmx_release_buf_id_impl(hi_u32 buf_id)
{
    hi_s32 ret;
    unsigned long mask;
    unsigned long *p = HI_NULL;
    tee_dmx_mgmt *tee_dmx_mgmt_ptr = get_dmx_mgmt();

    demux_mutex_lock(&tee_dmx_mgmt_ptr->lock_all_buf);
    /* check the id */
    mask = BIT_MASK(buf_id);
    p = ((unsigned long *)tee_dmx_mgmt_ptr->buf_bitmap) + BIT_WORD(buf_id);
    if (!(*p & mask)) {
        demux_mutex_unlock(&tee_dmx_mgmt_ptr->lock_all_buf);
        hi_log_err("buf_id(%d) is invalid.\n", buf_id);
        ret = HI_ERR_DMX_INVALID_PARA;
        goto out;
    }

    bitmap_clrbit(buf_id, tee_dmx_mgmt_ptr->buf_bitmap);
    demux_mutex_unlock(&tee_dmx_mgmt_ptr->lock_all_buf);

    ret = HI_SUCCESS;

out:
    return ret;
}

hi_s32 dmx_detach_raw_pidch_impl(hi_u32 raw_pidch)
{
    tee_dmx_mgmt *tee_dmx_mgmt_ptr = get_dmx_mgmt();
    tee_dmx_hal_pid_tab_ctl_dis_set(tee_dmx_mgmt_ptr, raw_pidch, DMX_PID_CHN_TEE_LOCK);

    return HI_SUCCESS;
}

static hi_s32 _dmx_get_secbuf_info(hi_u32 chan_id, dmx_chan_type chan_type, dmx_tee_mem_swap_info *secbuf_info)
{
    hi_s32 ret = HI_SUCCESS;
    hi_u32 buf_id;
    hi_u64 buf_start_addr;
    hi_u32 buf_size;
    tee_dmx_mgmt *tee_dmx_mgmt_ptr = get_dmx_mgmt();

    if (chan_type == DMX_CHAN_TYPE_TS) {
        dmx_err_condition_return(chan_id >= tee_dmx_mgmt_ptr->play_ts_cnt, HI_ERR_DMX_INVALID_PARA);
        demux_mutex_lock(&tee_dmx_mgmt_ptr->play_ts[chan_id].lock_ts);
        buf_id = tee_dmx_mgmt_ptr->play_ts[chan_id].ts_secbuf.buf_id;
        buf_start_addr = tee_dmx_mgmt_ptr->play_ts[chan_id].ts_secbuf.buf_start_addr;
        buf_size = tee_dmx_mgmt_ptr->play_ts[chan_id].ts_secbuf.buf_size;
        demux_mutex_unlock(&tee_dmx_mgmt_ptr->play_ts[chan_id].lock_ts);
    } else if ((chan_type == DMX_CHAN_TYPE_SEC) || (chan_type == DMX_CHAN_TYPE_PES)) {
        dmx_err_condition_return(chan_id >= tee_dmx_mgmt_ptr->play_pes_sec_cnt, HI_ERR_DMX_INVALID_PARA);
        demux_mutex_lock(&tee_dmx_mgmt_ptr->play_pes_sec[chan_id].lock_pes_sec);
        buf_id = tee_dmx_mgmt_ptr->play_pes_sec[chan_id].pes_sec_secbuf.buf_id;
        buf_start_addr = tee_dmx_mgmt_ptr->play_pes_sec[chan_id].pes_sec_secbuf.buf_start_addr;
        buf_size = tee_dmx_mgmt_ptr->play_pes_sec[chan_id].pes_sec_secbuf.buf_size;
        demux_mutex_unlock(&tee_dmx_mgmt_ptr->play_pes_sec[chan_id].lock_pes_sec);
    } else if ((chan_type == DMX_CHAN_TYPE_AUD) || (chan_type == DMX_CHAN_TYPE_VID)) {
        dmx_err_condition_return(chan_id >= tee_dmx_mgmt_ptr->avr_cnt, HI_ERR_DMX_INVALID_PARA);
        demux_mutex_lock(&tee_dmx_mgmt_ptr->play_avpes[chan_id].lock_avpes);
        buf_id = tee_dmx_mgmt_ptr->play_avpes[chan_id].avpes_secbuf.buf_id;
        buf_start_addr = tee_dmx_mgmt_ptr->play_avpes[chan_id].avpes_secbuf.buf_start_addr;
        buf_size = tee_dmx_mgmt_ptr->play_avpes[chan_id].avpes_secbuf.buf_size;
        demux_mutex_unlock(&tee_dmx_mgmt_ptr->play_avpes[chan_id].lock_avpes);
    } else if (chan_type == DMX_CHAN_TYPE_REC) {
        dmx_err_condition_return(chan_id >= tee_dmx_mgmt_ptr->avr_cnt, HI_ERR_DMX_INVALID_PARA);
        demux_mutex_lock(&tee_dmx_mgmt_ptr->rec_info[chan_id].lock_rec);
        buf_id = tee_dmx_mgmt_ptr->rec_info[chan_id].rec_secbuf.buf_id;
        buf_start_addr = tee_dmx_mgmt_ptr->rec_info[chan_id].rec_secbuf.buf_start_addr;
        buf_size = tee_dmx_mgmt_ptr->rec_info[chan_id].rec_secbuf.buf_size;
        demux_mutex_unlock(&tee_dmx_mgmt_ptr->rec_info[chan_id].lock_rec);
    } else {
        hi_log_err("Invalid chan_type[0x%x]\n", chan_type);
        return HI_ERR_DMX_INVALID_PARA;
    }

    secbuf_info->buf_id = buf_id;
    secbuf_info->buf_phy_addr = buf_start_addr;
    secbuf_info->buf_size = buf_size;

    return ret;
}

hi_s32 dmx_config_secbuf_impl(hi_u32 chan_id, dmx_chan_type chan_type)
{
    hi_s32 ret;

    tee_dmx_mgmt *tee_dmx_mgmt_ptr = get_dmx_mgmt();
    dmx_tee_mem_swap_info sec_mem_info = {0};

    ret = _dmx_get_secbuf_info(chan_id, chan_type, &sec_mem_info);
    if (ret != HI_SUCCESS) {
        hi_log_err("_dmx_get_secbuf_info failed chan_id[0x%x], chan_type[0x%x]\n", chan_id, chan_type);
        ret = HI_ERR_DMX_INVALID_PARA;
        goto out;
    }

    tee_dmx_hal_buf_config(tee_dmx_mgmt_ptr, sec_mem_info.buf_id, sec_mem_info.buf_phy_addr, sec_mem_info.buf_size);

out:
    return ret;
}

hi_s32 dmx_deconfig_secbuf_impl(hi_u32 chan_id, dmx_chan_type chan_type)
{
    hi_s32 ret;

    tee_dmx_mgmt *tee_dmx_mgmt_ptr = get_dmx_mgmt();
    dmx_tee_mem_swap_info sec_mem_info = {0};

    ret = _dmx_get_secbuf_info(chan_id, chan_type, &sec_mem_info);
    if (ret != HI_SUCCESS) {
        hi_log_err("_dmx_get_secbuf_info failed chan_id[0x%x], chan_type[0x%x]\n", chan_id, chan_type);
        ret = HI_ERR_DMX_INVALID_PARA;
        goto out;
    }

    tee_dmx_hal_buf_deconfig(tee_dmx_mgmt_ptr, sec_mem_info.buf_id);

out:
    return ret;
}

hi_s32 dmx_enable_rec_chan(hi_u32 id)
{
    tee_dmx_mgmt *tee_dmx_mgmt_ptr = get_dmx_mgmt();

    tee_dmx_hal_rec_chn_enable(tee_dmx_mgmt_ptr, id);

    return HI_SUCCESS;
}

static hi_u32 dmx_adp_fld_len(hi_u8 *ts_data)
{
    if (ts_data[0] != 0x47) {
        hi_log_err("head not 0x47\n");
        return 0;
    }

    if (((ts_data[0x3] >> 0x4) & 0x03) == 0x02) { /* index 3, 4 bits */
        return DMX_TS_PKT_SIZE - TS_PKT_HEADER_LEN;
    } else if (((ts_data[0x3] >> 0x4) & 0x03) == 0x03) { /* index 3, 4 bits */
        return  1 + (hi_u32)ts_data[0x4]; /* index 4 */
    }

    return 0;
}

static hi_u32 dmx_pes_header_len(hi_u8 *ts_data)
{
    if (ts_data[0] != 0x47) {
        hi_log_err("head not 0x47\n");
        return 0;
    }

    if (ts_data[1] & 0x40) {
        hi_u32 adp_len = dmx_adp_fld_len(ts_data);
        /* 4 is ts packet header length, 8 meanse pes header fild is  the 8th bytes of pes header. */
        return PES_PKT_HEADER_LENGTH + (hi_u32)ts_data[0x4 + adp_len + 0x8];
    }

    return 0;
}

static inline hi_u32 dmx_get_pid(hi_u8 *ts_data)
{
    if (*ts_data != 0x47) {
        hi_log_err("ts_data header is wrong:0x%x\n", *ts_data);
        return 0;
    }
    /*
     * Pid is 13 bits, it is composed of the lower 5 bits of the 2th byte of ts_data shift left 8 bits
     * and the 3ht byte of ts_data.
     */
    return ((*(ts_data + 1) & 0x1F) << 0x8) | *(ts_data + 0x2);
}

static hi_s32 dmx_parser_sc_data_proc_buf(dmx_recbuf_info *sec_buf_info, hi_u8 *buf_vir_addr,
    dmx_scd_buf *scd_buf_info)
{
    hi_u8 *data = HI_NULL;
    hi_u32 dest_idx, src_idx;

    for (data = sec_buf_info->buf_start_vir_addr + scd_buf_info->parse_offset, dest_idx = 0, src_idx = 0;
        dest_idx < HEVC_DUP_DATA_CMP_LEN; src_idx++, data++) {
        /* buf rewind */
        if (data >= sec_buf_info->buf_start_vir_addr + sec_buf_info->buf_size) {
            data = sec_buf_info->buf_start_vir_addr;
        }

        if (*data == 0x47 && ((scd_buf_info->parse_offset + src_idx) % DMX_TS_PKT_SIZE) == 0) {
            if (scd_buf_info->idx_pid != dmx_get_pid(data)) {
                /* skip entire ts pkt, continue will increase src_idx immeidately, so here sub 1 */
                src_idx += (DMX_TS_PKT_SIZE) - 1;
                data += (DMX_TS_PKT_SIZE) - 1;
                continue;
            } else { /* skip ts header,adp, pes header field. */
                const hi_u32 skip_len = TS_PKT_HEADER_LEN + dmx_adp_fld_len(data) + dmx_pes_header_len(data);

                src_idx += skip_len - 1;  /* continue will increase src_idx immeidately, so here sub 1 */
                data += skip_len - 1;
                continue;
            }
        }
        buf_vir_addr[dest_idx++] = *data;
    }

    return HI_SUCCESS;
}

/* for tee hevc index */
static hi_s32 dmx_parser_sc_data(dmx_scd_buf *dmx_scd_buf, hi_u32 rec_id, hi_u8 *scd_data_buf,
    hi_u32 scd_data_buf_len)
{
    hi_s32 ret = HI_FAILURE;
    dmx_rec_info *rec_info = HI_NULL;
    dmx_recbuf_info *sec_buf_info = HI_NULL;
    hi_u8 *buf_vir_addr = HI_NULL;

    hi_dbg_func_enter();

    tee_dmx_mgmt *tee_dmx_mgmt_ptr = get_dmx_mgmt();
    dmx_null_pointer_return(tee_dmx_mgmt_ptr);

    if (scd_data_buf == HI_NULL || scd_data_buf_len == 0) {
        hi_log_err("Invalid buf addr or length");
        hi_warn_print_h32(scd_data_buf);
        hi_warn_print_h32(scd_data_buf_len);
        goto out;
    }

    rec_info = &tee_dmx_mgmt_ptr->rec_info[rec_id];

    sec_buf_info = &rec_info->rec_secbuf;

    if (!(dmx_scd_buf->parse_offset < sec_buf_info->buf_size)) {
        hi_log_err("Invalid parser offset");
        hi_warn_print_h32(dmx_scd_buf->parse_offset);
        goto out;
    }

    if (sec_buf_info->buf_start_vir_addr == HI_NULL) {
        hi_log_err("Invalid secure buffer address\n");
        goto out;
    }

    buf_vir_addr = scd_data_buf;
    if (buf_vir_addr != HI_NULL) {
        ret = dmx_parser_sc_data_proc_buf(sec_buf_info, buf_vir_addr, dmx_scd_buf);
    }

out:
    hi_dbg_func_exit();
    return ret;
}

static hi_s32 dmx_parser_filter_sc_data_proc_buf(dmx_recbuf_info *sec_buf_info, dmx_scd_buf *dmx_scd_buf,
    hi_u8 *buf_vir_addr, dmx_parser_len_info *len_info)
{
    hi_u8 *data = HI_NULL;
    hi_u32 dest_idx, src_idx;

    hi_dbg_func_enter();

    for (data = sec_buf_info->buf_start_vir_addr + dmx_scd_buf->parse_offset, dest_idx = 0, src_idx = 0;
        dest_idx < HEVC_DUP_DATA_TOTAL_LEN; src_idx++, data++) {
        /* buf rewind */
        if (data >= sec_buf_info->buf_start_vir_addr + sec_buf_info->buf_size) {
            data = sec_buf_info->buf_start_vir_addr;
        }

        if (*data == 0x47 && ((dmx_scd_buf->parse_offset + src_idx) % DMX_TS_PKT_SIZE) == 0) {
            if (dmx_scd_buf->idx_pid != dmx_get_pid(data)) {
                /* skip entire ts pkt, continue will increase src_idx immeidately, so here sub 1 */
                src_idx += (DMX_TS_PKT_SIZE) - 1;
                data += (DMX_TS_PKT_SIZE) - 1;
                continue;
            } else { /* skip ts header,adp, pes header field. */
                const hi_u32 skip_len = TS_PKT_HEADER_LEN + dmx_adp_fld_len(data) + dmx_pes_header_len(data);

                src_idx += skip_len - 1;  /* continue will increase src_idx immeidately, so here sub 1 */
                data += skip_len - 1;

                continue;
            }
        }

        buf_vir_addr[dest_idx++] = *data;

        /*
         * according to hevc protocol, key pair('00 00 03') '03' means emulation_prevention_three_byte,
         * need to be deleted.
         */
        if ((dest_idx >= 0x3) && (buf_vir_addr[dest_idx - 0x3] == 0) &&
            (buf_vir_addr[dest_idx - 0x2] == 0) && (buf_vir_addr[dest_idx - 1] == 0x3)) {
            dest_idx--;
            continue;
        }

        /*
         * according to hevc protocol, reach the next Start Code Prefix(0x000001),
         * we consider it as the end of this nal unit
         */
        if (dest_idx >= 0x6 && buf_vir_addr[dest_idx - 0x3] == 0 &&
            buf_vir_addr[dest_idx - 0x2]  == 0 && buf_vir_addr[dest_idx - 1] == 1) {
            break;
        }
    }

    if (len_info != HI_NULL) {
        len_info->mono_parser_len = src_idx;
        len_info->real_parser_len = dest_idx;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
}

static hi_s32 dmx_parser_filter_sc_data(dmx_recbuf_info *sec_buf_info, dmx_scd_buf *dmx_scd_buf,
    dmx_scdata_info *scd_data_info, dmx_parser_len_info *len_info)
{
    hi_s32 ret = HI_FAILURE;

    hi_dbg_func_enter();

    if ((scd_data_info->scdata_buf == HI_NULL) || (scd_data_info->scdata_buf_len == 0)) {
        hi_warn_print_info("Invalid buf addr or length");
        hi_warn_print_h32(scd_data_info->scdata_buf);
        hi_warn_print_h32(scd_data_info->scdata_buf_len);
        goto out;
    }

    if (!(dmx_scd_buf->parse_offset < sec_buf_info->buf_size)) {
        hi_warn_print_info("Invalid parser offset");
        hi_warn_print_h32(dmx_scd_buf->parse_offset);
        goto out;
    }

    if (sec_buf_info->buf_start_vir_addr == HI_NULL) {
        hi_warn_print_info("Invalid secure buffer address");
        hi_warn_print_h32(sec_buf_info->buf_start_vir_addr);
        goto out;
    }

    if (scd_data_info->scdata_buf != HI_NULL) {
        ret = dmx_parser_filter_sc_data_proc_buf(sec_buf_info, dmx_scd_buf, scd_data_info->scdata_buf, len_info);
    }

out:
    hi_dbg_func_exit();
    return ret;
}

static hi_s32 dmx_hevc_recv_enough_data(dmx_scd_buf *dmx_scd_buf, hi_u32 rec_id)
{
    hi_s32 ret;
    hi_u32 loop_times = 0;
    dmx_recbuf_info *sec_buf_info = HI_NULL;
    tee_dmx_mgmt *tee_dmx_mgmt_ptr = get_dmx_mgmt();

    hi_dbg_func_enter();
    dmx_null_pointer_return(tee_dmx_mgmt_ptr);
    sec_buf_info = &(tee_dmx_mgmt_ptr->rec_info[rec_id].rec_secbuf);

    do {
        hi_u64 total_ts_rec_cnt = 0;
        dmx_parser_len_info len_info = {0};
        dmx_scdata_info scd_data_info = {.scdata_buf = dmx_scd_buf->findex_scd.extra_scdata,
            .scdata_buf_len = HEVC_DUP_DATA_TOTAL_LEN};

        ret = dmx_parser_filter_sc_data(sec_buf_info, dmx_scd_buf, &scd_data_info, &len_info);
        if (ret != HI_SUCCESS) {
            goto out;
        }

        dmx_scd_buf->findex_scd.extra_real_scdata_size = len_info.real_parser_len;

        /* ensure dup_data_buf is valid data. */
        tee_dmx_hal_get_rec_ts_cnt(tee_dmx_mgmt_ptr, rec_id, &total_ts_rec_cnt);
        if (total_ts_rec_cnt * DMX_TS_PKT_SIZE - dmx_scd_buf->findex_scd.global_offset >= len_info.mono_parser_len) {
            break;
        }

        /* wait 2ms/4ms/6ms/8ms/10ms */
        if ((loop_times == 0x2) || (loop_times == 0x4) || (loop_times == 0x6) || (loop_times == 0x8) ||
            (loop_times == 10)) { /* 10 times */
            hi_warn_print_info("not receive enough index data within millisecond");
            hi_warn_print_h32(loop_times);

            if (loop_times == 10) { /* 10 times */
                hi_warn_print_info("escape wait index data.\n");
                ret = HI_FAILURE;
                goto out;
            }
        }

        loop_times++;

        if (hi_drv_common_delay_us(1000)) { /* delay 1000ms */
            ret = HI_FAILURE;
            goto out;
        }
    } while (1);

out:
    hi_dbg_func_exit();
    return ret;
}

static hi_s32 dmx_get_hevc_index_data(dmx_scd_buf *dmx_scd_buf, hi_u32 rec_id)
{
    hi_s32 ret;
    hi_u8 *data_after_sc = HI_NULL;
    hi_u8 *dup_data_buf = HI_NULL;

    hi_dbg_func_enter();

    if (sizeof(hi_u8) * HEVC_DUP_DATA_TOTAL_LEN != dmx_scd_buf->findex_scd.extra_scdata_size) {
        hi_log_err("extra_scdata_size is invalid!\n");
    }

    dup_data_buf = dmx_scd_buf->findex_scd.extra_scdata;

    ret = dmx_parser_sc_data(dmx_scd_buf, rec_id, dup_data_buf, HEVC_DUP_DATA_CMP_LEN);
    if (ret != HI_SUCCESS) {
        hi_log_err("ret:0x%x\n", ret);
        goto out;
    }

    /* verify start code first. */
    if (unlikely(!(dup_data_buf[0] == 0x0 && dup_data_buf[1] == 0x0 &&
        (dup_data_buf[0x2] == 0x0 || dup_data_buf[0x2] == 0x1 ||
        dup_data_buf[0x2] == 0x2 || dup_data_buf[0x2] == 0x3) &&
        dmx_scd_buf->findex_scd.start_code == dup_data_buf[0x3]))) {
        hi_log_err("invalid start code(0x%02x 0x%02x 0x%02x 0x%02x) at offset(0x%llx).\n",
            dup_data_buf[0], dup_data_buf[1], dup_data_buf[0x2], dup_data_buf[0x3],
            dmx_scd_buf->findex_scd.global_offset);
        ret = HI_FAILURE;
        goto out;
    }

    data_after_sc = dup_data_buf + HEVC_DATA_OF_SC_OFFSET;

    /* verify saved bytes */
    if (unlikely(memcmp(data_after_sc, dmx_scd_buf->findex_scd.data_after_sc,
        sizeof(hi_u8) * HEVC_DATA_OF_SC_SAVED_LEN))) {
        hi_log_err("dismatched bytes(offset:%llx):0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x.\n",
            dmx_scd_buf->findex_scd.global_offset, data_after_sc[0], data_after_sc[1], data_after_sc[0x2],
            data_after_sc[0x3], data_after_sc[0x4], data_after_sc[0x5], data_after_sc[0x6], data_after_sc[0x7]);

        hi_log_err("saved bytes(offset:%llx):0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x.\n",
            dmx_scd_buf->findex_scd.global_offset, dmx_scd_buf->findex_scd.data_after_sc[0],
            dmx_scd_buf->findex_scd.data_after_sc[1], dmx_scd_buf->findex_scd.data_after_sc[0x2],
            dmx_scd_buf->findex_scd.data_after_sc[0x3], dmx_scd_buf->findex_scd.data_after_sc[0x4],
            dmx_scd_buf->findex_scd.data_after_sc[0x5], dmx_scd_buf->findex_scd.data_after_sc[0x6],
            dmx_scd_buf->findex_scd.data_after_sc[0x7]);
        ret = HI_FAILURE;
        goto out;
    }

    /* verify received enough data */
    ret = dmx_hevc_recv_enough_data(dmx_scd_buf, rec_id);

out:
    hi_dbg_func_exit();
    return ret;
}

hi_s32 dmx_utils_fixup_hevc_index(dmx_scd_buf *dmx_scd_buf)
{
    hi_s32 ret;
    dmx_rec_info *rec_info = HI_NULL;
    tee_dmx_mgmt *tee_dmx_mgmt_ptr = get_dmx_mgmt();
    hi_u32 rec_id = dmx_scd_buf->rec_id;

    if (dmx_scd_buf == HI_NULL) {
        hi_log_err("findex_scd is null\n");
        return HI_FAILURE;
    }

    rec_info = &tee_dmx_mgmt_ptr->rec_info[rec_id];

    dmx_scd_buf->findex_scd.extra_scdata_size = sizeof(hi_u8) * HEVC_DUP_DATA_TOTAL_LEN;
    dmx_scd_buf->findex_scd.extra_real_scdata_size = sizeof(hi_u8) * HEVC_DUP_DATA_TOTAL_LEN;
    dmx_scd_buf->findex_scd.extra_scdata = rec_info->rec_secbuf.buf_start_vir_addr;
    if (!dmx_scd_buf->findex_scd.extra_scdata) {
        hi_log_err("create hevc index extra buffer failed.\n");
        ret = HI_FAILURE;
        goto out0;
    }

    /* get pts data */
    ret = fidx_feed_hevc_index_pts(rec_info->pic_parser, &dmx_scd_buf->findex_scd);
    if (ret == HI_SUCCESS) {
        hi_log_warn("Get pts data success\n");
        goto out1;
    }

    /* receive enough data */
    ret = dmx_get_hevc_index_data(dmx_scd_buf, rec_id);
    if (ret != HI_SUCCESS) {
        hi_log_err("dmx_get_hevc_index_data failed\n");
        goto out0;
    }

    /* parse the hevc index */
    ret = fidx_feed_start_code(rec_info->pic_parser, &dmx_scd_buf->findex_scd);
    if (ret != HI_SUCCESS) {
        hi_log_err("fidx_feed_start_code failed\n");
        goto out0;
    }

out1:
    /* copy back the hevc index data */
    dmx_scd_buf->dmx_rec_index = rec_info->last_frame_info;
out0:
    dmx_scd_buf->findex_scd.extra_scdata = HI_NULL;
    dmx_scd_buf->findex_scd.extra_real_scdata_size = 0;
    dmx_scd_buf->findex_scd.extra_scdata_size = 0;
    return ret;
}

static hi_s32 calc_crc32(const hi_u8 *src, hi_u32 src_len, hi_u32 *dest)
{
    const hi_u32 poly_nomial = 0x04c11db7;
    hi_u32 crc_table[256];          /* Calculate CRC32 size is 256 */
    hi_u32 crc = 0xffffffff;
    hi_u32 i, j;
    hi_u32 crc_accum;
    hi_u32 index;

    if (src_len == 0) {
        return HI_FAILURE;
    }

    /* Init _crc_table[256] flag, Only init once time */
    for (i = 0; i < 256; i++) { /* 256 loops */
        crc_accum = (i << 24); /* left shift 24 bits */

        for (j = 0; j < 8; j++) { /* 8 loops */
            if (crc_accum & 0x80000000L) {
                crc_accum = (crc_accum << 1) ^ poly_nomial;
            } else {
                crc_accum = (crc_accum << 1);
            }
        }

        crc_table[i] = crc_accum;
    }

    while (src_len--) {
        index = ((crc >> 24) ^ *src) & 0xff; /* 24 shift right 3byte, 0xff first byte */
        if (index >= 256) { /* 256 crc_table size */
            return HI_FAILURE;
        }
        crc = (crc << 8) ^ crc_table[index]; /* 8 shift left 1 byte */
        src++;
    }

    *dest = crc;

    return HI_SUCCESS;
}

static hi_s32 __dmx_parse_sec_header(hi_u8 *parser_addr, hi_u32 *section_len, hi_bool *flush_shadow_buf)
{
    hi_u32 cal_crc = 0;
    hi_u32 ori_crc;
    hi_u32 sec_len;
    hi_u32 i;

    /* we only copy the PAT(0x0) or PMT(0x2) or SCTE (0xc6)section data to nosecure world */
    if ((parser_addr[0] != 0x0) && (parser_addr[0] != 0x2) && (parser_addr[0] != 0xc6)) {
        hi_log_err("Only support pat/pmt/scte copy back! tableID = 0x%x\n", parser_addr[0]);
        return HI_FAILURE;
    }

    /* the total section length need to be added 3 bytes forward  */
    sec_len = (((parser_addr[1] & 0x0F) << 8) | parser_addr[0x2]) + 0x3; /* 8 bits */
    if ((sec_len <= 0x4) || (sec_len > DMX_MAX_SEC_LEN)) {
        hi_log_err("invalid packet_len(%u)\n", sec_len);
        return HI_FAILURE;
    }

    /* calculate the crc */
    if (calc_crc32(parser_addr, sec_len - 0x4, &cal_crc) != HI_SUCCESS) {
        hi_log_err("get section crc failed!\n");
        return HI_FAILURE;
    }

    ori_crc = (parser_addr[sec_len - 1] | ((parser_addr[sec_len - 0x2] << 0x8) & 0xFF00) |
        ((parser_addr[sec_len - 0x3] << 16) & 0xFF0000) | /* left shift 16 bits */
        ((parser_addr[sec_len - 0x4] << 24) & 0xFF000000)); /* left shift 24 bits */

    if (cal_crc != ori_crc) {
        hi_log_err("cal_crc: %u, ori_crc: %u, sec_len: %u, 0x%x, 0x%x, 0x%x, 0x%x \n", cal_crc, ori_crc, sec_len,
            parser_addr[sec_len - 1], parser_addr[sec_len - 0x2], parser_addr[sec_len - 0x3],
            parser_addr[sec_len - 0x4]);
    }
    *flush_shadow_buf = (cal_crc == ori_crc) ? HI_TRUE : HI_FALSE;
    *section_len = sec_len;
    return HI_SUCCESS;
}

static hi_s32 _dmx_sec_flush_shadow_buf(dmx_play_pes_sec *chn, dmx_sec_pes_flush_info *flush_info)
{
    hi_s32 ret;
    hi_u32 data_len;
    hi_bool flush_shadow_buf = HI_FALSE;

    ret = __dmx_parse_sec_header(chn->pes_sec_secbuf.buf_start_vir_addr + flush_info->offset, &data_len,
        &flush_shadow_buf);
    if (ret != HI_SUCCESS) {
        hi_log_err("parse section header failed. ret = 0x%x\n", ret);
        return ret;
    }

    if (flush_shadow_buf == HI_TRUE) {
        ret = memcpy_s(chn->pes_sec_secbuf.shadow_buf_start_vir_addr + flush_info->offset,
            chn->pes_sec_secbuf.shadow_buf_size - flush_info->offset,
            chn->pes_sec_secbuf.buf_start_vir_addr + flush_info->offset, data_len);
        if (ret != EOK) {
            hi_log_err("copy secbuf data to shadow buffer failed. offset: %u, shadow_buf_size: %u, data_len: %u, "
                "ret = 0x%x\n", flush_info->offset, chn->pes_sec_secbuf.shadow_buf_size, data_len, ret);
            return HI_FAILURE;
        }
    } else {
        ret = memset_s(chn->pes_sec_secbuf.shadow_buf_start_vir_addr + flush_info->offset,
            chn->pes_sec_secbuf.shadow_buf_size - flush_info->offset, 0x0, data_len);
        if (ret != EOK) {
            hi_log_err("call memset_s failed. ret = 0x%x\n", ret);
            return HI_FAILURE;
        }
    }
    flush_info->data_len = data_len;

    return HI_SUCCESS;
}

static hi_s32 ___dmx_parse_pes_header(hi_u8 *parser_addr, hi_u32 *pes_len, hi_bool *flush_shadow_buf)
{
    const hi_u32 pes_header_len = 0x6;    /* 3(packet_start_code_prefix) + 1(stream_id) +2(pes_packet_length) */
    hi_u32 pes_pay_load_len;
    hi_u8 stream_id;

    if ((parser_addr[0] != 0x00) || (parser_addr[1] != 0x00) || (parser_addr[0x2] != 0x01)) {
        hi_log_err("pes start byte = 0x%x 0x%x 0x%x\n", parser_addr[0], parser_addr[1], parser_addr[0x2]);
        return HI_FAILURE;
    }
    hi_log_dbg("success pes start byte = 0x%x 0x%x 0x%x\n", parser_addr[0], parser_addr[1], parser_addr[0x2]);

    /* the value of pes_packet_length */
    pes_pay_load_len = ((parser_addr[0x4] << 8) | parser_addr[0x5]); /* 8 bits */

    *pes_len = pes_header_len + pes_pay_load_len;
    stream_id = parser_addr[0x3];   /* parser_addr[0x3]: stream_id */

    /*
     * [0xc0 ~ 0xe0): ISOhEC 13818-3 or ISOhEC 11172-3 or ISO/IEC 13818-7 or ISOhEC 14496-3 audio stream number x xxxx
     */
    if ((stream_id >= 0xc0) && (stream_id < 0xe0)) {
        *flush_shadow_buf = HI_TRUE;
    }

    return HI_SUCCESS;
}

static hi_s32 __dmx_parse_pes_unit(dmx_playbuf_info *playbuf, dmx_sec_pes_flush_info *flush_info,
    hi_bool *flush_shadow_buf)
{
    hi_s32 ret;
    hi_bool tmp_rool = HI_FALSE;
    hi_u8 *parse_addr = HI_NULL;
    hi_u8 pes_head_arry[DMX_PES_HEADER_LENGTH] = {0};

    if (flush_info->rool_flag == HI_TRUE) {
        if (playbuf->buf_size - flush_info->offset < DMX_PES_HEADER_LENGTH) {
            tmp_rool = HI_TRUE;
            ret = memcpy_s(pes_head_arry, sizeof(pes_head_arry), playbuf->buf_start_vir_addr + flush_info->offset,
                playbuf->buf_size - flush_info->offset);
            if (ret != EOK) {
                hi_log_err("call memcpy_s failed. ret = 0x%x, offset: %u, buf_size: %u\n", ret, flush_info->offset,
                    playbuf->buf_size);
                return ret;
            }
            ret = memcpy_s(pes_head_arry + playbuf->buf_size - flush_info->offset,
                sizeof(pes_head_arry) + flush_info->offset - playbuf->buf_size, playbuf->buf_start_vir_addr,
                DMX_PES_HEADER_LENGTH + flush_info->offset - playbuf->buf_size);
            if (ret != EOK) {
                hi_log_err("call memcpy_s failed. ret = 0x%x\n", ret);
                return ret;
            }
        } else {
            tmp_rool = HI_FALSE;
            ret = memcpy_s(pes_head_arry, sizeof(pes_head_arry), playbuf->buf_start_vir_addr + flush_info->offset,
                DMX_PES_HEADER_LENGTH);
            if (ret != EOK) {
                hi_log_err("call memcpy_s failed. ret = 0x%x\n", ret);
                return ret;
            }
        }
        parse_addr = pes_head_arry;
    } else {
        parse_addr = playbuf->buf_start_vir_addr + flush_info->offset;
    }

    ret = ___dmx_parse_pes_header(parse_addr, &(flush_info->data_len), flush_shadow_buf);
    if (ret != HI_SUCCESS) {
        hi_log_err("header_byte: 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x\n", parse_addr[0],
            parse_addr[1], parse_addr[0x2], parse_addr[0x3], parse_addr[0x4], parse_addr[0x5], parse_addr[0x6],
            parse_addr[0x7], parse_addr[0x8]);
        hi_log_err("offset: %u, rool_flag: %d, tmp_rool: %d\n", flush_info->offset, flush_info->rool_flag, tmp_rool);
    }

    flush_info->rool_flag = tmp_rool;

    return ret;
}

static hi_s32 _dmx_pes_flush_shadow_buf(dmx_play_pes_sec *chn, dmx_sec_pes_flush_info *flush_info)
{
    hi_s32 ret;
    hi_u32 tmp_len;
    hi_bool flush_shadow_buf = HI_FALSE;

    ret = __dmx_parse_pes_unit(&(chn->pes_sec_secbuf), flush_info, &flush_shadow_buf);
    if (ret != HI_SUCCESS) {
        hi_log_err("parse pes unit failed!\n");
        return ret;
    }

    if (flush_info->data_len + flush_info->offset > chn->pes_sec_secbuf.buf_size) {
        flush_info->rool_flag = HI_TRUE;
        if (flush_info->offset + flush_info->data_len > chn->pes_sec_secbuf.buf_size + DMX_PES_PACKAGE_MAX_LEN) {
            flush_info->data_len = chn->pes_sec_secbuf.buf_size + DMX_PES_PACKAGE_MAX_LEN - flush_info->offset;
        }
    }

    if (flush_shadow_buf == HI_FALSE) {
        if (memset_s(chn->pes_sec_secbuf.shadow_buf_start_vir_addr + flush_info->offset, flush_info->data_len,
            0x0, flush_info->data_len) != EOK) {
            hi_log_err("copy secbuf tail data to shadow buffer failed. data_len: %u\n", flush_info->data_len);
            return HI_FAILURE;
        }
        return HI_SUCCESS;
    }

    if (flush_info->rool_flag == HI_TRUE) {
        /* append head data to shadowbuffer tail */
        tmp_len = flush_info->offset + flush_info->data_len - chn->pes_sec_secbuf.buf_size;
        if (memcpy_s(chn->pes_sec_secbuf.shadow_buf_start_vir_addr + chn->pes_sec_secbuf.buf_size,
            chn->pes_sec_secbuf.shadow_buf_size - chn->pes_sec_secbuf.buf_size,
            chn->pes_sec_secbuf.buf_start_vir_addr, tmp_len) != EOK) {
            hi_log_err("copy secbuf head data to shadow buffer failed. data_len: %u\n", tmp_len);
            return HI_FAILURE;
        }

        /* copy tail data to shadowbuffer */
        if (memcpy_s(chn->pes_sec_secbuf.shadow_buf_start_vir_addr + flush_info->offset,
            chn->pes_sec_secbuf.buf_size - flush_info->offset,
            chn->pes_sec_secbuf.buf_start_vir_addr + flush_info->offset, flush_info->data_len - tmp_len) != EOK) {
            hi_log_err("copy secbuf tail data to shadow buffer failed. data_len: %u\n", flush_info->data_len - tmp_len);
            return HI_FAILURE;
        }
    } else {
        if (memcpy_s(chn->pes_sec_secbuf.shadow_buf_start_vir_addr + flush_info->offset,
            chn->pes_sec_secbuf.buf_size - flush_info->offset,
            chn->pes_sec_secbuf.buf_start_vir_addr + flush_info->offset, flush_info->data_len) != EOK) {
            hi_log_err("copy secbuf tail data to shadow buffer failed. data_len: %u\n", flush_info->data_len);
            return HI_FAILURE;
        }
    }

    return HI_SUCCESS;
}

hi_s32 dmx_sec_pes_flush_shadow_buf(dmx_sec_pes_flush_info *flush_info)
{
    hi_s32 ret = HI_FAILURE;
    tee_dmx_mgmt *tee_dmx_mgmt_ptr = get_dmx_mgmt();
    dmx_play_pes_sec *chn = HI_NULL;

    dmx_null_pointer_return(flush_info);
    if (flush_info->chan_id >= DMX_PLAY_SEC_PES_CNT) {
        hi_log_err("dmx_sec_pes_flush_shadow_buf, invalid chan_id(%u)\n", flush_info->chan_id);
        return HI_FAILURE;
    }

    chn = &(tee_dmx_mgmt_ptr->play_pes_sec[flush_info->chan_id]);
    if (flush_info->offset >= chn->pes_sec_secbuf.buf_size) {
        hi_log_err("invalid offset(%u), buffer_size(%u).\n", flush_info->offset, chn->pes_sec_secbuf.buf_size);
        return HI_FAILURE;
    }

    if (flush_info->chan_type == DMX_CHAN_TYPE_SEC) {
        ret = _dmx_sec_flush_shadow_buf(chn, flush_info);
    } else if (flush_info->chan_type == DMX_CHAN_TYPE_PES) {
        ret = _dmx_pes_flush_shadow_buf(chn, flush_info);
    }

    if (ret != HI_SUCCESS) {
        hi_log_err("flush shadow buffer failed. ret = 0x%x, chan_type: %d\n", ret, flush_info->chan_type);
    }

    return ret;
}

hi_s32 dmx_flt_sec_pes_lock(const dmx_tee_flt_info *flt_info)
{
    tee_dmx_mgmt *tee_dmx_mgmt_ptr = get_dmx_mgmt();

    tee_dmx_hal_flt_pes_sec_config(tee_dmx_mgmt_ptr, flt_info);

    return HI_SUCCESS;
}

hi_s32 dmx_config_cc_drop_info(const dmx_tee_cc_drop_info *info)
{
    tee_dmx_mgmt *tee_dmx_mgmt_ptr = get_dmx_mgmt();

    tee_dmx_hal_pid_tab_set_cc_drop(tee_dmx_mgmt_ptr, info->pid_ch_id, info->ccerr_drop, info->ccrepeat_drop);

    return HI_SUCCESS;
}

/*************************dmx_dsc_fct******************************/
static hi_s32 _dmx_dsc_fct_create(const dmx_dsc_attrs *attrs, hi_u32 dsc_id)
{
    hi_s32 ret;
    dmx_key_info *key_info = HI_NULL;
    tee_dmx_mgmt *tee_dmx_mgmt_ptr = get_dmx_mgmt();

    dmx_err_condition_return(dsc_id >= DMX_KEY_CNT, HI_ERR_DMX_INVALID_PARA);

    demux_mutex_lock(&tee_dmx_mgmt_ptr->lock_all_key);
    key_info = &tee_dmx_mgmt_ptr->key_info[dsc_id];
    key_info->ca_type = attrs->ca_type;
    key_info->ca_entropy = attrs->ca_entropy;
    key_info->alg = attrs->alg;
    key_info->key_len = DMX_KEY_MAX_LEN;
    key_info->keyslot_create_en = attrs->keyslot_create_en;
    key_info->key_secure_mode = attrs->key_secure_mode;

    ret = dmx_get_user_uuid(&key_info->user_uuid);
    if (ret != HI_SUCCESS) {
        hi_log_err("get user uuid error!\n");
        goto unlock_exit;
    }
    demux_mutex_unlock(&tee_dmx_mgmt_ptr->lock_all_key);

    demux_mutex_lock(&tee_dmx_mgmt_ptr->lock_all_key);
    if (attrs->keyslot_create_en == HI_TRUE) {
        ret = hi_drv_ks_create(HI_KEYSLOT_TYPE_TSCIPHER, &key_info->ks_handle);
        if (ret != HI_SUCCESS) {
            hi_log_err("create keyslot failed! ret=%#x\n", ret);
            goto unlock_exit;
        }
        /* let keyslot_attached = HI_TRUE, keyslot can attach pid channel automatic,
         * when call _raw_pid_ch_attach_dsc.
         */
        key_info->keyslot_attached = HI_TRUE;
        key_info->key_id = KS_HANDLE_2_ID(key_info->ks_handle);
    } else {
        key_info->ks_handle = HI_INVALID_HANDLE;
        key_info->keyslot_attached = HI_FALSE;
        key_info->key_id = dsc_id;
    }

    demux_mutex_unlock(&tee_dmx_mgmt_ptr->lock_all_key);

    return HI_SUCCESS;

unlock_exit:
    demux_mutex_unlock(&tee_dmx_mgmt_ptr->lock_all_key);
    return ret;
}

static hi_s32 _dmx_dsc_fct_destroy(hi_u32 dsc_id)
{
    hi_s32 ret;
    dmx_key_info *key_info = HI_NULL;
    tee_dmx_mgmt *tee_dmx_mgmt_ptr = get_dmx_mgmt();

    dmx_err_condition_return(dsc_id >= DMX_KEY_CNT, HI_ERR_DMX_INVALID_PARA);

    demux_mutex_lock(&tee_dmx_mgmt_ptr->lock_all_key);
    key_info = &tee_dmx_mgmt_ptr->key_info[dsc_id];

    if (key_info->keyslot_create_en == HI_TRUE && key_info->ks_handle != HI_INVALID_HANDLE) {
        check_keyslot_handle_goto(key_info->ks_handle, unlock_exit);

        ret = hi_drv_ks_destory(HI_KEYSLOT_TYPE_TSCIPHER, key_info->ks_handle);
        if (ret != HI_SUCCESS) {
            hi_log_err("destroy keyslot failed!\n");
            goto unlock_exit;
        }
    }
    key_info->ks_handle = HI_INVALID_HANDLE;
    key_info->key_id = 0;
    key_info->ca_entropy = DMX_CA_ENTROPY_MAX;
    key_info->alg = HI_CRYPTO_ENGINE_ALG_MAX;
    key_info->key_len = 0;
    key_info->key_secure_mode = DMX_KEY_MODE_MAX;
    ret = memset_s(key_info->iv, sizeof(key_info->iv), 0, sizeof(key_info->iv));
    if (ret != HI_SUCCESS) {
        hi_log_err("memset_s failed!\n");
        demux_mutex_unlock(&tee_dmx_mgmt_ptr->lock_all_key);
        return ret;
    }

    ret = HI_SUCCESS;

unlock_exit:
    demux_mutex_unlock(&tee_dmx_mgmt_ptr->lock_all_key);
    return ret;
}

static hi_s32 _dmx_dsc_get_attrs(hi_u32 dsc_id, dmx_dsc_attrs *attrs)
{
    dmx_key_info *key_info = HI_NULL;
    tee_dmx_mgmt *tee_dmx_mgmt_ptr = get_dmx_mgmt();

    dmx_err_condition_return(dsc_id >= DMX_KEY_CNT, HI_ERR_DMX_INVALID_PARA);
    demux_mutex_lock(&tee_dmx_mgmt_ptr->lock_all_key);

    key_info = &tee_dmx_mgmt_ptr->key_info[dsc_id];
    attrs->ca_type = key_info->ca_type;
    attrs->ca_entropy = key_info->ca_entropy;
    attrs->alg = key_info->alg;
    attrs->keyslot_create_en = key_info->keyslot_create_en;

    demux_mutex_unlock(&tee_dmx_mgmt_ptr->lock_all_key);
    return HI_SUCCESS;
}

static hi_s32 _dmx_dsc_set_attrs(hi_u32 dsc_id, const dmx_dsc_attrs *attrs)
{
    hi_s32 ret;
    dmx_key_info *key_info = HI_NULL;
    tee_dmx_mgmt *tee_dmx_mgmt_ptr = get_dmx_mgmt();

    dmx_err_condition_return(dsc_id >= DMX_KEY_CNT, HI_ERR_DMX_INVALID_PARA);
    demux_mutex_lock(&tee_dmx_mgmt_ptr->lock_all_key);

    key_info = &tee_dmx_mgmt_ptr->key_info[dsc_id];
    if (attrs->ca_entropy != key_info->ca_entropy) {
        hi_log_err("dsc_fct not support change ca_entropy yet!\n");
        ret = HI_ERR_DMX_INVALID_PARA;
        goto unlock_exit;
    }

    key_info->alg = attrs->alg;
    key_info->ca_type = attrs->ca_type;
    key_info->ca_entropy = attrs->ca_entropy;
    key_info->keyslot_create_en = attrs->keyslot_create_en;

    ret = HI_SUCCESS;

unlock_exit:
    demux_mutex_unlock(&tee_dmx_mgmt_ptr->lock_all_key);
    return ret;
}

static hi_s32 _dmx_dsc_attach_pid_ch(hi_u32 dsc_id, hi_handle pid_ch_handle)
{
    hi_s32 ret;
    hi_u32 raw_pid_chan_id;
    dmx_key_info *key_info = HI_NULL;
    tee_dmx_mgmt *tee_dmx_mgmt_ptr = get_dmx_mgmt();

    dmx_err_condition_return(dsc_id >= DMX_KEY_CNT, HI_ERR_DMX_INVALID_PARA);
    demux_mutex_lock(&tee_dmx_mgmt_ptr->lock_all_key);
    key_info = &tee_dmx_mgmt_ptr->key_info[dsc_id];

    /* if keyslot_attached == HI_FALSE,means keyslot created by keyslot unf fucntion,
     * so we should let dsc attach keyslot at first.
     */
    if (key_info->keyslot_attached == HI_FALSE) {
        hi_log_warn("Descrambler will attach pid channel at a later time!\n");
        ret = HI_ERR_DMX_NOATTACH_KEY;
        goto unlock_exit;
    }

    raw_pid_chan_id = dmx_handle_2_id(pid_ch_handle);

    /* enable the descrambler */
    tee_dmx_hal_pid_cw_en_set(tee_dmx_mgmt_ptr, raw_pid_chan_id, HI_TRUE);
    tee_dmx_hal_pid_set_cw_id(tee_dmx_mgmt_ptr, raw_pid_chan_id, key_info->key_id);
    /* enable ts descrambler support */
    tee_dmx_hal_pid_set_dsc_type(tee_dmx_mgmt_ptr, key_info->key_id, HI_TRUE, HI_FALSE);

    ret = HI_SUCCESS;

unlock_exit:
    demux_mutex_unlock(&tee_dmx_mgmt_ptr->lock_all_key);
    return ret;
}

static hi_s32 _dmx_dsc_detach_pid_ch(hi_u32 dsc_id, hi_handle pid_ch_handle)
{
    hi_u32 raw_pid_chan_id;
    dmx_key_info *key_info = HI_NULL;
    tee_dmx_mgmt *tee_dmx_mgmt_ptr = get_dmx_mgmt();

    dmx_err_condition_return(dsc_id >= DMX_KEY_CNT, HI_ERR_DMX_INVALID_PARA);
    demux_mutex_lock(&tee_dmx_mgmt_ptr->lock_all_key);
    key_info = &tee_dmx_mgmt_ptr->key_info[dsc_id];

    raw_pid_chan_id = dmx_handle_2_id(pid_ch_handle);

    /* disable the descrambler */
    tee_dmx_hal_pid_cw_en_set(tee_dmx_mgmt_ptr, raw_pid_chan_id, HI_FALSE);
    tee_dmx_hal_pid_set_cw_id(tee_dmx_mgmt_ptr, raw_pid_chan_id, 0);
    /* disable ts descrambler support */
    tee_dmx_hal_pid_set_dsc_type(tee_dmx_mgmt_ptr, key_info->key_id, HI_FALSE, HI_FALSE);

    demux_mutex_unlock(&tee_dmx_mgmt_ptr->lock_all_key);

    return HI_SUCCESS;
}

static hi_s32 _dmx_dsc_attach_keyslot(hi_u32 dsc_id, hi_handle ks_handle)
{
    hi_s32 ret;
    dmx_key_info *key_info = HI_NULL;
    tee_dmx_mgmt *tee_dmx_mgmt_ptr = get_dmx_mgmt();

    dmx_err_condition_return(dsc_id >= DMX_KEY_CNT, HI_ERR_DMX_INVALID_PARA);
    demux_mutex_lock(&tee_dmx_mgmt_ptr->lock_all_key);
    key_info = &tee_dmx_mgmt_ptr->key_info[dsc_id];

    if ((key_info->ks_handle != HI_INVALID_HANDLE) && (key_info->keyslot_attached == HI_TRUE)) {
        hi_log_err("This descrambler has already attach keyslot!\n");
        ret = HI_ERR_DMX_ATTACHED_KEY;
        goto unlock_exit;
    }

    /* if rdsc_fct->keyslot_handle == HI_INVALID_HANDLE meanse dsc did not attach keyslot */
    key_info->ks_handle = ks_handle;
    key_info->keyslot_attached = HI_TRUE;
    key_info->key_id = KS_HANDLE_2_ID(ks_handle);

    tee_dmx_hal_mdscset_entropy_reduction(tee_dmx_mgmt_ptr, key_info->key_id, DMX_CA_ENTROPY_CLOSE);

    ret = HI_SUCCESS;

unlock_exit:
    demux_mutex_unlock(&tee_dmx_mgmt_ptr->lock_all_key);
    return ret;
}

static hi_s32 _dmx_dsc_detach_keyslot(hi_u32 dsc_id)
{
    dmx_key_info *key_info = HI_NULL;
    tee_dmx_mgmt *tee_dmx_mgmt_ptr = get_dmx_mgmt();

    dmx_err_condition_return(dsc_id >= DMX_KEY_CNT, HI_ERR_DMX_INVALID_PARA);

    demux_mutex_lock(&tee_dmx_mgmt_ptr->lock_all_key);
    key_info = &tee_dmx_mgmt_ptr->key_info[dsc_id];

    key_info->keyslot_attached = HI_FALSE;
    key_info->key_id = 0;

    demux_mutex_unlock(&tee_dmx_mgmt_ptr->lock_all_key);

    return HI_SUCCESS;
}

static hi_s32 _dmx_dsc_get_keyslot_handle(hi_u32 dsc_id, hi_handle *ks_handle)
{
    hi_s32 ret;
    dmx_key_info *key_info = HI_NULL;
    tee_dmx_mgmt *tee_dmx_mgmt_ptr = get_dmx_mgmt();

    dmx_err_condition_return(dsc_id >= DMX_KEY_CNT, HI_ERR_DMX_INVALID_PARA);

    demux_mutex_lock(&tee_dmx_mgmt_ptr->lock_all_key);
    key_info = &tee_dmx_mgmt_ptr->key_info[dsc_id];

    if (key_info->ks_handle == HI_INVALID_HANDLE) {
        hi_log_err("keyslot is not attached!\n");
        ret = HI_ERR_DMX_NOATTACH_KEY;
        goto unlock_exit;
    }

    *ks_handle = key_info->ks_handle;

    ret = HI_SUCCESS;

unlock_exit:
    demux_mutex_unlock(&tee_dmx_mgmt_ptr->lock_all_key);
    return ret;
}

static hi_s32 _dmx_dsc_set_sys_key(hi_u32 dsc_id, const hi_u8 *key, hi_u32 len)
{
    hi_s32 ret;
    hi_u32 i;
    hi_u8 tmp_key[DMX_SYS_KEY_LEN] = {0};
    tee_dmx_mgmt *tee_dmx_mgmt_ptr = get_dmx_mgmt();

    dmx_err_condition_return(dsc_id >= DMX_KEY_CNT, HI_ERR_DMX_INVALID_PARA);

    demux_mutex_lock(&tee_dmx_mgmt_ptr->lock_all_key);

    if (len != DMX_SYS_KEY_LEN) {
        hi_log_err("system key len:%u, is not 32 Bytes!\n", len);
        ret = HI_ERR_DMX_INVALID_PARA;
        goto unlock_exit;
    }

    /* multi2 alg need reverse system key */
    for (i = 0; i < len; i++) {
        tmp_key[i] = key[len - i - 1];
    }

    /* set multi2 system key */
    tee_dmx_hal_mdsc_multi2_sys_key_cfg(tee_dmx_mgmt_ptr, tmp_key, len);

    ret = HI_SUCCESS;

unlock_exit:
    demux_mutex_unlock(&tee_dmx_mgmt_ptr->lock_all_key);
    return ret;
}

static hi_s32 _dmx_dsc_set_iv(hi_u32 dsc_id, dmx_dsc_key_type ivtype, const hi_u8 *iv, hi_u32 len)
{
    hi_s32 ret;
    klad_clear_iv_param iv_para = {0};
    dmx_key_info *key_info = HI_NULL;
    tee_dmx_mgmt *tee_dmx_mgmt_ptr = get_dmx_mgmt();

    dmx_err_condition_return(dsc_id >= DMX_KEY_CNT, HI_ERR_DMX_INVALID_PARA);

    demux_mutex_lock(&tee_dmx_mgmt_ptr->lock_all_key);
    key_info = &tee_dmx_mgmt_ptr->key_info[dsc_id];

    if (key_info->ks_handle == HI_INVALID_HANDLE) {
        hi_log_err("keyslot handle is invallid, dsc_id=%#x!\n", dsc_id);
        ret = HI_FAILURE;
        goto unlock_exit;
    }

    iv_para.ks_handle = key_info->ks_handle;
    if (ivtype == DMX_DSC_KEY_ODD) {
        iv_para.is_odd = HI_TRUE;
    } else if (ivtype == DMX_DSC_KEY_EVEN) {
        iv_para.is_odd = HI_FALSE;
    } else {
        hi_log_err("key type is error!\n");
        goto unlock_exit;
    }

    len = len > DMX_KEY_MAX_LEN ? DMX_KEY_MAX_LEN : len;
    ret = memcpy_s(iv_para.iv, HI_KLAD_MAX_IV_LEN, iv, len);
    if (ret != HI_SUCCESS) {
        hi_log_err("memcpy_s failed!\n");
        demux_mutex_unlock(&tee_dmx_mgmt_ptr->lock_all_key);
        return ret;
    }

    ret = hi_drv_klad_clear_iv(&iv_para);
    if (ret != HI_SUCCESS) {
        hi_log_err("set iv failed!\n");
        goto unlock_exit;
    }

    ret = HI_SUCCESS;

unlock_exit:
    demux_mutex_unlock(&tee_dmx_mgmt_ptr->lock_all_key);
    return ret;
}

static hi_s32 _dmx_dsc_get_key_handle(hi_handle pid_ch_handle, hi_handle *dsc_handle)
{
    hi_s32 ret;
    hi_u32 idx;
    hi_u32 raw_pid_chan_id;
    hi_u32 cw_id;
    tee_dmx_mgmt *tee_dmx_mgmt_ptr = get_dmx_mgmt();

    demux_mutex_lock(&tee_dmx_mgmt_ptr->lock_all_key);
    raw_pid_chan_id = dmx_handle_2_id(pid_ch_handle);
    tee_dmx_hal_pid_get_cw_id(tee_dmx_mgmt_ptr, raw_pid_chan_id, &cw_id);

    for (idx = 0; idx < tee_dmx_mgmt_ptr->key_cnt; idx++) {
        if (tee_dmx_mgmt_ptr->key_info[idx].key_id == cw_id) {
            break;
        }
    }
    if (idx >= tee_dmx_mgmt_ptr->key_cnt) {
        hi_log_err("descrambler did not attach pid channel yet!\n");
        goto error_exit;
    }

    *dsc_handle = dmx_id_2_handle(idx);
    ret = HI_SUCCESS;

error_exit:
    demux_mutex_unlock(&tee_dmx_mgmt_ptr->lock_all_key);
    return ret;
}

static hi_s32 _dmx_dsc_get_chan_handle(hi_u32 dmx_id, hi_u32 pid, hi_u32 *chan_num, hi_handle chan[])
{
    hi_u32 idx;
    hi_u32 cnt = 0;
    tee_dmx_mgmt *tee_dmx_mgmt_ptr = get_dmx_mgmt();

    demux_mutex_lock(&tee_dmx_mgmt_ptr->lock_all_key);

    for (idx = 0; idx < tee_dmx_mgmt_ptr->dmx_raw_pidch_cnt; idx++) {
        if ((tee_dmx_hal_pid_tab_flt_check(tee_dmx_mgmt_ptr, idx, dmx_id, pid) == HI_TRUE)) {
            chan[cnt] = dmx_id_2_handle(idx);
            cnt++;
        }
    }
    *chan_num = cnt;

    demux_mutex_unlock(&tee_dmx_mgmt_ptr->lock_all_key);

    return HI_SUCCESS;
}

hi_s32 dmx_dsc_fct_create(const dmx_dsc_attrs *attrs, hi_handle *handle)
{
    hi_s32 ret;
    hi_u32 id;
    tee_dmx_mgmt *tee_dmx_mgmt_ptr = get_dmx_mgmt();

    dmx_null_pointer_return(attrs);
    dmx_null_pointer_return(handle);

    demux_mutex_lock(&tee_dmx_mgmt_ptr->lock_all_key);
    id = find_first_zero_bit(tee_dmx_mgmt_ptr->key_bitmap, tee_dmx_mgmt_ptr->key_cnt);
    if (!(id < tee_dmx_mgmt_ptr->key_cnt)) {
        hi_log_err("there is no available desc now!\n");
        ret = HI_ERR_DMX_NO_RESOURCE;
        goto error_exit;
    }
    demux_mutex_unlock(&tee_dmx_mgmt_ptr->lock_all_key);

    ret = _dmx_dsc_fct_create(attrs, id);
    if (ret != HI_SUCCESS) {
        goto error_exit;
    }

    demux_mutex_lock(&tee_dmx_mgmt_ptr->lock_all_key);
    if (attrs->alg == HI_CRYPTO_ENGINE_ALG_CSA2) {
        if ((attrs->ca_entropy != DMX_CA_ENTROPY_CLOSE) && (attrs->ca_entropy != DMX_CA_ENTROPY_OPEN)) {
            hi_log_err("ca_entropy=%d\n", attrs->ca_entropy);
            ret = HI_ERR_DMX_INVALID_PARA;
            goto error_exit;
        }
        tee_dmx_hal_mdscset_entropy_reduction(tee_dmx_mgmt_ptr, tee_dmx_mgmt_ptr->key_info[id].key_id,
            attrs->ca_entropy);
    }

    if (attrs->key_secure_mode == DMX_KEY_MODE_TEE_SECURE) {
        tee_dmx_hal_mdsc_key_slot_sec_cfg(tee_dmx_mgmt_ptr, tee_dmx_mgmt_ptr->key_info[id].key_id, HI_TRUE);
    }

    *handle = dmx_id_2_handle(id);
    bitmap_setbit(id, tee_dmx_mgmt_ptr->key_bitmap);

    demux_mutex_unlock(&tee_dmx_mgmt_ptr->lock_all_key);

    return HI_SUCCESS;

error_exit:
    demux_mutex_unlock(&tee_dmx_mgmt_ptr->lock_all_key);
    return ret;
}

hi_s32 dmx_dsc_get_attrs(hi_handle handle, dmx_dsc_attrs *attrs)
{
    hi_u32 dsc_idx;

    DMX_CHECK_HANDLE(handle);
    dmx_null_pointer_return(attrs);

    dsc_idx = dmx_handle_2_id(handle);

    return _dmx_dsc_get_attrs(dsc_idx, attrs);
}

hi_s32 dmx_dsc_set_attrs(hi_handle handle, const dmx_dsc_attrs *attrs)
{
    hi_u32 dsc_idx;

    DMX_CHECK_HANDLE(handle);
    dmx_null_pointer_return(attrs);

    dsc_idx = dmx_handle_2_id(handle);

    return _dmx_dsc_set_attrs(dsc_idx, attrs);
}

hi_s32 dmx_dsc_attach_pid_ch(hi_handle handle, hi_handle pid_ch_handle)
{
    hi_u32 dsc_idx;

    DMX_CHECK_HANDLE(handle);
    DMX_CHECK_HANDLE(pid_ch_handle);

    dsc_idx = dmx_handle_2_id(handle);

    return _dmx_dsc_attach_pid_ch(dsc_idx, pid_ch_handle);
}

hi_s32 dmx_dsc_detach_pid_ch(hi_handle handle, hi_handle pid_ch_handle)
{
    hi_u32 dsc_idx;

    DMX_CHECK_HANDLE(handle);
    DMX_CHECK_HANDLE(pid_ch_handle);

    dsc_idx = dmx_handle_2_id(handle);

    return _dmx_dsc_detach_pid_ch(dsc_idx, pid_ch_handle);
}

hi_s32 dmx_dsc_attach_keyslot(hi_handle handle, hi_handle ks_handle)
{
    hi_u32 dsc_idx;

    DMX_CHECK_HANDLE(handle);
    CHECK_KEYSLOT_HANDLE(ks_handle);

    dsc_idx = dmx_handle_2_id(handle);

    return _dmx_dsc_attach_keyslot(dsc_idx, ks_handle);
}

hi_s32 dmx_dsc_detach_keyslot(hi_handle handle)
{
    hi_u32 dsc_idx;

    DMX_CHECK_HANDLE(handle);

    dsc_idx = dmx_handle_2_id(handle);

    return _dmx_dsc_detach_keyslot(dsc_idx);
}

hi_s32 dmx_dsc_get_keyslot_handle(hi_handle handle, hi_handle *ks_handle)
{
    hi_u32 dsc_idx;

    DMX_CHECK_HANDLE(handle);
    dmx_null_pointer_return(ks_handle);

    dsc_idx = dmx_handle_2_id(handle);

    return _dmx_dsc_get_keyslot_handle(dsc_idx, ks_handle);
}

hi_s32 dmx_dsc_set_sys_key(hi_handle handle, const hi_u8 *key, hi_u32 len)
{
    hi_u32 dsc_idx;

    DMX_CHECK_HANDLE(handle);
    dmx_null_pointer_return(key);

    dsc_idx = dmx_handle_2_id(handle);

    return _dmx_dsc_set_sys_key(dsc_idx, key, len);
}

hi_s32 dmx_dsc_set_iv(hi_handle handle, dmx_dsc_key_type ivtype, const hi_u8 *iv, hi_u32 len)
{
    hi_u32 dsc_idx;

    DMX_CHECK_HANDLE(handle);
    dmx_null_pointer_return(iv);
    dmx_err_condition_return(len < DMX_KEY_MIN_LEN || len > DMX_KEY_MAX_LEN, HI_ERR_DMX_INVALID_PARA);

    dsc_idx = dmx_handle_2_id(handle);

    return _dmx_dsc_set_iv(dsc_idx, ivtype, iv, len);
}

hi_s32 dmx_dsc_get_key_handle(hi_handle pid_ch_handle, hi_handle *dsc_handle)
{
    DMX_CHECK_HANDLE(pid_ch_handle);
    dmx_null_pointer_return(dsc_handle);

    return _dmx_dsc_get_key_handle(pid_ch_handle, dsc_handle);
}

hi_s32 dmx_dsc_get_chan_handle(hi_u32 dmx_id, hi_u32 pid, hi_u32 *chan_num, hi_handle chan[])
{
    dmx_null_pointer_return(chan_num);
    dmx_null_pointer_return(chan);

    return _dmx_dsc_get_chan_handle(dmx_id, pid, chan_num, chan);
}

hi_s32 dmx_dsc_fct_destroy(hi_handle handle)
{
    hi_s32 ret;
    hi_u32 dsc_idx;
    tee_dmx_mgmt *tee_dmx_mgmt_ptr = get_dmx_mgmt();
    DMX_CHECK_HANDLE(handle);

    dsc_idx = dmx_handle_2_id(handle);

    ret = _dmx_dsc_fct_destroy(dsc_idx);
    if (ret != HI_SUCCESS) {
        return ret;
    }

    demux_mutex_lock(&tee_dmx_mgmt_ptr->lock_all_key);
    bitmap_clrbit(dsc_idx, tee_dmx_mgmt_ptr->key_bitmap);
    demux_mutex_unlock(&tee_dmx_mgmt_ptr->lock_all_key);

    return HI_SUCCESS;
}

hi_void _dmx_drv_register_init(hi_void)
{
    /* configure the hardware clock */
    tee_dmx_hal_init_hw();

    /* init some hardware configure of dmx */
    tee_dmx_hal_en_mmu(&g_tee_dmx_mgmt);

    /* enable the tee descrambler */
    tee_dmx_hal_mdscset_en(&g_tee_dmx_mgmt, HI_TRUE, HI_TRUE, HI_TRUE);
    tee_dmx_hal_mdscdis_ca_core(&g_tee_dmx_mgmt, HI_FALSE);

    /* ree can read the buf write register */
    tee_dmx_hal_buf_lock_tee_rd(&g_tee_dmx_mgmt, HI_FALSE);

    hi_tee_drv_ssm_iommu_config(LOGIC_MOD_ID_DEMUX);
}

hi_s32 dmx_drv_mod_init(hi_void)
{
    hi_u32 idx;

    hi_dbg_func_enter();
    if (g_tee_dmx_mgmt_ptr != HI_NULL) {
        hi_log_dbg("tee demux already init!\n");
        goto out;
    }

    /* init the dmx avr channel */
    demux_mutex_init(&g_tee_dmx_mgmt.lock_all_avr);
    for (idx = 0; idx < g_tee_dmx_mgmt.avr_cnt; idx++) {
        demux_mutex_init(&g_tee_dmx_mgmt.play_avpes[idx].lock_avpes);
        demux_mutex_init(&g_tee_dmx_mgmt.rec_info[idx].lock_rec);
    }
    bitmap_zero(g_tee_dmx_mgmt.avr_bitmap, g_tee_dmx_mgmt.avr_cnt);

    /* init the dmx play ts channel */
    demux_mutex_init(&g_tee_dmx_mgmt.lock_all_play_ts);
    for (idx = 0; idx < g_tee_dmx_mgmt.play_ts_cnt; idx++) {
        demux_mutex_init(&g_tee_dmx_mgmt.play_ts[idx].lock_ts);
    }
    bitmap_zero(g_tee_dmx_mgmt.play_ts_bitmap, g_tee_dmx_mgmt.play_ts_cnt);

    /* init the dmx play sec pes channel */
    demux_mutex_init(&g_tee_dmx_mgmt.lock_all_play_pes_sec);
    for (idx = 0; idx < g_tee_dmx_mgmt.play_pes_sec_cnt; idx++) {
        demux_mutex_init(&g_tee_dmx_mgmt.play_pes_sec[idx].lock_pes_sec);
    }
    bitmap_zero(g_tee_dmx_mgmt.play_pes_sec_bitmap, g_tee_dmx_mgmt.play_pes_sec_cnt);

    /* init the dmx descrambler channel */
    demux_mutex_init(&g_tee_dmx_mgmt.lock_all_key);
    for (idx = 0; idx < g_tee_dmx_mgmt.key_cnt; idx++) {
        demux_mutex_init(&g_tee_dmx_mgmt.key_info[idx].lock_key);
    }
    bitmap_zero(g_tee_dmx_mgmt.key_bitmap, g_tee_dmx_mgmt.key_cnt);

    /* init the dmx ramport channel */
    demux_mutex_init(&g_tee_dmx_mgmt.lock_all_ramport);
    for (idx = 0; idx < g_tee_dmx_mgmt.ramport_cnt; idx++) {
        demux_mutex_init(&g_tee_dmx_mgmt.ramport_info[idx].lock_ramport);
    }
    bitmap_zero(g_tee_dmx_mgmt.ramport_bitmap, g_tee_dmx_mgmt.ramport_cnt);

    /* init the dmx channel */
    demux_mutex_init(&g_tee_dmx_mgmt.lock_all_dmx);
    for (idx = 0; idx < g_tee_dmx_mgmt.dmx_cnt; idx++) {
        demux_mutex_init(&g_tee_dmx_mgmt.dmx_info[idx].lock_dmx);
    }
    bitmap_zero(g_tee_dmx_mgmt.dmx_bitmap, g_tee_dmx_mgmt.ramport_cnt);

    /* init the dmx buf */
    demux_mutex_init(&g_tee_dmx_mgmt.lock_all_buf);
    bitmap_zero(g_tee_dmx_mgmt.buf_bitmap, g_tee_dmx_mgmt.buf_cnt);

    /* init the total lock */
    demux_mutex_init(&g_tee_dmx_mgmt.total_lock);

    /* init the dmx ioctl entry */
    g_tee_dmx_mgmt.dmx_ioctl_entry = (dmx_ioctl_entry*)&g_dmx_func_entry_map;

    /* configure the tee dmx register */
    _dmx_drv_register_init();

    g_tee_dmx_mgmt_ptr = &g_tee_dmx_mgmt;

out:
    hi_dbg_func_exit();

    return HI_SUCCESS;
}

hi_s32 dmx_drv_mod_exit(hi_void)
{
    hi_u32 idx;

    hi_dbg_func_enter();

    /* deinit the dmx avr channel */
    demux_mutex_deinit(&g_tee_dmx_mgmt.lock_all_avr);
    for (idx = 0; idx < g_tee_dmx_mgmt.avr_cnt; idx++) {
        demux_mutex_deinit(&g_tee_dmx_mgmt.play_avpes[idx].lock_avpes);
        demux_mutex_deinit(&g_tee_dmx_mgmt.rec_info[idx].lock_rec);
    }
    bitmap_zero(g_tee_dmx_mgmt.avr_bitmap, g_tee_dmx_mgmt.avr_cnt);

    /* deinit the dmx play ts channel */
    demux_mutex_deinit(&g_tee_dmx_mgmt.lock_all_play_ts);
    for (idx = 0; idx < g_tee_dmx_mgmt.play_ts_cnt; idx++) {
        demux_mutex_deinit(&g_tee_dmx_mgmt.play_ts[idx].lock_ts);
    }
    bitmap_zero(g_tee_dmx_mgmt.play_ts_bitmap, g_tee_dmx_mgmt.play_ts_cnt);

    /* deinit the dmx play sec pes channel */
    demux_mutex_deinit(&g_tee_dmx_mgmt.lock_all_play_pes_sec);
    for (idx = 0; idx < g_tee_dmx_mgmt.play_pes_sec_cnt; idx++) {
        demux_mutex_deinit(&g_tee_dmx_mgmt.play_pes_sec[idx].lock_pes_sec);
    }
    bitmap_zero(g_tee_dmx_mgmt.play_pes_sec_bitmap, g_tee_dmx_mgmt.play_pes_sec_cnt);

    /* deinit the dmx descrambler channel */
    demux_mutex_deinit(&g_tee_dmx_mgmt.lock_all_key);
    for (idx = 0; idx < g_tee_dmx_mgmt.key_cnt; idx++) {
        demux_mutex_deinit(&g_tee_dmx_mgmt.key_info[idx].lock_key);
    }
    bitmap_zero(g_tee_dmx_mgmt.key_bitmap, g_tee_dmx_mgmt.key_cnt);

    /* deinit the dmx ramport channel */
    demux_mutex_deinit(&g_tee_dmx_mgmt.lock_all_ramport);
    for (idx = 0; idx < g_tee_dmx_mgmt.ramport_cnt; idx++) {
        demux_mutex_deinit(&g_tee_dmx_mgmt.ramport_info[idx].lock_ramport);
    }
    bitmap_zero(g_tee_dmx_mgmt.ramport_bitmap, g_tee_dmx_mgmt.ramport_cnt);

    /* deinit the dmx channel */
    demux_mutex_deinit(&g_tee_dmx_mgmt.lock_all_dmx);
    for (idx = 0; idx < g_tee_dmx_mgmt.dmx_cnt; idx++) {
        demux_mutex_deinit(&g_tee_dmx_mgmt.dmx_info[idx].lock_dmx);
    }
    bitmap_zero(g_tee_dmx_mgmt.dmx_bitmap, g_tee_dmx_mgmt.ramport_cnt);

    /* deinit the dmx buf */
    demux_mutex_deinit(&g_tee_dmx_mgmt.lock_all_buf);
    bitmap_zero(g_tee_dmx_mgmt.buf_bitmap, g_tee_dmx_mgmt.buf_cnt);

    /* deinit the total lock */
    demux_mutex_deinit(&g_tee_dmx_mgmt.total_lock);

    /* disable the tee descrambler */
    tee_dmx_hal_mdscset_en(&g_tee_dmx_mgmt, HI_FALSE, HI_FALSE, HI_FALSE);

    /* deinit some hardware configure of dmx */
    tee_dmx_hal_dis_mmu(&g_tee_dmx_mgmt);

    /* ree can't read the buf write register */
    tee_dmx_hal_buf_lock_tee_rd(&g_tee_dmx_mgmt, HI_TRUE);

    /* deconfigure the hardware clock */
    tee_dmx_hal_deinit_hw();

    g_tee_dmx_mgmt_ptr = HI_NULL;

    hi_dbg_func_exit();

    return HI_SUCCESS;
}

tee_dmx_mgmt *get_dmx_mgmt(hi_void)
{
    if (g_tee_dmx_mgmt_ptr == HI_NULL) {
        if (dmx_drv_mod_init() != HI_SUCCESS) {
            hi_log_err("dmx_drv_mod_init failed!\n");
        }
        g_tee_dmx_mgmt_ptr = &g_tee_dmx_mgmt;
    }

    return g_tee_dmx_mgmt_ptr;
}
