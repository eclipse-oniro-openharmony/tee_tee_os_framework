/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: tee demux utils impl
 * Author: SDK
 * Create: 2019-10-11
 */

#include "hi_tee_hal.h"

#include "tee_demux_utils.h"
#include "tee_drv_demux_ioctl.h"

hi_s32 __tee_demux_ioctl(unsigned long cmd, const hi_void *pri_args)
{
    unsigned int args[] = {
        (unsigned long)cmd,
        (unsigned long)(uintptr_t)pri_args,
    };

    return hm_drv_call(HI_TEE_SYSCALL_DMX, args, ARRAY_SIZE(args));
}

hi_s32 tee_dmx_init(hi_void)
{
    unsigned long args[] = { 0, };
    return __tee_demux_ioctl(DMX_TEE_IOCTL_GLB_INIT, args);
}

hi_s32 tee_dmx_deinit(hi_void)
{
    unsigned long args[] = { 0, };
    return __tee_demux_ioctl(DMX_TEE_IOCTL_GLB_DEINIT, args);
}

hi_s32 tee_dmx_create_ramport(hi_u32 ram_id, hi_u32 buf_size, hi_u32 flush_buf_size, hi_u32 dsc_buf_size,
    dmx_tee_ramport_info *tee_ramport_info)
{
    hi_s32 ret;
    dmx_ramport_buf_info ramport_info = {0};

    dmx_null_pointer_return(tee_ramport_info);

    ramport_info.ram_id = ram_id;
    ramport_info.buf_size = buf_size;
    ramport_info.flush_buf_size  = flush_buf_size;
    ramport_info.dsc_buf_size = dsc_buf_size;

    ret = __tee_demux_ioctl(DMX_TEE_IOCTL_GLB_CREATE_RAMPORT, (void *)&ramport_info);
    if (ret == HI_SUCCESS) {
        *tee_ramport_info = ramport_info.tee_ramport_info;
    }

    return ret;
}

hi_s32 tee_dmx_destroy_ramport(hi_u32 ram_id, const dmx_tee_ramport_info *tee_ramport_info)
{
    dmx_ramport_buf_info ramport_info = {0};

    dmx_null_pointer_return(tee_ramport_info);

    ramport_info.ram_id = ram_id;
    ramport_info.tee_ramport_info = *tee_ramport_info;

    return __tee_demux_ioctl(DMX_TEE_IOCTL_GLB_DESTROY_RAMPORT, (void *)&ramport_info);
}

hi_s32 tee_dmx_set_ramport_dsc(hi_u32 ram_id, const dmx_tee_ramport_dsc *tee_ramport_dsc)
{
    dmx_ramport_dsc_info ramport_dsc_info = {0};

    dmx_null_pointer_return(tee_ramport_dsc);

    ramport_dsc_info.ram_id = ram_id;
    ramport_dsc_info.tee_ramport_dsc = *tee_ramport_dsc;

    return __tee_demux_ioctl(DMX_TEE_IOCTL_GLB_SET_RAMPORT_DSC, (void *)&ramport_dsc_info);
}

hi_s32 tee_dmx_create_play_chan(hi_u32 id, dmx_chan_type chan_type, hi_u32 buf_size, dmx_tee_mem_swap_info *mem_info)
{
    hi_s32 ret;
    dmx_chan_info chan_info = {0};

    dmx_null_pointer_return(mem_info);

    chan_info.id = id;
    chan_info.chan_type = chan_type;
    chan_info.buf_size = buf_size;
    chan_info.tee_mem_info.shadow_buf_start_addr = mem_info->shadow_buf_start_addr;
    chan_info.tee_mem_info.shadow_buf_size = mem_info->shadow_buf_size;

    ret = __tee_demux_ioctl(DMX_TEE_IOCTL_GLB_CREATE_PLAY_CHAN, (void *)&chan_info);
    if (ret == HI_SUCCESS) {
        *mem_info = chan_info.tee_mem_info;
    }

    return ret;
}

hi_s32 tee_dmx_destroy_play_chan(hi_u32 id, dmx_chan_type chan_type, const dmx_tee_mem_swap_info *mem_info)
{
    dmx_chan_info chan_info = {0};

    dmx_null_pointer_return(mem_info);

    chan_info.id = id;
    chan_info.chan_type = chan_type;
    chan_info.tee_mem_info = *mem_info;

    return __tee_demux_ioctl(DMX_TEE_IOCTL_GLB_DESTROY_PLAY_CHAN, (void *)&chan_info);
}

hi_s32 tee_dmx_attach_play_chan(hi_u32 chan_id, dmx_chan_type chan_type, hi_u32 raw_pidch_id,
    hi_u32 master_raw_pidch_id)
{
    dmx_play_attach_info attach_info = {0};

    attach_info.chan_id = chan_id;
    attach_info.chan_type = chan_type;
    attach_info.raw_pidch_id = raw_pidch_id;
    attach_info.master_raw_pidch_id = master_raw_pidch_id;

    return __tee_demux_ioctl(DMX_TEE_IOCTL_GLB_ATTACH_PLAY_CHAN, (void *)&attach_info);
}

hi_s32 tee_dmx_detach_play_chan(hi_u32 chan_id, dmx_chan_type chan_type, hi_u32 raw_pidch_id)
{
    dmx_play_detach_info detach_info = {0};

    detach_info.chan_id = chan_id;
    detach_info.chan_type = chan_type;
    detach_info.raw_pidch_id = raw_pidch_id;

    return __tee_demux_ioctl(DMX_TEE_IOCTL_GLB_DETACH_PLAY_CHAN, (void *)&detach_info);
}

hi_s32 tee_dmx_create_rec_chan(hi_u32 id, hi_u32 buf_size, dmx_tee_mem_swap_info *mem_info)
{
    hi_s32 ret;
    dmx_chan_info chan_info = {0};

    dmx_null_pointer_return(mem_info);

    chan_info.id = id;
    chan_info.chan_type = DMX_CHAN_TYPE_REC;
    chan_info.buf_size = buf_size;

    ret = __tee_demux_ioctl(DMX_TEE_IOCTL_GLB_CREATE_REC_CHAN, (void *)&chan_info);
    if (ret == HI_SUCCESS) {
        *mem_info = chan_info.tee_mem_info;
    }

    return ret;
}

hi_s32 tee_dmx_destroy_rec_chan(hi_u32 id, const dmx_tee_mem_swap_info *mem_info)
{
    dmx_chan_info chan_info = {0};

    dmx_null_pointer_return(mem_info);

    chan_info.id = id;
    chan_info.chan_type = DMX_CHAN_TYPE_REC;
    chan_info.tee_mem_info = *mem_info;

    return __tee_demux_ioctl(DMX_TEE_IOCTL_GLB_DESTROY_REC_CHAN, (void *)&chan_info);
}

hi_s32 tee_dmx_attach_rec_chan(const dmx_rec_attach_info *rec_attach_ptr)
{
    dmx_rec_attach_info attach_info = {0};
    dmx_null_pointer_return(rec_attach_ptr);

    attach_info = *rec_attach_ptr;

    return __tee_demux_ioctl(DMX_TEE_IOCTL_GLB_ATTACH_REC_CHAN, (void *)&attach_info);
}

hi_s32 tee_dmx_detach_rec_chan(const dmx_rec_detach_info *rec_detach_ptr)
{
    dmx_rec_detach_info detach_info = {0};
    dmx_null_pointer_return(rec_detach_ptr);

    detach_info = *rec_detach_ptr;

    return __tee_demux_ioctl(DMX_TEE_IOCTL_GLB_DETACH_REC_CHAN, (void *)&detach_info);
}

hi_s32 tee_dmx_update_play_read_idx(hi_u32 buf_id, dmx_chan_type chan_type, hi_u32 read_idx)
{
    dmx_play_idx_info play_idx_info = {0};

    play_idx_info.buf_id = buf_id;
    play_idx_info.chan_type = chan_type;
    play_idx_info.read_idx = read_idx;

    return __tee_demux_ioctl(DMX_TEE_IOCTL_GLB_UPDATE_PLAY_READ_IDX, (void *)&play_idx_info);
}

hi_s32 tee_dmx_update_rec_read_idx(hi_u32 buf_id, hi_u32 read_idx)
{
    dmx_rec_idx_info rec_idx_info = {0};

    rec_idx_info.buf_id = buf_id;
    rec_idx_info.chan_type = DMX_CHAN_TYPE_REC;
    rec_idx_info.read_idx = read_idx;

    return __tee_demux_ioctl(DMX_TEE_IOCTL_GLB_UPDATE_REC_READ_IDX, (void *)&rec_idx_info);
}

hi_s32 tee_dmx_acquire_buf_id(hi_u32 *buf_id_ptr)
{
    hi_s32 ret;
    hi_u32 buf_id;

    dmx_null_pointer_return(buf_id_ptr);

    ret = __tee_demux_ioctl(DMX_TEE_IOCTL_GLB_ACQUIRE_SECBUF_ID, (void *)&buf_id);
    if (ret == HI_SUCCESS) {
        *buf_id_ptr = buf_id;
    }

    return ret;
}

hi_s32 tee_dmx_release_buf_id(hi_u32 buf_id)
{
    return __tee_demux_ioctl(DMX_TEE_IOCTL_GLB_RELEASE_SECBUF_ID, (void *)&buf_id);
}

hi_s32 tee_dmx_detach_raw_pidch(hi_u32 raw_pidch)
{
    return __tee_demux_ioctl(DMX_TEE_IOCTL_GLB_DETACH_RAW_PIDCH, (void *)&raw_pidch);
}

hi_s32 tee_dmx_config_secbuf(hi_u32 chan_id, dmx_chan_type chan_type)
{
    dmx_config_secbuf_info config_secbuf = {0};

    config_secbuf.chan_id = chan_id;
    config_secbuf.chan_type = chan_type;

    return __tee_demux_ioctl(DMX_TEE_IOCTL_GLB_CONFIG_SECBUF, (void *)&config_secbuf);
}

hi_s32 tee_dmx_deconfig_secbuf(hi_u32 chan_id, dmx_chan_type chan_type)
{
    dmx_config_secbuf_info config_secbuf = {0};

    config_secbuf.chan_id = chan_id;
    config_secbuf.chan_type = chan_type;

    return __tee_demux_ioctl(DMX_TEE_IOCTL_GLB_DECONFIG_SECBUF, (void *)&config_secbuf);
}

hi_s32 tee_dmx_enable_rec_chn(hi_u32 id)
{
    return __tee_demux_ioctl(DMX_TEE_IOCTL_GLB_ENABLE_REC_CHAN, (void *)&id);
}

hi_s32 tee_dmx_fixup_hevc_index(dmx_tee_scd_buf *scd_buf_info)
{
    hi_s32 ret;
    dmx_scd_buf scd_buf = {0};

    dmx_null_pointer_return(scd_buf_info);
    scd_buf = *((dmx_scd_buf*)scd_buf_info);

    ret = __tee_demux_ioctl(DMX_TEE_IOCTL_GLB_FIXUP_HEVC_INDEX, (void *)&scd_buf);
    if (ret == HI_SUCCESS) {
        if (memcpy_s(&(scd_buf_info->dmx_rec_index), sizeof(scd_buf_info->dmx_rec_index),
            &(scd_buf.dmx_rec_index), sizeof(scd_buf.dmx_rec_index))) {
            return HI_FAILURE;
        }
    }

    return ret;
}

hi_s32 tee_dmx_sec_pes_flush_shadow_buf(hi_u32 chan_id, dmx_chan_type chan_type, hi_u32 offset, hi_bool *rool_flag,
    hi_u32 *data_len)
{
    hi_s32 ret;
    dmx_sec_pes_flush_info flush_info = {0};

    dmx_null_pointer_return(rool_flag);
    dmx_null_pointer_return(data_len);

    flush_info.rool_flag = *rool_flag;
    flush_info.chan_id = chan_id;
    flush_info.chan_type = chan_type;
    flush_info.offset = offset;

    ret = __tee_demux_ioctl(DMX_TEE_IOCTL_GLB_FLUSH_PES_SEC_DATA, (void *)&flush_info);
    if (ret == HI_SUCCESS) {
        *data_len = flush_info.data_len;
        *rool_flag = flush_info.rool_flag;
    }

    return ret;
}

hi_s32 tee_dmx_flt_sec_pes_lock(const dmx_tee_flt_info *flt_info)
{
    hi_s32 ret;
    dmx_tee_flt_info info;

    dmx_null_pointer_return(flt_info);

    info = *flt_info;
    ret = __tee_demux_ioctl(DMX_TEE_IOCTL_GLB_FLT_PES_SEC_LOCK, (void *)&info);
    return ret;
}

hi_s32 tee_dmx_config_cc_drop(const dmx_tee_cc_drop_info *cc_drop_info)
{
    hi_s32 ret;
    dmx_tee_cc_drop_info info;

    dmx_null_pointer_return(cc_drop_info);

    info = *cc_drop_info;
    ret = __tee_demux_ioctl(DMX_TEE_IOCTL_GLB_CONFIG_CC_DROP_INFO, (void *)&info);
    return ret;
}

