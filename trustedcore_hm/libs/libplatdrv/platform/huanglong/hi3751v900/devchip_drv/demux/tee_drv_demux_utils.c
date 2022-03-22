/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: tee drv demux utils impl.
 * Author: sdk
 * Create: 2019-09-05
 */

#include "hi_type_dev.h"
#include "hi_tee_drv_mem.h"
#include "tee_drv_demux_utils.h"
#include "tee_drv_demux_func.h"
#include "hi_tee_drv_demux.h"

void demux_mutex_init(struct hi_tee_hal_mutex *lock)
{
    hi_s32 ret;
    hi_char str[16] = {0}; /* the max mutex length is 16 bytes. */

    if (snprintf_s(str, sizeof(str), sizeof(str) - 1, "%p", lock) < 0) {
        hi_tee_drv_hal_printf("call snprintf_s failed.\n");
        return;
    }

    ret = hi_tee_drv_hal_mutex_init(str, lock);
    if (ret != HI_SUCCESS) {
        hi_tee_drv_hal_printf("Create mutex failed, ret[0x%x]\n", ret);
    }
}

void demux_mutex_deinit(struct hi_tee_hal_mutex *lock)
{
    hi_tee_drv_hal_mutex_destroy(lock);
}

void demux_mutex_lock(struct hi_tee_hal_mutex *lock)
{
    hi_tee_drv_hal_mutex_lock(lock);
}

void demux_mutex_unlock(struct hi_tee_hal_mutex *lock)
{
    hi_tee_drv_hal_mutex_unlock(lock);
}

/* memory interface */
hi_s32 dmx_alloc_and_map_secbuf(const hi_char *buf_name, hi_u32 buf_len, hi_u32 secbuf_size,
    hi_ulong *secbuf_smmu_addr_ptr, hi_u8 **secbuf_vir_addr_ptr)
{
    hi_s32 ret;
    hi_tee_smmu_buf secmmu_buf = {0};

    dmx_null_pointer_return(buf_name);
    dmx_null_pointer_return(secbuf_smmu_addr_ptr);
    dmx_null_pointer_return(secbuf_vir_addr_ptr);

    ret = hi_tee_drv_smmu_alloc(buf_name, secbuf_size, &secmmu_buf);
    if (ret != HI_SUCCESS) {
        hi_log_err("malloc dmx smmu failed ret[%#x], buf_name:%s, secbuf_size[%#x]\n",
            ret, buf_name, secbuf_size);
        goto out0;
    }

    dmx_err_condition_goto(secbuf_size != secmmu_buf.size, HI_TEE_ERR_MEM, out1);

    ret = hi_tee_drv_smmu_map_cpu(&secmmu_buf, 0);
    if (ret != HI_SUCCESS) {
        hi_log_err("mmap dmx smmu buf to cpu failed.\n");
        goto out1;
    }

    *secbuf_vir_addr_ptr   = secmmu_buf.virt;
    *secbuf_smmu_addr_ptr  = secmmu_buf.smmu_addr;
    HI_UNUSED(buf_len);

    return HI_SUCCESS;

out1:
    hi_tee_drv_smmu_free(&secmmu_buf);
out0:
    return ret;
}

hi_s32 dmx_unmap_and_free_secbuf(hi_u32 secbuf_size, hi_ulong secbuf_smmu_addr, hi_u8 *secbuf_vir_addr)
{
    hi_s32 ret;
    hi_tee_smmu_buf secmmu_buf = {0};

    secmmu_buf.virt = secbuf_vir_addr;
    secmmu_buf.smmu_addr = secbuf_smmu_addr;
    secmmu_buf.size = secbuf_size;

    ret = hi_tee_drv_smmu_unmap_cpu(&secmmu_buf);
    if (ret != HI_SUCCESS) {
        hi_log_err("unmmap secure buffer failed");
        goto out;
    }

    ret = hi_tee_drv_smmu_free(&secmmu_buf);
    if (ret != HI_SUCCESS) {
        hi_log_err("free secure buffer failed");
        goto out;
    }

out:
    return ret;
}

hi_s32 dmx_map_shadow_buffer(hi_ulong phy_addr, hi_u32 buf_len, hi_u8 **vir_addr)
{
    hi_s32 ret;
    hi_tee_mmz_buf non_sec_mmz_buf = {0};

    non_sec_mmz_buf.phys_addr = phy_addr;
    non_sec_mmz_buf.size = buf_len;
    ret = hi_tee_drv_nsmmz_map_cpu(&non_sec_mmz_buf, 0);
    if (ret != HI_SUCCESS) {
        hi_log_err("map shadow buffer failed!\n");
        return ret;
    }

    *vir_addr = (hi_u8*)non_sec_mmz_buf.virt;

    return HI_SUCCESS;
}

hi_s32 dmx_unmap_shadow_buffer(hi_ulong phy_addr, hi_u32 buf_len, hi_u8 *vir_addr)
{
    hi_s32 ret;
    hi_tee_mmz_buf non_sec_mmz_buf;

    non_sec_mmz_buf.phys_addr = phy_addr;
    non_sec_mmz_buf.virt = (hi_void*)vir_addr;
    non_sec_mmz_buf.size = buf_len;
    ret = hi_tee_drv_nsmmz_unmap_cpu(&non_sec_mmz_buf);
    if (ret != HI_SUCCESS) {
        hi_log_err("unmap shadow buffer failed!\n");
        return ret;
    }

    return HI_SUCCESS;
}

hi_s32 tee_drv_dmx_init(hi_void *argp)
{
    dmx_null_pointer_return(argp);

    return dmx_drv_mod_init();
}

hi_s32 tee_drv_dmx_deinit(hi_void *argp)
{
    dmx_null_pointer_return(argp);

    return dmx_drv_mod_exit();
}

hi_s32 tee_drv_dmx_create_ramport(hi_void *argp)
{
    dmx_null_pointer_return(argp);
    dmx_ramport_buf_info *ramport_buf_info = (dmx_ramport_buf_info *)argp;

    return dmx_create_ramport_impl(ramport_buf_info->ram_id, ramport_buf_info->buf_size,
                                   ramport_buf_info->flush_buf_size, ramport_buf_info->dsc_buf_size,
                                   &ramport_buf_info->tee_ramport_info);
}

hi_s32 tee_drv_dmx_destroy_ramport(hi_void *argp)
{
    dmx_null_pointer_return(argp);
    dmx_ramport_buf_info *ramport_buf_info = (dmx_ramport_buf_info *)argp;

    return dmx_destroy_ramport_impl(ramport_buf_info->ram_id, &ramport_buf_info->tee_ramport_info);
}

hi_s32 tee_drv_dmx_set_ramport_dsc(hi_void *argp)
{
    dmx_null_pointer_return(argp);
    dmx_ramport_dsc_info *ramport_dsc_info = (dmx_ramport_dsc_info *)argp;

    return dmx_set_ramport_dsc_impl(ramport_dsc_info->ram_id, &ramport_dsc_info->tee_ramport_dsc);
}

hi_s32 tee_drv_dmx_create_play_chan(hi_void *argp)
{
    dmx_null_pointer_return(argp);
    dmx_chan_info *chan_info = (dmx_chan_info *)argp;

    return dmx_create_play_chan_impl(chan_info->id, chan_info->chan_type, chan_info->buf_size,
                                     &chan_info->tee_mem_info);
}

hi_s32 tee_drv_dmx_destroy_play_chan(hi_void *argp)
{
    dmx_null_pointer_return(argp);
    dmx_chan_info *chan_info = (dmx_chan_info *)argp;

    return dmx_destroy_play_chan_impl(chan_info->id, chan_info->chan_type, &chan_info->tee_mem_info);
}

hi_s32 tee_drv_dmx_attach_play_chan(hi_void *argp)
{
    dmx_null_pointer_return(argp);
    dmx_play_attach_info *attach_info = (dmx_play_attach_info *)argp;

    return dmx_attach_play_chan_impl(attach_info->chan_id, attach_info->chan_type, attach_info->raw_pidch_id,
                                     attach_info->master_raw_pidch_id);
}

hi_s32 tee_drv_dmx_detach_play_chan(hi_void *argp)
{
    dmx_null_pointer_return(argp);
    dmx_play_detach_info *detach_info = (dmx_play_detach_info *)argp;

    return dmx_detach_play_chan_impl(detach_info->chan_id, detach_info->chan_type, detach_info->raw_pidch_id);
}

hi_s32 tee_drv_dmx_create_rec_chan(hi_void *argp)
{
    dmx_null_pointer_return(argp);
    dmx_chan_info *chan_info = (dmx_chan_info *)argp;

    return dmx_create_rec_chan_impl(chan_info->id, chan_info->buf_size, &chan_info->tee_mem_info);
}

hi_s32 tee_drv_dmx_destroy_rec_chan(hi_void *argp)
{
    dmx_null_pointer_return(argp);
    dmx_chan_info *chan_info = (dmx_chan_info *)argp;

    return dmx_destroy_rec_chan_impl(chan_info->id, &chan_info->tee_mem_info);
}

hi_s32 tee_drv_dmx_attach_rec_chan(hi_void *argp)
{
    dmx_null_pointer_return(argp);
    dmx_rec_attach_info *attach_info = (dmx_rec_attach_info *)argp;

    return dmx_attach_rec_chan_impl(attach_info);
}

hi_s32 tee_drv_dmx_detach_rec_chan(hi_void *argp)
{
    dmx_null_pointer_return(argp);
    dmx_rec_detach_info *detach_info = (dmx_rec_detach_info *)argp;

    return dmx_detach_rec_chan_impl(detach_info);
}

hi_s32 tee_drv_dmx_update_play_read_idx(hi_void *argp)
{
    dmx_null_pointer_return(argp);
    dmx_play_idx_info *play_idx_info = (dmx_play_idx_info *)argp;

    return dmx_update_play_read_idx_impl(play_idx_info->buf_id, play_idx_info->chan_type, play_idx_info->read_idx);
}

hi_s32 tee_drv_dmx_update_rec_read_idx(hi_void *argp)
{
    dmx_null_pointer_return(argp);
    dmx_rec_idx_info *rec_idx_info = (dmx_rec_idx_info *)argp;

    return dmx_update_rec_read_idx_impl(rec_idx_info->buf_id, rec_idx_info->read_idx);
}

hi_s32 tee_drv_dmx_acquire_buf_id(hi_void *argp)
{
    dmx_null_pointer_return(argp);
    hi_u32 *buf_id_ptr = (hi_u32 *)argp;

    return dmx_acquire_buf_id_impl(buf_id_ptr);
}

hi_s32 tee_drv_dmx_release_buf_id(hi_void *argp)
{
    dmx_null_pointer_return(argp);
    hi_u32 buf_id = *(hi_u32 *)argp;

    return dmx_release_buf_id_impl(buf_id);
}

hi_s32 tee_drv_dmx_detach_raw_pidch(hi_void *argp)
{
    dmx_null_pointer_return(argp);
    hi_u32 raw_pidch = *(hi_u32 *)argp;

    return dmx_detach_raw_pidch_impl(raw_pidch);
}

hi_s32 tee_drv_dmx_config_sebuf(hi_void *argp)
{
    dmx_null_pointer_return(argp);

    dmx_config_secbuf_info *secbuf_info = (dmx_config_secbuf_info *)argp;

    return dmx_config_secbuf_impl(secbuf_info->chan_id, secbuf_info->chan_type);
}

hi_s32 tee_drv_dmx_deconfig_secbuf(hi_void *argp)
{
    dmx_null_pointer_return(argp);

    dmx_config_secbuf_info *secbuf_info = (dmx_config_secbuf_info *)argp;

    return dmx_deconfig_secbuf_impl(secbuf_info->chan_id, secbuf_info->chan_type);
}

hi_s32 tee_drv_dmx_enable_rec_chan(hi_void *argp)
{
    dmx_null_pointer_return(argp);

    hi_u32 *id = (hi_u32 *)argp;

    return dmx_enable_rec_chan(*id);
}

hi_s32 tee_drv_dmx_fixup_hevc_index(hi_void *argp)
{
    hi_s32 ret;
    dmx_null_pointer_return(argp);

    dmx_scd_buf *scd_buf = (dmx_scd_buf *)argp;

    ret = dmx_utils_fixup_hevc_index(scd_buf);

    return ret;
}

hi_s32 tee_drv_dmx_dsc_create(hi_void *argp)
{
    dmx_null_pointer_return(argp);

    dmx_create_dsc_fct_info *desc_attr = (dmx_create_dsc_fct_info *)argp;

    return hi_tee_drv_dmx_dsc_create(&desc_attr->attrs, &desc_attr->handle);
}

hi_s32 tee_drv_dmx_dsc_destroy(hi_void *argp)
{
    dmx_null_pointer_return(argp);
    hi_handle handle = *(hi_handle *)argp;

    return hi_tee_drv_dmx_dsc_destroy(handle);
}

hi_s32 tee_drv_dmx_dsc_get_attr(hi_void *argp)
{
    dmx_null_pointer_return(argp);

    dmx_get_dsc_fct_attr_info *info = (dmx_get_dsc_fct_attr_info *)argp;

    return hi_tee_drv_dmx_dsc_get_attrs(info->handle, &info->attrs);
}

hi_s32 tee_drv_dmx_dsc_set_attr(hi_void *argp)
{
    dmx_null_pointer_return(argp);

    dmx_get_dsc_fct_attr_info *info = (dmx_get_dsc_fct_attr_info *)argp;

    return hi_tee_drv_dmx_dsc_set_attrs(info->handle, &info->attrs);
}

hi_s32 tee_drv_dmx_dsc_set_sys_key(hi_void *argp)
{
    dmx_null_pointer_return(argp);

    dmx_dsc_fct_sys_key_info *info = (dmx_dsc_fct_sys_key_info *)argp;

    return hi_tee_drv_dmx_dsc_set_sys_key(info->handle, info->key, info->len);
}

hi_s32 tee_drv_dmx_dsc_set_even_iv_key(hi_void *argp)
{
    dmx_null_pointer_return(argp);

    dmx_dsc_fct_iv_key_info *info = (dmx_dsc_fct_iv_key_info *)argp;

    return hi_tee_drv_dmx_dsc_set_even_iv(info->handle, info->key, info->len);
}

hi_s32 tee_drv_dmx_dsc_set_odd_iv_key(hi_void *argp)
{
    dmx_null_pointer_return(argp);

    dmx_dsc_fct_iv_key_info *info = (dmx_dsc_fct_iv_key_info *)argp;

    return hi_tee_drv_dmx_dsc_set_odd_iv(info->handle, info->key, info->len);
}

hi_s32 tee_drv_dmx_dsc_attach_keyslot(hi_void *argp)
{
    dmx_null_pointer_return(argp);

    dmx_dsc_fct_attach_info *info = (dmx_dsc_fct_attach_info *)argp;

    return hi_tee_drv_dmx_dsc_attach_keyslot(info->handle, info->target_handle);
}

hi_s32 tee_drv_dmx_dsc_detach_keyslot(hi_void *argp)
{
    dmx_null_pointer_return(argp);

    dmx_dsc_fct_detach_info *info = (dmx_dsc_fct_detach_info *)argp;

    return hi_tee_drv_dmx_dsc_detach_keyslot(info->handle);
}

hi_s32 tee_drv_dmx_dsc_get_keyslot_handle(hi_void *argp)
{
    dmx_null_pointer_return(argp);

    dmx_dsc_fct_get_ks_handle_info *info = (dmx_dsc_fct_get_ks_handle_info *)argp;

    return hi_tee_drv_dmx_dsc_get_keyslot_handle(info->handle, &info->ks_handle);
}

hi_s32 tee_drv_dmx_dsc_attach_pid_chan(hi_void *argp)
{
    dmx_null_pointer_return(argp);

    dmx_dsc_fct_attach_info *info = (dmx_dsc_fct_attach_info *)argp;

    return hi_tee_drv_dmx_dsc_attach_pid_chan(info->handle, info->target_handle);
}

hi_s32 tee_drv_dmx_dsc_detach_pid_chan(hi_void *argp)
{
    dmx_null_pointer_return(argp);

    dmx_dsc_fct_detach_info *info = (dmx_dsc_fct_detach_info *)argp;

    return hi_tee_drv_dmx_dsc_detach_pid_chan(info->handle, info->target_handle);
}

hi_s32 tee_drv_dmx_dsc_get_handle(hi_void *argp)
{
    dmx_null_pointer_return(argp);

    dmx_dsc_fct_get_key_handle_info *info = (dmx_dsc_fct_get_key_handle_info *)argp;

    return hi_tee_drv_dmx_dsc_get_key_handle(info->pid_ch_handle, &info->dsc_handle);
}

hi_s32 tee_drv_dmx_dsc_get_chan_handle(hi_void *argp)
{
    dmx_null_pointer_return(argp);

    dmx_dsc_fct_get_chan_handle_info *info = (dmx_dsc_fct_get_chan_handle_info *)argp;

    return hi_tee_drv_dmx_dsc_get_chan_handle(info->dmx_id, info->pid, &info->chan_num, info->chan);
}

hi_s32 tee_drv_dmx_sec_pes_flush_shadow_buf(hi_void *argp)
{
    dmx_null_pointer_return(argp);

    dmx_sec_pes_flush_info *flush_info = (dmx_sec_pes_flush_info *)argp;
    return dmx_sec_pes_flush_shadow_buf(flush_info);
}

hi_s32 tee_drv_dmx_flt_sec_pes_lock(hi_void *argp)
{
    dmx_null_pointer_return(argp);

    return dmx_flt_sec_pes_lock((dmx_tee_flt_info*)argp);
}

hi_s32 tee_drv_dmx_config_cc_drop_info(hi_void *argp)
{
    dmx_null_pointer_return(argp);

    return dmx_config_cc_drop_info((dmx_tee_cc_drop_info*)argp);
}

