/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: demux TA
 * Author: sdk
 * Create: 2019-07-13
 */

#include "hi_tee_hal.h"
#include "tee_demux_utils.h"

/*
 * sync with source/msp/drv/demux/drv_demux_tee.h
 */
#define TEEC_CMD_INIT                      0
#define TEEC_CMD_DEINIT                    1
#define TEEC_CMD_CREATE_RAMPORT            2
#define TEEC_CMD_DESTROY_RAMPORT           3
#define TEEC_CMD_SET_RAMPORT_DSC           4
#define TEEC_CMD_CREATE_PLAY_CHAN          5
#define TEEC_CMD_DESTROY_PLAY_CHAN         6
#define TEEC_CMD_ATTACH_PLAY_CHAN          7
#define TEEC_CMD_DETACH_PLAY_CHAN          8
#define TEEC_CMD_CREATE_REC_CHAN           9
#define TEEC_CMD_DESTROY_REC_CHAN          10
#define TEEC_CMD_ATTACH_REC_CHAN           11
#define TEEC_CMD_DETACH_REC_CHAN           12
#define TEEC_CMD_UPDATE_PLAY_READ_IDX      13
#define TEEC_CMD_UPDATE_REC_READ_IDX       14
#define TEEC_CMD_ACQUIRE_SECBUF_ID         15
#define TEEC_CMD_RELEASE_SECBUF_ID         16
#define TEEC_CMD_DETACH_RAW_PIDCH          17
#define TEEC_CMD_FIXUP_HEVC_INDEX          18
#define TEEC_CMD_CONFIG_SECBUF             19
#define TEEC_CMD_DECONFIG_SECBUF           20
#define TEEC_CMD_ENABLE_REC_CHAN           21
#define TEEC_CMD_FLUSH_SHADOW_BUF          22
#define TEEC_CMD_FLT_PES_SEC_LOCK          23
#define TEEC_CMD_CONFIG_CC_DROP            24

/* the user id from source/tee/core/libteec/src/tee_ca_daemon.c */
#define MEDIASERVER_USERID               0x3F5
#define DMX_REE_TEE_MAGIC                0x5AA5
#define DMX_REE_TEE_VERSION              "dmx_ver_01.01.01.00"
#define PARAM_LEN   4

/* structure definition */
typedef struct {
    hi_u32 cmd;
    hi_s32(*fun_entry)(uint32_t type, TEE_Param params[PARAM_LEN]);
} dmx_task_entry;

/* define the parameter check macro */
#define check_param_types(para_types, type0, type1, type2, type3) do { \
    if ((para_types) != TEE_PARAM_TYPES((type0), (type1), (type2), (type3))) {   \
        ta_debug("[%d]line bad parameter types!\n", __LINE__); \
        return TEE_ERROR_BAD_PARAMETERS;   \
    } \
} while (0)

__DEFAULT TEE_Result TA_CreateEntryPoint(void)
{
    TEE_Result ret;
    hi_char general_session_name[] = "tee_dmx_general_session";
    /* root id for all client */
    ret = AddCaller_CA_exec(general_session_name, 0);
    if (ret != TEE_SUCCESS) {
        tloge("AddCaller_CA_exec %s for root failed!\n", general_session_name);
        goto out;
    }

    /* for /system/bin/mediaserver user id */
    ret = AddCaller_CA_exec(general_session_name, MEDIASERVER_USERID);
    if (ret != TEE_SUCCESS) {
        tloge("AddCaller_CA_exec %s for media_server failed!\n", general_session_name);
        goto out;
    }

    ret = TEE_SUCCESS;
out:
    return ret;
}

__DEFAULT TEE_Result TA_OpenSessionEntryPoint(uint32_t type, TEE_Param params[PARAM_LEN], hi_void** sessionContext)
{
    dmx_ree_tee_version *dmx_ree_tee_buf = (dmx_ree_tee_version *)params[1].memref.buffer;
    hi_u32 dmx_ree_tee_ver_size = params[1].memref.size;

    check_param_types(type, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_MEMREF_INOUT,\
                                  TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT);

    dmx_null_pointer_return(dmx_ree_tee_buf);

    if (dmx_ree_tee_ver_size != sizeof(dmx_ree_tee_version) || dmx_ree_tee_buf->magic != DMX_REE_TEE_MAGIC) {
        tloge("Invalid head size[0x%x] or magic num[0x%x]!\n", dmx_ree_tee_ver_size, dmx_ree_tee_buf->magic);
        return HI_FAILURE;
    }

    if (memcpy_s(dmx_ree_tee_buf->version, sizeof(dmx_ree_tee_buf->version), DMX_REE_TEE_VERSION,
        sizeof(DMX_REE_TEE_VERSION))) {
        tloge("memcpy tee version failed!\n");
        return HI_FAILURE;
    }

    dmx_unused(sessionContext);
    return TEE_SUCCESS;
}

static hi_s32 dmx_creat_ramport(uint32_t type, TEE_Param params[PARAM_LEN])
{
    hi_s32 ret;
    dmx_tee_ramport_info tee_ramport_info = {0};
    hi_u32 ram_id = params[0].value.a;
    hi_u32 buf_size = params[0].value.b;
    hi_u32 flush_buf_size = params[1].value.a;
    hi_u32 dsc_buf_size = params[1].value.b;
    dmx_tee_ramport_info *tee_ramport_ptr = params[2].memref.buffer; /* 2: the second element in the array */
    hi_u32 tee_ramport_size = params[2].memref.size;    /* 2: the second element in the array */

    check_param_types(type, TEE_PARAM_TYPE_VALUE_INPUT,\
        TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE);

    if (tee_ramport_size != sizeof(dmx_tee_ramport_info)) {
        tloge("Invalid buffer size, tee_ramport_size[0x%x]!\n", tee_ramport_size);
        return HI_ERR_DMX_INVALID_PARA;
    }

    ret = tee_dmx_create_ramport(ram_id, buf_size, flush_buf_size, dsc_buf_size, &tee_ramport_info);
    if (ret == HI_SUCCESS) {
        if (memcpy_s(tee_ramport_ptr, tee_ramport_size, &tee_ramport_info, sizeof(dmx_tee_ramport_info))) {
            tloge("memcpy_s failed.\n");
            ret = HI_TEE_ERR_MEM;
        }
    }

    return ret;
}

static hi_s32 dmx_destroy_ramport(uint32_t type, TEE_Param params[PARAM_LEN])
{
    hi_s32 ret;
    dmx_tee_ramport_info tee_ramport_info = {0};
    hi_u32 ram_id = params[0].value.a;
    dmx_tee_ramport_info *tee_ramport_ptr = params[1].memref.buffer;
    hi_u32 tee_ramport_size = params[1].memref.size;

    check_param_types(type, TEE_PARAM_TYPE_VALUE_INPUT,\
        TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

    if (tee_ramport_size != sizeof(dmx_tee_ramport_info)) {
        tloge("Invalid buffer size, tee_ramport_size[0x%x]!\n", tee_ramport_size);
        return HI_ERR_DMX_INVALID_PARA;
    }

    if (memcpy_s(&tee_ramport_info, tee_ramport_size, tee_ramport_ptr, sizeof(dmx_tee_ramport_info))) {
        tloge("memcpy_s failed.\n");
        return HI_TEE_ERR_MEM;
    }

    ret = tee_dmx_destroy_ramport(ram_id, &tee_ramport_info);
    return ret;
}

static hi_s32 dmx_set_ramport_dec(uint32_t type, TEE_Param params[PARAM_LEN])
{
    hi_s32 ret;
    dmx_tee_ramport_dsc tee_ramport_dsc = {0};
    hi_u32 ram_id = params[0].value.a;
    dmx_tee_ramport_dsc *tee_ramport_dsc_ptr = params[1].memref.buffer;
    hi_u32 tee_ramport_dsc_size = params[1].memref.size;

    check_param_types(type, TEE_PARAM_TYPE_VALUE_INPUT,\
        TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

    if (tee_ramport_dsc_size != sizeof(dmx_tee_ramport_dsc)) {
        tloge("Invalid buffer size, tee_ramport_dsc_size[0x%x]!\n", tee_ramport_dsc_size);
        return HI_ERR_DMX_INVALID_PARA;
    }

    if (memcpy_s(&tee_ramport_dsc, tee_ramport_dsc_size, tee_ramport_dsc_ptr, sizeof(dmx_tee_ramport_dsc))) {
        tloge("memcpy_s failed.\n");
        return HI_TEE_ERR_MEM;
    }

    ret = tee_dmx_set_ramport_dsc(ram_id, &tee_ramport_dsc);
    return ret;
}

static hi_s32 dmx_create_play_chn(uint32_t type, TEE_Param params[PARAM_LEN])
{
    hi_s32 ret;
    dmx_tee_mem_swap_info tee_mem_info = {0};
    hi_u32 id = params[0].value.a;
    dmx_chan_type chan_type = (dmx_chan_type)params[0].value.b;
    hi_u32 buf_size = params[1].value.a;
    dmx_tee_mem_swap_info *tee_mem_info_ptr = params[2].memref.buffer;   /* 2: the second element in the array */
    hi_u32 tee_mem_info_size = params[2].memref.size;   /* 2: the second element in the array */

    check_param_types(type, TEE_PARAM_TYPE_VALUE_INPUT,\
        TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_MEMREF_INOUT, TEE_PARAM_TYPE_NONE);

    if (tee_mem_info_size != sizeof(dmx_tee_mem_swap_info)) {
        tloge("Invalid buffer size, tee_mem_info_size[0x%x]!\n", tee_mem_info_size);
        return HI_ERR_DMX_INVALID_PARA;
    }

    tee_mem_info.shadow_buf_start_addr = tee_mem_info_ptr->shadow_buf_start_addr;
    tee_mem_info.shadow_buf_size = tee_mem_info_ptr->shadow_buf_size;

    ret = tee_dmx_create_play_chan(id, chan_type, buf_size, &tee_mem_info);
    if (ret == HI_SUCCESS) {
        if (memcpy_s(tee_mem_info_ptr, tee_mem_info_size, &tee_mem_info, sizeof(dmx_tee_mem_swap_info)) != EOK) {
            tloge("memcpy_s failed.\n");
            ret = HI_TEE_ERR_MEM;
        }
    }
    return ret;
}

static hi_s32 dmx_destroy_play_chn(uint32_t type, TEE_Param params[PARAM_LEN])
{
    hi_s32 ret;
    dmx_tee_mem_swap_info tee_mem_info = {0};
    hi_u32 id = params[0].value.a;
    dmx_chan_type chan_type = (dmx_chan_type)params[0].value.b;
    dmx_tee_mem_swap_info *tee_mem_info_ptr = params[1].memref.buffer;
    hi_u32 tee_mem_info_size = params[1].memref.size;

    check_param_types(type, TEE_PARAM_TYPE_VALUE_INPUT,\
        TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

    if (tee_mem_info_size != sizeof(dmx_tee_mem_swap_info)) {
        tloge("Invalid buffer size, tee_mem_info_size[0x%x]!\n", tee_mem_info_size);
        return HI_ERR_DMX_INVALID_PARA;
    }

    if (memcpy_s(&tee_mem_info, tee_mem_info_size, tee_mem_info_ptr, sizeof(dmx_tee_mem_swap_info))) {
        tloge("memcpy_s failed.\n");
        return HI_TEE_ERR_MEM;
    }

    ret = tee_dmx_destroy_play_chan(id, chan_type, &tee_mem_info);
    return ret;
}

static hi_s32 dmx_attach_play_chn(uint32_t type, TEE_Param params[PARAM_LEN])
{
    hi_s32 ret;
    hi_u32 chan_id = params[0].value.a;
    dmx_chan_type chan_type = params[0].value.b;
    hi_u32 raw_pidch_id = params[1].value.a;
    hi_u32 master_raw_pidch_id = params[1].value.b;

    check_param_types(type, TEE_PARAM_TYPE_VALUE_INPUT,\
        TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

    ret = tee_dmx_attach_play_chan(chan_id, chan_type, raw_pidch_id, master_raw_pidch_id);
    return ret;
}

static hi_s32 dmx_detach_play_chn(uint32_t type, TEE_Param params[PARAM_LEN])
{
    hi_s32 ret;
    hi_u32 chan_id = params[0].value.a;
    dmx_chan_type chan_type = params[0].value.b;
    hi_u32 raw_pidch_id = params[1].value.a;

    check_param_types(type, TEE_PARAM_TYPE_VALUE_INPUT,\
        TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

    ret = tee_dmx_detach_play_chan(chan_id, chan_type, raw_pidch_id);
    return ret;
}

static hi_s32 dmx_create_rec_chn(uint32_t type, TEE_Param params[PARAM_LEN])
{
    hi_s32 ret;
    dmx_tee_mem_swap_info tee_mem_info = {0};
    hi_u32 id = params[0].value.a;
    hi_u32 buf_size = params[0].value.b;
    dmx_tee_mem_swap_info *tee_mem_info_ptr = params[1].memref.buffer;
    hi_u32 tee_mem_info_size = params[1].memref.size;

    dmx_null_pointer_return(tee_mem_info_ptr);

    check_param_types(type, TEE_PARAM_TYPE_VALUE_INPUT,\
        TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

    if (tee_mem_info_size != sizeof(dmx_tee_mem_swap_info)) {
        tloge("Invalid buffer size, tee_mem_info_size[0x%x]!\n", tee_mem_info_size);
        return HI_ERR_DMX_INVALID_PARA;
    }

    ret = tee_dmx_create_rec_chan(id, buf_size, &tee_mem_info);
    if (ret == HI_SUCCESS) {
        if (memcpy_s(tee_mem_info_ptr, tee_mem_info_size, &tee_mem_info, sizeof(dmx_tee_mem_swap_info))) {
            tloge("memcpy_s failed.\n");
            ret = HI_TEE_ERR_MEM;
        }
    }

    return ret;
}

static hi_s32 dmx_detroy_rec_chn(uint32_t type, TEE_Param params[PARAM_LEN])
{
    hi_s32 ret;
    dmx_tee_mem_swap_info tee_mem_info = {0};
    hi_u32 id = params[0].value.a;
    dmx_tee_mem_swap_info *tee_mem_info_ptr = params[1].memref.buffer;
    hi_u32 tee_mem_info_size = params[1].memref.size;

    dmx_null_pointer_return(tee_mem_info_ptr);

    check_param_types(type, TEE_PARAM_TYPE_VALUE_INPUT,\
        TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

    if (tee_mem_info_size != sizeof(dmx_tee_mem_swap_info)) {
        tloge("Invalid buffer size, tee_mem_info_size[0x%x]!\n", tee_mem_info_size);
        return HI_ERR_DMX_INVALID_PARA;
    }

    if (memcpy_s(&tee_mem_info, tee_mem_info_size, tee_mem_info_ptr, sizeof(dmx_tee_mem_swap_info))) {
        tloge("memcpy_s failed.\n");
        return HI_TEE_ERR_MEM;
    }

    ret = tee_dmx_destroy_rec_chan(id, &tee_mem_info);
    return ret;
}

static hi_s32 dmx_attach_rec_chn(uint32_t type, TEE_Param params[PARAM_LEN])
{
    hi_s32 ret;
    dmx_rec_attach_info *rec_attach_ptr = params[0].memref.buffer;
    hi_u32 rec_attach_size = params[0].memref.size;
    dmx_rec_attach_info rec_attach_info = {0};

    dmx_null_pointer_return(rec_attach_ptr);

    check_param_types(type, TEE_PARAM_TYPE_MEMREF_INPUT,\
        TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

    if (rec_attach_size != sizeof(dmx_rec_attach_info)) {
        tloge("Invalid buffer size, rec_attach_size[0x%x]!\n", rec_attach_size);
        return HI_ERR_DMX_INVALID_PARA;
    }

    if (memcpy_s(&rec_attach_info, rec_attach_size, rec_attach_ptr, sizeof(dmx_rec_attach_info))) {
        tloge("memcpy_s failed.\n");
        return HI_TEE_ERR_MEM;
    }

    ret = tee_dmx_attach_rec_chan(&rec_attach_info);
    return ret;
}

static hi_s32 dmx_detach_rec_chn(uint32_t type, TEE_Param params[PARAM_LEN])
{
    hi_s32 ret;
    dmx_rec_detach_info *rec_detach_ptr = params[0].memref.buffer;
    hi_u32 rec_detach_size = params[0].memref.size;
    dmx_rec_detach_info rec_detach_info = {0};

    dmx_null_pointer_return(rec_detach_ptr);

    check_param_types(type, TEE_PARAM_TYPE_MEMREF_INPUT,\
        TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

    if (rec_detach_size != sizeof(dmx_rec_detach_info)) {
        tloge("Invalid buffer size, rec_detach_size[0x%x]!\n", rec_detach_size);
        return HI_ERR_DMX_INVALID_PARA;
    }

    if (memcpy_s(&rec_detach_info, sizeof(dmx_rec_detach_info), rec_detach_ptr, rec_detach_size)) {
        tloge("memcpy_s failed.\n");
        return HI_TEE_ERR_MEM;
    }

    ret = tee_dmx_detach_rec_chan(&rec_detach_info);
    return ret;
}

static hi_s32 dmx_update_play_read_idx(uint32_t type, TEE_Param params[PARAM_LEN])
{
    hi_s32 ret;
    hi_u32 buf_id = params[0].value.a;
    dmx_chan_type chan_type = params[0].value.b;
    hi_u32 read_idx = params[1].value.a;

    check_param_types(type, TEE_PARAM_TYPE_VALUE_INPUT,\
        TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

    ret = tee_dmx_update_play_read_idx(buf_id, chan_type, read_idx);
    return ret;
}

static hi_s32 dmx_update_rec_read_idx(uint32_t type, TEE_Param params[PARAM_LEN])
{
    hi_s32 ret;
    check_param_types(type, TEE_PARAM_TYPE_VALUE_INPUT,\
            TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

    ret = tee_dmx_update_rec_read_idx((hi_u32)params[0].value.a, (hi_u32)params[0].value.b);
    return ret;
}

static hi_s32 dmx_acquire_secbuf_id(uint32_t type, TEE_Param params[PARAM_LEN])
{
    hi_s32 ret;
    hi_u32 buf_id = 0;

    check_param_types(type, TEE_PARAM_TYPE_VALUE_OUTPUT,\
        TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

    ret = tee_dmx_acquire_buf_id(&buf_id);

    params[0].value.a = buf_id;
    return ret;
}

static hi_s32 dmx_release_secbuf_id(uint32_t type, TEE_Param params[PARAM_LEN])
{
    hi_s32 ret;

    check_param_types(type, TEE_PARAM_TYPE_VALUE_INPUT,\
            TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

    ret = tee_dmx_release_buf_id((hi_u32)params[0].value.a);
    return ret;
}

static hi_s32 dmx_detach_raw_pid_ch(uint32_t type, TEE_Param params[PARAM_LEN])
{
    hi_s32 ret;
    check_param_types(type, TEE_PARAM_TYPE_VALUE_INPUT,\
            TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

    ret = tee_dmx_detach_raw_pidch((hi_u32)params[0].value.a);
    return ret;
}

static hi_s32 dmx_config_secbuf(uint32_t type, TEE_Param params[PARAM_LEN])
{
    hi_s32 ret;
    check_param_types(type, TEE_PARAM_TYPE_VALUE_INPUT,\
            TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

    ret = tee_dmx_config_secbuf((hi_u32)params[0].value.a, (dmx_chan_type)params[0].value.b);
    return ret;
}

static hi_s32 dmx_deconfig_secbuf(uint32_t type, TEE_Param params[PARAM_LEN])
{
    hi_s32 ret;
    check_param_types(type, TEE_PARAM_TYPE_VALUE_INPUT,\
            TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

    ret = tee_dmx_deconfig_secbuf((hi_u32)params[0].value.a, (dmx_chan_type)params[0].value.b);
    return ret;
}

static hi_s32 dmx_enable_rec_chn(uint32_t type, TEE_Param params[PARAM_LEN])
{
    hi_s32 ret;
    check_param_types(type, TEE_PARAM_TYPE_VALUE_INPUT,\
            TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

    ret = tee_dmx_enable_rec_chn((hi_u32)params[0].value.a);
    return ret;
}

static hi_s32 dmx_tee_fixup_hevc_index(uint32_t type, TEE_Param params[PARAM_LEN])
{
    hi_s32 ret;
    dmx_tee_scd_buf scd_buf_info;
    scd_buf_info.rec_pid = params[0].value.a;
    scd_buf_info.idx_pid = params[1].value.a;
    scd_buf_info.parse_offset = params[1].value.b;

    hi_void* findex_scd_buf = params[0x2].memref.buffer;
    scd_buf_info.findex_scd_size = params[0x2].memref.size;
    hi_void *dmx_rec_index_buf = params[0x3].memref.buffer;
    scd_buf_info.rec_index_size = params[0x3].memref.size;

    dmx_null_pointer_return(findex_scd_buf);
    dmx_null_pointer_return(dmx_rec_index_buf);
    check_param_types(type, TEE_PARAM_TYPE_VALUE_INPUT, \
            TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT);

    if (memcpy_s(&scd_buf_info.findex_scd, sizeof(scd_buf_info.findex_scd), findex_scd_buf,
        scd_buf_info.findex_scd_size) != EOK) {
        return HI_FAILURE;
    }

    if (memset_s(&scd_buf_info.dmx_rec_index, scd_buf_info.rec_index_size, 0x00, scd_buf_info.rec_index_size) != EOK) {
        return HI_FAILURE;
    }

    ret = tee_dmx_fixup_hevc_index(&scd_buf_info);
    if (ret == HI_SUCCESS) {
        if (memcpy_s(dmx_rec_index_buf, scd_buf_info.rec_index_size,
            &scd_buf_info.dmx_rec_index, sizeof(scd_buf_info.dmx_rec_index)) != EOK) {
            return HI_FAILURE;
        }
    }
    return ret;
}

static hi_s32 dmx_tee_sec_pes_flush_shadow_buf(uint32_t type, TEE_Param params[PARAM_LEN])
{
    hi_s32 ret;
    hi_u32 chan_id = params[0].value.a;
    dmx_chan_type chan_type = params[0].value.b;
    hi_u32 offset = params[1].value.a;
    hi_bool rool_flag = params[1].value.b;
    hi_u32 data_len = 0;

    check_param_types(type, TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_VALUE_OUTPUT,
        TEE_PARAM_TYPE_NONE);

    ret = tee_dmx_sec_pes_flush_shadow_buf(chan_id, chan_type, offset, &rool_flag, &data_len);
    params[0x2].value.a = data_len;
    params[0x2].value.b = rool_flag;

    return ret;
}

static hi_s32 dmx_tee_flt_sec_pes_lock(uint32_t type, TEE_Param params[PARAM_LEN])
{
    hi_s32 ret;
    dmx_tee_flt_info flt_info;

    check_param_types(type, TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

    flt_info = *((dmx_tee_flt_info*)params[0].memref.buffer);

    ret = tee_dmx_flt_sec_pes_lock(&flt_info);

    return ret;
}

static hi_s32 dmx_tee_config_cc_drop(uint32_t type, TEE_Param params[PARAM_LEN])
{
    hi_s32 ret;
    dmx_tee_cc_drop_info cc_drop_info;

    check_param_types(type, TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE);

    cc_drop_info.pid_ch_id = params[0].value.a;
    cc_drop_info.ccerr_drop = params[0].value.b;
    cc_drop_info.ccrepeat_drop = params[1].value.a;

    ret = tee_dmx_config_cc_drop(&cc_drop_info);

    return ret;
}

static dmx_task_entry g_dmx_func_cmd_map[] = {
    { TEEC_CMD_CREATE_RAMPORT, dmx_creat_ramport },
    { TEEC_CMD_DESTROY_RAMPORT, dmx_destroy_ramport },
    { TEEC_CMD_SET_RAMPORT_DSC, dmx_set_ramport_dec },
    { TEEC_CMD_CREATE_PLAY_CHAN, dmx_create_play_chn },
    { TEEC_CMD_DESTROY_PLAY_CHAN, dmx_destroy_play_chn },
    { TEEC_CMD_ATTACH_PLAY_CHAN, dmx_attach_play_chn },
    { TEEC_CMD_DETACH_PLAY_CHAN, dmx_detach_play_chn },
    { TEEC_CMD_CREATE_REC_CHAN, dmx_create_rec_chn },
    { TEEC_CMD_DESTROY_REC_CHAN, dmx_detroy_rec_chn },
    { TEEC_CMD_ATTACH_REC_CHAN, dmx_attach_rec_chn },
    { TEEC_CMD_DETACH_REC_CHAN, dmx_detach_rec_chn },
    { TEEC_CMD_UPDATE_PLAY_READ_IDX, dmx_update_play_read_idx },
    { TEEC_CMD_UPDATE_REC_READ_IDX, dmx_update_rec_read_idx },
    { TEEC_CMD_ACQUIRE_SECBUF_ID, dmx_acquire_secbuf_id },
    { TEEC_CMD_RELEASE_SECBUF_ID, dmx_release_secbuf_id },
    { TEEC_CMD_DETACH_RAW_PIDCH, dmx_detach_raw_pid_ch },
    { TEEC_CMD_CONFIG_SECBUF, dmx_config_secbuf },
    { TEEC_CMD_DECONFIG_SECBUF, dmx_deconfig_secbuf },
    { TEEC_CMD_ENABLE_REC_CHAN, dmx_enable_rec_chn },
    { TEEC_CMD_FIXUP_HEVC_INDEX, dmx_tee_fixup_hevc_index },
    { TEEC_CMD_FLUSH_SHADOW_BUF, dmx_tee_sec_pes_flush_shadow_buf },
    { TEEC_CMD_FLT_PES_SEC_LOCK, dmx_tee_flt_sec_pes_lock },
    { TEEC_CMD_CONFIG_CC_DROP, dmx_tee_config_cc_drop }
};

__DEFAULT TEE_Result TA_InvokeCommandEntryPoint(hi_void* session, uint32_t cmd, uint32_t type,
    TEE_Param params[PARAM_LEN])
{
    hi_u32 i;
    dmx_unused(session);

    if (cmd == TEEC_CMD_INIT) {
        return tee_dmx_init();
    } else if (cmd == TEEC_CMD_DEINIT) {
        return tee_dmx_deinit();
    } else {
        for (i = 0; i < sizeof(g_dmx_func_cmd_map) / sizeof(g_dmx_func_cmd_map[0]); i++) {
            if (cmd == g_dmx_func_cmd_map[i].cmd) {
                return g_dmx_func_cmd_map[i].fun_entry(type, params);
            }
        }
    }

    tloge("Invalid cmd[0x%x]!\n", cmd);
    return TEE_ERROR_BAD_PARAMETERS;
}

__DEFAULT void TA_CloseSessionEntryPoint(hi_void *session)
{
    dmx_unused(session);
}

__DEFAULT void TA_DestroyEntryPoint(void)
{
    return;
}
