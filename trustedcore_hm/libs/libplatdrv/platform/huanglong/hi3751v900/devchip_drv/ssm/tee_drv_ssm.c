/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019. All rights reserved.
 * Description: drv function file for Hisilicon SSM
 * Author: ssm group
 * Create: 2019/12/11
 * Notes:
 */

#include "hi_type_dev.h"
#include "tee_drv_ssm.h"
#include "hi_tee_drv_ssm.h"
#include "hi_tee_drv_os_hal.h"
#include "hi_tee_drv_syscall_id.h"
#include "hi_tee_module_id.h"
#include "hi_tee_errcode.h"
#include "hi_list.h"
#include "hi_tee_drv_mem.h"
#include "hi_tee_mbx.h"
#include "iommu_tag_init.h"
#include "pthread.h"

#define SSM_MAX_SESSION_NUM         16
#define SSM_INVALID_SESSION_ID      0x77
#define MAX_MOD_NUM                 4
#define SHIFT_FOR_MOD_ID            24
#define SHIFT_FOR_SEC_INFO_INDEX    16
#define SHIFT_FOR_SESSION_ID        8
#define SHIFT_FOR_HIGH_ADDR         32
#define SSM_CREATE_MBX_CMD          0xA1
#define SSM_CREATE_BUF_LEN          5
#define SSM_DESTROY_MBX_CMD         0xA2
#define SSM_DESTROY_BUF_LEN         5
#define SSM_ADD_RESOURCE_MBX_CMD    0xA3
#define SSM_ADD_RESOURCE_BUF_LEN    9
#define SSM_ATTACH_BUF_MBX_CMD      0xA4
#define SSM_ATTACH_BUF_BUF_LEN      17
#define SSM_DETACH_BUF_MBX_CMD      0xA5
#define SSM_DETACH_BUF_BUF_LEN      17

#define SSM_RETURN_BUF_LEN          5
#define MASK_FOR_LOW_8_BITS         0xff
#define MASK_FOR_LOW_16_BITS        0xffff

#define SSM_INIT_VMCU_CMD           0x0A
#define SSM_INIT_VDH_CMD            0x0B
#define SSM_GET_PGT_ADDR_CMD        0x0C
#define SSM_INIT_SEC_INFO_MBX_CMD   0x0D
#define SSM_INIT_SEC_INFO_BUF_LEN   17

#define SSM_PGT_ADDR_BUF_CMD_LEN    5

#define GLOBAL_SEC_INFO_TAG         0x912416AC
#define FRAME_SEC_INFO_TAG          0x6edbe953

#define SSM_SEND_POLICY_CMD          0x93
#define MBX_TRANSMIT_POLICY_LEN     (sizeof(hi_tee_ssm_policy_table) + sizeof(hi_u8) + sizeof(hi_handle))

#define MBX_TIME_OUT                100000
#define make_sm_handle(session_id)    ((HI_ID_SSM << SHIFT_FOR_MOD_ID) | (session_id))
#define SECURE_INFO_NAME            "secure_info"

#define ssm_check_pointer_return_if_fail(pointer) \
    do { \
        if ((pointer) == HI_NULL) { \
            hi_error_ssm("pointer is null\n"); \
            return HI_ERR_SSM_NULL_PTR; \
        } \
    } while (0)

#define ssm_check_intent_return_if_fail(intent) \
    do { \
        if ((intent) >= HI_TEE_SSM_INTENT_MAX) { \
            hi_error_ssm("invalid intent\n"); \
            return HI_ERR_SSM_INVALID_INTENT; \
        } \
    } while (0)

#define ssm_check_session_handle_return_if_fail(session_handle) \
    do { \
        if (((session_handle) == HI_INVALID_HANDLE) || \
            (((session_handle) >> SHIFT_FOR_MOD_ID) != HI_ID_SSM)) { \
            hi_error_ssm("session handle invalid\n"); \
            return HI_ERR_SSM_INVALID_SESSOION_HANDLE; \
        } \
    } while (0)

#define ssm_check_if_session_buf_return_if_fail(tag) \
    do { \
        if ((tag) < BUFFER_TAG_DMX_VID_ES_BUF || (tag) > BUFFER_TAG_PVR_PLAYBACK_TS_BUF) { \
            hi_error_ssm("this is not session belonged buffer\n"); \
            return HI_ERR_SSM_NOT_SESSION_BELONGED_BUF; \
        } \
    } while (0)

static ssm_tag_2_id_map g_id_tag_map[] = {
    {BUFFER_ID_INTERNAL_BUF_DMX, BUFFER_TAG_INTERNAL_BUF_DMX},
    {BUFFER_ID_INTERNAL_BUF_TSCIPHER, BUFFER_TAG_INTERNAL_BUF_TSCIPHER},
    {BUFFER_ID_CIPHER_CENC_BUF, BUFFER_TAG_INTERNAL_BUF_MCIPHER},
    {BUFFER_ID_INTERNAL_BUF_MCIPHER, BUFFER_TAG_INTERNAL_BUF_MCIPHER},
    {BUFFER_ID_VID_RAWLIST_MCU_ONLY, BUFFER_TAG_INTERNAL_BUF_VDEC},
    {BUFFER_ID_VID_SEGLIST_MCU_ONLY, BUFFER_TAG_INTERNAL_BUF_VDEC},
    {BUFFER_ID_VID_STDCTX_MCU_ONLY, BUFFER_TAG_INTERNAL_BUF_VDEC},
    {BUFFER_ID_VID_PICMSG_MCU_ONLY, BUFFER_TAG_INTERNAL_BUF_VDEC},
    {BUFFER_ID_VID_SLICEMSG_MCU_ONLY, BUFFER_TAG_INTERNAL_BUF_VDEC},
    {BUFFER_ID_VID_METADATA_MCU_ONLY, BUFFER_TAG_INTERNAL_BUF_VDEC},
    {BUFFER_ID_VID_SCDRAW_BUF, BUFFER_TAG_INTERNAL_BUF_VDEC},
    {BUFFER_ID_VID_SCDSEG_BUF, BUFFER_TAG_INTERNAL_BUF_VDEC},
    {BUFFER_ID_VID_SCDMSG, BUFFER_TAG_INTERNAL_BUF_VDEC},
    {BUFFER_ID_VID_VDHPMV_BUF, BUFFER_TAG_INTERNAL_BUF_VDEC},
    {BUFFER_ID_VID_VDHEXT_BUF_VID_ONLY, BUFFER_TAG_INTERNAL_BUF_VDEC},
    {BUFFER_ID_VID_FRMBIN_VDH_ONLY, BUFFER_TAG_INTERNAL_BUF_VDEC},
    {BUFFER_ID_INTERNAL_BUF_VDEC, BUFFER_TAG_INTERNAL_BUF_VDEC},
    {BUFFER_ID_INTERNAL_BUF_AUDDSP, BUFFER_TAG_INTERNAL_BUF_AUDDSP},
    {BUFFER_ID_INTERNAL_BUF_VENC, BUFFER_TAG_INTERNAL_BUF_VENC},
    {BUFFER_ID_INTERNAL_BUF_VPSS, BUFFER_TAG_INTERNAL_BUF_VPSS},
    {BUFFER_ID_VDP_SD_WRITEBACK_ONLY, BUFFER_TAG_INTERNAL_BUF_VDP},
    {BUFFER_ID_INTERNAL_BUF_VDP, BUFFER_TAG_INTERNAL_BUF_VDP},
    {BUFFER_ID_INTERNAL_BUF_GPU, BUFFER_TAG_INTERNAL_BUF_GPU},
    {BUFFER_ID_INTERNAL_BUF_HWC, BUFFER_TAG_INTERNAL_BUF_HWC},
    {BUFFER_ID_INTERNAL_BUF_JPEG_DEC, BUFFER_TAG_INTERNAL_BUF_JPEG_DEC},
    {BUFFER_ID_INTERNAL_BUF_JPEG_ENC, BUFFER_TAG_INTERNAL_BUF_JPEG_ENC},
    {BUFFER_ID_INTERNAL_BUF_NPU, BUFFER_TAG_INTERNAL_BUF_NPU},
    {BUFFER_ID_DMX_VID_ES_BUF, BUFFER_TAG_DMX_VID_ES_BUF},
    {BUFFER_ID_DMX_AUD_ES_BUF, BUFFER_TAG_DMX_AUD_ES_BUF},
    {BUFFER_ID_MCIPHER_VID_ES_BUF, BUFFER_TAG_MCIPHER_VID_ES_BUF},
    {BUFFER_ID_MCIPHER_AUD_ES_BUF, BUFFER_TAG_MCIPHER_AUD_ES_BUF},
    {BUFFER_ID_MCIPHER_TS_BUF, BUFFER_TAG_MCIPHER_TS_BUF},
    {BUFFER_ID_PVR_RECORD_TS_BUF, BUFFER_TAG_PVR_RECORD_TS_BUF},
    {BUFFER_ID_PVR_PLAYBACK_TS_BUF, BUFFER_TAG_PVR_PLAYBACK_TS_BUF},
    {BUFFER_ID_VID_FRM_BUF, BUFFER_TAG_VID_FRM_BUF},
    {BUFFER_ID_VPSS_OUTPUT_BUF, BUFFER_TAG_VPSS_OUTPUT_BUF},
    {BUFFER_ID_VDP_OUTPUT_BUF, BUFFER_TAG_VDP_OUTPUT_BUF},
    {BUFFER_ID_SECURE_INFOR_BUF, BUFFER_TAG_SECURE_INFOR_BUF},
    {BUFFER_ID_VIDEO_CAPTURE_ENCODE_OUTPUT_BUF, BUFFER_TAG_JPEG_ENCODE_OUTPUT_BUF},
    {BUFFER_ID_TRANSCODE_ENCODE_OUTPUT_BUF, BUFFER_TAG_VEDU_OUTPUT_BUF},
    {BUFFER_ID_MIRA_ENCODE_OUTPUT_BUF, BUFFER_TAG_VEDU_OUTPUT_BUF},
    {BUFFER_ID_GRAPHIC_OUPUT_BUF, BUFFER_TAG_GRAPHIC_OUPUT_BUF},
    {BUFFER_ID_NPU_OUTPUT_BUF, BUFFER_TAG_NPU_OUTPUT_BUF},
};

static hi_u32 g_session_num = 0;
struct list_head g_ssm_instance_head = {&g_ssm_instance_head, &g_ssm_instance_head};

static const hi_mod_id g_intent_table[HI_TEE_SSM_INTENT_MAX][MAX_MOD_NUM] = {
    {HI_ID_CIPHER, HI_ID_TSR2RCIPHER, HI_ID_DEMUX, HI_ID_VDEC}, /* WATCH */
    {HI_ID_CIPHER, HI_ID_TSR2RCIPHER, HI_ID_DEMUX, HI_ID_MAX}, /* RECORD */
    {HI_ID_CIPHER, HI_ID_TSR2RCIPHER, HI_ID_DEMUX, HI_ID_VDEC} /* EXPORT */
};

static hi_tee_ssm_sec_info_manager g_sec_info_manager = {0};
static hi_bool g_sec_info_inited = HI_FALSE;
static struct hi_tee_hal_mutex g_sec_info_lock = {0};
static struct hi_tee_hal_mutex g_instance_lock = {0};
static hi_s32 g_mbx_handle = HI_INVALID_HANDLE;
static hi_s32 g_mbx_rcv_handle = HI_INVALID_HANDLE;
static pthread_mutex_t g_thread_mutex = {0};
static pthread_cond_t  g_thread_cond = {0};
static pthread_t       g_thread = {0};
static hi_bool         g_thread_run_flag = HI_TRUE;
static hi_bool         g_ssm_need_proc = HI_FALSE;

static hi_bool         g_ssm_need_send_pgt = HI_FALSE;
static hi_bool         g_ssm_need_send_sec_info = HI_FALSE;


hi_s32 policy_table_transmit(hi_handle session_handle, const hi_tee_ssm_policy_table *policy_table)
{
    hi_u8      mbx_send_buf[MBX_TRANSMIT_POLICY_LEN] = {0};
    hi_u8      mbx_rcv_buf[SSM_RETURN_BUF_LEN] = {0};
    hi_u32     tx_len;
    hi_u32     rx_len;
    hi_handle *p = HI_NULL;
    hi_u32    *p2 = HI_NULL;
    hi_s32     ret;

    mbx_send_buf[0] = SSM_SEND_POLICY_CMD;

    p = (hi_handle *)&mbx_send_buf[1]; /* fill session handle in bit 1-4 */
    *p = session_handle;
    p = HI_NULL;

    p2 = (hi_u32 *)&mbx_send_buf[5]; /* fill buf addr in bit 5-12 */

    for (hi_u32 i = 0; i < SSM_MAX_HDCP_TYPE_NUM; i++) {
        for (hi_u32 j = 0; j < SSM_MAX_RESOLUTION_LVL_NUM; j++) {
            *(hi_u32 *)p2 = policy_table->table[i][j];
            p2++;
        }
    }

    ret = hi_tee_mbx_tx(g_mbx_handle, mbx_send_buf, MBX_TRANSMIT_POLICY_LEN, &tx_len, MBX_TIME_OUT);
    if (ret != HI_SUCCESS) {
        hi_error_ssm("mbx send policy data fail:%x\n", ret);
        return ret;
    }

    ret = hi_tee_mbx_rx(g_mbx_handle, mbx_rcv_buf, SSM_RETURN_BUF_LEN, &rx_len, MBX_TIME_OUT);
    if (ret != HI_SUCCESS) {
        hi_error_ssm("mbx rcv data fail:%x-%d\n", ret, __LINE__);
        return ret;
    }

    ret = *(hi_s32 *)mbx_rcv_buf;
    if (ret != HI_SUCCESS) {
        hi_error_ssm("sa add poliocy table fail,ret:%x\n", ret);
        return ret;
    }

    return HI_SUCCESS;
}

static inline ssm_buf_type get_buf_type(hi_tee_ssm_buffer_id buf_id)
{
    if (buf_id >= BUFFER_ID_INTERNAL_BUF_DMX && buf_id <= BUFFER_ID_INTERNAL_BUF_NPU) {
        return SSM_INTERNAL_BUF;
    } else if (buf_id >= BUFFER_ID_DMX_VID_ES_BUF && buf_id <= BUFFER_ID_PVR_PLAYBACK_TS_BUF) {
        return SSM_SESSION_BUF;
    } else if (buf_id >= BUFFER_ID_VID_FRM_BUF && buf_id <= BUFFER_ID_NPU_OUTPUT_BUF) {
        return SSM_FRAME_BUF;
    } else return SSM_INVALID_BUF;
}

static hi_s32 release_secure_info(hi_u32 sec_info_index)
{
    hi_tee_ssm_secure_info *secure_info_addr = HI_NULL;

    if (sec_info_index >= SECURE_INFO_MAX_NUM) {
        hi_error_ssm("invalid secure info index\n");
        return HI_ERR_SSM_INVALID_SECURE_INFO_INDEX;
    }

    hi_tee_drv_hal_mutex_lock(&g_sec_info_lock);

    if (g_sec_info_manager.status[sec_info_index].used == HI_TRUE) {
        secure_info_addr = (hi_tee_ssm_secure_info *)((hi_void *)g_sec_info_manager.secure_info_mem_header.virt +
                            sec_info_index * sizeof(hi_tee_ssm_secure_info));

        g_sec_info_manager.status[sec_info_index].used = HI_FALSE;
        g_sec_info_manager.numbers_used--;
    } else {
        hi_error_ssm("index is invalid\n");
        hi_tee_drv_hal_mutex_unlock(&g_sec_info_lock);

        return HI_ERR_SSM_INVALID_SECURE_INFO_INDEX;
    }

    hi_tee_drv_hal_mutex_unlock(&g_sec_info_lock);

    memset_s(secure_info_addr, sizeof(hi_tee_ssm_secure_info), 0, sizeof(hi_tee_ssm_secure_info));

    return HI_SUCCESS;
}

static hi_s32 get_free_secure_info(hi_tee_ssm_secure_info **secure_info_addr, hi_u32 *index)
{
    hi_u32 i = 0;

    ssm_check_pointer_return_if_fail(secure_info_addr);
    ssm_check_pointer_return_if_fail(index);

    hi_tee_drv_hal_mutex_lock(&g_sec_info_lock);

    for (i = 0; i < SECURE_INFO_MAX_NUM; i++) {
        if (g_sec_info_manager.status[i].used == HI_TRUE) {
            continue;
        }
        break;
    }

    if (i >= SECURE_INFO_MAX_NUM) {
        hi_tee_drv_hal_mutex_unlock(&g_sec_info_lock);
        hi_error_ssm("cannot get valid info\n");
        return HI_ERR_SSM_NO_VALID_SECURE_INFO;
    }

    g_sec_info_manager.status[i].used = HI_TRUE;
    g_sec_info_manager.numbers_used++;
    (*secure_info_addr) = (hi_tee_ssm_secure_info *)((hi_u8 *)g_sec_info_manager.secure_info_mem_header.virt +
            (i * sizeof(hi_tee_ssm_secure_info)));
    (*index) = i;

    hi_tee_drv_hal_mutex_unlock(&g_sec_info_lock);

    return HI_SUCCESS;
}

static hi_s32 get_secure_info_addr_by_index(hi_u32 secinfo_index, hi_tee_ssm_secure_info **secinfo_addr)
{
    ssm_check_pointer_return_if_fail(secinfo_addr);

    hi_tee_drv_hal_mutex_lock(&g_sec_info_lock);

    if (secinfo_index >= SECURE_INFO_MAX_NUM) {
        hi_tee_drv_hal_mutex_unlock(&g_sec_info_lock);
        hi_error_ssm("cannot get valid info\n");
        return HI_ERR_SSM_NO_VALID_SECURE_INFO;
    }

    if (g_sec_info_manager.status[secinfo_index].used != HI_TRUE) {
        hi_tee_drv_hal_mutex_unlock(&g_sec_info_lock);
        hi_error_ssm("this sec info is not used\n");
        return HI_FAILURE;
    }

    *secinfo_addr = (hi_tee_ssm_secure_info *)((hi_u8 *)g_sec_info_manager.secure_info_mem_header.virt +
        (secinfo_index * sizeof(hi_tee_ssm_secure_info)));
    hi_tee_drv_hal_mutex_unlock(&g_sec_info_lock);

    return HI_SUCCESS;
}


hi_u32 free_secure_info_pool(hi_void)
{
    hi_s32 ret;

    hi_tee_drv_hal_mutex_lock(&g_sec_info_lock);

    ret = hi_tee_drv_smmu_unmap_cpu(&g_sec_info_manager.secure_info_mem_header);
    if (ret != HI_SUCCESS) {
        hi_tee_drv_hal_mutex_unlock(&g_sec_info_lock);
        hi_error_ssm("unmap secure info fail:%x\n", ret);
        return ret;
    }

    ret = hi_tee_drv_smmu_free(&g_sec_info_manager.secure_info_mem_header);
    if (ret != HI_SUCCESS) {
        hi_tee_drv_hal_mutex_unlock(&g_sec_info_lock);
        hi_error_ssm("free secure info fail:%x\n", ret);
        return ret;
    }

    if (g_sec_info_manager.secure_info_mem_header.virt != HI_NULL) {
        g_sec_info_manager.secure_info_mem_header.size = 0;
        g_sec_info_manager.secure_info_mem_header.smmu_addr = 0;
        g_sec_info_manager.secure_info_mem_header.virt = HI_NULL;

        g_sec_info_manager.numbers_used = 0;

        (hi_void)memset_s(g_sec_info_manager.status, SECURE_INFO_MAX_NUM * sizeof(sec_info_status), 0,
            SECURE_INFO_MAX_NUM * sizeof(sec_info_status));

        hi_tee_drv_hal_mutex_unlock(&g_sec_info_lock);

        return HI_SUCCESS;
    } else {
        hi_tee_drv_hal_mutex_unlock(&g_sec_info_lock);
        return HI_FAILURE;
    }
}

hi_s32 notify_mbx_to_update_sec_info(hi_u32 sec_info_size, hi_u64 smmu_addr, hi_u32 total_size)
{
    hi_u8                    mbx_send_buf[SSM_INIT_SEC_INFO_BUF_LEN] = {0};
    hi_u32                   tx_len = SSM_INIT_SEC_INFO_BUF_LEN;
    hi_handle               *p = HI_NULL;
    hi_s32                   ret;

    mbx_send_buf[0] = SSM_INIT_SEC_INFO_MBX_CMD;

    p = (hi_handle *)&mbx_send_buf[1];
    *p = sec_info_size;

    p = (hi_handle *)&mbx_send_buf[5]; /* 5 is offset */
    *p = smmu_addr;

    p = (hi_handle *)&mbx_send_buf[13]; /* 13 is offset */
    *p = total_size;
    p = HI_NULL;

    ret = hi_tee_mbx_tx(g_mbx_rcv_handle, mbx_send_buf, SSM_INIT_SEC_INFO_BUF_LEN, &tx_len, MBX_TIME_OUT);
    if (ret != HI_SUCCESS) {
        hi_error_ssm("mbx send data fail:%x\n", ret);
        return ret;
    }

    return ret;
}


hi_s32 allocate_secure_info_pool(hi_void)
{
    hi_s32 ret;
    hi_tee_smmu_buf mem_header = {0};

    ret = hi_tee_drv_smmu_alloc(SECURE_INFO_NAME, SECURE_INFO_MAX_NUM * sizeof(hi_tee_ssm_secure_info), &mem_header);
    if (ret != HI_SUCCESS) {
        hi_error_ssm("alloc secure info fail\n");
        return HI_ERR_SSM_SECURE_INFO_INIT_FAIL;
    }

    ret = hi_tee_drv_smmu_map_cpu(&mem_header, HI_FALSE);
    if (ret != HI_SUCCESS) {
        hi_error_ssm("map secure info fail\n");
        (hi_void)hi_tee_drv_smmu_unmap_cpu(&mem_header);
        (hi_void)hi_tee_drv_smmu_free(&mem_header);
        memset_s(&mem_header, sizeof(hi_tee_smmu_buf), 0, sizeof(hi_tee_smmu_buf));
        return HI_ERR_SSM_SECURE_INFO_INIT_FAIL;
    }

    /* sec info has to be accessed by many modules, maybe not only VDEC */
    ret = hi_tee_drv_smmu_set_tag(&mem_header, BUFFER_TAG_INTERNAL_BUF_VDEC);
    if (ret != HI_SUCCESS) {
        hi_error_ssm("-----%d, %s fail\n", __LINE__, __func__);
    }

    ret = memset_s(mem_header.virt, SECURE_INFO_MAX_NUM * sizeof(hi_tee_ssm_secure_info), 0,
        SECURE_INFO_MAX_NUM * sizeof(hi_tee_ssm_secure_info));
    if (ret != HI_SUCCESS) {
        hi_error_ssm("init secure info fail\n");
        (hi_void)hi_tee_drv_smmu_unmap_cpu(&mem_header);
        (hi_void)hi_tee_drv_smmu_free(&mem_header);
        memset_s(&mem_header, sizeof(hi_tee_smmu_buf), 0, sizeof(hi_tee_smmu_buf));
        return HI_ERR_SSM_SECURE_INFO_INIT_FAIL;
    }

    hi_tee_drv_hal_mutex_lock(&g_sec_info_lock);

    g_sec_info_manager.secure_info_mem_header.size = mem_header.size;
    g_sec_info_manager.secure_info_mem_header.virt = mem_header.virt;
    g_sec_info_manager.secure_info_mem_header.smmu_addr = mem_header.smmu_addr;

    *(hi_u32 *)(uintptr_t)g_sec_info_manager.secure_info_mem_header.virt = GLOBAL_SEC_INFO_TAG;
    g_sec_info_manager.numbers_used++;
    g_sec_info_manager.status[0].used = HI_TRUE;

    (hi_void)memset_s(&mem_header, sizeof(hi_tee_smmu_buf), 0, sizeof(hi_tee_smmu_buf));

    hi_tee_drv_hal_mutex_unlock(&g_sec_info_lock);

    return HI_SUCCESS;
}

static hi_s32 map_buffer_id_to_tag(const hi_tee_ssm_buffer_id buf_id, hi_u32 *buf_tag)
{
    hi_u32 i;
    ssm_check_pointer_return_if_fail(buf_tag);

    for (i = 0; i < sizeof(g_id_tag_map) / sizeof(g_id_tag_map[0]); i++) {
        if (g_id_tag_map[i].buf_id == buf_id) {
            *buf_tag = g_id_tag_map[i].buf_tag;
            break;
        }
    }

    if (i >= sizeof(g_id_tag_map) / sizeof(g_id_tag_map[0])) {
        hi_error_ssm("input buffer id is invalid : %d\n", buf_id);
        return HI_FAILURE;
    }

    return HI_SUCCESS;
}

static hi_s32 clean_up_buffer_info_by_head(hi_tee_drv_ssm_buffer_info_head *list_head)
{
    hi_tee_drv_ssm_buffer_info_node *node_to_del = HI_NULL;

    ssm_check_pointer_return_if_fail(list_head);

    while (list_head->list.next != &(list_head->list)) {
        node_to_del = list_entry(list_head->list.next, hi_tee_drv_ssm_buffer_info_node, list);
        list_del(list_head->list.next);
        hi_tee_drv_hal_free(node_to_del);
        node_to_del = HI_NULL;
    }
    return HI_SUCCESS;
}

static hi_s32 clean_up_resource_by_head(hi_tee_drv_ssm_module_head *list_head)
{
    hi_tee_drv_ssm_module_node *node_to_del = HI_NULL;
    ssm_check_pointer_return_if_fail(list_head);

    while (list_head->list.next != &(list_head->list)) {
        node_to_del = list_entry(list_head->list.next, hi_tee_drv_ssm_module_node, list);
        list_del(list_head->list.next);
        hi_tee_drv_hal_free(node_to_del);
        node_to_del = HI_NULL;
    }
    return HI_SUCCESS;
}

static hi_tee_drv_ssm_instance *find_ssm_instance_by_session_id(const hi_u32 session_id)
{
    hi_tee_drv_ssm_instance *p = HI_NULL;

    list_for_each_entry(p, &g_ssm_instance_head, list) {
        if ((p != HI_NULL) && ((p->session_handle & 0xff) == session_id)) {
            return p;
        }
    }

    return HI_NULL;
}

static hi_s32 find_free_session_id(hi_void)
{
    hi_u32 tmp_id = 0;
    hi_tee_drv_ssm_instance *p = HI_NULL;

    for (tmp_id = 0; tmp_id < SSM_MAX_SESSION_NUM; tmp_id++) {
        p = find_ssm_instance_by_session_id(tmp_id);
        if (p == HI_NULL) {
            return tmp_id;
        }
    }

    return SSM_INVALID_SESSION_ID;
}

static hi_tee_drv_ssm_instance *create_session(const hi_tee_ssm_intent input_intent)
{
    hi_tee_drv_ssm_instance *new_ssm = HI_NULL;
    hi_u32 session_id;
    hi_u32 i = 0;
    hi_s32 ret;

    new_ssm = hi_tee_drv_hal_malloc(sizeof(hi_tee_drv_ssm_instance));
    if (new_ssm == HI_NULL) {
        hi_error_ssm("malloc new instance fail\n");
        return HI_NULL;
    }

    ret = memset_s(new_ssm, sizeof(hi_tee_drv_ssm_instance), 0, sizeof(hi_tee_drv_ssm_instance));
    if (ret != HI_SUCCESS) {
        hi_error_ssm("memset failed\n");
        hi_tee_drv_hal_free(new_ssm);
        new_ssm = HI_NULL;
        return HI_NULL;
    }

    session_id = find_free_session_id();
    if (session_id == SSM_INVALID_SESSION_ID) {
        hi_tee_drv_hal_free(new_ssm);
        new_ssm = HI_NULL;
        return HI_NULL;
    }

    new_ssm->session_handle = make_sm_handle(session_id);
    new_ssm->intent     = input_intent;

    INIT_LIST_HEAD(&new_ssm->cipher_head.list);
    INIT_LIST_HEAD(&new_ssm->plcipher_head.list);
    INIT_LIST_HEAD(&new_ssm->demux_head.list);
    INIT_LIST_HEAD(&new_ssm->vdec_head.list);

    for (i = 0;i < DRV_SSM_SESSION_BUF_TYPE_NUM; i++) {
        INIT_LIST_HEAD(&(new_ssm->buffer_info_list_head[i].list));
    }

    return new_ssm;
}

static hi_tee_drv_ssm_module_head *get_module_entry(hi_tee_drv_ssm_instance *session_instance, const hi_mod_id mod_id)
{
    if (mod_id == HI_ID_CIPHER) {
        return &(session_instance->cipher_head);
    } else if (mod_id == HI_ID_TSR2RCIPHER) {
        return &(session_instance->plcipher_head);
    } else if (mod_id == HI_ID_DEMUX) {
        return &(session_instance->demux_head);
    } else if (mod_id == HI_ID_VDEC) {
        return &(session_instance->vdec_head);
    } else {
        return HI_NULL;
    }
}

static hi_tee_drv_ssm_module_node *search_resource_by_handle(struct list_head *mod_head, const hi_handle mod_handle)
{
    hi_tee_drv_ssm_module_node *p = HI_NULL;

    list_for_each_entry(p, mod_head, list) {
        if (mod_handle == p->module_handle) {
            return p;
        }
    }

    return HI_NULL;
}


static hi_u32 check_module_handle(const hi_handle target_handle, const hi_handle target_session_handle,
                                  hi_tee_drv_ssm_instance *target_session)
{
    hi_mod_id mod_id;
    hi_tee_drv_ssm_instance    *ssm_instance = HI_NULL;
    hi_tee_drv_ssm_module_head *get_mod_head = HI_NULL;
    hi_tee_drv_ssm_module_node *get_mod_instance = HI_NULL;

    mod_id = target_handle >> SHIFT_FOR_MOD_ID;

    /* go through all valid sessions */
    list_for_each_entry(ssm_instance, &g_ssm_instance_head, list) {
        if ((ssm_instance != HI_NULL) && (ssm_instance != target_session)) {
            get_mod_head = get_module_entry(ssm_instance, mod_id);
            if (get_mod_head == HI_NULL) {
                hi_error_ssm("cannot get module entry\n");
                continue;
            }

            get_mod_instance = search_resource_by_handle(&(get_mod_head->list), target_handle);
            if (get_mod_instance != HI_NULL) {
                if (ssm_instance->session_handle == target_session_handle) {
                    return HI_ERR_SSM_BUFFER_ATTACHED_BEFORE;
                } else {
                    return HI_FAILURE;
                }
            }
        }
    }

    return HI_SUCCESS;
}


static hi_u32 check_intent(hi_tee_drv_ssm_instance *session_instance, const hi_tee_drv_ssm_module_node *resource_info)
{
    hi_tee_ssm_intent cur_intent;
    hi_u32                mod_id;
    hi_u32                i = 0;

    mod_id = (resource_info->module_handle) >> SHIFT_FOR_MOD_ID;
    cur_intent = session_instance->intent;

    for (i = 0; i < MAX_MOD_NUM; i++) {
        if (mod_id == g_intent_table[cur_intent][i]) {
            return HI_SUCCESS;
        }
    }

    hi_error_ssm("rule doesn't match\n");
    return HI_FAILURE;
}

static hi_s32 add_module_resource(hi_tee_drv_ssm_module_head *mod_entry, const hi_tee_ssm_module_info *resource_info)
{
    hi_tee_drv_ssm_module_node *p = HI_NULL;
    hi_tee_drv_ssm_module_node *get_mod_node = HI_NULL;

    list_for_each_entry(get_mod_node, &(mod_entry->list), list) {
        if (get_mod_node->module_handle == resource_info->module_handle) {
            return HI_SUCCESS;
        }
    }

    /* do add module resource into SSM instance */
    p = (hi_tee_drv_ssm_module_node *)hi_tee_drv_hal_malloc(sizeof(hi_tee_drv_ssm_module_node));
    if (p == HI_NULL) {
        hi_error_ssm("malloc node fail\n");
        return HI_FAILURE;
    }

    p->module_handle = resource_info->module_handle;
    list_add(&p->list, &mod_entry->list);

    return HI_SUCCESS;
}

/* check steps:
   1.check intent
   2.if  input mod handle is matched in src/dst list
*/
static hi_s32 check_policy_rules(const hi_u32 buf_tag, hi_handle module_handle,
                                 hi_tee_drv_ssm_instance *target_session, hi_u32 *src_dst_flag)
{
    hi_u32            mod_id = module_handle >> SHIFT_FOR_MOD_ID;
    hi_u32            i = 0;
    hi_u32            flag = 0;

    ssm_check_pointer_return_if_fail(src_dst_flag);
    if (buf_tag >= BUFFER_TAG_INTERNAL_BUF_DMX && buf_tag <= BUFFER_TAG_INTERNAL_BUF_NPU) {
        return HI_SUCCESS;
    }

    if (buf_tag >= BUFFER_TAG_DMX_VID_ES_BUF && buf_tag < BUFFER_TAG_VPSS_OUTPUT_BUF) {
        ssm_check_pointer_return_if_fail(target_session);
        if (target_session->intent != g_policy_table[buf_tag].intent) {
            return HI_ERR_SSM_POLICY_INTENT_DISMATCH;
        }
    }

    for (i = 0; i < g_policy_table[buf_tag].src_mod_num; i++) {
        if (mod_id == g_policy_table[buf_tag].src_module[i].mod_id) {
            flag = flag | POLICY_MOD_SRC;
            break;
        }
    }

    for (i = 0; i < g_policy_table[buf_tag].dst_mod_num; i++) {
        if (mod_id == g_policy_table[buf_tag].dst_module[i].mod_id) {
            flag = flag | POLICY_MOD_DST;
            break;
        }
    }

    if (flag == 0) {
        return HI_ERR_SSM_POLICY_MODULE_DISMATCH;
    } else {
        (*src_dst_flag) = flag;
        return HI_SUCCESS;
    }
}

hi_s32 update_mod_info_in_list(hi_tee_drv_ssm_buffer_info_node *node, hi_u32 flag, hi_handle mod_handle)
{
    /* update src/dst module handle list, for session buf, only entry one path */
    if (flag & POLICY_MOD_SRC) {
        if (node->src_mod_handle == 0) {
            node->src_mod_handle = mod_handle;
            return HI_ERR_SSM_NO_NEED_SET_TAG_AGAIN;
        } else if (node->src_mod_handle == mod_handle) {
            return HI_ERR_SSM_NO_NEED_SET_TAG_AGAIN;
        } else {
            return HI_ERR_SSM_BUFFER_ATTACHED_BEFORE;
        }
    }

    if (flag & POLICY_MOD_DST) {
        if (node->dst_mod_handle == 0) {
            node->dst_mod_handle = mod_handle;
            return HI_ERR_SSM_NO_NEED_SET_TAG_AGAIN;
        } else if (node->dst_mod_handle == mod_handle) {
            return HI_ERR_SSM_NO_NEED_SET_TAG_AGAIN;
        } else {
            return HI_ERR_SSM_BUFFER_ATTACHED_BEFORE;
        }
    }

    return HI_SUCCESS;
}

static hi_u32 add_buffer_into_session(hi_tee_drv_ssm_instance *target_instance,
    const hi_tee_drv_ssm_buf_attach_info *buf_info, hi_u32 src_dst_flag)
{
    hi_s32 ret;
    hi_u32 buf_addr_begin, buf_addr_end;
    hi_u32 buf_tag = BUFFER_TAG_INVALID;
    hi_tee_drv_ssm_buffer_info_node *buf_info_node = HI_NULL;

    ret = map_buffer_id_to_tag(buf_info->buf_id, &buf_tag);
    if (ret != HI_SUCCESS) {
        hi_error_ssm("cannot get tag by id:%x\n", ret);
        return ret;
    }

    ssm_check_if_session_buf_return_if_fail(buf_tag);

    buf_addr_begin = buf_info->buf_smmu_addr;
    buf_addr_end = buf_info->buf_smmu_addr + buf_info->buf_len;

    /* check if this buffer has been attached before,if exactly match,then update src/dst module handle list */
    /* 1.check handle */
    /* 2,check buffer addr range */
    list_for_each_entry(buf_info_node,
        &(target_instance->buffer_info_list_head[buf_tag - BUFFER_TAG_DMX_VID_ES_BUF].list), list) {
        if ((buf_info_node->buf_addr != buf_addr_begin) || (buf_info_node->buf_end_addr != buf_addr_end)) {
            continue;
        }

        return update_mod_info_in_list(buf_info_node, src_dst_flag, buf_info->module_handle);
    }

    /* buffer has not been attached before */
    buf_info_node = hi_tee_drv_hal_malloc(sizeof(hi_tee_drv_ssm_buffer_info_node));
    if (buf_info_node == HI_NULL) {
        hi_error_ssm("malloc node fail\n");
        return HI_FAILURE;
    }

    memset_s(buf_info_node, sizeof(hi_tee_drv_ssm_buffer_info_node), 0, sizeof(hi_tee_drv_ssm_buffer_info_node));

    buf_info_node->buf_addr = buf_addr_begin;
    buf_info_node->buf_end_addr = buf_addr_end;

    if (src_dst_flag & POLICY_MOD_SRC) {
        buf_info_node->src_mod_handle = buf_info->module_handle;
    }

    if (src_dst_flag & POLICY_MOD_DST) {
        buf_info_node->dst_mod_handle = buf_info->module_handle;
    }

    list_add(&buf_info_node->list, &(target_instance->buffer_info_list_head[buf_tag - BUFFER_TAG_DMX_VID_ES_BUF].list));

    return HI_SUCCESS;
}

hi_s32 tee_drv_ssm_create(hi_tee_ssm_intent intent, hi_handle *session_handle)
{
    hi_tee_drv_ssm_instance *created_instance = HI_NULL;
    hi_s32                   ret;
    hi_u8                    mbx_send_buf[SSM_CREATE_BUF_LEN] = {0};
    hi_u8                    mbx_rcv_buf[SSM_RETURN_BUF_LEN] = {0};
    hi_u32                   tx_len = SSM_CREATE_BUF_LEN;
    hi_u32                   rx_len = SSM_RETURN_BUF_LEN;
    hi_handle               *p = HI_NULL;

    ssm_check_pointer_return_if_fail(session_handle);
    ssm_check_intent_return_if_fail(intent);

    hi_tee_drv_hal_mutex_lock(&g_instance_lock);

    if (g_session_num > SSM_MAX_SESSION_NUM) {
        hi_tee_drv_hal_mutex_unlock(&g_instance_lock);
        hi_error_ssm("session num is full\n");
        return HI_ERR_SSM_FULL_SESSION_NUM;
    }

    created_instance = create_session(intent);
    if (created_instance == HI_NULL) {
        hi_tee_drv_hal_mutex_unlock(&g_instance_lock);
        hi_error_ssm("create session fail\n");
        return HI_ERR_SSM_CREATE_SESSOION_FAIL;
    }

    list_add(&(created_instance->list), &g_ssm_instance_head);

    (*session_handle) = created_instance->session_handle;
    g_session_num++;

    mbx_send_buf[0] = SSM_CREATE_MBX_CMD;

    p = (hi_handle *)&mbx_send_buf[1];
    *p = created_instance->session_handle;
    p = HI_NULL;

    ret = hi_tee_mbx_tx(g_mbx_handle, mbx_send_buf, SSM_CREATE_BUF_LEN, &tx_len, MBX_TIME_OUT);
    if (ret != HI_SUCCESS) {
        hi_tee_drv_hal_mutex_unlock(&g_instance_lock);
        hi_error_ssm("mbx send data fail:%x\n", ret);
        return ret;
    }

    ret = hi_tee_mbx_rx(g_mbx_handle, mbx_rcv_buf, SSM_RETURN_BUF_LEN, &rx_len, MBX_TIME_OUT);
    if (ret != HI_SUCCESS) {
        hi_tee_drv_hal_mutex_unlock(&g_instance_lock);
        hi_error_ssm("mbx rcv data fail:%x-%d\n", ret, __LINE__);
        return ret;
    }
    ret = *(hi_s32 *)mbx_rcv_buf;
    if (ret != HI_SUCCESS) {
        hi_error_ssm("sa create fail,ret:%x\n", ret);
    }
    hi_tee_drv_hal_mutex_unlock(&g_instance_lock);
    return ret;
}

hi_s32 tee_drv_ssm_destroy(const hi_handle session_handle)
{
    hi_s32 ret;
    hi_tee_drv_ssm_instance *target_session = HI_NULL;
    hi_u32 i = 0;
    hi_u8                    mbx_send_buf[SSM_DESTROY_BUF_LEN] = {0};
    hi_u8                    mbx_rcv_buf[SSM_RETURN_BUF_LEN] = {0};
    hi_u32                   tx_len = SSM_DESTROY_BUF_LEN;
    hi_u32                   rx_len = SSM_RETURN_BUF_LEN;
    hi_handle               *p = HI_NULL;

    ssm_check_session_handle_return_if_fail(session_handle);

    hi_tee_drv_hal_mutex_lock(&g_instance_lock);
    mbx_send_buf[0] = SSM_DESTROY_MBX_CMD;
    p = (hi_handle *)&mbx_send_buf[1];
    *p = session_handle;
    p = HI_NULL;

    ret = hi_tee_mbx_tx(g_mbx_handle, mbx_send_buf, SSM_DESTROY_BUF_LEN, &tx_len, MBX_TIME_OUT);
    if (ret != HI_SUCCESS) {
        hi_error_ssm("mbx send data fail:%x\n", ret);
        goto unlock_mutex;
    }

    ret = hi_tee_mbx_rx(g_mbx_handle, mbx_rcv_buf, SSM_RETURN_BUF_LEN, &rx_len, MBX_TIME_OUT);
    if (ret != HI_SUCCESS) {
        hi_error_ssm("mbx rcv data fail:%x-%d\n", ret, __LINE__);
        goto unlock_mutex;
    }

    ret = *(hi_s32 *)mbx_rcv_buf;
    if (ret != HI_SUCCESS) {
        hi_error_ssm("sa destroy fail,ret:%x\n", ret);
        goto unlock_mutex;
    }

    target_session = find_ssm_instance_by_session_id((session_handle & 0xff));
    if (target_session == HI_NULL) {
        hi_error_ssm("cannot find instance to destroy\n");
        ret = HI_ERR_SSM_INVALID_SESSOION_HANDLE;
        goto unlock_mutex;
    }

    ret = clean_up_resource_by_head(&target_session->cipher_head);
    if (ret != HI_SUCCESS) {
        hi_error_ssm("cleanup module list fail\n");
        goto unlock_mutex;
    }

    ret = clean_up_resource_by_head(&target_session->plcipher_head);
    if (ret != HI_SUCCESS) {
        hi_error_ssm("cleanup module list fail\n");
        goto unlock_mutex;
    }

    ret = clean_up_resource_by_head(&target_session->demux_head);
    if (ret != HI_SUCCESS) {
        hi_error_ssm("cleanup module list fail\n");
        goto unlock_mutex;
    }

    ret = clean_up_resource_by_head(&target_session->vdec_head);
    if (ret != HI_SUCCESS) {
        hi_error_ssm("cleanup module list fail\n");
        goto unlock_mutex;
    }

    for (i = 0; i < DRV_SSM_SESSION_BUF_TYPE_NUM; i++) {
        ret = clean_up_buffer_info_by_head(&target_session->buffer_info_list_head[i]);
        if (ret != HI_SUCCESS) {
            hi_error_ssm("cleanup secure info list fail\n");
            goto unlock_mutex;
        }
    }

    list_del(&(target_session->list));

    hi_tee_drv_hal_free(target_session);
    target_session = HI_NULL;
    g_session_num--;

    hi_tee_drv_hal_mutex_unlock(&g_instance_lock);

    return HI_SUCCESS;

unlock_mutex:
    hi_tee_drv_hal_mutex_unlock(&g_instance_lock);
    return ret;
}

hi_s32 notify_mbx_to_add_resource(const hi_handle session_handle, const hi_tee_ssm_module_info *resource_info)
{
    hi_u8                    mbx_send_buf[SSM_ADD_RESOURCE_BUF_LEN] = {0};
    hi_u8                    mbx_rcv_buf[SSM_RETURN_BUF_LEN] = {0};
    hi_u32                   tx_len = SSM_ADD_RESOURCE_BUF_LEN;
    hi_u32                   rx_len = SSM_RETURN_BUF_LEN;
    hi_handle               *p = HI_NULL;
    hi_s32                   ret;

    mbx_send_buf[0] = SSM_ADD_RESOURCE_MBX_CMD;

    p = (hi_handle *)&mbx_send_buf[1];
    *p = session_handle;

    p = (hi_handle *)&mbx_send_buf[5]; /* 5 is offset */
    *p = resource_info->module_handle;
    p = HI_NULL;

    ret = hi_tee_mbx_tx(g_mbx_handle, mbx_send_buf, SSM_ADD_RESOURCE_BUF_LEN, &tx_len, MBX_TIME_OUT);
    if (ret != HI_SUCCESS) {
        hi_error_ssm("mbx send data fail:%x\n", ret);
        return ret;
    }

    ret = hi_tee_mbx_rx(g_mbx_handle, mbx_rcv_buf, SSM_RETURN_BUF_LEN, &rx_len, MBX_TIME_OUT);
    if (ret != HI_SUCCESS) {
        hi_error_ssm("mbx rcv data fail:%x-%d\n", ret, __LINE__);
        return ret;
    }

    ret = *(hi_s32 *)mbx_rcv_buf;
    if (ret != HI_SUCCESS) {
        hi_error_ssm("sa add resource fail, mbx ret:%x\n", ret);
    }

    return ret;
}

hi_s32 tee_drv_ssm_add_resource (const hi_handle session_handle, const hi_tee_ssm_module_info *resource_info)
{
    hi_s32 ret = HI_FAILURE;
    hi_tee_drv_ssm_instance    *target_session = HI_NULL;
    hi_tee_drv_ssm_module_head *mod_entry = HI_NULL;

    ssm_check_session_handle_return_if_fail(session_handle);
    ssm_check_pointer_return_if_fail(resource_info);

    hi_tee_drv_hal_mutex_lock(&g_instance_lock);

    target_session = find_ssm_instance_by_session_id(session_handle & 0xff);
    if (target_session == HI_NULL) {
        hi_error_ssm("cannot find instance to destroy\n");
        ret = HI_ERR_SSM_INVALID_SESSOION_HANDLE;
        goto unlock_mutex;
    }

    /* check if resource has been added, success means find the resource in other session */
    ret = check_module_handle(resource_info->module_handle, session_handle, target_session);
    if (ret != HI_SUCCESS) {
        hi_error_ssm("Fail to check module handle \n");
        goto unlock_mutex;
    }

    ret = check_intent(target_session, (hi_tee_drv_ssm_module_node *)resource_info);
    if (ret != HI_SUCCESS) {
        hi_error_ssm("add operation disobey the rule\n");
        ret = HI_ERR_SSM_DISOBEY_RULES;
        goto unlock_mutex;
    }

    mod_entry = get_module_entry(target_session, (resource_info->module_handle >> SHIFT_FOR_MOD_ID));
    if (mod_entry == HI_NULL) {
        hi_error_ssm("cannot get module entry\n");
        ret = HI_ERR_SSM_CANT_FIND_ENTRY;
        goto unlock_mutex;
    }

    if ((resource_info->module_handle >> SHIFT_FOR_MOD_ID) == HI_ID_VDEC) {
        ret = notify_mbx_to_add_resource(session_handle, resource_info);
        if (ret != HI_SUCCESS) {
            hi_error_ssm("cannot notify mbx to add resouce : 0x%x\n", ret);
            goto unlock_mutex;
        }
    }
    ret = add_module_resource(mod_entry, resource_info);
    if (ret != HI_SUCCESS) {
        hi_error_ssm("add resource fail\n");
        goto unlock_mutex;
    }
    hi_tee_drv_hal_mutex_unlock(&g_instance_lock);

    return HI_SUCCESS;

unlock_mutex:
    hi_tee_drv_hal_mutex_unlock(&g_instance_lock);
    return ret;
}

static hi_s32 check_attach_buffer_params(hi_tee_ssm_buf_attach_pre_params buf_attach_pre_params, hi_u32 *tag_value)
{
    hi_s32                              ret = HI_FAILURE;
    hi_tee_drv_ssm_instance            *target_session = HI_NULL;
    hi_tee_drv_ssm_module_head         *mod_entry = HI_NULL;
    hi_tee_drv_ssm_module_node         *target_module = HI_NULL;
    hi_u32                              buf_tag = BUFFER_TAG_INVALID;
    hi_u32                              src_dst_flag = 0;

    ssm_check_pointer_return_if_fail(tag_value);

    /* (buf_attach_pre_params.buf_id == BUFFER_ID_VPSS_OUTPUT_BUF) is required in CS */
    if ((get_buf_type(buf_attach_pre_params.buf_id) == SSM_SESSION_BUF) ||
        ((buf_attach_pre_params.buf_id == BUFFER_ID_VID_FRM_BUF))) {
        ssm_check_session_handle_return_if_fail(buf_attach_pre_params.session_handle);
    }

    hi_tee_drv_hal_mutex_lock(&g_instance_lock);

    if (((buf_attach_pre_params.buf_id >= BUFFER_ID_DMX_VID_ES_BUF) &&
         (buf_attach_pre_params.buf_id <= BUFFER_ID_PVR_PLAYBACK_TS_BUF)) ||
        (buf_attach_pre_params.buf_id == BUFFER_ID_VID_FRM_BUF)) {
        target_session = find_ssm_instance_by_session_id(((buf_attach_pre_params.session_handle) & 0xff));
        if (target_session == HI_NULL) {
            hi_error_ssm("cannot find instance to attach\n");
            ret = HI_ERR_SSM_INVALID_SESSOION_HANDLE;
            goto unlock_mutex;
        }

        mod_entry = get_module_entry(target_session, (buf_attach_pre_params.module_handle >> SHIFT_FOR_MOD_ID));
        if (mod_entry == HI_NULL) {
            hi_error_ssm("cannot get module entry\n");
            ret = HI_ERR_SSM_CANT_FIND_ENTRY;
            goto unlock_mutex;
        }

        target_module = search_resource_by_handle(&(mod_entry->list), buf_attach_pre_params.module_handle);
        if (target_module == HI_NULL) {
            hi_error_ssm("target mod isnt in the list\n");
            ret = HI_ERR_SSM_CANT_FIND_MOD;
            goto unlock_mutex;
        }
    }

    ret = map_buffer_id_to_tag(buf_attach_pre_params.buf_id, &buf_tag);
    if (ret != HI_SUCCESS) {
        hi_error_ssm("Fail to map buffer id to buffer tag:%x\n", ret);
        goto unlock_mutex;
    }

    ret = check_policy_rules(buf_tag, buf_attach_pre_params.module_handle, target_session, &src_dst_flag);
    if (ret != HI_SUCCESS) {
        hi_error_ssm("disobey policy rules\n");
        goto unlock_mutex;
    }

    hi_tee_drv_hal_mutex_unlock(&g_instance_lock);

    *tag_value = buf_tag;

    return HI_SUCCESS;

unlock_mutex:
    hi_tee_drv_hal_mutex_unlock(&g_instance_lock);
    return ret;
}

hi_s32 process_frame_buf_attach(hi_bool set_tag, hi_u32 tag_value, hi_u32 *ssm_tag,
                                hi_tee_ssm_secure_info *sec_info_addr)
{
    hi_u32 index = 0;
    hi_s32 ret;
    hi_u32 ssm_tag_tmp = 0;
    ssm_check_pointer_return_if_fail(ssm_tag);

    if (set_tag == HI_TRUE) {
        ret = get_free_secure_info(&sec_info_addr, &index);
        if (ret != HI_SUCCESS) {
            hi_error_ssm("cannot get secure info:%x\n", ret);
            return ret;
        }

        ssm_tag_tmp |= index << 16; /* left shift index 16 bit to set it to [31:16] */
        ssm_tag_tmp = ssm_tag_tmp | (tag_value & MASK_FOR_LOW_8_BITS);
        *ssm_tag = ssm_tag_tmp;
    } else { /* in buf check func, sec info has been alloc, need to get secinfo addr */
        ret = get_secure_info_addr_by_index((tag_value >> 16), &sec_info_addr); /* right shift 16 to get index */
        if (ret != HI_SUCCESS) {
            hi_error_ssm("cannot get secure info addr:%x\n", ret);
            return ret;
        }
    }

    return HI_SUCCESS;
}

hi_s32 process_session_buf_attach(const hi_tee_drv_ssm_buf_attach_info *attach_info,
                                  hi_u32 tag_value, hi_bool *tag_is_set)
{
    hi_s32 ret;
    hi_tee_drv_ssm_instance  *target_session = HI_NULL;
    hi_u32   src_dst_flag = 0;
    ssm_check_pointer_return_if_fail(tag_is_set);
    ssm_check_pointer_return_if_fail(attach_info);

    target_session = find_ssm_instance_by_session_id(((attach_info->session_handle) & 0xff));
    if (target_session == HI_NULL) {
        hi_error_ssm("cannot find instance to attach\n");
        return HI_ERR_SSM_INVALID_SESSOION_HANDLE;
    }

    ret = check_policy_rules(tag_value, attach_info->module_handle, target_session, &src_dst_flag);
    if (ret != HI_SUCCESS) {
        hi_error_ssm("disobey policy rules\n");
        return ret;
    }

    ret = add_buffer_into_session(target_session, attach_info, src_dst_flag);
    if (ret != HI_SUCCESS) {
        if (ret == HI_ERR_SSM_NO_NEED_SET_TAG_AGAIN) {
            *tag_is_set = HI_TRUE;
        } else {
            hi_error_ssm("add_buffer_into_session fail\n");
            return ret;
        }
    }

    return HI_SUCCESS;
}

hi_s32 notify_mbx_to_attach_buf(const hi_tee_drv_ssm_buf_attach_info *buffer_attach_infor)
{
    hi_u8      mbx_send_buf[SSM_ATTACH_BUF_BUF_LEN] = {0};
    hi_u8      mbx_rcv_buf[SSM_RETURN_BUF_LEN] = {0};
    hi_u32     tx_len = SSM_ATTACH_BUF_BUF_LEN;
    hi_u32     rx_len = SSM_RETURN_BUF_LEN;
    hi_handle *p = HI_NULL;
    hi_u64    *p2 = HI_NULL;
    hi_s32     ret;

    mbx_send_buf[0] = SSM_ATTACH_BUF_MBX_CMD;

    p = (hi_handle *)&mbx_send_buf[1]; /* fill session handle in bit 1-4 */
    *p = buffer_attach_infor->session_handle;
    p = HI_NULL;

    p2 = (hi_u64 *)&mbx_send_buf[5]; /* fill buf addr in bit 5-12 */
    *p2 = buffer_attach_infor->buf_smmu_addr;
    p2 = HI_NULL;

    p = (hi_handle *)&mbx_send_buf[13]; /* fill buf len in bit 13-16 */
    *p = buffer_attach_infor->buf_len;

    ret = hi_tee_mbx_tx(g_mbx_handle, mbx_send_buf, SSM_ADD_RESOURCE_BUF_LEN, &tx_len, MBX_TIME_OUT);
    if (ret != HI_SUCCESS) {
        hi_error_ssm("mbx send data fail:%x\n", ret);
        return ret;
    }

    ret = hi_tee_mbx_rx(g_mbx_handle, mbx_rcv_buf, SSM_RETURN_BUF_LEN, &rx_len, MBX_TIME_OUT);
    if (ret != HI_SUCCESS) {
        hi_error_ssm("mbx rcv data fail:%x-%d\n", ret, __LINE__);
        return ret;
    }

    ret = *(hi_s32 *)mbx_rcv_buf;
    if (ret != HI_SUCCESS) {
        hi_error_ssm("sa add resource fail,ret:%x\n", ret);
        return ret;
    }

    return HI_SUCCESS;
}

static hi_s32 do_attach_buffer(const hi_tee_drv_ssm_buf_attach_info *buffer_attach_infor, hi_u64 *secure_info_addr,
                               hi_bool set_tag, hi_u32 tag_value)
{
    hi_s32   ret = HI_FAILURE;
    hi_u32   ssm_tag = 0;
    hi_bool  tag_is_set = HI_FALSE;
    hi_tee_ssm_secure_info *sec_info_addr = HI_NULL;

    hi_tee_drv_hal_mutex_lock(&g_instance_lock);

    if (get_buf_type(buffer_attach_infor->buf_id) == SSM_INTERNAL_BUF) {
        ssm_tag = tag_value;
        ret = HI_SUCCESS;
    } else if (get_buf_type(buffer_attach_infor->buf_id) == SSM_SESSION_BUF) {
        ret = process_session_buf_attach(buffer_attach_infor, tag_value, &tag_is_set);
        if (ret != HI_SUCCESS) {
            hi_error_ssm("add_buffer_into_session fail\n");
            goto UNLOCK_MUTEX;
        }

        if ((tag_value >= BUFFER_TAG_DMX_VID_ES_BUF && tag_value <= BUFFER_TAG_MCIPHER_AUD_ES_BUF) &&
            (tag_is_set == HI_FALSE)) {
            ret = notify_mbx_to_attach_buf(buffer_attach_infor);
            if (ret != HI_SUCCESS) {
                goto UNLOCK_MUTEX;
            }
        }

        /* ssm_tag arrangement: |sec_info index (31-16)|session id (15-8)|buf tag (7-0)| */
        ssm_tag = (buffer_attach_infor->session_handle & MASK_FOR_LOW_8_BITS) << 8; /* left shift 8bit to set sid */
        ssm_tag = ssm_tag | (tag_value & MASK_FOR_LOW_8_BITS);
    } else if (get_buf_type(buffer_attach_infor->buf_id) == SSM_FRAME_BUF) { /* attach smmu tag */
        ret = process_frame_buf_attach(set_tag, tag_value, &ssm_tag, sec_info_addr);
        if (ret != HI_SUCCESS) {
            hi_error_ssm("attach frame buf, get sec info fail set_tag set_tag: %d,tag_val:0x%x\n", set_tag, tag_value);
            goto UNLOCK_MUTEX;
        }
    } else {
        ret = HI_ERR_SSM_INVALID_BUFFER_TYPE;
        goto UNLOCK_MUTEX;
    }

    /* when true,need set tag */
    if ((set_tag == HI_TRUE) && (tag_is_set == HI_FALSE)) {
        hi_tee_smmu_buf smmu_buf = {0};

        smmu_buf.smmu_addr = buffer_attach_infor->buf_smmu_addr;
        smmu_buf.size = buffer_attach_infor->buf_len;

        /* ssm_tag arrangement: |sec_info index (31-16)|session id (15-8)|buf tag (7-0)| */
        ret = hi_tee_drv_smmu_set_tag(&smmu_buf, ssm_tag);
        if (ret != HI_SUCCESS) {
            goto UNLOCK_MUTEX;
        }
    }

    (*secure_info_addr) = (uintptr_t)sec_info_addr;
UNLOCK_MUTEX:
    hi_tee_drv_hal_mutex_unlock(&g_instance_lock);
    return ret;
}

hi_s32 tee_drv_ssm_set_iommu_tag(hi_tee_logic_mod_id module_id)
{
    hi_s32 ret;

    ret = iommu_sec_config(module_id);
    if (ret != HI_SUCCESS) {
        hi_error_ssm("set iommu tag fail-%d\n", __LINE__);
        return HI_FAILURE;
    }

    return HI_SUCCESS;
}

hi_void rcv_mbx_callback()
{
    hi_s32 ret;
    hi_u8 test_rx[SSM_RETURN_BUF_LEN] = {0};
    hi_u32 len = 0;

    ret = hi_tee_mbx_rx(g_mbx_rcv_handle, test_rx, SSM_RETURN_BUF_LEN, &len, MBX_TIME_OUT);
    if (ret < 0) {
        hi_error_ssm("rcv_mbx_callback in callback %d failed\n", ret);
        return;
    }

    if (len <= 0) {
        hi_error_ssm("Rx0 nothing!!\n");
        return;
    }

    if (test_rx[0] == SSM_INIT_VMCU_CMD) {
        (hi_void)tee_drv_ssm_set_iommu_tag(LOGIC_MOD_ID_VMCU);
    } else if (test_rx[0] == SSM_INIT_VDH_CMD) {
        (hi_void)tee_drv_ssm_set_iommu_tag(LOGIC_MOD_ID_VDH);
    } else if (test_rx[0] == SSM_GET_PGT_ADDR_CMD) {
        pthread_mutex_lock(&g_thread_mutex);
        g_ssm_need_proc = HI_TRUE;
        g_ssm_need_send_pgt = HI_TRUE;
        pthread_cond_signal(&g_thread_cond);
        pthread_mutex_unlock(&g_thread_mutex);
    } else if (test_rx[0] == SSM_INIT_SEC_INFO_MBX_CMD) {
        pthread_mutex_lock(&g_thread_mutex);
        g_ssm_need_proc = HI_TRUE;
        g_ssm_need_send_sec_info = HI_TRUE;
        pthread_cond_signal(&g_thread_cond);
        pthread_mutex_unlock(&g_thread_mutex);
    } else {
        hi_error_ssm("invalid cmd-%s-%d\n", __func__, __LINE__);
    }
    return;
}

hi_s32 thread_func()
{
    hi_u8     mbx_send_buf[SSM_PGT_ADDR_BUF_CMD_LEN] = {0};
    hi_u32    tx_len = SSM_PGT_ADDR_BUF_CMD_LEN;
    hi_s32    ret;

    while (g_thread_run_flag == HI_TRUE) {
        pthread_mutex_lock(&g_thread_mutex);
        while (g_ssm_need_proc == HI_FALSE) {
            pthread_cond_wait(&g_thread_cond, &g_thread_mutex);
        }

        if (g_ssm_need_send_pgt == HI_TRUE) {
            hi_u64 pgt_addr = 0;
            hi_u64 *p = HI_NULL;

            iommu_get_pgt_addr(&pgt_addr);
            if (pgt_addr == 0) {
                hi_error_ssm("get invalid pgt_addr:0 !\n");
                g_ssm_need_send_pgt = HI_FALSE;
                g_ssm_need_proc = HI_FALSE;
                pthread_mutex_unlock(&g_thread_mutex);
                continue;
            }

            mbx_send_buf[0] = SSM_GET_PGT_ADDR_CMD;
            p = (hi_u64 *)&mbx_send_buf[1];
            *p = pgt_addr;
            ret = hi_tee_mbx_tx(g_mbx_rcv_handle, mbx_send_buf, SSM_PGT_ADDR_BUF_CMD_LEN, &tx_len, MBX_TIME_OUT);
            if (ret != HI_SUCCESS) {
                hi_error_ssm("mbx tx fail:%s-%d : %x\n", __func__, __LINE__, ret);
            }

            g_ssm_need_send_pgt = HI_FALSE;
            g_ssm_need_proc = HI_FALSE;
        }

        if (g_ssm_need_send_sec_info == HI_TRUE) {
            ret = notify_mbx_to_update_sec_info(sizeof(hi_tee_ssm_secure_info),
                g_sec_info_manager.secure_info_mem_header.smmu_addr, g_sec_info_manager.secure_info_mem_header.size);
            if (ret != HI_SUCCESS) {
                hi_error_ssm("fail to update sec info to vmcu! ret : 0x%x\n", ret);
            }

            g_ssm_need_send_sec_info = HI_FALSE;
            g_ssm_need_proc = HI_FALSE;
        }

        pthread_mutex_unlock(&g_thread_mutex);
    }

    return 0;
}

hi_s32 ssm_misc_init(hi_void)
{
    hi_s32 ret;
    pthread_attr_t    ssm_thread_attr = {0};

    pthread_attr_init(&ssm_thread_attr);
    pthread_attr_settee(&ssm_thread_attr, TEESMP_THREAD_ATTR_CA_INHERIT,
        TEESMP_THREAD_ATTR_TASK_ID_INHERIT, TEESMP_THREAD_ATTR_HAS_SHADOW);
    pthread_mutex_init(&g_thread_mutex, HI_NULL);
    pthread_cond_init(&g_thread_cond, HI_NULL);

    if (0 != pthread_create(&g_thread, &ssm_thread_attr, (hi_void *)thread_func, HI_NULL)) {
        hi_error_ssm("create ssm thread fail! :%x\n", errno);
        return HI_FAILURE;
    }

    ret = hi_tee_drv_hal_mutex_init("ssm_sec_info", &g_sec_info_lock);
    if (ret != HI_SUCCESS) {
        hi_error_ssm("ssm init ssm_sec_info lock fail:%x\n", ret);
        return ret;
    }

    ret = hi_tee_drv_hal_mutex_init("ssm_instance", &g_instance_lock);
    if (ret != HI_SUCCESS) {
        hi_error_ssm("ssm init ssm_instance lock fail:%x\n", ret);
        return ret;
    }

    return HI_SUCCESS;
}

hi_s32 tee_drv_ssm_init(hi_void)
{
    hi_u32 ret;

    if (g_sec_info_inited == HI_TRUE) {
        return HI_SUCCESS;
    }

    ret = ssm_misc_init();
    if (ret != HI_SUCCESS) {
        hi_error_ssm("ssm call ssm_misc_init fail:%x\n", ret);
        return ret;
    }

    iommu_tag_init();

    g_mbx_handle = hi_tee_mbx_open(HI_MBX_TCPU2VMCU0_SSM);
    if (g_mbx_handle < 0) {
        hi_error_ssm("ssm hi_tee_mbx_open fail:%x-%d\n", ret, __LINE__);
        ret = g_mbx_handle;
        goto instance_mutex_destroy;
    }

    g_mbx_rcv_handle = hi_tee_mbx_open(HI_MBX_TCPU2VMCU0_SSM_2);
    if (g_mbx_rcv_handle < 0) {
        hi_error_ssm("ssm hi_tee_mbx_open fail:%x-%d\n", ret, __LINE__);
        ret = g_mbx_rcv_handle;
        goto close_mbx1;
    }

    ret = hi_tee_mbx_register_irq_callback(g_mbx_rcv_handle, rcv_mbx_callback, HI_NULL);
    if (ret != HI_SUCCESS) {
        hi_error_ssm("register mbx callback fail:%x-%d\n", ret, __LINE__);
        goto close_mbx2;
    }

    ret = allocate_secure_info_pool();
    if (ret != HI_SUCCESS) {
        hi_error_ssm("ssm init secure_info_pool fail:%x\n", ret);
        goto close_mbx2;
    }

    g_sec_info_inited = HI_TRUE;
    return HI_SUCCESS;

close_mbx2:
    (hi_void)hi_tee_mbx_close(HI_MBX_TCPU2VMCU0_SSM_2);

close_mbx1:
    (hi_void)hi_tee_mbx_close(HI_MBX_TCPU2VMCU0_SSM);

instance_mutex_destroy:
    hi_tee_drv_hal_mutex_destroy(&g_instance_lock);
    hi_tee_drv_hal_mutex_destroy(&g_sec_info_lock);
    return ret;
}

hi_s32 tee_drv_ssm_check_uuid(const hi_handle ssm_handle)
{
    hi_s32 ret;
    TEE_UUID cur_uuid = {0};
    hi_tee_drv_ssm_instance *ssm_instance = HI_NULL;

    ssm_check_session_handle_return_if_fail(ssm_handle);

    hi_tee_drv_hal_mutex_lock(&g_instance_lock);

    ssm_instance = find_ssm_instance_by_session_id(ssm_handle & 0xff);
    if (ssm_instance == HI_NULL) {
        hi_error_ssm("cannot find instance to check uuid\n");
        ret = HI_ERR_SSM_INVALID_SESSOION_HANDLE;
        goto err_unlock;
    }

    ret = memcmp(&ssm_instance->uuid, &cur_uuid, sizeof(TEE_UUID));
    if (ret == 0) {
        hi_error_ssm("uuid of this session has not been set\n");
        goto err_unlock;
    }

    ret = hi_tee_drv_hal_current_uuid(&cur_uuid);
    if (ret != HI_SUCCESS) {
        hi_error_ssm("get cur uuid fail:%x\n", ret);
        goto err_unlock;
    }

    ret = memcmp(&ssm_instance->uuid, &cur_uuid, sizeof(TEE_UUID));
    if (ret == 0) {
        hi_tee_drv_hal_mutex_unlock(&g_instance_lock);
        return HI_SUCCESS;
    } else {
        hi_error_ssm("uuid not match\n");
        ret = HI_ERR_SSM_UUID_NOT_MATCH;
        goto err_unlock;
    }

err_unlock:
    hi_tee_drv_hal_mutex_unlock(&g_instance_lock);
    return ret;
}

hi_s32 tee_drv_ssm_set_uuid(const hi_handle ssm_handle)
{
    hi_s32 ret;
    TEE_UUID cur_uuid = {0};
    hi_tee_drv_ssm_instance *ssm_instance = HI_NULL;

    ssm_check_session_handle_return_if_fail(ssm_handle);

    hi_tee_drv_hal_mutex_lock(&g_instance_lock);

    ssm_instance = find_ssm_instance_by_session_id(ssm_handle & 0xff);
    if (ssm_instance == HI_NULL) {
        hi_error_ssm("cannot find instance to set uuid\n");
        ret = HI_ERR_SSM_INVALID_SESSOION_HANDLE;
        goto err_unlock;
    }

    ret = memcmp(&ssm_instance->uuid, &cur_uuid, sizeof(TEE_UUID));
    if (ret != 0) {
        ret = hi_tee_drv_hal_current_uuid(&cur_uuid);
        if (ret != HI_SUCCESS) {
            hi_error_ssm("get cur uuid fail:%x\n", ret);
            goto err_unlock;
        }

        ret = memcmp(&ssm_instance->uuid, &cur_uuid, sizeof(TEE_UUID));
        if (ret == 0) {
            hi_tee_drv_hal_mutex_unlock(&g_instance_lock);
            return HI_SUCCESS;
        } else {
            hi_error_ssm("this instance's uuid has been set--%d\n", __LINE__);
            ret = HI_ERR_SSM_UUID_SET_BEFORE;
            goto err_unlock;
        }
    }

    ret = hi_tee_drv_hal_current_uuid(&cur_uuid);
    if (ret != HI_SUCCESS) {
        hi_error_ssm("get cur uuid fail:%x\n", ret);
        goto err_unlock;
    }

    ret = memcpy_s(&ssm_instance->uuid, sizeof(ssm_instance->uuid), &cur_uuid, sizeof(TEE_UUID));
    if (ret != HI_SUCCESS) {
        hi_error_ssm("set cur uuid fail fail:%x\n", ret);
        hi_tee_drv_hal_mutex_unlock(&g_instance_lock);
        return ret;
    }

    hi_tee_drv_hal_mutex_unlock(&g_instance_lock);
    return HI_SUCCESS;

err_unlock:
    hi_tee_drv_hal_mutex_unlock(&g_instance_lock);
    return ret;
}

hi_s32 tee_drv_ssm_attach_buffer(const hi_tee_drv_ssm_buf_attach_info *buffer_attach_infor, hi_u64 *secure_info_addr)
{
    hi_s32                              ret;
    hi_tee_ssm_buf_attach_pre_params    buf_attach_pre_params = {0};
    hi_u32                              tag_value = 0;

    ssm_check_pointer_return_if_fail(secure_info_addr);
    ssm_check_pointer_return_if_fail(buffer_attach_infor);

    buf_attach_pre_params.session_handle = buffer_attach_infor->session_handle;
    buf_attach_pre_params.module_handle = buffer_attach_infor->module_handle;
    buf_attach_pre_params.buf_id = buffer_attach_infor->buf_id;

    ret = check_attach_buffer_params(buf_attach_pre_params, &tag_value);
    if (ret != HI_SUCCESS) {
        hi_error_ssm("fail to check attach buffer params\n");
        return HI_FAILURE;
    }

    ret = do_attach_buffer(buffer_attach_infor, secure_info_addr, HI_TRUE, tag_value);
    if (ret != HI_SUCCESS) {
        hi_error_ssm("fail to do attach buffer \n");
        return HI_FAILURE;
    }

    return HI_SUCCESS;
}

hi_s32 tee_drv_ssm_check_attach_params_by_mem(unsigned long long priv_data, hi_u32 priv_len, hi_u32 *tag_value)
{
    hi_s32  ret;
    hi_u32  tmp_value;
    hi_tee_ssm_buf_attach_pre_params  buf_attach_pre_params = {0};
    hi_tee_ssm_buf_attach_pre_params *virt_addr = HI_NULL;
    hi_tee_ssm_secure_info *sec_info_addr = HI_NULL;
    hi_u32                  sec_index = 0;

    ssm_check_pointer_return_if_fail(tag_value);

    if (priv_data == HI_NULL || priv_len != sizeof(hi_tee_ssm_buf_attach_pre_params)) {
        hi_error_ssm("invalid parameters\n");
        return HI_FAILURE;
    }

    virt_addr = hi_tee_drv_hal_remap((unsigned long long)priv_data, priv_len, 0, HI_TRUE);
    if (virt_addr == HI_NULL) {
        hi_error_ssm("remap addr fail\n");
        return HI_FAILURE;
    }

    ret = memcpy_s(&buf_attach_pre_params, sizeof(buf_attach_pre_params), virt_addr, priv_len);
    if (ret != HI_SUCCESS) {
        hi_error_ssm("memcpy fail\n");
        return ret;
    }

    ret = check_attach_buffer_params(buf_attach_pre_params, &tmp_value);
    if (ret != HI_SUCCESS) {
        hi_error_ssm("fail to check attach buffer params\n");
        return HI_FAILURE;
    }

    if ((buf_attach_pre_params.buf_id >= BUFFER_ID_VID_FRM_BUF) && (buf_attach_pre_params.buf_id < BUFFER_ID_MAX)) {
        ret = get_free_secure_info(&sec_info_addr, &sec_index);
        if (ret != HI_SUCCESS) {
            hi_error_ssm("fail to get sec info\n");
            return ret;
        }

        tmp_value = tmp_value | ((sec_index & MASK_FOR_LOW_16_BITS) << 16); /* left shift 16 bit to set it to[31:16] */
    }

    *tag_value = tmp_value;

    return HI_SUCCESS;
}

hi_s32 tee_drv_ssm_attach_buffer_error_handle(hi_u32 tag_val)
{
    hi_u32 sec_info_index;
    hi_u32 buf_tag;

    sec_info_index = tag_val >> SHIFT_FOR_SEC_INFO_INDEX;
    buf_tag = tag_val & 0xFF;

    if ((buf_tag >= BUFFER_TAG_VID_FRM_BUF) && (buf_tag <= BUFFER_TAG_NPU_OUTPUT_BUF)) {
        hi_tee_drv_hal_mutex_lock(&g_sec_info_lock);

        if (g_sec_info_manager.status[sec_info_index].used == HI_TRUE) {
            g_sec_info_manager.status[sec_info_index].used = HI_FALSE;
            g_sec_info_manager.numbers_used--;
        }

        hi_tee_drv_hal_mutex_unlock(&g_sec_info_lock);
    }
    return HI_SUCCESS;
}

/* priv_data and len are phy addr, buf_addr_begin/end are smmu addr */
hi_s32 tee_drv_ssm_attach_buffer_by_mem(unsigned long long priv_data, hi_u32 priv_len, hi_u64 buf_addr_begin,
                                        hi_u64 buf_addr_end, hi_u32 tag_val)
{
    hi_s32  ret;
    hi_tee_ssm_buf_attach_pre_params      buf_attach_pre_params = {0};
    hi_tee_drv_ssm_buf_attach_info        buffer_attach_infor = {0};
    hi_u64 secure_info_addr = 0x0ul;
    hi_tee_ssm_buf_attach_pre_params     *virt_addr = HI_NULL;

    if (priv_data == HI_NULL || priv_len != sizeof(hi_tee_ssm_buf_attach_pre_params)) {
        hi_error_ssm("invalid parameters\n");
        return HI_FAILURE;
    }

    virt_addr = hi_tee_drv_hal_remap((unsigned long long)priv_data, priv_len, 0, HI_TRUE);
    if (virt_addr == HI_NULL) {
        hi_error_ssm("remap addr fail\n");
        return HI_FAILURE;
    }

    ret = memcpy_s(&buf_attach_pre_params, sizeof(hi_tee_ssm_buf_attach_pre_params), virt_addr, priv_len);
    if (ret != HI_SUCCESS) {
        hi_error_ssm("memcpy fail\n");
        return ret;
    }

    if (((buf_attach_pre_params.buf_id >= BUFFER_ID_DMX_VID_ES_BUF) &&
         (buf_attach_pre_params.buf_id <= BUFFER_ID_PVR_PLAYBACK_TS_BUF)) ||
        (buf_attach_pre_params.buf_id == BUFFER_ID_VID_FRM_BUF) ||
        (buf_attach_pre_params.buf_id == BUFFER_ID_VPSS_OUTPUT_BUF)) {
        ssm_check_session_handle_return_if_fail(buf_attach_pre_params.session_handle);
    }
    buffer_attach_infor.session_handle = buf_attach_pre_params.session_handle;
    buffer_attach_infor.module_handle = buf_attach_pre_params.module_handle;
    buffer_attach_infor.buf_id = buf_attach_pre_params.buf_id;
    buffer_attach_infor.buf_smmu_addr = buf_addr_begin;
    buffer_attach_infor.buf_len = buf_addr_end - buf_addr_begin;

    ret = do_attach_buffer(&buffer_attach_infor, &secure_info_addr, HI_FALSE, tag_val);
    if (ret != HI_SUCCESS) {
        hi_error_ssm("fail to do attach buffer \n");
        return HI_FAILURE;
    }

    if ((buf_attach_pre_params.buf_id >= BUFFER_ID_VID_FRM_BUF) &&
         (buf_attach_pre_params.buf_id <= BUFFER_ID_NPU_OUTPUT_BUF)) {
        buf_attach_pre_params.si_addr = secure_info_addr;
    }

    return HI_SUCCESS;
}

hi_s32 notify_mbx_to_detach_buf(hi_u32 session_id, hi_u32 buf_len, hi_u64 buffer_addr_begin)
{
    hi_s32    ret;
    hi_u8     mbx_send_buf[SSM_DETACH_BUF_BUF_LEN] = {0};
    hi_u32    tx_len = SSM_DETACH_BUF_BUF_LEN;
    hi_handle session_handle = make_sm_handle(session_id);

    mbx_send_buf[0] = SSM_DETACH_BUF_MBX_CMD;
    ret = memcpy_s((hi_void *)mbx_send_buf + sizeof(hi_u8), SSM_DETACH_BUF_BUF_LEN - 1,
        &session_handle, sizeof(hi_handle));
    if (ret != HI_SUCCESS) {
        hi_error_ssm("init mbx send buf fail\n");
        return ret;
    }
    ret = memcpy_s((hi_void *)mbx_send_buf + sizeof(hi_u8) + sizeof(hi_handle),
        SSM_DETACH_BUF_BUF_LEN - 5, &buffer_addr_begin, sizeof(hi_u64)); /* offset 5, fill buf addr */
    if (ret != HI_SUCCESS) {
        hi_error_ssm("init mbx send buf fail\n");
        return ret;
    }
    ret = memcpy_s((hi_void *)mbx_send_buf + sizeof(hi_u8) + sizeof(hi_handle) + sizeof(hi_u64),
        SSM_DETACH_BUF_BUF_LEN - 13, &buf_len, sizeof(hi_u32)); /* offset 13, fill buf len */
    if (ret != HI_SUCCESS) {
        hi_error_ssm("init mbx send buf fail\n");
        return ret;
    }
    ret = hi_tee_mbx_tx(g_mbx_handle, mbx_send_buf, SSM_DETACH_BUF_BUF_LEN, &tx_len, MBX_TIME_OUT);
    if (ret != HI_SUCCESS) {
        hi_error_ssm("mbx send data fail:%x\n", ret);
    }

    return ret;
}


hi_s32 tee_drv_ssm_detach_buffer_by_mem(hi_u32 ssm_tag, hi_u64 buffer_addr_begin, hi_u64 buf_addr_end)
{
    hi_tee_drv_ssm_instance         *ssm_instance = HI_NULL;
    hi_u32                           session_id = (ssm_tag >> SHIFT_FOR_SESSION_ID) & 0xFF;
    hi_s32                           ret = HI_FAILURE;
    hi_u32                           i = 0;
    hi_tee_drv_ssm_buffer_info_node *buffer_info_node = HI_NULL;
    hi_u32                           buf_tag = ssm_tag & 0xFF;

    if ((buf_tag >= BUFFER_TAG_DMX_VID_ES_BUF) && (buf_tag <= BUFFER_TAG_PVR_PLAYBACK_TS_BUF)) {
        hi_tee_drv_hal_mutex_lock(&g_instance_lock);

        ssm_instance = find_ssm_instance_by_session_id(session_id);
        if (ssm_instance == HI_NULL) {
            hi_tee_drv_hal_mutex_unlock(&g_instance_lock);
            /* although cannot find a correspond instance to coincide still can succes for free buffer */
            return HI_SUCCESS;
        }

        for (i = 0; i < DRV_SSM_SESSION_BUF_TYPE_NUM; i++) {
            /* go through all the buffer info list to find the buffer to detach,
                 if module handle match any of the stored module handle ,then free the node
                */
            list_for_each_entry(buffer_info_node, &(ssm_instance->buffer_info_list_head[i].list), list) {
                if ((buffer_addr_begin != buffer_info_node->buf_addr) ||
                    (buf_addr_end != buffer_info_node->buf_end_addr)) {
                    continue;
                }

                ret = notify_mbx_to_detach_buf(session_id, buf_addr_end - buffer_addr_begin, buffer_addr_begin);
                if (ret != HI_SUCCESS) {
                    hi_error_ssm("call notify_mbx_to_detach_buf fail : 0x%x\n", ret);
                    goto unlock_mutex;
                }

                list_del(&(buffer_info_node->list));
                hi_tee_drv_hal_free(buffer_info_node);
                buffer_info_node = HI_NULL;

                hi_tee_drv_hal_mutex_unlock(&g_instance_lock);
                return ret;
            }
        }
        hi_tee_drv_hal_mutex_unlock(&g_instance_lock);

        return HI_SUCCESS;
    } else if ((buf_tag >= BUFFER_TAG_VID_FRM_BUF) && (buf_tag <= BUFFER_TAG_MAX)) {
        /* frame buffer */
        hi_u32 sec_info_index = (ssm_tag & 0xFFFF0000) >> SHIFT_FOR_SEC_INFO_INDEX; /* 0xFFFF0000 to get high 16bit */

        ret = release_secure_info(sec_info_index);
        if (ret != HI_SUCCESS) {
            hi_error_ssm("recycle sec info fail:%x\n", ret);
        }

        return ret;
    } else {
        /* internal buffer and invalid buffer */
        return HI_SUCCESS;
    }
unlock_mutex:
    hi_tee_drv_hal_mutex_unlock(&g_instance_lock);
    return ret;
}

hi_s32 do_check_buf(hi_tee_drv_ssm_instance *ssm_instance, hi_u32 buf_tag,
                    hi_tee_drv_ssm_buf_check_info *buffer_check_info, hi_u32 src_dst_flag)
{
    hi_tee_drv_ssm_buffer_info_node *buffer_info_node = HI_NULL;
    hi_u32                           actual_buf_size;
    hi_u32                           flag = 0;

    list_for_each_entry(buffer_info_node,
        &(ssm_instance->buffer_info_list_head[buf_tag - BUFFER_TAG_DMX_VID_ES_BUF].list), list) {
        if ((buffer_check_info->buf_addr < buffer_info_node->buf_addr) ||
            (buffer_check_info->buf_addr > buffer_info_node->buf_end_addr)) {
            continue;
        }

        actual_buf_size = buffer_info_node->buf_end_addr - buffer_check_info->buf_addr;
        if (buffer_check_info->buf_size <= actual_buf_size) {
            if ((src_dst_flag & POLICY_MOD_DST) != 0) {
                if (buffer_check_info->module_handle == buffer_info_node->dst_mod_handle) {
                        flag = flag | POLICY_MOD_DST;
                }
            }

            if ((src_dst_flag & POLICY_MOD_SRC) != 0) {
                if (buffer_check_info->module_handle == buffer_info_node->src_mod_handle) {
                        flag = flag | POLICY_MOD_SRC;
                }
            }

            if (src_dst_flag == flag) {
                return HI_SUCCESS;
            }
        }
    }

    return HI_ERR_SSM_BUFFER_CHECK_NOT_MATCH;
}

hi_s32 tee_drv_ssm_check_buffer(hi_tee_drv_ssm_buf_check_info *buffer_check_info)
{
    hi_tee_drv_ssm_instance         *ssm_instance = HI_NULL;
    hi_u32                           buf_tag = BUFFER_TAG_INVALID;
    hi_u32                           src_dst_flag = 0;
    hi_s32                           ret;

    ssm_check_pointer_return_if_fail(buffer_check_info);
    ssm_check_session_handle_return_if_fail(buffer_check_info->session_handle);

    if (get_buf_type(buffer_check_info->buf_id) != SSM_SESSION_BUF) {
        hi_error_ssm("only check session buffer\n");
        return HI_ERR_SSM_NOT_SESSION_BELONGED_BUF;
    }

    hi_tee_drv_hal_mutex_lock(&g_instance_lock);

    ssm_instance = find_ssm_instance_by_session_id(buffer_check_info->session_handle & 0xff);
    if (ssm_instance == HI_NULL) {
        hi_tee_drv_hal_mutex_unlock(&g_instance_lock);
        hi_error_ssm("cannot find instance,instance :%x\n", buffer_check_info->session_handle & 0xff);
        return HI_EER_SSM_INVALID_SESSOION_HANDLE;
    }

    ret = map_buffer_id_to_tag(buffer_check_info->buf_id, &buf_tag);
    if (ret != HI_SUCCESS) {
        hi_tee_drv_hal_mutex_unlock(&g_instance_lock);
        hi_error_ssm("cannot get tag by id:%x\n", ret);
        return ret;
    }

    ret = check_policy_rules(buf_tag, buffer_check_info->module_handle, ssm_instance, &src_dst_flag);
    if (ret != HI_SUCCESS) {
        hi_tee_drv_hal_mutex_unlock(&g_instance_lock);
        hi_error_ssm("cannot find correspond tag for id\n");
        return ret;
    }

    /* first check if buffer addr is in the range,then check if mod handle is in the handle list */
    ret = do_check_buf(ssm_instance, buf_tag, buffer_check_info, src_dst_flag);
    if (ret != HI_SUCCESS) {
        hi_tee_drv_hal_mutex_unlock(&g_instance_lock);
        hi_error_ssm("check session buf fail: 0x%x\n", ret);
        return ret;
    }

    hi_tee_drv_hal_mutex_unlock(&g_instance_lock);
    return ret;
}

hi_s32 tee_drv_ssm_get_intent(hi_handle session_handle, hi_tee_ssm_intent *intent)
{
    hi_tee_drv_ssm_instance *get_instance = HI_NULL;

    ssm_check_pointer_return_if_fail(intent);
    ssm_check_session_handle_return_if_fail(session_handle);

    hi_tee_drv_hal_mutex_lock(&g_instance_lock);

    get_instance = find_ssm_instance_by_session_id(session_handle & 0xff);
    if (get_instance == HI_NULL) {
        hi_tee_drv_hal_mutex_unlock(&g_instance_lock);
        hi_error_ssm("cannot find instance\n");
        return HI_ERR_SSM_INVALID_SESSOION_HANDLE;
    }

    (*intent) = get_instance->intent;

    hi_tee_drv_hal_mutex_unlock(&g_instance_lock);

    return HI_SUCCESS;
}

hi_s32 tee_drv_ssm_set_private_data(hi_handle session_handle, const hi_u32 addr, const hi_u32 len)
{
    hi_tee_drv_ssm_instance *get_instance = HI_NULL;

    ssm_check_session_handle_return_if_fail(session_handle);

    hi_tee_drv_hal_mutex_lock(&g_instance_lock);

    get_instance = find_ssm_instance_by_session_id(session_handle & 0xff);
    if (get_instance == HI_NULL) {
        hi_tee_drv_hal_mutex_unlock(&g_instance_lock);
        hi_error_ssm("cannot find instance\n");
        return HI_ERR_SSM_INVALID_SESSOION_HANDLE;
    }

    get_instance->private_data.length = len;
    get_instance->private_data.priv_data = (hi_void *)addr;

    hi_tee_drv_hal_mutex_unlock(&g_instance_lock);

    return HI_SUCCESS;
}

hi_s32 tee_drv_ssm_get_private_data(hi_handle session_handle, hi_u32 *addr, hi_u32 *len)
{
    hi_tee_drv_ssm_instance *get_instance = HI_NULL;

    ssm_check_session_handle_return_if_fail(session_handle);
    ssm_check_pointer_return_if_fail(addr);
    ssm_check_pointer_return_if_fail(len);

    hi_tee_drv_hal_mutex_lock(&g_instance_lock);

    get_instance = find_ssm_instance_by_session_id(session_handle & 0xff);
    if (get_instance == HI_NULL) {
        hi_tee_drv_hal_mutex_unlock(&g_instance_lock);
        hi_error_ssm("cannot find instance\n");
        return HI_ERR_SSM_INVALID_SESSOION_HANDLE;
    }

    *len = get_instance->private_data.length;
    *addr = (uintptr_t)get_instance->private_data.priv_data;

    hi_tee_drv_hal_mutex_unlock(&g_instance_lock);

    return HI_SUCCESS;
}

hi_s32 tee_drv_ssm_set_3rd_partner_intent(hi_handle session_handle, hi_u32 third_partner_intent)
{
    hi_tee_drv_ssm_instance *get_instance = HI_NULL;

    ssm_check_session_handle_return_if_fail(session_handle);

    hi_tee_drv_hal_mutex_lock(&g_instance_lock);

    get_instance = find_ssm_instance_by_session_id(session_handle & 0xff);
    if (get_instance == HI_NULL) {
        hi_tee_drv_hal_mutex_unlock(&g_instance_lock);
        hi_error_ssm("cannot find instance\n");
        return HI_ERR_SSM_INVALID_SESSOION_HANDLE;
    }

    get_instance->third_partner_intent = third_partner_intent;

    hi_tee_drv_hal_mutex_unlock(&g_instance_lock);

    return HI_SUCCESS;
}

hi_s32 tee_drv_ssm_set_reg(hi_u32 addr, hi_u32 val)
{
    return ssm_set_reg(addr, val);
}
hi_s32 tee_drv_ssm_send_policy_table(hi_handle session_handle, const hi_tee_ssm_policy_table *policy_table)
{
    hi_s32 ret;
    hi_tee_ssm_policy_table p_table = {0};

    ret = memcpy_s(&p_table, sizeof(p_table), policy_table, sizeof(hi_tee_ssm_policy_table));
    if (ret < 0) {
        hi_error_ssm("cannot cpy policy table ! : 0x%x\n", ret);
        return ret;
    }

    ret = policy_table_transmit(session_handle, &p_table);
    if (ret != 0) {
        hi_error_ssm("cannot send policy table ! : 0x%x\n", ret);
        return ret;
    }

    return HI_SUCCESS;
}

hi_s32 hi_tee_drv_ssm_iommu_config(hi_tee_logic_mod_id module_id)
{
    hi_s32 ret;

    ret = iommu_sec_config(module_id);
    if (ret != HI_SUCCESS) {
        hi_error_ssm("set iommu tag fail-%d\n", __LINE__);
        return HI_FAILURE;
    }
    return HI_SUCCESS;
}

hi_s32 hi_tee_drv_ssm_attach_buf(const hi_tee_ssm_buffer_attach_info *buffer_attach_infor, hi_u64 *secure_info_addr)
{
    return tee_drv_ssm_attach_buffer((hi_tee_drv_ssm_buf_attach_info *)buffer_attach_infor, secure_info_addr);
}

hi_s32 ssm_syscall_create_handler(TSK_REGS_S *regs, unsigned long long permissions)
{
    hi_s32 ret;

    ret = hi_tee_drv_hal_permission_check(permissions, GENERAL_GROUP_PERMISSION);
    if (ret != 0) {
        regs->r0 = ret;
        hi_error_ssm("check ssm init permission fail\n");
        return HI_FAILURE;
    }

    ret = hi_tee_drv_hal_user_mmap((void **)&(regs->r1), sizeof(hi_handle));
    if (ret != 0) {
        regs->r0 = ret;
        hi_error_ssm("check ssm init map fail\n");
        return ret;
    }

    /* need malloc */
    ret = tee_drv_ssm_init();
    if (ret != HI_SUCCESS) {
        hi_error_ssm("init sec info fail\n");
        goto err_umap;
    }

    if (g_sec_info_inited == HI_TRUE) {
        ret = tee_drv_ssm_create(regs->r0, (hi_handle *)regs->r1);
        if (ret != HI_SUCCESS) {
            hi_error_ssm("tee_drv_ssm_create fail:%x\n", ret);
            goto err_umap;
        } else {
            regs->r0 = 0;  /* return value for api */
        }
    }
    hi_tee_drv_hal_user_munmap((void *)(regs->r1), sizeof(hi_handle));
    return HI_SUCCESS;
err_umap:
    regs->r0 = ret;
    hi_tee_drv_hal_user_munmap((void *)(regs->r1), sizeof(hi_handle));
    return ret;
}

hi_s32 ssm_syscall_destroy_handler(TSK_REGS_S *regs, unsigned long long permissions)
{
    hi_s32 ret;

    ret = hi_tee_drv_hal_permission_check(permissions, GENERAL_GROUP_PERMISSION);
    if (ret != 0) {
        regs->r0 = ret;
        hi_error_ssm("check ssm init permission fail\n");
        return ret;
    }

    ret = tee_drv_ssm_destroy(regs->r0);
    if (ret != HI_SUCCESS) {
        hi_error_ssm("tee_drv_ssm_destroy fail:%x\n", ret);
        regs->r0 = ret;
    } else {
        regs->r0 = 0;
    }

    return ret;
}

hi_s32 ssm_syscall_add_resource_handler(TSK_REGS_S *regs, unsigned long long permissions)
{
    hi_s32 ret;

    ret = hi_tee_drv_hal_permission_check(permissions, GENERAL_GROUP_PERMISSION);
    if (ret != 0) {
        regs->r0 = ret;
        hi_error_ssm("check ssm add res permission fail\n");
        return ret;
    }

    ret = hi_tee_drv_hal_user_mmap((void **)&(regs->r1), sizeof(hi_tee_ssm_module_info));
    if (ret != 0) {
        regs->r0 = ret;
        hi_error_ssm("check ssm add resource map fail\n");
        return ret;
    }

    ret = tee_drv_ssm_add_resource(regs->r0, (hi_tee_ssm_module_info *)regs->r1);
    if (ret != HI_SUCCESS) {
        hi_error_ssm("tee_drv_ssm_add_resource fail:%x\n", ret);
        regs->r0 = ret;
    } else {
        regs->r0 = 0;
    }

    hi_tee_drv_hal_user_munmap((void *)(regs->r1), sizeof(hi_tee_ssm_module_info));
    return HI_SUCCESS;
}

hi_s32 ssm_syscall_attach_buf_handler(TSK_REGS_S *regs, unsigned long long permissions)
{
    hi_s32 ret;
    hi_tee_drv_ssm_buf_attach_info drv_attach_info = {0};
    hi_tee_smmu_buf smmu_buf = {0};

    ret = hi_tee_drv_hal_permission_check(permissions, GENERAL_GROUP_PERMISSION);
    if (ret != 0) {
        regs->r0 = ret;
        hi_error_ssm("check ssm attach_buf permission fail\n");
        return ret;
    }

    ret = hi_tee_drv_hal_user_mmap((void **)&(regs->r1), sizeof(hi_u64));
    if (ret != 0) {
        regs->r0 = ret;
        hi_error_ssm("check ssm attach_buf map fail\n");
        return ret;
    }

    ret = hi_tee_drv_hal_user_mmap((void **)&(regs->r0), sizeof(hi_tee_ssm_buffer_attach_info));
    if (ret != 0) {
        hi_tee_drv_hal_user_munmap((void *)(regs->r1), sizeof(hi_u64));
        regs->r0 = ret;
        return ret;
    }
    ret = memcpy_s(&drv_attach_info, sizeof(hi_tee_drv_ssm_buf_attach_info), (hi_void *)regs->r0,
        sizeof(hi_tee_ssm_buffer_attach_info));
    if (ret != 0) {
        hi_tee_drv_hal_user_munmap((void *)(regs->r1), sizeof(hi_u64));
        hi_tee_drv_hal_user_munmap((void *)(regs->r0), sizeof(hi_u64));
        regs->r0 = ret;
        return ret;
    }

    ret = hi_tee_drv_mem_get_secsmmu_by_handle_id(&smmu_buf,
        ((hi_tee_ssm_buffer_attach_info *)(regs->r0))->buf_smmu_handle);
    if (ret != 0) {
        hi_tee_drv_hal_user_munmap((void *)(regs->r1), sizeof(hi_u64));
        hi_tee_drv_hal_user_munmap((void *)(regs->r0), sizeof(hi_u64));
        regs->r0 = ret;
        return ret;
    }

    drv_attach_info.buf_smmu_addr = smmu_buf.smmu_addr;
    ret = tee_drv_ssm_attach_buffer(&drv_attach_info, (hi_u64 *)regs->r1);
    /* r0 addr need te be unmapped before overwrited */
    hi_tee_drv_hal_user_munmap((void *)(regs->r0), sizeof(hi_tee_ssm_buffer_attach_info));
    if (ret != HI_SUCCESS) {
        regs->r0 = ret;
    } else {
        regs->r0 = 0;
    }

    hi_tee_drv_hal_user_munmap((void *)(regs->r1), sizeof(hi_u64));
    return ret;
}

hi_s32 ssm_syscall_get_intent_handler(TSK_REGS_S *regs, unsigned long long permissions)
{
    hi_s32 ret;

    ret = hi_tee_drv_hal_permission_check(permissions, GENERAL_GROUP_PERMISSION);
    if (ret != 0) {
        regs->r0 = ret;
        hi_error_ssm("check ssm get_intent permission fail\n");
        return ret;
    }

    ret = hi_tee_drv_hal_user_mmap((void **)&(regs->r1), sizeof(hi_tee_ssm_intent));
    if (ret != 0) {
        regs->r0 = ret;
        hi_error_ssm("check ssm get_intent map fail\n");
        return ret;
    }

    ret = tee_drv_ssm_get_intent(regs->r0, (hi_tee_ssm_intent *)regs->r1);
    if (ret != HI_SUCCESS) {
        hi_error_ssm("tee_drv_ssm_get_intent fail:%x\n", ret);
        regs->r0 = ret;
    } else {
        regs->r0 = 0;
    }

    hi_tee_drv_hal_user_munmap((void *)(regs->r1), sizeof(hi_tee_ssm_intent));
    return HI_SUCCESS;
}

hi_s32 ssm_syscall_set_iommu_handler(TSK_REGS_S *regs, unsigned long long permissions)
{
    hi_s32 ret;

    ret = hi_tee_drv_hal_permission_check(permissions, GENERAL_GROUP_PERMISSION);
    if (ret != 0) {
        regs->r0 = ret;
        hi_error_ssm("check ssm set_iommu permission fail\n");
        return ret;
    }

    ret = tee_drv_ssm_set_iommu_tag(regs->r0);
    if (ret != HI_SUCCESS) {
        hi_error_ssm("set iommu tag fail:%x\n", ret);
        regs->r0 = ret;
    } else {
        regs->r0 = 0;
    }

    return HI_SUCCESS;
}

hi_s32 ssm_syscall_set_uuid_handler(TSK_REGS_S *regs, unsigned long long permissions)
{
    hi_s32 ret;

    ret = hi_tee_drv_hal_permission_check(permissions, GENERAL_GROUP_PERMISSION);
    if (ret != 0) {
        regs->r0 = ret;
        hi_error_ssm("check ssm set_uuid permission fail\n");
        return ret;
    }

    ret = tee_drv_ssm_set_uuid(regs->r0);
    if (ret != HI_SUCCESS) {
        hi_error_ssm("set tee_drv_ssm_set_uuid fail:%x\n", ret);
        regs->r0 = ret;
    } else {
        regs->r0 = 0;
    }

    return HI_SUCCESS;
}

hi_s32 ssm_syscall_check_uuid_handler(TSK_REGS_S *regs, unsigned long long permissions)
{
    hi_s32 ret;

    ret = hi_tee_drv_hal_permission_check(permissions, GENERAL_GROUP_PERMISSION);
    if (ret != 0) {
        regs->r0 = ret;
        hi_error_ssm("check ssm check_uuid permission fail\n");
        return ret;
    }

    ret = tee_drv_ssm_check_uuid(regs->r0);
    if (ret != HI_SUCCESS) {
        hi_error_ssm("set tee_drv_ssm_check_uuid fail:%x\n", ret);
        regs->r0 = ret;
    } else {
        regs->r0 = 0;
    }

    return HI_SUCCESS;
}

hi_s32 ssm_syscall_check_buf_handler(TSK_REGS_S *regs, unsigned long long permissions)
{
    hi_s32 ret;
    hi_tee_drv_ssm_buf_check_info drv_buf_chk_info = {0};
    hi_tee_smmu_buf smmu_buf = {0};

    ret = hi_tee_drv_hal_permission_check(permissions, GENERAL_GROUP_PERMISSION);
    if (ret != 0) {
        regs->r0 = ret;
        hi_error_ssm("check ssm check_buf permission fail\n");
        return ret;
    }

    ret = hi_tee_drv_hal_user_mmap((void **)&(regs->r0), sizeof(hi_tee_ssm_buffer_check_info));
    if (ret != 0) {
        regs->r0 = ret;
        hi_error_ssm("ssm check_buf map fail\n");
        return ret;
    }

    ret = memcpy_s(&drv_buf_chk_info, sizeof(hi_tee_drv_ssm_buf_check_info), (hi_void *)regs->r0,
        sizeof(hi_tee_ssm_buffer_check_info));
    if (ret != 0) {
        hi_tee_drv_hal_user_munmap((void *)(regs->r0), sizeof(hi_tee_ssm_buffer_check_info));
        hi_error_ssm("cpy check_buf fail\n");
        regs->r0 = ret;
        return ret;
    }

    ret = hi_tee_drv_mem_get_secsmmu_by_handle_id(&smmu_buf, ((hi_tee_ssm_buffer_check_info *)(regs->r0))->buf_handle);
    if (ret != 0) {
        hi_tee_drv_hal_user_munmap((void *)(regs->r0), sizeof(hi_tee_ssm_buffer_check_info));
        hi_error_ssm("ssm chk buf get_secsmmu_by_handle_id fail\n");
        regs->r0 = ret;
        return ret;
    }
    drv_buf_chk_info.buf_addr = smmu_buf.smmu_addr;
    ret = tee_drv_ssm_check_buffer(&drv_buf_chk_info);
    /* need umap before overwrited */
    hi_tee_drv_hal_user_munmap((void *)(regs->r0), sizeof(hi_tee_ssm_buffer_check_info));
    if (ret != HI_SUCCESS) {
        hi_error_ssm("check tee_drv_ssm_check_buffer fail:%x\n", ret);
        regs->r0 = ret;
    } else {
        regs->r0 = 0;
    }
    return HI_SUCCESS;
}

hi_s32 ssm_syscall_init_handler(TSK_REGS_S *regs, unsigned long long permissions)
{
    hi_s32 ret;

    ret = hi_tee_drv_hal_permission_check(permissions, GENERAL_GROUP_PERMISSION);
    if (ret != 0) {
        regs->r0 = ret;
        hi_error_ssm("check init_handler permission fail\n");
        return ret;
    }

    if (g_sec_info_inited == HI_FALSE) {
        /* need malloc */
        ret = tee_drv_ssm_init();
        if (ret != HI_SUCCESS) {
            hi_error_ssm("init sec info fail\n");
            regs->r0 = ret;
        } else {
            g_sec_info_inited = HI_TRUE;
            regs->r0 = 0;
        }
    }
    return HI_SUCCESS;
}

hi_s32 ssm_syscall_send_policy_handler(TSK_REGS_S *regs, unsigned long long permissions)
{
    hi_s32 ret;

    ret = hi_tee_drv_hal_permission_check(permissions, GENERAL_GROUP_PERMISSION);
    if (ret != 0) {
        regs->r0 = ret;
        hi_tee_drv_hal_printf("check ssm attach_buf permission fail\n");
        return ret;
    }

    ret = hi_tee_drv_hal_user_mmap((void **)&(regs->r1), sizeof(hi_tee_ssm_policy_table));
    if (ret != 0) {
        regs->r0 = ret;
        hi_tee_drv_hal_printf("map op addr fail\n");
        return ret;
    }

    ret = tee_drv_ssm_send_policy_table(regs->r0, (hi_tee_ssm_policy_table *)regs->r1);
    if (ret != 0) {
        regs->r0 = ret;
        hi_tee_drv_hal_printf("map op addr fail\n");
        hi_tee_drv_hal_user_munmap((void *)(regs->r1), sizeof(hi_tee_ssm_policy_table));
        return ret;
    }

    hi_tee_drv_hal_user_munmap((void *)(regs->r1), sizeof(hi_tee_ssm_policy_table));
    regs->r0 = 0;
    return 0;
}

hi_s32 ssm_syscall_set_reg(TSK_REGS_S *regs, unsigned long long permissions)
{
    hi_s32 ret;

    ret = hi_tee_drv_hal_permission_check(permissions, GENERAL_GROUP_PERMISSION);
    if (ret != 0) {
        regs->r0 = ret;
        hi_tee_drv_hal_printf("check ssm set reg permission fail\n");
        return ret;
    }

    ret = tee_drv_ssm_set_reg(regs->r0, regs->r1);
    if (ret != HI_SUCCESS) {
        hi_error_ssm("ssm set reg fail:%x\n", ret);
        regs->r0 = ret;
    } else {
        regs->r0 = 0;
    }

    return ret;
}

static ssm_syscall_map g_syscall_map[] = {
    {HI_TEE_SYSCALL_SSM_CREATE, ssm_syscall_create_handler},
    {HI_TEE_SYSCALL_SSM_DESTROY, ssm_syscall_destroy_handler},
    {HI_TEE_SYSCALL_SSM_ADD_RESOURCE, ssm_syscall_add_resource_handler},
    {HI_TEE_SYSCALL_SSM_ATTACH_BUF, ssm_syscall_attach_buf_handler},
    {HI_TEE_SYSCALL_SSM_GET_INTENT, ssm_syscall_get_intent_handler},
    {HI_TEE_SYSCALL_SSM_IOMMU_CONFIG, ssm_syscall_set_iommu_handler},
    {HI_TEE_SYSCALL_SSM_SET_UUID, ssm_syscall_set_uuid_handler},
    {HI_TEE_SYSCALL_SSM_CHECK_UUID, ssm_syscall_check_uuid_handler},
    {HI_TEE_SYSCALL_SSM_CHECK_BUF, ssm_syscall_check_buf_handler},
    {HI_TEE_SYSCALL_SSM_INIT, ssm_syscall_init_handler},
    {HI_TEE_SYSCALL_SSM_SEND_POLICY, ssm_syscall_send_policy_handler},
    {HI_TEE_SYSCALL_SSM_SET_REG, ssm_syscall_set_reg},
};

int ssm_syscall(int swi_id, TSK_REGS_S *regs, UINT64 permissions)
{
    hi_s32 ret = -EINVAL;
    hi_u32 i;

    for (i = 0; i < sizeof(g_syscall_map) / sizeof(g_syscall_map[0]); i++) {
        if (g_syscall_map[i].swi_id == swi_id) {
            ret = g_syscall_map[i].syscall_handler(regs, permissions);
            if (regs->r0 != 0) {
                hi_error_ssm("call ssm swi_id fail : 0x%x\n", swi_id);
            }
            break;
        }
    }

    return ret;
}

hi_tee_drv_hal_driver_init_late(drv_ssm, 0, NULL, ssm_syscall, NULL, NULL);

