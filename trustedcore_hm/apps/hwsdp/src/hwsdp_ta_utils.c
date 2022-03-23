/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: This file contains the public implementation for HWSDP TA
 * Author: Huzhonghua h00440650
 * Create: 2020-10-19
 */

#include "securec.h"
#include "tee_mem_mgmt_api.h"
#include "tee_log.h"

#include "hwsdp_ta.h"
#include "hwsdp_ta_utils.h"
#include "hwsdp_ta_keymgr.h"

/* free the buf with clean data */
void secure_free(void *buf, uint32_t buf_size)
{
    errno_t eno;

    eno = memset_s(buf, buf_size, 0, buf_size);
    if (eno != EOK)
        SLogError("secure_free: memset_s failed");

    TEE_Free(buf);
    return;
}

hwsdp_msghandler hwsdp_get_msghandler(uint32_t tee_cmd, int32_t op_code)
{
    hwsdp_msghandler msg_handler = NULL;

    switch (tee_cmd) {
    case CMD_HWSDP_KEY_MANAGER:
        msg_handler = get_isec_key_handler_by_opcode(op_code);
        break;
    default:
        (void)op_code;
        break;
    }
    return msg_handler;
}

TEE_Result hwsdp_proc_message(uint32_t tee_cmd, uint32_t param_types, TEE_Param *params)
{
    uint8_t *data = NULL;
    uint32_t data_len;
    uint32_t param_type_tmp;
    int32_t ret;
    hwsdp_msghdr *msg_hdr = NULL;
    hwsdp_msghandler msg_handler = NULL;

    SLogTrace("enter hwsdp_proc_message ...");

    param_type_tmp = TEE_PARAM_TYPE_GET(param_types, 0);
    if ((param_type_tmp != TEE_PARAM_TYPE_VALUE_INPUT) &&
        (param_type_tmp != TEE_PARAM_TYPE_MEMREF_INOUT))
        return TEE_ERROR_BAD_PARAMETERS;

    data = (uint8_t *)(params[0].memref.buffer);
    data_len = params[0].memref.size;
    msg_hdr = (hwsdp_msghdr *)data;
    if (data == NULL)
        return TEE_ERROR_NO_DATA;

    /* ensure that ipc data length is correct */
    if (msg_hdr->length != (data_len - sizeof(hwsdp_msghdr))) {
        SLogTrace("hwsdp_proc_message, message length[%u] error", msg_hdr->length);
        return TEE_ERROR_GENERIC;
    }

    msg_handler = hwsdp_get_msghandler(tee_cmd, msg_hdr->op_code);
    if (msg_handler == NULL) {
        SLogTrace("hwsdp_proc_message, message handler invalied, tee_cmd: %u, op_code: %d",
            tee_cmd, msg_hdr->op_code);
        return TEE_ERROR_GENERIC;
    }
    /* 4 - the number of params */
    ret = msg_handler(param_types, params, 4u);
    if (ret != HWSDP_TEE_SUCCESS) {
        SLogTrace("hwsdp_proc_message, process message failed, tee_cmd: %u, error: %d",
            tee_cmd, ret);
        return TEE_ERROR_GENERIC;
    }
    SLogTrace("hwsdp_proc_message done");
    return TEE_SUCCESS;
}

void hwsdp_destroy_all_modules(void)
{
    destroy_isec_key_all_mgr_blk();
    return;
}

void hwsdp_release_data_buffer(hwsdp_data_info *data_info)
{
    if ((data_info->len >
        (uint32_t)sizeof(data_info->data.buf)) && (data_info->data.mem_ptr != NULL))
        secure_free(data_info->data.mem_ptr, data_info->len);

    (void)memset_s(data_info, sizeof(hwsdp_data_info), 0, sizeof(hwsdp_data_info));
    return;
}

int32_t hwsdp_store_data(hwsdp_data_info *dst, const uint8_t *src, uint32_t src_len)
{
    errno_t eno;
    uint32_t tag = 0;
    uint32_t dst_len;
    void *dst_buf = dst->data.buf;

    dst_len = (uint32_t)HWSDP_DATA_MAX_LENGTH;
    if (src_len > (uint32_t)sizeof(dst->data.buf)) {
        dst_buf = (void *)TEE_Malloc(src_len, 0u);
        if (dst_buf == NULL)
            return HWSDP_TEE_MEMORY_ALLOC_ERR;

        tag = 1;
        hwsdp_release_data_buffer(dst);
        dst->data.mem_ptr = dst_buf;
        dst_len = src_len;
    }
    eno = memcpy_s(dst_buf, dst_len, (const void *)src, src_len);
    if (eno != EOK) {
        if (tag == 1) {
            secure_free(dst_buf, src_len);
            dst->data.mem_ptr = NULL;
        }
        return HWSDP_TEE_MEMCPY_FAIL;
    }
    dst->len = src_len;
    return HWSDP_TEE_SUCCESS;
}

uint32_t hwsdp_copy_data(hwsdp_data_info *src, uint8_t *dst_buf, uint32_t bufsz)
{
    uint8_t *src_ptr = NULL;
    errno_t eno;

    src_ptr = src->data.buf;
    if (src->len > HWSDP_DATA_MAX_LENGTH)
        src_ptr = src->data.mem_ptr;

    eno = memcpy_s(dst_buf, bufsz, src_ptr, src->len);
    if (eno != EOK) {
        SLogError("hwsdp_copy_data: memcpy_s failed, errno %d", eno);
        return 0u;
    }
    return src->len;
}

int32_t get_first_true_bit_idx(uint32_t num)
{
    int32_t i;

    if (num == 0u)
        return BITMAP_MAX_INDEX;

    i = 0;
    while (((num >> i) & 0x01u) == 0u)
        i++;

    return i;
}
