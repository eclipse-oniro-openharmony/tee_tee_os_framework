/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: process ts data for play
 */

#include "libhwsecurec/securec.h"
#include "tee_pvr.h"
#include "tee_pvr_utils.h"
#include "tee_drv_pvr.h"
#include "tee_drv_pvr_play.h"

/* the length of ts packet. the difference between ts&tts is processed by ree */
#define PVR_TS_LEN                      188

/* the header byte of ts packet */
#define PVR_TS_HEAD                     0x47

/* the header len os ts packet */
#define PVR_TS_HEAD_SIZE                4

/* adapt field located in the 3 byte from 0 */
#define PVR_TS_ADAPT_FLD_POS            3

/* the fifth byte in TS header of the length area of padding */
#define PVR_TS_PD_SIZE_POS              4

/* the sixth byte in TS header of the flag area of padding */
#define PVR_TS_PD_FLAG_POS              5

/* the min payload size if exist */
#define PVR_TS_MIN_PD_SIZE              2

#define PVR_TS_ADAPT_PLD_ONLY           0x1
#define PVR_TS_ADAPT_ADAPT_ONLY         0x2
#define PVR_TS_ADAPT_BOTH               0x3
#define pvr_ts_is_have_adapt(flag)      ((flag) & PVR_TS_ADAPT_ADAPT_ONLY)

static inline hi_void pvr_play_set_adp_field(hi_u8 *header, hi_u32 flag)
{
    hi_u8 tmp = header[PVR_TS_ADAPT_FLD_POS];

    tmp = (tmp & 0xcf) | ((flag & 0x3) << 0x4); /* set adp field bits */
    header[PVR_TS_ADAPT_FLD_POS] = tmp;

    return;
}

static inline hi_u8 pvr_play_get_adp_field(const hi_u8 *header)
{
    return (header[PVR_TS_ADAPT_FLD_POS] >> 0x4) & 0x3;
}

static inline hi_void pvr_play_disorder_cnt(hi_u8 *header, hi_bool is_tail)
{
    hi_u8 old_cnt;
    hi_u8 delta = (is_tail == HI_TRUE) ? 3 : 5; /* 3/5 is rand number, to make the cnt of ts packet is discontinous */
    hi_u8 tmp = header[PVR_TS_ADAPT_FLD_POS];

    old_cnt = (tmp & 0xf) + delta;
    tmp = (tmp & 0xf0) | (old_cnt & 0xf);
    header[PVR_TS_ADAPT_FLD_POS] = tmp;

    return;
}

static hi_void pvr_play_proc_head(hi_u8 *header, hi_u32 start_pos)
{
    hi_s32 ret;
    hi_u32 tmp_len;
    hi_u8 adapt_flag;

    /* invalid ts header, just return */
    if (header[0] != PVR_TS_HEAD) {
        hi_warn_print_info("Wrong Header!");
        hi_warn_print_u32((hi_u32)(header[0x0]));
        hi_warn_print_u32((hi_u32)(header[0x1]));
        hi_warn_print_u32((hi_u32)(header[0x2]));
        hi_warn_print_u32((hi_u32)(header[0x3]));
        return;
    }

    /* no need to process, just return */
    if ((start_pos <= PVR_TS_HEAD_SIZE) || ((header[1] & 0x40) != 0)) {
        hi_warn_print_u32(start_pos);
        hi_dbg_print_u32((hi_u32)(header[1]));
        return;
    }

    tmp_len = PVR_TS_HEAD_SIZE + PVR_TS_MIN_PD_SIZE;
    if (start_pos >= tmp_len) {
        adapt_flag = pvr_play_get_adp_field(header);

        /* if the dataStartPos is not equal the size of ts head, it should be both */
        pvr_play_set_adp_field(header, PVR_TS_ADAPT_BOTH);
        header[PVR_TS_PD_SIZE_POS] = (hi_u8)(start_pos - (PVR_TS_HEAD_SIZE + 1));

        if (pvr_ts_is_have_adapt(adapt_flag) == 0) {
            header[PVR_TS_PD_FLAG_POS] = 0;
        }

        /* modify the padding area length */
        ret = memset_s(header + tmp_len, start_pos - tmp_len, 0xff, start_pos - tmp_len);
        if (ret != 0) {
            hi_err_print_call_fun_err(memset_s, ret);
            return;
        }
    } else {
        /* only 1Byte Adapt_len */
        pvr_play_set_adp_field(header, PVR_TS_ADAPT_BOTH);
        header[PVR_TS_PD_SIZE_POS] = 0;
    }

    pvr_play_disorder_cnt(header, HI_FALSE);
    return;
}

static hi_void pvr_proc_end_with_pad(hi_u8 *buf, hi_u32 data_end,  hi_u32 end_add)
{
    hi_s32 ret;
    hi_u32 data_in_last;

    /* existent the padding field */
    if (end_add + PVR_TS_HEAD_SIZE + PVR_TS_MIN_PD_SIZE > PVR_TS_LEN) {
        end_add = PVR_TS_LEN - (PVR_TS_HEAD_SIZE + PVR_TS_MIN_PD_SIZE);
    }

    data_in_last = PVR_TS_LEN - (end_add + PVR_TS_HEAD_SIZE + PVR_TS_MIN_PD_SIZE);
    ret = memmove_s(buf + data_end  + end_add - data_in_last,
        data_in_last, buf + data_end  - data_in_last, data_in_last);
    if (ret != 0) {
        hi_err_print_call_fun_err(memmove_s, ret);
        return;
    }

    ret = memset_s(buf + data_end  - data_in_last, end_add, 0xff, end_add);
    if (ret != 0) {
        hi_err_print_call_fun_err(memset_s, ret);
        return;
    }
    buf[data_end  - (data_in_last + PVR_TS_MIN_PD_SIZE)] += (hi_u8)(end_add);

    return;
}

static hi_void pvr_proc_end_no_pad(hi_u8 *buf, hi_u8 *header, hi_u32 data_end,  hi_u32 end_add)
{
    hi_s32 ret;
    hi_u32 data_in_last;

    if (end_add + PVR_TS_HEAD_SIZE > PVR_TS_LEN) {
        end_add = PVR_TS_LEN - (PVR_TS_HEAD_SIZE);
    }

    data_in_last = PVR_TS_LEN - (end_add + PVR_TS_HEAD_SIZE);
    ret = memmove_s(header + PVR_TS_HEAD_SIZE + end_add, data_in_last, header + PVR_TS_HEAD_SIZE, data_in_last);
    if (ret != 0) {
        hi_err_print_call_fun_err(memmove_s, ret);
        return;
    }

    ret = memset_s(header + PVR_TS_HEAD_SIZE, end_add, 0xff, end_add);
    if (ret != 0) {
        hi_err_print_call_fun_err(memset_s, ret);
        return;
    }
    header[PVR_TS_PD_SIZE_POS] = (hi_u8)(end_add - 1);
    header[PVR_TS_PD_FLAG_POS] = 0;
    pvr_unused(buf);
    pvr_unused(data_end);

    return;
}

static hi_void pvr_play_proc_end(hi_u8 *buf, hi_u32 data_end,  hi_u32 end_add)
{
    hi_u8 *header = HI_NULL;
    hi_u8 adapt_flag;
    hi_u8 tmp_flag;

    if (end_add == 0) {
        return;
    }

    header = buf + data_end + end_add - PVR_TS_LEN;

    /* invalided header, just return */
    if (header[0] != PVR_TS_HEAD) {
        hi_warn_print_info("Wrong Header!");
        hi_warn_print_u32((hi_u32)(header[0x0]));
        hi_warn_print_u32((hi_u32)(header[0x1]));
        hi_warn_print_u32((hi_u32)(header[0x2]));
        hi_warn_print_u32((hi_u32)(header[0x3]));
        return;
    }

    adapt_flag = pvr_play_get_adp_field(header);

    tmp_flag = ((end_add + PVR_TS_HEAD_SIZE) == PVR_TS_LEN) ? PVR_TS_ADAPT_ADAPT_ONLY : PVR_TS_ADAPT_BOTH;
    pvr_play_set_adp_field(header, tmp_flag);
    pvr_play_disorder_cnt(header, HI_TRUE);

    /*  if it should have adaptation, we need to check whether it length is zero or not */
    if ((pvr_ts_is_have_adapt(adapt_flag) != 0) && (header[PVR_TS_PD_SIZE_POS] != 0)) {
        /* existent the padding field */
        pvr_proc_end_with_pad(buf, data_end, end_add);
    } else {
        /* nonexistent padding field */
        pvr_proc_end_no_pad(buf, header, data_end, end_add);
    }

    return;
}

hi_s32 drv_pvr_play_copy_ree_data_to_tee(hi_void *dst, hi_u32 dst_len, const hi_void *src, hi_u32 src_len)
{
    hi_s32 ret;

    hi_info_func_enter();

    if ((dst == HI_NULL) || (src == HI_NULL) || (src_len == 0)) {
        hi_warn_print_info("Invalid input argument!");
        hi_log_err("dst:%p src:%p len:%u\n", dst, src, src_len);
        hi_err_print_err_code(HI_TEE_ERROR_PVR_INVALID_PARAM);
        return HI_TEE_ERROR_PVR_INVALID_PARAM;
    }

    ret = memcpy_s(dst, dst_len, src, src_len);
    if (ret != 0) {
        hi_err_print_call_fun_err(memcpy_s, ret);
        return HI_FAILURE;
    }

    hi_info_func_exit();
    return HI_SUCCESS;
}

hi_s32 drv_pvr_play_proc_tsdata(tee_pvr_play_tsdata_info *data_info, hi_void *data_addr)
{
    hi_u8 *tsdata_buf = HI_NULL;

    hi_info_func_enter();

    if ((data_info == HI_NULL) || (data_addr == HI_NULL)) {
        hi_warn_print_info("Invalid input argument!");
        hi_err_print_err_code(HI_TEE_ERROR_PVR_NULL_PTR);
        return HI_TEE_ERROR_PVR_NULL_PTR;
    }

    /*
     * |-------------|-------------|-------------------------|-------------|-----------|
     * | cipherToHead  |  headToAdd     |                dataSend            |      endToAdd   | cipherToEnd |
     * head_offset <--> cipherToHead;
     * head_add <--> headToAdd
     * end_offset <--> cipherToHead+headToAdd+dataSend
     * end_add <--> endToAdd
     */
    if ((data_info->head_offset >= data_info->end_offset) || (data_info->head_add >= data_info->end_offset) ||
        (data_info->head_offset + data_info->head_add >= data_info->end_offset)) {
        hi_warn_print_info("Invalid input argument!");
        hi_warn_print_u32(data_info->head_offset);
        hi_warn_print_u32(data_info->head_add);
        hi_warn_print_u32(data_info->end_offset);
        hi_err_print_err_code(HI_TEE_ERROR_PVR_INVALID_PARAM);
        return HI_TEE_ERROR_PVR_INVALID_PARAM;
    }

    /* because head_add and end_add is used to align by PVR_TS_LEN, so them should less than PVR_TS_LEN */
    if ((data_info->head_add >= PVR_TS_LEN) || (data_info->end_add >= PVR_TS_LEN)) {
        hi_warn_print_info("Invalid input argument!");
        hi_warn_print_u32(data_info->head_add);
        hi_warn_print_u32(data_info->end_add);
        hi_err_print_err_code(HI_TEE_ERROR_PVR_INVALID_PARAM);
        return HI_TEE_ERROR_PVR_INVALID_PARAM;
    }

    /* the sumd of headToAdd+dataSend+endToAdd should larger than the PVR_TS_LEN */
    if (data_info->end_offset + data_info->end_add < data_info->head_offset + PVR_TS_LEN) {
        hi_warn_print_info("should be include one ts packet!");
        hi_warn_print_u32(data_info->end_offset);
        hi_warn_print_u32(data_info->end_add);
        hi_warn_print_u32(data_info->head_offset);
        hi_err_print_err_code(HI_TEE_ERROR_PVR_INVALID_PARAM);
        return HI_TEE_ERROR_PVR_INVALID_PARAM;
    }

    tsdata_buf = (hi_u8 *)data_addr;
    pvr_play_proc_head(tsdata_buf + data_info->head_offset, data_info->head_add);
    pvr_play_proc_end(tsdata_buf, data_info->end_offset, data_info->end_add);

    hi_info_func_exit();
    return HI_SUCCESS;
}
