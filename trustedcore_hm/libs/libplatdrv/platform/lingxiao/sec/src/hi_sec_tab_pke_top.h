/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2014-2019. All rights reserved.
 * Description: PKE表项定义
 * Author: o00302765
 * Create: 2019-10-22
 */

#ifndef __HI_SDK_L0_TAB_PKE_TOP_H__
#define __HI_SDK_L0_TAB_PKE_TOP_H__

#define HI_SDK_L0_TAB_PKE_TOP_BASE      0x10770000
#define HI_SDK_L0_TAB_PKE_TOP_MRAM_BASE (HI_SDK_L0_TAB_PKE_TOP_BASE + 0x0200)
#define HI_SDK_L0_TAB_PKE_TOP_MRAM_LEN  128
#define HI_SDK_L0_TAB_PKE_TOP_NRAM_BASE (HI_SDK_L0_TAB_PKE_TOP_BASE + 0x0600)
#define HI_SDK_L0_TAB_PKE_TOP_NRAM_LEN  128
#define HI_SDK_L0_TAB_PKE_TOP_KRAM_BASE (HI_SDK_L0_TAB_PKE_TOP_BASE + 0x0a00)
#define HI_SDK_L0_TAB_PKE_TOP_KRAM_LEN  128
#define HI_SDK_L0_TAB_PKE_TOP_RRAM_BASE (HI_SDK_L0_TAB_PKE_TOP_BASE + 0x0e00)
#define HI_SDK_L0_TAB_PKE_TOP_RRAM_LEN  128

struct hi_sdk_l0_tab_pke_top_mram_s {
	hi_uint32 mram : 32; /*[0:31]*/
};

struct hi_sdk_l0_tab_pke_top_mram_item_s {
	hi_uint32 idx;
	struct hi_sdk_l0_tab_pke_top_mram_s mram;
};

struct hi_sdk_l0_tab_pke_top_nram_s {
	hi_uint32 nram : 32; /*[0:31]*/
};

struct hi_sdk_l0_tab_pke_top_nram_item_s {
	hi_uint32 idx;
	struct hi_sdk_l0_tab_pke_top_nram_s nram;
};

struct hi_sdk_l0_tab_pke_top_kram_s {
	hi_uint32 kram : 32; /*[0:31]*/
};

struct hi_sdk_l0_tab_pke_top_kram_item_s {
	hi_uint32 idx;
	struct hi_sdk_l0_tab_pke_top_kram_s kram;
};

struct hi_sdk_l0_tab_pke_top_rram_s {
	hi_uint32 rram : 32; /*[0:31]*/
};

struct hi_sdk_l0_tab_pke_top_rram_item_s {
	hi_uint32 idx;
	struct hi_sdk_l0_tab_pke_top_rram_s rram;
};

hi_uint32 hi_sdk_l0_tab_set_pke_top_mram(hi_void *data, hi_uint32 inlen, hi_uint32 *outlen);
hi_uint32 hi_sdk_l0_tab_get_pke_top_mram(hi_void *data, hi_uint32 inlen, hi_uint32 *outlen);
hi_uint32 hi_sdk_l0_tab_set_pke_top_nram(hi_void *data, hi_uint32 inlen, hi_uint32 *outlen);
hi_uint32 hi_sdk_l0_tab_get_pke_top_nram(hi_void *data, hi_uint32 inlen, hi_uint32 *outlen);
hi_uint32 hi_sdk_l0_tab_set_pke_top_kram(hi_void *data, hi_uint32 inlen, hi_uint32 *outlen);
hi_uint32 hi_sdk_l0_tab_get_pke_top_kram(hi_void *data, hi_uint32 inlen, hi_uint32 *outlen);
hi_uint32 hi_sdk_l0_tab_set_pke_top_rram(hi_void *data, hi_uint32 inlen, hi_uint32 *outlen);
hi_uint32 hi_sdk_l0_tab_get_pke_top_rram(hi_void *data, hi_uint32 inlen, hi_uint32 *outlen);

#endif
