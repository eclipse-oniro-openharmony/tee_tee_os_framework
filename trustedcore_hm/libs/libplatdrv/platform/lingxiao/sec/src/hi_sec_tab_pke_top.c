/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
 * Description: PKE Ä£¿é
 * Author: hsan
 * Create: 2017-4-11
 * History: 2017-4-11³õ¸åÍê³É
 *          2019-1-31 hsan code restyle
 */

#include <hisilicon/chip/level_0/hi_sdk_l0.h>
#include "hi_sec_tab_pke_top.h"

hi_uint32 hi_sdk_l0_tab_set_pke_top_mram( hi_void *data,
	hi_uint32 inlen, hi_uint32 *outlen )
{
	struct hi_sdk_l0_tab_info_s tab_info;

	tab_info.base_addr = HI_SDK_L0_TAB_PKE_TOP_MRAM_BASE;
	tab_info.tab_len = HI_SDK_L0_TAB_PKE_TOP_MRAM_LEN;
	tab_info.item_size =
		sizeof(struct hi_sdk_l0_tab_pke_top_mram_s);
	return hi_sdk_l0_tab_write(&tab_info, data, outlen);
}

hi_uint32 hi_sdk_l0_tab_get_pke_top_mram( hi_void *data,
	hi_uint32 inlen, hi_uint32 *outlen )
{
	struct hi_sdk_l0_tab_info_s tab_info;

	tab_info.base_addr = HI_SDK_L0_TAB_PKE_TOP_MRAM_BASE;
	tab_info.tab_len = HI_SDK_L0_TAB_PKE_TOP_MRAM_LEN;
	tab_info.item_size =
		sizeof(struct hi_sdk_l0_tab_pke_top_mram_s);
	return hi_sdk_l0_tab_read(&tab_info, data, outlen);
}

hi_uint32 hi_sdk_l0_tab_set_pke_top_nram( hi_void *data,
	hi_uint32 inlen, hi_uint32 *outlen )
{
	struct hi_sdk_l0_tab_info_s tab_info;

	tab_info.base_addr = HI_SDK_L0_TAB_PKE_TOP_NRAM_BASE;
	tab_info.tab_len = HI_SDK_L0_TAB_PKE_TOP_NRAM_LEN;
	tab_info.item_size =
		sizeof(struct hi_sdk_l0_tab_pke_top_nram_s);
	return hi_sdk_l0_tab_write(&tab_info, data, outlen);
}

hi_uint32 hi_sdk_l0_tab_get_pke_top_nram( hi_void *data,
	hi_uint32 inlen, hi_uint32 *outlen )
{
	struct hi_sdk_l0_tab_info_s tab_info;

	tab_info.base_addr = HI_SDK_L0_TAB_PKE_TOP_NRAM_BASE;
	tab_info.tab_len = HI_SDK_L0_TAB_PKE_TOP_NRAM_LEN;
	tab_info.item_size =
		sizeof(struct hi_sdk_l0_tab_pke_top_nram_s);
	return hi_sdk_l0_tab_read(&tab_info, data, outlen);
}

hi_uint32 hi_sdk_l0_tab_set_pke_top_kram( hi_void *data,
	hi_uint32 inlen, hi_uint32 *outlen )
{
	struct hi_sdk_l0_tab_info_s tab_info;

	tab_info.base_addr = HI_SDK_L0_TAB_PKE_TOP_KRAM_BASE;
	tab_info.tab_len = HI_SDK_L0_TAB_PKE_TOP_KRAM_LEN;
	tab_info.item_size =
		sizeof(struct hi_sdk_l0_tab_pke_top_kram_s);
	return hi_sdk_l0_tab_write(&tab_info, data, outlen);
}

hi_uint32 hi_sdk_l0_tab_get_pke_top_kram( hi_void *data,
	hi_uint32 inlen, hi_uint32 *outlen )
{
	struct hi_sdk_l0_tab_info_s tab_info;

	tab_info.base_addr = HI_SDK_L0_TAB_PKE_TOP_KRAM_BASE;
	tab_info.tab_len = HI_SDK_L0_TAB_PKE_TOP_KRAM_LEN;
	tab_info.item_size =
		sizeof(struct hi_sdk_l0_tab_pke_top_kram_s);
	return hi_sdk_l0_tab_read(&tab_info, data, outlen);
}

hi_uint32 hi_sdk_l0_tab_set_pke_top_rram( hi_void *data,
	hi_uint32 inlen, hi_uint32 *outlen )
{
	struct hi_sdk_l0_tab_info_s tab_info;

	tab_info.base_addr = HI_SDK_L0_TAB_PKE_TOP_RRAM_BASE;
	tab_info.tab_len = HI_SDK_L0_TAB_PKE_TOP_RRAM_LEN;
	tab_info.item_size =
		sizeof(struct hi_sdk_l0_tab_pke_top_rram_s);
	return hi_sdk_l0_tab_write(&tab_info, data, outlen);
}

hi_uint32 hi_sdk_l0_tab_get_pke_top_rram(hi_void *data,
	hi_uint32 inlen, hi_uint32 *outlen )
{
	struct hi_sdk_l0_tab_info_s tab_info;

	tab_info.base_addr = HI_SDK_L0_TAB_PKE_TOP_RRAM_BASE;
	tab_info.tab_len = HI_SDK_L0_TAB_PKE_TOP_RRAM_LEN;
	tab_info.item_size =
		sizeof(struct hi_sdk_l0_tab_pke_top_rram_s);
	return hi_sdk_l0_tab_read(&tab_info, data, outlen);
}
