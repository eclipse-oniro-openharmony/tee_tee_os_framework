/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description:ddr autofsgt client in secure os, for sec protection
 * Author: bujing
 * Create: 2020-9-23
 */

#ifndef __HISI_DDR_AUTOFSGT_PROXY_BURBANK_H__
#define __HISI_DDR_AUTOFSGT_PROXY_BURBANK_H__

#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_BURBANK)
enum ddr_autofsgt_proxy_secos_client_id {
	DDR_AUTOFSGT_HIFI_SET,
	DDR_AUTOFSGT_HIFI_CLEAN,
	DDR_AUTOFSGT_SUBBIT_RGN_CFG,
	DDR_AUTOFSGT_FACE_CFG,
	DDR_AUTOFSGT_CHECK_UNSEC_SGLIST,
	DDR_AUTOFSGT_SEC_RGN_INIT,
	DDR_AUTOFSGT_CA_RD_CFG,
	DDR_AUTOFSGT_TZMP2_CFG,
	DDR_AUTOFSGT_TZMP2_INIT,
	DDR_AUTOFSGT_CLIENT_MAX = 32,
};
#endif

int ddr_autofsgt_ctrl(unsigned int client, unsigned int cmd);

#endif