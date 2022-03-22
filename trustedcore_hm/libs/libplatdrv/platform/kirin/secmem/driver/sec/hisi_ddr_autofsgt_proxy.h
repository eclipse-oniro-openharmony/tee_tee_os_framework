/*
 * Copyright @ Huawei Technologies Co., Ltd. 2019-2029. All rights reserved.
 * File Name: hisi_ddr_autofsgt_proxy.h
 * Description: head file of ddr_autofsgt_proxy, for 990 and after.
 * Author: l00353600
 * Create: 2019-7-2
 */

#ifndef __HISI_DDR_AUTOFSGT_PROXY_H__
#define __HISI_DDR_AUTOFSGT_PROXY_H__

#define WRITE_MASK_SHIFT	(16)

#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_BALTIMORE)
typedef enum {
	DDR_AUTOFSGT_HIFI_SET,
	DDR_AUTOFSGT_HIFI_CLEAN,
	DDR_AUTOFSGT_KERNEL_RO,
	DDR_AUTOFSGT_SUBBIT_RGN_CFG,
	DDR_AUTOFSGT_NORMAL_RGN_CFG,
	DDR_AUTOFSGT_FACE_CFG,
	DDR_AUTOFSGT_CHECK_UNSEC_SGLIST,
	DDR_AUTOFSGT_SEC_RGN_INIT,
	DDR_AUTOFSGT_CA_RD_CFG,
	DDR_AUTOFSGT_TZMP2_CFG,
	DDR_AUTOFSGT_TZMP2_INIT,
	DDR_AUTOFSGT_CLIENT_MAX = 32,
} DDR_AUTOFSGT_PROXY_SECOS_CLIENT_ID;
#endif

int ddr_autofsgt_ctrl(unsigned int client, unsigned int cmd);

#endif /* end of hisi_ddr_autofsgt_proxy.h */
