/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description:about npu firmware
 */
#ifndef __NPU_FIRMWARE_H
#define __NPU_FIRMWARE_H

#define DEVDRV_TS_BINARY_PATH      "/vendor/firmware/tsch_fw.bin"
#define DEVDRV_AICPU_BINARY_PATH  "/vendor/firmware/aicpu_fw.bin"

#define TS_FW_REMAP_SIZE (512*1024)
#define TS_FW_MAX_SIZE (1024*1024)

#define DEVDRV_TS_BIN_CHEKC_LEN        32
#define DEVDRV_TS_BIN_MAX_SEGMENT_NUM  16

#define BUFF_LEN 512

enum npu_cpu_type {
	DEVDRV_FW_TYPE_AICPU,
	DEVDRV_FW_TYPE_TS,
	DEVDRV_FW_TYPE_MAX,
};

struct npu_check_sum {
	u8 check[DEVDRV_TS_BIN_CHEKC_LEN];
};

struct npu_ts_bin_segment {
	u32 offset;
	u32 len;
	struct npu_check_sum segment_check;
};

struct npu_ts_bin_info {
	u32 ts_check_file;
	u32 fw_data_len;
	struct npu_check_sum fw_data_check;
	u32 segment_num;
	struct npu_ts_bin_segment segment[DEVDRV_TS_BIN_MAX_SEGMENT_NUM];
};

int npu_load_cpu_fw(void);
u64 npu_get_firmware_phy_addr(int type);

#endif
