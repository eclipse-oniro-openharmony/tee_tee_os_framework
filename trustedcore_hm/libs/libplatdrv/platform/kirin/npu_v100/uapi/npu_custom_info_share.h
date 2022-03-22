/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description:about npu custom info share
 */

#ifndef __NPU_CUSTOM_STRUCT_SHARE_H
#define __NPU_CUSTOM_STRUCT_SHARE_H
#include <stdint.h> // uint64_t
#include <sre_typedef.h> // UINT32
#include "npu_spec_share.h"
typedef int32_t pid_t;

#define u64 uint64_t
#define u32 uint32_t
#define u16 uint16_t
#define u8  uint8_t

// vaddr for hiai ta access
typedef struct npu_shm_vaddr {
	uintptr_t info_vaddr;
	uintptr_t sq_vaddr;
	uintptr_t cq_vaddr;
	uintptr_t ts_log_vaddr; // tscpu log vaddr
	uintptr_t pesistent_vaddr; // pesistent task buff vaddr
} npu_shm_vaddr_t;

enum npu_ts_status {
	DEVDRV_TS_WORK = 0x0,
	DEVDRV_TS_SLEEP,
	DEVDRV_TS_DOWN,
	DEVDRV_TS_INITING,
	DEVDRV_TS_BOOTING,
	DEVDRV_TS_FAIL_TO_SUSPEND,
	DEVDRV_TS_MAX_STATUS,
};

struct npu_ts_sq_info {
	u32 head;
	u32 tail;
	u32 credit;
	u32 index;

	int uio_fd;
	u8 *uio_addr;
	int uio_size;

	u32 stream_num;
	u64 send_count;

	void *sq_sub;
};

struct npu_ts_cq_info {
	u32 head;
	u32 tail;
	volatile u32 count_report;
	u32 index;
	u32 phase;
	u32 int_flag;

	int uio_fd;
	u8 *uio_addr;
	int uio_size;

	u32 stream_num;
	u64 receive_count;

	void *cq_sub;

	u8 slot_size;
};

struct npu_stream_info {
	int id;
	u32 devid;
	u32 cq_index;
	u32 sq_index;
	void *stream_sub;
	int pid; // ta pid in teeos
	u32 strategy;
};

#define DEVDRV_SQ_INFO_OCCUPY_SIZE		\
	(sizeof(struct npu_ts_sq_info) * DEVDRV_MAX_SQ_NUM)
#define DEVDRV_CQ_INFO_OCCUPY_SIZE		\
	(sizeof(struct npu_ts_cq_info) * DEVDRV_MAX_CQ_NUM)
#define DEVDRV_STREAM_INFO_OCCUPY_SIZE	\
	(sizeof(struct npu_stream_info) * DEVDRV_MAX_STREAM_ID)

#define DEVDRV_MAX_INFO_SIZE	   \
	(DEVDRV_SQ_INFO_OCCUPY_SIZE + \
		DEVDRV_CQ_INFO_OCCUPY_SIZE + \
			DEVDRV_STREAM_INFO_OCCUPY_SIZE + \
				sizeof(u32))

struct npu_mailbox_user_message {
	u8 message_payload[64];
	int message_length;
	int feedback_num;
	u8 *feedback_buffer;	/*
				 * if a sync message need feedback, must alloc buffer for feedback data.
				 * if a async message need feedback, set this to null,
				 * because driver will send a callback parameter to callback func,
				 * app has no need to free callback parameter in callback func.
				 */
	int sync_type;
	int cmd_type;
	int message_index;
	int message_pid;
};

struct npu_mailbox_feedback {
	void (*callback)(void *data);
	u8 *buffer;
	int feedback_num;
	int process_result;
};

struct npu_user_parameter {
	u32 devid;
	u32 cq_slot_size;
	u16 disable_wakelock;
};

struct npu_svm_to_devid {
	u32 src_devid;
	u32 dest_devid;
	unsigned long src_addr;
	unsigned long dest_addr;
};

struct npu_notify_ioctl_info {
	u32 dev_id;
	u32 notify_id;
	u64 dev_addr;
	u64 host_addr;
	char name[DEVDRV_HCCL_NAME_SIZE];
};

struct npu_hardware_spec {
	u32 devid;
	u32 ai_core_num;
	u32 first_ai_core_id;
	u32 ai_cpu_num;
	u32 first_ai_cpu_id;
};

struct npu_hardware_inuse {
	u32 devid;
	u32 ai_core_num;
	u32 ai_core_error_bitmap;
	u32 ai_cpu_num;
	u32 ai_cpu_error_bitmap;
};

struct npu_manager_hccl_devinfo {
	u8 env_type;
	u32 dev_id;
	u32 ctrl_cpu_ip;
	u32 ctrl_cpu_id;
	u32 ctrl_cpu_core_num;
	u32 ctrl_cpu_endian_little;
	u32 ts_cpu_core_num;
	u32 ai_cpu_core_num;
	u32 ai_core_num;
	u32 ai_cpu_bitmap;
	u32 ai_core_id;
	u32 ai_cpu_core_id;
	u32 hardware_version;	/* mini, cloud, lite, etc. */

	u32 num_dev;
	u32 devids[DEVDRV_MAX_DAVINCI_NUM];
};

struct npu_sysrdy_info {
	u32 probe_dev_num;
	u32 rdy_dev_num;
};

enum npu_arch_type {
	ARCH_BEGIN = 0,
	ARCH_V100 = ARCH_BEGIN,
	ARCH_V200,
	ARCH_END,
};

enum npu_chip_type {
	CHIP_BEGIN = 0,
	CHIP_MINI = CHIP_BEGIN,
	CHIP_CLOUD,
	CHIP_LITE_PHOENIX,
	CHIP_LITE_ORLANDO,
	CHIP_TINY_PHOENIX,
	CHIP_LITE_DENVER,
	CHIP_LITE_LAGUNA,
	CHIP_LITE_BURBANK,
	CHIP_END,
};

enum npu_version {
	VER_BEGIN = 0,
	VER_NA = VER_BEGIN,
	VER_ES,
	VER_CS,
	VER_CS2,
	VER_END,
};

#define PLAT_COMBINE(arch, chip, ver) ((arch<<16) | (chip<<8) | (ver))
#define PLAT_GET_ARCH(type) ((type>>16) & 0xffff)
#define PLAT_GET_CHIP(type) ((type>>8) & 0xff)
#define PLAT_GET_VER(type)    (type & 0xff)

enum npu_hardware_version {
	DEVDRV_PLATFORM_MINI_V1 = PLAT_COMBINE(ARCH_V100, CHIP_MINI, VER_NA),
	DEVDRV_PLATFORM_CLOUD_V1 = PLAT_COMBINE(ARCH_V100, CHIP_CLOUD, VER_NA),
	DEVDRV_PLATFORM_LITE_PHOENIX_ES =
	    PLAT_COMBINE(ARCH_V100, CHIP_LITE_PHOENIX, VER_ES),
	DEVDRV_PLATFORM_LITE_PHOENIX_CS =
	    PLAT_COMBINE(ARCH_V100, CHIP_LITE_PHOENIX, VER_CS),
	DEVDRV_PLATFORM_LITE_PHOENIX_CS2 =
	    PLAT_COMBINE(ARCH_V100, CHIP_LITE_PHOENIX, VER_CS2),
	DEVDRV_PLATFORM_LITE_ORLANDO =
	    PLAT_COMBINE(ARCH_V100, CHIP_LITE_ORLANDO, VER_NA),
	DEVDRV_PLATFORM_TINY_PHOENIX_ES =
	    PLAT_COMBINE(ARCH_V100, CHIP_TINY_PHOENIX, VER_ES),
	DEVDRV_PLATFORM_TINY_PHOENIX_CS =
	    PLAT_COMBINE(ARCH_V100, CHIP_TINY_PHOENIX, VER_CS),
	DEVDRV_PLATFORM_LITE_DENVER =
	    PLAT_COMBINE(ARCH_V100, CHIP_LITE_DENVER, VER_NA),
	DEVDRV_PLATFORM_LITE_LAGUNA =
	    PLAT_COMBINE(ARCH_V100, CHIP_LITE_LAGUNA, VER_NA),
	DEVDRV_PLATFORM_LITE_BURBANK =
	    PLAT_COMBINE(ARCH_V100, CHIP_LITE_BURBANK, VER_NA),
	DEVDRV_PLATFORM_END,
};

struct npu_occupy_stream_id {
	u16 count;
	u16 id[DEVDRV_MAX_STREAM_ID];
};

struct npu_black_box_devids {
	u32 dev_num;
	u32 devids[DEVDRV_MAX_DAVINCI_NUM];
};

struct npu_black_box_user {
	u32 devid;
	u32 size;
	u64 phy_addr;
	void *dst_buffer;
	u32 thread_should_stop;
	u32 exception_code;
	u64 tv_sec;
	u64 tv_nsec;

	union {
		struct npu_black_box_devids bbox_devids;
	} priv_data;
};

struct npu_module_status {
	u8 lpm3_start_fail;
	u8 lpm3_lost_heart_beat;
	u8 ts_start_fail;
	u8 ts_lost_heart_beat;
	u8 ts_sram_broken;
	u8 ts_sdma_broken;
	u8 ts_bs_broken;
	u8 ts_l2_buf0_broken;
	u8 ts_l2_buf1_broken;
	u8 ts_spcie_broken;
	u8 ts_ai_core_broken;
	u8 ts_hwts_broken;
	u8 ts_doorbell_broken;
};

struct npu_get_user_config_para {
	char config_name[DEVDRV_USER_CONFIG_NAME_LEN];
	char config_value[DEVDRV_USER_CONFIG_VALUE_LEN];
	u32 config_value_len;
};

struct npu_get_device_boot_status_para {
	unsigned int devId;
	u32 boot_status;
};
struct npu_get_host_phy_mach_flag_para {
	unsigned int devId;
	unsigned int host_flag;
};

struct npu_emmc_voltage_para {
	int emmc_vcc;		// should be 2950 mv
	int emmc_vccq;		// should be 1800 mv
};

#define DMANAGE_ERROR_ARRAY_NUM 128
struct npu_error_code_para {
	int error_code_count;
	unsigned int error_code[DMANAGE_ERROR_ARRAY_NUM];
};
struct tsensor_ioctl_arg {
	u32 coreid;
	u32 result_size;
	u32 result[4];
};

/*
 * add necessary dfx function if you need
 */
enum npu_dfx_cmd {
	DEVDRV_DFX_QUERY_STATUS,
	DEVDRV_DFX_MAX_CMD,
};

/*
 * DEVDRV_DFX_QUERY_STATUS
 * add necessary value info if you need, remember add both user code and kernel code
 */
struct npu_status_info {
	u16 sq_head[DEVDRV_MAX_SQ_NUM];
	u16 sq_tail[DEVDRV_MAX_SQ_NUM];
	u16 cq_head[DEVDRV_MAX_CQ_NUM];
	u16 cq_tail[DEVDRV_MAX_CQ_NUM];
	u16 func_sq_head[DEVDRV_MAX_DFX_SQ_NUM];
	u16 func_sq_tail[DEVDRV_MAX_DFX_SQ_NUM];
	u16 func_cq_head[DEVDRV_MAX_DFX_CQ_NUM];
	u16 func_cq_tail[DEVDRV_MAX_DFX_CQ_NUM];
	u64 sq_addr[DEVDRV_MAX_SQ_NUM];
	u64 cq_addr[DEVDRV_MAX_CQ_NUM];
	u64 func_sq_addr[DEVDRV_MAX_DFX_SQ_NUM];
	u64 func_cq_addr[DEVDRV_MAX_DFX_CQ_NUM];
	u16 stream_sq[DEVDRV_MAX_STREAM_ID];
	u16 stream_cq[DEVDRV_MAX_STREAM_ID];
	u32 ts_beat_count;
	u32 m3_beat_count;
	u32 ts_status;
	u8 ts_beat_en;
	u8 m3_beat_en;
	u8 cq_phase[DEVDRV_MAX_CQ_NUM];
	u8 func_cq_phase[DEVDRV_MAX_DFX_CQ_NUM];
};

/* ioctl parameter */
struct npu_dfx_para {
	u32 devid;
	u32 cmd;
	void *in;
	void *out;
};

enum npu_container_cmd {
	DEVDRV_CONTAINER_NOTIFY,
	DEVDRV_CONTAINER_ALLOCATE_TFLOPS,
	DEVDRV_CONTAINER_IS_CONTAINER,
	DEVDRV_CONTAINER_DOCKER_EXIT,
	DEVDRV_CONTAINER_DOCKER_CREATE,	/* container tflops mode cmd end */

	/* container device assignment mode cmd begin */
	DEVDRV_CONTAINER_ASSIGN_NOTIFY,
	DEVDRV_CONTAINER_ASSIGN_ALLOCATE_DEVICES,
	DEVDRV_CONTAINER_ASSIGN_IS_ASSIGN_MODE,
	DEVDRV_CONTAINER_ASSIGN_SET_UUID,	/* container device assignment mode cmd end */

	DEVDRV_CONTAINER_IS_IN_CONTAINER,

	/* user for no plusgin container */
	DEVDRV_CONTAINER_OVERLAP_DAVINCI_DEVLIST, /* read davinci devlist from /dev directory */
	DEVDRV_CONTAINER_LOGICID_TO_PHYSICID,
	DEVDRV_CONTAINER_GET_BARE_PID,
	DEVDRV_CONTAINER_GET_BARE_TGID,

	DEVDRV_CONTAINER_MAX_CMD,
};

struct npu_container_para {
	struct npu_dfx_para para;
};

#define DEVDRV_MINI_TOTAL_TFLOP 16
#define DEVDRV_MINI_FP16_UNIT   1
#define DEVDRV_MINI_INT8_UNIT   2

struct npu_container_alloc_para {
	u32 num;
	u32 npu_id[DEVDRV_MAX_DAVINCI_NUM];
};

struct npu_container_tflop_config {
	u32 tflop_mode;
	u32 total_tflop;
	u32 alloc_unit;
	u32 tflop_num;
};

enum npu_run_mode {
	DEVDRV_NORMAL_MODE = 0,
	DEVDRV_CONTAINER_MODE,
	DEVDRV_MAX_RUN_MODE,
};

enum npu_container_tflop_mode {
	DEVDRV_FP16 = 0,
	DEVDRV_INT8,
	DEVDRV_MAX_TFLOP_MODE,
};

struct npu_time_sync {
	int tz_minuteswest;
	int tz_dsttime;
	u8 thread_should_exit;
};

#define DEVDRV_MAX_LIB_LENGTH    128

struct npu_load_kernel {
	unsigned int devid;
	unsigned int share;
	char libname[DEVDRV_MAX_LIB_LENGTH];
	unsigned char sha256[32];
	int pid;
	void *binary;
	unsigned int size;
};

struct npu_load_kernel_serve {
	struct npu_load_kernel load_kernel;
	u8 thread_should_exit;
	u8 save_state;		// succ: 0, fail: 1
};

/*
|___SQ___|____INFO_____|__DOORBELL___|___CQ____|
*/
typedef struct {
	u32 version;
	u32 cmd;
	u32 result;
	u32 arg_size; // the size of the secondary  structure point by arg
	// (use for ACCESS_CHECK remap plat_drv vaddr)
	u64 arg;
} npu_custom_para_t;


struct davinci_area_info {
	unsigned long va;
	unsigned long pa;
	unsigned long len;
};

#define UINT64  uint64_t
#define UINT32  uint32_t
#define UINT16  uint16_t
#define UINT8   uint8_t

struct process_info {
	pid_t vpid;
	UINT64 ttbr;
	UINT64 tcr;
	int pasid;
	UINT32 flags;
};

struct npu_chip_info {
	UINT32 l2_size;
	UINT32 reserved[3];
};

// for custom ioctl power up&down
typedef struct npu_secure_info {
	uint32_t secure_mode;
} npu_secure_info_t;

enum {
	STREAM_STRATEGY_NONSINK = 0,
	STREAM_STRATEGY_SINK = 1,
	STREAM_STRATEGY_MAX
};

struct npu_stream_strategy_ioctl_info {
	int stream_id;
	u32 strategy;
	u32 devid;
};

typedef struct ta_vm_area {		/* The first cache line has the info for VMA tree walking. */
	unsigned long vm_start;		/* Our start address within vm_mm. */
	unsigned long vm_end;		/* The first byte after our end address within vm_mm. */
	unsigned int vm_page_prot;		/* Access permissions of this VMA. */
	unsigned int vm_flags;		/* Flags, see mm.h. */
	/* Information about our backing store: */
	unsigned int vm_pgoff;		/* Offset (within vm_file) in PAGE_SIZE units */
	unsigned long ta_vaddr_after_drv_map;  /* output para */
} ta_vm_area_t;

// should be consistent with hiai ta side
typedef struct npu_unmap_ta_vaddr {
	uintptr_t ta_vaddr;
	u32 size;
} npu_unmap_ta_vaddr_t;

typedef struct {
	int fd;
} npu_ops_release_info;

typedef struct {
	int fd;
	unsigned int cmd;
	unsigned int *param;
	unsigned int param_size; /* indicate param mem size */
} npu_ops_ioctl_info;

#endif
