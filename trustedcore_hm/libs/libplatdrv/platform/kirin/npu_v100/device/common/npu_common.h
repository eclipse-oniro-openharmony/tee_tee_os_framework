/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description:about npu add and remove
 */
#ifndef NPU_COMMON_H
#define NPU_COMMON_H

#include <string.h>
#include <list.h>
#include <sre_hwi.h>
#include <sre_typedef.h>
#include <secure_gic_common.h>
#include <tee_defines.h>
#include "pthread.h"
#include "drv_log.h"
#include "securec.h"
#include "npu_custom_info_share.h"

#define BITS_PER_BYTE 8
#define DIV_ROUD_UP(n, d) (((n) + (d)-1) / (d))
#define BITS_TO_BYTE(nr) DIV_ROUD_UP(nr, BITS_PER_BYTE * sizeof(u8))
#define DECLARE_BITMAP(name, bits) u8 name[BITS_TO_BYTE(bits)]

#define NPU_DEV_NUM		1
#define UNUSED(x) ((void)(x))

#define DEVDRV_NO_NEED_TO_INFORM  0
#define DEVDRV_HAVE_TO_INFORM	1

#define DEVDRV_WAKELOCK_SIZE	56
#define DEVDRV_INVALID_FD_OR_NUM	(-1)
#define DEVDRV_SQ_CQ_MAP     0
#define DEVDRV_SQ_FLOOR 	   16
#define DEVDRV_CQSQ_INVALID_INDEX  0xFEFE
#define CQ_HEAD_UPDATE_FLAG	   0x1
#define DEVDRV_REPORT_PHASE	   0x8000

#define MAX_MEM_INFO_NUM	4
#define NPU_DDR_CONFIG_VALID_MAGIC      0X5A5A5A5A

typedef struct {
	volatile int counter;
} atomic_t;

#define atomic_inc(x) (__sync_fetch_and_add (&(x)->counter, 1))
#define atomic_dec(x) (__sync_sub_and_fetch(&(x)->counter, 1))
#define atomic_read(v)      (*(volatile int *)&(v)->counter)
#define atomic_set(x, i)     (((x)->counter) = (i))

enum secure_state {
	NPU_NONSEC = 0,
	NPU_SEC = 1,
	NPU_SEC_UNDEFINED = 0xFFFFF,
};

struct npu_mailbox_sending_queue {
	volatile int status;	/* mailbox busy or free */
	int mailbox_type;	/* mailbox communication method: SPI+SRAM or IPC */
	struct list_head list_header;
};

struct npu_mailbox {
	struct npu_mailbox_sending_queue send_queue;
	u8 *send_sram;
	u8 *receive_sram;
	volatile int working;
};

typedef struct excep_time_t {
	UINT64 tv_sec;
	UINT64 tv_usec;
} excep_time;

#define DATA_CEIL(data, size)	(((((data) - 1) / (size)) + 1) * (size))
#define DATA_FLOOR(data, size)	(((data) / (size)) * (size))

struct npu_event_info {
	int id;
	u32 devid;
	struct list_head list;
};

struct npu_manager_lpm3_func {
	u32 lpm3_heart_beat_en;
};

struct npu_manager_ts_func {
	u32 ts_heart_beat_en;
};

struct npu_device_manager_config {
	struct npu_manager_ts_func ts_func;
	struct npu_manager_lpm3_func lpm3_func;
};

struct npu_dev_ctx {
	/* device id assigned by local device driver */
	u8 devid;
	u8 plat_type;

	u32 sink_stream_num;
	u32 stream_num;
	u32 event_num;
	u32 sq_num;
	u32 cq_num;
	u32 model_id_num;
	u32 task_id_num;
	u32 notify_id_num;

	struct list_head proc_ctx_list;
	struct list_head rubbish_context_list;
	struct list_head stream_available_list;
	struct list_head sink_stream_available_list;
	struct list_head event_available_list;
	struct list_head model_available_list;
	struct list_head task_available_list;
	struct list_head notify_available_list;

	struct list_head sq_available_list;
	struct list_head cq_available_list;
	struct list_head resource_software_list;
	struct list_head resource_hardware_list;

	struct npu_mailbox mailbox;
	u32 ai_cpu_core_num;
	u32 ai_core_num;
	u32 ai_subsys_ip_broken_map;

	struct npu_device_manager_config config;
	struct npu_hardware_inuse inuse;

	void *dfx_cqsq_addr;	// pointer struct npu_dfx_cqsq
	u32 ts_work_status;
	u32 secure_state; /* indicates npu state:secure or non_secure */

	void *event_addr;
	void *sq_sub_addr;
	void *cq_sub_addr;
	void *stream_sub_addr;
	void *sink_stream_sub_addr;
	void *model_addr;
	void *task_addr;
	void *notify_addr;

	pthread_mutex_t mailbox_mutex;
	pthread_mutex_t stream_mutex;
	pthread_mutex_t event_mutex;
	pthread_mutex_t model_mutex;
	pthread_mutex_t task_mutex;
	pthread_mutex_t notify_mutex;
	pthread_mutex_t cma_mutex;

	pthread_mutex_t calc_cq_mutex;
	pthread_mutex_t open_close_mutex;
	pthread_mutex_t pm_mutex; // power management
	pthread_mutex_t mbx_send_mutex; // protect mailbox sending to avoid multhread problem

	u32 power_stage; /* for power manager */
	struct list_head parameter_list;	/* list for parameter */

	void *hisi_svm;

	atomic_t accessible;
	atomic_t poweron_access;
	atomic_t poweron_success;
};

struct npu_chip_cfg {
	u32 valid_magic; /* if value is 0x5a5a5a5a, valid_magic is ok */
	u32 aicore_disable_bitmap; /* bit0 is aicore0, bit1 is aicore1;each bit:0:enable 1:disable */
};

void dev_ctx_array_init(void);

int npu_add_proc_ctx(struct list_head *proc_ctx, u8 dev_id);

int npu_remove_proc_ctx(struct list_head *proc_ctx, u8 dev_id);

int npu_add_proc_ctx_to_rubbish_ctx_list(struct list_head *proc_ctx, u8 dev_id);

void set_dev_ctx_with_dev_id(struct npu_dev_ctx *dev_ctx, u8 dev_id);

struct npu_dev_ctx *get_dev_ctx_by_id(u8 dev_id);

void npu_set_sec_stat(u8 dev_id, u32 state);

u32 npu_get_sec_stat(u8 dev_id);

int bitmap_set(u8 map[], u32 map_size, u32 bit_pos);

int bitmap_clear(u8 map[], u32 map_size, u32 bit_pos);

bool bitmap_occupied(u8 map[], u32 map_size, u32 bit_pos);

#define BITMAP_GET(val, pos)         (((val) >> (pos)) & 0x01)
#define BITMAP_SET(map, pos) bitmap_set(map, sizeof(map), pos)
#define BITMAP_CLEAR(map, pos) bitmap_clear(map, sizeof(map), pos)
#define BITMAP_OCCUPIED(map, pos) bitmap_occupied(map, sizeof(map), pos)

static inline int list_empty_careful(const struct list_head *head)
{
	struct list_head *next = head->next;
	return (next == head) && (next == head->prev);
}

#define list_first_entry(ptr, type, member) \
	list_entry((ptr)->next, type, member)

#define IRQF_TRIGGER_NONE	0x00000000
#define IRQF_TRIGGER_RISING	0x00000001
#define IRQF_TRIGGER_FALLING	0x00000002
#define IRQF_TRIGGER_HIGH	0x00000004
#define IRQF_TRIGGER_LOW	0x00000008
#define IRQF_TRIGGER_MASK	(IRQF_TRIGGER_HIGH | IRQF_TRIGGER_LOW | \
				IRQF_TRIGGER_RISING | IRQF_TRIGGER_FALLING)
#define IRQF_TRIGGER_PROBE	0x00000010

typedef enum {
	IRQ_NONE,
	IRQ_HANDLED
} irqreturn_t;
typedef irqreturn_t (*irq_handler_t)(void *);

static inline int request_irq(unsigned int irq, irq_handler_t handler,
                              unsigned long flags, const char *name, void *arg)
{
	UNUSED(flags);
	UNUSED(name);

	UINT32 ret = SRE_HwiCreate((HWI_HANDLE_T)(irq), 0xa0, INT_SECURE, (HWI_PROC_FUNC)handler, (HWI_ARG_T)arg);
	if (ret != SRE_OK) {
		NPU_ERR("SRE_HwiCreate irq %d errorNO 0x%x\n", irq, ret);
		return ret;
	}
	// SRE_HwiEnable do it at NPU internal side
	NPU_INFO("request_irq  irq = %d  ret = %d success", irq, ret);
	return ret;
}

static inline void free_irq(unsigned int irq, void *arg)
{
	UNUSED(arg);
	UINTPTR ret;
	// SRE_HwiDisable do it at NPU internal side
	ret = SRE_HwiDelete((HWI_HANDLE_T)irq);
	if (ret != SRE_OK) {
		NPU_ERR("SRE_HwiDelete irq %d errorNO 0x%x\n", irq, ret);
		return;
	}
}

#define isb() __asm__ __volatile__ ("isb" : : : "memory")
#define dsb() __asm__ __volatile__ ("dsb" : : : "memory")
#define dmb() __asm__ __volatile__ ("dmb" : : : "memory")
static inline void mb()
{
	asm volatile("dsb sy"
	             :
	             :
	             : "memory");
}


#define MUTEX_SWITCH_ON

#ifdef MUTEX_SWITCH_ON
/* ************************************************************************************** */
#define MUTEX_LOCK(resource)	\
	do { \
		struct npu_dev_ctx *_dev_ctx;	\
		_dev_ctx = get_dev_ctx_by_id(0); \
		(void)pthread_mutex_lock(&_dev_ctx->resource##_mutex); \
	} while (0)

#define MUTEX_UNLOCK(resource)  \
	do { \
		struct npu_dev_ctx *_dev_ctx;	\
		_dev_ctx = get_dev_ctx_by_id(0); \
		(void)pthread_mutex_unlock(&_dev_ctx->resource##_mutex); \
	} while (0)

#else  // one hiai ta no need mutex indeed

#define MUTEX_LOCK(resource)	\
	do { \
	} while (0)

#define MUTEX_UNLOCK(resource)  \
	do { \
	} while (0)
#endif

#endif /* __NPU_COMMON_H */
