#ifndef _NPU_TASK_PUBLIC_SEC_H_
#define _NPU_TASK_PUBLIC_SEC_H_

#include "npu_task_sec.h"

#define NPU_DEBUG_SSWQ_REG

#define SUCCESS                     (0)
#define NPU_SSWQ_LOW_FIFO_DEPTH     (8)
#define NPU_SSWQ_HIGH_FIFO_DEPTH    (8)
#define NPU_SSWQ_FIFO_DEPTH         (8)
#define NPU_PM_VOTE_NUM_MAX         (NPU_SSWQ_LOW_FIFO_DEPTH + NPU_SSWQ_HIGH_FIFO_DEPTH)

#define NPU_WATCHDOG_TIMEOUT        (0x23C34600) /*600000000 */

#define SOC_NPU_SSWQ_WORK_QUEUE_INFO_ADDR(base)        ((base) + (0x0074))
#define SOC_NPU_SSWQ_WORK_QUEUE_FINISH_ADDR(base)      ((base) + (0x0078))
#define SOC_NPU_SSWQ_SELF_START_CONFIG_ADDR(base)      ((base) + (0x007C))
#define SOC_NPU_SSWQ_SELF_START_LO_ADDR(base)          ((base) + (0x0080))
#define SOC_NPU_SSWQ_SELF_START_HI_ADDR(base)          ((base) + (0x0084))
#define SOC_NPU_SSWQ_SELF_START_SIZE_ADDR(base)        ((base) + (0x0088))
#define SOC_NPU_SSWQ_SELF_START_ID_ADDR(base)          ((base) + (0x008C))
#define SOC_NPU_SSWQ_PUSH_WORK_QUEUE_ADDR(base)        ((base) + (0x0090))
#define SOC_NPU_SSWQ_SOFT_RESET_ADDR(base)             ((base) + (0x00A8))
#define SOC_NPU_SSWQ_DDR_BASE_ADDR(base)               ((base) + (0x00C0))
#define SOC_NPU_IE_ADDR(base)                          ((base) + (0x0098))
#define SOC_NPU_IS_ADDR(base)                          ((base) + (0x00A0))
#define SOC_NPU_INTERRUPT_INST_ADDR(base)              ((base) + (0x00AC))
#define SOC_NPU_INTERRUPT_PC_ADDR(base)                ((base) + (0x00B0))
#define SOC_NPU_CONTROL_ID_ADDR(base)                  ((base) + (0x0200))
#define SOC_NPU_CONTROL_TIMER_ADDR(base)               ((base) + (0x0210))
#define SOC_NPU_WATCH_DOG_TIMER_LOW_ADDR(base)         ((base) + (0x0204))
#define SOC_NPU_WATCH_DOG_TIMER_HIGH_ADDR(base)        ((base) + (0x0208))
#define SOC_NPU_WATCH_DOG_ADDR(base)                   ((base) + (0x020C))
#define SOC_NPU_ID_ADDR(base)                          ((base) + (0x40000))
#define SOC_NPU_TIMER_ADDR(base)                       ((base) + (0x40008))

/* ICS start Register  
    SOC_ICS_START_UNION */
#define SOC_ICS_START_ADDR(base)                      ((base) + (0x0018))

/* ICS status Register
   SOC_ICS_STATUS_UNION */
#define SOC_ICS_STATUS_ADDR(base)                     ((base) + (0x0020))

/* ICS base address
   SOC_ICS_BASE_ADDR_UNION */
#define SOC_ICS_BASE_ADDR_ADDR(base)                  ((base) + (0x0028))

typedef struct {
    /* config reg addr */
    unsigned int config_reg_length;
    unsigned int config_reg_phys_addr;
    unsigned int config_reg_virt_addr;

    /* inst reg addr */
    unsigned int inst_ram_size;
    unsigned int inst_ram_phys_addr;
    unsigned int inst_ram_virt_addr;
} NPU_REG_SPACE_S;

typedef int Priority;

/* the NPU task type */
typedef enum taskType {
    NPU_TASK_ENUM_START = 0,
    NPU_NONE_TASK = NPU_TASK_ENUM_START,
    /*First*/
    NPU_COMPUTE_TASK = 1,
    NPU_SYNC_TASK = 4,
    //Add new to here!
    NPU_TASK_ENUM_END
} taskType_t;

typedef enum taskFlag{
    NPU_TASK_FLAG_START = 0,
    NPU_TASK_FLAG_NONE = NPU_TASK_FLAG_START,
    /*First*/
    NPU_TASK_FLAG_SYNC_WAITING,
    NPU_TASK_FLAG_SYNC_DONE,
    //Add new to here!
    NPU_TASK_FLAG_END
} taskFlag_t;

/* the NPU task element */
typedef struct taskStruct {
    unsigned int taskType;//define different cmd type
    taskFlag_t* ptaskFlag;//use to mark task status
    unsigned long long offchipInstAddr;
    unsigned long long offchipInstSize;
    unsigned int taskId;
    Priority prior;
} taskElement;

typedef enum {
    NPU_TASK_START_NONE = 0,
    NPU_TASK_START_DOING,
    NPU_TASK_START_DONE,
} COMPUTING_TASK_STATE_E;

typedef struct {
    COMPUTING_TASK_STATE_E state;
    taskElement start_element;
} COMPUTING_TASK_ELEMENT;

typedef struct {
    unsigned int core_num;
    unsigned long long watchdog_timer[MAX_SUPPORT_CORE_NUM];
    NPU_REG_SPACE_S reg_space[MAX_SUPPORT_CORE_NUM];
    COMPUTING_TASK_ELEMENT start_task[MAX_SUPPORT_CORE_NUM];
    NPU_CALLBACK_FUNC_S callback_fun;
} NPU_TASK_PRIVATE_S;

extern NPU_TASK_PRIVATE_S g_task_private;

#define NPU_DUALINT_TO_LONG(num1, num2)  (((unsigned long long)(num1) << 32) | (unsigned long long)(num2))

/* the npu task status */
typedef enum {
    NPU_SSWQ_TASK_START = 0,
    NPU_SSWQ_TASK_NONE = NPU_SSWQ_TASK_START,
    /*First*/
    NPU_SSWQ_TASK_WAITING,
    NPU_SSWQ_TASK_DONE,
    /*Add new to here*/
    NPU_SSWQ_TASK_END
} NPU_SSWQ_TASK_STATUS_E;

/* the npu task type */
typedef enum {
    NPU_SSWQU_TASK_ENUM_START = 0,
    NPU_SSWQU_NONE_TASK = NPU_SSWQU_TASK_ENUM_START,
    /*First*/
    NPU_SSWQU_SILENCE_TASK  = 1,
    NPU_SSWQU_MASK_TASK     = 2,
    NPU_SSWQU_NOTIFY_TASK   = 3,
    NPU_WQ_SYNC_TASK        = 4,
    /* Add new to here! */
    NPU_SSWQU_TASK_ENUM_END
} NPU_SSWQ_TASK_TYPE_E;

/* the npu task element */
typedef struct {
    unsigned int core_id;
    unsigned int task_type;
    unsigned int inst_size;
    unsigned int task_id;
    unsigned int thread_id;
    unsigned int task_config;
    unsigned int task_priority;
    unsigned long long inst_addr_off;
    unsigned long long ddr_base_addr;
    /*use to mark task status*/
    volatile NPU_SSWQ_TASK_STATUS_E *task_status;
} NPU_SSWQ_TASK_ELEMENT_S;

int npu_task_reset_proc(unsigned int core_id);

int npu_task_fifo_opt_lock(unsigned int core_id);

int npu_task_fifo_opt_unlock(unsigned int core_id);

void npu_task_watchdog_start(unsigned int core_id);

#endif

