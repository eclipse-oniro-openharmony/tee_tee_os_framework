#ifndef _NPU_TASK_SSWQ_SEC_H_
#define _NPU_TASK_SSWQ_SEC_H_
/**
 * NPU_IE_REG
 */
#define WORK_QUEUE_FINISH_IE_BIT        (1)
#define WORK_QUEUE_FINISH_IE_MASK       (0x1<<WORK_QUEUE_FINISH_IE_BIT)
#define WORK_QUEUE_NORMAL_FINISH_IE_BIT (0)
#define NORMAL_FINISH_IE_MASK           (0x1<<WORK_QUEUE_NORMAL_FINISH_IE_BIT)

/**
 * NPU_IS_REG
 */
#define SRAM_ERROR_INT_BIT              (8)
#define SRAM_ERROR_INT_MASK             (0x1<<SRAM_ERROR_INT_BIT)
#define INTERRUPTINST_INT_BIT           (7)
#define INTERRUPTINST_INT_MASK          (0x1<<INTERRUPTINST_INT_BIT)
#define NPU_INTERRUPT_BIT               (6)
#define NPU_INTERRUPT_MASK              (0x1<<NPU_INTERRUPT_BIT)
#define NPU_CONTROL_INT_BIT             (5)
#define NPU_CONTROL_INT_MASK            (0x1<<NPU_CONTROL_INT_BIT)
#define NPU_WATCH_DOG_BIT               (4)
#define NPU_WATCH_DOG_MASK              (0x1<<NPU_WATCH_DOG_BIT)
#define WORK_QUEUE_ALL_FINISH_IS_BIT    (3)
#define WORK_QUEUE_ALL_FINISH_IS_MASK   (0x1<<WORK_QUEUE_ALL_FINISH_IS_BIT)
#define WORK_QUEUE_MASK_FINISH_IS_BIT   (2)
#define WORK_QUEUE_MASK_FINISH_IS_MASK  (0x1<<WORK_QUEUE_MASK_FINISH_IS_BIT)
#define WORK_QUEUE_FINISH_IS_BIT        (1)
#define WORK_QUEUE_FINISH_IS_MASK       (0x1<<WORK_QUEUE_FINISH_IS_BIT)
#define NORMAL_FINISH_IS_BIT            (0)
#define NORMAL_FINISH_IS_MASK           (0x1<<NORMAL_FINISH_IS_BIT)

/* SSWQ_WORK_QUEUE_INFO_REG
 */
#define LOW_EMPTY_ID_BIT            (24)
#define LOW_EMPTY_ID_MASK           (0xF<<LOW_EMPTY_ID_BIT)
#define HIGH_EMPTY_ID_BIT           (20)
#define HIGH_EMPTY_ID_MASK          (0xF<<HIGH_EMPTY_ID_BIT)
#define WORKING_ID_BIT              (16)
#define WORKING_ID_MASK             (0xF<<WORKING_ID_BIT)
#define LOW_FIFO_COUNT_BIT          (12)
#define LOW_FIFO_COUNT_MASK         (0xF<<LOW_FIFO_COUNT_BIT)
#define HIGH_FIFO_COUNT_BIT         (8)
#define HIGH_FIFO_COUNT_MASK        (0xF<<HIGH_FIFO_COUNT_BIT)
#define TOTAL_FIFO_COUNT_BIT        (4)
#define TOTAL_FIFO_COUNT_MASK       (0xF<<TOTAL_FIFO_COUNT_BIT)
#define LOW_FIFO_FULL_BIT           (2)
#define LOW_FIFO_FULL_MASK          (0x1<<LOW_FIFO_FULL_BIT)
#define HIGH_FIFO_FULL_BIT          (1)
#define HIGH_FIFO_FULL_MASK         (0x1<<HIGH_FIFO_FULL_BIT)
#define TOTAL_FIFO_FULL_BIT         (0)
#define TOTAL_FIFO_FULL_MASK        (0x1<<TOTAL_FIFO_FULL_BIT)
/**
 * SSWQ_WORK_QUEUE_FINISH_REG
 */
#define WORK_QUEUE_COMPLETE_STATUS_BIT  (16)
#define WORK_QUEUE_COMPLETE_STATUS_MASK (0xFFFF<<WORK_QUEUE_FINISH_BIT)
#define WORK_QUEUE_FINISH_BIT           (0)
#define WORK_QUEUE_FINISH_MASK          (0xFFFF<<WORK_QUEUE_FINISH_BIT)
/**
 * SSWQ_PUSH_WORK_QUEUE_REG
 */
#define PUSH_WORK_QUEUE_EN_BIT      (16)
#define PUSH_WORK_QUEUE_EN_MASK     (0x1<<PUSH_WORK_QUEUE_EN_BIT)
#define WORK_QUEUE_SILENCE_EN_BIT   (9)
#define WORK_QUEUE_SILENCE_EN_MASK  (0x1<<WORK_QUEUE_SILENCE_EN_BIT)
#define WORK_QUEUE_MASK_EN_BIT      (8)
#define WORK_QUEUE_MASK_EN_MASK     (0x1<<WORK_QUEUE_MASK_EN_BIT)
#define WORK_QUEUE_ID_BIT           (0)
#define WORK_QUEUE_ID_MASK          (0xF)
/**
 * SSWQ_SELF_START_CONFIG_REG
 */
#define SELF_START_CONFIG_BIT       (0)
#define SELF_START_CONFIG_MASK      (0xF<<SELF_START_CONFIG_BIT)
/**
 * SSWQ_SELF_START_ADDR_LO_REG
 */
#define SELF_START_ADDR_LO_BIT      (0)
#define SELF_START_ADDR_LO_MASK     (0xFFFFFFFF<<SELF_START_ADDR_LO_BIT)
/**
 * SSWQ_SELF_START_ADDR_HI_REG
 */
#define SELF_START_ADDR_HI_BIT      (0)
#define SELF_START_ADDR_HI_MASK     (0xFFFFFFFF<<SELF_START_ADDR_HI_BIT)
/**
 * SSWQ_SELF_START_SIZE_REG
 */
#define SELF_STARRT_SIZE_BIT        (0)
#define SELF_STARRT_SIZE_MASK       (0xFFFFFFFF<<SELF_STARRT_SIZE_BIT)
/**
 * SSWQ_SELF_START_ID_REG
 */
#define SELF_STARRT_TASK_ID_BIT     (16)
#define SELF_STARRT_TASK_ID_MASK    (0xFFFF<<SELF_STARRT_TASK_ID_BIT)
#define SELF_STARRT_THREAD_ID_BIT   (0)
#define SELF_STARRT_THREAD_ID_MASK  (0xFFFF<<SELF_STARRT_THREAD_ID_BIT)
/**
 * SSWQU SOFT RESET
 */
#define SSWQ_SOFT_RESET_BIT             (0)
#define SSWQ_SOFT_RESET_MASK            (0x1 << SSWQ_SOFT_RESET_BIT)

/* the npu task prority level */
typedef enum {
    NPU_TASK_PRIO_HI = 0,
    NPU_TASK_PRIO_LOW,
    NPU_TASK_PRIO_NUM
} NPU_TASK_PRIORITY_E;

int npu_task_sswq_init(void);

void npu_task_sswq_exit(void);

int npu_push_sswq_task(const void *arg);

void npu_sswq_task_restore(unsigned int core_id);

void npu_sswq_get_interrupt_status(unsigned int core_id);

void npu_sswq_core_interrupt_handler(unsigned int core_id);

void npu_sswq_workqueue_finish_reg_clear(unsigned int core_id);

void npu_sswq_interrupt_msg_clear(unsigned int core_id);

#endif

