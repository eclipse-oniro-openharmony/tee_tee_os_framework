#ifndef _NPU_TASK_SEC_H_
#define _NPU_TASK_SEC_H_

typedef void (* NPU_RESET_CALLBACK_FUNC)(unsigned int);
typedef void (* NPU_COMMON_LOCK_FUNC)(unsigned int);
typedef void (* NPU_COMMON_UNLOCK_FUNC)(unsigned int);

/* task */
typedef struct {
    NPU_RESET_CALLBACK_FUNC  pf_npu_reset;
    NPU_COMMON_LOCK_FUNC   pf_npu_common_lock;
    NPU_COMMON_UNLOCK_FUNC pf_npu_common_unlock;
} NPU_CALLBACK_FUNC_S;

int npu_push_task(unsigned int* arg, unsigned int irq_num);

void npu_core_irq_handler(unsigned int core_id, unsigned int irq_io_addr);

int npu_task_finish_interrupt_clear(unsigned int core_id);

int npu_task_write_inst(unsigned int core_id, const char *buf, unsigned int count, int file_pos);

int npu_task_llseek_proc(unsigned int core_id, int file_pos, int off, int whence);

int npu_task_read_dword(unsigned int core_id, int offset);

int npu_task_write_dword(unsigned int core_id, int offset, int data);

int npu_task_set_boot_inst(unsigned int core_id, bool cfg_flag, unsigned int data);

int npu_task_init(unsigned int core_num, NPU_CALLBACK_FUNC_S* callback_fun_ptr);

void npu_task_exit(void);

void npu_task_restore(unsigned int core_id);

#endif
