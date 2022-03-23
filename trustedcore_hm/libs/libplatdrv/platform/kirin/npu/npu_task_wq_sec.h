#ifndef _NPU_TASK_WQ_SEC_H_
#define _NPU_TASK_WQ_SEC_H_

int npu_push_wq_task(const void *arg, unsigned int irq_num);

int npu_task_wq_init(void);

void npu_task_wq_exit(void);

bool npu_get_wq_task(unsigned int core_id);

int npu_write_when_npu_down(NPU_REG_SPACE_S* reg_space, const char *buf, unsigned int count, unsigned int file_pos);

void npu_start_wq_next_task(unsigned int core_id);

void npu_wq_task_restore(unsigned int core_id);

#endif
