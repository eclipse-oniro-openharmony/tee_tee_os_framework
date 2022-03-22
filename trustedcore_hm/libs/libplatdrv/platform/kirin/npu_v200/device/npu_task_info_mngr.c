#include "npu_task_info_mngr.h"
#include "npu_base_define.h"

void npu_init_task_info_mngr(npu_task_info_mngr_t *mngr)
{
	int i = 0;
	INIT_LIST_HEAD(&(mngr->task_list));

	for (; i < DEVDRV_MAX_TASK_ID; ++i) {
		mngr->tasks[i].task_id = i;
		mngr->tasks[i].proc_ctx = NULL;
		INIT_LIST_HEAD(&(mngr->tasks[i].list_node));
		list_add(&(mngr->tasks[i].list_node), &(mngr->task_list));
	}
}

npu_task_info_t *npu_alloc_task_info(npu_task_info_mngr_t *mngr)
{
    npu_task_info_t *task_info = NULL;
	struct list_head *task_list = (&mngr->task_list);
	if (!list_empty(task_list)) {
		task_info = list_first_entry(task_list, npu_task_info_t, list_node);
		list_del(&(task_info->list_node));
	}

	return task_info;
}

void npu_free_task_info(npu_task_info_mngr_t *mngr, int task_id)
{
	if ((task_id >= DEVDRV_MAX_TASK_ID) || (task_id < 0))
		return;

	npu_task_info_t *task_info = &(mngr->tasks[task_id]);
	struct list_head *task_list = &(mngr->task_list);
	list_add(&(task_info->list_node), task_list);
}

npu_task_info_t *npu_get_task_info(npu_task_info_mngr_t *mngr, int task_id)
{
	npu_task_info_t *task_info = NULL;
	if ((task_id < DEVDRV_MAX_TASK_ID) && (task_id >= 0))
		task_info = &(mngr->tasks[task_id]);

	return task_info;
}

