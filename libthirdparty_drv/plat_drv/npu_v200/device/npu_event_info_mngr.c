#include "npu_event_info_mngr.h"
#include "npu_base_define.h"

void npu_init_event_info_mngr(npu_event_info_mngr_t *mngr)
{
	int i = 0;
	INIT_LIST_HEAD(&(mngr->event_list));

	for (; i < NPU_MAX_EVENT_ID; ++i) {
		mngr->events[i].event_id = i;
		mngr->events[i].proc_ctx = NULL;
		INIT_LIST_HEAD(&(mngr->events[i].list_node));
		list_add(&(mngr->events[i].list_node), &(mngr->event_list));
	}
}

npu_event_info_t *npu_alloc_event_info(npu_event_info_mngr_t *mngr)
{
	npu_event_info_t *event_info = NULL;
	struct list_head *event_list = (&mngr->event_list);
	if (!list_empty(event_list)) {
		event_info = list_first_entry(event_list, npu_event_info_t, list_node);
		list_del(&(event_info->list_node));
	}

	return event_info;
}

void npu_free_event_info(npu_event_info_mngr_t *mngr, int event_id)
{
	if ((event_id >= NPU_MAX_EVENT_ID) || (event_id < 0))
		return;

	npu_event_info_t *event_info = &(mngr->events[event_id]);
	struct list_head *event_list = &(mngr->event_list);
	list_add(&(event_info->list_node), event_list);
}

npu_event_info_t *npu_get_event_info(npu_event_info_mngr_t *mngr, int event_id)
{
	npu_event_info_t *event_info = NULL;
	if ((event_id < NPU_MAX_EVENT_ID) && (event_id >= 0))
		event_info = &(mngr->events[event_id]);

	return event_info;
}

