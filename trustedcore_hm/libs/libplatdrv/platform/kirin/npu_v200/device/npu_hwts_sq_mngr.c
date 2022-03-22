#include "npu_base_define.h"
#include "npu_hwts_sq_mngr.h"

void npu_init_hwts_sq_mngr(npu_hwts_sq_mngr_t *mngr)
{
	int i = 0;
	INIT_LIST_HEAD(&(mngr->sq_list));

	for (; i < DEVDRV_SEC_SQ_NUM; ++i) {
		mngr->sqs[i].proc_ctx = NULL;
		mngr->sqs[i].stream_id = -1;
		mngr->sqs[i].sq_id = DEVDRV_SEC_SQ_ID_BEGIN + i;
		INIT_LIST_HEAD(&(mngr->sqs[i].list_node));
		list_add(&(mngr->sqs[i].list_node), &(mngr->sq_list));
	}
}

npu_hwts_sq_t *npu_alloc_hwts_sq(npu_hwts_sq_mngr_t *mngr)
{
	npu_hwts_sq_t *sq = NULL;
	struct list_head *sq_list = (&mngr->sq_list);
	if (!list_empty(sq_list)) {
		sq = list_first_entry(sq_list, npu_hwts_sq_t, list_node);
		list_del(&(sq->list_node));
	}

	return sq;
}

void npu_free_hwts_sq(npu_hwts_sq_mngr_t *mngr, int sq_id)
{
	if ((sq_id < DEVDRV_SEC_SQ_ID_BEGIN) ||
		((sq_id - DEVDRV_SEC_SQ_ID_BEGIN) >= DEVDRV_SEC_SQ_NUM)) {
		return;
	}

	npu_hwts_sq_t *sq = &(mngr->sqs[sq_id - DEVDRV_SEC_SQ_ID_BEGIN]);
	struct list_head *sq_list = &(mngr->sq_list);
	list_add(&(sq->list_node), sq_list);
}

npu_hwts_sq_t *npu_get_hwts_sq(npu_hwts_sq_mngr_t *mngr, int sq_id)
{
	npu_hwts_sq_t *sq = NULL;
	if ((sq_id >= DEVDRV_SEC_SQ_ID_BEGIN) &&
		((sq_id - DEVDRV_SEC_SQ_ID_BEGIN) < DEVDRV_SEC_SQ_NUM)) {
		sq =  &(mngr->sqs[sq_id - DEVDRV_SEC_SQ_ID_BEGIN]);
	}

	return sq;
}

