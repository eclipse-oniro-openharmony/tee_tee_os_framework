#include "npu_base_define.h"
#include "npu_model_info_mngr.h"

void npu_init_model_info_mngr(npu_model_info_mngr_t *mngr)
{
	int i = 0;
	INIT_LIST_HEAD(&(mngr->model_list));

	for (; i < NPU_MAX_MODEL_ID; ++i) {
		mngr->models[i].model_id = i;
		mngr->models[i].proc_ctx = NULL;
		INIT_LIST_HEAD(&(mngr->models[i].list_node));
		INIT_LIST_HEAD(&(mngr->models[i].stream_list));
		list_add(&(mngr->models[i].list_node), &(mngr->model_list));
	}
}

npu_model_info_t *npu_alloc_model_info(npu_model_info_mngr_t *mngr)
{
    npu_model_info_t *model_info = NULL;
	struct list_head *model_list = (&mngr->model_list);
	if (!list_empty(model_list)) {
		model_info = list_first_entry(model_list, npu_model_info_t, list_node);
		list_del(&(model_info->list_node));
	}

	return model_info;
}

void npu_free_model_info(npu_model_info_mngr_t *mngr, int model_id)
{
	if ((model_id >= NPU_MAX_MODEL_ID) || (model_id < 0)) {
		return;
	}

	npu_model_info_t *model_info = &(mngr->models[model_id]);
	struct list_head *model_list = &(mngr->model_list);
	list_add(&(model_info->list_node), model_list);
}

npu_model_info_t *npu_get_model_info(npu_model_info_mngr_t *mngr, int model_id)
{
	npu_model_info_t *model_info = NULL;
	if ((model_id < NPU_MAX_MODEL_ID) && (model_id >= 0)) {
		model_info = &(mngr->models[model_id]);
	}

	return model_info;
}

