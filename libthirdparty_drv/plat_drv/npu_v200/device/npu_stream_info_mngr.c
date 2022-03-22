#include "npu_stream_info_mngr.h"
#include "npu_base_define.h"
#include "npu_dev_ctx_mngr.h"

void npu_init_stream_info_mngr(npu_stream_info_mngr_t *mngr)
{
	int i, j;
	npu_dev_ctx_t *dev_ctx = npu_get_dev_ctx(0);
	u32 sq_len = NPU_MAX_HWTS_SQ_DEPTH * NPU_HWTS_SQ_SLOT_SIZE;
	uintptr_t phy_base = dev_ctx->shm_mem[NPU_SHM_SQ].phy_base;
	uintptr_t virt_base = dev_ctx->shm_mem[NPU_SHM_SQ].virt_base;

	INIT_LIST_HEAD(&(mngr->non_sink_stream_list));
	INIT_LIST_HEAD(&(mngr->sink_stream_list));

	for (i = 0; i < NPU_MAX_NON_SINK_STREAM_ID; ++i) {
		INIT_LIST_HEAD(&(mngr->streams[i].list_node));
		mngr->streams[i].stream_id = i;
		mngr->streams[i].strategy = STREAM_STRATEGY_NONSINK;
		mngr->streams[i].proc_ctx = NULL;
		mngr->streams[i].sink_sub = NULL;
		list_add(&(mngr->streams[i].list_node), &(mngr->non_sink_stream_list));
	}

	for (j = 0; i < NPU_MAX_STREAM_ID; ++i, ++j) {
		mngr->sink_subs[j].model_id = -1;
		mngr->sink_subs[j].sqe_count = 0;
		mngr->sink_subs[j].phy_addr = phy_base + (j * sq_len);
		mngr->sink_subs[j].virt_addr = virt_base + (j * sq_len);

		INIT_LIST_HEAD(&(mngr->streams[i].list_node));
		mngr->streams[i].stream_id = i;
		mngr->streams[i].strategy = STREAM_STRATEGY_SINK;
		mngr->streams[i].proc_ctx = NULL;
		mngr->streams[i].sink_sub = &(mngr->sink_subs[j]);
		list_add(&(mngr->streams[i].list_node), &(mngr->sink_stream_list));
	}
}

npu_stream_info_t *npu_alloc_stream_info(npu_stream_info_mngr_t *mngr, u32 strategy)
{
	struct list_head *stream_list = NULL;
	npu_stream_info_t *stream_info = NULL;

	stream_list = (strategy == STREAM_STRATEGY_NONSINK ?
					(&mngr->non_sink_stream_list) : (&mngr->sink_stream_list));
	if (!list_empty(stream_list)) {
		stream_info = list_first_entry(stream_list, npu_stream_info_t, list_node);
		list_del(&(stream_info->list_node));
	}

	return stream_info;
}

void npu_free_stream_info(npu_stream_info_mngr_t *mngr, int stream_id)
{
	if ((stream_id >= NPU_MAX_STREAM_ID) || (stream_id < 0))
		return;

	struct list_head *stream_list = NULL;
	npu_stream_info_t *stream_info = &(mngr->streams[stream_id]);
	stream_list = (stream_info->strategy == STREAM_STRATEGY_NONSINK ?
		(&mngr->non_sink_stream_list) : (&mngr->sink_stream_list));
	list_add(&(stream_info->list_node), stream_list);
}

npu_stream_info_t *npu_get_stream_info(npu_stream_info_mngr_t *mngr, int stream_id)
{
	npu_stream_info_t *stream_info = NULL;
	if ((stream_id < NPU_MAX_STREAM_ID) && (stream_id >= 0))
		stream_info = &(mngr->streams[stream_id]);

	return stream_info;
}

