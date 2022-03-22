#include "hisee_video_smmu.h"
#include <pal_smmu_plat.h>
#include <pal_log.h>
#include <mspe_smmu_v2.h>
#include <secmem.h>

#define BSP_THIS_MODULE            BSP_MODULE_SCE

err_bsp_t hisee_video_smmu_init(u32 buffer_id, u32 size, u32 *iova)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);
	u64 pgt_pa;

	ret = pal_mmu_map(buffer_id, size, iova);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	pgt_pa = (u64)hisi_sion_get_pgtable(SEC_TASK_DRM);
	if (PAL_CHECK(!pgt_pa))
		return ERR_API(ERRCODE_NULL);

	/* protect is smmu non-sec channel */
	mspe_smmu_set_pgt_addr(pgt_pa, FALSE);

	return BSP_RET_OK;
}

void hisee_video_smmu_deinit(u32 buffer_id, u32 size)
{
	pal_mmu_unmap(buffer_id, size);
}

