/*
 * ISP driver, hisp_mem.c
 */

#include "hisp_mem.h"
#include <mem_mode.h> // non_secure
#include <sre_typedef.h> // UINT32
#include <hisi_debug.h>
#include "hisp.h"
#include "secmem.h"
#include "sec_smmu_com.h"

UINT32 hisp_nonsec_mem_map(struct smmu_domain *domain, secisp_mem_info *buffer, struct sglist *sgl)
{
	UINT32 ret = SECISP_SUCCESS;

	if (buffer->da == 0) {
		ISP_ERR("wrong da, type.%d, da.0x%x", buffer->type, buffer->da);
		return SECISP_BAD_PARA;
	}

	if (buffer->size == 0) {
		ISP_ERR("wrong size, type.%d, size.0x%x", buffer->type, buffer->size);
		return SECISP_BAD_PARA;
	}

	if (buffer->sec_flag != non_secure) {
		ISP_ERR("wrong sec flag, type.%d, sec flag.%d", buffer->type, buffer->sec_flag);
		return SECISP_BAD_PARA;
	}

	ISP_DEBUG("iommu map for secisp nonsec");
	ret = siommu_map(domain, sgl, buffer->da, buffer->size, buffer->prot, buffer->sec_flag);
	if (ret != 0) {
		ISP_ERR("fail, siommu_map. ret.%u", ret);
	}

	return ret;
}

UINT32 hisp_nonsec_mem_unmap(struct smmu_domain *domain, secisp_mem_info *buffer, struct sglist *sgl)
{
	UINT32 ret;

	if (buffer->da == 0) {
		ISP_ERR("wrong da, type.%d, da.0x%x", buffer->type, buffer->da);
		return SECISP_BAD_PARA;
	}

	if (buffer->size == 0) {
		ISP_ERR("wrong size, type.%d, size.0x%x", buffer->type, buffer->size);
		return SECISP_BAD_PARA;
	}

	if (buffer->sec_flag != non_secure) {
		ISP_ERR("wrong sec flag, type.%d, sec flag.%d", buffer->type, buffer->sec_flag);
		return SECISP_BAD_PARA;
	}

	ISP_DEBUG("iommu unmap for secisp nonsec mem");
	ret = siommu_unmap(domain, sgl, buffer->da, buffer->size, buffer->sec_flag);
	if (ret != 0)
		ISP_ERR("fail, siommu_map. ret.%u", ret);

	return ret;
}

UINT32 hisp_sec_mem_map(secisp_mem_info *buffer, UINT32 sfd)
{
	struct mem_chunk_list mcl;
	UINT32 ret;

	if (buffer->size == 0) {
		ISP_ERR("wrong size, type.%d, size.0x%x", buffer->type, buffer->size);
		return SECISP_BAD_PARA;
	}

	if (buffer->sec_flag != secure) {
		ISP_ERR("wrong sec flag, type.%d, sec flag.%d", buffer->type, buffer->sec_flag);
		return SECISP_BAD_PARA;
	}

	mcl.protect_id = SEC_TASK_SEC;
	mcl.buff_id = sfd;
	mcl.va = buffer->da;
	mcl.size = buffer->size;
	mcl.prot = buffer->prot;
	mcl.mode = buffer->sec_flag;
	ISP_DEBUG("iommu map for secisp sec mem");
	ret = sion_map_iommu(&mcl);
	if (ret != 0)
		ISP_ERR("fail, sion_map_iommu. ret.%u", ret);

	return ret;
}

UINT32 hisp_sec_mem_unmap(secisp_mem_info *buffer, UINT32 sfd)
{
	struct mem_chunk_list mcl;
	UINT32 ret;

	if (buffer->size == 0) {
		ISP_ERR("wrong size, type.%d, size.0x%x", buffer->type, buffer->size);
		return SECISP_BAD_PARA;
	}

	if (buffer->sec_flag != secure) {
		ISP_ERR("wrong sec flag, type.%d, sec flag.%d", buffer->type, buffer->sec_flag);
		return SECISP_BAD_PARA;
	}

	mcl.protect_id = SEC_TASK_SEC;
	mcl.buff_id = sfd;
	mcl.va = buffer->da;
	mcl.size = buffer->size;
	mcl.prot = buffer->prot;
	mcl.mode = buffer->sec_flag;
	mcl.smmuid = SMMU_MEDIA1;
	mcl.sid = SECSMMU_STREAMID_ISP;
	mcl.ssid = SECSMMU_SUBSTREAMID_ISP;
	ISP_DEBUG("iommu unmap for secisp sec mem");
	ret = sion_unmap_iommu(&mcl);
	if (ret != 0)
		ISP_ERR("fail, sion_unmap_iommu. ret.%u", ret);

	return ret;
}

