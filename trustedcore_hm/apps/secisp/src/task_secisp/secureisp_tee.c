#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wimplicit-function-declaration"

/* ----------------------------------------------------------------------------
*   Includes
* ---------------------------------------------------------------------------- */
#include "tee_internal_api.h"
#include "mem_mode.h" // secure
#include "secureisp_tee.h"
#include <malloc.h>
#include <stdint.h>
#include "sre_syscalls_ext.h"
#include "vltmm_client_api.h"

#include "libhwsecurec/securec.h"
#define UNUSED(x) ((void)x)

#define SIZE_2M         0x200000

typedef TEE_Result (*isp_cmd_handler)(uint32_t paramTypes, TEE_Param params[4]);

/* isp func */
static int do_disreset_call(void)
{
	return __secisp_disreset();
}

static int do_reset_call(void)
{
	return __secisp_reset();
}

static int do_nonsec_map_call(void *sglist, unsigned int sg_size, void *buffer, unsigned int buffer_size)
{
	return __secisp_nonsec_map(sglist, sg_size, buffer, buffer_size);
}

static int do_nonsec_unmap_call(void *sglist, unsigned int sg_size, void *buffer, unsigned int buffer_size)
{
	return __secisp_nonsec_unmap(sglist, sg_size, buffer, buffer_size);
}

static int do_sec_map_call(uint32_t sfd, unsigned int sg_size, void *buffer, unsigned int buffer_size)
{
	return __secisp_sec_map(sfd, sg_size, buffer, buffer_size);
}

static int do_sec_unmap_call(uint32_t sfd, unsigned int sg_size, void *buffer, unsigned int buffer_size)
{
	return __secisp_sec_unmap(sfd, sg_size, buffer, buffer_size);
}

static TEE_Result Isp_Cfg_SecMem(unsigned int sfd, unsigned int size, unsigned int sec_id, unsigned int sec_flag,
	SECISP_DDR_CFG_TYPE ddr_cfg_type)
{
	int ret = 0;

	isp_info("sec_flag.%d", sec_flag);
	if (sec_flag == SECISP_SEC) {
		isp_info("sion_ddr_sec_cfg : ddr_cfg_type.%d", ddr_cfg_type);
		ret = sion_ddr_sec_cfg((u16)sfd, size, true, sec_id, ddr_cfg_type);
		if (ret != 0) {
			isp_err("wrong sec_id.%d", sec_id);
			return TEE_ERROR_BAD_PARAMETERS;
		}
	}

	return TEE_SUCCESS;
}

static TEE_Result Isp_Alloc_Ion_Sglist(TEE_ISP_MEM_INFO *info, struct sglist **sglist, unsigned int size)
{
	struct sglist *ion_sglist = NULL;

	if (info == NULL) {
		isp_err("info is NULL!");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if ((size > MAX_MALLOC_SIZE) || (size != info->size)) {
		isp_err("size is wrong! 0x%x", size);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	ion_sglist = malloc(sizeof(struct sglist) + sizeof(TEE_PAGEINFO));
	if (ion_sglist == NULL) {
		isp_err("ion_sglist is NULL!", size);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	ion_sglist->sglistSize = STATIC_MEM_SGLIST_SIZE;
	ion_sglist->ion_size   = size;
	ion_sglist->infoLength = STATIC_MEM_INFOLENGTH;
	ion_sglist->info[0].phys_addr = info->pa;
	ion_sglist->info[0].npages    = size / STATIC_MEM_PAGE_ALIGN;
	*sglist = ion_sglist;

	return TEE_SUCCESS;
}

static TEE_Result ISP_Boot_Img_Mem_Map(struct secisp_boot_mem_info *boot_info)
{
	struct secisp_img_mem_info *img_info = NULL;
	TEE_Result result;
	int index, ret;

	for (index = 0; index < HISP_SEC_BOOT_MAX_TYPE; index++) {
		img_info = &boot_info->img_info[index];
		if (img_info == NULL) {
			isp_err("img_info is NULL, index is %d", index);
			goto err_img_map;
		}

		isp_info("sfd is 0x%x, index is %d", img_info->sfd, index);
		result = Isp_Cfg_SecMem(img_info->sfd, img_info->info.size, SECISP_DDR_SEC_FEATURE,
			img_info->info.sec_flag, SECISP_DDR_SET_SEC);
		if (result != TEE_SUCCESS) {
			isp_err("Isp_Cfg_SecMem failed.%d, index.%d", result, index);
			goto err_img_map;
		}

		/* mem map */
		ret = do_sec_map_call(img_info->sfd, img_info->info.size, &img_info->info, sizeof(TEE_ISP_MEM_INFO));
		if (ret != 0) {
			isp_err("type.%d do_map_call failed.%d", img_info->info.type, ret);
			(void)Isp_Cfg_SecMem(img_info->sfd, img_info->info.size, SECISP_DDR_SEC_FEATURE,
				img_info->info.sec_flag, SECISP_DDR_UNSET_SEC);
			goto err_img_map;
		}
	}

	return TEE_SUCCESS;
err_img_map:
	while (index > 0) {
		index--;
		img_info = &boot_info->img_info[index];
		ret = do_sec_unmap_call(img_info->sfd, img_info->info.size, &img_info->info, sizeof(TEE_ISP_MEM_INFO));
		if (ret != 0)
			isp_err("type.%d do_unmap_call failed.%x", img_info->info.type, ret);

		/* cfg mem nosec */
		ret = Isp_Cfg_SecMem(img_info->sfd, img_info->info.size, SECISP_DDR_SEC_FEATURE,
			img_info->info.sec_flag, SECISP_DDR_UNSET_SEC);
		if (ret != 0)
			isp_err("sec_flag.%d Isp_Cfg_SecMem failed.%x", img_info->info.sec_flag, ret);
	}

	return TEE_FAIL;
}

static TEE_Result ISP_Boot_Img_Mem_Unmap(struct secisp_boot_mem_info *boot_info)
{
	struct secisp_img_mem_info *img_info = NULL;
	TEE_Result result = TEE_SUCCESS;
	int index, ret;

	for (index = HISP_SEC_BOOT_MAX_TYPE - 1; index >= 0; index--) {
		img_info = &boot_info->img_info[index];
		ret = do_sec_unmap_call(img_info->sfd, img_info->info.size, &img_info->info, sizeof(TEE_ISP_MEM_INFO));
		if (ret != 0) {
			isp_err("type.%d do_unmap_call failed.%x", img_info->info.type, ret);
			result = TEE_FAIL;
		}

		/* cfg mem nosec */
		ret = Isp_Cfg_SecMem(img_info->sfd, img_info->info.size, SECISP_DDR_SEC_FEATURE,
			img_info->info.sec_flag, SECISP_DDR_UNSET_SEC);
		if (ret != 0) {
			isp_err("sec_flag.%d Isp_Cfg_SecMem failed.%x", img_info->info.sec_flag, ret);
			result = TEE_FAIL;
		}
	}

	return result;
}

static TEE_Result ISP_Boot_Rsv_Mem_Map(struct secisp_boot_mem_info *boot_info)
{
	TEE_ISP_MEM_INFO *rsv_info = NULL;
	TEE_Result result = TEE_SUCCESS;
	struct sglist *ionmem_sglist[HISP_SEC_RSV_MAX_TYPE] = {NULL};
	int index, ret;

	for (index = 0; index < HISP_SEC_RSV_MAX_TYPE; index++) {
		rsv_info = &boot_info->rsv_info[index];
		if (rsv_info == NULL) {
			isp_err("rsv_info is NULL, index is %d", index);
			goto err_rsv_map;
		}

		result = Isp_Alloc_Ion_Sglist(rsv_info, &ionmem_sglist[index], rsv_info->size);
		if (result != TEE_SUCCESS) {
			isp_err("Isp_Alloc_Ion_Sglist fail, index is %d", index);
			goto err_rsv_map;
		}

		/* mem map */
		ret = do_nonsec_map_call(ionmem_sglist[index], STATIC_MEM_SGLIST_SIZE, rsv_info, sizeof(TEE_ISP_MEM_INFO));
		if (ret != 0) {
			isp_err("type.%d do_map_call failed.%x", rsv_info->type, ret);
			free(ionmem_sglist[index]);
			ionmem_sglist[index] = NULL;
			goto err_rsv_map;
		}
	}

	for (index = 0; index < HISP_SEC_RSV_MAX_TYPE; index++) {
		free(ionmem_sglist[index]);
		ionmem_sglist[index] = NULL;
	}

	return TEE_SUCCESS;
err_rsv_map:
	while (index > 0) {
		index--;
		rsv_info = &boot_info->rsv_info[index];
		ret = do_nonsec_unmap_call(ionmem_sglist[index], STATIC_MEM_SGLIST_SIZE, rsv_info, sizeof(TEE_ISP_MEM_INFO));
		if (ret != 0)
			isp_err("type.%d do_unmap_call failed.%x", rsv_info->type, ret);

		free(ionmem_sglist[index]);
		ionmem_sglist[index] = NULL;
	}

	return TEE_FAIL;
}

static TEE_Result ISP_Boot_Rsv_Mem_Unmap(struct secisp_boot_mem_info *boot_info)
{
	TEE_ISP_MEM_INFO *rsv_info = NULL;
	struct sglist *ionmem_sglist[HISP_SEC_RSV_MAX_TYPE] = {NULL};
	TEE_Result result = TEE_SUCCESS;
	int index, ret;

	for (index = HISP_SEC_RSV_MAX_TYPE - 1; index>= 0; index--) {
		rsv_info = &boot_info->rsv_info[index];
		result = Isp_Alloc_Ion_Sglist(rsv_info, &ionmem_sglist[index], rsv_info->size);
		if (result != TEE_SUCCESS) {
			isp_err("Isp_Alloc_Ion_Sglist fail, index is %d", index);
			continue;
		}

		ret = do_nonsec_unmap_call(ionmem_sglist[index], STATIC_MEM_SGLIST_SIZE, rsv_info, sizeof(TEE_ISP_MEM_INFO));
		if (ret != 0) {
			isp_err("type.%d do_unmap_call failed.%x", rsv_info->type, ret);
			result = TEE_FAIL;
		}

		free(ionmem_sglist[index]);
		ionmem_sglist[index] = NULL;
	}

	return result;
}

TEE_Result ISP_ImgMap_and_Disreset(uint32_t paramTypes, TEE_Param params[4])
{
	int ret;

	isp_info("ISP_ImgMap_and_Disreset +");
	ret = do_disreset_call();
	if (ret != 0) {
		isp_err("type.%d do_unmap_call failed.%x", ret);
		return TEE_FAIL;
	}

	isp_info("ISP_ImgMap_and_Disreset -");
	return TEE_SUCCESS;
}

TEE_Result ISP_ImgUnmap_and_Reset(uint32_t paramTypes, TEE_Param params[4])
{
	int ret;

	isp_info("ISP_ImgUnmap_and_Reset +");
	ret = do_reset_call();
	if (ret != 0) {
		isp_err("do_reset_call failed.%x", ret);
		return TEE_FAIL;
	}

	isp_info("ISP_ImgUnmap_and_Reset -");
	return TEE_SUCCESS;
}

TEE_Result ISP_Sec_Mem_Cfg_and_Map(uint32_t paramTypes, TEE_Param params[4])
{
	TEE_ISP_MEM_INFO *ion_meminfo = NULL;
	unsigned int sfd_size = 0;
	unsigned int buffer_size = 0;
	unsigned int sfd;
	TEE_Result result = TEE_SUCCESS;
	int ret = 0;

	isp_info("ISP_Sec_Mem_Cfg_and_Map size.0x%x", params[1].memref.size);
	/* check buffer */
	buffer_size = (unsigned int)params[1].memref.size;
	if (buffer_size != sizeof(TEE_ISP_MEM_INFO)) {
		isp_err("wrong buffer_size.0x%x", buffer_size);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* get buffer */
	ion_meminfo = (TEE_ISP_MEM_INFO *)params[1].memref.buffer;
	if (ion_meminfo == NULL) {
		isp_err("ion_meminfo is NULL! buffer_size.0x%x", buffer_size);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	isp_debug("Mem ion info sharefd.%d, buffer_size.0x%x",
		ion_meminfo->sharefd, buffer_size);
	isp_debug("Mem buffer info type.%d, da.0x%x, size.0x%x",
		ion_meminfo->type, ion_meminfo->da, ion_meminfo->size);
	isp_debug("Mem buffer info prot.0x%x, sec_flag.%d, pa.0x%llx",
		ion_meminfo->prot, ion_meminfo->sec_flag, ion_meminfo->pa);
	/* get ion sfd info */
	sfd = params[0].value.a;
	sfd_size = params[0].value.b;
	isp_debug("Mem sfd.0x%x", sfd);
	isp_debug("Mem sfd_size.0x%x -- 0x%x", params[0].memref.size, sfd_size);
	/* cfg mem sec */
	result = Isp_Cfg_SecMem(sfd, sfd_size, SECISP_DDR_SEC_FEATURE,
		ion_meminfo->sec_flag, SECISP_DDR_SET_SEC);
	if (result != TEE_SUCCESS) {
		isp_err("sec_flag.%d Isp_Cfg_SecMem failed.%x", ion_meminfo->sec_flag, ret);
		return TEE_ERROR_NO_DATA;
	}

	/* mem map */
	isp_debug("[%s]: pa.0x%llx size.0x%x", __func__, ion_meminfo->pa, ion_meminfo->size);
	ret = do_sec_map_call(sfd, sfd_size, ion_meminfo, buffer_size);
	if (ret != 0) {
		isp_err("type.%d do_map_call failed.%x", ion_meminfo->type, ret);
		(void)Isp_Cfg_SecMem(sfd, sfd_size, SECISP_DDR_SEC_FEATURE,
			ion_meminfo->sec_flag, SECISP_DDR_UNSET_SEC);
		return TEE_FAIL;
	}

	isp_info("ISP_Sec_Mem_Cfg_and_Map -");
	return TEE_SUCCESS;
}

TEE_Result ISP_Sec_Mem_Cfg_and_Unmap(uint32_t paramTypes, TEE_Param params[4])
{
	TEE_ISP_MEM_INFO *ion_meminfo = NULL;
	unsigned int sfd;
	unsigned int sfd_size = 0;
	unsigned int buffer_size = 0;
	int ret = 0;

	isp_info("ISP_Sec_Mem_Cfg_and_Unmap +");
	buffer_size = (unsigned int)params[1].memref.size;
	if (buffer_size != sizeof(TEE_ISP_MEM_INFO)) {
		isp_err("wrong buffer_size.0x%x", buffer_size);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* get buffer */
	ion_meminfo = (TEE_ISP_MEM_INFO *)params[1].memref.buffer;
	if (ion_meminfo == NULL) {
		isp_err("ion_meminfo is NULL! buffer_size.0x%x", buffer_size);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* get ion sfd info */
	sfd = params[0].value.a;
	sfd_size = params[0].value.b;

	/* mem map */
	ret = do_sec_unmap_call(sfd, sfd_size, ion_meminfo, buffer_size);
	if (ret != 0) {
		isp_err("type.%d do_unmap_call failed.%x", ion_meminfo->type, ret);
		return TEE_FAIL;
	}

	/* cfg mem nosec */
	ret = Isp_Cfg_SecMem(sfd, sfd_size, SECISP_DDR_SEC_FEATURE,
		ion_meminfo->sec_flag, SECISP_DDR_UNSET_SEC);
	if (ret != 0) {
		isp_err("sec_flag.%d Isp_Cfg_SecMem failed.%x", ion_meminfo->sec_flag, ret);
		return TEE_ERROR_NO_DATA;
	}

	isp_info("ISP_Sec_Mem_Cfg_and_Unmap -");
	return TEE_SUCCESS;
}

TEE_Result ISP_Nonsec_Mem_Map_Sec(uint32_t paramTypes, TEE_Param params[4])
{
	TEE_ISP_MEM_INFO *nonsec_meminfo = NULL;
	struct sglist *ionmem_sglist  = NULL;
	unsigned int buffer_size = 0;
	unsigned int mem_size = 0;
	int ret = 0;

	isp_info("ISP_Nonsec_Mem_Map_Sec +");
	/* check buffer */
	buffer_size = (unsigned int)params[1].memref.size;
	if (buffer_size != sizeof(TEE_ISP_MEM_INFO)) {
		isp_err("wrong buffer_size.0x%x", buffer_size);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* get buffer */
	nonsec_meminfo = (TEE_ISP_MEM_INFO *)params[1].memref.buffer;
	if (nonsec_meminfo == NULL) {
		isp_err("nonsec_meminfo is NULL! buffer_size.0x%x", buffer_size);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	isp_debug("nonsec mem buffer info type.%d, da.0x%x, size.0x%x",
		nonsec_meminfo->type, nonsec_meminfo->da, nonsec_meminfo->size);
	isp_debug("nonsec mem buffer info prot.0x%x, sec_flag.%d, pa.0x%llx",
		nonsec_meminfo->prot, nonsec_meminfo->sec_flag, nonsec_meminfo->pa);
	/* get staitc mem sglist */
	mem_size = (unsigned int)params[0].memref.size;

	/* get buffer */
	ionmem_sglist = (struct sglist *)params[0].memref.buffer;
	if (ionmem_sglist == NULL) {
		isp_err("ionmem_sglist is NULL! size.0x%x", mem_size);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	isp_debug("nonsec mem ion info ion_size.0x%x", ionmem_sglist->ion_size);
	/* mem map */
	ret = do_nonsec_map_call(ionmem_sglist, mem_size, nonsec_meminfo, buffer_size);
	if (ret != 0) {
		isp_err("type.%d do_map_call failed.%x", nonsec_meminfo->type,ret);
		return TEE_FAIL;
	}

	isp_info("ISP_Nonsec_Mem_Map_Sec -");
	return TEE_SUCCESS;
}

TEE_Result ISP_Nonsec_Mem_Unmap_Sec(uint32_t paramTypes, TEE_Param params[4])
{
	TEE_ISP_MEM_INFO *nonsec_meminfo = NULL;
	struct sglist *ionmem_sglist  = NULL;
	unsigned int buffer_size = 0;
	unsigned int mem_size = 0;
	int ret = 0;

	isp_info("ISP_Nonsec_Mem_Unmap_Sec +");
	/* check buffer */
	buffer_size = (unsigned int)params[1].memref.size;
	if (buffer_size != sizeof(TEE_ISP_MEM_INFO)) {
		isp_err("wrong buffer_size.0x%x", buffer_size);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* get buffer */
	nonsec_meminfo = (TEE_ISP_MEM_INFO *)params[1].memref.buffer;
	if (nonsec_meminfo == NULL) {
		isp_err("nonsec_meminfo is NULL! buffer_size.0x%x", buffer_size);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	isp_debug("nonsec mem buffer info type.%d, da.0x%x, size.0x%x",
		nonsec_meminfo->type, nonsec_meminfo->da, nonsec_meminfo->size);
	isp_debug("nonsec mem buffer info prot.0x%x, sec_flag.%d, pa.0x%llx",
		nonsec_meminfo->prot, nonsec_meminfo->sec_flag, nonsec_meminfo->pa);
	/* get staitc mem sglist */
	mem_size = (unsigned int)params[0].memref.size;

	/* get buffer */
	ionmem_sglist = (struct sglist *)params[0].memref.buffer;
	if (ionmem_sglist == NULL) {
		isp_err("ionmem_sglist is NULL! size.0x%x", mem_size);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	isp_debug("nonsec mem ion info ion_size.0x%x", ionmem_sglist->ion_size);
	/* mem map */
	ret = do_nonsec_unmap_call(ionmem_sglist, mem_size, nonsec_meminfo, buffer_size);
	if (ret != 0) {
		isp_err("type.%d do_unmap_call failed.%x", nonsec_meminfo->type, ret);
		return TEE_FAIL;
	}

	isp_info("ISP_Nonsec_Mem_Unmap_Sec -");
	return TEE_SUCCESS;
}

TEE_Result ISP_Boot_Mem_Map(uint32_t paramTypes, TEE_Param params[4])
{
	struct secisp_boot_mem_info *boot_info = NULL;
	unsigned int buffer_size = 0;
	TEE_Result result = TEE_SUCCESS;

	isp_info("ISP_Boot_Mem_Map +");
	/* check buffer */
	buffer_size = (unsigned int)params[0].memref.size;
	if (buffer_size != sizeof(struct secisp_boot_mem_info)) {
		isp_err("wrong buffer_size.0x%x", buffer_size);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* get buffer */
	boot_info = (struct secisp_boot_mem_info *)params[0].memref.buffer;
	if (boot_info == NULL) {
		isp_err("boot_info is NULL! buffer_size.0x%x", buffer_size);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	result = ISP_Boot_Img_Mem_Map(boot_info);
	if (result != TEE_SUCCESS) {
		isp_err("ISP_Boot_Img_Mem_Map fail");
		return result;
	}

	result = ISP_Boot_Rsv_Mem_Map(boot_info);
	if (result != TEE_SUCCESS) {
		isp_err("ISP_Boot_Rsv_Mem_Map fail");
		goto err_rsv_map;
	}
	isp_info("ISP_Boot_Mem_Map -");
	return result;

err_rsv_map:
	result = ISP_Boot_Img_Mem_Unmap(boot_info);
	if (result != TEE_SUCCESS)
		isp_err("ISP_Boot_Img_Mem_Unmap fail");

	isp_info("ISP_Boot_Mem_Map -");
	return result;
}

TEE_Result ISP_Boot_Mem_Unmap(uint32_t paramTypes, TEE_Param params[4])
{
	struct secisp_boot_mem_info *boot_info = NULL;
	unsigned int buffer_size = 0;
	TEE_Result result1, result2;

	isp_info("ISP_Boot_Mem_Unmap +");
	/* check buffer */
	buffer_size = (unsigned int)params[0].memref.size;
	if (buffer_size != sizeof(struct secisp_boot_mem_info)) {
		isp_err("wrong buffer_size.0x%x", buffer_size);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* get buffer */
	boot_info = (struct secisp_boot_mem_info *)params[0].memref.buffer;
	if (boot_info == NULL) {
		isp_err("boot_info is NULL! buffer_size.0x%x", buffer_size);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	result1 = ISP_Boot_Rsv_Mem_Unmap(boot_info);
	if (result1 != TEE_SUCCESS)
		isp_err("ISP_Boot_Rsv_Mem_Unmap fail, result %d", result1);

	result2 = ISP_Boot_Img_Mem_Unmap(boot_info);
	if (result2 != TEE_SUCCESS)
		isp_err("ISP_Boot_Rsv_Mem_Unmap fail, result %d", result2);

	isp_info("ISP_Boot_Mem_Unmap -");
	return (result1 | result2);
}

/* ------------------------------------------s----------------------------------
 *   Trusted Application Entry Points
 * ---------------------------------------------------------------------------- */

static isp_cmd_handler g_isp_handler[TEE_SECISP_CMD_MAX] = {
	[TEE_SECISP_CMD_IMG_DISRESET]       = ISP_ImgMap_and_Disreset,
	[TEE_SECISP_CMD_RESET]              = ISP_ImgUnmap_and_Reset,
	[TEE_SECISP_SEC_MEM_CFG_AND_MAP]    = ISP_Sec_Mem_Cfg_and_Map,
	[TEE_SECISP_SEC_MEM_CFG_AND_UNMAP]  = ISP_Sec_Mem_Cfg_and_Unmap,
	[TEE_SECISP_NONSEC_MEM_MAP_SEC]     = ISP_Nonsec_Mem_Map_Sec,
	[TEE_SECISP_NONSEC_MEM_UNMAP_SEC]   = ISP_Nonsec_Mem_Unmap_Sec,
	[TEE_SECISP_BOOT_MEM_CFG_AND_MAP]   = ISP_Boot_Mem_Map,
	[TEE_SECISP_BOOT_MEM_CFG_AND_UNMAP] = ISP_Boot_Mem_Unmap,
};

/**
 *  Function TA_CreateEntryPoint
 *  Description:
 *    The function TA_CreateEntryPoint is the Trusted Application's constructor,
 *    which the Framework calls when it creates a new instance of the Trusted Application.
 */
__attribute__((visibility("default"))) TEE_Result TA_CreateEntryPoint(void)
{
	isp_info("----- TA_CreateEntryPoint ----- ");
	TEE_Result ret;
	ret = (TEE_Result)AddCaller_CA_exec(CameraDaemonSERVER_NAME, CameraDaemon_UID);

	if (TEE_SUCCESS != ret) {
		isp_err("----- TA_CreateEntryPoint failed = 0x%lx----- ", ret);
		return ret;
	}

	return ret;
}

/**
 *  Function TA_DestroyEntryPoint
 *  Description:
 *    The function TA_DestroyEntryPoint is the Trusted Application's destructor,
 *    which the Framework calls when the instance is being destroyed.
 */
__attribute__((visibility("default"))) void TA_DestroyEntryPoint(void)
{
	isp_info("---- TA_DestroyEntryPoint ---- ");
}

/**
 *  Function TA_OpenSessionEntryPoint
 *  Description:
 *    The Framework calls the function TA_OpenSessionEntryPoint
 *    when a client requests to open a session with the Trusted Application.
 *    The open session request may result in a new Trusted Application instance
 *    being created.
 */
/*lint -save -e715*/

__attribute__((visibility("default"))) TEE_Result TA_OpenSessionEntryPoint(uint32_t paramTypes,
		TEE_Param params[4], void **sessionContext)
{
	int ret;
	isp_info("---- TA_OpenSessionEntryPoint -------- ");

	ret = secmem_smmu_domain_init(SEC_ISP, SIZE_2M);
	if (ret) {
		isp_err("----- TA_OpenSessionEntryPoint failed = 0x%lx----- ", ret);
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	return TEE_SUCCESS;
}
/*lint -restore*/

/**
 *  Function TA_CloseSessionEntryPoint:
 *  Description:
 *    The Framework calls this function to close a client session.
 *    During the call to this function the implementation can use
 *    any session functions.
 */
/*lint -save -e715*/
__attribute__((visibility("default"))) void TA_CloseSessionEntryPoint(void *session_context)
{
	int ret;

	ret = secmem_smmu_domain_destroy(SEC_ISP);
	if (ret)
		isp_err("----- TA_OpenSessionEntryPoint failed = %d----- ", ret);

	isp_info("---- TA_CloseSessionEntryPoint ----- ");
}
/*lint -restore*/

static TEE_Result secisp_input_check(unsigned int cmd_id, uint32_t paramTypes)
{
	switch (cmd_id) {
	case TEE_SECISP_CMD_IMG_DISRESET:
	case TEE_SECISP_CMD_RESET:
		if (!check_param_type(paramTypes, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE)) {
			isp_err("Bad expected parameter types, cmd %d", cmd_id);
			return TEE_ERROR_BAD_PARAMETERS;
		}

		break;

	case TEE_SECISP_SEC_MEM_CFG_AND_MAP:
	case TEE_SECISP_SEC_MEM_CFG_AND_UNMAP:
		if (!check_param_type(paramTypes, TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT,
			TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE)) {
			isp_err("Bad expected parameter types, cmd %d", cmd_id);
			return TEE_ERROR_BAD_PARAMETERS;
		}

		break;

	case TEE_SECISP_NONSEC_MEM_MAP_SEC:
	case TEE_SECISP_NONSEC_MEM_UNMAP_SEC:
		if (!check_param_type(paramTypes, TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT,
			TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE)) {
			isp_err("Bad expected parameter types, cmd %d", cmd_id);
			return TEE_ERROR_BAD_PARAMETERS;
		}

		break;

	case TEE_SECISP_BOOT_MEM_CFG_AND_MAP:
	case TEE_SECISP_BOOT_MEM_CFG_AND_UNMAP:
		if (!check_param_type(paramTypes, TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE)) {
			isp_err("Bad expected parameter types, cmd %d", cmd_id);
			return TEE_ERROR_BAD_PARAMETERS;
		}

		break;

	default:
		isp_err("Invalid ISP CMD ID: %d", cmd_id);
		return TEE_ERROR_INVALID_CMD;
	}

	return TEE_SUCCESS;
}

/**
 *  Function TA_InvokeCommandEntryPoint:
 *  Description:
 *    The Framework calls this function when the client invokes a command
 *    within the given session.
 */
/*lint -save -e715 -e835 -e845*/
__attribute__((visibility("default"))) TEE_Result TA_InvokeCommandEntryPoint(void *session_context, uint32_t cmd_id,
	uint32_t paramTypes, TEE_Param params[4])
{
	TEE_Result ret;

	UNUSED(session_context);
	isp_info("---- TA_InvokeCommandEntryPoint cmd.%d ----------- ", cmd_id);
	ret = secisp_input_check(cmd_id, paramTypes);
	if (ret != TEE_SUCCESS) {
		isp_err("Invalid paramTypes: %d", cmd_id);
		return ret;
	}

	ret = g_isp_handler[cmd_id](paramTypes, params);
	return ret;
}
/*lint -restore*/

#pragma GCC diagnostic pop
