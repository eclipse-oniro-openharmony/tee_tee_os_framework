/*
 * hisilicon ISP driver, hisp_secboot.c
 *
 * Copyright (c) 2013 Hisilicon Technologies CO., Ltd.
 *
 */

#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <sre_typedef.h> // UINT64
#include <mem_ops.h>
#include <drv_module.h>
#include "sre_task.h"
#include "sre_syscalls_id_ext.h"
#include "sre_syscalls_id.h"
#include "sre_access_control.h"
#include "drv_pal.h"
#include <hmdrv_stub.h>
#include "sre_syscall.h"
#include "sre_access_control.h"
#include "sre_syscalls_id_ext.h"
#include "hisp.h"
#include "hisp_mem.h"
#include "hisp_load.h"
#include "hisp_power.h"
#include "secmem.h"
#include "sec_region_ops.h"

#ifndef UNUSED
#define UNUSED(var) (void)(var)
#endif

#define SECISP_TYPE_INFO_LENGTH (64)

unsigned int isp_mem_end_flag = 0;

static char secisp_type_info[SECISP_MAX_TYPE][SECISP_TYPE_INFO_LENGTH] = {
	[SECISP_TEXT]             = "SECISP_TEXT",
	[SECISP_DATA]             = "SECISP_DATA",
	[SECISP_SEC_POOL]         = "SECISP_SEC_POOL",
	[SECISP_ISPSEC_POOL]      = "SECISP_ISPSEC_POOL",
	[SECISP_DYNAMIC_POOL]     = "SECISP_DYNAMIC_POOL",
	[SECISP_RDR]              = "SECISP_RDR",
	[SECISP_SHRD]             = "SECISP_SHARE",
	[SECISP_VQ]               = "SECISP_VQ",
	[SECISP_VR0]              = "SECISP_VR0",
	[SECISP_VR1]              = "SECISP_VR1",
};

static UINT32 secisp_disreset(void)
{
	UINT32 ret;

	ret = hisp_top_pwron_and_disreset(siommu_domain_grab(SEC_TASK_SEC));
	if (ret != SECISP_SUCCESS)
		ISP_ERR("hisp_top_pwron_and_disreset fail. ret.%u", ret);

	return ret;
}

static UINT32 secisp_reset(void)
{
	UINT32 ret;

	ret = hisp_top_pwroff_and_reset(siommu_domain_grab(SEC_TASK_SEC));
	if (ret != SECISP_SUCCESS)
		ISP_ERR("hisp_top_pwroff_and_reset fail. ret.%u", ret);

	return ret;
}

static UINT32 secisp_nonsec_map(struct smmu_domain *domain, secisp_mem_info *buffer, struct sglist *sgl)
{
	UINT32 ret;

	if (domain == NULL) {
		ISP_ERR("domain is NULL");
		return SECISP_BAD_PARA;
	}

	if (buffer == NULL) {
		ISP_ERR("buffer is NULL");
		return SECISP_BAD_PARA;
	}

	if (sgl == NULL) {
		ISP_ERR("sgl is NULL");
		return SECISP_BAD_PARA;
	}

	if (buffer->type >= SECISP_MAX_TYPE || buffer->type < SECISP_DYNAMIC_POOL) {
		ISP_ERR("type is wrong. type.%u", buffer->type);
		return SECISP_BAD_PARA;
	}

	ISP_DEBUG("set up pagetable mapping by buffer information");
	ret = hisp_nonsec_mem_map(domain, buffer, sgl);
	if (ret != SECISP_SUCCESS)
		ISP_ERR("hisp_nonsec_mem_map fail. ret.%u", ret);

	return ret;
}

static UINT32 secisp_nonsec_unmap(struct smmu_domain *domain, secisp_mem_info *buffer, struct sglist *sgl)
{
	UINT32 ret;

	if (domain == NULL) {
		ISP_ERR("domain is NULL");
		return SECISP_BAD_PARA;
	}

	if (buffer == NULL) {
		ISP_ERR("buffer is NULL");
		return SECISP_BAD_PARA;
	}

	if (sgl == NULL) {
		ISP_ERR("sgl is NULL");
		return SECISP_BAD_PARA;
	}

	if (buffer->type >= SECISP_MAX_TYPE || buffer->type < SECISP_DYNAMIC_POOL) {
		ISP_ERR("type is wrong. type.%u", buffer->type);
		return SECISP_BAD_PARA;
	}

	ISP_DEBUG("set up pagetable mapping by buffer information");
	ret = hisp_nonsec_mem_unmap(domain, buffer, sgl);
	if (ret != SECISP_SUCCESS)
		ISP_ERR("hisp_nonsec_mem_unmap fail. ret.%u", ret);

	return ret;
}

static UINT32 secisp_sec_map(secisp_mem_info *buffer, UINT32 sfd)
{
	UINT32 ret;

	if (buffer == NULL) {
		ISP_ERR("buffer is NULL");
		return SECISP_BAD_PARA;
	}

	if (buffer->type > SECISP_ISPSEC_POOL) {
		ISP_ERR("type is wrong. type.%u", buffer->type);
		return SECISP_BAD_PARA;
	}

	ISP_DEBUG("set up pagetable mapping by buffer information");
	ret = hisp_sec_mem_map(buffer, sfd);
	if (ret != SECISP_SUCCESS) {
		ISP_ERR("hisp_sec_mem_map fail. ret.%u", ret);
		return ret;
	}

	if (buffer->type == SECISP_TEXT) {
		ISP_DEBUG("copy text image to specified location");
		ret = hisp_sec_text_img_copy(sfd, buffer->size);
		if (ret != SECISP_SUCCESS) {
			ISP_ERR("hisp_sec_text_img_copy fail. ret.%u", ret);
			goto secisp_maperr;
		}
	}

	if (buffer->type == SECISP_DATA) {
		ISP_DEBUG("copy data image to specified location");
		ret = hisp_sec_data_img_copy(sfd, buffer->size);
		if (ret != SECISP_SUCCESS) {
			ISP_ERR("hisp_sec_data_img_copy fail. ret.%u", ret);
			goto secisp_maperr;
		}
	}

	return ret;

secisp_maperr:
	ISP_DEBUG("err process, unmap secisp mem");
	ret = hisp_sec_mem_unmap(buffer, sfd);
	if (ret != SECISP_SUCCESS)
		ISP_ERR("hisp_sec_mem_unmap fail. ret.%u", ret);

	return ret;
}

static UINT32 secisp_sec_unmap(secisp_mem_info *buffer, UINT32 sfd)
{
	UINT32 ret;

	if (buffer == NULL) {
		ISP_ERR("buffer is NULL");
		return SECISP_BAD_PARA;
	}

	if (buffer->type > SECISP_ISPSEC_POOL) {
		ISP_ERR("type is wrong. type.%u", buffer->type);
		return SECISP_BAD_PARA;
	}

	ISP_DEBUG("set up pagetable mapping by buffer information");
	ret = hisp_sec_mem_unmap(buffer, sfd);
	if (ret != SECISP_SUCCESS)
		ISP_ERR("hisp_sec_mem_map fail. ret.%u", ret);

	return ret;
}

static UINT32 isp_syscall_secisp_disreset(void)
{
	UINT32 ret;

	isp_mem_end_flag = 0;

	ret = secisp_disreset();
	if (ret != SECISP_SUCCESS)
		ISP_ERR("secisp_disreset fail. ret.%d", ret);

	return ret;
}

static UINT32 isp_syscall_secisp_reset(void)
{
	UINT32 ret;

	ret = secisp_reset();
	if (ret != 0)
		ISP_ERR("secisp_reset fail. ret.%u", ret);

	return ret;
}

static UINT32 isp_syscall_secisp_nonsec_mem_map(struct drv_param *params)
{
	struct sglist *sgl = NULL;
	secisp_mem_info *buffer = NULL;
	UINT32 ret;
	struct smmu_domain *domain = NULL;
	uint64_t *args = (uint64_t *)(uintptr_t)params->args;

	sgl = (struct sglist *)(uintptr_t)(args[0]);
	buffer = (secisp_mem_info *)(uintptr_t)(args[2]);
	if (args[3] != sizeof(secisp_mem_info)) {
		ISP_ERR("wrong buffer_size.0x%x", args[3]);
		return SECISP_FAIL;
	}

	ISP_INFO("secisp nonsec mem type is %s", secisp_type_info[buffer->type]);
	ISP_DEBUG("secisp mem info pa is 0x%llx, da is 0x%x, size is 0x%x", buffer->pa, buffer->da, buffer->size);
	ISP_DEBUG("secisp mem info sec_flag is %u, prot is 0x%x", buffer->sec_flag, buffer->prot);

	domain = siommu_domain_grab(SEC_TASK_SEC);
	if (domain == NULL) {
		ISP_ERR("page is not been set up!");
		return SECISP_FAIL;
	}

	ret = secisp_nonsec_map(domain, buffer, sgl);
	if (ret != 0)
		ISP_ERR("secisp_nonsec_map fail. type.%u, ret.%u.", buffer->type, ret);

	return ret;
}

static UINT32 isp_syscall_secisp_nonsec_mem_unmap(struct drv_param *params)
{
	struct sglist *sgl = NULL;
	secisp_mem_info *buffer = NULL;
	UINT32 ret;
	struct smmu_domain *domain = NULL;
	uint64_t *args = (uint64_t *)(uintptr_t)params->args;

	sgl = (struct sglist *)(uintptr_t)(args[0]);
	buffer = (secisp_mem_info *)(uintptr_t)(args[2]);
	if (args[3] != sizeof(secisp_mem_info)) {
		ISP_ERR("wrong buffer_size.0x%x", args[3]);
		return SECISP_FAIL;
	}

	ISP_INFO("secisp nonsec mem type is %s", secisp_type_info[buffer->type]);
	ISP_DEBUG("secisp mem info pa is 0x%llx, da is 0x%x, size is 0x%x", buffer->pa, buffer->da, buffer->size);
	ISP_DEBUG("secisp mem info sec_flag is %u, prot is 0x%x", buffer->sec_flag, buffer->prot);

	domain = siommu_domain_grab(SEC_TASK_SEC);
	if (domain == NULL) {
		ISP_ERR("page is not been set up!");
		return SECISP_FAIL;
	}

	ret = secisp_nonsec_unmap(domain, buffer, sgl);
	if (ret != 0)
		ISP_ERR("secisp_nonsec_unmap fail. type.%u, ret.%u.", buffer->type, ret);

	return ret;
}

static UINT32 isp_syscall_secisp_sec_mem_map(struct drv_param *params)
{
	UINT32 sfd;
	secisp_mem_info *buffer = NULL;
	UINT32 ret;
	uint64_t *args = (uint64_t *)(uintptr_t)params->args;

	sfd = (UINT32)(args[0]);
	buffer = (secisp_mem_info *)(uintptr_t)(args[2]);
	if (args[3] != sizeof(secisp_mem_info)) {
		ISP_ERR("wrong buffer_size.0x%x", args[3]);
		return SECISP_FAIL;
	}

	ISP_INFO("secisp sec mem info type is %s", secisp_type_info[buffer->type]);
	ISP_DEBUG("secisp mem info pa is 0x%llx, da is 0x%x, size is 0x%x", buffer->pa, buffer->da, buffer->size);
	ISP_DEBUG("secisp mem info sec_flag is %u, prot is 0x%x", buffer->sec_flag, buffer->prot);

	ret = secisp_sec_map(buffer, sfd);
	if (ret != 0)
		ISP_ERR("secisp_sec_map fail. type.%u, ret.%d", buffer->type, ret);

	if(buffer->type == SECISP_ISPSEC_POOL)
		isp_mem_end_flag = 1;

	return ret;
}

static UINT32 isp_syscall_secisp_sec_mem_unmap(struct drv_param *params)
{
	UINT32 sfd;
	secisp_mem_info *buffer = NULL;
	UINT32 ret;
	uint64_t *args = (uint64_t *)(uintptr_t)params->args;

	sfd = (UINT32)(args[0]);
	buffer = (secisp_mem_info *)(uintptr_t)(args[2]);
	if (args[3] != sizeof(secisp_mem_info)) {
		ISP_ERR("wrong buffer_size.0x%x", args[3]);
		return SECISP_FAIL;
	}

	ISP_INFO("secisp sec mem info type is %s", secisp_type_info[buffer->type]);
	ISP_DEBUG("secisp mem info pa is 0x%llx, da is 0x%x, size is 0x%x", buffer->pa, buffer->da, buffer->size);
	ISP_DEBUG("secisp mem info sec_flag is %u, prot is 0x%x", buffer->sec_flag, buffer->prot);

	ret = secisp_sec_unmap(buffer, sfd);
	if (ret != 0) {
		ISP_ERR("secisp_ummap fail. type.%u, ret.%u", buffer->type, ret);
		return ret;
	}

	isp_mem_end_flag = 0;

	return ret;
}

static UINT32 isp_syscall_secisp_mem_end(void)
{
	return isp_mem_end_flag;
}

static int isp_syscall(int swi_id, struct drv_param *params, UINT64 permissions)
{
	UINT32 uwRet;
	/* According to ARM AAPCS arguments from 5-> in a function call
	 * are stored on the stack, which in this case is pointer by
	 * user sp. Our own TrustedCore also push FP and LR on the stack
	 * just before SWI, so skip them */
	if (params == NULL || params->args == 0)
		return -1;
	uint64_t *args = (uint64_t *)(uintptr_t)params->args;
	UNUSED(args);

	HANDLE_SYSCALL(swi_id) {
		SYSCALL_PERMISSION(SW_SYSCALL_SECISP_DISRESET, permissions, ISP_GROUP_PERMISSION)
		ISP_INFO("sys call secisp disreset start!");
		uwRet = isp_syscall_secisp_disreset();
		args[0] = uwRet;
		ISP_INFO("sys call secisp disreset end!");
		SYSCALL_END

		SYSCALL_PERMISSION(SW_SYSCALL_SECISP_RESET, permissions, ISP_GROUP_PERMISSION)
		ISP_INFO("sys call secisp reset start!");
		uwRet = isp_syscall_secisp_reset();
		args[0] = uwRet;
		ISP_INFO("sys call secisp reset end!");
		SYSCALL_END

		SYSCALL_PERMISSION(SW_SYSCALL_SECISP_NONSEC_MEM_MAP, permissions, ISP_GROUP_PERMISSION)
		ISP_INFO("sys call secisp nonsec mem map start!");
		if (args[1] == 0 || args[3] == 0) {
			args[0] = OS_ERROR;
			goto out;
		}
		ACCESS_CHECK_A64(args[0], args[1]);
		ACCESS_CHECK_A64(args[2], args[3]);
		ACCESS_WRITE_RIGHT_CHECK(args[0], args[1]);
		ACCESS_WRITE_RIGHT_CHECK(args[2], args[3]);
		uwRet = isp_syscall_secisp_nonsec_mem_map(params);
		args[0] = uwRet;
		ISP_INFO("sys call secisp nonsec mem map end");
		SYSCALL_END

		SYSCALL_PERMISSION(SW_SYSCALL_SECISP_NONSEC_MEM_UNMAP, permissions, ISP_GROUP_PERMISSION)
		ISP_INFO("sys call secisp nonsec mem unmap start");
		if (args[1] == 0 || args[3] == 0) {
			args[0] = OS_ERROR;
			goto out;
		}
		ACCESS_CHECK_A64(args[0], args[1]);
		ACCESS_CHECK_A64(args[2], args[3]);
		ACCESS_WRITE_RIGHT_CHECK(args[0], args[1]);
		ACCESS_WRITE_RIGHT_CHECK(args[2], args[3]);
		uwRet = isp_syscall_secisp_nonsec_mem_unmap(params);
		args[0] = uwRet;
		ISP_INFO("sys call secisp nonsec mem unmap end");
		SYSCALL_END

		SYSCALL_PERMISSION(SW_SYSCALL_SECISP_SEC_MEM_MAP, permissions, ISP_GROUP_PERMISSION)
		ISP_INFO("sys call secisp sec mem map start!");
		if (args[3] == 0) {
			args[0] = OS_ERROR;
			goto out;
		}
		ACCESS_CHECK_A64(args[2], args[3]);
		ACCESS_WRITE_RIGHT_CHECK(args[2], args[3]);
		uwRet = isp_syscall_secisp_sec_mem_map(params);
		args[0] = uwRet;
		ISP_INFO("sys call secisp sec mem map end");
		SYSCALL_END

		SYSCALL_PERMISSION(SW_SYSCALL_SECISP_SEC_MEM_UNMAP, permissions, ISP_GROUP_PERMISSION)
		ISP_INFO("sys call secisp sec mem unmap start");
		if (args[3] == 0) {
			args[0] = OS_ERROR;
			goto out;
		}
		ACCESS_CHECK_A64(args[2], args[3]);
		ACCESS_WRITE_RIGHT_CHECK(args[2], args[3]);
		uwRet = isp_syscall_secisp_sec_mem_unmap(params);
		args[0] = uwRet;
		ISP_INFO("sys call secisp sec mem unmap end");
		SYSCALL_END

		SYSCALL_PERMISSION(SW_SYSCALL_SECISP_MEM_END, permissions, FR_GROUP_PERMISSION)
		ISP_INFO("sys call secisp mem end start");
		uwRet = isp_syscall_secisp_mem_end();
		args[0] = uwRet;
		ISP_INFO("sys call secisp mem end end");
		SYSCALL_END
	default:
		return -1;
	}
	return 0; /*lint !e438*/
}
/*lint -e528 -esym(528,*)*/

DECLARE_TC_DRV(isp_driver, 0, 0, 0, TC_DRV_MODULE_INIT, NULL, NULL, isp_syscall, NULL, NULL);
/*lint +e528 -esym(528,*)*/

