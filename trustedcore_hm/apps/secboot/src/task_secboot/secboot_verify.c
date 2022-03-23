/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2013-2019. All rights reserved.
 * Description: secboot verify, called by secboot TA
 * Create: 2013/5/16
 */

#include "secboot_verify.h"
#include "tee_defines.h"
#include "tee_log.h"
#include "mem_page_ops.h"
#include <secureboot/secboot.h>
#include <securec.h>
#include "secboot_drv_call.h"

#define SECBOOT_INVALID_ADDR 0xFFFFFFFF
#if (TRUSTEDCORE_PLATFORM_CHOOSE == WITH_HIGENERIC_PLATFORM)
#define SECBOOT_VRL_SIZE 0x1000
#endif
#if (TRUSTEDCORE_PLATFORM_CHOOSE == WITH_BALONG_V722_PLATFORM)
#define SECBOOT_VRL_SIZE 0x1000
#endif

#define SECBOOT_INIT_PROCESS_TYPE 0
#define SECBOOT_FAIL_PROCESS_TYPE 1
#define SECBOOT_SUCC_PROCESS_TYPE 2

uint32_t g_vrl_buffer[MAX_SOC][SECBOOT_VRL_SIZE / sizeof(uint32_t)];

TEE_Result seb_reset_image(uint32_t paramtypes, TEE_Param params[PARAMS_COUNT])
{
	TEE_Result ret;
	unsigned int soc_type;

	if (!check_param_type(paramtypes, TEE_PARAM_TYPE_VALUE_INPUT,
			      TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
			      TEE_PARAM_TYPE_NONE)) {
		tloge("paramtypes is not valid\n");
		ret = TEE_ERROR_GENERIC;
		return ret;
	}

	soc_type = params[0].value.a;
	if (soc_type < MAX_SOC) {
		ret = (TEE_Result)__hisi_secboot_soc_reset(soc_type);
	} else {
		tloge("invalid soc type!\n");
		ret = TEE_FAIL;
	}
	return ret;
}

TEE_Result seb_copy_vrl_type(uint32_t paramtypes,
			     TEE_Param params[PARAMS_COUNT])
{
	TEE_Result ret;
	unsigned int soc_type;
	void *src_addr = NULL;
	uint32_t size;

	if (!check_param_type(paramtypes, TEE_PARAM_TYPE_VALUE_INPUT,
			      TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_NONE,
			      TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	soc_type = params[0].value.a;
	src_addr = params[1].memref.buffer;
	size = (uint32_t)params[1].memref.size;
	if (soc_type >= MAX_SOC) {
		tloge("soc type(0x%x) is not correct\n", soc_type);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (size > SECBOOT_VRL_SIZE) {
		tloge("size(0x%x) is too large\n", size);
		ret = TEE_ERROR_BAD_PARAMETERS;
	} else {
		if (memcpy_s((void *)(&g_vrl_buffer[soc_type][0]),
			       SECBOOT_VRL_SIZE, src_addr, size) != EOK)
			ret = TEE_ERROR_GENERIC;
		else
			ret = TEE_SUCCESS;
	}
	return ret;
}

TEE_Result seb_copy_soc_data_type(uint32_t paramtypes,
				  TEE_Param params[PARAMS_COUNT])
{
	TEE_Result ret;
	unsigned int soc_type;
	paddr_t src_addr;
	uint32_t size;
	uint32_t offset;
	paddr_t dst_addr;

	if (!check_param_type(paramtypes, TEE_PARAM_TYPE_VALUE_INPUT,
			      TEE_PARAM_TYPE_VALUE_INPUT,
			      TEE_PARAM_TYPE_VALUE_INPUT,
			      TEE_PARAM_TYPE_VALUE_INPUT)) {
		tloge("paramtypes is not valid\n");
		ret = TEE_ERROR_GENERIC;
		return ret;
	}

	soc_type = params[0].value.a;
	if (soc_type >= MAX_SOC) {
		tloge("soc type(0x%x) is not correct\n", soc_type);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	src_addr = params[2].value.a | ((paddr_t)params[2].value.b << BITS32);
	size = (uint32_t)params[3].value.a; /* get size from params[3] */
	dst_addr = params[0].value.b | ((paddr_t)params[1].value.a << BITS32);
	offset = params[1].value.b;

	/* first copy check and config dst addr */
	if (offset == 0) {
		/* check dst addr is valid, if valid to continue buffer copy */
		ret = (TEE_Result)__hisi_secboot_process_soc_addr(
			soc_type, dst_addr, SECBOOT_INIT_PROCESS_TYPE);
		if (ret) {
			tloge("process soc addr fail\n");
			return ret;
		}
	}
	return (TEE_Result)__hisi_secboot_copy_soc_data(soc_type, offset,
							src_addr, size);
}

TEE_Result seb_copy_soc_img_type(uint32_t paramtypes,
				 TEE_Param params[PARAMS_COUNT])
{
	TEE_Result ret;
	unsigned int soc_type;
	paddr_t img_addr;

	if (!check_param_type(paramtypes, TEE_PARAM_TYPE_VALUE_INPUT,
			      TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_NONE,
			      TEE_PARAM_TYPE_NONE)) {
		tloge("paramtypes is not valid\n");
		ret = TEE_ERROR_GENERIC;
		return ret;
	}

	soc_type = params[0].value.a;
	img_addr = params[1].value.a | (((paddr_t)params[1].value.b) << BITS32);

	if (soc_type >= MAX_SOC) {
		tloge("soc type(0x%x) is not correct\n", soc_type);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	ret = (TEE_Result)__hisi_secboot_process_soc_addr(
		soc_type, img_addr, SECBOOT_INIT_PROCESS_TYPE);
	if (!ret) {
		/* copy img data from secure buffer to run addr */
		ret = (TEE_Result)__hisi_secboot_copy_img_from_os(soc_type);
		if (!ret)
			/* process input addr succ to disreset the soc */
			ret = (TEE_Result)__hisi_secboot_soc_set(soc_type);
	} else {
		/* copy img data fail to clean run addr */
		if (__hisi_secboot_process_soc_addr(soc_type, img_addr,
						    SECBOOT_FAIL_PROCESS_TYPE))
			tloge("process image addr failed");
	}
	return ret;
}

TEE_Result seb_verify_soc_data_type(uint32_t paramtypes,
				    TEE_Param params[PARAMS_COUNT])
{
	TEE_Result ret;
	unsigned int soc_type;
	unsigned int lock_state;
	paddr_t image_address;
	uint32_t vrl_address;

	if (!check_param_type(paramtypes, TEE_PARAM_TYPE_VALUE_INPUT,
			      TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_NONE,
			      TEE_PARAM_TYPE_NONE)) {
		tloge("paramtypes is not valid\n");
		ret = TEE_ERROR_GENERIC;
		return ret;
	}

	soc_type = params[0].value.a;
	lock_state = params[0].value.b;
	image_address =
		params[1].value.a | ((paddr_t)params[1].value.b << BITS32);
	if (soc_type >= MAX_SOC) {
		tloge("soc type(0x%x) is not correct\n", soc_type);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	vrl_address = (uint32_t)(uintptr_t)&g_vrl_buffer[soc_type][0];
	ret = (TEE_Result)__hisi_secboot_soc_verification(
		soc_type, vrl_address, image_address, lock_state);
	if (!ret) {
		/* verify succ to proccess input addr */
		ret = (TEE_Result)__hisi_secboot_process_soc_addr(
			soc_type, image_address, SECBOOT_SUCC_PROCESS_TYPE);
		if (!ret)
			/* process input addr succ to disreset the soc */
			ret = (TEE_Result)__hisi_secboot_soc_set(soc_type);
	} else {
		/* verify fail to clean input addr and return verify errcode */
		if (__hisi_secboot_process_soc_addr(soc_type, image_address,
						    SECBOOT_FAIL_PROCESS_TYPE))
			tloge("process image addr failed\n");
	}
	return ret;
}

/*
 * this macro can't be open in ship version cause if ree sends an address,
 * it may cause any address to be written in tee.
 */
#ifdef HW_RANDOM_HISI_TRNG
TEE_Result seb_get_rng_num(uint32_t paramtypes, TEE_Param params[PARAMS_COUNT])
{
	if (!check_param_type(paramtypes, TEE_PARAM_TYPE_MEMREF_INOUT,
			      TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
			      TEE_PARAM_TYPE_NONE)) {
		tloge("paramtypes is not valid\n");
		return TEE_ERROR_GENERIC;
	}

	void *random_buff = params[0].memref.buffer;
	size_t random_len = params[0].memref.size;

	if (!random_buff || random_len == 0) {
		tloge("%s: params is invalid!\n", __func__);
		return TEE_ERROR_GENERIC;
	}

	TEE_GenerateRandom(random_buff, random_len);
	tlogd("success to get random data from engine\n");

	return TEE_SUCCESS;
}
#endif
