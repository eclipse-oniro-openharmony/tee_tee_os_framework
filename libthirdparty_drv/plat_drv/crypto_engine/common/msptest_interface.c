/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: hieps drive interface, Analysis of test commands，
 *              call different test interfaces
 * Author: zhaohaisheng z00452790
 * Create: 2018-12-01
 */
#include <securec.h>
#include <sre_sys.h>
#include <sre_syscall.h>
#include <hm_unistd.h>
#include <tee_log.h>
#include <string.h>
#include <ipc_call.h> /* __smc_switch_to_atf */
#include <mem_mode.h> /* non_secure */
#include <drv_mem.h> /* sre_mmap */
#include <register_ops.h> /* read32 */
#include <msptest_interface.h>
#include <hat_entry.h>
#include <hieps_smc.h>
#include <hieps_errno.h>
#include <hieps_power.h>
#include <secmem.h>
#include <hieps_timer.h>
#include <hieps_cdrm_cmd.h>
#include <hat_framework.h>
#include <hat_memory.h>
#include <mspc_test.h>
#include <mspe_power.h>
#include <hisee_video_cmaion_mgr.h>
#include <secmem.h>
#include <mem_mode.h>
#include <sec_smmu_com.h>

typedef uint32_t (*msptest_ecall_func)(uint32_t, const struct msptest_to_tee_parms *, char *);

struct common_test_func_s {
	msptest_ecall_func    ecall_func;
	char    *desc;
};

/*
 * @brief      : hieps_ion_map_buffer  buf_id ——> pvir_addr g_iova_addr
 * @param[in]  : ion buf id, ion buf size, ion cache mode, va, iova
 * @return     : 0：success，!0：fail
 * @note       : get va and iova
 */
static uint32_t hieps_ion_map_buffer(uint32_t buf_id, uint32_t buf_size,
	uint32_t cache_mode, uint32_t *pvir_addr, uint32_t *piova_addr)
{
	uint32_t ret;
	uint32_t ret1;
	struct mem_chunk_list mcl = {0};

	mcl.protect_id = SEC_TASK_DRM;
	mcl.buff_id = buf_id;
	mcl.size = buf_size;
	mcl.cache = cache_mode;
	tloge("hieps: buf_id = %d, buf_size = %d\n", buf_id, buf_size);
	ret = sion_map_kernel(&mcl);
	if (ret != HIEPS_TEEOS_SUCCESS) {
		tloge("hieps: map va addr failed, ret: 0x%x\n", ret);
		return ret;
	}
	*pvir_addr = mcl.va;

	ret = sion_map_iommu(&mcl);
	if (ret != HIEPS_TEEOS_SUCCESS) {
		tloge("hieps: map iova failed, ret: 0x%x\n", ret);
		ret1 = sion_unmap_kernel(&mcl);
		if (ret1 != HIEPS_TEEOS_SUCCESS)
			tloge("hieps:unmap kernel failed, ret1 = %d", ret1);
		return ret;
	}
	*piova_addr = mcl.va;
	return ret;
}

/*
 * @brief      : hieps_ion_unmap_buffer
 * @param[in]  : buf-> id  buf-> size
 * @return     : 0：success，!0：fail
 * @note       : unmap buffer
 */
static uint32_t hieps_ion_unmap_buffer(uint32_t buf_id, uint32_t buf_size)
{
	uint32_t ret;
	struct mem_chunk_list mcl = {0};

	mcl.protect_id = SEC_TASK_DRM;
	mcl.buff_id    = buf_id;
	mcl.size       = buf_size;
	mcl.smmuid     = SMMU_MEDIA2;
	mcl.sid        = SECSMMU_STREAMID_EPS;
	mcl.ssid       = SECSMMU_SUBSTREAMID_EPS;
	ret = sion_unmap_kernel(&mcl);
	if (ret) {
		tloge("hieps: unmap va failed ret: 0x%x\n", ret);
		return ret;
	}

	ret = sion_unmap_iommu(&mcl);
	if (ret)
		tloge("hieps: unmap iova failed ret: 0x%x\n", ret);
	return ret;
}

/*
 * @brief      : ion and cma mmemroy map unmap test
 * @return     : 0：success，!0：fail
 */
static uint32_t ion_mem_test(const struct msptest_to_tee_parms *parm_info)
{
	uint32_t ret = 0;
	uint32_t ion_iova = 0;
	uint32_t ion_va   = 0;
	uint32_t cma_va;
	uint32_t ion_len = parm_info->ion_len;
	uint32_t sharefd = parm_info->ion_sharefd;
	uint32_t cma_phy = parm_info->cma_phy;
	uint32_t cma_len = parm_info->cma_len;
	uint32_t ret1;

	tloge("sharefd = %d, ion_len = %d, cma_phy = 0x%x, cma_len = %d.\n",
		parm_info->ion_sharefd, parm_info->ion_len, parm_info->cma_phy, parm_info->cma_len);

	ret = sre_mmap(cma_phy, cma_len, (unsigned int *)(uintptr_t)&cma_va, non_secure, non_cache);
	if (ret != HIEPS_TEEOS_SUCCESS) {
		tloge("hieps: sre map failed ! ret = 0x%x\n", ret);
		return ret;
	}
	tloge("hieps: sre map success !\n");
	ret = hieps_ion_map_buffer(sharefd, ion_len, non_cache, &ion_va, &ion_iova);
	if (ret != HIEPS_TEEOS_SUCCESS) {
		tloge("hieps: ion map failed ! ret = 0x%x\n", ret);
		ret1 = sre_unmap(cma_va, cma_len);
		if (ret1 != HIEPS_TEEOS_SUCCESS)
			tloge("hieps: sre unmap failed,ret1 = %d\n", ret1);
		return ret;
	}
	tloge("hieps: ion map success !\n");

	ret = hieps_ion_unmap_buffer(sharefd, ion_len);
	if (ret != HIEPS_TEEOS_SUCCESS)
		tloge("hieps: ion unmap failed ! ret = 0x%x\n", ret);
	else
		tloge("hieps: ion unmap success !\n");

	ret = sre_unmap(cma_va, cma_len);
	if (ret != HIEPS_TEEOS_SUCCESS)
		tloge("hieps: sre unmap failed ! ret = 0x%x\n", ret);
	else
		tloge("hieps: sre unmap success !\n");
	return ret;
}

/*
 * @brief      : hieps_ta_drives_test  ta-->teeos test
 * @param[in]  : NA
 * @return     : success
 * @note       : NA
 */
static uint32_t hieps_ta_drives_test(void)
{
	uint32_t ret = HIEPS_TEEOS_SUCCESS;

	tloge("hieps: ta to drivers test success!\n");
	return ret;
}

/*
 * @brief      : hieps_smc_to_atf_test : teeos-->atf test
 * @param[in]  : NA
 * @return     : HIEPS_TEEOS_SUCCESS is success, OTHER is failed
 * @note       : NA
 */
static uint32_t hieps_smc_to_atf_test(void)
{
	uint32_t ret;
	kcall_tee_smc_atf_t hieps_smc_data = {
		.x1 = HIEPS_ATF_TEEOS_TEST_CMD,
		.x2 = 0,
		.x3 = 0,
		.x4 = 0,
	};

	ret = __smc_switch_to_atf(HIEPS_SMC_FID, &hieps_smc_data);
	if (ret != HIEPS_OK)
		tloge("hieps: TEEOS to ATF smc test failed! ret = 0x%x\n", ret);
	else
		tloge("hieps: TEEOS to ATF smc test successful!\n");
	return ret;
}

/*
 * @brief      : hieps_atf_kernel_test  atf-->kernel test
 * @param[in]  : NA
 * @return     : HIEPS_TEEOS_SUCCESS is success, OTHER is failed
 * @note       : NA
 */
static uint32_t hieps_atf_kernel_test(void)
{
	uint32_t ret;

	ret = hieps_smc_send_process(HIEPS_ATF_KERNEL_TEST_CMD, 0, 0, 0);
	if (ret != HIEPS_OK) {
		tloge("hieps: send smc failed! ret = 0x%x\n", ret);
		return ret;
	}

	/* ATF-->Kernel test use the power result memory to transfer data. */
	ret = read32(HIEPS_POWER_RESULT_ADDR);
	if (ret != HIEPS_ATF_KERNEL_TEST_SUCCESS) {
		tloge("hieps: ATF<->Kernel test failed!ret=0x%x\n", ret);
	} else {
		tloge("hieps: ATF<->Kernel test successful\n");
		ret = HIEPS_TEEOS_SUCCESS;
	}
	return ret;
}

/*
 * @brief      : hieps_loop_test  Complete pathway test
 * @param[in]  : test data pointer
 * @return     : HIEPS_TEEOS_SUCCESS is success, OTHER is failed
 * @note       : test data pathway(CA-TA-TEEOS-ATF-KRNEL)
 *               return data pathway(KERNEL-TAF-TEEOS-TA-CA)
 */
static uint32_t hieps_loop_test(const struct msptest_to_tee_parms *parm_info)
{
	uint32_t ret;
	uint32_t test_data;
	uint32_t return_data;
	char *pparm = NULL;

	pparm = (char *)&(parm_info->parm[0]);
	test_data = (uint32_t)atoi(pparm);

	ret = hieps_smc_send_process(HIEPS_LOOP_TEST_CMD, test_data, 0, 0);
	if (ret != HIEPS_OK) {
		tloge("hieps: send smc failed! ret = 0x%x\n", ret);
		return ret;
	}

	/* Loop test use the power result memory to transfer data. */
	return_data = read32(HIEPS_POWER_RESULT_ADDR);
	if (return_data != ~test_data) {
		tloge("hieps: loop test failed! Recv:%d, Expected:%d\n",
			return_data, ~test_data);
		ret = HIEPS_TEEOS_LOOP_TEST_DATA_ERROR;
	} else {
		tloge("hieps: loop test sucessful!\n");
		ret = HIEPS_TEEOS_SUCCESS;
	}
	return ret;
}

/*
 * @brief      : hieps_power_ctrl hieps power contrl
 * @param[in]  : cmd, data pointer
 * @return     : HIEPS_TEEOS_SUCCESS is success, OTHER is failed
 * @note       : test CA TA power control interface
 */
static uint32_t hieps_power_ctrl(uint32_t cmd, const struct msptest_to_tee_parms *parm_info)
{
	uint32_t ret = HIEPS_TEEOS_ERROR;
	uint32_t power_id, profile_id;
	uint32_t parmnum;
	char *pparm = NULL;

	parmnum = parm_info->parm_num;
	if (parmnum != 2) {   /* power id and profile id */
		tloge("hieps: Invalid param!\n");
		return HIEPS_TEEOS_PARM_ERROR;
	}

	pparm = (char *)&(parm_info->parm[0]);
	if (!pparm) {
		tloge("hieps: pparm is null\n");
		return HIEPS_TEEOS_PARM_ERROR;
	}
	power_id = (uint32_t)atoi(pparm);
	pparm = (char *)&(parm_info->parm[1]);
	if (!pparm) {
		tloge("hieps: pparm1 is null\n");
		return HIEPS_TEEOS_PARM_ERROR;
	}
	profile_id = (uint32_t)atoi(pparm);
	tloge("hieps powerid = %d, profileid = %d\n", power_id, profile_id);

	if (cmd == HIEPS_POWERON)
		ret = hieps_power_on(power_id, profile_id);
	else if (cmd == HIEPS_POWEROFF)
		ret = hieps_power_off(power_id, profile_id);
	else
		tloge("%s-%d:Invalid cmd:%x!", __func__, __LINE__, cmd);

	if (ret != HIEPS_OK) {
		tloge("HiEPS: power operation failed! ret = %x\n", ret);
		return HIEPS_TEEOS_RESULT_ERROR;
	}

	/* factory test for msp engine */
	if (cmd == HIEPS_POWERON && power_id == 0) {
		ret = (uint32_t)mspe_factory_test();
		tloge("mspe_factory_test, ret=%x\n", ret);
		if (ret == BSP_RET_OK)
			ret = HIEPS_OK;
	}

	return ret;
}

/*
 * @brief      : ecall_func_test  ecall func test
 * @param[in]  : parm num , parm pointer
 * @return     : HIEPS_TEEOS_SUCCESS is success, OTHER is failed
 */
static uint32_t ecall_func_test(uint32_t num, const struct msptest_to_tee_parms *parm_info, char *iodata)
{
	(void)num;
	(void)parm_info;
	(void)iodata;
	tloge("msptest: ecall test success\n");
	return HIEPS_TEEOS_SUCCESS;
}

/*
 * @brief      : cdrm_test  cdrm ipc send addr and size test
 * @param[in]  : parm num , parm pointer
 * @return     : HIEPS_TEEOS_SUCCESS is success, OTHER is failed
 */
static uint32_t cdrm_test(uint32_t num, const struct msptest_to_tee_parms *parm_info, char *iodata)
{
	(void)num;
	(void)parm_info;
	(void)iodata;
	//u32 addr = 0x1000; /* Just a test data. */
	//u32 size = 0x123; /* Just a test data. */

	tloge("HiEPS: Test CDRM IPC send!\n");
	// hieps_send_cdrm_msg(addr, size);
	return HIEPS_OK;

}

/*
 * @brief      : hieps_get_lcs : get hieps lcs mode.
 *
 * @param[in]  : num parm pointer.
 * @param[in]  : parm_info parm data.
 *
 * @return     : lcs
 */
static uint32_t hieps_get_lcs(uint32_t num, const struct msptest_to_tee_parms *parm_info, char *iodata)
{
	(void)num;
	(void)parm_info;
	(void)iodata;
	uint32_t ret, lcs;

	ret = hieps_smc_send_process(HIEPS_GET_LCS_CMD, 0, 0, 0);
	if (ret != HIEPS_OK) {
		tloge("hieps: send smc failed! ret = 0x%x\n", ret);
		return ret;
	}

	lcs = read32(HIEPS_LCS_ADDR);
	tloge("hieps lcs: 0x%x!\n", lcs);
	tloge("hieps: ICCT:0x1E7887E1, ICDT:0x376A1DC3, UM:0x565F3E6A\n");
	tloge("hieps: RMA:0x7B8A17A5, SDM:0x9C31AF2B\n");

	return lcs;
}

struct common_test_func_s common_test_func_tbl[] = {
	{ ecall_func_test,        "ecall_func_test" },
	{ cdrm_test,              "cdrm_test" },
	{ hieps_get_lcs,          "get_lcs" },
	{ mspc_driver_test,       "mspc_driver_test" },
};

/*
 * @brief      : common_test_process  common process
 * @param[in]  : input pointer, input len
 * @return     : HIEPS_TEEOS_SUCCESS is success, OTHER is failed
 * @note       : teeos Functions call
 */
static uint32_t common_test_process(char * iodata, const struct msptest_to_tee_parms *parm_info)
{
	uint32_t ret;
	uint32_t parmnum;
	char *pfunc_name = NULL;
	uint32_t i;

	parmnum = parm_info->parm_num;
	if (parmnum > PARMNUM) {
		ret = HIEPS_TEEOS_PARM_ERROR;
		return ret;
	}
	pfunc_name = (char *)&(parm_info->parm[0]);
	uint32_t count = sizeof(common_test_func_tbl) / sizeof(struct common_test_func_s);

	for (i = 0; i < count; i++) {
		if (strncmp(common_test_func_tbl[i].desc, pfunc_name,
			strlen(common_test_func_tbl[i].desc) + 1) == 0) {
			if (common_test_func_tbl[i].ecall_func) {
				/* the numbers of parameters remove the function name */
				ret = common_test_func_tbl[i].ecall_func(parmnum - 1, parm_info, iodata);
				return ret;
			}
			break;
		}
	}
	tloge("msptest common test func error.\n");
	ret = HIEPS_TEEOS_CMD_ERROR;
	return ret;
}

/*
 * @brief      : hat_testcase_entry  hat_testcase_entry
 * @param[in]  : input pointer, input data len, max data len, ion sharefd, ion len
 * @return     : HIEPS_TEEOS_SUCCESS is success, OTHER is failed
 */
static uint32_t hat_testcase_entry(char *data, uint32_t size, uint32_t max_len)
{
	uint32_t ret = HIEPS_TEEOS_ERROR;
	err_bsp_t proc_ret;
	int32_t libc_ret;
	struct basic_data pdata;

	pdata.size = hat_packet_max_size();
	pdata.size = MAX(pdata.size, size);
	pdata.pdata = hat_alloc(HAT_MEM_TYPE_DEF, pdata.size);
	if (PAL_CHECK(!pdata.pdata)) {
		tloge("malloc %d failed for pack size = %d\n", pdata.size, size);
		return HIEPS_TEEOS_ERROR;
	}

	libc_ret = memmove_s(pdata.pdata, pdata.size, data, size);
	if (PAL_CHECK(libc_ret != EOK)) {
		tloge("memmove_s data to pdata.pdata!\n");
		ret = HIEPS_TEEOS_ERROR;
		goto hat_exit;
	}

	proc_ret = hat_process(HAT_PORT_PACK, pdata.pdata, &pdata.size);
	if (PAL_CHECK(proc_ret != BSP_RET_OK)) {
		tloge("hat_process failed\n");
		ret = HIEPS_TEEOS_ERROR;
		goto hat_exit;
	}

	libc_ret = memmove_s(((u32 *)data + 1), max_len - sizeof(u32), pdata.pdata, pdata.size);
	if (PAL_CHECK(libc_ret != EOK)) {
		tloge("memmove_s pdata.pdata to data!\n");
		ret = HIEPS_TEEOS_ERROR;
		goto hat_exit;
	}
	*((uint32_t *)data) = sizeof(u32) + pdata.size;

	ret = HIEPS_TEEOS_SUCCESS;
hat_exit:
	hat_free(HAT_MEM_TYPE_DEF, pdata.pdata);
	return ret;
}

/*
 * @brief      : hieps_seceng_process  hieps seceng process
 * @param[in]  : input pointer, input data len, max data len, ion sharefd, ion len
 * @return     : 0：success，!0：fail
 * @note       : NA
 */
static uint32_t hieps_seceng_process(char *input, const struct msptest_to_tee_parms *parm_info)
{
	uint32_t ret1 = HIEPS_TEEOS_ERROR;
	uint32_t ret2 = HIEPS_TEEOS_ERROR;
	uint32_t ret3 = HIEPS_TEEOS_ERROR;
	uint32_t ret4 = HIEPS_TEEOS_ERROR;
	uint32_t ret5 = HIEPS_TEEOS_ERROR;
	uint32_t ion_len = parm_info->ion_len;
	uint32_t sharefd = parm_info->ion_sharefd;
	uint32_t inputlen = parm_info->real_data_len;
	uint32_t max_data_len = parm_info->max_data_len;
	uint32_t cma_phy = parm_info->cma_phy;
	uint32_t cma_len = parm_info->cma_len;
	uintptr_t cma_va = 0;
	uint32_t ion_iova = 0;
	uint32_t ion_va   = 0;

	/* ion test func */
	if (parm_info->ion_test_flag == 1) {
		uint32_t ret = ion_mem_test(parm_info);
		return ret;
	}

	if (ion_len > 0) {
		/* map cma */
		ret1 = sre_mmap(cma_phy, cma_len, (unsigned int *)&cma_va, non_secure, non_cache);
		if (ret1 != HIEPS_TEEOS_SUCCESS) {
			tloge("hieps: sre map failed ! ret1 = 0x%x\n", ret1);
			ret1 = HIEPS_TEEOS_MMAP_ERROR;
			goto exit_0;
		}
		/* map ion */
		ret2 = hieps_ion_map_buffer(sharefd, ion_len, non_cache, &ion_va, &ion_iova);
		if (ret2 != HIEPS_TEEOS_SUCCESS) {
			tloge("hieps: ion map failed ! ret2 = 0x%x\n", ret2);
			ret2 = HIEPS_TEEOS_MMAP_ERROR;
			goto exit_0;
		}

		tloge("cma_va=%x,cma_len=%x\n", cma_va, cma_len);
		tloge("sharefd=%d,ion_iova=%x,ion_len=%d\n", sharefd, ion_iova, ion_len);
		hisee_video_cma_init((u32)(uintptr_t)cma_va, cma_phy, cma_len);
		hisee_video_ion_init(sharefd, ion_iova, ion_va, ion_len);
	}

	/* seceng test entry */
	ret3 = hat_testcase_entry((void *)input, inputlen, max_data_len);
	if (ret3 != HIEPS_TEEOS_SUCCESS)
		tloge("hieps: seceng test failed! ret3 = %x\n", ret3);
	else
		ret3 = HIEPS_TEEOS_SUCCESS;

exit_0:
	if (ion_len > 0) {
		/* unmap ion */
		if (ret1 == HIEPS_TEEOS_SUCCESS) {
			ret4 = hieps_ion_unmap_buffer(sharefd, ion_len);
			if (ret4 != HIEPS_TEEOS_SUCCESS)
				tloge("hieps: ion unmap failed! ret4 = %x\n", ret4);
		}
		/* unmap cma */
		if (ret2 == HIEPS_TEEOS_SUCCESS) {
			ret5 = sre_unmap((u32)cma_va, cma_len);
			if (ret5 != HIEPS_TEEOS_SUCCESS)
				tloge("hieps: cma unmap failed! ret5 = %x\n", ret5);
		}
	}

	return ret3;
}

/*
 * @brief      : hieps_cmd_analysis_moudle  cmd analysis
 * @param[in]  : cmd, input pointer, max data len, msptest_to_tee_parms pointer
 * @return     : 0：success，!0：fail
 * @note       : NA
 */
static uint32_t hieps_cmd_analysis_moudle(uint32_t cmd, char *input,
	uint32_t max_data_len, const struct msptest_to_tee_parms *parm_info)
{
	(void)max_data_len;
	uint32_t ret;

	switch (cmd) {
	case HIEPS_POWERON:
	case HIEPS_POWEROFF:
		ret = hieps_power_ctrl(cmd, parm_info);
		break;
	case HIEPS_LOOP_TEST:
		ret = hieps_loop_test(parm_info);
		break;
	case HIEPS_TA_DRIVES_TEST:
		ret = hieps_ta_drives_test();
		break;
	case HIEPS_DRIVES_ATF_TEST:
		ret = hieps_smc_to_atf_test();
		break;
	case HIEPS_ATF_KERNEL_TEST:
		ret = hieps_atf_kernel_test();
		break;
	case HIEPS_SECENG_TEST:
		ret = hieps_seceng_process(input, parm_info);
		break;
	case HIEPS_ECALL:
		/* Fall-through */
	case COMMON_TEST:
		ret = common_test_process(input, parm_info);
		break;
	default:
		tloge("msptest: Invalid cmd:0x%x\n", cmd);
		ret = HIEPS_TEEOS_CMD_ERROR;
		break;
	}

	return ret;
}

/*
 * @brief      : tee_call_hieps_drivers  ta-->teeos entry function
 * @param[in]  : cmd, iodata, max data len, parm pointer, param size
 * @return     : 0：success，!0：fail
 * @note       : NA
 */
uint32_t tee_call_hieps_drivers(uint32_t cmd, char *iodata,
	uint32_t max_data_len, const char *parm_info, uint32_t parm_size)
{
	uint32_t ret;
	struct msptest_to_tee_parms *pparm_info = NULL;

	pparm_info = (struct msptest_to_tee_parms *)parm_info;
	if (iodata == NULL || pparm_info == NULL ||
		(parm_size != sizeof(struct msptest_to_tee_parms))) {
		ret = HIEPS_TEEOS_DATA_ERROR;
		tloge("msptest: parm error.\n");
		return ret;
	}
	ret = hieps_cmd_analysis_moudle(cmd, iodata, max_data_len, pparm_info);
	if (ret != HIEPS_TEEOS_SUCCESS)
		tloge("msptest: error in cmd_analysis_moudle ret = 0x%x!\n", ret);
	return ret;
}
