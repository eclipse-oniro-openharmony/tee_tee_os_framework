/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: hieps drive interface, Analysis of test commands，
 *              call different test interfaces
 * Author: zhaohaisheng z00452790
 * Create: 2018-12-01
 */
#include <mspe_test.h>
#include <drv_mem.h> /* sre_mmap */
#include <eps_ddr_layout_define.h>
#include <hat_entry.h>
#include <hat_framework.h>
#include <hat_memory.h>
#include <hieps_cdrm_cmd.h>
#include <hieps_errno.h>
#include <hieps_power.h>
#include <hieps_smc.h>
#include <hieps_timer.h>
#include <hisee_video_cmaion_mgr.h>
#include <hm_unistd.h>
#include <ipc_call.h> /* __smc_switch_to_atf */
#include <mem_mode.h> /* non_secure */
#include <msp_ta_channel.h>
#include <mspe_power.h>
#include <register_ops.h> /* read32 */
#include <sec_smmu_com.h>
#include <secmem.h>
#include <securec.h>
#include <soc_acpu_baseaddr_interface.h>
#include <string.h>
#include <tee_log.h>
#include <mspe_factory.h>

#define HIEPS_LCS_ADDR            (EPS_LCS_ADDR(HIEPS_DDR_SPACE_BASE_ADDR))
struct mspe_chan_cb_s {
    uint32_t cmd;
    uint32_t (*cb_func)(char *iodata, const struct msp_chan_parms *chan_parms);
};

struct msptest_to_tee_parms {
    char parm[PARMNUM][PARMSIZE];
    uint32_t parm_num;
    uint32_t ion_test_flag;
    uint32_t real_data_len;
    uint32_t max_data_len;
    uint32_t ion_sharefd;
    uint32_t ion_len;
    uint32_t cma_phy;
    uint32_t cma_len;
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
    if (ret != 0) {
        tloge("hieps: map va addr failed, ret: 0x%x\n", ret);
        return ret;
    }
    *pvir_addr = mcl.va;

    ret = sion_map_iommu(&mcl);
    if (ret != 0) {
        tloge("hieps: map iova failed, ret: 0x%x\n", ret);
        ret1 = sion_unmap_kernel(&mcl);
        if (ret1 != 0)
            tloge("hieps:unmap kernel failed, ret1 = %d", ret1);
        return ret;
    }
    *piova_addr = mcl.va;
    return HIEPS_TEEOS_SUCCESS;
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
    if (ret != 0) {
        tloge("hieps: unmap va failed ret: 0x%x\n", ret);
        return ret;
    }

    ret = sion_unmap_iommu(&mcl);
    if (ret != 0) {
        tloge("hieps: unmap iova failed ret: 0x%x\n", ret);
        return ret;
    }

    return HIEPS_TEEOS_SUCCESS;
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
 * @brief      : hieps_smc_to_atf_test : teeos-->atf test
 * @param[in]  : NA
 * @return     : HIEPS_TEEOS_SUCCESS is success, OTHER is failed
 * @note       : NA
 */
static uint32_t hieps_smc_to_atf_test(char *iodata, const struct msp_chan_parms *chan_parms)
{
    (void)iodata;
    (void)chan_parms;
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
static uint32_t hieps_atf_kernel_test(char *iodata, const struct msp_chan_parms *chan_parms)
{
    (void)iodata;
    (void)chan_parms;
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
static uint32_t hieps_loop_test(char *iodata, const struct msp_chan_parms *chan_parms)
{
    (void)iodata;
    uint32_t ret;
    uint32_t test_data;
    uint32_t return_data;
    char *pparm = NULL;

    if (!chan_parms)
        return HIEPS_TEEOS_PARM_ERROR;

    pparm = (char *)&(chan_parms->parm[0]);
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
 * @brief      : hieps power control parm extract
 * @param[in]  : power_id, profile_id, chan_parms
 * @return     : HIEPS_TEEOS_SUCCESS is success, OTHER is failed
 * @note       : extract parm from chan_parms to power_id and profile_id
 */
static uint32_t hieps_power_parm_extract(uint32_t *power_id, uint32_t *profile_id,
                       const struct msp_chan_parms *chan_parms)
{
    char *pparm = NULL;
    const uint32_t PCTRL_PARM_NUMS = 2;  /* power id and profile id */

    if (!chan_parms || chan_parms->parm_info[0] != PCTRL_PARM_NUMS) {
        tloge("hieps: Invalid param!\n");
        return HIEPS_TEEOS_PARM_ERROR;
    }

    pparm = (char *)&(chan_parms->parm[0]);
    if (!pparm) {
        tloge("hieps: pparm is null\n");
        return HIEPS_TEEOS_PARM_ERROR;
    }
    *power_id = (uint32_t)atoi(pparm);

    pparm = (char *)&(chan_parms->parm[1]);
    if (!pparm) {
        tloge("hieps: pparm1 is null\n");
        return HIEPS_TEEOS_PARM_ERROR;
    }
    *profile_id = (uint32_t)atoi(pparm);

    return HIEPS_TEEOS_SUCCESS;
}

/*
 * @brief      : hieps power on
 * @param[in]  : iodata, data pointer
 * @return     : HIEPS_TEEOS_SUCCESS is success, OTHER is failed
 * @note       : test hieps power on interface
 */
static uint32_t hieps_power_ctrl_on(char *iodata, const struct msp_chan_parms *chan_parms)
{
    (void)iodata;
    uint32_t ret = HIEPS_TEEOS_ERROR;
    uint32_t power_id, profile_id;

    ret = hieps_power_parm_extract(&power_id, &profile_id, chan_parms);
    if (ret != HIEPS_TEEOS_SUCCESS)
        return ret;

    tloge("hieps poweron powerid = %d, profileid = %d\n", power_id, profile_id);

    ret = hieps_power_on(power_id, profile_id);
    if (ret != HIEPS_OK) {
        tloge("HiEPS: power ctrl on failed! ret = %x\n", ret);
        return HIEPS_TEEOS_RESULT_ERROR;
    }

    /* factory test for msp engine */
    if (power_id == 0) {
        ret = (uint32_t)mspe_factory_test();
        tloge("mspe_factory_test, ret=%x\n", ret);
        if (ret == BSP_RET_OK)
            ret = HIEPS_OK;
    }

    return ret;
}

/*
 * @brief      : hieps power off
 * @param[in]  : iodata, data pointer
 * @return     : HIEPS_TEEOS_SUCCESS is success, OTHER is failed
 * @note       : test hieps power off interface
 */
static uint32_t hieps_power_ctrl_off(char *iodata, const struct msp_chan_parms *chan_parms)
{
    (void)iodata;
    uint32_t ret = HIEPS_TEEOS_ERROR;
    uint32_t power_id, profile_id;

    ret = hieps_power_parm_extract(&power_id, &profile_id, chan_parms);
    if (ret != HIEPS_TEEOS_SUCCESS)
        return ret;

    tloge("hieps poweroff powerid = %d, profileid = %d\n", power_id, profile_id);

    ret = hieps_power_off(power_id, profile_id);
    if (ret != HIEPS_OK) {
        tloge("HiEPS: power ctrl off failed! ret = %x\n", ret);
        return HIEPS_TEEOS_RESULT_ERROR;
    }

    return ret;
}

/*
 * @brief      : cdrm_test  cdrm ipc send addr and size test
 * @param[in]  : chan_parms pointer parm data.
 * @return     : HIEPS_TEEOS_SUCCESS is success, OTHER is failed
 */
static uint32_t cdrm_test(const struct msp_chan_parms *chan_parms)
{
    (void)chan_parms;

    tloge("HiEPS: Test CDRM IPC send!\n");

    return HIEPS_OK;
}

/*
 * @brief      : hieps_get_lcs : get hieps lcs mode.
 * @param[in]  : chan_parms pointer parm data.
 * @return     : lcs
 */
static uint32_t hieps_get_lcs(const struct msp_chan_parms *chan_parms)
{
    (void)chan_parms;
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
static uint32_t hieps_seceng_process(char *iodata, const struct msp_chan_parms *chan_parms)
{
    const struct msptest_to_tee_parms* parm_info = (struct msptest_to_tee_parms*)chan_parms;
    if (!parm_info)
        return HIEPS_TEEOS_PARM_ERROR;

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
    ret3 = hat_testcase_entry((void *)iodata, inputlen, max_data_len);
    if (ret3 != HIEPS_TEEOS_SUCCESS)
        tloge("hieps: seceng test failed! ret3 = %x\n", ret3);

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

static struct mspe_chan_cb_s g_mspe_test_cb_table[] = {
    { HIEPS_POWERON, hieps_power_ctrl_on },
    { HIEPS_POWEROFF, hieps_power_ctrl_off },
    { HIEPS_LOOP_TEST, hieps_loop_test },
    { HIEPS_DRIVES_ATF_TEST, hieps_smc_to_atf_test },
    { HIEPS_ATF_KERNEL_TEST, hieps_atf_kernel_test },
    { HIEPS_SECENG_TEST, hieps_seceng_process },
};

/*
 * @brief      : register mspe callback function on msp ta channel
 * @param[in]  : NA
 * @return     : MSP_TA_CHANNEL_OK：success，others：fail
 */
int32_t mspe_test_callback_init(void)
{
    int32_t ret;
    uint32_t count = sizeof(g_mspe_test_cb_table) / sizeof(struct mspe_chan_cb_s);
    uint32_t i;

    for (i = 0; i < count; i++) {
        ret = msp_chan_rgst_callback(g_mspe_test_cb_table[i].cmd, g_mspe_test_cb_table[i].cb_func);
        if (ret != MSP_TA_CHANNEL_OK)
            return ret;
    }

    ret = msp_chan_rgst_ecall_func("cdrm_test", cdrm_test);
    if (ret != MSP_TA_CHANNEL_OK)
        return ret;

    ret = msp_chan_rgst_ecall_func("get_lcs", hieps_get_lcs);
    if (ret != MSP_TA_CHANNEL_OK)
        return ret;

    return HIEPS_OK;
}
