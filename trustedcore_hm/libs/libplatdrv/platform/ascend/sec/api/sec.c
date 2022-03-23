/*
* Copyright (c) Huawei Technologies Co., Ltd. 2019-2021. All rights reserved.
* Description: the internal function of sec
* Author: chenyao
* Create: 2019/12/30
*/
#include "timer.h"
#include "tee_log.h"
#include "mem_ops.h"
#include "register_ops.h"

#include "securec.h"

#include "driver_common.h"
#include "sec.h"
#include "sec_api.h"

STATIC uint32_t sec_read_status(unsigned long reg_addr, uint32_t mask, uint32_t expect_value, uint32_t timeout)
{
    volatile uint32_t status;
    uint32_t cnt = 0;

    for (; cnt < timeout; cnt++) {
        status = read32(reg_addr);
        if ((status & mask) == expect_value) {
            break;
        }
    }

    if (cnt == timeout) {
        return ERR_SEC_ERR_TIMEOUT;
    }

    return SEC_SUCCESS;
}

uint32_t sec_rst_req_en(void)
{
    write32(SC_SEC_RESET_REQ_REG, SEC_RST);
    return sec_read_status(SC_SEC_RESET_ST_REG, (~0), SEC_RST_REF, TIMEOUT);
}

uint32_t sec_rst_req_disable(void)
{
    write32(SC_SEC_RESET_DREQ_REG, SEC_RST_REL);
    return sec_read_status(SC_SEC_RESET_ST_REG, (~0), SEC_RST_REL_REF, TIMEOUT);
}

uint32_t sec_clk_en(void)
{
    write32(SC_SEC_ICG_EN_REG, SEC_CLOCK_OPEN);
    return sec_read_status(SC_SEC_ICG_ST_REG, (~0), SEC_CLOCK_OPEN_REF, TIMEOUT);
}

uint32_t sec_clk_disable(void)
{
    write32(SC_SEC_ICG_DIS_REG, SEC_CLOCK_CLOSE);
    return sec_read_status(SC_SEC_ICG_ST_REG, (~0), SEC_CLOCK_CLOSE_REF, TIMEOUT);
}

uint32_t sec_clk_rst(void)
{
    uint32_t ret;

    ret = sec_clk_disable();
    if (ret != SEC_SUCCESS) {
        return ret;
    }

    ret = sec_rst_req_en();
    if (ret != SEC_SUCCESS) {
        return ret;
    }

    ret = sec_clk_en();
    if (ret != SEC_SUCCESS) {
        return ret;
    }

    SRE_SwMsleep(SEC_CLK_TIME_DELAY);

    ret = sec_clk_disable();
    if (ret != SEC_SUCCESS) {
        return ret;
    }

    ret = sec_rst_req_disable();
    if (ret != SEC_SUCCESS) {
        return ret;
    }

    ret = sec_clk_en();
    if (ret != SEC_SUCCESS) {
        return ret;
    }

    return SEC_SUCCESS;
}

uint32_t sec_close_bus(void)
{
    uint32_t tmp;

    tmp = read32(AM_CTRL_GLOBAL_REG);
    tmp = tmp | BIT0;
    write32(AM_CTRL_GLOBAL_REG, tmp);

    return sec_read_status(AM_CURR_TRANS_RETURN_REG, (~0), AM_CURR_TRANS_FINISH, 0xffff);
}

/* sec pbu and peh config */
static void sec_pbu_conf(void)
{
    write32(SC_SEC_PBU_PCIHDR_CMDSTS_REG, SEC_PBU_CMDSTS_CFG);
    write32(SC_SEC_PBU_PCIHDR_PRE_MEM_BASE_LIMIT_REG, SEC_PBU_MEM_CFG);
}

static void sec_peh_conf(void)
{
    write32(DISP_ECAM_DAW_EN_REG, SEC_ECAM_DAW_ON);
    write32(PCIHDR_CMDSTS_REG, SEC_PCIHDR_START);
    write32(PCIHDR_BAR2_REG, SEC_PF_BAR_ADDR_L);
    write32(PCIHDR_BAR3_REG, SEC_PF_BAR_ADDR_H);
    write32(SRIOV_CTRL_REG, SEC_SRIOV_ON);
    write32(FUNC_DEP_VF_NUM_REG, SEC_VF_NUMBER);
    write32(VF_BAR2_REG, SEC_VF_BAR_ADDR_L);
    write32(VF_BAR3_REG, SEC_VF_BAR_ADDR_H);
}

uint32_t sec_init_check(void)
{
    uint32_t pcie_status = 0;

    pcie_status += (read32(SC_SEC_PBU_PCIHDR_CMDSTS_REG) & (~SEC_PBU_CMDSTS_RD_CFG));
    pcie_status += (read32(SC_SEC_PBU_PCIHDR_PRE_MEM_BASE_LIMIT_REG) & (~SEC_PBU_MEM_RD_CFG));

    pcie_status += (read32(DISP_ECAM_DAW_EN_REG) & (~SEC_ECAM_DAW_ON));
    pcie_status += (read32(PCIHDR_CMDSTS_REG) & (~SEC_PCIHDR_RD_START));
    pcie_status += (read32(PCIHDR_BAR2_REG) & (~SEC_PF_BAR_ADDR_RD_L));
    pcie_status += (read32(PCIHDR_BAR3_REG) & (~SEC_PF_BAR_ADDR_H));
    pcie_status += (read32(SRIOV_CTRL_REG) & (~SEC_SRIOV_RD_ON));
    pcie_status += (read32(FUNC_DEP_VF_NUM_REG) & (~SEC_VF_NUMBER));
    pcie_status += (read32(VF_BAR2_REG) & (~SEC_VF_BAR_ADDR_RD_L));
    pcie_status += (read32(VF_BAR3_REG) & (~SEC_VF_BAR_ADDR_H));

    return pcie_status;
}

static void sec_pf_mem_conf(void)
{
    write32(AM_CFG_MAX_TRANS_REG, AXI_MASTER_OOO_OUTSTANDING);
    write32(SEC_ECO_RW_REG, SEC_ECO_RW_CONFIG);
    write32(SEC_BD_PACKET_OST_CFG_REG, SEC_READ_BD_OUTSTANDING);
    write32(SEC_MEM_START_INIT_REG, SEC_MEM_INIT_EN);
}

/* PF config */
uint32_t sec_pf_conf(void)
{
    uint32_t timeout = TIMEOUT;
    uint32_t done = 0;
    U_SEC_MEM_INIT_DONE mem_init;

    /* pcie config */
    sec_pbu_conf();
    sec_peh_conf();
    sec_pf_mem_conf();

    do {
        mem_init.status = read32(SEC_MEM_INIT_DONE_REG);
        done = mem_init.bits.mem_init_done;
        if (timeout == 0) {
            tloge("SEC MEMSET FAILED\n");
            return ERR_SEC_MEMSET_FAILED;
        }
        timeout--;
    } while (done != SEC_MEM_INIT_DONE);

    write32(SEC_CNT_CLR_CE_REG, DEFAULT_VALUE);
    write32(SEC_SAA_EN_REG, SEC_SAA_EN);
    write32(SEC_LINK_RSV_REG, LISTADD_LIMIT);
    return SEC_SUCCESS;
}

void sec_bd_fifo_conf(void)
{
    write32(BDF_EN_STATUS_REG, SEC_BD_FIFO_EN);
    write32(ACC_STREAMID_S_REG, DEFAULT_VALUE);
    write32(SEC_BDF_CFG_AWUSER_REG, DEFAULT_VALUE);
    write32(SEC_BDF_CFG_ARUSER_REG, DEFAULT_VALUE);
    write32(SEC_BDF_CFG_PD_TAG_REG, DEFAULT_VALUE);
    write32(SEC_BDF_CNT_CLR_CE_REG, SEC_BDF_CNT_CLR_DISABLE);
    write32(SEC_BDF_CFG_SKIP_LENGTH_REG, SEC_MAX_SKIP_LENGTH);
    write32(SEC_BDF_INT_ENABLE_REG, SEC_BDF_INT_DISABLE);
    write32(SEC_BDF_EN_REG, SEC_POP_PUSH_EN);
    write32(BDF_ECO_RW_REG, INIT_DONE);
}

uint32_t sec_check_init(void)
{
    uint32_t ret;

    ret = read32(BDF_ECO_RW_REG);
    if (ret != INIT_DONE) {
        return ERR_SEC_INIT_FAILED;
    }
    return SEC_SUCCESS;
}

uint32_t km_req_key_hand(uint32_t type)
{
    uint32_t done = 0;
    uint32_t doing = 0;
    uint32_t fail;
    uint32_t timeout = TIMEOUT0;
    U_KM_REQ_DONE_REG req_done;

    write32(KM_REQ_START_REG, type);

    dsb();
    do {
        req_done.status = read32(KM_REQ_DONE_REG);
        done = req_done.bits.km_key_done;
        doing = req_done.bits.km_key_doing;
        if (timeout == 0) {
            return ERR_SEC_ERR_TIMEOUT;
        }
        timeout--;
    } while ((done == 0) && (doing == 1));

    fail = req_done.bits.km_key_fail;
    if (fail == 1) {
        return ERR_SEC_KM_REQ_FAILED;
    } else {
        return SEC_SUCCESS;
    }
}

uint32_t sec_aes_sm4_bd(SEC_AES_INFO_S *aes_info)
{
    SEC_BD_S *pstsecbd = NULL;

    pstsecbd = (SEC_BD_S *)(uintptr_t)(aes_info->bd_addr);
    if (memset_s((void *)pstsecbd, sizeof(SEC_BD_S), 0x0, sizeof(SEC_BD_S)) != EOK) {
        tloge("sec memset failed!\n");
        return ERR_SEC_MEMSET_FAILED;
    }

    dsb();
    pstsecbd->sec_bd_word0.bits.bd_type = SEC_N_TYPE;
    pstsecbd->sec_bd_word0.bits.cipher =  aes_info->aes_enc;
    if (aes_info->data_addr == aes_info->result_addr) {
        pstsecbd->sec_bd_word0.bits.de = 0;
    } else {
        pstsecbd->sec_bd_word0.bits.de = SEC_DST_ADDR_EN;
    }

    pstsecbd->sec_bd_word0.bits.scene = SEC_NO_SCENE;
    pstsecbd->sec_bd_word0.bits.src_addr_type = SEC_PBUFFER;
    pstsecbd->sec_bd_word0.bits.dst_addr_type = SEC_PBUFFER;
    pstsecbd->sec_bd_word1.bits.auth_pad = SEC_LAST_BLOCK_PADDING;

    if (aes_info->key_addr != 0) {
        pstsecbd->sec_bd_word2.bits.key_sel = SEC_READ_FROM_DDR;
        pstsecbd->cipher_key_addr_h = (uint32_t)(virt_mem_to_phys(aes_info->key_addr) >> SEC_SHIFT32);
        pstsecbd->cipher_key_addr_l = (uint32_t)(virt_mem_to_phys(aes_info->key_addr));
    } else {
        pstsecbd->sec_bd_word2.bits.key_sel = (uint32_t)aes_info->key_type;
    }

    pstsecbd->sec_bd_word3.bits.ckey_len = aes_info->aes_key_len;
    pstsecbd->sec_bd_word3.bits.c_alg = aes_info->cipher_mode;
    pstsecbd->sec_bd_word3.bits.c_mode = aes_info->aes_mode;

    pstsecbd->sec_bd_word5.bits.cipher_len = aes_info->data_len;

    pstsecbd->word21.cipher_ivin_addr_h = (uint32_t)(virt_mem_to_phys(aes_info->iv_addr) >> SEC_SHIFT32);
    pstsecbd->word20.cipher_ivin_addr_l = (uint32_t)(virt_mem_to_phys(aes_info->iv_addr));

    pstsecbd->data_src_addr_h = (uint32_t)(virt_mem_to_phys(aes_info->data_addr) >> SEC_SHIFT32);
    pstsecbd->data_src_addr_l = (uint32_t)(virt_mem_to_phys(aes_info->data_addr));

    pstsecbd->data_dst_addr_h = (uint32_t)(virt_mem_to_phys(aes_info->result_addr) >> SEC_SHIFT32);
    pstsecbd->data_dst_addr_l = (uint32_t)(virt_mem_to_phys(aes_info->result_addr));

    return SEC_SUCCESS;
}

/* AES-GCM bd build */
uint32_t sec_aes_gcm_bd(SEC_AES_GCM_INFO_S *aes_gcm_info)
{
    SEC_BD_S *pstsecbd = NULL;

    pstsecbd = (SEC_BD_S *)(uintptr_t)(aes_gcm_info->bd_addr);
    if (memset_s((void *)pstsecbd, sizeof(SEC_BD_S), 0, sizeof(SEC_BD_S)) != EOK) {
        return ERR_SEC_MEMSET_FAILED;
    }

    dsb();

    pstsecbd->sec_bd_word0.bits.bd_type = SEC_N_TYPE;
    pstsecbd->sec_bd_word0.bits.cipher =  aes_gcm_info->aes_enc;
    pstsecbd->sec_bd_word0.bits.de = SEC_DST_ADDR_EN;
    pstsecbd->sec_bd_word0.bits.scene = SEC_NO_SCENE;
    pstsecbd->sec_bd_word0.bits.src_addr_type = SEC_PBUFFER;
    pstsecbd->sec_bd_word0.bits.dst_addr_type = SEC_PBUFFER;

    if (aes_gcm_info->key_addr != 0) {
        pstsecbd->sec_bd_word2.bits.key_sel = SEC_READ_FROM_DDR;
        pstsecbd->cipher_key_addr_h = (uint32_t)(virt_mem_to_phys(aes_gcm_info->key_addr) >> SEC_SHIFT32);
        pstsecbd->cipher_key_addr_l = (uint32_t)(virt_mem_to_phys(aes_gcm_info->key_addr));
    } else {
        pstsecbd->sec_bd_word2.bits.key_sel = (uint32_t)aes_gcm_info->key_type;
    }

    pstsecbd->sec_bd_word3.bits.ckey_len = aes_gcm_info->aes_key_len;
    pstsecbd->sec_bd_word3.bits.c_alg = SEC_AES;
    pstsecbd->sec_bd_word3.bits.c_mode = SEC_GCM;
    pstsecbd->sec_bd_word3.bits.c_icv_len = aes_gcm_info->tag_len;
    pstsecbd->sec_bd_word4.bits.auth_len = aes_gcm_info->aad_len;

    pstsecbd->sec_bd_word6.bits.cipher_src_offset = aes_gcm_info->cipheroff_addr;
    pstsecbd->sec_bd_word5.bits.cipher_len = aes_gcm_info->data_len;

    pstsecbd->word21.cipher_ivin_addr_h = (uint32_t)(virt_mem_to_phys(aes_gcm_info->iv_addr) >> SEC_SHIFT32);
    pstsecbd->word20.cipher_ivin_addr_l = (uint32_t)(virt_mem_to_phys(aes_gcm_info->iv_addr));

    pstsecbd->mac_addr_h = (uint32_t)(virt_mem_to_phys(aes_gcm_info->mac_addr) >> SEC_SHIFT32);
    pstsecbd->mac_addr_l = (uint32_t)(virt_mem_to_phys(aes_gcm_info->mac_addr));

    pstsecbd->data_src_addr_h = (uint32_t)(virt_mem_to_phys(aes_gcm_info->data_addr) >> SEC_SHIFT32);
    pstsecbd->data_src_addr_l = (uint32_t)(virt_mem_to_phys(aes_gcm_info->data_addr));

    pstsecbd->data_dst_addr_h = (uint32_t)(virt_mem_to_phys(aes_gcm_info->result_addr) >> SEC_SHIFT32);
    pstsecbd->data_dst_addr_l = (uint32_t)(virt_mem_to_phys(aes_gcm_info->result_addr));

    return SEC_SUCCESS;
}

uint32_t sec_aes_gcm_km_bd(SEC_AES_GCM_INFO_S *aes_gcm_info)
{
    SEC_BD_S *pstsecbd = NULL;

    pstsecbd = (SEC_BD_S *)(uintptr_t)(aes_gcm_info->bd_addr);
    if (memset_s((void *)pstsecbd, sizeof(SEC_BD_S), 0, sizeof(SEC_BD_S)) != EOK) {
        return ERR_SEC_MEMSET_FAILED;
    }

    dsb();

    pstsecbd->sec_bd_word0.bits.bd_type = SEC_N_TYPE;
    pstsecbd->sec_bd_word0.bits.cipher =  aes_gcm_info->aes_enc;
    pstsecbd->sec_bd_word0.bits.de = SEC_DST_ADDR_EN;
    pstsecbd->sec_bd_word0.bits.scene = SEC_NO_SCENE;
    pstsecbd->sec_bd_word0.bits.src_addr_type = SEC_PBUFFER;
    pstsecbd->sec_bd_word0.bits.dst_addr_type = SEC_PBUFFER;

    pstsecbd->sec_bd_word2.bits.key_sel = (uint32_t)aes_gcm_info->key_type;
    pstsecbd->sec_bd_word2.bits.update_key = 1;
    pstsecbd->sec_bd_word3.bits.ckey_len = aes_gcm_info->aes_key_len;
    pstsecbd->sec_bd_word3.bits.c_alg = SEC_AES;
    pstsecbd->sec_bd_word3.bits.c_mode = SEC_GCM;
    pstsecbd->sec_bd_word3.bits.c_icv_len = 0x10;
    pstsecbd->sec_bd_word4.bits.auth_len = aes_gcm_info->aad_len;

    pstsecbd->sec_bd_word6.bits.cipher_src_offset = aes_gcm_info->cipheroff_addr;
    pstsecbd->sec_bd_word5.bits.cipher_len = aes_gcm_info->data_len;

    pstsecbd->cipher_key_addr_h = (uint32_t)(virt_mem_to_phys(aes_gcm_info->key_addr) >> SEC_SHIFT32);
    pstsecbd->cipher_key_addr_l = (uint32_t)(virt_mem_to_phys(aes_gcm_info->key_addr));

    pstsecbd->word21.cipher_ivin_addr_h = (uint32_t)(virt_mem_to_phys(aes_gcm_info->iv_addr) >> SEC_SHIFT32);
    pstsecbd->word20.cipher_ivin_addr_l = (uint32_t)(virt_mem_to_phys(aes_gcm_info->iv_addr));

    pstsecbd->mac_addr_h = (uint32_t)(virt_mem_to_phys(aes_gcm_info->mac_addr) >> SEC_SHIFT32);
    pstsecbd->mac_addr_l = (uint32_t)(virt_mem_to_phys(aes_gcm_info->mac_addr));

    pstsecbd->data_src_addr_h = (uint32_t)(virt_mem_to_phys(aes_gcm_info->data_addr) >> SEC_SHIFT32);
    pstsecbd->data_src_addr_l = (uint32_t)(virt_mem_to_phys(aes_gcm_info->data_addr));

    pstsecbd->data_dst_addr_h = (uint32_t)(virt_mem_to_phys(aes_gcm_info->result_addr) >> SEC_SHIFT32);
    pstsecbd->data_dst_addr_l = (uint32_t)(virt_mem_to_phys(aes_gcm_info->result_addr));

    return SEC_SUCCESS;
}

uint32_t sec_aes_gcm_init_bd(SEC_AES_GCM_INFO_S *aes_gcm_info)
{
    SEC_BD_S *pstsecbd = NULL;

    pstsecbd = (SEC_BD_S *)(uintptr_t)aes_gcm_info->bd_addr;
    if (memset_s((void *)pstsecbd, sizeof(SEC_BD_S), 0x0, sizeof(SEC_BD_S)) != EOK) {
        tloge("sec memset failed!\n");
        return ERR_SEC_MEMSET_FAILED;
    }

    dsb();

    pstsecbd->sec_bd_word0.bits.bd_type = SEC_N_TYPE;
    pstsecbd->sec_bd_word0.bits.auth = 1;
    pstsecbd->sec_bd_word0.bits.seq = 1;
    pstsecbd->sec_bd_word0.bits.de = SEC_DST_ADDR_EN;
    pstsecbd->sec_bd_word0.bits.scene = SEC_STEAM;
    pstsecbd->sec_bd_word0.bits.src_addr_type = SEC_PBUFFER;
    pstsecbd->sec_bd_word0.bits.dst_addr_type = SEC_PBUFFER;
    pstsecbd->sec_bd_word1.bits.auth_pad = SEC_LAST_BLOCK_NO_PADDING;
    pstsecbd->sec_bd_word1.bits.ai_gen = 0;

    pstsecbd->sec_bd_word3.bits.c_icv_len = SEC_GCM_MAC_LEN;

    if (aes_gcm_info->key_addr != 0) {
        pstsecbd->sec_bd_word2.bits.key_sel = SEC_READ_FROM_DDR;
        pstsecbd->auth_key_addr_h = (uint32_t)(virt_mem_to_phys(aes_gcm_info->key_addr) >> SEC_SHIFT32);
        pstsecbd->auth_key_addr_l = (uint32_t)(virt_mem_to_phys(aes_gcm_info->key_addr));
        pstsecbd->cipher_key_addr_h = (uint32_t)(virt_mem_to_phys(aes_gcm_info->key_addr) >> SEC_SHIFT32);
        pstsecbd->cipher_key_addr_l = (uint32_t)(virt_mem_to_phys(aes_gcm_info->key_addr));
    } else {
        pstsecbd->sec_bd_word2.bits.key_sel = (uint32_t)aes_gcm_info->key_type;
    }
    pstsecbd->sec_bd_word2.bits.akey_len = SEC_GCM_AKEY_Q + (SEC_GCM_AKEY_M * aes_gcm_info->aes_key_len);
    pstsecbd->sec_bd_word2.bits.a_alg = SEC_GMAC;
    pstsecbd->sec_bd_word2.bits.mac_len = SEC_GCM_UPDATE_IV;

    pstsecbd->sec_bd_word3.bits.ckey_len = aes_gcm_info->aes_key_len;
    pstsecbd->sec_bd_word3.bits.c_alg = SEC_AES;
    pstsecbd->sec_bd_word3.bits.c_mode = SEC_GCM;
    pstsecbd->sec_bd_word3.bits.c_icv_len = SEC_GCM_MAC_LEN;

    pstsecbd->sec_bd_word4.bits.auth_len = aes_gcm_info->aad_len;

    pstsecbd->sec_bd_word6.bits.auth_src_offset = 0;

    pstsecbd->data_src_addr_h = (uint32_t)(virt_mem_to_phys(aes_gcm_info->data_addr) >> SEC_SHIFT32);
    pstsecbd->data_src_addr_l = (uint32_t)(virt_mem_to_phys(aes_gcm_info->data_addr));

    pstsecbd->word21.cipher_ivin_addr_h = (uint32_t)(virt_mem_to_phys(aes_gcm_info->iv_addr) >> SEC_SHIFT32);
    pstsecbd->word20.cipher_ivin_addr_l = (uint32_t)(virt_mem_to_phys(aes_gcm_info->iv_addr));

    pstsecbd->mac_addr_h = (uint32_t)(virt_mem_to_phys(aes_gcm_info->mac_addr) >> SEC_SHIFT32);
    pstsecbd->mac_addr_l = (uint32_t)(virt_mem_to_phys(aes_gcm_info->mac_addr));

    return SEC_SUCCESS;
}

uint32_t sec_aes_gcm_update_bd(SEC_AES_GCM_INFO_S *aes_gcm_info)
{
    SEC_BD_S *pstsecbd = NULL;

    pstsecbd = (SEC_BD_S *)(uintptr_t)aes_gcm_info->bd_addr;
    if (memset_s((void *)pstsecbd, sizeof(SEC_BD_S), 0x0, sizeof(SEC_BD_S)) != EOK) {
        tloge("sec aes gcm, memset failed!\n");
        return ERR_SEC_MEMSET_FAILED;
    }

    dsb();

    if (aes_gcm_info->key_addr != 0) {
        pstsecbd->sec_bd_word2.bits.key_sel = SEC_READ_FROM_DDR;
        pstsecbd->auth_key_addr_h = (uint32_t)(virt_mem_to_phys(aes_gcm_info->key_addr) >> SEC_SHIFT32);
        pstsecbd->auth_key_addr_l = (uint32_t)(virt_mem_to_phys(aes_gcm_info->key_addr));
        pstsecbd->cipher_key_addr_h = (uint32_t)(virt_mem_to_phys(aes_gcm_info->key_addr) >> SEC_SHIFT32);
        pstsecbd->cipher_key_addr_l = (uint32_t)(virt_mem_to_phys(aes_gcm_info->key_addr));
    } else {
        pstsecbd->sec_bd_word2.bits.key_sel = (uint32_t)aes_gcm_info->key_type;
    }

    pstsecbd->sec_bd_word0.bits.bd_type = SEC_N_TYPE;
    pstsecbd->sec_bd_word0.bits.cipher = aes_gcm_info->aes_enc;
    pstsecbd->sec_bd_word0.bits.seq = 0;

    if (aes_gcm_info->data_addr == aes_gcm_info->result_addr) {
        pstsecbd->sec_bd_word0.bits.de = 0;
    } else {
        pstsecbd->sec_bd_word0.bits.de = SEC_DST_ADDR_EN;
    }

    pstsecbd->sec_bd_word0.bits.scene = SEC_STEAM;
    pstsecbd->sec_bd_word0.bits.src_addr_type = SEC_PBUFFER;
    pstsecbd->sec_bd_word0.bits.dst_addr_type = SEC_PBUFFER;
    pstsecbd->sec_bd_word1.bits.auth_pad = SEC_LAST_BLOCK_NO_PADDING;
    pstsecbd->sec_bd_word1.bits.ai_gen = 1;

    pstsecbd->sec_bd_word3.bits.ckey_len = aes_gcm_info->aes_key_len;
    pstsecbd->sec_bd_word3.bits.c_alg = SEC_AES;
    pstsecbd->sec_bd_word3.bits.c_mode = SEC_GCM;
    pstsecbd->sec_bd_word3.bits.c_icv_len = SEC_GCM_MAC_LEN;

    pstsecbd->sec_bd_word6.bits.cipher_src_offset = 0;
    pstsecbd->sec_bd_word6.bits.auth_src_offset = 0;
    pstsecbd->sec_bd_word5.bits.cipher_len = aes_gcm_info->data_len;

    pstsecbd->sec_bd_word2.bits.akey_len = SEC_GCM_AKEY_Q + (SEC_GCM_AKEY_M * aes_gcm_info->aes_key_len);
    pstsecbd->sec_bd_word2.bits.a_alg = SEC_GMAC;
    pstsecbd->sec_bd_word2.bits.mac_len = SEC_GCM_UPDATE_IV;

    pstsecbd->word14.auth_ivin_addr_l = (uint32_t)(virt_mem_to_phys(aes_gcm_info->auth_iv_addr));
    pstsecbd->word15.auth_ivin_addr_h = (uint32_t)(virt_mem_to_phys(aes_gcm_info->auth_iv_addr) >> SEC_SHIFT32);

    pstsecbd->word20.cipher_ivin_addr_l = (uint32_t)(virt_mem_to_phys(aes_gcm_info->iv_addr));
    pstsecbd->word21.cipher_ivin_addr_h = (uint32_t)(virt_mem_to_phys(aes_gcm_info->iv_addr) >> SEC_SHIFT32);

    pstsecbd->mac_addr_h = (uint32_t)(virt_mem_to_phys(aes_gcm_info->mac_addr) >> SEC_SHIFT32);
    pstsecbd->mac_addr_l = (uint32_t)(virt_mem_to_phys(aes_gcm_info->mac_addr));

    pstsecbd->data_src_addr_h = (uint32_t)(virt_mem_to_phys(aes_gcm_info->data_addr) >> SEC_SHIFT32);
    pstsecbd->data_src_addr_l = (uint32_t)(virt_mem_to_phys(aes_gcm_info->data_addr));

    pstsecbd->data_dst_addr_h = (uint32_t)(virt_mem_to_phys(aes_gcm_info->result_addr) >> SEC_SHIFT32);
    pstsecbd->data_dst_addr_l = (uint32_t)(virt_mem_to_phys(aes_gcm_info->result_addr));

    return SEC_SUCCESS;
}

uint32_t sec_aes_gcm_final_bd(SEC_AES_GCM_INFO_S *aes_gcm_info)
{
    SEC_BD_S *pstsecbd = NULL;

    pstsecbd = (SEC_BD_S *)(uintptr_t)aes_gcm_info->bd_addr;
    if (memset_s((void *)pstsecbd, sizeof(SEC_BD_S), 0x0, sizeof(SEC_BD_S)) != EOK) {
        tloge("sec_aes_gcm final, memset failed!\n");
        return ERR_SEC_MEMSET_FAILED;
    }

    dsb();

    if (aes_gcm_info->key_addr != 0) {
        pstsecbd->sec_bd_word2.bits.key_sel = SEC_READ_FROM_DDR;
        pstsecbd->auth_key_addr_h = (uint32_t)(virt_mem_to_phys(aes_gcm_info->key_addr) >> SEC_SHIFT32);
        pstsecbd->auth_key_addr_l = (uint32_t)(virt_mem_to_phys(aes_gcm_info->key_addr));
        pstsecbd->cipher_key_addr_h = (uint32_t)(virt_mem_to_phys(aes_gcm_info->key_addr) >> SEC_SHIFT32);
        pstsecbd->cipher_key_addr_l = (uint32_t)(virt_mem_to_phys(aes_gcm_info->key_addr));
    } else {
        pstsecbd->sec_bd_word2.bits.key_sel = (uint32_t)aes_gcm_info->key_type;
    }

    pstsecbd->sec_bd_word0.bits.bd_type = SEC_N_TYPE;
    pstsecbd->sec_bd_word0.bits.cipher = aes_gcm_info->aes_enc;
    pstsecbd->sec_bd_word0.bits.scene = SEC_STEAM;

    if (aes_gcm_info->data_addr == aes_gcm_info->result_addr) {
        pstsecbd->sec_bd_word0.bits.de = 0;
    } else {
        pstsecbd->sec_bd_word0.bits.de = SEC_DST_ADDR_EN;
    }

    pstsecbd->sec_bd_word0.bits.src_addr_type = SEC_PBUFFER;
    pstsecbd->sec_bd_word0.bits.dst_addr_type = SEC_PBUFFER;
    pstsecbd->sec_bd_word1.bits.auth_pad = SEC_LAST_BLOCK_PADDING;
    pstsecbd->sec_bd_word1.bits.ai_gen = 1;

    pstsecbd->sec_bd_word3.bits.ckey_len = aes_gcm_info->aes_key_len;
    pstsecbd->sec_bd_word3.bits.c_alg = SEC_AES;
    pstsecbd->sec_bd_word3.bits.c_mode = SEC_GCM;
    pstsecbd->sec_bd_word3.bits.c_icv_len = aes_gcm_info->tag_len;

    pstsecbd->sec_bd_word6.bits.cipher_src_offset = 0;
    pstsecbd->sec_bd_word6.bits.auth_src_offset = 0;
    pstsecbd->sec_bd_word5.bits.cipher_len = aes_gcm_info->data_len;

    pstsecbd->sec_bd_word2.bits.akey_len = SEC_GCM_AKEY_Q + (SEC_GCM_AKEY_M * aes_gcm_info->aes_key_len);
    pstsecbd->sec_bd_word2.bits.a_alg = SEC_GMAC;
    pstsecbd->sec_bd_word2.bits.mac_len = SEC_GCM_UPDATE_IV;

    pstsecbd->sec_bd_word12.long_auth_data_len_l = aes_gcm_info->long_data_len_l;
    pstsecbd->sec_bd_word13.long_auth_data_len_h = aes_gcm_info->long_data_len_h;

    pstsecbd->word15.auth_ivin_addr_h = (uint32_t)(virt_mem_to_phys(aes_gcm_info->auth_iv_addr) >> SEC_SHIFT32);
    pstsecbd->word14.auth_ivin_addr_l = (uint32_t)(virt_mem_to_phys(aes_gcm_info->auth_iv_addr));

    pstsecbd->word21.cipher_ivin_addr_h = (uint32_t)(virt_mem_to_phys(aes_gcm_info->iv_addr) >> SEC_SHIFT32);
    pstsecbd->word20.cipher_ivin_addr_l = (uint32_t)(virt_mem_to_phys(aes_gcm_info->iv_addr));

    pstsecbd->mac_addr_h = (uint32_t)(virt_mem_to_phys(aes_gcm_info->mac_addr) >> SEC_SHIFT32);
    pstsecbd->mac_addr_l = (uint32_t)(virt_mem_to_phys(aes_gcm_info->mac_addr));

    pstsecbd->data_src_addr_h = (uint32_t)(virt_mem_to_phys(aes_gcm_info->data_addr) >> SEC_SHIFT32);
    pstsecbd->data_src_addr_l = (uint32_t)(virt_mem_to_phys(aes_gcm_info->data_addr));

    pstsecbd->data_dst_addr_h = (uint32_t)(virt_mem_to_phys(aes_gcm_info->result_addr) >> SEC_SHIFT32);
    pstsecbd->data_dst_addr_l = (uint32_t)(virt_mem_to_phys(aes_gcm_info->result_addr));

    return SEC_SUCCESS;
}

uint32_t sec_hash_bd(SEC_HASH_INFO_S *hash_info)
{
    SEC_BD_S *pstsecbd = NULL;

    pstsecbd = (SEC_BD_S *)(uintptr_t)hash_info->bd_addr;
    if (memset_s((void *)pstsecbd, sizeof(SEC_BD_S), 0x0, sizeof(SEC_BD_S)) != EOK) {
        tloge("sec hash bd, memset failed!\n");
        return ERR_SEC_MEMSET_FAILED;
    }

    dsb();

    pstsecbd->sec_bd_word0.bits.bd_type = SEC_N_TYPE;
    pstsecbd->sec_bd_word0.bits.auth = SEC_MAC_TO_DDR;
    pstsecbd->sec_bd_word0.bits.scene = SEC_NO_SCENE;
    pstsecbd->sec_bd_word0.bits.src_addr_type = SEC_PBUFFER;
    pstsecbd->sec_bd_word0.bits.dst_addr_type = SEC_PBUFFER;
    pstsecbd->sec_bd_word1.bits.auth_pad = SEC_LAST_BLOCK_PADDING;

    pstsecbd->sec_bd_word2.bits.a_alg = hash_info->hash_type;
    pstsecbd->sec_bd_word2.bits.mac_len = hash_info->mac_len;
    pstsecbd->sec_bd_word4.bits.auth_len = hash_info->data_len;

    pstsecbd->mac_addr_h = (uint32_t)(virt_mem_to_phys(hash_info->result_addr) >> SEC_SHIFT32);
    pstsecbd->mac_addr_l = (uint32_t)(virt_mem_to_phys(hash_info->result_addr));

    pstsecbd->data_src_addr_h = (uint32_t)(virt_mem_to_phys(hash_info->data_addr) >> SEC_SHIFT32);
    pstsecbd->data_src_addr_l = (uint32_t)(virt_mem_to_phys(hash_info->data_addr));

    return SEC_SUCCESS;
}

uint32_t sec_hash_init_bd(SEC_HASH_INFO_S *hash_info)
{
    SEC_BD_S *pstsecbd = NULL;

    pstsecbd = (SEC_BD_S *)(uintptr_t)hash_info->bd_addr;
    if (memset_s((void *)pstsecbd, sizeof(SEC_BD_S), 0x0, sizeof(SEC_BD_S)) != EOK) {
        tloge("sec hash init, memset failed!\n");
        return ERR_SEC_MEMSET_FAILED;
    }

    dsb();

    pstsecbd->sec_bd_word0.bits.bd_type = SEC_N_TYPE;
    pstsecbd->sec_bd_word0.bits.auth = SEC_MAC_TO_DDR;
    pstsecbd->sec_bd_word0.bits.scene = SEC_NO_SCENE;
    pstsecbd->sec_bd_word0.bits.src_addr_type = SEC_PBUFFER;
    pstsecbd->sec_bd_word0.bits.dst_addr_type = SEC_PBUFFER;
    pstsecbd->sec_bd_word1.bits.auth_pad = SEC_LAST_BLOCK_NO_PADDING;
    pstsecbd->sec_bd_word1.bits.ai_gen = SEC_AUTH_IV_OFF;

    pstsecbd->sec_bd_word2.bits.a_alg = hash_info->hash_type;
    pstsecbd->sec_bd_word2.bits.mac_len = hash_info->mac_len;
    pstsecbd->sec_bd_word4.bits.auth_len = hash_info->data_len;

    pstsecbd->mac_addr_h = (uint32_t)(virt_mem_to_phys(hash_info->result_addr) >> SEC_SHIFT32);
    pstsecbd->mac_addr_l = (uint32_t)(virt_mem_to_phys(hash_info->result_addr));

    pstsecbd->data_src_addr_h = (uint32_t)(virt_mem_to_phys(hash_info->data_addr) >> SEC_SHIFT32);
    pstsecbd->data_src_addr_l = (uint32_t)(virt_mem_to_phys(hash_info->data_addr));

    return SEC_SUCCESS;
}

uint32_t sec_hash_update_bd(SEC_HASH_INFO_S *hash_info)
{
    SEC_BD_S *pstsecbd = NULL;

    pstsecbd = (SEC_BD_S *)(uintptr_t)hash_info->bd_addr;
    if (memset_s((void *)pstsecbd, sizeof(SEC_BD_S), 0x0, sizeof(SEC_BD_S)) != EOK) {
        tloge("snist memset failed!\n");
        return ERR_SEC_MEMSET_FAILED;
    }

    dsb();

    pstsecbd->sec_bd_word0.bits.bd_type = SEC_N_TYPE;
    pstsecbd->sec_bd_word0.bits.auth = SEC_MAC_TO_DDR;
    pstsecbd->sec_bd_word0.bits.scene = SEC_NO_SCENE;
    pstsecbd->sec_bd_word0.bits.src_addr_type = SEC_PBUFFER;
    pstsecbd->sec_bd_word0.bits.dst_addr_type = SEC_PBUFFER;
    pstsecbd->sec_bd_word1.bits.auth_pad = SEC_LAST_BLOCK_NO_PADDING;
    pstsecbd->sec_bd_word1.bits.ai_gen = SEC_AUTH_IV_ON;

    pstsecbd->sec_bd_word2.bits.a_alg = hash_info->hash_type;
    pstsecbd->sec_bd_word2.bits.mac_len = hash_info->mac_len;
    pstsecbd->sec_bd_word4.bits.auth_len = hash_info->data_len;

    pstsecbd->mac_addr_h = (uint32_t)(virt_mem_to_phys(hash_info->result_addr) >> SEC_SHIFT32);
    pstsecbd->mac_addr_l = (uint32_t)(virt_mem_to_phys(hash_info->result_addr));

    pstsecbd->word15.auth_ivin_addr_h = (uint32_t)(virt_mem_to_phys(hash_info->iv_addr) >> SEC_SHIFT32);
    pstsecbd->word14.auth_ivin_addr_l = (uint32_t)(virt_mem_to_phys(hash_info->iv_addr));

    pstsecbd->data_src_addr_h = (uint32_t)(virt_mem_to_phys(hash_info->data_addr) >> SEC_SHIFT32);
    pstsecbd->data_src_addr_l = (uint32_t)(virt_mem_to_phys(hash_info->data_addr));

    return SEC_SUCCESS;
}

uint32_t sec_hash_final_bd(SEC_HASH_INFO_S *hash_info)
{
    SEC_BD_S *pstsecbd = NULL;

    pstsecbd = (SEC_BD_S *)(uintptr_t)hash_info->bd_addr;
    if (memset_s((void *)pstsecbd, sizeof(SEC_BD_S), 0x0, sizeof(SEC_BD_S)) != EOK) {
        tloge("sec memset failed!\n");
        return ERR_SEC_MEMSET_FAILED;
    }

    dsb();

    pstsecbd->sec_bd_word0.bits.bd_type = SEC_N_TYPE;
    pstsecbd->sec_bd_word0.bits.auth = SEC_MAC_TO_DDR;
    pstsecbd->sec_bd_word0.bits.scene = SEC_NO_SCENE;
    pstsecbd->sec_bd_word0.bits.src_addr_type = SEC_PBUFFER;
    pstsecbd->sec_bd_word0.bits.dst_addr_type = SEC_PBUFFER;
    pstsecbd->sec_bd_word1.bits.auth_pad = SEC_LAST_BLOCK_PADDING;
    pstsecbd->sec_bd_word1.bits.ai_gen = SEC_AUTH_IV_ON;

    pstsecbd->sec_bd_word2.bits.a_alg = hash_info->hash_type;
    pstsecbd->sec_bd_word2.bits.mac_len = hash_info->mac_len;
    pstsecbd->sec_bd_word4.bits.auth_len = hash_info->data_len;

    pstsecbd->sec_bd_word12.long_auth_data_len_l = hash_info->long_data_len_l;
    pstsecbd->sec_bd_word13.long_auth_data_len_h = hash_info->long_data_len_h;

    pstsecbd->mac_addr_h = (uint32_t)(virt_mem_to_phys(hash_info->result_addr) >> SEC_SHIFT32);
    pstsecbd->mac_addr_l = (uint32_t)(virt_mem_to_phys(hash_info->result_addr));

    pstsecbd->word15.auth_ivin_addr_h = (uint32_t)(virt_mem_to_phys(hash_info->iv_addr) >> SEC_SHIFT32);
    pstsecbd->word14.auth_ivin_addr_l = (uint32_t)(virt_mem_to_phys(hash_info->iv_addr));

    pstsecbd->data_src_addr_h = (uint32_t)(virt_mem_to_phys(hash_info->data_addr) >> SEC_SHIFT32);
    pstsecbd->data_src_addr_l = (uint32_t)(virt_mem_to_phys(hash_info->data_addr));

    return SEC_SUCCESS;
}

uint32_t sec_hmac_bd(SEC_HMAC_INFO_S *hmac_info)
{
    SEC_BD_S *pstsecbd = NULL;

    pstsecbd = (SEC_BD_S *)(uintptr_t)(hmac_info->bd_addr);
    if (memset_s((void *)pstsecbd, sizeof(SEC_BD_S), 0, sizeof(SEC_BD_S)) != EOK) {
        return ERR_SEC_MEMSET_FAILED;
    }

    dsb();

    pstsecbd->sec_bd_word0.bits.bd_type = SEC_N_TYPE;
    pstsecbd->sec_bd_word0.bits.auth = SEC_MAC_TO_DDR;
    pstsecbd->sec_bd_word0.bits.scene = SEC_NO_SCENE;
    pstsecbd->sec_bd_word0.bits.src_addr_type = SEC_PBUFFER;
    pstsecbd->sec_bd_word0.bits.dst_addr_type = SEC_PBUFFER;
    pstsecbd->sec_bd_word1.bits.auth_pad = SEC_LAST_BLOCK_PADDING;

    pstsecbd->sec_bd_word2.bits.key_sel = hmac_info->key_type;
    pstsecbd->auth_key_addr_h = (uint32_t)(virt_mem_to_phys(hmac_info->key_addr) >> SEC_SHIFT32);
    pstsecbd->auth_key_addr_l = (uint32_t)(virt_mem_to_phys(hmac_info->key_addr));

    if ((hmac_info->key_type == WRAPK1) || (hmac_info->key_type == WRAPK2)) {
        pstsecbd->sec_bd_word2.bits.update_key = 1;
    }

    pstsecbd->sec_bd_word2.bits.a_alg = hmac_info->hmac_type;
    pstsecbd->sec_bd_word2.bits.akey_len = hmac_info->key_len;
    pstsecbd->sec_bd_word2.bits.mac_len = hmac_info->mac_len;

    pstsecbd->sec_bd_word4.bits.auth_len = hmac_info->data_len;

    pstsecbd->mac_addr_h = (uint32_t)(virt_mem_to_phys(hmac_info->result_addr) >> SEC_SHIFT32);
    pstsecbd->mac_addr_l = (uint32_t)(virt_mem_to_phys(hmac_info->result_addr));

    pstsecbd->data_src_addr_h = (uint32_t)(virt_mem_to_phys(hmac_info->data_addr) >> SEC_SHIFT32);
    pstsecbd->data_src_addr_l = (uint32_t)(virt_mem_to_phys(hmac_info->data_addr));

    return SEC_SUCCESS;
}

uint32_t sec_hmac_init_bd(SEC_HMAC_INFO_S *hmac_info)
{
    SEC_BD_S *pstsecbd = NULL;

    pstsecbd = (SEC_BD_S *)(uintptr_t)hmac_info->bd_addr;
    if (memset_s((void *)pstsecbd, sizeof(SEC_BD_S), 0x0, sizeof(SEC_BD_S)) != EOK) {
        tloge("sec memset failed!\n");
        return ERR_SEC_MEMSET_FAILED;
    }

    dsb();

    pstsecbd->sec_bd_word0.bits.bd_type = SEC_N_TYPE;
    pstsecbd->sec_bd_word0.bits.auth = SEC_MAC_TO_DDR;
    pstsecbd->sec_bd_word0.bits.scene = SEC_NO_SCENE;
    pstsecbd->sec_bd_word0.bits.src_addr_type = SEC_PBUFFER;
    pstsecbd->sec_bd_word0.bits.dst_addr_type = SEC_PBUFFER;
    pstsecbd->sec_bd_word1.bits.auth_pad = SEC_LAST_BLOCK_NO_PADDING;
    pstsecbd->sec_bd_word1.bits.ai_gen = SEC_AUTH_IV_OFF;

    pstsecbd->sec_bd_word2.bits.key_sel = hmac_info->key_type;
    pstsecbd->auth_key_addr_h = (uint32_t)(virt_mem_to_phys(hmac_info->key_addr) >> SEC_SHIFT32);
    pstsecbd->auth_key_addr_l = (uint32_t)(virt_mem_to_phys(hmac_info->key_addr));

    if ((hmac_info->key_type == WRAPK1) || (hmac_info->key_type == WRAPK2)) {
        pstsecbd->sec_bd_word2.bits.update_key = 1;
    }

    pstsecbd->sec_bd_word2.bits.a_alg = hmac_info->hmac_type;
    pstsecbd->sec_bd_word2.bits.akey_len = hmac_info->key_len;
    pstsecbd->sec_bd_word2.bits.mac_len = hmac_info->mac_len;
    pstsecbd->sec_bd_word4.bits.auth_len = hmac_info->data_len;
    pstsecbd->mac_addr_h = (uint32_t)(virt_mem_to_phys(hmac_info->result_addr) >> SEC_SHIFT32);
    pstsecbd->mac_addr_l = (uint32_t)(virt_mem_to_phys(hmac_info->result_addr));
    pstsecbd->data_src_addr_h = (uint32_t)(virt_mem_to_phys(hmac_info->data_addr) >> SEC_SHIFT32);
    pstsecbd->data_src_addr_l = (uint32_t)(virt_mem_to_phys(hmac_info->data_addr));

    return SEC_SUCCESS;
}

uint32_t sec_hmac_update_bd(SEC_HMAC_INFO_S *hmac_info)
{
    SEC_BD_S *pstsecbd = NULL;

    pstsecbd = (SEC_BD_S *)(uintptr_t)hmac_info->bd_addr;
    if (memset_s((void *)pstsecbd, sizeof(SEC_BD_S), 0x0, sizeof(SEC_BD_S)) != EOK) {
        tloge("sec memset failed!\n");
        return ERR_SEC_MEMSET_FAILED;
    }

    dsb();

    pstsecbd->sec_bd_word0.bits.bd_type = SEC_N_TYPE;
    pstsecbd->sec_bd_word0.bits.auth = SEC_MAC_TO_DDR;
    pstsecbd->sec_bd_word0.bits.scene = SEC_NO_SCENE;
    pstsecbd->sec_bd_word0.bits.src_addr_type = SEC_PBUFFER;
    pstsecbd->sec_bd_word0.bits.dst_addr_type = SEC_PBUFFER;
    pstsecbd->sec_bd_word1.bits.auth_pad = SEC_LAST_BLOCK_NO_PADDING;
    pstsecbd->sec_bd_word1.bits.ai_gen = SEC_AUTH_IV_ON;

    pstsecbd->auth_key_addr_h = (uint32_t)(virt_mem_to_phys(hmac_info->key_addr) >> SEC_SHIFT32);
    pstsecbd->auth_key_addr_l = (uint32_t)(virt_mem_to_phys(hmac_info->key_addr));
    pstsecbd->sec_bd_word2.bits.key_sel = hmac_info->key_type;

    if ((hmac_info->key_type == WRAPK1) || (hmac_info->key_type == WRAPK2)) {
        pstsecbd->sec_bd_word2.bits.update_key = 1;
    }

    pstsecbd->sec_bd_word2.bits.a_alg = hmac_info->hmac_type;
    pstsecbd->sec_bd_word2.bits.akey_len = hmac_info->key_len;
    pstsecbd->sec_bd_word2.bits.mac_len = hmac_info->mac_len;
    pstsecbd->sec_bd_word4.bits.auth_len = hmac_info->data_len;
    pstsecbd->mac_addr_h = (uint32_t)(virt_mem_to_phys(hmac_info->result_addr) >> SEC_SHIFT32);
    pstsecbd->mac_addr_l = (uint32_t)(virt_mem_to_phys(hmac_info->result_addr));

    pstsecbd->word15.auth_ivin_addr_h = (uint32_t)(virt_mem_to_phys(hmac_info->iv_addr) >> SEC_SHIFT32);
    pstsecbd->word14.auth_ivin_addr_l = (uint32_t)(virt_mem_to_phys(hmac_info->iv_addr));

    pstsecbd->data_src_addr_h = (uint32_t)(virt_mem_to_phys(hmac_info->data_addr) >> SEC_SHIFT32);
    pstsecbd->data_src_addr_l = (uint32_t)(virt_mem_to_phys(hmac_info->data_addr));

    return SEC_SUCCESS;
}

uint32_t sec_hmac_final_bd(SEC_HMAC_INFO_S *hmac_info)
{
    SEC_BD_S *pstsecbd = NULL;

    pstsecbd = (SEC_BD_S *)(uintptr_t)hmac_info->bd_addr;
    if (memset_s((void *)pstsecbd, sizeof(SEC_BD_S), 0x0, sizeof(SEC_BD_S)) != EOK) {
        tloge("sec memset failed!\n");
        return ERR_SEC_MEMSET_FAILED;
    }

    dsb();
    pstsecbd->sec_bd_word0.bits.bd_type = SEC_N_TYPE;
    pstsecbd->sec_bd_word0.bits.auth = SEC_MAC_TO_DDR;
    pstsecbd->sec_bd_word0.bits.scene = SEC_NO_SCENE;
    pstsecbd->sec_bd_word0.bits.src_addr_type = SEC_PBUFFER;
    pstsecbd->sec_bd_word0.bits.dst_addr_type = SEC_PBUFFER;
    pstsecbd->sec_bd_word1.bits.auth_pad = SEC_LAST_BLOCK_PADDING;
    pstsecbd->sec_bd_word1.bits.ai_gen = SEC_AUTH_IV_ON;

    pstsecbd->auth_key_addr_h = (uint32_t)(virt_mem_to_phys(hmac_info->key_addr) >> SEC_SHIFT32);
    pstsecbd->auth_key_addr_l = (uint32_t)(virt_mem_to_phys(hmac_info->key_addr));
    pstsecbd->sec_bd_word2.bits.key_sel = hmac_info->key_type;

    if ((hmac_info->key_type == WRAPK1) || (hmac_info->key_type == WRAPK2)) {
        pstsecbd->sec_bd_word2.bits.update_key = 1;
    }

    pstsecbd->sec_bd_word2.bits.a_alg = hmac_info->hmac_type;
    pstsecbd->sec_bd_word2.bits.akey_len = hmac_info->key_len;
    pstsecbd->sec_bd_word2.bits.mac_len = hmac_info->mac_len;

    pstsecbd->sec_bd_word4.bits.auth_len = hmac_info->data_len;
    pstsecbd->sec_bd_word12.long_auth_data_len_l = hmac_info->long_data_len_l;
    pstsecbd->sec_bd_word13.long_auth_data_len_h = hmac_info->long_data_len_h;

    pstsecbd->word15.auth_ivin_addr_h = (uint32_t)(virt_mem_to_phys(hmac_info->iv_addr) >> SEC_SHIFT32);
    pstsecbd->word14.auth_ivin_addr_l = (uint32_t)(virt_mem_to_phys(hmac_info->iv_addr));

    pstsecbd->mac_addr_h = (uint32_t)(virt_mem_to_phys(hmac_info->result_addr) >> SEC_SHIFT32);
    pstsecbd->mac_addr_l = (uint32_t)(virt_mem_to_phys(hmac_info->result_addr));

    pstsecbd->data_src_addr_h = (uint32_t)(virt_mem_to_phys(hmac_info->data_addr) >> SEC_SHIFT32);
    pstsecbd->data_src_addr_l = (uint32_t)(virt_mem_to_phys(hmac_info->data_addr));

    return SEC_SUCCESS;
}

uint32_t sec_pbkdf2_bd(SEC_PBKDF2_INFO_S *pbkdf2_info)
{
    SEC_BD_S *pstsecbd = NULL;

    pstsecbd = (SEC_BD_S *)(uintptr_t)(pbkdf2_info->bd_addr);
    if (memset_s((void *)pstsecbd, sizeof(SEC_BD_S), 0, sizeof(SEC_BD_S)) != EOK) {
        return ERR_SEC_MEMSET_FAILED;
    }

    dsb();

    pstsecbd->sec_bd_word0.bits.bd_type = SEC_N_TYPE;
    pstsecbd->sec_bd_word0.bits.auth = SEC_MAC_TO_DDR;
    pstsecbd->sec_bd_word0.bits.scene = SEC_PBKDF2;
    pstsecbd->sec_bd_word0.bits.src_addr_type = SEC_PBUFFER;
    pstsecbd->sec_bd_word0.bits.dst_addr_type = SEC_PBUFFER;
    pstsecbd->sec_bd_word1.bits.auth_pad = SEC_LAST_BLOCK_PADDING;

    if (pbkdf2_info->key_addr != 0) {
        pstsecbd->sec_bd_word2.bits.key_sel = SEC_READ_FROM_DDR;
        pstsecbd->auth_key_addr_h = (uint32_t)(virt_mem_to_phys(pbkdf2_info->key_addr) >> SEC_SHIFT32);
        pstsecbd->auth_key_addr_l = (uint32_t)(virt_mem_to_phys(pbkdf2_info->key_addr));
    } else if (pbkdf2_info->key_type == HUK) {
        pstsecbd->sec_bd_word1.bits.huk = pbkdf2_info->key_type;
    } else {
        pstsecbd->sec_bd_word2.bits.key_sel = pbkdf2_info->key_type;
    }

    pstsecbd->sec_bd_word2.bits.a_alg = pbkdf2_info->hmac_type;
    pstsecbd->sec_bd_word2.bits.akey_len = SEC_HMAC_SHA256_AKEY_LEN;
    pstsecbd->sec_bd_word2.bits.mac_len = SEC_HMAC_SHA256_MAC_LEN;

    pstsecbd->data_src_addr_h = (uint32_t)(virt_mem_to_phys(pbkdf2_info->seed_addr) >> SEC_SHIFT32);
    pstsecbd->data_src_addr_l = (uint32_t)(virt_mem_to_phys(pbkdf2_info->seed_addr));

    pstsecbd->sec_bd_word4.bits.auth_len = pbkdf2_info->seed_len;
    pstsecbd->sec_bd_word5.bits.cipher_len = pbkdf2_info->cnt;
    pstsecbd->sec_bd_word8.data2.pass_word_len = pbkdf2_info->key_len;
    pstsecbd->sec_bd_word8.data2.dk_len = pbkdf2_info->mac_len;

    pstsecbd->mac_addr_h = (uint32_t)(virt_mem_to_phys(pbkdf2_info->result_addr) >> SEC_SHIFT32);
    pstsecbd->mac_addr_l = (uint32_t)(virt_mem_to_phys(pbkdf2_info->result_addr));

    return SEC_SUCCESS;
}

uint32_t sec_add_task(unsigned long bd_addr)
{
    uint32_t timeout = TIMEOUT;
    U_SEC_BDF_FIFO_STATUS bdf_status;
    unsigned long bd_phys = (unsigned long)(uintptr_t)(virt_mem_to_phys)(bd_addr);

    write32(SEC_BDF_EN_REG, SEC_POP_PUSH_EN);

    do {
        if (timeout == 0) {
            tloge("ERR_SEC_BDFIFO_TIMEOUT\n");
            return ERR_SEC_BDFIFO_TIMEOUT;
        }
        bdf_status.status = read32(SEC_BDF_FIFO_STATUS_REG);
        timeout--;
        dsb();
    } while (bdf_status.bits.bdf_fifo_full == SEC_BDFIFO_FULL);

    write32(SEC_BDF_DATA_LOW_REG, (uint32_t)bd_phys);
    dsb();
    write32(SEC_BDF_DATA_HIG_REG, (uint32_t)(bd_phys >> SEC_SHIFT32));
    dsb();

    return SEC_SUCCESS;
}

uint32_t sec_task_check(unsigned long bd_addr)
{
    uint32_t idx = 0;
    uint32_t bd_cnt_idx = 0;
    uint32_t timeout = TIMEOUT;
    SEC_BD_S *bd = (SEC_BD_S *)(uintptr_t)bd_addr;

    while (idx < timeout) {
        dsb();
        if ((volatile uint32_t)(bd->sec_bd_word28.bits.done) == 0x1) {
            dsb();
            break;
        }
        idx++;
        if (idx == timeout) {
            tloge("sec task check time out!\n");
            return ERR_SEC_TASK_TIMEOUT;
        }
    }

    while (bd_cnt_idx < BD_CNT_TIMEOUT) {
        if ((read32(SEC_BDF_PKG_DONE_CNT_REG) + read32(SEC_BDF_SPOP_CNT_REG)) == read32(SEC_BDF_PKG_GET_CNT_REG)) {
            break;
        }
        bd_cnt_idx++;
        if (bd_cnt_idx == BD_CNT_TIMEOUT) {
            tloge("sec bdf cnt check time out!\n");
            return ERR_SEC_TASK_TIMEOUT;
        }
        SRE_SwUsleep(BD_CNT_DELAY_1US);
    }

    if ((volatile uint32_t)(bd->sec_bd_word28.bits.error_type) == 0) {
        return SEC_SUCCESS;
    } else {
        tloge("SEC Failed, Error_Type = 0x%x\n",  bd->sec_bd_word28.bits.error_type);
        return ERR_SEC_TASK_FAILED;
    }
}

uint32_t sec_final_task_check(unsigned long bd_addr)
{
    uint32_t idx = 0;
    uint32_t bd_cnt_idx = 0;
    uint32_t timeout = TIMEOUT;
    SEC_BD_S *bd = (SEC_BD_S *)(uintptr_t)bd_addr;

    while (idx < timeout) {
        dsb();
        if ((volatile uint32_t)(bd->sec_bd_word28.bits.done) == 0x1) {
            dsb();
            break;
        }
        idx++;
        if (idx == timeout) {
            tloge("sec task check time out!\n");
            return ERR_SEC_TASK_TIMEOUT;
        }
    }

    while (bd_cnt_idx < BD_CNT_TIMEOUT) {
        if ((read32(SEC_BDF_PKG_DONE_CNT_REG) + read32(SEC_BDF_SPOP_CNT_REG)) == read32(SEC_BDF_PKG_GET_CNT_REG)) {
            break;
        }
        bd_cnt_idx++;
        if (bd_cnt_idx == BD_CNT_TIMEOUT) {
            tloge("sec bdf cnt check time out!\n");
            return ERR_SEC_TASK_TIMEOUT;
        }
        SRE_SwUsleep(BD_CNT_DELAY_1US);
    }

    if (((volatile uint32_t)(bd->sec_bd_word3.bits.c_mode) == SEC_GCM) &&
        ((volatile uint32_t)(bd->sec_bd_word0.bits.cipher) == AES_DEC) &&
        (((volatile uint32_t)(bd->sec_bd_word28.bits.flag) & 0x1) == 0x1) &&
        ((volatile uint32_t)(bd->sec_bd_word28.bits.icv) != 0x1)) {
        tloge("verify fail\n");
        return ERR_SEC_TASK_FAILED;
    }

    if ((volatile uint32_t)(bd->sec_bd_word28.bits.error_type) == 0) {
        return SEC_SUCCESS;
    } else {
        tloge("SEC Failed, Error_Type = 0x%x\n",  bd->sec_bd_word28.bits.error_type);
        return ERR_SEC_TASK_FAILED;
    }
}
