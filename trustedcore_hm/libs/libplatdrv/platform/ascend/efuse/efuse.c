/*
* Copyright (c) Huawei Technologies Co., Ltd. 2019-2021. All rights reserved.
* Description: efuse source file
* Author: huawei
* Create: 2019/09/18
*/
#include <timer.h>
#include <register_ops.h>
#include "tee_defines.h"
#include "tee_log.h"

#include "securec.h"

#include "driver_common.h"
#include "hsm_dev_id.h"
#include "efuse_mapping.h"
#include "efuse_internal_api.h"
#include "efuse_api.h"
#include "efuse.h"
#include "timer.h"

STATIC uint32_t check_djtag_start_en_status(uint32_t base)
{
    volatile uint32_t loop = EFUSE_READ_DATA_TIME;
    volatile uint32_t value;

    /* 4.step--start DJTAG master access */
    write32(base + DJTAG_MASTER_START_EN, 0x1);
    dsb();

    /* 5.step--read data util 0x0 */
    do {
        value = read32(base + DJTAG_MASTER_START_EN);
        if (loop == 0) {
            tloge("config value timeout! value = 0x%x\n", value);
            return TEE_ERROR_TIMEOUT;
        }
        loop--;
    } while (value != 0x0);

    return TEE_SUCCESS;
}

static uint32_t get_write_chain_number(uint32_t chain_choose)
{
    if (chain_choose == EFUSE_BLOCK_NUM0_ID) {
        return EFUSE_BLOCK_NUM0_CHAIN_W;
    }

    return EFUSE_BLOCK_NUM1_CHAIN_W;
}

static uint32_t get_read_chain_number(uint32_t chain_choose)
{
    if (chain_choose == EFUSE_BLOCK_NUM0_ID) {
        return EFUSE_BLOCK_NUM0_CHAIN_R;
    }

    return EFUSE_BLOCK_NUM1_CHAIN_R;
}

uint32_t get_efuse_base_addr(uint32_t dev_id, uint64_t *base_addr)
{
    uint32_t ret;

    ret = drv_dev_id_verify(dev_id);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    if (dev_id == 0) {
        *base_addr = 0;
    } else {
        *base_addr = EFUSE_CHIP_OFFSET * dev_id;
    }

    return TEE_SUCCESS;
}
/*
* function: read the EFUSE data info(include bufer data and efuse data)
* param[in]: uwaddr-- access addr that to be check
*            read_chain_choose -- efuse checking chain choose
* param[out]: out_data -- read out data
* return value: SUCCESS means OK, other value means failure
*/
STATIC uint32_t buffer_djtag_check(uint32_t uwaddr, uint32_t read_chain_choose,
                                   uint32_t *out_data, uint32_t dev_id)
{
    uint64_t base = 0;
    uint32_t ret;

    ret = get_efuse_base_addr(dev_id, &base);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    /* 1.step--enable DJTAG master */
    write32(base + DJTAG_MASTER_EN, 0x1);
    dsb();

    /* 2.step--DJTAG master config */
    write32(base + DJTAG_MASTER_CFG, read_chain_choose);
    dsb();

    /* 3.step--config DJTAG master access addr */
    write32(base + DJTAG_MASTER_ADDR, uwaddr);
    dsb();

    /* 4.step--start DJTAG master access */
    ret = check_djtag_start_en_status(base);
    if (ret != SUCCESS) {
        return ERR_EFUSE_DJTAG_CHECK_TIMEOUT;
    }

    /* 5.step--read data of the only addr */
    *out_data = read32(base + DJTAG_RD_DATA0_REG);

    return TEE_SUCCESS;
}

STATIC uint32_t config_value_to_reg(uint32_t value, uint32_t reg,
                                    uint32_t chain_write, uint32_t dev_id)
{
    uint32_t ret;
    uint64_t base = 0;

    ret = get_efuse_base_addr(dev_id, &base);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    /* 1.1--enable DJTAG master */
    write32(base + DJTAG_MASTER_EN, 0x1);
    dsb();

    /* 1.2--DJTAG master cfg */
    write32(base + DJTAG_MASTER_CFG, chain_write);
    dsb();

    /* 1.3--config DJTAG master access addr */
    write32(base + DJTAG_MASTER_ADDR, reg);
    dsb();

    /* 1.4--config DJTAG master writing data */
    write32(base + DJTAG_MASTER_DATA, value);
    dsb();

    /* 1.5--start DJTAG master */
    ret = check_djtag_start_en_status(base);
    if (ret != TEE_SUCCESS) {
        return ERR_EFUSE_READ_CONFIG_VALUE_TIMEOUT;
    }

    return TEE_SUCCESS;
}

/*
* function: read the EFUSE data of the choosed EFUSE block
* param[in]: word--the word that to be read, chain_choose--EFUSE block that choose to read
* return vale: data that readed by caller
*/
uint32_t read_efuse(uint32_t word, uint32_t chain_choose, uint32_t *out_data, uint32_t dev_id)
{
    uint32_t chain_read = get_read_chain_number(chain_choose);
    uint32_t ret;

    ret = buffer_djtag_check(EFUSE_REG_CTRL_OFFSET_BASE + word, chain_read, out_data, dev_id);
    if (ret != SUCCESS) {
        tloge("Read efuse data failed, 0x%x\n", ret);
        return ret;
    }

    return TEE_SUCCESS;
}

/*
* function: write value into the word of chain_choose EFUSE block
* param[in]: word--the word that to write, value--value that be writed by caller,
*            chain_choose--EFUSE block that choose to write
* return vale: 0x0 means success, other value means failure
*/
STATIC uint32_t write_efuse(uint32_t word, uint32_t value, uint32_t chain_choose, uint32_t dev_id)
{
    uint32_t uwtmp = 0;
    uint32_t ret;
    uint32_t chain_read = get_read_chain_number(chain_choose);
    uint32_t chain_write = get_write_chain_number(chain_choose);

    /* write data into efuse's buffer */
    ret = config_value_to_reg(value, EFUSE_BUFDATA_OFFSET_BASE + word, chain_write, dev_id);
    if (ret != TEE_SUCCESS) {
        tloge("Write data into buffer failed, 0x%x\n", ret);
        return ret;
    }

    /* make sure the buffer data is the excepted data */
    ret = buffer_djtag_check(EFUSE_BUFDATA_OFFSET_BASE + word, chain_read, &uwtmp, dev_id);
    if (ret != TEE_SUCCESS) {
        tloge("Djtag check failed, 0x%x\n", ret);
        return ret;
    }

    /* check buffer data */
    if (uwtmp != value) {
        tloge("efuse write, check buffer data failed! uwtmp=0x%x, value=0x%x\n", uwtmp, value);
        return ERR_EFUSE_CHECK_BUFFER_DATA_FAILED;
    }

    return TEE_SUCCESS;
}

/*
* function: burn the excepted EFUSE block
* param[in]: chain_choose--EFUSE block that to burn
* return vale: 0x0 means success, other value means failure
*/
STATIC uint32_t burn_efuse(uint32_t chain_choose, uint32_t dev_id)
{
    uint32_t chain_write = get_write_chain_number(chain_choose);
    uint32_t ret;

    /* 1. write 0x1 into reg:0x7 */
    ret = config_value_to_reg(0x1, EFUSE_REG_0X7, chain_write, dev_id);
    if (ret != TEE_SUCCESS) {
        tloge("Burn step 1 failed, 0x%x\n", ret);
        return ret;
    }

    /* 2. write 0x0 into reg:0x8 */
    ret = config_value_to_reg(0x0, EFUSE_REG_0X8, chain_write, dev_id);
    if (ret != TEE_SUCCESS) {
        tloge("Burn step 2 failed, 0x%x\n", ret);
        return ret;
    }

    /* 3. write 0x840 into reg:0x0 */
    ret = config_value_to_reg(EFUSE_REG_VALUE0, 0x0, chain_write, dev_id);
    if (ret != TEE_SUCCESS) {
        tloge("Burn step 3 failed, 0x%x\n", ret);
        return ret;
    }

    /* 4. write 0x846 into reg:0x0 */
    ret = config_value_to_reg(EFUSE_REG_VALUE1, 0x0, chain_write, dev_id);
    if (ret != TEE_SUCCESS) {
        tloge("Burn step 4 failed, 0x%x\n", ret);
        return ret;
    }

    SRE_SwMsleep(EFUSE_DELAY_COUNT); /* delaly 1s */

    return TEE_SUCCESS;
}

STATIC const efuse_desc_t *efuse_block_choose(uint32_t efuse_block_num, uint32_t *array_size_out)
{
    const efuse_desc_t *temp = NULL;

    if (efuse_block_num == EFUSE_BLOCK_NUM0_ID) {
        *array_size_out = sizeof(g_efuse0) / sizeof(efuse_desc_t);
        temp = g_efuse0;
    } else if (efuse_block_num == EFUSE_BLOCK_NUM1_ID) {
        *array_size_out = sizeof(g_efuse1) / sizeof(efuse_desc_t);
        temp = g_efuse1;
    } else {
        *array_size_out = 0;
        temp = NULL;
        tloge("Invalid efuse block num, 0x%x!\n", efuse_block_num);
    }

    return temp;
}

STATIC uint32_t wr_efuse_common(EFUSE_COMM_INFO info, uint8_t *input,
                                uint32_t *word_out, uint32_t *count_out, uint32_t *mask_out)
{
    uint32_t i;
    uint32_t array_size = 0;
    uint32_t efuse_block_num;
    uint32_t start_bit;
    uint32_t dest_size;
    const efuse_desc_t *tmp_desc = NULL;
    uint32_t *ptr_input = (uint32_t *)input;

    efuse_block_num = info.efuse_block_num;
    start_bit = info.start_bit;
    dest_size = info.dest_size;
    tmp_desc = efuse_block_choose(efuse_block_num, &array_size);
    if ((tmp_desc == NULL) || (array_size == 0)) {
        tloge("wr efuse common params error!\n");
        return ERR_EFUSE_WR_COMMON_ARRAY_SIZE_WRONG;
    }

    for (i = 0; i < array_size; i++) {
        if ((start_bit == tmp_desc->start) && (dest_size == tmp_desc->size)) {
            *word_out = tmp_desc->word;
            *mask_out = tmp_desc->mask;
            if (tmp_desc->size <= WORD_BITS) {
                *count_out = 1;
            } else {
                *count_out = tmp_desc->size / WORD_BITS;
            }
            break;
        }
        tmp_desc++;
    }

    if (i >= array_size) {
        tloge("don't find right efuse mapping data!\n");
        return ERR_EFUSE_DONT_FIND_EFUSE_MAPPING;
    }

    /* mask action */
    if (tmp_desc->size <= WORD_BITS) {
        *ptr_input = (*ptr_input) & (tmp_desc->mask); /* masked when writing & checking efuse data */
    }

    return TEE_SUCCESS;
}

STATIC uint32_t efuse_check_operation(EFUSE_OPERATE_INFO info, uint8_t *check_data, uint32_t mask, uint32_t dev_id)
{
    uint32_t value = 0;
    uint32_t i;
    uint8_t efuse_block_num;
    uint32_t word;
    uint32_t count;
    uint32_t *input_temp = (uint32_t *)check_data;

    efuse_block_num = info.efuse_block_num;
    word = info.word;
    count = info.count;

    for (i = 0; i < count; i++, word++) {
        uint32_t ret;

        ret = read_efuse(word, efuse_block_num, &value, dev_id);
        if (ret != SUCCESS) {
            tloge("read efuse action failed, 0x%x\n", ret);
            return ERR_EFUSE_READ_OPERATION_ERROR;
        }

        value = value & mask; /* should mask */
        if (value != (*(input_temp + i))) {
            tloge("efuse check failed! input=0x%x, readout=0x%x\n", (*(input_temp + i)), value);
            return ERR_EFUSE_DATA_CHECK_FAILED;
        }
    }

    return TEE_SUCCESS;
}

STATIC uint32_t efuse_write_operation(uint32_t efuse_block_num, uint32_t word, uint32_t count,
                                      uint8_t *writed_data, uint32_t mask, uint32_t dev_id)
{
    uint32_t *ptr_writed_data = (uint32_t *)writed_data;
    uint32_t i;
    uint32_t value;

    for (i = 0; i < count; i++, word++) {
        uint32_t ret;

        value = (*(ptr_writed_data + i)) & mask;
        tloge("the word %u write value is : 0x%x\n", word, value);

        ret = write_efuse(word, value, efuse_block_num, dev_id);
        if (ret != TEE_SUCCESS) {
            tloge("efuse write failed, 0x%x\n", ret);
            return ret;
        }
    }

    return TEE_SUCCESS;
}

uint32_t itrustee_burn_efuse(uint32_t chain_choose, uint32_t dev_id)
{
    return burn_efuse(chain_choose, dev_id);
}

uint32_t itrustee_efuse_check(uint32_t efuse_block_num, uint32_t start_bit, uint32_t dest_size,
                              uint8_t *check_data, uint32_t dev_id)
{
    uint32_t ret;
    uint32_t word = 0;
    uint32_t mask = MASK_DEFAULT_VALUE;
    uint32_t count = 0;
    EFUSE_COMM_INFO info;
    EFUSE_OPERATE_INFO operate;

    info.efuse_block_num = efuse_block_num;
    info.start_bit = start_bit;
    info.dest_size = dest_size;
    ret = wr_efuse_common(info, check_data, &word, &count, &mask);
    if (ret != SUCCESS) {
        tloge("Write efuse failed, 0x%x!\n", ret);
        return ERR_EFUSE_START_BIT_SIZE_INPUT_PARAM;
    }

    operate.efuse_block_num = efuse_block_num;
    operate.word = word;
    operate.count = count;

    ret = efuse_check_operation(operate, check_data, mask, dev_id);
    if (ret != SUCCESS) {
        tloge("efuse check failed, 0x%x\n", ret);
        return ret;
    }

    return TEE_SUCCESS;
}

uint32_t itrustee_write_efuse(uint32_t efuse_blk_num, uint32_t start_bit, uint32_t dest_size,
                              uint8_t *writed_data, uint32_t dev_id)
{
    uint32_t ret;
    uint32_t word = 0;
    uint32_t mask = MASK_DEFAULT_VALUE;
    uint32_t count = 0;
    EFUSE_COMM_INFO info;

    info.efuse_block_num = efuse_blk_num;
    info.start_bit = start_bit;
    info.dest_size = dest_size;
    ret = wr_efuse_common(info, writed_data, &word, &count, &mask);
    if (ret != SUCCESS) {
        tloge("Write efuse failed, 0x%x!\n", ret);
        return ERR_EFUSE_WRITE_FAILED;
    }

    ret = efuse_write_operation(efuse_blk_num, word, count, writed_data, mask, dev_id);
    if (ret != SUCCESS) {
        tloge("Write efuse failed, 0x%x\n", ret);
        return ret;
    }

    return TEE_SUCCESS;
}

uint32_t bisr_reset(uint32_t dev_id)
{
    uint64_t base = 0;
    uint32_t ret;

    ret = get_efuse_base_addr(dev_id, &base);
    if (ret != TEE_SUCCESS) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    write32(base + BISR_RESET_REQ_REG, 0x1);
    if (read32(base + BISR_RESET_ST_REG) != 0x1) {
        tloge("Bisr reset start fail\n");
        return TEE_ERROR_BAD_STATE;
    }

    write32(base + BISR_RESET_DREQ_REG, 0x1);
    if (read32(base + BISR_RESET_ST_REG) != 0x0) {
        tloge("Bisr reset end fail\n");
        return TEE_ERROR_BAD_STATE;
    }

    SRE_SwMsleep(BISR_RESET_DELAY_5S);
    return TEE_SUCCESS;
}
