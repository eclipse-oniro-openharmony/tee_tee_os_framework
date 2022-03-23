/*
* Copyright (c) Huawei Technologies Co., Ltd. 2019-2021. All rights reserved.
* Description: scmi source file
* Author: pengcong
* Create: 2019/12/25
*/

#include <register_ops.h>
#include <tee_defines.h>
#include <register_ops.h>
#include "tee_log.h"

#include "securec.h"
#include "scmi.h"
#include "scmi_api.h"
#include "driver_common.h"

void scmi_set_doorbell(uint32_t dev_id, uint32_t channel)
{
    write32(SCMI_DOORBELL_SET + (dev_id * DEVICE_ADDR_OFFSET), CHANNEL_TO_BIT(channel));
}

uint32_t scmi_get_doorbell(uint32_t dev_id)
{
    return read32(SCMI_DOORBELL + (dev_id * DEVICE_ADDR_OFFSET));
}

void scmi_set_doorbellackset(uint32_t dev_id, uint32_t channel)
{
    write32(SCMI_DOORBELLACK_SET + (dev_id * DEVICE_ADDR_OFFSET), CHANNEL_TO_BIT(channel));
}

void scmi_set_channel_enable(uint32_t dev_id, uint32_t channel)
{
    write32(SCMI_CHANNEL_ENABLE + (dev_id * DEVICE_ADDR_OFFSET), CHANNEL_TO_BIT(channel));
}

void scmi_set_channel_disable(uint32_t dev_id, uint32_t channel)
{
    write32(SCMI_CHANNEL_ENABLE + (dev_id * DEVICE_ADDR_OFFSET), ~(CHANNEL_TO_BIT(channel)));
}

uint32_t scmi_get_channel_enable(uint32_t dev_id)
{
    return read32(SCMI_CHANNEL_ENABLE + (dev_id * DEVICE_ADDR_OFFSET));
}

void scmi_set_channel_doorbell_msk(uint32_t dev_id, uint32_t value)
{
    write32(SCMI_DOORBELL_MSK + (dev_id * DEVICE_ADDR_OFFSET), value);
}

uint32_t scmi_get_channel_doorbell_msk(uint32_t dev_id)
{
    return read32(SCMI_DOORBELL_MSK + (dev_id * DEVICE_ADDR_OFFSET));
}

void scmi_set_channel_doorbellack_msk(uint32_t dev_id, uint32_t value)
{
    write32(SCMI_DOORBELLACK_MSK + (dev_id * DEVICE_ADDR_OFFSET), value);
}

uint32_t scmi_get_channel_doorbellack_msk(uint32_t dev_id)
{
    return read32(SCMI_DOORBELLACK_MSK + (dev_id * DEVICE_ADDR_OFFSET));
}

void scmi_set_channel_notifyint_msk(uint32_t dev_id, uint32_t value)
{
    write32(SCMI_NOTIFYINT_MSK + (dev_id * DEVICE_ADDR_OFFSET), value);
}

uint32_t scmi_get_channel_notifyint_msk(uint32_t dev_id)
{
    return read32(SCMI_NOTIFYINT_MSK + (dev_id * DEVICE_ADDR_OFFSET));
}

void scmi_set_channel_notifyint(uint32_t dev_id, uint32_t value)
{
    write32(SCMI_NOTIFYINT + (dev_id * DEVICE_ADDR_OFFSET), value);
}

uint32_t scmi_get_channel_notifyint(uint32_t dev_id)
{
    return read32(SCMI_NOTIFYINT + (dev_id * DEVICE_ADDR_OFFSET));
}

uint32_t scmi_get_channel_state(uint32_t dev_id, uint32_t channel)
{
    uint32_t val;

    val = read32(SCMI_CHANNEL_ST0 + (dev_id * DEVICE_ADDR_OFFSET));
    if ((val & CHANNEL_TO_BIT(channel)) != 0) {
        return SCMI_BUSY;
    }

    return SCMI_IDLE;
}

uint32_t scmi_get_dev_number(void)
{
    uint32_t val = read32(SYSCTRL_REG_BASE + SC_PAD_INFO_OFFSET);
    uint32_t dev_num = ((val & BIT5) == BIT5) ? DEV_NUM_2 : DEV_NUM_1;

    return dev_num;
}

uint32_t scmi_write_mailbox(uint32_t dev_id, uint32_t channel, uint8_t *buf, uint32_t len)
{
    uint64_t mailbox_addr;
    uint32_t word_num;
    uint32_t data[MAILBOX_CHANNEL_SIZE] = {0};
    int ret;

    ret = memcpy_s(data, sizeof(uint32_t) * MAILBOX_CHANNEL_SIZE, buf, len);
    if (ret != EOK) {
        tloge("memory copy failed, 0x%x.\n", len);
        return TEE_ERROR_BAD_STATE;
    }

    word_num = ((len % REG_LEN_4BYTES) ? ((len / REG_LEN_4BYTES) + 1) : (len / REG_LEN_4BYTES));
    mailbox_addr = (MAILBOX_CHANNEL_SIZE * channel) + SCMI_MBX_DR + (dev_id * DEVICE_ADDR_OFFSET);

    for (uint32_t i = 0; i < word_num; i++) {
        write32(mailbox_addr + (sizeof(uint32_t) * i), data[i]);
    }

    return TEE_SUCCESS;
}

uint32_t scmi_read_mailbox(uint32_t dev_id, uint32_t channel, uint8_t *outbuf, uint32_t len)
{
    uint64_t mailbox_addr;
    uint32_t word_num;
    uint32_t data[MAILBOX_CHANNEL_SIZE] = {0};
    uint32_t data_size = len;
    int ret;

    word_num = ((len % REG_LEN_4BYTES) ? ((len / REG_LEN_4BYTES) + 1) : (len / REG_LEN_4BYTES));
    mailbox_addr = (MAILBOX_CHANNEL_SIZE * channel) + SCMI_MBX_DR + (dev_id * DEVICE_ADDR_OFFSET);

    for (uint32_t i = 0; i < word_num; i++) {
        data[i] = read32(mailbox_addr + (sizeof(uint32_t) * i));
    }

    ret = memcpy_s(outbuf, len, data, data_size);
    if (ret != EOK) {
        tloge("read mailbox cpy failed!\n");
        return TEE_ERROR_BAD_STATE;
    }

    return TEE_SUCCESS;
}
