/*
* Copyright (c) Huawei Technologies Co., Ltd. 2019-2021. All rights reserved.
* Description: scmi header file
* Author: huawei
* Create: 2019/12/25
*/
#ifndef SCMI_H
#define SCMI_H

#define SHARE_DDR_ADDR_BASE         0x2E00000
#define SHARE_DDR_ADDR_END          0x3E00000
#define SHARE_DDR_SIZE              (SHARE_DDR_ADDR_END - SHARE_DDR_ADDR_BASE)

#ifdef ASCEND920_BUILD
#define SCMI_0_BASE                 0x84700000U
#else
#define SCMI_0_BASE                 0x84080000U
#endif

#define SCMI_DOORBELL               (SCMI_0_BASE + 0x0000)
#define SCMI_DOORBELL_MSK           (SCMI_0_BASE + 0x0004)
#define SCMI_DOORBELL_SET           (SCMI_0_BASE + 0x0008)
#define SCMI_DOORBELL_CLR           (SCMI_0_BASE + 0x000C)
#define SCMI_DOORBELLACK            (SCMI_0_BASE + 0x0010)
#define SCMI_DOORBELLACK_MSK        (SCMI_0_BASE + 0x0014)
#define SCMI_DOORBELLACK_SET        (SCMI_0_BASE + 0x0018)
#define SCMI_DOORBELLACK_CLR        (SCMI_0_BASE + 0x001C)
#define SCMI_NOTIFYINT              (SCMI_0_BASE + 0x0020)
#define SCMI_NOTIFYINT_MSK          (SCMI_0_BASE + 0x0024)
#define SCMI_NOTIFYINT_SET          (SCMI_0_BASE + 0x0028)
#define SCMI_NOTIFYINT_CLR          (SCMI_0_BASE + 0x002C)
#define SCMI_CHANNEL_ENABLE         (SCMI_0_BASE + 0x0030)
#define SCMI_CHANNEL_ST0            (SCMI_0_BASE + 0x0034)
#define SCMI_CHANNEL_ST1            (SCMI_0_BASE + 0x0038)
#define SCMI_MBX_DR                 (SCMI_0_BASE + 0x0200)

#define CHANNEL_TO_BIT(ch)          (uint32_t)(0x1 << (ch))
#define REG_LEN_4BYTES              4

#define SCMI_CHECK_TIMEOUT          7000
#define SCMI_SEND_TIMEOUT           0xFFFFFF
#define SCMI_CHANNEL_ENABLE_VAL     0x000000FF
#define SCMI_DOORBELL_MSK_CLOSE     0xFFFFFF00
#define SCMI_DOORBELLACK_MSK_CLOSE  0xFFFFFF00
#define SCMI_NOTIFYINT_MSK_CLOSE    0xFFFFFF00

#define SCMI_IDLE                   0
#define SCMI_BUSY                   1

#define DEVICE_ADDR_OFFSET          0x8000000000U

void scmi_set_doorbell(uint32_t dev_id, uint32_t channel);
uint32_t scmi_get_doorbell(uint32_t dev_id);
void scmi_set_doorbellackset(uint32_t dev_id, uint32_t channel);
void scmi_set_channel_enable(uint32_t dev_id, uint32_t channel);
void scmi_set_channel_disable(uint32_t dev_id, uint32_t channel);
uint32_t scmi_get_channel_enable(uint32_t dev_id);
void scmi_set_channel_doorbell_msk(uint32_t dev_id, uint32_t value);
void scmi_set_channel_doorbellack_msk(uint32_t dev_id, uint32_t value);
uint32_t scmi_get_channel_doorbell_msk(uint32_t dev_id);
uint32_t scmi_get_channel_doorbellack_msk(uint32_t dev_id);
void scmi_set_channel_notifyint_msk(uint32_t dev_id, uint32_t value);
uint32_t scmi_get_channel_notifyint_msk(uint32_t dev_id);
void scmi_set_channel_notifyint(uint32_t dev_id, uint32_t value);
uint32_t scmi_get_channel_notifyint(uint32_t dev_id);
uint32_t scmi_get_channel_state(uint32_t dev_id, uint32_t channel);
uint32_t scmi_write_mailbox(uint32_t dev_id, uint32_t channel, uint8_t *buf, uint32_t len);
uint32_t scmi_read_mailbox(uint32_t dev_id, uint32_t channel, uint8_t *outbuf, uint32_t len);
uint32_t scmi_get_dev_number(void);
#endif
