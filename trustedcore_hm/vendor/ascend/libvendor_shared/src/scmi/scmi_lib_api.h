/*
* Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
* Description: scmi libs api file
* Author: pengcong
* Create: 2020/1/14
*/

#ifndef SCMI_LIB_API_H
#define SCMI_LIB_API_H

#define SCMI_LIB_RESULT_SUCCESS         0x0U

uint32_t lib_scmi_channel_open(uint32_t dev_id, uint32_t channel);
uint32_t lib_scmi_channel_close(uint32_t dev_id, uint32_t channel);
uint32_t lib_scmi_channel_send_data(uint32_t dev_id, uint32_t channel, uint8_t *buf, uint32_t len);
uint32_t lib_scmi_check_task_and_get_data(uint32_t dev_id, uint32_t channel, uint8_t *buf, uint32_t len);
uint32_t lib_hiss_shared_paddr_to_vaddr(uint32_t dev_id, uint64_t *vaddr_out);
#endif
