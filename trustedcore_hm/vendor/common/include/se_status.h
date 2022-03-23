/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: set and get se channel information from platdrv
 * Create: 2020-1-14
 */
#ifndef SE_STATUS_H
#define SE_STATUS_H
#include <stdint.h>

void __sre_se_channel_info_write(uint32_t reader_id, uint32_t channel_id, uint32_t task_id);
void __sre_se_channel_info_read(uint32_t reader_id, uint32_t *task_id, uint32_t *cnt);
void __sre_se_deactive_write(uint32_t deactive);
void __sre_se_deactive_read(uint32_t *deactive);
void __sre_seaid_switch_write(uint8_t *seaid_list, uint32_t seaid_list_len);
void __sre_seaid_list_len_read(uint32_t *seaid_list_len);
void __sre_seaid_switch_read(uint8_t *seaid_list, uint32_t seaid_list_len);
void __sre_se_connect_info_write(uint32_t reader_id, uint8_t *se_connect_info, uint32_t se_connect_info_len);
void __sre_se_connect_info_read(uint32_t reader_id, uint8_t *se_connect_info, uint32_t *se_connect_info_len);

#endif
