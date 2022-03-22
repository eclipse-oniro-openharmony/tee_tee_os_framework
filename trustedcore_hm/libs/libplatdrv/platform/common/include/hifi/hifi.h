/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * Description: process load hifi
 * Create: 2018-5-21
 */

#ifndef __HIFI_H__
#define __HIFI_H__

#include "tee_log.h"

#define HIFI_LOG_TAG "soc_hifi"

#define alogi(fmt, ...) \
	tee_print(LOG_LEVEL_INFO, "%s %d:%s:%s:" fmt "\n", TAG_INFO, __LINE__, HIFI_LOG_TAG, __func__, ##__VA_ARGS__)

#define alogw(fmt, ...) \
	tee_print(LOG_LEVEL_WARN, "%s %d:%s:%s:" fmt "\n", TAG_WARN, __LINE__, HIFI_LOG_TAG, __func__, ##__VA_ARGS__)

#define aloge(fmt, ...) \
	tee_print(LOG_LEVEL_ERROR, "%s %d:%s:%s:" fmt "\n", TAG_ERROR, __LINE__, HIFI_LOG_TAG, __func__, ##__VA_ARGS__)

unsigned int get_hifi_cma_size(void);
unsigned int get_hifi_image_size(unsigned int *image_size);
unsigned int prepare_reload_hifi(void);
unsigned int load_hifi_image(const void *img_buf);
unsigned int dump_cma_text(const void *img_buf);

#endif /* _HIFI_H_ */

