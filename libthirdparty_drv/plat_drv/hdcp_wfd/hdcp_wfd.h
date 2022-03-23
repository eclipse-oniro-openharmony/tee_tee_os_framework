/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: HDCP registers configuration in secure_os
 * Author: Hisilicon
 * Create: 2019-12-29
 */

#ifndef HDCP_WFD_H
#define HDCP_WFD_H

#include "tee_log.h"
#include "secmem.h"

int hdcp_wfd_handle_map(unsigned int *mappedAddr, unsigned int cacheMode,
                        unsigned int secShareFd, unsigned int dataLen);
int hdcp_wfd_handle_unmap(unsigned int secShareFd, unsigned int dataLen);
#endif

