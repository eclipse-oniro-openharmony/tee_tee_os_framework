/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: taload api
 * Author: Hisilicon
 * Created: 2020-05-10
 */

#ifndef _HI_TEE_TALOAD_H
#define _HI_TEE_TALOAD_H

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cplusplus */
#endif /* __cplusplus */

int hisi_check_header(const char *buf, unsigned int size);
int hisi_get_total_len(const char *buf, unsigned int size, unsigned int *total_len);
int hisi_get_private_data(const char *buf, unsigned int size, const unsigned int *data_size,
                          const unsigned int *data_offest);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif /* _HI_TEE_TALOAD_H */

