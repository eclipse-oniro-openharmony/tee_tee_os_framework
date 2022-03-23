/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2015-2020. All rights reserved.
 * Description: IVP driver
 * Create: 2015-05-06
 */

#ifndef _IVP_H_
#define _IVP_H_

unsigned int get_ivp_cma_size(void);
unsigned int get_ivp_img_size(void);
int load_ivp_image(unsigned int fw_addr);

#endif /* _IVP_H_ */
