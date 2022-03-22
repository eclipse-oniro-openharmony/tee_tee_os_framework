/*******************************************************************************
* @file       thp_afe_hal.h
*
* @version    V0.08
*
* @authors    caiweigang@huawei.com
*
* @par Description
*   This is Touch Host Processing(THP) Analog Front End(AFE)
*   Hardware Abstraction Layer(HAL) header file.
*   All the touch IC suppliers should implement AFE driver based on it.
*
********************************************************************************
* Copyright (2016-2017), Huawei Company. All Rights Reserved.
*******************************************************************************/

#ifndef __THP_AFE_HAL_H_
#define __THP_AFE_HAL_H_

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
    int status;
    int x;
    int y;
    int area;
    int pressure;
    int orientation;
    int major;
    int minor;
    int event;
    unsigned int cur_pid;
}ts_tui_finger;
int thp_init(void);
int  thp_deinit(void);
#ifdef __cplusplus
}
#endif

#endif /* __THP_AFE_HAL_H_ */

