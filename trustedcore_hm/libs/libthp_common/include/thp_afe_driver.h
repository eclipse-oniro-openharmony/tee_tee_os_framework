/*******************************************************************************
* @file       thp_afe_driver.h
*
* @version    V0.01
*
* @authors    dale.lijie@huawei.com
*
* @Description
*   This is Touch Host Processing(THP) Analog Front End(AFE)
*   Hardware Abstraction Layer driver(HAL driver) header file.
*   All the touch IC suppliers should implement AFE driver based on it.
* Create: 2017-01-20
* Author: l00481845
********************************************************************************
* Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
*******************************************************************************/

#ifndef __THP_AFE_DRIVER_H_
#define __THP_AFE_DRIVER_H_

#include "thp_afe.h"
#include "securec.h"
#include "tee_mem_mgmt_api.h"

#ifdef __cplusplus
extern "C" {
#endif

#define THP_PROJECT_ID_LEN       10
#define THP_IOCTL_CMD_GET_FRAME  0x1
#define THP_IOCTL_CMD_SPI_SYNC   0x2

#undef ENOBUFS
#define	ENOBUFS   55    /* No buffer space available */

/**********************************************************************************
time struct --touch IC suppliers should use this structure

*************************************************************************************/
struct timeval {
    unsigned int tv_sec; // secend
    unsigned int tv_usec;    // micro-second in TEE is calculated by milli-second*1000,
                             // so the least 3 digital is always 0
};

struct thp_ioctl_get_frame_data {
    char* buf;
    char* tv; /* struct timeval */
    unsigned int size;
};

struct thp_ioctl_spi_sync_data {
    char* tx;
    char* rx;
    unsigned int size;
};

/******************************************************************************
* Function: int thp_tee_ioctl( unsigned int cmd, unsigned int arg)
******************************************************************************
* @summary
*   just like ioctl in linux, using THP_IOCTL_CMD_GET_FRAME to get frame.
*                                 using  THP_IOCTL_CMD_SPI_SYNC to read/write regiser
*
* @return
*   THP_AFE_ERR_ENUM
*
*****************************************************************************/
THP_AFE_ERR_ENUM thp_tee_ioctl(unsigned int cmd, unsigned int arg);

/******************************************************************************
* Function: thp_tee_Malloc
******************************************************************************
* @summary
*    malloc buferr
* @return
*   fail  NULL
*   success:buferr
*
*****************************************************************************/
void *thp_tee_Malloc(unsigned int size);

/******************************************************************************
* Function: thp_tee_Free
******************************************************************************
* @summary
*    free buferr &set buffer null
* @return
*   void
*
*****************************************************************************/
void thp_tee_Free(void *buffer);

/*****************************************************************************
* Function: thp_tee_MSleep
******************************************************************************
* @summary
*   sleep micro seconds
* @return
*
*
*****************************************************************************/
unsigned int  thp_tee_MSleep(unsigned int uwMsecs);

int thp_tee_Init();
void thp_tee_deInit();
void thp_tee_setIrq(int irq_flag);
int thp_tee_getProjectId(void* projectId);
extern int __ts_ioctl(unsigned int cmd, void *arg);
extern uint32_t __SRE_SwMsleep(uint32_t uwMsecs);
#ifdef __cplusplus
}
#endif

#endif /* __THP_AFE_DRIVER_H_  */

