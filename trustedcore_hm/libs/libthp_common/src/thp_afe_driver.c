/*
* Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
* Description: common interface file
* Author: 00481845 & l00492120 & c00414356
* Create: 2017-01-20
* Notes: this file's api is for TP driver interface
*/
#include "thp_afe_driver.h"
#include "tee_time_api.h"
#include "tee_log.h"
#include "tee_mem_mgmt_api.h" /* TEE_Malloc */
/***********************************************************
*  NOTICE: any change should kee align with platform_touchscreen.h
************************************************************/
/* buff size */
#define MAX_FRAME_LEN   4096
#define MAX_REG_LEN     2048
#define TS_GET_FRAME    0x1
#define TS_SPI_SYNC     0x2
#define TS_IRQ_CTL      0x3
#define TS_GET_PRO_ID   0x4

struct ts_frame_data {
    unsigned int size;
    char  buf[MAX_FRAME_LEN];
};
struct ts_reg_data {
    unsigned int size;
    char  txbuf[MAX_REG_LEN];
    char  rxbuf[MAX_REG_LEN];
};
struct ts_info {
    union  __ts_ioctl_data {
        struct ts_frame_data ts_frame_info;
        struct ts_reg_data  reg_data;
        char project_id[THP_PROJECT_ID_LEN + 1];
    } ts_ioctl_data;
    unsigned char reserved;
};

struct ts_info* g_tsa_info = NULL;

/******************************************************************************
* Function: int thp_tee_getFrame( struct thp_ioctl_get_frame_data *pFramedata)
******************************************************************************
* @summary
*   get frame data from kernel
*
* @return
*   THP_AFE_ERR_ENUM
*
*****************************************************************************/
THP_AFE_ERR_ENUM thp_tee_getFrame(struct thp_ioctl_get_frame_data* pFramedata)
{
    unsigned int ret;
    struct ts_frame_data* pstFrame = NULL;
    TEE_Time time;
    struct timeval* pstTime = NULL;

    if ((pFramedata == NULL) || (g_tsa_info == NULL))
        return THP_AFE_ENOMEM;

    if (pFramedata->buf == NULL)
        return THP_AFE_ENOMEM;

    pstFrame = &g_tsa_info->ts_ioctl_data.ts_frame_info;
    pstFrame->size = pFramedata->size;
    ret = __ts_ioctl(TS_GET_FRAME, (void*)g_tsa_info);
    if (ret != 0)
        return THP_AFE_EDATA;

    ret = memcpy_s(pFramedata->buf, pstFrame->size, pstFrame->buf, pstFrame->size);
    if (ret != EOK)
        return THP_AFE_EDATA;

    if (pFramedata->tv != NULL) {
        TEE_GetSystemTime(&time);
        pstTime = (struct timeval*)pFramedata->tv;
        pstTime->tv_sec = time.seconds;
        pstTime->tv_usec = time.millis * 1000;
    }
    return THP_AFE_OK;
}
/******************************************************************************
* Function: int thp_tee_spiSync(  struct thp_ioctl_spi_sync_data *pSpiSyncdata)
******************************************************************************
* @summary
*  read/write  data from IC
*
* @return
*   THP_AFE_ERR_ENUM
*
*****************************************************************************/
THP_AFE_ERR_ENUM thp_tee_spiSync(struct thp_ioctl_spi_sync_data* pSpiSyncdata)
{
    unsigned int ret;
    struct ts_reg_data* pstSpiTransfer = NULL;
    if ((pSpiSyncdata == NULL) || (g_tsa_info == NULL))
        return THP_AFE_ENOMEM;

    pstSpiTransfer = &g_tsa_info->ts_ioctl_data.reg_data;
    pstSpiTransfer->size = pSpiSyncdata->size;

    if (pstSpiTransfer->size > MAX_REG_LEN)
        return THP_AFE_ENOMEM;

    if ((pSpiSyncdata->tx == NULL) && (pSpiSyncdata->rx == NULL))
        return THP_AFE_ENOMEM;

    if (pSpiSyncdata->tx != NULL) {
        ret = memcpy_s((void*)pstSpiTransfer->txbuf, pstSpiTransfer->size, pSpiSyncdata->tx, pstSpiTransfer->size);
        if(ret != EOK)
            return THP_AFE_EDATA;
    }

    ret = __ts_ioctl(TS_SPI_SYNC, (void*)g_tsa_info);
    if (ret != 0)
        return THP_AFE_EDATA;

    if (pSpiSyncdata->rx != NULL) {
        ret = memcpy_s((void*)pSpiSyncdata->rx, pstSpiTransfer->size,
                       (void*)pstSpiTransfer->rxbuf, pstSpiTransfer->size);
        if(ret != EOK)
            return THP_AFE_EDATA;
    }
    return THP_AFE_OK;
}

/******************************************************************************
* Function: int thp_tee_ioctl( unsigned int cmd, unsigned int arg)
******************************************************************************
* @summary
*   just like ioctl in linux, using THP_IOCTL_CMD_GET_FRAME to get frame.
*                             using THP_IOCTL_CMD_SPI_SYNC to read/write regiser
*
* @return
*   THP_AFE_ERR_ENUM
*
*****************************************************************************/
THP_AFE_ERR_ENUM thp_tee_ioctl(unsigned int cmd, unsigned int arg)
{
    THP_AFE_ERR_ENUM ret = THP_AFE_OK;
    void* argp = (void*)(uintptr_t)arg;

    switch (cmd) {
    case THP_IOCTL_CMD_GET_FRAME:
        ret = thp_tee_getFrame((struct thp_ioctl_get_frame_data*)argp);
        break;
    case THP_IOCTL_CMD_SPI_SYNC:
        ret = thp_tee_spiSync((struct thp_ioctl_spi_sync_data*)argp);
        break;
    default:
        break;
    }
    return ret;
}

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
void* thp_tee_Malloc(unsigned int size)
{
    return TEE_Malloc(size, 0);
}
/******************************************************************************
* Function: thp_tee_Free
******************************************************************************
* @summary
*    free buferr &set buffer null
* @return
*   void
*
*****************************************************************************/
void thp_tee_Free(void* buffer)
{
    if (buffer == NULL)
        return;

    TEE_Free(buffer);
    buffer = NULL;
    return;
}

/*****************************************************************************
 * Function: thp_tee_MemSet
 ******************************************************************************
 * @summary
 *    like memset with c lib
 * @return
 *   void
 *
 *****************************************************************************/
void thp_tee_MemSet(void* buffer, unsigned int x, unsigned int size)
{
    if (buffer == NULL)
        return;
    TEE_MemFill(buffer, x, size);
    return;
}

/*****************************************************************************
 * Function: thp_tee_MemCpy
 ******************************************************************************
 * @summary
 *    like memcpy with c lib
 * @return
 *   void
 *
 *****************************************************************************/
void thp_tee_MemCpy(void* dest, void* src, unsigned int size)
{
    if ((dest == NULL) || (src == NULL))
        return;
    TEE_MemMove(dest, src, size);
    return;
}

/*****************************************************************************
* Function: thp_tee_MSleep
******************************************************************************
* @summary
*   sleep micro seconds
* @return
*
*
*****************************************************************************/
unsigned int thp_tee_MSleep(unsigned int uwMsecs)
{
    return __SRE_SwMsleep(uwMsecs);
}

/*****************************************************************************
* Function: func
******************************************************************************
* @summary
*   sleep micro seconds
* @return
*
*
*****************************************************************************/
int thp_tee_Init()
{
    g_tsa_info = (struct ts_info*)TEE_Malloc(sizeof(struct ts_info), 0);
    if (g_tsa_info == NULL) {
        tloge("in thp_tee_Init g_tsa_info is null");
        return -ENOBUFS;
    }

    (void)memset_s(g_tsa_info, sizeof(struct ts_info), 0, sizeof(struct ts_info));
    return 0;
}

void thp_tee_deInit()
{
    if (g_tsa_info != NULL)
        TEE_Free(g_tsa_info);
    g_tsa_info = NULL;
}

void thp_tee_setIrq(int irq_flag)
{
    if (g_tsa_info == NULL) {
        tloge("Failed to alloc mem for info!\n");
        return;
    }

    int ret;
    g_tsa_info->reserved = irq_flag;
    /* set irq */
    ret = __ts_ioctl(TS_IRQ_CTL, (void*)g_tsa_info);
    (void)ret;
    tlogi("set irq ret = %d, value =%d!\n", ret, irq_flag);
}

int thp_tee_getProjectId(void* projectId)
{
    if (projectId == NULL) {
        tloge("The project is NULL !!");
        return -ENOBUFS;
    }
    __ts_ioctl(TS_GET_PRO_ID, (void*)g_tsa_info);
    int ret = memcpy_s(projectId, THP_PROJECT_ID_LEN, g_tsa_info->ts_ioctl_data.project_id, THP_PROJECT_ID_LEN);
    if (ret != EOK)
        return -ENOBUFS;
    return 0;
}
