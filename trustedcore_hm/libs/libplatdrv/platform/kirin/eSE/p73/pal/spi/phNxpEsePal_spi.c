/******************************************************************************
 *
 *  Copyright 2018-2019 NXP
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/

/*
 * DAL spi port implementation for linux
 *
 * Project: Trusted ESE Linux
 *
 */

#include "phNxpEsePal_spi.h"

#ifdef LOG_TAG
#undef LOG_TAG
#define LOG_TAG "NxpEseHal"
#endif

#include "../../../spi/spi.h"
#include "../common/include/gpio.h"
#include <errno.h>
#include <sre_sys.h>
#include "mem_page_ops.h"
#include <legacy_mem_ext.h>
#include <sre_typedef.h>
#include <mem_ops.h>
#include <memory.h>
#include "sre_task.h"
#include "boot_sharedmem.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <ese_config_hisi.h>
#include <phEseStatus.h>
#include <phNxpEsePal.h>
#include <phNxpEsePal_spi.h>
#include <string.h>
#include "phNxpEse_Api.h"
#include "p73.h"

#define MAX_RETRY_CNT 10
#define HAL_NFC_SPI_DWP_SYNC 21

extern int omapi_status;

unsigned long int configNum1, configNum2, cold_reset_intf;
unsigned int gpio_spi_cs;
//unsigned int spi_bus_addr = 0;


/*******************************************************************************
**
** Function         phPalEse_spi_close
**
** Description      Closes PN547 device
**
** Parameters       pDevHandle - device handle
**
** Returns          None
**
*******************************************************************************/
ESESTATUS phPalEse_spi_close(void* pDevHandle) {
    (void)pDevHandle;
    return ESESTATUS_SUCCESS;
}

/*******************************************************************************
**
** Function         phNxpEse_spiIoctl
**
** Description      Perform cross HAL IOCTL functionality
**
** Parameters       ioctlType, input data
**
** Returns          SUCCESS/FAIL
**
*******************************************************************************/
ESESTATUS phNxpEse_spiIoctl(uint64_t ioctlType, void* p_data) {
    (void)p_data;
    (void)ioctlType;
    return ESESTATUS_SUCCESS;
}

/*******************************************************************************
**
** Function         phPalEse_spi_open_and_configure
**
** Description      Open and configure pn547 device
**
** Parameters       pConfig     - hardware information
**                  pLinkHandle - device handle
**
** Returns          ESE status:
**                  ESESTATUS_SUCCESS            - open_and_configure operation
*success
**                  ESESTATUS_INVALID_DEVICE     - device open operation failure
**
*******************************************************************************/
ESESTATUS phPalEse_spi_open_and_configure(pphPalEse_Config_t pConfig) {
  (void)pConfig;
  p73_load_config();
  return ESESTATUS_SUCCESS;
}

/*******************************************************************************
**
** Function         phPalEse_spi_read
**
** Description      Reads requested number of bytes from pn547 device into given
*buffer
**
** Parameters       pDevHandle       - valid device handle
**                  pBuffer          - buffer for read data
**                  nNbBytesToRead   - number of bytes requested to be read
**
** Returns          numRead   - number of successfully read bytes
**                  -1        - read operation failure
**
*******************************************************************************/
int phPalEse_spi_read(void* pDevHandle, uint8_t* pBuffer, int nNbBytesToRead) {

    int count;
    (void)pDevHandle;
    HISI_PRINT_DEBUG("receive -Enter\n");
    count = p61_dev_read((char *)pBuffer, nNbBytesToRead);
    if (count <= 0) {
        HISI_PRINT_ERROR("ERROR:Failed to receive data from device\n");
        return -1;
    }

    HISI_PRINT_DEBUG("receive -Exit\n");

    return count;

}

/*******************************************************************************
**
** Function         phPalEse_spi_write
**
** Description      Writes requested number of bytes from given buffer into
*pn547 device
**
** Parameters       pDevHandle       - valid device handle
**                  pBuffer          - buffer for read data
**                  nNbBytesToWrite  - number of bytes requested to be written
**
** Returns          numWrote   - number of successfully written bytes
**                  -1         - write operation failure
**
*******************************************************************************/
int phPalEse_spi_write(void* pDevHandle, uint8_t* pBuffer,
                       int nNbBytesToWrite) {
    int count = 0;
    (void)pDevHandle;
    HISI_PRINT_DEBUG("send - Enter\n");

    // call to the spi bird wrapper
    count = p61_dev_write((char *)pBuffer, nNbBytesToWrite);
    if (count == 0) {
        HISI_PRINT_ERROR("ERROR:Failed to send data to device\n");
        return -1;
    }
    return count;
}

/*******************************************************************************
**
** Function         phPalEse_spi_ioctl
**
** Description      Exposed ioctl by p61 spi driver
**
** Parameters       pDevHandle     - valid device handle
**                  level          - reset level
**
** Returns           0   - ioctl operation success
**                  -1   - ioctl operation failure
**
*******************************************************************************/
ESESTATUS phPalEse_spi_ioctl(phPalEse_ControlCode_t eControlCode,
                             void* pDevHandle, long level) {
    (void)eControlCode;
    (void)pDevHandle;
    (void)level;
    return ESESTATUS_SUCCESS;
}

