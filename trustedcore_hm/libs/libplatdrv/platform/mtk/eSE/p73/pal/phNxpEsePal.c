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
#define LOG_TAG "NxpEseHal"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <phEseStatus.h>
#include <ese_config_hisi.h>
#include <phNxpEsePal_spi.h>
#include <string.h>
#include <log_hisi.h>
#include "tee_log.h"
#include <sys/time.h>
#include <time.h>

/*!
 * \brief Normal mode header length
 */
#define NORMAL_MODE_HEADER_LEN 3
/*!
 * \brief Normal mode header offset
 */
#define NORMAL_MODE_LEN_OFFSET 2
/*!
 * \brief Start of frame marker
 */
#define SEND_PACKET_SOF 0x5A
/*!
 * \brief To enable SPI interface for ESE communication
 */
#define SPI_ENABLED 1

#define USECS_PER_SEC (1000 * 1000)
#define NSECS_PER_USEC 1000

/*******************************************************************************
**
** Function         phPalEse_close
**
** Description      Closes PN547 device
**
** Parameters       pDevHandle - device handle
**
** Returns          None
**
*******************************************************************************/
void phPalEse_close(void* pDevHandle) {
  if (NULL != pDevHandle) {
#ifdef SPI_ENABLED
    phPalEse_spi_close(pDevHandle);
#else
/* RFU */
#endif
  }
  return;
}

/*******************************************************************************
**
** Function         phPalEse_open_and_configure
**
** Description      Open and configure ESE device
**
** Parameters       pConfig     - hardware information
**
** Returns          ESE status:
**                  ESESTATUS_SUCCESS            - open_and_configure operation
*success
**                  ESESTATUS_INVALID_DEVICE     - device open operation failure
**
*******************************************************************************/
ESESTATUS phPalEse_open_and_configure(pphPalEse_Config_t pConfig) {
  ESESTATUS status = ESESTATUS_FAILED;
#ifdef SPI_ENABLED
  status = phPalEse_spi_open_and_configure(pConfig);
#else
/* RFU */
#endif
  return status;
}

/*******************************************************************************
**
** Function         phPalEse_read
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
int phPalEse_read(void* pDevHandle, uint8_t* pBuffer, int nNbBytesToRead) {
  int ret = -1;
#ifdef SPI_ENABLED
  ret = phPalEse_spi_read(pDevHandle, pBuffer, nNbBytesToRead);
#else
/* RFU */
#endif
  return ret;
}

/*******************************************************************************
**
** Function         phPalEse_write
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
int phPalEse_write(void* pDevHandle, uint8_t* pBuffer, int nNbBytesToWrite) {
  int numWrote = 0;
  tloge("phPalEse_write, pDevHandle 0x%x", pDevHandle);

  if (NULL == pDevHandle) {
    tloge("phPalEse_write NULL == pDevHandle");
    //return -1;
  }
#ifdef SPI_ENABLED
  numWrote = phPalEse_spi_write(pDevHandle, pBuffer, nNbBytesToWrite);
#else
/* RFU */
#endif
  return numWrote;
}

/*******************************************************************************
**
** Function         phPalEse_ioctl
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
ESESTATUS phPalEse_ioctl(phPalEse_ControlCode_t eControlCode, void* pDevHandle,
                   long level) {
  ESESTATUS ret = ESESTATUS_FAILED;
  tloge("phPalEse_spi_ioctl(), ioctl %x , level %lx",
           eControlCode, level);
#ifdef SPI_ENABLED
  ret = phPalEse_spi_ioctl(eControlCode, pDevHandle, level);
#else
/* RFU */
#endif
  return ret;
}

/*******************************************************************************
**
** Function         phPalEse_print_packet
**
** Description      Print packet
**
** Returns          None
**
*******************************************************************************/
void phPalEse_print_packet(const char* pString, const uint8_t* p_data,
                           uint16_t len) {
  uint32_t i;
  char print_buffer[len * 3 + 1];
    int nciBufLen;

  memset(print_buffer, 0, sizeof(print_buffer));
  for (i = 0; i < len; i++) {
    snprintf(&print_buffer[i * 2], 3, "%02X", p_data[i]);
  }
  if (memcmp(pString, "SEND", 0x04) == 0) {
    tloge("NxpEseDataX len = %3d > %s", len, print_buffer);
  } else if (memcmp(pString, "RECV", 0x04) == 0) {
        nciBufLen = strlen(print_buffer);
        if ((nciBufLen > 18) && // cplc len is more then 18
            (p_data[3] == 0x9F && p_data[4] == 0x7F)) { // p_data 3 byte cmp 9F, p_data 4 byte cmp 7F
            tloge("NxpEseDataR len = %3d > is cplc \n", len);
            return;
        } else {
            tloge("NxpEseDataR len = %3d > %s", len, print_buffer);
        }
  }
  return;
}

/*******************************************************************************
**
** Function         phPalEse_sleep
**
** Description      This function  suspends execution of the calling thread for
**                  (at least) usec microseconds
**
** Returns          None
**
*******************************************************************************/
void phPalEse_sleep(long usec) {
  struct timespec ts;
  int err;
  ts.tv_sec = (usec / USECS_PER_SEC);                      // transfor usec to second
  ts.tv_nsec = (usec % USECS_PER_SEC) * NSECS_PER_USEC;    // transfor usec to nanosecond
  do {
      err = nanosleep(&ts, &ts);
  } while (err < 0 && errno == EINTR);
}

/*******************************************************************************
**
** Function         phPalEse_memset
**
** Description
**
** Returns          None
**
*******************************************************************************/
void* phPalEse_memset(void* buff, int val, unsigned int len) {
  return memset(buff, val, len);
}

/*******************************************************************************
**
** Function         phPalEse_memcpy
**
** Description
**
** Returns          None
**
*******************************************************************************/
void* phPalEse_memcpy(void* dest, const void* src, unsigned int len) {
  return memcpy(dest, src, len);
}

/*******************************************************************************
**
** Function         phPalEse_memalloc
**
** Description
**
** Returns          None
**
*******************************************************************************/
void* phPalEse_memalloc(uint32_t size) { return malloc(size); }

/*******************************************************************************
**
** Function         phPalEse_calloc
**
** Description
**
** Returns          None
**
*******************************************************************************/
void* phPalEse_calloc(unsigned int datatype, unsigned int size) {
  return calloc(datatype, size);
}

/*******************************************************************************
**
** Function         phPalEse_free
**
** Description
**
** Returns          None
**
*******************************************************************************/
void phPalEse_free(void* ptr) {
  if (ptr != NULL) {
    free(ptr);
    ptr = NULL;
  }
  return;
}
