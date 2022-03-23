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
#include <hm_unistd.h>
#include <securec.h>
#include <stdlib.h>
#include <phNxpEseFeatures.h>

#include <phNxpEsePal.h>
#include <phNxpEsePal_spi.h>
#include <phNxpEseProto7816_3_p61.h>
#include <phNxpEse_Internal_p61.h>
#include "tee_log.h"

#define RECIEVE_PACKET_SOF 0xA5
#define PH_PAL_ESE_PRINT_PACKET_TX(data, len) \
  ({ phPalEse_print_packet("SEND", data, len); })
#define PH_PAL_ESE_PRINT_PACKET_RX(data, len) \
  ({ phPalEse_print_packet("RECV", data, len); })
static int phNxpEse_readPacket(void* pDevHandle, uint8_t* pBuffer,
                               int nNbBytesToRead);
#if (NXP_NFCC_SPI_FW_DOWNLOAD_SYNC == true)
static ESESTATUS phNxpEse_checkFWDwnldStatus(void);
#endif
void phNxpEse_GetMaxTimer(unsigned long *pMaxTimer);
#if (NXP_SECURE_TIMER_SESSION == true)
static unsigned char* phNxpEse_GgetTimerTlvBuffer(unsigned char* timer_buffer,
                                                  unsigned int value);
#endif
/*********************** Global Variables *************************************/

/* ESE Context structure */
phNxpEse_Context_t nxpese_ctxt_p61;

/******************************************************************************
 * Function         phNxpLog_InitializeLogLevel_p61
 *
 * Description      This function is called during phNxpEse_init_p61 to initialize
 *                  debug log level.
 *
 * Returns          None
 *
 ******************************************************************************/

void phNxpLog_InitializeLogLevel_p61() {
  return;
}

/******************************************************************************
 * Function         phNxpEse_init_p61
 *
 * Description      This function is called by Jni/phNxpEse_open_p61 during the
 *                  initialization of the ESE. It initializes protocol stack
 *instance variable
 *
 * Returns          This function return ESESTATUS_SUCCES (0) in case of success
 *                  In case of failure returns other failure value.
 *
 ******************************************************************************/
ESESTATUS phNxpEse_init_p61(phNxpEse_initParams_p61 initParams) {
  ESESTATUS wConfigStatus = ESESTATUS_FAILED;
  unsigned long int num;
  unsigned long maxTimer = 0;
  phNxpEseProto7816InitParam_t protoInitParam;
  phNxpEse_memset_p61(&protoInitParam, 0x00, sizeof(phNxpEseProto7816InitParam_t));
  /* STATUS_OPEN */
  nxpese_ctxt_p61.EseLibStatus = ESE_STATUS_OPEN;

  if (EseConfig_hasKey(NAME_NXP_WTX_COUNT_VALUE)) {
    num = EseConfig_getUnsigned(NAME_NXP_WTX_COUNT_VALUE);
    protoInitParam.wtx_counter_limit = num;
  } else {
    protoInitParam.wtx_counter_limit = PH_PROTO_WTX_DEFAULT_COUNT;
  }
  if (EseConfig_hasKey(NAME_NXP_MAX_RNACK_RETRY)) {
    protoInitParam.rnack_retry_limit =
        EseConfig_getUnsigned(NAME_NXP_MAX_RNACK_RETRY);
  } else {
    protoInitParam.rnack_retry_limit = MAX_RNACK_RETRY_LIMIT;
  }
  if (P61_ESE_MODE_NORMAL ==
      initParams.initMode) /* TZ/Normal wired mode should come here*/
  {
    if (EseConfig_hasKey(NAME_NXP_SPI_INTF_RST_ENABLE)) {
      protoInitParam.interfaceReset =
          (EseConfig_getUnsigned(NAME_NXP_SPI_INTF_RST_ENABLE) == 1) ? true
                                                                      : false;
    } else {
      protoInitParam.interfaceReset = true;
    }
  } else /* OSU mode, no interface reset is required */
  {
    protoInitParam.interfaceReset = false;
  }
  /* Sharing lib context for fetching secure timer values */
  protoInitParam.pSecureTimerParams =
      (phNxpEseProto7816SecureTimer_t*)&nxpese_ctxt_p61.secureTimerParams;

  phNxpEse_GetMaxTimer(&maxTimer);

  /* T=1 Protocol layer open */
  wConfigStatus = phNxpEseProto7816_Open_p61(protoInitParam);
  if ((ESESTATUS_FAILED == wConfigStatus) ||
      (ESESTATUS_WRITE_FAILED == wConfigStatus) ||
      (ESESTATUS_READ_FAILED == wConfigStatus)) {
    wConfigStatus = ESESTATUS_FAILED;
    tloge("phNxpEseProto7816_Open_p61 failed");
    if (ESESTATUS_SUCCESS == phNxpEse_close_p61()) {
      tloge("phNxpEse Close was success");
    }
  }
  return wConfigStatus;
}

/******************************************************************************
 * Function         phNxpEse_open_p61
 *
 * Description      This function is called by Jni during the
 *                  initialization of the ESE. It opens the physical connection
 *                  with ESE and creates required client thread for
 *                  operation.
 * Returns          This function return ESESTATUS_SUCCES (0) in case of success
 *                  In case of failure returns other failure value.
 *
 ******************************************************************************/
ESESTATUS phNxpEse_open_p61(phNxpEse_initParams_p61 initParams) {
  phPalEse_Config_t tPalConfig;
  ESESTATUS wConfigStatus = ESESTATUS_SUCCESS;
  unsigned long int tpm_enable = 0;
  char ese_dev_node[64];
  //std::string ese_node;
#ifdef SPM_INTEGRATED
  ESESTATUS wSpmStatus = ESESTATUS_SUCCESS;
  spm_state_t current_spm_state = SPM_STATE_INVALID;
#endif

  (void)initParams;
  tloge("%s: Proceed with open...", __FUNCTION__);
  /*When spi channel is already opened return status as FAILED*/
  if (nxpese_ctxt_p61.EseLibStatus != ESE_STATUS_CLOSE) {
    tloge("already opened\n");
    return ESESTATUS_BUSY;
  }

  phNxpEse_memset_p61(&nxpese_ctxt_p61, 0x00, sizeof(nxpese_ctxt_p61));
  phNxpEse_memset_p61(&tPalConfig, 0x00, sizeof(tPalConfig));


  if (EseConfig_hasKey(NAME_NXP_TP_MEASUREMENT)) {
    tpm_enable = EseConfig_getUnsigned(NAME_NXP_TP_MEASUREMENT);
  } else {
    tloge("SPI Throughput not defined in config file - %lu", tpm_enable);
  }
#if (NXP_POWER_SCHEME_SUPPORT == true)
  unsigned long int num = 0;
  if (EseConfig_hasKey(NAME_NXP_POWER_SCHEME)) {
    num = EseConfig_getUnsigned(NAME_NXP_POWER_SCHEME);
    nxpese_ctxt_p61.pwr_scheme = num;
  } else {
    nxpese_ctxt_p61.pwr_scheme = PN67T_POWER_SCHEME;
    tloge("Power scheme not defined in config file - %lu", num);
  }
#else
  nxpese_ctxt_p61.pwr_scheme = PN67T_POWER_SCHEME;
  tpm_enable = 0x00;
#endif
  /* initialize trace level */
  phNxpLog_InitializeLogLevel_p61();

  /*Read device node path*/
  strcpy(ese_dev_node, "/dev/pn81a");
  tPalConfig.pDevName = (int8_t*)ese_dev_node;

  /* Initialize PAL layer */
  wConfigStatus = phPalEse_open_and_configure(&tPalConfig);
  if (wConfigStatus != ESESTATUS_SUCCESS) {
    tloge("phPalEse_Init Failed");
    goto clean_and_return;
  }

  /* Copying device handle to ESE Lib context*/
  nxpese_ctxt_p61.pDevHandle = tPalConfig.pDevHandle;

#ifdef SPM_INTEGRATED
  /* Get the Access of ESE*/
  wSpmStatus = phNxpEse_SPM_Init(nxpese_ctxt_p61.pDevHandle);
  if (wSpmStatus != ESESTATUS_SUCCESS) {
    tloge("phNxpEse_SPM_Init Failed");
    wConfigStatus = ESESTATUS_FAILED;
    goto clean_and_return_2;
  }
  wSpmStatus = phNxpEse_SPM_SetPwrScheme(nxpese_ctxt_p61.pwr_scheme);
  if (wSpmStatus != ESESTATUS_SUCCESS) {
    tloge(" %s : phNxpEse_SPM_SetPwrScheme Failed", __FUNCTION__);
    wConfigStatus = ESESTATUS_FAILED;
    goto clean_and_return_1;
  }
#if (NXP_NFCC_SPI_FW_DOWNLOAD_SYNC == true)
  wConfigStatus = phNxpEse_checkFWDwnldStatus();
  if (wConfigStatus != ESESTATUS_SUCCESS) {
    tloge(
             "Failed to open SPI due to VEN pin used by FW download \n");
    wConfigStatus = ESESTATUS_FAILED;
    goto clean_and_return_1;
  }
#endif
  wSpmStatus = phNxpEse_SPM_GetState(&current_spm_state);
  if (wSpmStatus != ESESTATUS_SUCCESS) {
    tloge(" %s : phNxpEse_SPM_GetPwrState Failed", __FUNCTION__);
    wConfigStatus = ESESTATUS_FAILED;
    goto clean_and_return_1;
  } else {
    if (((current_spm_state & SPM_STATE_SPI) |
        (current_spm_state & SPM_STATE_SPI_PRIO)) &&
        !(current_spm_state & SPM_STATE_SPI_FAILED)) {
      tloge(" %s : SPI is already opened...second instance not allowed",
            __FUNCTION__);
      wConfigStatus = ESESTATUS_FAILED;
      goto clean_and_return_1;
    }
  }
#if (NXP_ESE_JCOP_DWNLD_PROTECTION == true)
  if (current_spm_state & SPM_STATE_JCOP_DWNLD) {
    tloge(" %s : Denying to open JCOP Download in progress", __FUNCTION__);
    wConfigStatus = ESESTATUS_FAILED;
    goto clean_and_return_1;
  }
#endif
  phNxpEse_memcpy_p61(&nxpese_ctxt_p61.initParams, &initParams,
                  sizeof(phNxpEse_initParams_p61));
  wSpmStatus = phNxpEse_SPM_ConfigPwr(SPM_POWER_ENABLE);
  if (wSpmStatus != ESESTATUS_SUCCESS) {
    tloge("phNxpEse_SPM_ConfigPwr: enabling power Failed");
    if (wSpmStatus == ESESTATUS_BUSY) {
      wConfigStatus = ESESTATUS_BUSY;
    } else if (wSpmStatus == ESESTATUS_DWNLD_BUSY) {
      wConfigStatus = ESESTATUS_DWNLD_BUSY;
    } else {
      wConfigStatus = ESESTATUS_FAILED;
    }
    goto clean_and_return;
  } else {
    tloge("nxpese_ctxt_p61.spm_power_state true");
    nxpese_ctxt_p61.spm_power_state = true;
  }
#endif

  tloge("wConfigStatus %x", wConfigStatus);
  return wConfigStatus;

clean_and_return:
#ifdef SPM_INTEGRATED
  wSpmStatus = phNxpEse_SPM_ConfigPwr(SPM_POWER_DISABLE);
  if (wSpmStatus != ESESTATUS_SUCCESS) {
    tloge("phNxpEse_SPM_ConfigPwr: disabling power Failed wConfigStatus %x", wSpmStatus);
  }
clean_and_return_1:
  phNxpEse_SPM_DeInit();
clean_and_return_2:
#endif
  if (NULL != nxpese_ctxt_p61.pDevHandle) {
    phPalEse_close(nxpese_ctxt_p61.pDevHandle);
    phNxpEse_memset_p61(&nxpese_ctxt_p61, 0x00, sizeof(nxpese_ctxt_p61));
  }
  nxpese_ctxt_p61.EseLibStatus = ESE_STATUS_CLOSE;
  nxpese_ctxt_p61.spm_power_state = false;
  return ESESTATUS_FAILED;
}

/******************************************************************************
 * \ingroup spi_libese
 *
 * \brief  Check if libese has opened
 *
 * \retval return false if it is close, otherwise true.
 *
 ******************************************************************************/
bool phNxpEse_isOpen_p61() { return nxpese_ctxt_p61.EseLibStatus != ESE_STATUS_CLOSE; }

/******************************************************************************
 * Function         phNxpEse_openPrioSession_p61
 *
 * Description      This function is called by Jni during the
 *                  initialization of the ESE. It opens the physical connection
 *                  with ESE () and creates required client thread for
 *                  operation.  This will get priority access to ESE for timeout
 duration.

 * Returns          This function return ESESTATUS_SUCCES (0) in case of success
 *                  In case of failure returns other failure value.
 *
 ******************************************************************************/
ESESTATUS phNxpEse_openPrioSession_p61(phNxpEse_initParams_p61 initParams) {
  phPalEse_Config_t tPalConfig;
  ESESTATUS wConfigStatus = ESESTATUS_SUCCESS;
  unsigned long int num = 0;

  (void)initParams;

#ifdef SPM_INTEGRATED
  ESESTATUS wSpmStatus = ESESTATUS_SUCCESS;
  spm_state_t current_spm_state = SPM_STATE_INVALID;
#endif
  phNxpEse_memset_p61(&nxpese_ctxt_p61, 0x00, sizeof(nxpese_ctxt_p61));
  phNxpEse_memset_p61(&tPalConfig, 0x00, sizeof(tPalConfig));


#if (NXP_POWER_SCHEME_SUPPORT == true)
  if (EseConfig_hasKey(NAME_NXP_POWER_SCHEME)) {
    num = EseConfig_getUnsigned(NAME_NXP_POWER_SCHEME);
    nxpese_ctxt_p61.pwr_scheme = num;
  } else
#endif
  {
    nxpese_ctxt_p61.pwr_scheme = PN67T_POWER_SCHEME;
    tloge("Power scheme not defined in config file - %lu", num);
  }
  if (EseConfig_hasKey(NAME_NXP_TP_MEASUREMENT)) {
    num = EseConfig_getUnsigned(NAME_NXP_TP_MEASUREMENT);
  } else {
    tloge("SPI Throughput not defined in config file - %lu", num);
  }
  /* initialize trace level */
  phNxpLog_InitializeLogLevel_p61();

  tPalConfig.pDevName = (int8_t*)"/dev/p73";

  /* Initialize PAL layer */
  wConfigStatus = phPalEse_open_and_configure(&tPalConfig);
  if (wConfigStatus != ESESTATUS_SUCCESS) {
    tloge("phPalEse_Init Failed");
    goto clean_and_return;
  }
  /* Copying device handle to hal context*/
  nxpese_ctxt_p61.pDevHandle = tPalConfig.pDevHandle;

#ifdef SPM_INTEGRATED
  /* Get the Access of ESE*/
  wSpmStatus = phNxpEse_SPM_Init(nxpese_ctxt_p61.pDevHandle);
  if (wSpmStatus != ESESTATUS_SUCCESS) {
    tloge("phNxpEse_SPM_Init Failed");
    wConfigStatus = ESESTATUS_FAILED;
    goto clean_and_return_2;
  }
  wSpmStatus = phNxpEse_SPM_SetPwrScheme(nxpese_ctxt_p61.pwr_scheme);
  if (wSpmStatus != ESESTATUS_SUCCESS) {
    tloge(" %s : phNxpEse_SPM_SetPwrScheme Failed", __FUNCTION__);
    wConfigStatus = ESESTATUS_FAILED;
    goto clean_and_return_1;
  }
  wSpmStatus = phNxpEse_SPM_GetState(&current_spm_state);
  if (wSpmStatus != ESESTATUS_SUCCESS) {
    tloge(" %s : phNxpEse_SPM_GetPwrState Failed", __FUNCTION__);
    wConfigStatus = ESESTATUS_FAILED;
    goto clean_and_return_1;
  } else {
    if ((current_spm_state & SPM_STATE_SPI) |
        (current_spm_state & SPM_STATE_SPI_PRIO)) {
      tloge(" %s : SPI is already opened...second instance not allowed",
            __FUNCTION__);
      wConfigStatus = ESESTATUS_FAILED;
      goto clean_and_return_1;
    }
#if (NXP_ESE_JCOP_DWNLD_PROTECTION == true)
    if (current_spm_state & SPM_STATE_JCOP_DWNLD) {
      tloge(" %s : Denying to open JCOP Download in progress", __FUNCTION__);
      wConfigStatus = ESESTATUS_FAILED;
      goto clean_and_return_1;
    }
#endif
#if (NXP_NFCC_SPI_FW_DOWNLOAD_SYNC == true)
    wConfigStatus = phNxpEse_checkFWDwnldStatus();
    if (wConfigStatus != ESESTATUS_SUCCESS) {
      tloge(
               "Failed to open SPI due to VEN pin used by FW download \n");
      wConfigStatus = ESESTATUS_FAILED;
      goto clean_and_return_1;
    }
#endif
  }
  phNxpEse_memcpy_p61(&nxpese_ctxt_p61.initParams, &initParams.initMode,
                  sizeof(phNxpEse_initParams_p61));
  wSpmStatus = phNxpEse_SPM_ConfigPwr(SPM_POWER_PRIO_ENABLE);
  if (wSpmStatus != ESESTATUS_SUCCESS) {
    tloge("phNxpEse_SPM_ConfigPwr: enabling power for spi prio Failed wConfigStatus %x", wConfigStatus);
    if (wSpmStatus == ESESTATUS_BUSY) {
      wConfigStatus = ESESTATUS_BUSY;
    } else if (wSpmStatus == ESESTATUS_DWNLD_BUSY) {
      wConfigStatus = ESESTATUS_DWNLD_BUSY;
    } else {
      wConfigStatus = ESESTATUS_FAILED;
    }
    goto clean_and_return;
  } else {
    nxpese_ctxt_p61.spm_power_state = true;
  }
#endif

#ifndef SPM_INTEGRATED
  wConfigStatus =
      phPalEse_ioctl(phPalEse_e_ResetDevice, nxpese_ctxt_p61.pDevHandle, 2);
  if (wConfigStatus != ESESTATUS_SUCCESS) {
    tloge("phPalEse_IoCtl Failed");
    goto clean_and_return;
  }
#endif
  wConfigStatus =
      phPalEse_ioctl(phPalEse_e_EnableLog, nxpese_ctxt_p61.pDevHandle, 0);
  if (wConfigStatus != ESESTATUS_SUCCESS) {
    tloge("phPalEse_IoCtl Failed");
    goto clean_and_return;
  }
  wConfigStatus =
      phPalEse_ioctl(phPalEse_e_EnablePollMode, nxpese_ctxt_p61.pDevHandle, 1);
  if (wConfigStatus != ESESTATUS_SUCCESS) {
    tloge("phPalEse_IoCtl Failed");
    goto clean_and_return;
  }

  return wConfigStatus;

clean_and_return:
#ifdef SPM_INTEGRATED
  wSpmStatus = phNxpEse_SPM_ConfigPwr(SPM_POWER_DISABLE);
  if (wSpmStatus != ESESTATUS_SUCCESS) {
    tloge("phNxpEse_SPM_ConfigPwr : disabling power Failed");
  }
clean_and_return_1:
  phNxpEse_SPM_DeInit();
clean_and_return_2:
#endif
  if (NULL != nxpese_ctxt_p61.pDevHandle) {
    phPalEse_close(nxpese_ctxt_p61.pDevHandle);
    phNxpEse_memset_p61(&nxpese_ctxt_p61, 0x00, sizeof(nxpese_ctxt_p61));
  }
  nxpese_ctxt_p61.EseLibStatus = ESE_STATUS_CLOSE;
  nxpese_ctxt_p61.spm_power_state = false;
  return ESESTATUS_FAILED;
}

/******************************************************************************
 * Function         phNxpEse_Transceive_p61
 *
 * Description      This function update the len and provided buffer
 *
 * Returns          On Success ESESTATUS_SUCCESS else proper error code
 *
 ******************************************************************************/
ESESTATUS phNxpEse_Transceive_p61(phNxpEse_data_p61* pCmd, phNxpEse_data_p61* pRsp) {
  ESESTATUS status = ESESTATUS_FAILED;

  if ((NULL == pCmd) || (NULL == pRsp)) return ESESTATUS_INVALID_PARAMETER;

  if ((pCmd->len == 0) || pCmd->p_data == NULL) {
    tloge(" phNxpEse_Transceive_p61 - Invalid Parameter no data\n");
    return ESESTATUS_INVALID_PARAMETER;
  } else if ((ESE_STATUS_CLOSE == nxpese_ctxt_p61.EseLibStatus)) {
    tloge(" %s ESE Not Initialized \n", __FUNCTION__);
    return ESESTATUS_NOT_INITIALISED;
  } else if ((ESE_STATUS_BUSY == nxpese_ctxt_p61.EseLibStatus)) {
    tloge(" %s ESE - BUSY \n", __FUNCTION__);
    return ESESTATUS_BUSY;
  } else {
    nxpese_ctxt_p61.EseLibStatus = ESE_STATUS_BUSY;
    status = phNxpEseProto7816_Transceive_p61((phNxpEse_data_p61*)pCmd,
                                          (phNxpEse_data_p61*)pRsp);
    if (ESESTATUS_SUCCESS != status) {
      tloge(" %s phNxpEseProto7816_Transceive_p61- Failed \n", __FUNCTION__);
    }
    nxpese_ctxt_p61.EseLibStatus = ESE_STATUS_IDLE;

    tloge(" %s Exit status 0x%x \n", __FUNCTION__,
             status);
    return status;
  }
}

/******************************************************************************
 * Function         phNxpEse_reset_p61
 *
 * Description      This function reset the ESE interface and free all
 *
 * Returns          It returns ESESTATUS_SUCCESS (0) if the operation is
 *successful else
 *                  ESESTATUS_FAILED(1)
 ******************************************************************************/
ESESTATUS phNxpEse_reset_p61(void) {
  ESESTATUS status = ESESTATUS_FAILED;
  unsigned long maxTimer = 0;
#ifdef SPM_INTEGRATED
  ESESTATUS wSpmStatus = ESESTATUS_SUCCESS;
#endif

  /* TBD : Call the ioctl to reset the ESE */
  /* Do an interface reset, don't wait to see if JCOP went through a full power
   * cycle or not */
  status = phNxpEseProto7816_IntfReset_p61(
      (phNxpEseProto7816SecureTimer_t *)&nxpese_ctxt_p61.secureTimerParams);
  if (status != ESESTATUS_SUCCESS) {
    tloge("phNxpEseProto7816_IntfReset_p61 Failed");
  }
   phNxpEse_GetMaxTimer(&maxTimer);
#ifdef SPM_INTEGRATED
#if (NXP_SECURE_TIMER_SESSION == true)
  status = phNxpEse_SPM_DisablePwrControl(maxTimer);
  if (status != ESESTATUS_SUCCESS) {
    tloge("%s phNxpEse_SPM_DisablePwrControl: failed", __FUNCTION__);
  }
#endif
  if ((nxpese_ctxt_p61.pwr_scheme == PN67T_POWER_SCHEME) ||
      (nxpese_ctxt_p61.pwr_scheme == PN80T_LEGACY_SCHEME)) {
    wSpmStatus = phNxpEse_SPM_ConfigPwr(SPM_POWER_RESET);
    if (wSpmStatus != ESESTATUS_SUCCESS) {
      tloge("phNxpEse_SPM_ConfigPwr: reset Failed");
    }
  }
#else
  /* if arg ==2 (hard reset)
   * if arg ==1 (soft reset)
   */
  status = phPalEse_ioctl(phPalEse_e_ResetDevice, nxpese_ctxt_p61.pDevHandle, 2);
  if (status != ESESTATUS_SUCCESS) {
    tloge("phNxpEse_reset_p61 Failed");
  }
#endif
   return status;
}

/******************************************************************************
 * Function         phNxpEse_resetJcopUpdate_p61
 *
 * Description      This function reset the ESE interface during JCOP Update
 *
 * Returns          It returns ESESTATUS_SUCCESS (0) if the operation is
 *successful else
 *                  ESESTATUS_FAILED(1)
 ******************************************************************************/
ESESTATUS phNxpEse_resetJcopUpdate_p61(void) {
  ESESTATUS status = ESESTATUS_FAILED;

#ifdef SPM_INTEGRATED
#if (NXP_POWER_SCHEME_SUPPORT == true)
  unsigned long int num = 0;
#endif
#endif

  /* TBD : Call the ioctl to reset the  */
  /* Reset interface after every reset irrespective of
  whether JCOP did a full power cycle or not. */
#ifdef SPM_INTEGRATED
#if (NXP_POWER_SCHEME_SUPPORT == true)
  if (EseConfig_hasKey(NAME_NXP_POWER_SCHEME)) {
    num = EseConfig_getUnsigned(NAME_NXP_POWER_SCHEME);
    if ((num == 1) || (num == 2)) {
      tloge(" %s Call Config Pwr Reset \n", __FUNCTION__);
      status = phNxpEse_SPM_ConfigPwr(SPM_POWER_RESET);
      if (status != ESESTATUS_SUCCESS) {
        tloge("phNxpEse_resetJcopUpdate_p61: reset Failed");
      }
    } else if (num == 3) {
      tloge(" %s Call eSE Chip Reset \n", __FUNCTION__);
      status = phNxpEse_chipReset_p61();
      if (status != ESESTATUS_SUCCESS) {
        tloge("phNxpEse_resetJcopUpdate_p61: chip reset Failed");
      }
    } else {
      tloge(" %s Invalid Power scheme \n", __FUNCTION__);
    }
  }
#else
  {
    status = phNxpEse_SPM_ConfigPwr(SPM_POWER_RESET);
    if (status != ESESTATUS_SUCCESS) {
      tloge("phNxpEse_SPM_ConfigPwr: reset Failed");
    }
  }
#endif
#else
  /* if arg ==2 (hard reset)
   * if arg ==1 (soft reset)
   */
  status = phPalEse_ioctl(phPalEse_e_ResetDevice, nxpese_ctxt_p61.pDevHandle, 2);
  if (status != ESESTATUS_SUCCESS) {
    tloge("phNxpEse_resetJcopUpdate_p61 Failed");
  }
#endif
  status = phNxpEseProto7816_Reset_p61();
  return status;
}
/******************************************************************************
 * Function         phNxpEse_EndOfApdu_p61
 *
 * Description      This function is used to send S-frame to indicate
 *END_OF_APDU
 *
 * Returns          It returns ESESTATUS_SUCCESS (0) if the operation is
 *successful else
 *                  ESESTATUS_FAILED(1)
 *
 ******************************************************************************/
ESESTATUS phNxpEse_EndOfApdu_p61(void) {
  ESESTATUS status = ESESTATUS_SUCCESS;
#if (NXP_ESE_END_OF_SESSION == true)
  status = phNxpEseProto7816_Close_p61(
      (phNxpEseProto7816SecureTimer_t*)&nxpese_ctxt_p61.secureTimerParams);
#endif
  return status;
}

/******************************************************************************
 * Function         phNxpEse_chipReset_p61
 *
 * Description      This function is used to reset the ESE.
 *
 * Returns          Always return ESESTATUS_SUCCESS (0).
 *
 ******************************************************************************/
ESESTATUS phNxpEse_chipReset_p61(void) {
  ESESTATUS status = ESESTATUS_FAILED;
  ESESTATUS bStatus = ESESTATUS_FAILED;
  if (nxpese_ctxt_p61.pwr_scheme == PN80T_EXT_PMU_SCHEME) {
    bStatus = phNxpEseProto7816_Reset_p61();
    if (!bStatus) {
      tloge("Inside phNxpEse_chipReset_p61, phNxpEseProto7816_Reset_p61 Failed");
    }
    status = phPalEse_ioctl(phPalEse_e_ChipRst, nxpese_ctxt_p61.pDevHandle, 6);
    if (status != ESESTATUS_SUCCESS) {
      tloge("phNxpEse_chipReset_p61  Failed");
    }
  } else {
    tloge("phNxpEse_chipReset_p61 is not supported in legacy power scheme");
  }
  return status;
}

/******************************************************************************
 * Function         phNxpEse_deInit_p61
 *
 * Description      This function de-initializes all the ESE protocol params
 *
 * Returns          Always return ESESTATUS_SUCCESS (0).
 *
 ******************************************************************************/
ESESTATUS phNxpEse_deInit_p61(void) {
  ESESTATUS status = ESESTATUS_SUCCESS;
  status = phNxpEseProto7816_Close_p61(
      (phNxpEseProto7816SecureTimer_t*)&nxpese_ctxt_p61.secureTimerParams);
  if (status == ESESTATUS_FAILED) {
    status = ESESTATUS_FAILED;
  }
  return status;
}

/******************************************************************************
 * Function         phNxpEse_close_p61
 *
 * Description      This function close the ESE interface and free all
 *                  resources.
 *
 * Returns          Always return ESESTATUS_SUCCESS (0).
 *
 ******************************************************************************/
ESESTATUS phNxpEse_close_p61(void) {
  ESESTATUS status = ESESTATUS_SUCCESS;
  if ((ESE_STATUS_CLOSE == nxpese_ctxt_p61.EseLibStatus)) {
    tloge(" %s ESE Not Initialized \n", __FUNCTION__);
    return ESESTATUS_NOT_INITIALISED;
  }

#ifdef SPM_INTEGRATED
  ESESTATUS wSpmStatus = ESESTATUS_SUCCESS;
#endif

#ifdef SPM_INTEGRATED
  /* Release the Access of  */
  wSpmStatus = phNxpEse_SPM_ConfigPwr(SPM_POWER_DISABLE);
  if (wSpmStatus != ESESTATUS_SUCCESS) {
    tloge("phNxpEse_SPM_ConfigPwr : disabling power Failed");
  } else {
    nxpese_ctxt_p61.spm_power_state = false;
  }
  wSpmStatus = phNxpEse_SPM_DeInit();
  if (wSpmStatus != ESESTATUS_SUCCESS) {
    tloge("phNxpEse_SPM_DeInit Failed");
  }

#endif
  if (NULL != nxpese_ctxt_p61.pDevHandle) {
    phPalEse_close(nxpese_ctxt_p61.pDevHandle);
    phNxpEse_memset_p61(&nxpese_ctxt_p61, 0x00, sizeof(nxpese_ctxt_p61));
  }

  /* Return success always */
  return status;
}

/******************************************************************************
 * Function         phNxpEse_read_p61
 *
 * Description      This function write the data to ESE through physical
 *                  interface (e.g. I2C) using the  driver interface.
 *                  Before sending the data to ESE, phNxpEse_write_ext
 *                  is called to check if there is any extension processing
 *                  is required for the SPI packet being sent out.
 *
 * Returns          It returns ESESTATUS_SUCCESS (0) if read successful else
 *                  ESESTATUS_FAILED(1)
 *
 ******************************************************************************/
ESESTATUS phNxpEse_read_p61(uint32_t* data_len, uint8_t** pp_data) {
  ESESTATUS status = ESESTATUS_SUCCESS;
  int ret = -1;

  ret = phNxpEse_readPacket(nxpese_ctxt_p61.pDevHandle, nxpese_ctxt_p61.p_read_buff,
                            MAX_DATA_LEN);
  if (ret < 0) {
    tloge("PAL Read status error status = %x", status);
    *data_len = 2;
    *pp_data = nxpese_ctxt_p61.p_read_buff;
    status = ESESTATUS_FAILED;
  } else {
    PH_PAL_ESE_PRINT_PACKET_RX(nxpese_ctxt_p61.p_read_buff, ret);
    *data_len = (uint32_t)ret;
    *pp_data = nxpese_ctxt_p61.p_read_buff;
    status = ESESTATUS_SUCCESS;
  }

  return status;
}

/******************************************************************************
 * Function         phNxpEse_readPacket
 *
 * Description      This function Reads requested number of bytes from
 *                  pn547 device into given buffer.
 *
 * Returns          nNbBytesToRead- number of successfully read bytes
 *                  -1        - read operation failure
 *
 ******************************************************************************/
static int phNxpEse_readPacket(void* pDevHandle, uint8_t* pBuffer,
                               int nNbBytesToRead) {
  int ret = -1;
  int sof_counter = 0; /* one read may take 1 ms*/
  int total_count = 0, numBytesToRead = 0, headerIndex = 0;

  do {
    sof_counter++;
    ret = -1;
    ret = phPalEse_read(pDevHandle, pBuffer, 2);
    if (ret < 0) {
      /*Polling for read on spi, hence Debug log*/
      tloge("_spi_read() [HDR]errno : %x ret : %X", errno,
               ret);
    }
    if (pBuffer[0] == RECIEVE_PACKET_SOF) {
      /* Read the HEADR of one byte*/
      numBytesToRead = 1;
      headerIndex = 1;
      break;
    } else if (pBuffer[1] == RECIEVE_PACKET_SOF) {
      /* Read the HEADR of Two bytes*/
      pBuffer[0] = RECIEVE_PACKET_SOF;
      numBytesToRead = 2;
      headerIndex = 0;
      break;
    }
    phPalEse_sleep( GET_WAKE_UP_DELAY() * NAD_POLLING_SCALER);
  } while (sof_counter < ESE_NAD_POLLING_MAX);
  if (pBuffer[0] == RECIEVE_PACKET_SOF) {
    tloge("%s SOF FOUND", __FUNCTION__);
    /* Read the HEADR of one/Two bytes based on how two bytes read A5 PCB or 00
     * A5*/
    ret = phPalEse_read(pDevHandle, &pBuffer[1 + headerIndex], numBytesToRead);
    if (ret < 0) {
      tloge("_spi_read() [HDR]errno : %x ret : %X", errno, ret);
    }
    total_count = 3;
    nNbBytesToRead = pBuffer[2];
    /* Read the Complete data + one byte CRC*/
    ret = phPalEse_read(pDevHandle, &pBuffer[3], (nNbBytesToRead + 1));
    if (ret < 0) {
      tloge("_spi_read() [HDR]errno : %x ret : %X", errno, ret);
      ret = -1;
    } else {
      ret = (total_count + (nNbBytesToRead + 1));
    }
  } else if (ret < 0) {
    /*In case of IO Error*/
    ret = -2;
    pBuffer[0] = 0x64;
    pBuffer[1] = 0xFF;
  } else {
    ret = -1;
  }
  return ret;
}
/******************************************************************************
 * Function         phNxpEse_WriteFrame_p61
 *
 * Description      This is the actual function which is being called by
 *                  phNxpEse_write. This function writes the data to ESE.
 *                  It waits till write callback provide the result of write
 *                  process.
 *
 * Returns          It returns ESESTATUS_SUCCESS (0) if write successful else
 *                  ESESTATUS_FAILED(1)
 *
 ******************************************************************************/
ESESTATUS phNxpEse_WriteFrame_p61(uint32_t data_len, uint8_t* p_data) {
  ESESTATUS status = ESESTATUS_INVALID_PARAMETER;
  int32_t dwNoBytesWrRd = 0;

  {
    p_data[0] = ESE_NAD_TX;
  }
  /* Create local copy of cmd_data */
  phNxpEse_memcpy_p61(nxpese_ctxt_p61.p_cmd_data, p_data, data_len);
  nxpese_ctxt_p61.cmd_len = data_len;

  dwNoBytesWrRd = phPalEse_write(nxpese_ctxt_p61.pDevHandle, nxpese_ctxt_p61.p_cmd_data,
                                 nxpese_ctxt_p61.cmd_len);
  if (-1 == dwNoBytesWrRd) {
    tloge(" - Error in SPI Write.....\n");
    status = ESESTATUS_FAILED;
  } else {
    status = ESESTATUS_SUCCESS;
    PH_PAL_ESE_PRINT_PACKET_TX(nxpese_ctxt_p61.p_cmd_data, nxpese_ctxt_p61.cmd_len);
  }

  return status;
}

/******************************************************************************
 * Function         phNxpEse_setIfsc
 *
 * Description      This function sets the IFSC size to 240/254 support JCOP OS
 *Update.
 *
 * Returns          Always return ESESTATUS_SUCCESS (0).
 *
 ******************************************************************************/
ESESTATUS phNxpEse_setIfsc(uint16_t IFSC_Size) {
  /*SET the IFSC size to 240 bytes*/
  phNxpEseProto7816_SetIfscSize(IFSC_Size);
  return ESESTATUS_SUCCESS;
}

/******************************************************************************
 * Function         phNxpEse_Sleep_p61
 *
 * Description      This function  suspends execution of the calling thread for
 *           (at least) usec microseconds
 *
 * Returns          Always return ESESTATUS_SUCCESS (0).
 *
 ******************************************************************************/
ESESTATUS phNxpEse_Sleep_p61(uint32_t usec) {
  phPalEse_sleep(usec);
  return ESESTATUS_SUCCESS;
}

/******************************************************************************
 * Function         phNxpEse_memset_p61
 *
 * Description      This function updates destination buffer with val
 *                  data in len size
 *
 * Returns          Always return ESESTATUS_SUCCESS (0).
 *
 ******************************************************************************/
void* phNxpEse_memset_p61(void* buff, int val, size_t len) {
  return phPalEse_memset(buff, val, len);
}

/******************************************************************************
 * Function         phNxpEse_memcpy_p61
 *
 * Description      This function copies source buffer to  destination buffer
 *                  data in len size
 *
 * Returns          Return pointer to allocated memory location.
 *
 ******************************************************************************/
void* phNxpEse_memcpy_p61(void* dest, const void* src, size_t len) {
  return phPalEse_memcpy(dest, src, len);
}

/******************************************************************************
 * Function         phNxpEse_memalloc_p61
 *
 * Description      This function allocation memory
 *
 * Returns          Return pointer to allocated memory or NULL.
 *
 ******************************************************************************/
void* phNxpEse_memalloc_p61(uint32_t size) {
  return phPalEse_memalloc(size);
  ;
}

/******************************************************************************
 * Function         phNxpEse_calloc_p61
 *
 * Description      This is utility function for runtime heap memory allocation
 *
 * Returns          Return pointer to allocated memory or NULL.
 *
 ******************************************************************************/
void* phNxpEse_calloc_p61(size_t datatype, size_t size) {
  return phPalEse_calloc(datatype, size);
}

/******************************************************************************
 * Function         phNxpEse_free_p61
 *
 * Description      This function de-allocation memory
 *
 * Returns         void.
 *
 ******************************************************************************/
void phNxpEse_free_p61(void* ptr) {
  if (ptr != NULL) {
    free(ptr);
    ptr = NULL;
  }
  return;
}

/******************************************************************************
 * Function         phNxpEse_GetMaxTimer
 *
 * Description      This function finds out the max. timer value returned from
 *JCOP
 *
 * Returns          void.
 *
 ******************************************************************************/
void phNxpEse_GetMaxTimer(unsigned long *pMaxTimer) {

  /* Finding the max. of the timer value */
  *pMaxTimer = nxpese_ctxt_p61.secureTimerParams.secureTimer1;
  if (*pMaxTimer < nxpese_ctxt_p61.secureTimerParams.secureTimer2)
    *pMaxTimer = nxpese_ctxt_p61.secureTimerParams.secureTimer2;
  *pMaxTimer = (*pMaxTimer < nxpese_ctxt_p61.secureTimerParams.secureTimer3)
                   ? (nxpese_ctxt_p61.secureTimerParams.secureTimer3)
                   : *pMaxTimer;

  /* Converting timer to millisecond from sec */
  *pMaxTimer = SECOND_TO_MILLISECOND(*pMaxTimer);
  /* Add extra 5% to the timer */
  *pMaxTimer +=
      CONVERT_TO_PERCENTAGE(*pMaxTimer, ADDITIONAL_SECURE_TIME_PERCENTAGE);
  return;
}

#if (NXP_NFCC_SPI_FW_DOWNLOAD_SYNC == true)
/******************************************************************************
 * Function         phNxpEse_checkFWDwnldStatus
 *
 * Description      This function is  used to  check whether FW download
 *                  is completed or not.
 *
 * Returns          returns  ESESTATUS_SUCCESS or ESESTATUS_BUSY
 *
 ******************************************************************************/
static ESESTATUS phNxpEse_checkFWDwnldStatus(void) {
  ESESTATUS wSpmStatus = ESESTATUS_SUCCESS;
  spm_state_t current_spm_state = SPM_STATE_INVALID;
  uint8_t ese_dwnld_retry = 0x00;
  ESESTATUS status = ESESTATUS_FAILED;

  wSpmStatus = phNxpEse_SPM_GetState(&current_spm_state);
  if (wSpmStatus == ESESTATUS_SUCCESS) {
    /* Check current_spm_state and update config/Spm status*/
    while (ese_dwnld_retry < ESE_FW_DWNLD_RETRY_CNT) {
      tloge("ESE_FW_DWNLD_RETRY_CNT retry count");
      wSpmStatus = phNxpEse_SPM_GetState(&current_spm_state);
      if (wSpmStatus == ESESTATUS_SUCCESS) {
        if ((current_spm_state & SPM_STATE_DWNLD)) {
          status = ESESTATUS_FAILED;
        } else {
          tloge("Exit polling no FW Download ..");
          status = ESESTATUS_SUCCESS;
          break;
        }
      } else {
        status = ESESTATUS_FAILED;
        break;
      }
      phNxpEse_Sleep_p61(500000); /*sleep for 500 ms checking for fw dwnld status*/
      ese_dwnld_retry++;
    }
  }

  return status;
}
#endif
/******************************************************************************
 * Function         phNxpEse_GetEseStatus_p61(unsigned char *timer_buffer)
 *
 * Description      This function returns the all three timer
 * Timeout buffer length should be minimum 18 bytes. Response will be in below
 format:
 * <0xF1><Len><Timer Value><0xF2><Len><Timer Value><0xF3><Len><Timer Value>
 *
 * Returns         SUCCESS/FAIL.
 * ESESTATUS_SUCCESS if 0xF1 or 0xF2 tag timeout >= 0 & 0xF3 == 0
 * ESESTATUS_BUSY if 0xF3 tag timeout > 0
 * ESESTATUS_FAILED if any other error

 ******************************************************************************/
ESESTATUS phNxpEse_GetEseStatus_p61(phNxpEse_data_p61* timer_buffer) {
  ESESTATUS status = ESESTATUS_FAILED;

  phNxpEse_SecureTimer_t secureTimerParams;
  uint8_t* temp_timer_buffer = NULL;

  if (timer_buffer != NULL) {
    timer_buffer->len =
        (sizeof(secureTimerParams.secureTimer1) +
         sizeof(secureTimerParams.secureTimer2) +
         sizeof(secureTimerParams.secureTimer3)) +
        PH_PROPTO_7816_FRAME_LENGTH_OFFSET * PH_PROPTO_7816_FRAME_LENGTH_OFFSET;
    temp_timer_buffer = (uint8_t*)phNxpEse_memalloc_p61(timer_buffer->len);
    timer_buffer->p_data = temp_timer_buffer;

#if (NXP_SECURE_TIMER_SESSION == true)
    phNxpEse_memcpy_p61(&secureTimerParams, &nxpese_ctxt_p61.secureTimerParams,
                    sizeof(phNxpEse_SecureTimer_t));

    *temp_timer_buffer++ = PH_PROPTO_7816_SFRAME_TIMER1;
    *temp_timer_buffer++ = sizeof(secureTimerParams.secureTimer1);
    temp_timer_buffer = phNxpEse_GgetTimerTlvBuffer(
        temp_timer_buffer, secureTimerParams.secureTimer1);
    if (temp_timer_buffer != NULL) {
      *temp_timer_buffer++ = PH_PROPTO_7816_SFRAME_TIMER2;
      *temp_timer_buffer++ = sizeof(secureTimerParams.secureTimer2);
      temp_timer_buffer = phNxpEse_GgetTimerTlvBuffer(
          temp_timer_buffer, secureTimerParams.secureTimer2);
      if (temp_timer_buffer != NULL) {
        *temp_timer_buffer++ = PH_PROPTO_7816_SFRAME_TIMER3;
        *temp_timer_buffer++ = sizeof(secureTimerParams.secureTimer3);
        temp_timer_buffer = phNxpEse_GgetTimerTlvBuffer(
            temp_timer_buffer, secureTimerParams.secureTimer3);
        if (temp_timer_buffer != NULL) {
          if (secureTimerParams.secureTimer3 > 0) {
            status = ESESTATUS_BUSY;
          } else {
            status = ESESTATUS_SUCCESS;
          }
        }
      }
    }
#endif
  } else {
    tloge("%s Invalid timer buffer ", __FUNCTION__);
  }

  return status;
}
#if (NXP_SECURE_TIMER_SESSION == true)
static unsigned char* phNxpEse_GgetTimerTlvBuffer(uint8_t* timer_buffer,
                                                  unsigned int value) {
  short int count = 0, shift = 3;
  unsigned int mask = 0x000000FF;
  tloge("value = %x \n", value);
  for (count = 0; count < 4; count++) {
    if (timer_buffer != NULL) {
      *timer_buffer = (value >> (shift * 8) & mask);
      timer_buffer++;
      shift--;
    } else {
      break;
    }
  }
  return timer_buffer;
}
#endif
