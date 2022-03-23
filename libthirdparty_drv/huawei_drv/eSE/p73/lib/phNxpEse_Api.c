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
#include <stdlib.h>
#include <phNxpEseFeatures.h>

#ifdef HISI_TEE
#include <ese_config_hisi.h>
#else
#include <ese_config.h>
#endif

#include <phNxpEsePal.h>
#include <phNxpEsePal_spi.h>
#include <phNxpEseProto7816_3.h>
#include <phNxpEse_Internal.h>
#include <log_hisi.h>

#ifdef LOG_TAG
#undef LOG_TAG
#define LOG_TAG "NxpEseHal"
#endif

#define RECIEVE_PACKET_SOF 0xA5
#define CHAINED_PACKET_WITHSEQN 0x60
#define CHAINED_PACKET_WITHOUTSEQN 0x20
#define PH_PAL_ESE_PRINT_PACKET_TX(data, len)                   \
  ({                                                            \
      phPalEse_print_packet("SEND", data, len);                 \
  })
#define PH_PAL_ESE_PRINT_PACKET_RX(data, len)                   \
  ({                                                            \
      phPalEse_print_packet("RECV", data, len);                 \
  })
#define MAX_SUPPORTED_DATA_SIZE 0x8800
static int phNxpEse_readPacket(void* pDevHandle, uint8_t* pBuffer,
                               int nNbBytesToRead);
#ifdef SPM_INTEGRATED
static ESESTATUS phNxpEse_checkJcopDwnldState(void);
static ESESTATUS phNxpEse_setJcopDwnldState(phNxpEse_JcopDwnldState state);
static ESESTATUS phNxpEse_checkFWDwnldStatus(void);
#endif
static void phNxpEse_GetMaxTimer(unsigned long* pMaxTimer);
static unsigned char* phNxpEse_GgetTimerTlvBuffer(unsigned char* timer_buffer,
                                                  unsigned int value);
static int poll_sof_chained_delay = 0;
static int sOsVersion = 0xFF;  // TODO: static phNxpEse_OsVersion_t sOsVersion = INVALID_OS_VERSION;

/*********************** Global Variables *************************************/

/* ESE Context structure */
phNxpEse_Context_t nxpese_ctxt;
bool ese_debug_enabled = false;

/******************************************************************************
 * Function         phNxpEse_SetEndPoint_Cntxt
 *
 * Description      This function is called set the SE endpoint
 *
 * Returns          None
 *
 ******************************************************************************/

ESESTATUS phNxpEse_SetEndPoint_Cntxt(uint8_t uEndPoint)
{
  ESESTATUS status = ESESTATUS_FAILED;
  status = phNxpEseProto7816_SetEndPoint(uEndPoint);
  if (status == ESESTATUS_SUCCESS) {
      nxpese_ctxt.nadInfo.nadRx = nadInfoRx_ptr[uEndPoint];
      nxpese_ctxt.nadInfo.nadTx = nadInfoTx_ptr[uEndPoint];
      nxpese_ctxt.endPointInfo = uEndPoint;
  }
  /*if (GET_CHIP_OS_VERSION() != OS_VERSION_4_0) {
    status = phNxpEseProto7816_SetEndPoint(uEndPoint);
    if (status == ESESTATUS_SUCCESS) {
      nxpese_ctxt.nadInfo.nadRx = nadInfoRx_ptr[uEndPoint];
      nxpese_ctxt.nadInfo.nadTx = nadInfoTx_ptr[uEndPoint];
      nxpese_ctxt.endPointInfo = uEndPoint;
    }
    HISI_PRINT_ERROR( "%s: Enpoint=%d", __FUNCTION__, uEndPoint);
  } else {
    HISI_PRINT_ERROR("%s- Function not supported", __FUNCTION__);
  } */
  return status;
}

/******************************************************************************
 * Function         phNxpEse_ResetEndPoint_Cntxt
 *
 * Description      This function is called to reset the SE endpoint
 *
 * Returns          None
 *
 ******************************************************************************/
ESESTATUS phNxpEse_ResetEndPoint_Cntxt(uint8_t uEndPoint)
{
  ESESTATUS status = ESESTATUS_FAILED;
  status = phNxpEseProto7816_ResetEndPoint(uEndPoint);
  /*if (GET_CHIP_OS_VERSION() != OS_VERSION_4_0) {
    status = phNxpEseProto7816_ResetEndPoint(uEndPoint);
  } else */{
    HISI_PRINT_INFO("%s- Function not supported", __FUNCTION__);
  }
  return status;
}
/******************************************************************************
 * Function         phNxpLog_InitializeLogLevel
 *
 * Description      This function is called during phNxpEse_init to initialize
 *                  debug log level.
 *
 * Returns          None
 *
 ******************************************************************************/

void phNxpLog_InitializeLogLevel() {
    ese_debug_enabled = true;
//      (EseConfig_getUnsigned(NAME_SE_DEBUG_ENABLED, 0) != 0) ? true : false;
#if 0
  char valueStr[PROPERTY_VALUE_MAX] = {0};
  int len = property_get("vendor.ese.debug_enabled", valueStr, "");
  if (len > 0) {
    // let Android property override .conf variable
    unsigned debug_enabled = 0;
    sscanf(valueStr, "%u", &debug_enabled);
    ese_debug_enabled = (debug_enabled == 0) ? false : true;
  }
  #endif
  ese_debug_enabled = true;

  HISI_PRINT_INFO( "%s: level=%u", __func__, ese_debug_enabled);
}


/******************************************************************************
 * Function         phNxpEse_init
 *
 * Description      This function is called by Jni/phNxpEse_open during the
 *                  initialization of the ESE. It initializes protocol stack
 *instance variable
 *
 * Returns          This function return ESESTATUS_SUCCES (0) in case of success
 *                  In case of failure returns other failure value.
 *
 ******************************************************************************/
ESESTATUS phNxpEse_init(phNxpEse_initParams initParams) {
  ESESTATUS wConfigStatus = ESESTATUS_FAILED;
  unsigned long int num, ifsd_value = 0;
  unsigned long maxTimer = 0;
  phNxpEseProto7816InitParam_t protoInitParam;
  phNxpEse_memset(&protoInitParam, 0x00, sizeof(phNxpEseProto7816InitParam_t));
  /* STATUS_OPEN */
  nxpese_ctxt.EseLibStatus = ESE_STATUS_OPEN;

  if (EseConfig_hasKey(NAME_NXP_WTX_COUNT_VALUE)) {
    num = EseConfig_getUnsigned(NAME_NXP_WTX_COUNT_VALUE);
    protoInitParam.wtx_counter_limit = num;
    HISI_PRINT_INFO( "Wtx_counter read from config file - %lu",
             protoInitParam.wtx_counter_limit);
  } else {
    protoInitParam.wtx_counter_limit = PH_PROTO_WTX_DEFAULT_COUNT;
  }
  if (EseConfig_hasKey(NAME_RNACK_RETRY_DELAY)) {
    num = EseConfig_getUnsigned(NAME_RNACK_RETRY_DELAY);
    nxpese_ctxt.invalidFrame_Rnack_Delay = num;
    HISI_PRINT_INFO( "Rnack retry_delay read from config file - %lu",
             num);
  } else {
    nxpese_ctxt.invalidFrame_Rnack_Delay = 7000;
  }
  if (EseConfig_hasKey(NAME_NXP_MAX_RNACK_RETRY)) {
    protoInitParam.rnack_retry_limit =
        EseConfig_getUnsigned(NAME_NXP_MAX_RNACK_RETRY);
  } else {
    protoInitParam.rnack_retry_limit = MAX_RNACK_RETRY_LIMIT;
  }
  if (ESE_MODE_NORMAL ==
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
      (phNxpEseProto7816SecureTimer_t*)&nxpese_ctxt.secureTimerParams;

  HISI_PRINT_INFO(
           "%s secureTimer1 0x%x secureTimer2 0x%x secureTimer3 0x%x",
           __FUNCTION__, nxpese_ctxt.secureTimerParams.secureTimer1,
           nxpese_ctxt.secureTimerParams.secureTimer2,
           nxpese_ctxt.secureTimerParams.secureTimer3);

  phNxpEse_GetMaxTimer(&maxTimer);
#ifdef SPM_INTEGRATED
  if (GET_CHIP_OS_VERSION() == OS_VERSION_4_0) {
    wConfigStatus = phNxpEse_SPM_DisablePwrControl(maxTimer);
    HISI_PRINT_ERROR("%s(%d): status(0x%x)!\n", __func__, __LINE__, wConfigStatus);
    if (wConfigStatus != ESESTATUS_SUCCESS) {
      HISI_PRINT_ERROR("%s phNxpEse_SPM_DisablePwrControl: failed", __FUNCTION__);
    }
  }
#endif

  /* T=1 Protocol layer open */
  wConfigStatus = phNxpEseProto7816_Open(protoInitParam);
  HISI_PRINT_INFO("%s %d: status 0x%x!\n", __func__, __LINE__, wConfigStatus);

  if (ESESTATUS_SUCCESS == wConfigStatus) {
    HISI_PRINT_ERROR( "phNxpEseProto7816_Open completed >>>>>");
    /* Retrieving the IFS-D value configured in the config file and applying to
     * Card */
    if ((nxpese_ctxt.endPointInfo == END_POINT_ESE) &&
        (EseConfig_hasKey(NAME_NXP_ESE_IFSD_VALUE))) {
      ifsd_value = EseConfig_getUnsigned(NAME_NXP_ESE_IFSD_VALUE);
      if ((0xFFFF > ifsd_value) && (ifsd_value > 0)) {
        HISI_PRINT_ERROR(
                 "phNxpEseProto7816_SetIFS IFS adjustment requested with %ld",
                 ifsd_value);
        phNxpEse_setIfs(ifsd_value);
      } else {
        HISI_PRINT_ERROR(
                 "phNxpEseProto7816_SetIFS IFS adjustment argument invalid");
      }
    } else if ((nxpese_ctxt.endPointInfo == END_POINT_EUICC) &&
               (EseConfig_hasKey(NAME_NXP_EUICC_IFSD_VALUE))) {
      ifsd_value = EseConfig_getUnsigned(NAME_NXP_EUICC_IFSD_VALUE);
      if ((0xFFFF > ifsd_value) && (ifsd_value > 0)) {
        HISI_PRINT_ERROR(
                 "phNxpEseProto7816_SetIFS IFS adjustment requested with %ld",
                 ifsd_value);
        phNxpEse_setIfs(ifsd_value);
      } else {
        HISI_PRINT_ERROR(
                 "phNxpEseProto7816_SetIFS IFS adjustment argument invalid");
      }
    }
  } else {
    HISI_PRINT_ERROR("phNxpEseProto7816_Open failed with status = %x", wConfigStatus);
  }

  return wConfigStatus;
}

/******************************************************************************
 * Function         phNxpEse_open
 *
 * Description      This function is called by Jni during the
 *                  initialization of the ESE. It opens the physical connection
 *                  with ESE and creates required NAME_NXP_MAX_RNACK_RETRYclient thread for
 *                  operation.
 * Returns          This function return ESESTATUS_SUCCES (0) in case of success
 *                  In case of failure returns other failure value.
 *
 ******************************************************************************/
ESESTATUS phNxpEse_open(phNxpEse_initParams initParams) {
  phPalEse_Config_t tPalConfig;
  ESESTATUS wConfigStatus = ESESTATUS_SUCCESS;
  unsigned long int num = 0, tpm_enable = 0;
  char ese_dev_node[64];
  //std::string ese_node;
#ifdef SPM_INTEGRATED
  ESESTATUS wSpmStatus = ESESTATUS_SUCCESS;
  spm_state_t current_spm_state = SPM_STATE_INVALID;
#endif
  /* initialize trace level */
  phNxpLog_InitializeLogLevel();

  HISI_PRINT_INFO( "phNxpEse_open Enter");
  /*When spi channel is already opened return status as FAILED*/
  if (nxpese_ctxt.EseLibStatus != ESE_STATUS_CLOSE) {
    HISI_PRINT_ERROR( "already opened\n");
    return ESESTATUS_BUSY;
  }

  phNxpEse_memset(&nxpese_ctxt, 0x00, sizeof(nxpese_ctxt));
  phNxpEse_memset(&tPalConfig, 0x00, sizeof(tPalConfig));

  HISI_PRINT_INFO( "MW SEAccessKit Version");
  HISI_PRINT_INFO( "Android Version:0x%x", NXP_ANDROID_VER);
  HISI_PRINT_INFO( "Major Version:0x%x", ESELIB_MW_VERSION_MAJ);
  HISI_PRINT_INFO( "Minor Version:0x%x", ESELIB_MW_VERSION_MIN);

  {
  // TODO: OS_VERSION_5_2 value  sOsVersion = OS_VERSION_5_2;
    sOsVersion = 3;
    HISI_PRINT_ERROR(
             "Chip type not defined in config file osVersion- %d", sOsVersion);
  }
  if (EseConfig_hasKey(NAME_NXP_TP_MEASUREMENT)) {
    tpm_enable = EseConfig_getUnsigned(NAME_NXP_TP_MEASUREMENT);
    HISI_PRINT_INFO(
        "SPI Throughput measurement enable/disable read from config file - %lu",
        tpm_enable);
  } else {
    HISI_PRINT_ERROR(
             "SPI Throughput not defined in config file - %lu", tpm_enable);
  }
#if (NXP_POWER_SCHEME_SUPPORT == true)
  if (EseConfig_hasKey(NAME_NXP_POWER_SCHEME)) {
    num = EseConfig_getUnsigned(NAME_NXP_POWER_SCHEME);
    nxpese_ctxt.pwr_scheme = num;
    HISI_PRINT_INFO( "Power scheme read from config file - %lu",
             num);
  } else {
    nxpese_ctxt.pwr_scheme = PN67T_POWER_SCHEME;
    HISI_PRINT_ERROR( "Power scheme not defined in config file - %lu",
             num);
  }
#else
  nxpese_ctxt.pwr_scheme = PN67T_POWER_SCHEME;
  tpm_enable = 0x00;
#endif

  if (EseConfig_hasKey(NAME_NXP_NAD_POLL_RETRY_TIME)) {
    num = EseConfig_getUnsigned(NAME_NXP_NAD_POLL_RETRY_TIME);
    nxpese_ctxt.nadPollingRetryTime = num;
  }
  else
  {
    nxpese_ctxt.nadPollingRetryTime = 5;
  }

  HISI_PRINT_INFO( "Nad poll retry time in us - %lu us",
           nxpese_ctxt.nadPollingRetryTime * GET_WAKE_UP_DELAY() *
               GET_NAD_POLLING_SCALER());

  /*Read device node path*/
  //ese_node = EseConfig_getString(NAME_NXP_ESE_DEV_NODE, "/dev/pn81a");
  strcpy(ese_dev_node, "/dev/pn81a");
  tPalConfig.pDevName = (int8_t*)ese_dev_node;

  /* Initialize PAL layer */
  wConfigStatus = phPalEse_open_and_configure(&tPalConfig);
  if (wConfigStatus != ESESTATUS_SUCCESS) {
    HISI_PRINT_ERROR("phPalEse_Init Failed");
    /*if (GET_CHIP_OS_VERSION() != OS_VERSION_4_0) {
      if (ESESTATUS_DRIVER_BUSY == wConfigStatus)
        HISI_PRINT_ERROR("Ese Driver is Busy!!!");
    }*/
    goto clean_and_return;
  }
  /* Copying device handle to ESE Lib context*/
  nxpese_ctxt.pDevHandle = tPalConfig.pDevHandle;
  if(ESE_PROTOCOL_MEDIA_SPI == initParams.mediaType){
    HISI_PRINT_ERROR(
             "Inform eSE about the starting of trusted Mode");
    wConfigStatus = phPalEse_ioctl(phPalEse_e_SetSecureMode,
                                     tPalConfig.pDevHandle,0x01);
    if (ESESTATUS_SUCCESS != wConfigStatus)
      goto clean_and_return_2;
  }
#ifdef SPM_INTEGRATED
  /* Get the Access of ESE*/
  wSpmStatus = phNxpEse_SPM_Init(nxpese_ctxt.pDevHandle);
  if (wSpmStatus != ESESTATUS_SUCCESS) {
    HISI_PRINT_ERROR("phNxpEse_SPM_Init Failed");
    wConfigStatus = ESESTATUS_FAILED;
    goto clean_and_return_2;
  }
  wSpmStatus = phNxpEse_SPM_SetPwrScheme(nxpese_ctxt.pwr_scheme);
  if (wSpmStatus != ESESTATUS_SUCCESS) {
    HISI_PRINT_ERROR(" %s : phNxpEse_SPM_SetPwrScheme Failed", __FUNCTION__);
    wConfigStatus = ESESTATUS_FAILED;
    goto clean_and_return_1;
  }
  if (GET_CHIP_OS_VERSION() == OS_VERSION_4_0) {
    wConfigStatus = phNxpEse_checkFWDwnldStatus();
    if (wConfigStatus != ESESTATUS_SUCCESS) {
      HISI_PRINT_ERROR("Failed to open SPI due to VEN pin used by FW download \n");
      wConfigStatus = ESESTATUS_FAILED;
      goto clean_and_return_1;
    }
  }
  wSpmStatus = phNxpEse_SPM_GetState(&current_spm_state);
  if (wSpmStatus != ESESTATUS_SUCCESS) {
    HISI_PRINT_ERROR(" %s : phNxpEse_SPM_GetPwrState Failed", __FUNCTION__);
    wConfigStatus = ESESTATUS_FAILED;
    goto clean_and_return_1;
  } else {
    if (((current_spm_state & SPM_STATE_SPI) |
         (current_spm_state & SPM_STATE_SPI_PRIO)) &&
        !(current_spm_state & SPM_STATE_SPI_FAILED)) {
      HISI_PRINT_ERROR(" %s : SPI is already opened...second instance not allowed",
            __FUNCTION__);
      wConfigStatus = ESESTATUS_FAILED;
      goto clean_and_return_1;
    }
  }
  if (current_spm_state & SPM_STATE_JCOP_DWNLD) {
    HISI_PRINT_ERROR(" %s : Denying to open JCOP Download in progress", __FUNCTION__);
    wConfigStatus = ESESTATUS_FAILED;
    goto clean_and_return_1;
  }
  phNxpEse_memcpy(&nxpese_ctxt.initParams, &initParams,
                  sizeof(phNxpEse_initParams));
  if (GET_CHIP_OS_VERSION() == OS_VERSION_4_0) {
    /* Updating ESE power state based on the init mode */
    if (ESE_MODE_OSU == nxpese_ctxt.initParams.initMode) {
      HISI_PRINT_ERROR( "%s Init mode ---->OSU", __FUNCTION__);
      wConfigStatus = phNxpEse_checkJcopDwnldState();
      if (wConfigStatus != ESESTATUS_SUCCESS) {
        HISI_PRINT_ERROR("phNxpEse_checkJcopDwnldState failed");
        goto clean_and_return_1;
      }
    }
  }
  wSpmStatus = phNxpEse_SPM_ConfigPwr(SPM_POWER_ENABLE);
  if (wSpmStatus != ESESTATUS_SUCCESS) {
    HISI_PRINT_ERROR("phNxpEse_SPM_ConfigPwr: enabling power Failed wConfigStatus %x",
      wConfigStatus);
    if (wSpmStatus == ESESTATUS_BUSY) {
      wConfigStatus = ESESTATUS_BUSY;
    } else if (wSpmStatus == ESESTATUS_DWNLD_BUSY) {
      wConfigStatus = ESESTATUS_DWNLD_BUSY;
    } else {
      wConfigStatus = ESESTATUS_FAILED;
    }
    goto clean_and_return;
  } else {
    HISI_PRINT_ERROR( "nxpese_ctxt.spm_power_state true");
    nxpese_ctxt.spm_power_state = true;
  }
#endif
  /*if (GET_CHIP_OS_VERSION() == OS_VERSION_4_0) {
    if (tpm_enable) {
      wConfigStatus = phPalEse_ioctl(phPalEse_e_EnableThroughputMeasurement,
                                   nxpese_ctxt.pDevHandle, 0);
      if (wConfigStatus != ESESTATUS_SUCCESS) {
        HISI_PRINT_ERROR("phPalEse_IoCtl Failed");
        goto clean_and_return;
      }
    }
  }*/
  HISI_PRINT_INFO( "wConfigStatus %x", wConfigStatus);
  return wConfigStatus;

clean_and_return:
#ifdef SPM_INTEGRATED
  wSpmStatus = phNxpEse_SPM_ConfigPwr(SPM_POWER_DISABLE);
  if (wSpmStatus != ESESTATUS_SUCCESS) {
    HISI_PRINT_ERROR("phNxpEse_SPM_ConfigPwr: disabling power Failed");
  }
clean_and_return_1:
  phNxpEse_SPM_DeInit();
#endif
clean_and_return_2:
  if (NULL != nxpese_ctxt.pDevHandle) {
    phPalEse_close(nxpese_ctxt.pDevHandle);
    phNxpEse_memset(&nxpese_ctxt, 0x00, sizeof(nxpese_ctxt));
  }
  nxpese_ctxt.EseLibStatus = ESE_STATUS_CLOSE;
  nxpese_ctxt.spm_power_state = false;
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
bool phNxpEse_isOpen() { return nxpese_ctxt.EseLibStatus != ESE_STATUS_CLOSE; }

/******************************************************************************
 * Function         phNxpEse_openPrioSession
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
ESESTATUS phNxpEse_openPrioSession(phNxpEse_initParams initParams) {
  phPalEse_Config_t tPalConfig;
  ESESTATUS wConfigStatus = ESESTATUS_SUCCESS;
  unsigned long int num = 0, tpm_enable = 0;
  (void)initParams;
  /* initialize trace level */
  phNxpLog_InitializeLogLevel();
  HISI_PRINT_INFO("phNxpEse_openPrioSession Enter");
#ifdef SPM_INTEGRATED
  ESESTATUS wSpmStatus = ESESTATUS_SUCCESS;
  spm_state_t current_spm_state = SPM_STATE_INVALID;
#endif
  phNxpEse_memset(&nxpese_ctxt, 0x00, sizeof(nxpese_ctxt));
  phNxpEse_memset(&tPalConfig, 0x00, sizeof(tPalConfig));
  HISI_PRINT_INFO( "MW SEAccessKit Version, Android Version:0x%x, Major Version:0x%x, Minor Version:0x%x",
      NXP_ANDROID_VER, ESELIB_MW_VERSION_MAJ, ESELIB_MW_VERSION_MIN);

#if (NXP_POWER_SCHEME_SUPPORT == true)
  if (EseConfig_hasKey(NAME_NXP_POWER_SCHEME)) {
    num = EseConfig_getUnsigned(NAME_NXP_POWER_SCHEME);
    nxpese_ctxt.pwr_scheme = num;
    HISI_PRINT_INFO( "Power scheme read from config file - %lu", num);
  } else
#endif
  {
    nxpese_ctxt.pwr_scheme = PN67T_POWER_SCHEME;
    HISI_PRINT_ERROR( "Power scheme not defined in config file - %lu", num);
  }
  if (EseConfig_hasKey(NAME_NXP_TP_MEASUREMENT)) {
    tpm_enable = EseConfig_getUnsigned(NAME_NXP_TP_MEASUREMENT);
    (void)tpm_enable
    HISI_PRINT_INFO("SPI Throughput measurement enable/disable read from config file - %lu");
  } else {
    HISI_PRINT_ERROR("SPI Throughput not defined in config file - %lu", num);
  }

  tPalConfig.pDevName = (int8_t*)"/dev/p73";

  /* Initialize PAL layer */
  wConfigStatus = phPalEse_open_and_configure(&tPalConfig);
  if (wConfigStatus != ESESTATUS_SUCCESS) {
    HISI_PRINT_ERROR("phPalEse_Init Failed");
    goto clean_and_return;
  }
  /* Copying device handle to hal context*/
  nxpese_ctxt.pDevHandle = tPalConfig.pDevHandle;

#ifdef SPM_INTEGRATED
  /* Get the Access of ESE*/
  wSpmStatus = phNxpEse_SPM_Init(nxpese_ctxt.pDevHandle);
  if (wSpmStatus != ESESTATUS_SUCCESS) {
    HISI_PRINT_ERROR("phNxpEse_SPM_Init Failed");
    wConfigStatus = ESESTATUS_FAILED;
    goto clean_and_return_2;
  }
  wSpmStatus = phNxpEse_SPM_SetPwrScheme(nxpese_ctxt.pwr_scheme);
  if (wSpmStatus != ESESTATUS_SUCCESS) {
    HISI_PRINT_ERROR(" %s : phNxpEse_SPM_SetPwrScheme Failed", __FUNCTION__);
    wConfigStatus = ESESTATUS_FAILED;
    goto clean_and_return_1;
  }
  wSpmStatus = phNxpEse_SPM_GetState(&current_spm_state);
  if (wSpmStatus != ESESTATUS_SUCCESS) {
    HISI_PRINT_ERROR(" %s : phNxpEse_SPM_GetPwrState Failed", __FUNCTION__);
    wConfigStatus = ESESTATUS_FAILED;
    goto clean_and_return_1;
  } 
  phNxpEse_memcpy(&nxpese_ctxt.initParams, &initParams.initMode,
                  sizeof(phNxpEse_initParams));
  if (GET_CHIP_OS_VERSION() == OS_VERSION_4_0) {
    /* Updating ESE power state based on the init mode */
    if (ESE_MODE_OSU == nxpese_ctxt.initParams.initMode) {
      wConfigStatus = phNxpEse_checkJcopDwnldState();
      if (wConfigStatus != ESESTATUS_SUCCESS) {
        HISI_PRINT_ERROR("phNxpEse_checkJcopDwnldState failed");
        goto clean_and_return_1;
      }
    }
  }
  wSpmStatus = phNxpEse_SPM_ConfigPwr(SPM_POWER_PRIO_ENABLE);
  if (wSpmStatus != ESESTATUS_SUCCESS) {
    HISI_PRINT_ERROR("phNxpEse_SPM_ConfigPwr: spi prio Failed wConfigStatus %x",
      wConfigStatus);
    if (wSpmStatus == ESESTATUS_BUSY) {
      wConfigStatus = ESESTATUS_BUSY;
    } else if (wSpmStatus == ESESTATUS_DWNLD_BUSY) {
      wConfigStatus = ESESTATUS_DWNLD_BUSY;
    } else {
      wConfigStatus = ESESTATUS_FAILED;
    }
    goto clean_and_return;
  } else {
    HISI_PRINT_INFO("nxpese_ctxt.spm_power_state true");
    nxpese_ctxt.spm_power_state = true;
  }
#endif

#ifndef SPM_INTEGRATED
  wConfigStatus =
      phPalEse_ioctl(phPalEse_e_ResetDevice, nxpese_ctxt.pDevHandle, 2);
  if (wConfigStatus != ESESTATUS_SUCCESS) {
    HISI_PRINT_ERROR("phPalEse_IoCtl Failed");
    goto clean_and_return;
  }
#endif
  wConfigStatus =
      phPalEse_ioctl(phPalEse_e_EnableLog, nxpese_ctxt.pDevHandle, 0);
  if (wConfigStatus != ESESTATUS_SUCCESS) {
    HISI_PRINT_ERROR("phPalEse_IoCtl Failed");
    goto clean_and_return;
  }
  wConfigStatus =
      phPalEse_ioctl(phPalEse_e_EnablePollMode, nxpese_ctxt.pDevHandle, 1);
  if (wConfigStatus != ESESTATUS_SUCCESS) {
    HISI_PRINT_ERROR("phPalEse_IoCtl Failed");
    goto clean_and_return;
  }
  HISI_PRINT_INFO( "wConfigStatus %x", wConfigStatus);

  return wConfigStatus;

clean_and_return:
#ifdef SPM_INTEGRATED
  wSpmStatus = phNxpEse_SPM_ConfigPwr(SPM_POWER_DISABLE);
  if (wSpmStatus != ESESTATUS_SUCCESS) {
    HISI_PRINT_ERROR("phNxpEse_SPM_ConfigPwr: disabling power Failed");
  }
clean_and_return_1:
  phNxpEse_SPM_DeInit();
clean_and_return_2:
#endif
  if (NULL != nxpese_ctxt.pDevHandle) {
    phPalEse_close(nxpese_ctxt.pDevHandle);
    phNxpEse_memset(&nxpese_ctxt, 0x00, sizeof(nxpese_ctxt));
  }
  nxpese_ctxt.EseLibStatus = ESE_STATUS_CLOSE;
  nxpese_ctxt.spm_power_state = false;
  return ESESTATUS_FAILED;
}

#ifdef SPM_INTEGRATED
/******************************************************************************
 * Function         phNxpEse_setJcopDwnldState
 *
 * Description      This function is  used to check whether JCOP OS
 *                  download can be started or not.
 *
 * Returns          returns  ESESTATUS_SUCCESS or ESESTATUS_FAILED
 *
 ******************************************************************************/
static ESESTATUS phNxpEse_setJcopDwnldState(phNxpEse_JcopDwnldState state) {

    ESESTATUS w_config_status = ESESTATUS_FAILED;
    (void)state;
    HISI_PRINT_INFO( "phNxpEse_setJcopDwnldState Enter");

    return w_config_status;
}

/******************************************************************************
 * Function         phNxpEse_checkJcopDwnldState
 *
 * Description      This function is  used to check whether JCOP OS
 *                  download can be started or not.
 *
 * Returns          returns  ESESTATUS_SUCCESS or ESESTATUS_BUSY
 *
 ******************************************************************************/
static ESESTATUS phNxpEse_checkJcopDwnldState(void) {
  HISI_PRINT_INFO( "phNxpEse_checkJcopDwnld Enter");
  return ESESTATUS_SUCCESS;
#if 0
  ESESTATUS wSpmStatus = ESESTATUS_SUCCESS;
  spm_state_t current_spm_state = SPM_STATE_INVALID;
  uint8_t ese_dwnld_retry = 0x00;
  ESESTATUS status = ESESTATUS_FAILED;

  wSpmStatus = phNxpEse_SPM_GetState(&current_spm_state);
  if (wSpmStatus == ESESTATUS_SUCCESS) {
    /* Check current_spm_state and update config/Spm status*/
    if ((current_spm_state & SPM_STATE_JCOP_DWNLD) ||
        (current_spm_state & SPM_STATE_WIRED))
      return ESESTATUS_BUSY;

    status = phNxpEse_setJcopDwnldState(JCP_DWNLD_INIT);
    if (status == ESESTATUS_SUCCESS) {
      while (ese_dwnld_retry < ESE_JCOP_OS_DWNLD_RETRY_CNT) {
        HISI_PRINT_ERROR( "ESE_JCOP_OS_DWNLD_RETRY_CNT retry count");
        wSpmStatus = phNxpEse_SPM_GetState(&current_spm_state);
        if (wSpmStatus == ESESTATUS_SUCCESS) {
          if ((current_spm_state & SPM_STATE_JCOP_DWNLD)) {
            status = ESESTATUS_SUCCESS;
            break;
          }
        } else {
          status = ESESTATUS_FAILED;
          break;
        }
        phNxpEse_Sleep(
            200000); /*sleep for 200 ms checking for jcop dwnld status*/
        ese_dwnld_retry++;
      }
    }
  }

  HISI_PRINT_ERROR( "phNxpEse_checkJcopDwnldState status %x", status);
  return status;
  #endif
}
#endif

/******************************************************************************
 * Function         phNxpEse_Transceive
 *
 * Description      This function update the len and provided buffer
 *
 * Returns          On Success ESESTATUS_SUCCESS else proper error code
 *
 ******************************************************************************/
ESESTATUS phNxpEse_Transceive(phNxpEse_data* pCmd, phNxpEse_data* pRsp) {
  ESESTATUS status = ESESTATUS_FAILED;

  if ((NULL == pCmd) || (NULL == pRsp)) return ESESTATUS_INVALID_PARAMETER;

  if ((pCmd->len == 0) || pCmd->p_data == NULL) {
    HISI_PRINT_ERROR(" phNxpEse_Transceive - Invalid Parameter no data\n");
    return ESESTATUS_INVALID_PARAMETER;
  } else if (pCmd->len > MAX_SUPPORTED_DATA_SIZE) {
    HISI_PRINT_ERROR(" phNxpEse_Transceive - Invalid data size \n");
    return ESESTATUS_INVALID_RECEIVE_LENGTH;
  } else if ((ESE_STATUS_CLOSE == nxpese_ctxt.EseLibStatus)) {
    HISI_PRINT_ERROR(" %s ESE Not Initialized \n", __FUNCTION__);
    return ESESTATUS_NOT_INITIALISED;
  } else if ((ESE_STATUS_BUSY == nxpese_ctxt.EseLibStatus)) {
    HISI_PRINT_ERROR(" %s ESE - BUSY \n", __FUNCTION__);
    return ESESTATUS_BUSY;
  } else if ((ESE_STATUS_RECOVERY == nxpese_ctxt.EseLibStatus)) {
    HISI_PRINT_ERROR(" %s ESE - RECOVERY \n", __FUNCTION__);
    return ESESTATUS_REVOCERY_STARTED;
  } else {
    nxpese_ctxt.EseLibStatus = ESE_STATUS_BUSY;
    status = phNxpEseProto7816_Transceive((phNxpEse_data*)pCmd,
                                           (phNxpEse_data*)pRsp);
    if (ESESTATUS_SUCCESS != status) {
      HISI_PRINT_ERROR(" %s phNxpEseProto7816_Transceive- Failed \n", __FUNCTION__);
      if (ESESTATUS_TRANSCEIVE_FAILED == status) {
        /*MAX WTX reached*/
        nxpese_ctxt.EseLibStatus = ESE_STATUS_RECOVERY;
      } else {
        /*Timeout/ No response*/
        nxpese_ctxt.EseLibStatus = ESE_STATUS_IDLE;
      }
    } else {
      nxpese_ctxt.EseLibStatus = ESE_STATUS_IDLE;
    }
    nxpese_ctxt.rnack_sent = false;

    HISI_PRINT_INFO( " %s Exit status 0x%x \n", __FUNCTION__,
             status);
    return status;
  }
}
/******************************************************************************
 * Function         phNxpEse_coldReset
 *
 * Description      This function power cycles the ESE
 *                  (cold reset by prop. FW command) interface by
 *                  talking to NFC HAL
 *
 *                  Note:
 *                  After cold reset, phNxpEse_init need to be called to
 *                  reset the host AP T=1 stack parameters
 *
 * Returns          It returns ESESTATUS_SUCCESS (0) if the operation is
 *successful else
 *                  ESESTATUS_FAILED(1)
 ******************************************************************************/
ESESTATUS phNxpEse_coldReset(void) {
  ESESTATUS wSpmStatus = ESESTATUS_SUCCESS;
  HISI_PRINT_INFO( " %s Enter \n", __FUNCTION__);
  /*if (GET_CHIP_OS_VERSION() != OS_VERSION_4_0) {
    wSpmStatus = phNxpEse_SPM_ConfigPwr(SPM_RECOVERY_RESET);
  } else {
    wSpmStatus = ESESTATUS_FAILED;
    HISI_PRINT_ERROR(" %s Function not supported \n", __FUNCTION__);
  }*/
  HISI_PRINT_INFO( " %s Exit status 0x%x \n", __FUNCTION__,
           wSpmStatus);
  return wSpmStatus;
}

/******************************************************************************
 * Function         phNxpEse_reset
 *
 * Description      This function reset the ESE interface and free all
 *
 * Returns          It returns ESESTATUS_SUCCESS (0) if the operation is
 *successful else
 *                  ESESTATUS_FAILED(1)
 ******************************************************************************/
ESESTATUS phNxpEse_reset(void) {
  ESESTATUS status = ESESTATUS_FAILED;
  unsigned long maxTimer = 0;
#ifdef SPM_INTEGRATED
  ESESTATUS wSpmStatus = ESESTATUS_SUCCESS;
#endif

  /* TBD : Call the ioctl to reset the ESE */
  HISI_PRINT_INFO( " %s Enter \n", __FUNCTION__);
  /* Do an interface reset, don't wait to see if JCOP went through a full power
   * cycle or not */
  status = phNxpEseProto7816_IntfReset(
      (phNxpEseProto7816SecureTimer_t*)&nxpese_ctxt.secureTimerParams);
  if (!status) {
    HISI_PRINT_ERROR("%s Ese status Failed", __FUNCTION__);
  }

  HISI_PRINT_INFO(
           "%s secureTimer1 0x%x secureTimer2 0x%x secureTimer3 0x%x",
           __FUNCTION__, nxpese_ctxt.secureTimerParams.secureTimer1,
           nxpese_ctxt.secureTimerParams.secureTimer2,
           nxpese_ctxt.secureTimerParams.secureTimer3);
  phNxpEse_GetMaxTimer(&maxTimer);
#ifdef SPM_INTEGRATED
  if (GET_CHIP_OS_VERSION() == OS_VERSION_4_0) {
    status = phNxpEse_SPM_DisablePwrControl(maxTimer);
    if (status != ESESTATUS_SUCCESS) {
      HISI_PRINT_ERROR("%s phNxpEse_SPM_DisablePwrControl: failed", __FUNCTION__);
    }
  }
  if ((nxpese_ctxt.pwr_scheme == PN67T_POWER_SCHEME) ||
      (nxpese_ctxt.pwr_scheme == PN80T_LEGACY_SCHEME)) {
    wSpmStatus = phNxpEse_SPM_ConfigPwr(SPM_POWER_RESET);
    if (wSpmStatus != ESESTATUS_SUCCESS)
    HISI_PRINT_ERROR("phNxpEse_SPM_ConfigPwr: reset Failed");
  }
#else
  /* if arg ==2 (hard reset)
   * if arg ==1 (soft reset)
   */
  status = phPalEse_ioctl(phPalEse_e_ResetDevice, nxpese_ctxt.pDevHandle, 2);
  if (status != ESESTATUS_SUCCESS) {
    HISI_PRINT_ERROR("phNxpEse_reset Failed");
  }
#endif
  HISI_PRINT_INFO( " %s Exit \n", __FUNCTION__);
  return status;
}

/******************************************************************************
 * Function         phNxpEse_resetJcopUpdate
 *
 * Description      This function reset the ESE interface during JCOP Update
 *
 * Returns          It returns ESESTATUS_SUCCESS (0) if the operation is
 *successful else
 *                  ESESTATUS_FAILED(1)
 ******************************************************************************/
ESESTATUS phNxpEse_resetJcopUpdate(void) {
  ESESTATUS status = ESESTATUS_SUCCESS;
#ifdef SPM_INTEGRATED
  unsigned long int num = 0;
#endif

  /* TBD : Call the ioctl to reset the  */
  HISI_PRINT_INFO( " %s Enter \n", __FUNCTION__);

  /* Reset interface after every reset irrespective of
  whether JCOP did a full power cycle or not. */
  status = phNxpEseProto7816_Reset();
  /* Retrieving the IFS-D value configured in the config file and applying to Card */
  if (EseConfig_hasKey(NAME_NXP_ESE_IFSD_VALUE)) {
    unsigned long int ifsd_value = 0;
    ifsd_value = EseConfig_getUnsigned(NAME_NXP_ESE_IFSD_VALUE);
    if((0xFFFF > ifsd_value) &&
      (ifsd_value > 0)) {
      HISI_PRINT_INFO(
               "phNxpEseProto7816_SetIFS IFS adjustment requested with %ld",
               ifsd_value);
      phNxpEse_setIfs(ifsd_value);
    } else {
      HISI_PRINT_ERROR(
               "phNxpEseProto7816_SetIFS IFS adjustment argument invalid");
    }
  }
#ifdef SPM_INTEGRATED
#if (NXP_POWER_SCHEME_SUPPORT == true)
  if (EseConfig_hasKey(NAME_NXP_POWER_SCHEME)) {
    num = EseConfig_getUnsigned(NAME_NXP_POWER_SCHEME);
    if ((num == 1) || (num == 2)) {
      HISI_PRINT_ERROR( " %s Call Config Pwr Reset \n", __FUNCTION__);
      status = phNxpEse_SPM_ConfigPwr(SPM_POWER_RESET);
      if (status != ESESTATUS_SUCCESS) {
        HISI_PRINT_ERROR("phNxpEse_resetJcopUpdate: reset Failed");
        status = ESESTATUS_FAILED;
      }
    } else if (num == 3) {
      HISI_PRINT_ERROR( " %s Call eSE Chip Reset \n", __FUNCTION__);
      status = phNxpEse_chipReset();
      if (status != ESESTATUS_SUCCESS) {
        HISI_PRINT_ERROR("phNxpEse_resetJcopUpdate: chip reset Failed");
        status = ESESTATUS_FAILED;
      }
    } else {
      HISI_PRINT_ERROR( " %s Invalid Power scheme \n", __FUNCTION__);
    }
  }
#else
  {
    status = phNxpEse_SPM_ConfigPwr(SPM_POWER_RESET);
    if (status != ESESTATUS_SUCCESS) {
      HISI_PRINT_ERROR("phNxpEse_SPM_ConfigPwr: reset Failed");
      status = ESESTATUS_FAILED;
    }
  }
#endif
#else
  /* if arg ==2 (hard reset)
   * if arg ==1 (soft reset)
   */
  status = phPalEse_ioctl(phPalEse_e_ResetDevice, nxpese_ctxt.pDevHandle, 2);
  if (status != ESESTATUS_SUCCESS) {
    HISI_PRINT_ERROR("phNxpEse_resetJcopUpdate Failed");
  }
#endif

  HISI_PRINT_INFO( " %s Exit \n", __FUNCTION__);
  return status;
}
/******************************************************************************
 * Function         phNxpEse_EndOfApdu
 *
 * Description      This function is used to send S-frame to indicate
 *END_OF_APDU
 *
 * Returns          It returns ESESTATUS_SUCCESS (0) if the operation is
 *successful else
 *                  ESESTATUS_FAILED(1)
 *
 ******************************************************************************/
ESESTATUS phNxpEse_EndOfApdu(void) {
  ESESTATUS status = ESESTATUS_SUCCESS;
#if (NXP_ESE_END_OF_SESSION == true)
  status = phNxpEseProto7816_Close(
      (phNxpEseProto7816SecureTimer_t*)&nxpese_ctxt.secureTimerParams);
#endif
  return status;
}

/******************************************************************************
 * Function         phNxpEse_chipReset
 *
 * Description      This function is used to reset the ESE.
 *
 * Returns          Always return ESESTATUS_SUCCESS (0).
 *
 ******************************************************************************/
ESESTATUS phNxpEse_chipReset(void) {
  ESESTATUS status = ESESTATUS_FAILED;
  ESESTATUS bStatus = ESESTATUS_FAILED;
  if (nxpese_ctxt.pwr_scheme == PN80T_EXT_PMU_SCHEME) {
    bStatus = phNxpEseProto7816_Reset();
    if (!bStatus) {
      HISI_PRINT_ERROR("Inside phNxpEse_chipReset, phNxpEseProto7816_Reset Failed");
    }
    status = phPalEse_ioctl(phPalEse_e_ChipRst, nxpese_ctxt.pDevHandle, 6);
    if (status != ESESTATUS_SUCCESS) {
      HISI_PRINT_ERROR("phNxpEse_chipReset  Failed");
    }
  } else {
    HISI_PRINT_ERROR(
             "phNxpEse_chipReset is not supported in legacy power scheme");
  }
  return status;
}

 /******************************************************************************
 * Function         phNxpEse_GetOsMode
 *
 * Description      This function is used to get OS mode(JCOP/OSU)
 *
 * Returns          0x01 : JCOP_MODE
 *                  0x02 : OSU_MODE
 *
 ******************************************************************************/
phNxpEseProto7816_OsType_t phNxpEse_GetOsMode(void) {
  return phNxpEseProto7816_GetOsMode();
}

/******************************************************************************
 * Function         phNxpEse_deInit
 *
 * Description      This function de-initializes all the ESE protocol params
 *
 * Returns          Always return ESESTATUS_SUCCESS (0).
 *
 ******************************************************************************/
ESESTATUS phNxpEse_deInit(void) {
  ESESTATUS status = ESESTATUS_SUCCESS;
  unsigned long maxTimer = 0;
  unsigned long num = 0;
  /*TODO : to be removed after JCOP fix*/
  if (EseConfig_hasKey(NAME_NXP_VISO_DPD_ENABLED))
  {
      num = EseConfig_getUnsigned(NAME_NXP_VISO_DPD_ENABLED);
  }
  if(num == 0 && nxpese_ctxt.nadInfo.nadRx == EUICC_NAD_RX)
  {
      //do nothing
  }
  else
  {
    status = phNxpEseProto7816_Close(
          (phNxpEseProto7816SecureTimer_t*)&nxpese_ctxt.secureTimerParams);
    if (status == ESESTATUS_SUCCESS) {
      HISI_PRINT_INFO(
               "%s secureTimer1 0x%x secureTimer2 0x%x secureTimer3 0x%x",
               __FUNCTION__, nxpese_ctxt.secureTimerParams.secureTimer1,
               nxpese_ctxt.secureTimerParams.secureTimer2,
               nxpese_ctxt.secureTimerParams.secureTimer3);
      phNxpEse_GetMaxTimer(&maxTimer);
#ifdef SPM_INTEGRATED
      if (GET_CHIP_OS_VERSION() == OS_VERSION_4_0) {
        status = phNxpEse_SPM_DisablePwrControl(maxTimer);
        if (status != ESESTATUS_SUCCESS) {
          HISI_PRINT_ERROR("%s phNxpEseP61_DisablePwrCntrl: failed", __FUNCTION__);
        }
      }
#endif
    }
  }
  return status;
}

/******************************************************************************
 * Function         phNxpEse_close
 *
 * Description      This function close the ESE interface and free all
 *                  resources.
 *
 * Returns          Always return ESESTATUS_SUCCESS (0).
 *
 ******************************************************************************/
ESESTATUS phNxpEse_close(ESESTATUS deInitStatus) {
    ESESTATUS status = ESESTATUS_SUCCESS;
    (void)deInitStatus;
    HISI_PRINT_INFO( "phNxpEse_close Enter");
    if ((ESE_STATUS_CLOSE == nxpese_ctxt.EseLibStatus)) {
        HISI_PRINT_ERROR(" %s ESE Not Initialized \n", __FUNCTION__);
        return ESESTATUS_NOT_INITIALISED;
    }

#ifdef SPM_INTEGRATED
    ESESTATUS w_spm_status = ESESTATUS_SUCCESS;
#endif

#ifdef SPM_INTEGRATED
    /* Release the Access of  */
    w_spm_status = phNxpEse_SPM_ConfigPwr(SPM_POWER_DISABLE);
    if (w_spm_status != ESESTATUS_SUCCESS) {
        HISI_PRINT_ERROR("phNxpEse_SPM_ConfigPwr: disabling power Failed");
    } else {
        nxpese_ctxt.spm_power_state = false;
    }

    if (GET_CHIP_OS_VERSION() == OS_VERSION_4_0) {
        if (ESE_MODE_OSU == nxpese_ctxt.initParams.initMode) {
            status = phNxpEse_setJcopDwnldState(JCP_SPI_DWNLD_COMPLETE);
            if (status != ESESTATUS_SUCCESS)
            HISI_PRINT_ERROR("%s: phNxpEse_setJcopDwnldState failed", __FUNCTION__);
        }
    } else {
        if (NULL != nxpese_ctxt.pDevHandle) {
            if (ESE_PROTOCOL_MEDIA_SPI == nxpese_ctxt.initParams.mediaType) {
                HISI_PRINT_ERROR( "Inform eSE that trusted Mode is over");
                status = phPalEse_ioctl(phPalEse_e_SetSecureMode,
                                        nxpese_ctxt.pDevHandle, 0x00);
            }
            if (nxpese_ctxt.EseLibStatus == ESE_STATUS_RECOVERY ||
                (deInitStatus == ESESTATUS_RESPONSE_TIMEOUT) ||
                (ESESTATUS_SUCCESS != phNxpEseProto7816_CloseAllSessions())) {
                HISI_PRINT_ERROR( "eSE not responding perform hard reset");
                phNxpEse_SPM_ConfigPwr(SPM_RECOVERY_RESET);
            }
        }
    }

    w_spm_status = phNxpEse_SPM_DeInit();
    if (w_spm_status != ESESTATUS_SUCCESS)
    HISI_PRINT_ERROR("phNxpEse_SPM_DeInit Failed");
#endif
    if (NULL != nxpese_ctxt.pDevHandle) {
        phPalEse_close(nxpese_ctxt.pDevHandle);
        phNxpEse_memset(&nxpese_ctxt, 0x00, sizeof(nxpese_ctxt));
        HISI_PRINT_INFO(
                 "phNxpEse_close - ESE Context deinit completed");
    }
    /* Return success always */
    return status;
}

/******************************************************************************
 * Function         phNxpEse_read
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
ESESTATUS phNxpEse_read(uint32_t* data_len, uint8_t** pp_data) {
  ESESTATUS status = ESESTATUS_SUCCESS;
  int ret = -1;

  HISI_PRINT_INFO( "%s Enter", __FUNCTION__);

  ret = phNxpEse_readPacket(nxpese_ctxt.pDevHandle, nxpese_ctxt.p_read_buff,
                            MAX_DATA_LEN);
  if (ret < 0) {
    HISI_PRINT_ERROR("PAL Read status error status = %x", status);
    *data_len = 2;
    *pp_data = nxpese_ctxt.p_read_buff;
    status = ESESTATUS_FAILED;
  } else {
    PH_PAL_ESE_PRINT_PACKET_RX(nxpese_ctxt.p_read_buff, ret);
    *data_len = ret;
    *pp_data = nxpese_ctxt.p_read_buff;
    status = ESESTATUS_SUCCESS;
  }

  HISI_PRINT_INFO( "%s Exit", __FUNCTION__);
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
static int phNxpEse_readPacket(void* pDevHandle, uint8_t* pBuffer, int nNbBytesToRead)
{
    int ret = ESESTATUS_IOCTL_FAILED;
    int sofCounter = 0;
    int totalCount = 0;
    int numBytesToRead = 0;
    int headerIndex = 0;

    HISI_PRINT_INFO("%s Enter", __FUNCTION__);
    int maxSofCounter = 0;
    /* Max retry to get SOF in case of chaining */
    if (poll_sof_chained_delay == 1) {
        /* Wait Max for 1.3 sec before retry/recvoery */
        /* (max_sof_counter(1300) * 10 us) = 1.3 sec  */
        maxSofCounter = ESE_POLL_TIMEOUT * 10;
    } else { /* Max retry to get SOF in case of Non-chaining */
        /* wait based on config option */
        /* (nadPollingRetryTime * WAKE_UP_DELAY_SN1xx * NAD_POLLING_SCALER_SN1xx) */
        maxSofCounter = ((ESE_POLL_TIMEOUT * 1000) / (nxpese_ctxt.nadPollingRetryTime *
            GET_WAKE_UP_DELAY() * GET_NAD_POLLING_SCALER()));
    }
    if (nxpese_ctxt.rnack_sent) {
        phPalEse_sleep(nxpese_ctxt.invalidFrame_Rnack_Delay);
    }
    HISI_PRINT_INFO("read() max_sof_counter: %X ESE_POLL_TIMEOUT %2X",
        maxSofCounter, ESE_POLL_TIMEOUT);
    do {
        ret = ESESTATUS_IOCTL_FAILED;
        ret = phPalEse_read(pDevHandle, pBuffer, 2); /* read 2 bytes sof header */
        if (ret < 0) {
            /* Polling for read on spi, hence Debug log */
            HISI_PRINT_ERROR("_spi_read() [HDR]errno : %x ret : %X", errno, ret);
        }
        if ((pBuffer[0] == nxpese_ctxt.nadInfo.nadRx) ||
            (pBuffer[0] == RECIEVE_PACKET_SOF)) {
            /* Read the HEADR of one byte */
            HISI_PRINT_INFO("%s Read HDR SOF + PCB, pBuffer[0] = 0x%x, pBuffer[1] = 0x%x",
                __FUNCTION__, pBuffer[0], pBuffer[1]);
            numBytesToRead = 1; /* Read only INF LEN */
            headerIndex = 1;
            break;
        } else if (((pBuffer[0] == 0x00) || (pBuffer[0] == 0xFF)) &&
            ((pBuffer[1] == nxpese_ctxt.nadInfo.nadRx) ||
            (pBuffer[1] == RECIEVE_PACKET_SOF))) {
            /* Read the HEADR of Two bytes */
            HISI_PRINT_INFO("%s Read HDR only SOF", __FUNCTION__);
            pBuffer[0] = pBuffer[1];
            numBytesToRead = 2; /* Read PCB + INF LEN */
            headerIndex = 0;
            break;
        } else if (((pBuffer[0] == 0x00) && (pBuffer[1] == 0x00)) ||
            ((pBuffer[0] == 0xFF) && (pBuffer[1] == 0xFF))) { /* while read invalid header then continue */
            HISI_PRINT_DEBUG("_spi_read() Buf[0]: %X Buf[1]: %X", pBuffer[0], pBuffer[1]);
        } else if (ret >= 0) { /* Corruption happened during the receipt from Card, go flush out the data */
            HISI_PRINT_ERROR("_spi_read() Corruption Buf[0]: %X Buf[1]: %X ..len=%d",
                pBuffer[0], pBuffer[1], ret);
            break;
        }
        /* If it is Chained packet wait for 100 usec */
        if (poll_sof_chained_delay == 1) {
            HISI_PRINT_ERROR("%s Chained Pkt, delay read %dus",
                __FUNCTION__, GET_WAKE_UP_DELAY() * CHAINED_PKT_SCALER);
            phPalEse_sleep(GET_WAKE_UP_DELAY() * CHAINED_PKT_SCALER);
        } else {
            phPalEse_sleep(nxpese_ctxt.nadPollingRetryTime * GET_WAKE_UP_DELAY() *
                GET_NAD_POLLING_SCALER());
        }
        sofCounter++;
    } while (sofCounter < maxSofCounter);

    /* SOF Read timeout happened, go for frame retransmission */
    if (sofCounter == maxSofCounter) {
        ret = ESESTATUS_IOCTL_FAILED;
    }
    if ((pBuffer[0] == nxpese_ctxt.nadInfo.nadRx) ||
        (pBuffer[0] == RECIEVE_PACKET_SOF)) {
        HISI_PRINT_INFO("%s SOF FOUND, headerIndex = 0x%x, numBytesToRead = 0x%x", __FUNCTION__,
            headerIndex, numBytesToRead);
        /* Read the HEADR of one/Two bytes based on how two bytes read A5 PCB or * 00 A5 */
        if ((1 + headerIndex > MAX_DATA_LEN) || (1 + headerIndex + numBytesToRead > MAX_DATA_LEN)) {
            ret = ESESTATUS_IOCTL_FAILED;
            HISI_PRINT_ERROR("%s buffer is overflow", __FUNCTION__, ret);
            return ret;
        }
        ret = phPalEse_read(pDevHandle, &pBuffer[1 + headerIndex], numBytesToRead);
        if (ret < 0) {
            HISI_PRINT_ERROR("_spi_read() [HDR]errno : %x ret : %X", errno, ret);
        }
        if ((pBuffer[1] == CHAINED_PACKET_WITHOUTSEQN) ||
            (pBuffer[1] == CHAINED_PACKET_WITHSEQN)) {
            poll_sof_chained_delay = 1; // is chained data
            HISI_PRINT_INFO("poll_sof_chained_delay value is %d ", poll_sof_chained_delay);
        } else {
            poll_sof_chained_delay = 0; // not chained data
            HISI_PRINT_INFO("poll_sof_chained_delay value is %d ", poll_sof_chained_delay);
        }
        totalCount = 3;
        uint8_t pcb;
        phNxpEseProto7816_PCB_bits_t pcb_bits;
        pcb = pBuffer[PH_PROPTO_7816_PCB_OFFSET];
        HISI_PRINT_INFO("%s pBuffer[PH_PROPTO_7816_PCB_OFFSET] = 0x%x", __FUNCTION__,
            pBuffer[PH_PROPTO_7816_PCB_OFFSET]);

        (void)memset_s(&pcb_bits, sizeof(phNxpEseProto7816_PCB_bits_t), 0x00, sizeof(phNxpEseProto7816_PCB_bits_t));
        if (memcpy_s(&pcb_bits, sizeof(pcb_bits), &pcb, sizeof(uint8_t)) != EOK) {
            ret = ESESTATUS_IOCTL_FAILED;
            HISI_PRINT_ERROR("%s memcpy_s is fail", __FUNCTION__, ret);
            return ret;
        }

        /* For I-Frame Only */
        HISI_PRINT_INFO("%s pcb_bits.msb=0x%x, pBuffer[2] = 0x%x", __FUNCTION__, pcb_bits.msb, pBuffer[2]);
        if (0 == pcb_bits.msb) {
        /* length is one or two bytes by read pBuffer[2] */
            if (pBuffer[2] != EXTENDED_FRAME_MARKER) {
                nNbBytesToRead = pBuffer[2];
                headerIndex = 3; /* include sof pcb and length */
            } else { /* length is two bytes, are pBuffer[3] and pBuffer[4] */
                ret = phPalEse_read(pDevHandle, &pBuffer[3], 2);
                if (ret < 0) {
                    HISI_PRINT_ERROR("_spi_read() [HDR]errno : %x ret : %X", errno, ret);
                }
                HISI_PRINT_INFO("_spi_read() %d, pBuffer[3] = 0x%x, pBuffer[4] = 0x%x, total_count = 0x%x",
                    ret, pBuffer[3], pBuffer[4], totalCount);
                nNbBytesToRead = (pBuffer[3] << 8);
                nNbBytesToRead = nNbBytesToRead | pBuffer[4];
                totalCount += 2;
                headerIndex = 5;
            }
        } else { /* For Non-IFrame, only pBuffer[2] is length field */
            nNbBytesToRead = pBuffer[2];
            headerIndex = 3;
        }
        /* Read the Complete data + one byte CRC */
        if ((headerIndex > MAX_DATA_LEN) || (headerIndex + nNbBytesToRead + 1 > MAX_DATA_LEN)) {
            ret = ESESTATUS_IOCTL_FAILED;
            HISI_PRINT_ERROR("%s buffer is overflow", __FUNCTION__, ret);
            return ret;
        }
        ret = phPalEse_read(pDevHandle, &pBuffer[headerIndex], (nNbBytesToRead + 1));
        if (ret < 0) {
            HISI_PRINT_ERROR("_spi_read() [HDR]errno : %x ret : %X", errno, ret);
            ret = ESESTATUS_IOCTL_FAILED;
        } else {
            ret = (totalCount + (nNbBytesToRead + 1));
            /* If I-Frame received with invalid length respond with RNACK */
            if ((pcb_bits.msb == 0) && ((nNbBytesToRead == 0) ||
                (nNbBytesToRead > phNxpEseProto7816_GetIfs()))) {
                HISI_PRINT_ERROR("I-Frame with invalid len == %d", nNbBytesToRead);
                pBuffer[0] = 0x90;
                pBuffer[1] = RECIEVE_PACKET_SOF;
                ret = 0x02;
            }
        }
        nxpese_ctxt.rnack_sent = false;
    } else if (ret < 0) {
        /* In case of IO Error */
        ret = -2;
        pBuffer[0] = 0x64;
        pBuffer[1] = 0xFF;
    } else { /* Received corrupted frame: Flushing out data in the Rx buffer so that Card can switch the  mode */
        uint16_t ifsd_size = phNxpEseProto7816_GetIfs();
        uint32_t total_frame_size = 0;
        HISI_PRINT_ERROR("_spi_read() corrupted, IFSD size=%d flushing it out!!", ifsd_size);
        /* If a non-zero byte is received while polling for NAD byte and the byte
         * is not a valid NAD byte (0xA5 or 0xB4): 1)  Read & discard (without
         * de-asserting SPI CS line) : a.  Max IFSD size + 5 (remaining four
         * prologue + one LRC bytes) bytes from eSE  if max IFS size is greater
         * than 254 bytes OR b.  Max IFSD size + 3 (remaining two prologue + one
         * LRC bytes) bytes from eSE  if max IFS size is less than 255 bytes.
         * 2) Send R-NACK to request eSE to re-transmit the frame
         */

        if (ifsd_size > IFSC_SIZE_SEND) {
            total_frame_size = ifsd_size + 4;
        } else {
            total_frame_size = ifsd_size + 2;
        }
        nxpese_ctxt.rnack_sent = true;
        phPalEse_sleep(nxpese_ctxt.invalidFrame_Rnack_Delay);
        if (2 + total_frame_size > MAX_DATA_LEN) {
            ret = ESESTATUS_IOCTL_FAILED;
            HISI_PRINT_ERROR("%s buffer is overflow", __FUNCTION__, ret);
            return ret;
        }
        ret = phPalEse_read(pDevHandle, &pBuffer[2], total_frame_size);
        if (ret < 0) {
            HISI_PRINT_ERROR("_spi_read() [HDR]errno : %x ret : %X", errno, ret);
        } else { /* LRC fail expected for this frame to send R-NACK */
            ret = total_frame_size + 2;
            HISI_PRINT_ERROR("_spi_read() SUCCESS  ret : %X LRC fail excpected for this frame", ret);
            PH_PAL_ESE_PRINT_PACKET_RX(pBuffer, ret);
        }
        pBuffer[0] = 0x90;
        pBuffer[1] = RECIEVE_PACKET_SOF;
        ret = 0x02;
        phPalEse_sleep(nxpese_ctxt.invalidFrame_Rnack_Delay);
    }
    HISI_PRINT_INFO("%s Exit ret = %d", __FUNCTION__, ret);
    return ret;
}

/******************************************************************************
 * Function         phNxpEse_WriteFrame
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
ESESTATUS phNxpEse_WriteFrame(uint32_t data_len, uint8_t* p_data) {
  ESESTATUS status = ESESTATUS_INVALID_PARAMETER;
  int32_t dwNoBytesWrRd = 0;
  HISI_PRINT_INFO( "Enter %s ", __FUNCTION__);

  {
    p_data[0] = ESE_NAD_TX;
  }
  /* Create local copy of cmd_data */
  phNxpEse_memcpy(nxpese_ctxt.p_cmd_data, p_data, data_len);
  nxpese_ctxt.cmd_len = data_len;

  dwNoBytesWrRd = phPalEse_write(nxpese_ctxt.pDevHandle, nxpese_ctxt.p_cmd_data,
                                 nxpese_ctxt.cmd_len);
  if (-1 == dwNoBytesWrRd) {
    HISI_PRINT_ERROR(" - Error in SPI Write.....%d\n", errno);
    status = ESESTATUS_FAILED;
  } else {
    status = ESESTATUS_SUCCESS;
    PH_PAL_ESE_PRINT_PACKET_TX(nxpese_ctxt.p_cmd_data, nxpese_ctxt.cmd_len);
  }

  HISI_PRINT_INFO( "Exit %s status %x\n", __FUNCTION__, status);
  return status;
}

/******************************************************************************
 * Function         phNxpEse_getAtr
 *
 * Description      This function retrieves ATR bytes from 7816-3 layer
 *Update.
 *
 * Returns          It returns ESESTATUS_SUCCESS (0) if write successful else
 *                  ESESTATUS_FAILED(1
 *
 ******************************************************************************/
ESESTATUS phNxpEse_getAtr(phNxpEse_data* pATR) {
    ESESTATUS status = ESESTATUS_FAILED;
    (void)pATR;
    HISI_PRINT_INFO(" %s - Function not supported\n", __FUNCTION__);
    return status;
}

/******************************************************************************
 * Function         phNxpEse_setIfs
 *
 * Description      This function sets the IFS size to 240/254 support JCOP OS
 *Update.
 *
 * Returns          Always return ESESTATUS_SUCCESS (0).
 *
 ******************************************************************************/
ESESTATUS phNxpEse_setIfs(uint16_t IFS_Size) {
  phNxpEseProto7816_SetIfs(IFS_Size);
  return ESESTATUS_SUCCESS;
}

/******************************************************************************
 * Function         phNxpEse_Sleep
 *
 * Description      This function  suspends execution of the calling thread for
 *           (at least) usec microseconds
 *
 * Returns          Always return ESESTATUS_SUCCESS (0).
 *
 ******************************************************************************/
ESESTATUS phNxpEse_Sleep(uint32_t usec) {
  phPalEse_sleep(usec);
  return ESESTATUS_SUCCESS;
}

/******************************************************************************
 * Function         phNxpEse_memset
 *
 * Description      This function updates destination buffer with val
 *                  data in len size
 *
 * Returns          Always return ESESTATUS_SUCCESS (0).
 *
 ******************************************************************************/
void* phNxpEse_memset(void* buff, int val, unsigned int len) {
  return phPalEse_memset(buff, val, len);
}

/******************************************************************************
 * Function         phNxpEse_memcpy
 *
 * Description      This function copies source buffer to  destination buffer
 *                  data in len size
 *
 * Returns          Return pointer to allocated memory location.
 *
 ******************************************************************************/
void* phNxpEse_memcpy(void* dest, const void* src, unsigned int len) {
  return phPalEse_memcpy(dest, src, len);
}

/******************************************************************************
 * Function         phNxpEse_Memalloc
 *
 * Description      This function allocation memory
 *
 * Returns          Return pointer to allocated memory or NULL.
 *
 ******************************************************************************/
void* phNxpEse_memalloc(uint32_t size) {
  return phPalEse_memalloc(size);
  ;
}

/******************************************************************************
 * Function         phNxpEse_calloc
 *
 * Description      This is utility function for runtime heap memory allocation
 *
 * Returns          Return pointer to allocated memory or NULL.
 *
 ******************************************************************************/
void* phNxpEse_calloc(unsigned int datatype, unsigned int size) {
  return phPalEse_calloc(datatype, size);
}

/******************************************************************************
 * Function         phNxpEse_free
 *
 * Description      This function de-allocation memory
 *
 * Returns         void.
 *
 ******************************************************************************/
void phNxpEse_free(void* ptr) { return phPalEse_free(ptr); }

/******************************************************************************
 * Function         phNxpEse_GetMaxTimer
 *
 * Description      This function finds out the max. timer value returned from
 *JCOP
 *
 * Returns          void.
 *
 ******************************************************************************/
static void phNxpEse_GetMaxTimer(unsigned long* pMaxTimer) {
  /* Finding the max. of the timer value */
  *pMaxTimer = nxpese_ctxt.secureTimerParams.secureTimer1;
  if (*pMaxTimer < nxpese_ctxt.secureTimerParams.secureTimer2)
    *pMaxTimer = nxpese_ctxt.secureTimerParams.secureTimer2;
  *pMaxTimer = (*pMaxTimer < nxpese_ctxt.secureTimerParams.secureTimer3)
                   ? (nxpese_ctxt.secureTimerParams.secureTimer3)
                   : *pMaxTimer;

  /* Converting timer to millisecond from sec */
  *pMaxTimer = SECOND_TO_MILLISECOND(*pMaxTimer);
  /* Add extra 5% to the timer */
  *pMaxTimer +=
      CONVERT_TO_PERCENTAGE(*pMaxTimer, ADDITIONAL_SECURE_TIME_PERCENTAGE);
  HISI_PRINT_INFO( "%s Max timer value = %lu", __FUNCTION__,
           *pMaxTimer);
  return;
}

/******************************************************************************
 * Function         phNxpEseP61_DisablePwrCntrl
 *
 * Description      This function disables eSE GPIO power off/on control
 *                  when enabled
 *
 * Returns         SUCCESS/FAIL.
 *
 ******************************************************************************/
ESESTATUS phNxpEse_DisablePwrCntrl(void) {
  ESESTATUS status = ESESTATUS_SUCCESS;
  unsigned long maxTimer = 0;
  HISI_PRINT_INFO("%s Enter", __FUNCTION__);
  phNxpEse_GetMaxTimer(&maxTimer);
  {
    HISI_PRINT_INFO("%s phNxpEseP61_DisablePwrCntrl: not supported", __FUNCTION__);
    status = ESESTATUS_FAILED;
  }
  return status;
}

/******************************************************************************
 * Function         phNxpEse_getOsVersion
 *
 * Description      This function returns OS version from config file &
 *                  runtime from ATR response
 *
 * Returns         SUCCESS/FAIL.
 *
 ******************************************************************************/
int phNxpEse_getOsVersion() { return sOsVersion; }

/******************************************************************************
 * Function         phNxpEse_setOsVersion
 *
 * Description      This function sets chip type based on ATR response
 *
 * Returns         None.
 *
 ******************************************************************************/
void phNxpEse_setOsVersion(int chipType) { sOsVersion = chipType; }

#ifdef SPM_INTEGRATED
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
  HISI_PRINT_INFO( "phNxpEse_checkFWDwnldStatus Enter");
  return ESESTATUS_SUCCESS;
}
#endif
/******************************************************************************
 * Function         phNxpEse_GetEseStatus(unsigned char *timer_buffer)
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
ESESTATUS phNxpEse_GetEseStatus(phNxpEse_data* timer_buffer) {
  ESESTATUS status = ESESTATUS_FAILED;

  phNxpEse_SecureTimer_t secureTimerParams;
  uint8_t* temp_timer_buffer = NULL;
  HISI_PRINT_INFO( "%s Enter", __FUNCTION__);
 /* if (GET_CHIP_OS_VERSION() != OS_VERSION_4_0) {
    HISI_PRINT_ERROR("%s function not supported", __FUNCTION__);
    return status;
  }*/
  if (timer_buffer != NULL) {
    timer_buffer->len =
        (sizeof(secureTimerParams.secureTimer1) +
         sizeof(secureTimerParams.secureTimer2) +
         sizeof(secureTimerParams.secureTimer3)) +
        PH_PROPTO_7816_FRAME_LENGTH_OFFSET * PH_PROPTO_7816_FRAME_LENGTH_OFFSET;
    temp_timer_buffer = (uint8_t*)phNxpEse_memalloc(timer_buffer->len);
    timer_buffer->p_data = temp_timer_buffer;

    phNxpEse_memcpy(&secureTimerParams, &nxpese_ctxt.secureTimerParams,
                    sizeof(phNxpEse_SecureTimer_t));

    HISI_PRINT_INFO(
        "%s secureTimer1 0x%x secureTimer2 0x%x secureTimer3 0x%x len = %d",
        __FUNCTION__, secureTimerParams.secureTimer1,
        secureTimerParams.secureTimer2, secureTimerParams.secureTimer3,
        timer_buffer->len);

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
  } else {
    HISI_PRINT_ERROR("%s Invalid timer buffer ", __FUNCTION__);
  }

  HISI_PRINT_INFO( "%s Exit status = 0x%x", __FUNCTION__, status);
  return status;
}

static unsigned char* phNxpEse_GgetTimerTlvBuffer(uint8_t* timer_buffer,
                                                  unsigned int value) {
  short int count = 0, shift = 3;
  unsigned int mask = 0x000000FF;
  {
    HISI_PRINT_ERROR( "value = %x \n", value);
    for (count = 0; count < 4; count++) {
      if (timer_buffer != NULL) {
        *timer_buffer = (value >> (shift * 8) & mask);
        HISI_PRINT_INFO( "*timer_buffer=0x%x shift=0x%x",
                *timer_buffer, shift);
        timer_buffer++;
        shift--;
      } else {
        break;
      }
    }
  }
  return timer_buffer;
}
