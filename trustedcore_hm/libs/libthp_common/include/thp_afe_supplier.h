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


#ifdef __cplusplus
extern "C" {
#endif

#include "thp_afe.h"

/******************************************************************************
* Function: thp_afe_hal_spec_version()
****************************************************************************//**
* @summary
*   Return THP AFE HAL spec version.
*
* @return
*   THP AFE HAL spec version which is defined by THP_AFE_HAL_SPEC_VERSION macro
*
* @par Notes
*   THP AFE HAL spec version follows Semantic Versioning 2.0.0 spec, 
*   refer to http://semver.org/ for details.
*   version = major*65536 + minor*256 + patch
*
*****************************************************************************/

uint32_t afe_tui_fun_wrapper(thp_afe_hal_spec_version)(void);

/******************************************************************************
* Function: thp_afe_hal_spec_major_version()
****************************************************************************//**
* @summary
*   Return THP AFE HAL spec major version.
*
* @return
*   THP AFE HAL spec major version which is defined by 
*   THP_AFE_HAL_SPEC_MAJOR_VERSION macro
*
* @par Notes
*   THP AFE HAL spec version follows Semantic Versioning 2.0.0 spec, 
*   refer to http://semver.org/ for details.
*   version = major*65536 + minor*256 + patch
*
*****************************************************************************/
uint8_t afe_tui_fun_wrapper(thp_afe_hal_spec_major_version)(void);

/******************************************************************************
* Function: thp_afe_hal_spec_minor_version()
****************************************************************************//**
* @summary
*   Return THP AFE HAL spec minor version.
*
* @return
*   THP AFE HAL spec minor version which is defined by 
*   THP_AFE_HAL_SPEC_MINOR_VERSION macro
*
* @par Notes
*   THP AFE HAL spec version follows Semantic Versioning 2.0.0 spec, 
*   refer to http://semver.org/ for details.
*   version = major*65536 + minor*256 + patch
*
*****************************************************************************/
uint8_t afe_tui_fun_wrapper(thp_afe_hal_spec_minor_version)(void);

/******************************************************************************
* Function: thp_afe_hal_spec_patch_version()
****************************************************************************//**
* @summary
*   Return THP AFE HAL spec patch version.
*
* @return
*   THP AFE HAL spec patch version which is defined by 
*   THP_AFE_HAL_SPEC_PATCH_VERSION macro
*
* @par Notes
*   THP AFE HAL spec version follows Semantic Versioning 2.0.0 spec, 
*   refer to http://semver.org/ for details.
*   version = major*65536 + minor*256 + patch
*
*****************************************************************************/
uint8_t afe_tui_fun_wrapper(thp_afe_hal_spec_patch_version)(void);

/******************************************************************************
* Function: thp_afe_open()
****************************************************************************//**
* @summary
*   Creates an instance of AFE library for default project. 
*   This is the entry point to AFE library.
*   No other APIs can be used before this API call.
*
* @return
*   THP_AFE_ERR_ENUM
*
*****************************************************************************/
THP_AFE_ERR_ENUM afe_tui_fun_wrapper(thp_afe_open)(void);

/******************************************************************************
* Function: thp_afe_open_project()
****************************************************************************//**
* @summary
*   Creates an instance of AFE library for project specified by proj_id. 
*   This is the entry point to AFE library.
*   No other APIs can be used before this API call.
*
* @param proj_id
*   proj_id is 10 characters string to identify different TP modules.
*
* @return
*   THP_AFE_ERR_ENUM
*
*****************************************************************************/
THP_AFE_ERR_ENUM afe_tui_fun_wrapper(thp_afe_open_project)(const char* proj_id);

/******************************************************************************
* Function: thp_afe_close()
****************************************************************************//**
* @summary
*   Releases AFE.
*
* @return
*   THP_AFE_ERR_ENUM
*
*****************************************************************************/
THP_AFE_ERR_ENUM afe_tui_fun_wrapper(thp_afe_close)(void);

/******************************************************************************
* Function: thp_afe_start()
****************************************************************************//**
* @summary
*   Start AFE. Upon successful return, AFE is powered on and initialized to
*   work in default mode.
*
* @return
*   THP_AFE_ERR_ENUM
*
* @par Notes
*   Before calling the_afe_start, thp_afe_set_calib_data_callback_func()
*   should be called properly.
*
*****************************************************************************/
THP_AFE_ERR_ENUM afe_tui_fun_wrapper(thp_afe_start)(void);

/******************************************************************************
* Function: thp_afe_stop()
****************************************************************************//**
* @summary
*   Stop AFE operation and power off AFE.
*
* @return
*   THP_AFE_ERR_ENUM
*
*****************************************************************************/
THP_AFE_ERR_ENUM afe_tui_fun_wrapper(thp_afe_stop)(void);

/******************************************************************************
* Function: thp_afe_get_info()
****************************************************************************//**
* @summary
*   Returns information about the AFE and AFE library, such as vendor name,
*   product name and AFE version.
*
* @return
*   pointer to AFE information
*
*****************************************************************************/
THP_AFE_INFO_STRUCT* afe_tui_fun_wrapper(thp_afe_get_info)(void);

/******************************************************************************
* Function: thp_afe_get_hw_cap()
****************************************************************************//**
* @summary
*   Returns capabilities of the AFE, such as number of col/row, pitch size,
*    whether frequency shift is supported, etc.
*
* @return
*   pointer to hardware capability information
*
*****************************************************************************/
THP_AFE_HW_CAP_STRUCT* afe_tui_fun_wrapper(thp_afe_get_hw_cap)(void);

/******************************************************************************
* Function: thp_afe_get_frame()
****************************************************************************//**
* @summary
*   Retrieves grid data, button data, AFE status etc.
*
* @return
*   pointer to frame data
*
* @par Notes
*   This API is a blocking call, AFE should provide a timeout mechanism.
*   When this API is blocking, if thp_afe_screen_off is called, 
*   this API should return NULL immediately;
*   Please note that the content of frame data buffer should not be changed
*   until thp_afe_get_frame() getting called next time.
*****************************************************************************/
THP_AFE_FRAME_DATA_STRUCT* afe_tui_fun_wrapper(thp_afe_get_frame)(void);

/******************************************************************************
* Function: thp_afe_set_calib_data_callback_func()
****************************************************************************//**
* @summary
*   Set call back function to save calibration data, after each calibration, 
*   AFE should call the callback function to save calibration data.
*
* @return
*   THP_AFE_ERR_ENUM
*
* @param 
*   calibDataWriteCallback: call back funtion to save calibration data
*   calibDataReadCallback: call back funtion to load calibration data
*
* @par Notes
*   1. This API is designed for the AFE which has no space 
*      to save calibration data on silicon;
*   2. this API should be called before thp_afe_start;
*   3. if the return value of calibDataReadCallback() is not THP_AFE_OK, 
*      which indicates the calibration data is broken or missing, 
*      AFE need re-do calibration and save calibration data; 
*
*****************************************************************************/
THP_AFE_ERR_ENUM afe_tui_fun_wrapper(thp_afe_set_calib_data_callback_func)
(THP_AFE_ERR_ENUM(*calibDataWriteCallback)(void* dataPtr, uint32_t dataLen), 
 THP_AFE_ERR_ENUM(*calibDataReadCallback)(void* dataPtr, uint32_t dataLen)); 

/******************************************************************************
* Function: thp_afe_clear_status()
****************************************************************************//**
* @summary
*   Clear the specified status.
*
* @return
*   THP_AFE_ERR_ENUM
*
* @param status
*   Specify which status to clear
*
* @par Notes
*   Refer to thp_afe_start_calibration() and thp_afe_start_freq_shift() for more info.
*
*****************************************************************************/
THP_AFE_ERR_ENUM afe_tui_fun_wrapper(thp_afe_clear_status)(THP_AFE_STATUS_ENUM status);

/******************************************************************************
* Function: thp_afe_set_log_callback_func()
****************************************************************************//**
* @summary
*   Set log call back function to AFE, AFE should output all the log
*   to the log callback function.
*
* @return
*   THP_AFE_ERR_ENUM
*
* @param void(*)(const char *)
*   AFE log call back funtion
*
* @par Notes
*   The suggested log format is: LogLevel+TimeStamp+FunctionName+LogContent,
*   for example: [I][1473384419770][thp_afe_hal_funcion] log-content;
*   TimeStamp = tv.tv_sec * 1000 + tv.tv_usec / 1000;
*   tv is the system timeval which could be obtained from system.
*
*****************************************************************************/
THP_AFE_ERR_ENUM afe_tui_fun_wrapper(thp_afe_set_log_callback_func)(void(*log_func)(const char *));

/******************************************************************************
* Function: thp_afe_set_log_level()
****************************************************************************//**
* @summary
*   Set log call back function to AFE, AFE should output all the log
*   to the log callback function.
*
* @return
*   THP_AFE_ERR_ENUM
*
* @par Notes
*   If this API is not called, AFE should have a default log level;
*   log level is defined as below:
*   THP_AFE_LOG_LEVEL_ERROR(1)
*   THP_AFE_LOG_LEVEL_WARNING(2)
*   THP_AFE_LOG_LEVEL_INFO(3)
*   THP_AFE_LOG_LEVEL_DEBUG(4)
*
*****************************************************************************/
THP_AFE_ERR_ENUM afe_tui_fun_wrapper(thp_afe_set_log_level)(uint8_t log_level);

/******************************************************************************
* Function: thp_afe_enable_wakeup_gesture()
****************************************************************************//**
* @summary
*   Inform AFE to enable wakeup gesture.
*
* @return
*   THP_AFE_ERR_ENUM
*
* @par Notes
*   After wakeup gesture being enabled, 
*   AFE should enter gesture mode automatically when screen off; 
*   It is AFE HAL/AFE¡¯s responsibility to detect gesture instead of caller.
*
*****************************************************************************/

#ifdef __cplusplus
}
#endif
