/***************************************************************************//**
* @file TSA_Lib.h
*
* This is TSA algorithm library header
*
* @version 1.0
*
* $DateTime: 2011/08/05 04:21:58 $
* $Change: 269709 $
* $Revision: #8 $
* $Author:  TSAlgLib@gmail.com $
*
*//*****************************************************************************
* Copyright (2013) , TSA Corporation. All Right Reserved.
*******************************************************************************/

#ifndef __TSA_LIB_H
#define __TSA_LIB_H

/*******************************************************************************
* header files including
*******************************************************************************/
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*******************************************************************************
* TSA Version Definition
*******************************************************************************/
/******************************************************************************/


/*******************************************************************************
* MACRO Definition
*******************************************************************************/
/******************************************************************************/


/*******************************************************************************
* Data Type Definition
*******************************************************************************/
#ifndef INT8U_DEFINED
typedef uint8_t  INT8U;       /* < Unsigned  8 bit quantity */
#define INT8U_DEFINED
typedef int8_t   INT8S;       /* < Signed    8 bit quantity */
typedef uint16_t INT16U;      /* < Unsigned 16 bit quantity */
typedef int16_t  INT16S;      /* < Signed   16 bit quantity */
typedef uint32_t INT32U;      /* < Unsigned 32 bit quantity */
typedef int32_t  INT32S;      /* < Signed   32 bit quantity */
typedef uint64_t INT64U;      /* < Unsigned 64 bit quantity */
typedef int64_t  INT64S;      /* < Signed   64 bit quantity */
#endif

#define INT8U_MAX       255
#define INT8U_MIN       0
#define INT8S_MAX       127
#define INT8S_MIN       -128
#define INT16U_MAX      65535
#define INT16U_MIN      0
#define INT16S_MAX      32767
#define INT16S_MIN      -32768
#define INT32U_MAX      0xFFFFFFFF
#define INT32U_MIN      0
#define INT32S_MAX      2147483647
#define INT32S_MIN     (-2147483647 - 1)
/******************************************************************************/


/*******************************************************************************
* Enum Data Definition
*******************************************************************************/
typedef enum {
    TSA_CTRL_NULL               = 0,
    TSA_CTRL_POWER_ON           = (1 << 0),     // 0x00000001
    TSA_CTRL_RESET              = (1 << 1),     // 0x00000002
    TSA_CTRL_WAKE_UP            = (1 << 2),     // 0x00000004
    TSA_CTRL_RE_CALIBRATION     = (1 << 3),     // 0x00000008
    TSA_CTRL_FREQ_HOPPED        = (1 << 4),     // 0x00000010
    TSA_CTRL_CHARGER_PLUGGED    = (1 << 5),     // 0x00000020
    TSA_CTRL_DEVICE_FLOATING    = (1 << 6),     // 0x00000040
    TSA_CTRL_ORIENTATION_ROTATED  = (1 << 7),   // 0x00000080
    TSA_CTRL_SCREEN_OFF         = (1 << 8),     // 0x00000100
    TSA_CTRL_GET_RAW            = (1 << 9),     // 0x00000200
    TSA_CTRL_GET_PRE_FILTERED_DIFF = (1 << 10), // 0x00000400
    TSA_CTRL_GET_BASELINE       = (1 << 11),    // 0x00000800
    TSA_CTRL_GET_BASELINE_LSB   = (1 << 12),    // 0x00001000
    TSA_CTRL_GET_DIFF           = (1 << 13),    // 0x00002000
    TSA_CTRL_SELF_PROCESS       = (1 << 14),    // 0x00004000
    TSA_CTRL_MUTUAL_PROCESS     = (1 << 15),    // 0x00008000
    TSA_CTRL_MUTUAL_DIFF        = (1 << 16),    // 0x00010000
    TSA_CTRL_ALL_FREQ_NOISY     = (1 << 17),    // 0x00020000
    TSA_CTRL_IN_PHONE_CALL      = (1 << 18),    // 0x00040000
    TSA_CTRL_FACTORY_MODE       = (1 << 19),    // 0x00080000
    TSA_CTRL_AUTO_TEST_MODE     = (1 << 20),    // 0x00100000
    TSA_CTRL_FINGER_PRINT_TOUCHED = (1 << 21),  // 0x00200000
} TSA_CTRL_ENUM;

typedef enum {
    TSA_TYPE_NULL              = 0,
    TSA_TYPE_SMALL             = (1 << 0),
    TSA_TYPE_NORMAL            = (1 << 1),
    TSA_TYPE_FAT               = (1 << 2),
    TSA_TYPE_MULTI             = (1 << 3)
} TSA_TYPE_ENUM;

/* value indicate priority */
typedef enum {
    TSA_EXCEPTION_NONE = 0,
    TSA_EXCEPTION_SD_TBD = (1 << 1),
    TSA_EXCEPTION_BENDING = (1 << 2),
    TSA_EXCEPTION_SD = (1 << 3),
    TSA_EXCEPTION_ESD = (1 << 4),
    TSA_EXCEPTION_TEMP = (1 << 5),
    TSA_EXCEPTION_WATER = (1 << 6),
    TSA_EXCEPTION_WET_FINGER = (1 << 7),
    TSA_EXCEPTION_CHARGER = (1 << 8),
    TSA_EXCEPTION_WAKEUP = (1 << 9),
    TSA_EXCEPTION_HARDWARE = (1 << 10),
    TSA_EXCEPTION_BASELINE = (1 << 11),
    TSA_EXCEPTION_CALIBRATION = (1 << 12),
    TSA_EXCEPTION_UNDER_WATER = (1 << 13),
    TSA_EXCEPTION_OUTOF_WATER = (1 << 14)
} TSA_EXCEPTION_ENUM;

typedef enum {
    TSA_DMD_NONE = 0,
    TSA_DMD_RF_NOISE = (1 << 0),
    TSA_DMD_RAW_JUMP = (1 << 1),
    TSA_DMD_SENSOR_BROKEN = (1 << 2),
    TSA_DMD_ASSERTED = (1 << 3),
    TSA_DMD_OTHER = (1 << 4)
} TSA_DMD_ENUM;

typedef enum {
    TSA_ERROR_NULL                      = 0,
    TSA_ERROR_INVALID                   = (1 << 0)
} TSA_ERROR_ENUM;

#define TSA_FEATURE_INVALID  -1
typedef enum {
    TSA_FEATURE_NONE                    = 0,
    TSA_FEATURE_GLOVE                   = (1 << 0),
    TSA_FEATURE_SMART_COVER             = (1 << 1),
    TSA_FEATURE_ROI                     = (1 << 2),
    TSA_FEATURE_GESTURE                 = (1 << 3),
    TSA_FEATURE_STYLUS                  = (1 << 4),
    TSA_FEATURE_GRIP_FILTER             = (1 << 5),
    TSA_FEATURE_SIGNAL_DISPARITY        = (1 << 6),
    TSA_FEATURE_BENDING                 = (1 << 7),
    TSA_FEATURE_CLICK_FLICK_BALANCE     = (1 << 8),
    TSA_FEATURE_HI_SENSE                = (1 << 9),
    TSA_FEATURE_BASELINE_RESTORE        = (1 << 10),
    TSA_FEATURE_UNDER_WATER             = (1 << 11),
    TSA_FEATURE_TOTAL                   = (1 << 12) /* always in the end to support TSA_FEATURE_INVALID */
} TSA_FEATURE_ENUM;
#define TSA_FEATURE_EXTERNAL (TSA_FEATURE_GLOVE | \
                              TSA_FEATURE_STYLUS | \
                              TSA_FEATURE_SMART_COVER)

#define TSA_WORKAROUND_INVALID (-1)
typedef enum {
    TSA_WORKAROUND_NONE                 = 0,
    TSA_WORKAROUND_EDGE_PEAK_FILTER     = (1 << 0),
    TSA_WORKAROUND_TOTAL                = (1 << 1) /* always in the end to support TSA_WORKAROUND_INVALID */
} TSA_WORKAROUND_ENUM;

typedef enum {
    TSA_SIDE_NONE                       = 0,
    TSA_SIDE_TOP                        = (1 << 0),
    TSA_SIDE_BOTTOM                     = (1 << 1),
    TSA_SIDE_LEFT                       = (1 << 2),
    TSA_SIDE_RIGHT                      = (1 << 3)
} TSA_SIDE_ENUM;

/* Sensor architecture */
typedef enum {
    TSA_SENSOR_ARCH_ONCELL = 1,         /* On cell sensor */
    TSA_SENSOR_ARCH_HYBRID_INCELL,      /* Hybrid in cell sensor */
    TSA_SENSOR_ARCH_FULL_INCELL         /* Full in cell sensor */
} TSA_SENSOR_ARCH_ENUM;
/******************************************************************************/


/*******************************************************************************
* Global Function Declaration
*******************************************************************************/
/** Data Processing APIs */
extern void TSA_Init_UI(void);
extern void TSA_InitProject_UI(const char* projID);
extern TSA_ERROR_ENUM TSA_InitAFEProject_UI(const char* projID, void* afeInfo, void* afeCaps);
extern void TSA_Processing(void* DataPtr, INT32U CtrlFlags, INT64U msTimeStamp);
extern TSA_ERROR_ENUM TSA_ProcessingAFEFrame(void* frame, INT32U CtrlFlags, INT64U msTimeStamp);
extern TSA_ERROR_ENUM TSA_ProcessingExt(void* DataPtr, INT32U CtrlFlags, INT64U msTimeStamp, INT16U scanFreq, INT8U scanRate, INT8U afeStatus);
extern TSA_ERROR_ENUM TSA_AutoCheckProcess(void* frame, INT32U CtrlFlags, INT64U msTimeStamp);
extern INT8U TSA_IsDone(void);
/** Version Control API */
extern const char* TSA_GetProjectName(void);
extern const char* TSA_GetBranchName(void);
extern INT32U TSA_GetVersion(void);
extern INT8U TSA_GetMajorVersion(void);
extern INT16U TSA_GetMinorVersion(void);
extern INT8U TSA_GetPatchVersion(void);
extern const char* TSA_GetOSName(void);
extern const char* TSA_GetPrmtName(void);
extern const char** TSA_GetPrmtNameList(void);
extern const char* TSA_GetIndexedPrmtName(INT8U index);
extern INT8U TSA_GetTotalPrmtNum(void);
extern INT32U TSA_GetPrmtVersion(void);
extern INT16U TSA_GetMaxSensorNum(void);
extern INT8U TSA_GetMaxDim1Length(void);
extern INT8U TSA_GetMaxDim2Length(void);
extern INT8U TSA_GetDim1Length(void);
extern INT8U TSA_GetDim2Length(void);
extern INT8U TSA_GetDim1Pitch(void);
extern INT8U TSA_GetDim2Pitch(void);
extern INT8U TSA_SetDim1Length(INT8U);
extern INT8U TSA_SetDim2Length(INT8U);
extern INT16U TSA_GetDim1Res(void);
extern INT16U TSA_GetDim2Res(void);
extern INT8U TSA_SetDim1Res(INT16U);
extern INT8U TSA_SetDim2Res(INT16U);
extern INT16U TSA_GetXRes(void);
extern INT16U TSA_GetYRes(void);
extern INT8U TSA_SetXRes(INT16U);
extern INT8U TSA_SetYRes(INT16U);
extern INT8U TSA_GetMaxFingerSupported(void);
extern INT8U TSA_GetFingerSupported(void);
extern INT8U TSA_SetFingerSupported(INT8U);
extern INT8U TSA_GetMSRawTypeSize(void);
extern INT8U TSA_GetMSRawTypeSign(void);
extern INT8U TSA_GetMSDiffTypeSize(void);
extern INT8U TSA_GetMSDiffTypeSign(void);
/** Report Access API */
extern INT8U TSA_RptTouchNum(void);
extern INT8U TSA_RptTouchZoneNum(void);
extern INT8U TSA_RptLONum(void);
extern INT8U TSA_RptIsTouchDown(INT8U Idx);
extern INT8U TSA_RptIsLiftOff(INT8U Idx);
extern INT8U TSA_RptTouchID(INT8U Idx);
extern INT16U TSA_RptTouchAge(INT8U idx);
extern INT8U TSA_RptTouchSizeInMM(INT8U idx);
extern INT8U TSA_RptTouchShape(INT8U Idx);
extern INT8U TSA_RptTouchObject(INT8U idx);
extern INT8U TSA_RptTouchEvent(INT8U idx);
extern INT16U TSA_RptTouchException(INT8U idx);
extern INT16U TSA_RptTouchXPos(INT8U Idx);
extern INT16U TSA_RptTouchYPos(INT8U Idx);
extern INT8U TSA_RptTouchXWidth(INT8U idx);
extern INT8U TSA_RptTouchYWidth(INT8U idx);
extern INT8U TSA_RptTouchXEdgeWidth(INT8U idx);
extern INT8U TSA_RptTouchYEdgeWidth(INT8U idx);
extern INT8U TSA_RptTouchXGripRatio(INT8U idx);
extern INT8U TSA_RptTouchYGripRatio(INT8U idx);
extern INT8U TSA_RptTouchGripRatio(INT8U idx);
extern INT8U TSA_RptTouchDim1Center(INT8U Idx);
extern INT8U TSA_RptTouchDim2Center(INT8U Idx);
extern INT8U TSA_RptTouchXCenter(INT8U Idx);
extern INT8U TSA_RptTouchYCenter(INT8U Idx);
extern INT8U TSA_RptTouchDim1Peak(INT8U Idx);
extern INT8U TSA_RptTouchDim2Peak(INT8U Idx);
extern INT16U TSA_RptTouchPressure(INT8U Idx);
extern INT16U TSA_RptTouchAxisMajor(INT8U Idx);
extern INT16U TSA_RptTouchAxisMinor(INT8U Idx);
extern INT8S TSA_RptTouchAxisAngle(INT8U Idx);
extern void* TSA_RptRawPtr(void);
extern void* TSA_RptPreRawPtr(void);
extern void* TSA_RptPreFilteredRawPtr(void);
extern void* TSA_RptPreFilteredDifPtr(void);
extern void* TSA_RptBaselinePtr(void);
extern void* TSA_RptNormalBaselinePtr(void);
extern void* TSA_RptBaselineLSBPtr(void);
extern void* TSA_RptDiffPtr(void);
extern void* TSA_RptSDPtr(void);
extern void* TSA_RptSelfDiffPtr(void);
/** Control Access API */
extern TSA_EXCEPTION_ENUM TSA_DetectedNoiseLevel(void);
extern TSA_EXCEPTION_ENUM TSA_DetectedSDLevel(void);
extern TSA_EXCEPTION_ENUM TSA_DetectedWaterLevel(void);
extern TSA_EXCEPTION_ENUM TSA_DetectedESDLevel(void);
extern TSA_EXCEPTION_ENUM TSA_IsWakeupDetected(void);
extern TSA_EXCEPTION_ENUM TSA_IsWetFingerDetected(void);
extern TSA_EXCEPTION_ENUM TSA_IsUnderWaterDetected(void);
extern TSA_EXCEPTION_ENUM TSA_IsOutOfWaterDetected(void);
extern TSA_EXCEPTION_ENUM TSA_DetectedHardwareException(void);
extern TSA_DMD_ENUM TSA_GetDMDType(void);
extern INT16U TSA_GetMaxCMFNoiseValue(void);
extern INT16U TSA_GetMaxContinuousCMFNoiseFrameNum(void);
extern const char* TSA_GetExceptionDescription(void);
extern TSA_EXCEPTION_ENUM TSA_DetectedBendingException(void);
extern void TSA_RetrieveBaseline(INT16U* raw, const INT16S* dif);

extern INT8U TSA_IsFreqHopNeeded(void);
extern INT8U TSA_IsAllFreqNoisy(void);
extern INT8U TSA_IsReCalibNeeded(void);
extern INT8U TSA_IsOKToResetIDLEBaseline(void);
extern INT8U TSA_IsOKToEnterIDLEMode(void);
extern INT8U TSA_IsOKToDisableFreqShift(void);
extern INT16U TSA_GetIDLETouchThold(void);
extern INT16U TSA_GetMutualTouchTholdInIDLEMode(void);
/** TSA Internal State */
extern INT8U TSA_IsBaselineOK(void);
extern INT8U TSA_GetTouchMode(void);
extern INT8U TSA_GetTouchModeStage(void);
extern INT8U TSA_GetTouchSize(void);
extern INT16U TSA_GetTouchThold(void);
extern INT16U TSA_GetBaselineThold(void);
extern INT16U TSA_GetTZThold(INT8U idx);
extern INT32U TSA_GetSigSum(INT8U idx);
extern INT32U TSA_GetZ9(INT8U idx);
extern INT32U TSA_GetZ4(INT8U idx);
extern TSA_EXCEPTION_ENUM TSA_GetException(void);
extern INT32S TSA_GetMutualRawMax(void);
extern INT32S TSA_GetMutualRawMin(void);
extern INT32S TSA_GetMutualDifMax(void);
extern INT32S TSA_GetMutualDifMin(void);
extern INT32S TSA_GetMutualSDCoef(void);
/** TSA Feature Access */
extern TSA_ERROR_ENUM TSA_SetFeatures(TSA_FEATURE_ENUM features);
extern TSA_ERROR_ENUM TSA_SetExternalFeatures(TSA_FEATURE_ENUM features);
extern TSA_FEATURE_ENUM TSA_GetFeatures(void);
extern TSA_ERROR_ENUM TSA_EnableGloveFeature(void);
extern void TSA_DisableGloveFeature(void);
extern INT8U TSA_IsGloveFeatureEnabled(void);
extern TSA_ERROR_ENUM TSA_EnableSmartCoverFeature(void);
extern TSA_ERROR_ENUM TSA_SetSmartCoverRange(INT16U xStart, INT16U yStart, INT16U xEnd, INT16U yEnd);
extern void TSA_DisableSmartCoverFeature(void);
extern INT8U TSA_IsSmartCoverFeatureEnabled(void);
extern TSA_ERROR_ENUM TSA_EnableGripFilterFeature(void);
extern void TSA_DisableGripFilterFeature(void);
extern INT8U TSA_IsGripFilterFeatureEnabled(void);
extern TSA_ERROR_ENUM TSA_EnableUnderWaterFeature(void);
extern void TSA_DisableUnderWaterFeature(void);
extern INT8U TSA_IsUnderWaterFeatureEnabled(void);
extern TSA_ERROR_ENUM TSA_SetWorkarounds(TSA_WORKAROUND_ENUM workarounds);
extern TSA_WORKAROUND_ENUM TSA_GetWorkarounds(void);
extern TSA_ERROR_ENUM TSA_EnableEdgePeakFilterWorkaround(void);
extern void TSA_DisableEdgePeakFilterWorkaround(void);
extern INT8U TSA_IsEdgePeakFilterWorkaroundEnabled(void);
extern INT32U TSA_GetAFESpecVersion(void);
extern INT8U TSA_GetAFESpecMajorVersion(void);
extern INT8U TSA_GetAFESpecMinorVersion(void);
extern INT8U TSA_GetAFESpecPatchVersion(void);
extern TSA_ERROR_ENUM TSA_SetAFEInfo(void* info);
extern TSA_ERROR_ENUM TSA_SetAFECaps(void* caps);
extern TSA_ERROR_ENUM TSA_SetAFEFrame(void* frame);
extern TSA_ERROR_ENUM TSA_GetAFEScanFreqIndex(INT8U* index);
extern TSA_ERROR_ENUM TSA_GetAFEScanRateIndex(INT8U* index);
extern TSA_SIDE_ENUM TSA_GetThenarSide(void);
extern INT16U TSA_GetThenarPosition(void);
extern INT8U TSA_IsThenarDetected(void);
extern INT8U TSA_IsThenarGestureTriggered(void);
extern TSA_SIDE_ENUM TSA_GetHandSide(void);
extern INT8U TSA_IsBothHandOperating(void);
extern INT8U TSA_IsTouchRecorderTrigger(void);
extern INT8U TSA_IsPreNthFrameTriggered(void); /* Is the Nth frame should be triggered */
extern INT32S TSA_GetTriggeredFrameIndex(void); /* The triggered frame index counted from current frame(0) [-55,-10] */
extern INT8U TSA_GetTriggerEventOffset(void);  /* The frame number from TriggeredFrameIndex to the actual event */
extern const char* TSA_GetTriggerEventDescription(void); /* The Description of actual event */

#ifdef __cplusplus
}
#endif

#endif/* __TSA_LIB_H */
