/****************************************************************************
* The confidential and proprietary information contained in this file may    *
* only be used by a person authorised under and to the extent permitted      *
* by a subsisting licensing agreement from ARM Limited or its affiliates.    *
* 	(C) COPYRIGHT [2001-2017] ARM Limited or its affiliates.	     *
*	    ALL RIGHTS RESERVED						     *
* This entire notice must be reproduced on all copies of this file           *
* and copies of this file may only be made by a person if such person is     *
* permitted to do so under the terms of a subsisting license agreement       *
* from ARM Limited or its affiliates.					     *
*****************************************************************************/

#ifndef  CC_UTIL_PM_H
#define  CC_UTIL_PM_H

/*!
@file
@brief This file contains power management definitions and APIs.
*/

#define POWER_DOWN_EN_OFF 	0
#define POWER_DOWN_EN_ON 	1

#include "cc_util.h"

/************************************************************************************/
/****************        Power managment API           *****************************/
/************************************************************************************/

/****************************************************************************************/
/**
 *
 * @brief This function should be called by user before the ARM TEE is being power down.
 *
 * @return CC_UTIL_OK on success.
 * @return A non-zero value on failure.
 */
CCUtilError_t CC_UtilPmSuspend(void);


/****************************************************************************************/
/**
 *
 * @brief This function should be called by user once restoring the ARM TEE from power down state,
 * 	before any cryptographic operation.
 *
 * @return CC_UTIL_OK on success.
 * @return A non-zero value on failure.
 */
CCUtilError_t CC_UtilPmResume(void);


/****************************************************************************************/
/**
 *
 * @brief The function controls signal that disable Secure host from power down the ARM TEE.
 *
 * @return void.
 */
void CC_UtilPmPowerDownDisable(void);


/****************************************************************************************/
/**
 *
 * @brief The function controls signal that enable Secure host to power down the ARM TEE.
 *
 * @return void.
 */
void CC_UtilPmPowerDownEnable(void);

#endif
