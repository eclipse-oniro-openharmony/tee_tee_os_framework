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



/************* Include Files ****************/
#include "cc_pal_types.h"
#include "cc_pal_error.h"
#include "cc_pal_mem.h"

/************************ Defines ******************************/

/************************ Enums ******************************/


/************************ Typedefs ******************************/


/************************ Global Data ******************************/

/************************ Private Functions ******************************/


/************************ Public Functions ******************************/

/**
 * @brief This function purpose is to perform secured memory comparison between two given
 *        buffers according to given size. The function will compare each byte till aSize
 *        number of bytes was compared even if the bytes are different.
 *        The function should be used to avoid security timing attacks.
 *
 *
 * @param[in] aTarget - The target buffer to compare
 * @param[in] aSource - The Source buffer to compare to
 * @param[in] aSize - Number of bytes to compare
 *
 * @return The function will return CC_SUCCESS in case of success, else errors from
 *         cc_pal_error.h will be returned.
 */
CCError_t CC_PalSecMemCmp(	const uint8_t* aTarget,
	                  	const uint8_t* aSource,
		                size_t  aSize		)
{
  /* internal index */
  uint32_t i = 0;

  /* error return */
  uint32_t error = CC_SUCCESS;

  /*------------------
      CODE
  -------------------*/

  /* Go over aTarget till aSize is reached (even if its not equal) */
  for (i = 0; i < aSize; i++)
  {
    if (aTarget[i] != aSource[i])
    {
      if (error != CC_SUCCESS)
        continue;
      else
      {
        if (aTarget[i] < aSource[i])
          error = CC_PAL_MEM_BUF2_GREATER;
        else
          error = CC_PAL_MEM_BUF1_GREATER;
      }
    }
  }

  return error;
}/* End of CC_PalSecMemCmp */

