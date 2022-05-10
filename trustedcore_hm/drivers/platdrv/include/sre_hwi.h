/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: Header file of the hardware interrupt module
 * Create: 2019-11-01
 */

#ifndef LIBHWI_SRE_HWI_H
#define LIBHWI_SRE_HWI_H

#include <sre_typedef.h>
#include <sre_errno.h> /* SRE_ERRNO_OS_ERROR */
#include <drv_hwi.h>

typedef VOID (*HWI_PROC_FUNC)(HWI_ARG_T);

/*
 * @ingroup SRE_hwi
 * @brief Creating a hwi processing function.
 * @par Description:
 * a processing function to register a hwi
 * @attention
 * Before calling this function, ensure that the interrupt attribute is set.
 * For the SD6181, SD6108, and SD6182 chips in Tensilica, the available hwi IDs(event IDs) range from 0 to 31.
 * The priorities of SD6181 and SD6108 are 1-6, and the priorities of SD6182 are 1-5.
 * After a hard interrupt is created, the corresponding event ID is enabled, but the corresponding interrupt
 * vector is not enabled. You need to enable it by calling #SRE_HwiEnable explicitly.
 * @param  uw_hwi_num [IN] type#HWI_HANDLE_T, the hard interrupt number.
 * @param  pfn_handler [IN] type#HWI_PROC_FUNC, the processing function when a hard interrupt is triggered.
 * @param  uw_arg [IN] type#HWI_ARG_T, the parameter transferred when the hard interrupt processing function is called.
 * @retval #OS_ERRNO_HWI_NUM_INVALID                     0x02001400, invalid interrupt number.
 * @retval #OS_ERRNO_HWI_PROC_FUNC_NULL                  0x02001403, the hwi processing function is null.
 * @retval #OS_ERRNO_HWI_MODE_UNSET                      0x0200140c, the hard interrupt mode is not set.
 * @retval #OS_ERRNO_HWI_MEMORY_ALLOC_FAILED             0x02001408, private and static memory allocation failed
 *                                                                   for the combined interrupt node.
 * @retval #OS_ERRNO_HWI_COMBINEHOOK_ALREADY_CREATED     0x02001409, the combinehook has already been created.
 * @retval #OS_ERRNO_HWI_ALREADY_CREATED                 0x02001402, the hwi has already been created or the current
 *                                                                   interrupt number has been occupied.
 * @retval #OS_ERRNO_HWI_HM_INTERNAL                     0x02001411, Harmony Kernel Internal Error.
 * @retval #SRE_OK                                       0x00000000, the hardware interruption is created successfully.
 * sre_hwi.h:the header file where interfaces are decleared.
 * @since RTOSck V100R001C01
 * @see SRE_HwiDelete
 */
uint32_t SRE_HwiCreate(HWI_HANDLE_T uw_hwi_num, HWI_PRIOR_T us_hwi_prio, HWI_MODE_T us_mode, HWI_PROC_FUNC pfn_handler,
                       HWI_ARG_T uw_arg);

uint32_t SRE_HwiResume(HWI_HANDLE_T uw_hwi_num, HWI_PRIOR_T us_hwi_prio, HWI_MODE_T us_mode);

/*
 * @ingroup  SRE_hwi
 * @brief Deleting a hardware interrupt function.
 * @par Description:
 * Mask the corresponding hardware interrupt or event, and cancel the registration of the hardware interrupt
 * processing function.
 * @attention
 * For the SD6181, SD6108, and SD6182 chips in Tensilica, the available hwi IDs(event IDs) range from 0 to 31.
 * @param  uw_hwi_num [IN] type#HWI_HANDLE_T, the hardware interrupt number.
 * @retval #OS_ERRNO_HWI_NUM_INVALID            0x02001400, the interrupt number is invalid.
 * @retval #OS_ERRNO_HWI_DELETE_TICK_INT        0x02001405, deleting the TICK interruption.
 * @retval #OS_ERRNO_HWI_DELETED                0x0200140b, deleting uncreated hardware interrupts.
 * @retval #SRE_OK                              0x00000000, the hardware interrupt is successfully deleted.
 * @retval #OS_ERRNO_HWI_HM_INTERNAL            0x02001411, Harmony Kernel Internal Error.
 * sre_hwi.h:the header file where the interfaces are decleared.
 * @since RTOSck V100R001C01
 * @see SRE_HwiCreate
 */
uint32_t SRE_HwiDelete(HWI_HANDLE_T uw_hwi_num);

/*
 * @ingroup  SRE_hwi
 * @brief Masking the specific hardware interruption.
 * @par Description:
 * Disable the DSP from responding to the request of a specified hardware interrupt.
 * @attention
 * For the chips in Tensilica, the available hwi IDs(event IDs) range from 0 to 31.
 * Special function of Tensilica: all hardware interrupts can be masked when the input parameter is OS_HWI_ALL.
 * @param  uw_hwi_num [IN] type#HWI_HANDLE_T, the hardware interrupt ID or vector ID varies according to the chips.
 * For details, see the precautions.
 * @retval #OS_ERRNO_HWI_HM_INTERNAL                0x02001411, Harmony Kernel Internal Error.
 * @retval #Value of the interrupt enable register before masking.
 * sre_hwi.h:the header file where the interfaces are decleared.
 * @since RTOSck V100R001C01
 * @see SRE_HwiEnable
 */
uint32_t SRE_HwiDisable(HWI_HANDLE_T uw_hwi_num);

/*
 * @ingroup  SRE_hwi
 * @brief Enabling the specific hardware interruption.
 * @par Description:
 * Allow the DSP to respond to the request of a specified hardware interrupt.
 * @attention
 * For the chips in Tensilica, the available hwi IDs(event IDs) range from 0 to 31.
 * Special function of Tensilica: all hardware interrupts can be masked when the input parameter is OS_HWI_ALL.
 * The meaning of the returned value varies according to the chip. For details, see the description
 * of the returned value.
 * @param  uw_hwi_num [IN] type#HWI_HANDLE_T, the hardware interrupt ID or vector ID varies according to the chips.
 * @retval #Value of the interrupt enable register before enabling.
 * @retval #OS_ERRNO_HWI_HM_INTERNAL                0x02001411, Harmony Kernel Internal Error.
 * sre_hwi.h:the header file where the interfaces are decleared.
 * @since RTOSck V100R001C01
 * @see SRE_HwiDisable
 */
uint32_t SRE_HwiEnable(HWI_HANDLE_T uw_hwi_num);

#endif /* LIBHWI_SRE_HWI_H */
