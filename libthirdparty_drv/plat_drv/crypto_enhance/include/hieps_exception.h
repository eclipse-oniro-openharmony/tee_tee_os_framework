/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: This is header file for exception module.
 * Author: w00371137, wangyuzhu4@@huawei.com
 * Create: 2019-01-31
 */


#ifndef __HIEPS_EXCEPTION_H__
#define __HIEPS_EXCEPTION_H__


/*===============================================================================
 *                                types/macros                                 *
===============================================================================*/
#define HIEPS_ALARM_IRQ                    (452)
#define HIEPS_RESET_TIME                   (3000000) /* 3s = 3000000us */
#define HIEPS_MAX_RESET_CNT                (5)

#define HIEPS_ALARM_WAIT_TIMEOUT           (100000) /* 100000 x 2us = 200ms */

/* the type definition of msg from hieps to teeos for hieps mntn,
 * keep the same as defined in hieps.
 */
typedef enum {
    /* hieps -> teeos */
    HIEPS_TEEOS_HIEPS_OK = 0,
    HIEPS_TEEOS_EXCPT_VERSION1,
    HIEPS_TEEOS_EXCPT_VERSION2,
} hieps_excpt_msg_type;

/**
  * ROM excption format: fault value only use the lowest 16bit
  *   rom head        fault id        fault value
  *   BIT  31---28    27---16     15---0
  * Just the first version(Phoenix ROM) use this type.
  */
#define HIEPS_EXC_HEAD_VALUE        (0xA0000000)
#define HIEPS_EXC_HEAD_MASK         (0xF0000000)
#define HIEPS_EXC_TYPE_OFFSET       (16)
#define HIEPS_EXC_VALUE_MASK        (0x0000FFFF)



/*===============================================================================
 *                                global objects                               *
===============================================================================*/


/*===============================================================================
 *                                  functions                                  *
===============================================================================*/
int32_t hieps_exception_init(void);
int32_t hieps_exception_resume(void);
uint32_t hiep_get_soft_exception_flag(void);
void hiep_clear_soft_exception_flag(void);
uint32_t hiep_get_alarm_exception_flag(void);
void hiep_clear_alarm_exception_flag(void);
void hieps_soft_exception_process(void);
void hieps_alarm_process(void);

#endif /*  __HIEPS_EXCEPTION_H__ */
