/******************************************************************************

                 版权所有 (C), 2001-2019, 华为技术有限公司

 ******************************************************************************
  文 件 名   : soc_sm9_interface.h
  版 本 号   : 初稿
  作    者   : Excel2Code
  生成日期   : 2019-10-26 10:53:29
  最近修改   :
  功能描述   : 接口头文件
  函数列表   :
  修改历史   :
  1.日    期   : 2019年10月26日
    作    者   : l00249396
    修改内容   : 从《HiEPS V200 nmanager寄存器手册_SM9.xml》自动生成

******************************************************************************/

/*****************************************************************************
  1 其他头文件包含
*****************************************************************************/

#ifndef __SOC_SM9_INTERFACE_H__
#define __SOC_SM9_INTERFACE_H__

#ifdef __cplusplus
    #if __cplusplus
        extern "C" {
    #endif
#endif



/*****************************************************************************
  2 宏定义
*****************************************************************************/

/****************************************************************************
                     (1/1) reg_define
 ****************************************************************************/
/* 寄存器说明：忙状态寄存器
   位域定义UNION结构:  SOC_SM9_BUSY_UNION */
#define SOC_SM9_BUSY_ADDR(base)                       ((base) + (0x0000))

/* 寄存器说明：启动操作寄存器
   位域定义UNION结构:  SOC_SM9_START_UNION */
#define SOC_SM9_START_ADDR(base)                      ((base) + (0x0004))

/* 寄存器说明：中断屏蔽寄存器
   位域定义UNION结构:  SOC_SM9_INT_MASK_UNION */
#define SOC_SM9_INT_MASK_ADDR(base)                   ((base) + (0x0008))

/* 寄存器说明：中断状态寄存器(屏蔽后上报的状态)
   位域定义UNION结构:  SOC_SM9_INT_STATUS_UNION */
#define SOC_SM9_INT_STATUS_ADDR(base)                 ((base) + (0x000C))

/* 寄存器说明：中断屏蔽前状态寄存器(实际状态)
   位域定义UNION结构:  SOC_SM9_INT_NOMASK_STATUS_UNION */
#define SOC_SM9_INT_NOMASK_STATUS_ADDR(base)          ((base) + (0x0010))

/* 寄存器说明：中断清除寄存器
   位域定义UNION结构:  SOC_SM9_INT_CLR_UNION */
#define SOC_SM9_INT_CLR_ADDR(base)                    ((base) + (0x0014))

/* 寄存器说明：ALARM屏蔽寄存器
   位域定义UNION结构:  SOC_SM9_ALARM_MASK_UNION */
#define SOC_SM9_ALARM_MASK_ADDR(base)                 ((base) + (0x0018))

/* 寄存器说明：ALARM状态寄存器(屏蔽后上报的状态)
   位域定义UNION结构:  SOC_SM9_ALARM_STATUS_UNION */
#define SOC_SM9_ALARM_STATUS_ADDR(base)               ((base) + (0x001C))

/* 寄存器说明：ALARM屏蔽前状态寄存器(实际状态)
   位域定义UNION结构:  SOC_SM9_ALARM_NOMASK_STATUS_UNION */
#define SOC_SM9_ALARM_NOMASK_STATUS_ADDR(base)        ((base) + (0x0020))

/* 寄存器说明：ALARM清除寄存器
   位域定义UNION结构:  SOC_SM9_ALARM_CLR_UNION */
#define SOC_SM9_ALARM_CLR_ADDR(base)                  ((base) + (0x0024))

/* 寄存器说明：SM9结果标志寄存器
   位域定义UNION结构:  SOC_SM9_RESULT_FLAG_UNION */
#define SOC_SM9_RESULT_FLAG_ADDR(base)                ((base) + (0x0028))

/* 寄存器说明：SM9结果失败标志寄存器
   位域定义UNION结构:  SOC_SM9_FAILURE_FLAG_UNION */
#define SOC_SM9_FAILURE_FLAG_ADDR(base)               ((base) + (0x002C))

/* 寄存器说明：IRAM边界地址寄存器
   位域定义UNION结构:  SOC_SM9_IRAM_BOUNDRY_UNION */
#define SOC_SM9_IRAM_BOUNDRY_ADDR(base)               ((base) + (0x0030))

/* 寄存器说明：MOD_ADD选择寄存器
   位域定义UNION结构:  SOC_SM9_ADD_SEL_UNION */
#define SOC_SM9_ADD_SEL_ADDR(base)                    ((base) + (0x0034))

/* 寄存器说明：IRAM0指针寄存器
   位域定义UNION结构:  SOC_SM9_PC_CNT_IRAM0_UNION */
#define SOC_SM9_PC_CNT_IRAM0_ADDR(base)               ((base) + (0x0038))

/* 寄存器说明：IRAM1指针寄存器
   位域定义UNION结构:  SOC_SM9_PC_CNT_IRAM1_UNION */
#define SOC_SM9_PC_CNT_IRAM1_ADDR(base)               ((base) + (0x003C))

/* 寄存器说明：IRAM0在DEBUG时的使能寄存器
   位域定义UNION结构:  SOC_SM9_PC_DEBUG_IRAM0_EN_UNION */
#define SOC_SM9_PC_DEBUG_IRAM0_EN_ADDR(base)          ((base) + (0x0040))

/* 寄存器说明：IRAM0在DEBUG时的地址寄存器
   位域定义UNION结构:  SOC_SM9_PC_DEBUG_IRAM0_UNION */
#define SOC_SM9_PC_DEBUG_IRAM0_ADDR(base)             ((base) + (0x0044))

/* 寄存器说明：模数P
   位域定义UNION结构:  SOC_SM9_MODULUS_P_UNION */
#define SOC_SM9_MODULUS_P_ADDR(base, n)               ((base) + (0x0400+(n)*4))

/* 寄存器说明：模数N
   位域定义UNION结构:  SOC_SM9_MODULUS_N_UNION */
#define SOC_SM9_MODULUS_N_ADDR(base, n)               ((base) + (0x0420+(n)*4))

/* 寄存器说明：IRAM(4096*64bit)读写寄存器
   位域定义UNION结构:  SOC_SM9_IRAM_UNION */
#define SOC_SM9_IRAM_ADDR(base, m)                    ((base) + (0x0800+(m)*4))

/* 寄存器说明：DRAM(3520*256bit)读写寄存器
   位域定义UNION结构:  SOC_SM9_DRAM_UNION */
#define SOC_SM9_DRAM_ADDR(base, k)                    ((base) + (0x8800+(k)*4))





/*****************************************************************************
  3 枚举定义
*****************************************************************************/



/*****************************************************************************
  4 消息头定义
*****************************************************************************/


/*****************************************************************************
  5 消息定义
*****************************************************************************/



/*****************************************************************************
  6 STRUCT定义
*****************************************************************************/



/*****************************************************************************
  7 UNION定义
*****************************************************************************/

/****************************************************************************
                     (1/1) reg_define
 ****************************************************************************/
/*****************************************************************************
 结构名    : SOC_SM9_BUSY_UNION
 结构说明  : BUSY 寄存器结构定义。地址偏移量:0x0000，初值:0x00000000，宽度:32
 寄存器说明: 忙状态寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sm9_busy : 1;  /* bit[0]   : SM9模块空忙状态标志
                                                    0x1表示模块处于忙状态
                                                    0x0表示模块处于空闲状态
                                                   说明：CPU启动执行操作前查询该值，为0时才能启动执行某操作，硬件开始执行操作期间保持为忙状态，完成后变为闲状态，CPU可读取结果数据 */
        unsigned int  reserved : 31; /* bit[1-31]: 保留 */
    } reg;
} SOC_SM9_BUSY_UNION;
#endif
#define SOC_SM9_BUSY_sm9_busy_START  (0)
#define SOC_SM9_BUSY_sm9_busy_END    (0)


/*****************************************************************************
 结构名    : SOC_SM9_START_UNION
 结构说明  : START 寄存器结构定义。地址偏移量:0x0004，初值:0x00000000，宽度:32
 寄存器说明: 启动操作寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sm9_start : 1;  /* bit[0]   : CPU配置启动
                                                    0x1 ：启动执行操作；
                                                    0x0：不启动执行。
                                                    说明：CPU配置启动后，硬件开始执行相应的操作。SM9执行操作期间CPU不能配置该寄存器 */
        unsigned int  reserved  : 31; /* bit[1-31]: 保留 */
    } reg;
} SOC_SM9_START_UNION;
#endif
#define SOC_SM9_START_sm9_start_START  (0)
#define SOC_SM9_START_sm9_start_END    (0)


/*****************************************************************************
 结构名    : SOC_SM9_INT_MASK_UNION
 结构说明  : INT_MASK 寄存器结构定义。地址偏移量:0x0008，初值:0x00000001，宽度:32
 寄存器说明: 中断屏蔽寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sm9_int_mask : 1;  /* bit[0]   : 1：屏蔽该中断源
                                                       0：不屏蔽该中断源 */
        unsigned int  reserved     : 31; /* bit[1-31]: 保留 */
    } reg;
} SOC_SM9_INT_MASK_UNION;
#endif
#define SOC_SM9_INT_MASK_sm9_int_mask_START  (0)
#define SOC_SM9_INT_MASK_sm9_int_mask_END    (0)


/*****************************************************************************
 结构名    : SOC_SM9_INT_STATUS_UNION
 结构说明  : INT_STATUS 寄存器结构定义。地址偏移量:0x000C，初值:0x00000000，宽度:32
 寄存器说明: 中断状态寄存器(屏蔽后上报的状态)
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sm9_int_status : 1;  /* bit[0]   : mask后处理完成中断 状态寄存器
                                                         1：完成中断有效，表示处理完成
                                                         0：完成中断无效，可能是逻辑还在处理，也有可能是处理完成，但是中断被mask掉，或未启动操作 */
        unsigned int  reserved       : 31; /* bit[1-31]: 保留 */
    } reg;
} SOC_SM9_INT_STATUS_UNION;
#endif
#define SOC_SM9_INT_STATUS_sm9_int_status_START  (0)
#define SOC_SM9_INT_STATUS_sm9_int_status_END    (0)


/*****************************************************************************
 结构名    : SOC_SM9_INT_NOMASK_STATUS_UNION
 结构说明  : INT_NOMASK_STATUS 寄存器结构定义。地址偏移量:0x0010，初值:0x00000000，宽度:32
 寄存器说明: 中断屏蔽前状态寄存器(实际状态)
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sm9_int_nomsk_status : 1;  /* bit[0]   : mask前(即按无屏蔽中断) 处理完成中断 状态寄存器
                                                               1：完成中断有效，表示处理完成
                                                               0：完成中断无效，逻辑还在处理或未启动操作 */
        unsigned int  reserved             : 31; /* bit[1-31]: 保留 */
    } reg;
} SOC_SM9_INT_NOMASK_STATUS_UNION;
#endif
#define SOC_SM9_INT_NOMASK_STATUS_sm9_int_nomsk_status_START  (0)
#define SOC_SM9_INT_NOMASK_STATUS_sm9_int_nomsk_status_END    (0)


/*****************************************************************************
 结构名    : SOC_SM9_INT_CLR_UNION
 结构说明  : INT_CLR 寄存器结构定义。地址偏移量:0x0014，初值:0x00000000，宽度:32
 寄存器说明: 中断清除寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sm9_int_clr : 1;  /* bit[0]   : 说明：软件写0x1清除对应中断源，逻辑只在收到写0x1的时刻才对中断源进行清零。 */
        unsigned int  reserved    : 31; /* bit[1-31]: 保留 */
    } reg;
} SOC_SM9_INT_CLR_UNION;
#endif
#define SOC_SM9_INT_CLR_sm9_int_clr_START  (0)
#define SOC_SM9_INT_CLR_sm9_int_clr_END    (0)


/*****************************************************************************
 结构名    : SOC_SM9_ALARM_MASK_UNION
 结构说明  : ALARM_MASK 寄存器结构定义。地址偏移量:0x0018，初值:0x00000001，宽度:32
 寄存器说明: ALARM屏蔽寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sm9_alarm_mask : 1;  /* bit[0]   : SM9 ALARM屏蔽
                                                         0x1：屏蔽，不输出ALARM
                                                         0x0：不屏蔽 */
        unsigned int  reserved       : 31; /* bit[1-31]: 保留 */
    } reg;
} SOC_SM9_ALARM_MASK_UNION;
#endif
#define SOC_SM9_ALARM_MASK_sm9_alarm_mask_START  (0)
#define SOC_SM9_ALARM_MASK_sm9_alarm_mask_END    (0)


/*****************************************************************************
 结构名    : SOC_SM9_ALARM_STATUS_UNION
 结构说明  : ALARM_STATUS 寄存器结构定义。地址偏移量:0x001C，初值:0x00000000，宽度:32
 寄存器说明: ALARM状态寄存器(屏蔽后上报的状态)
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sm9_alarm_status : 1;  /* bit[0]   : SM9屏蔽后 ALARM 状态
                                                           1：检测到alarm
                                                           0：未检测alarm */
        unsigned int  reserved         : 31; /* bit[1-31]: 保留 */
    } reg;
} SOC_SM9_ALARM_STATUS_UNION;
#endif
#define SOC_SM9_ALARM_STATUS_sm9_alarm_status_START  (0)
#define SOC_SM9_ALARM_STATUS_sm9_alarm_status_END    (0)


/*****************************************************************************
 结构名    : SOC_SM9_ALARM_NOMASK_STATUS_UNION
 结构说明  : ALARM_NOMASK_STATUS 寄存器结构定义。地址偏移量:0x0020，初值:0x00000000，宽度:32
 寄存器说明: ALARM屏蔽前状态寄存器(实际状态)
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sm9_alarm_nomask_status : 1;  /* bit[0]   : SM9原始ALARM 状态
                                                                  1：检测到原始alarm
                                                                  0：未检测到原始alarm */
        unsigned int  reserved                : 31; /* bit[1-31]: 保留 */
    } reg;
} SOC_SM9_ALARM_NOMASK_STATUS_UNION;
#endif
#define SOC_SM9_ALARM_NOMASK_STATUS_sm9_alarm_nomask_status_START  (0)
#define SOC_SM9_ALARM_NOMASK_STATUS_sm9_alarm_nomask_status_END    (0)


/*****************************************************************************
 结构名    : SOC_SM9_ALARM_CLR_UNION
 结构说明  : ALARM_CLR 寄存器结构定义。地址偏移量:0x0024，初值:0x00000000，宽度:32
 寄存器说明: ALARM清除寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sm9_alarm_clr : 1;  /* bit[0]   : 说明：软件写0x1清除ALARM源，其他值无效，逻辑只在收到写0x1的时刻才对ALRAM进行清零。 */
        unsigned int  reserved      : 31; /* bit[1-31]: 保留 */
    } reg;
} SOC_SM9_ALARM_CLR_UNION;
#endif
#define SOC_SM9_ALARM_CLR_sm9_alarm_clr_START  (0)
#define SOC_SM9_ALARM_CLR_sm9_alarm_clr_END    (0)


/*****************************************************************************
 结构名    : SOC_SM9_RESULT_FLAG_UNION
 结构说明  : RESULT_FLAG 寄存器结构定义。地址偏移量:0x0028，初值:0x00000000，宽度:32
 寄存器说明: SM9结果标志寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sm9_result_flag : 4;  /* bit[0-3] : 结果标志
                                                          0x00：初始或运行状态，无结果
                                                          0x05：处理成功，清RAM操作时RAM数据无效，其它操作RAM中有结果数据。
                                                          0x0a：处理失败，无结果数据。(失败原因见寄存器SM9_FAILURE_FLAG)
                                                          其他：保留。
                                                          说明：配置SM9_START启动操作后在SM9_BUSY由忙变为不忙时再读寄存器。 */
        unsigned int  reserved        : 28; /* bit[4-31]: 保留。 */
    } reg;
} SOC_SM9_RESULT_FLAG_UNION;
#endif
#define SOC_SM9_RESULT_FLAG_sm9_result_flag_START  (0)
#define SOC_SM9_RESULT_FLAG_sm9_result_flag_END    (3)


/*****************************************************************************
 结构名    : SOC_SM9_FAILURE_FLAG_UNION
 结构说明  : FAILURE_FLAG 寄存器结构定义。地址偏移量:0x002C，初值:0x00000000，宽度:32
 寄存器说明: SM9结果失败标志寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sm9_failure_flag : 3;  /* bit[0-2] : 结果失败原因寄存器
                                                           0x0：初始或运行状态，无结果
                                                           0x1: 模逆无结果
                                                           0x4:点乘或点加结果为无穷远点
                                                           其它：保留。 */
        unsigned int  reserved         : 29; /* bit[3-31]: 保留。 */
    } reg;
} SOC_SM9_FAILURE_FLAG_UNION;
#endif
#define SOC_SM9_FAILURE_FLAG_sm9_failure_flag_START  (0)
#define SOC_SM9_FAILURE_FLAG_sm9_failure_flag_END    (2)


/*****************************************************************************
 结构名    : SOC_SM9_IRAM_BOUNDRY_UNION
 结构说明  : IRAM_BOUNDRY 寄存器结构定义。地址偏移量:0x0030，初值:0x00000800，宽度:32
 寄存器说明: IRAM边界地址寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sm9_iram_boundry : 12; /* bit[0-11] : IRAM0/IRAM1的逻辑边界，底层素域指令集从这里开始配置 */
        unsigned int  reserved         : 20; /* bit[12-31]: 保留。 */
    } reg;
} SOC_SM9_IRAM_BOUNDRY_UNION;
#endif
#define SOC_SM9_IRAM_BOUNDRY_sm9_iram_boundry_START  (0)
#define SOC_SM9_IRAM_BOUNDRY_sm9_iram_boundry_END    (11)


/*****************************************************************************
 结构名    : SOC_SM9_ADD_SEL_UNION
 结构说明  : ADD_SEL 寄存器结构定义。地址偏移量:0x0034，初值:0x00000000，宽度:32
 寄存器说明: MOD_ADD选择寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sm9_add_sel : 1;  /* bit[0]   : 模加模块选择信号：
                                                      0x0：使用高性能模加模块；
                                                      0x1：使用RSA中模加模块。 */
        unsigned int  reserved    : 31; /* bit[1-31]: 保留。 */
    } reg;
} SOC_SM9_ADD_SEL_UNION;
#endif
#define SOC_SM9_ADD_SEL_sm9_add_sel_START  (0)
#define SOC_SM9_ADD_SEL_sm9_add_sel_END    (0)


/*****************************************************************************
 结构名    : SOC_SM9_PC_CNT_IRAM0_UNION
 结构说明  : PC_CNT_IRAM0 寄存器结构定义。地址偏移量:0x0038，初值:0x00000000，宽度:32
 寄存器说明: IRAM0指针寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  pc_cnt_iram0 : 12; /* bit[0-11] : IRAM0跳转指针计数器 */
        unsigned int  reserved     : 20; /* bit[12-31]: 保留。 */
    } reg;
} SOC_SM9_PC_CNT_IRAM0_UNION;
#endif
#define SOC_SM9_PC_CNT_IRAM0_pc_cnt_iram0_START  (0)
#define SOC_SM9_PC_CNT_IRAM0_pc_cnt_iram0_END    (11)


/*****************************************************************************
 结构名    : SOC_SM9_PC_CNT_IRAM1_UNION
 结构说明  : PC_CNT_IRAM1 寄存器结构定义。地址偏移量:0x003C，初值:0x00000000，宽度:32
 寄存器说明: IRAM1指针寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  pc_cnt_iram1 : 12; /* bit[0-11] : IRAM1跳转指针计数器 */
        unsigned int  reserved     : 20; /* bit[12-31]: 保留。 */
    } reg;
} SOC_SM9_PC_CNT_IRAM1_UNION;
#endif
#define SOC_SM9_PC_CNT_IRAM1_pc_cnt_iram1_START  (0)
#define SOC_SM9_PC_CNT_IRAM1_pc_cnt_iram1_END    (11)


/*****************************************************************************
 结构名    : SOC_SM9_PC_DEBUG_IRAM0_EN_UNION
 结构说明  : PC_DEBUG_IRAM0_EN 寄存器结构定义。地址偏移量:0x0040，初值:0x00000000，宽度:32
 寄存器说明: IRAM0在DEBUG时的使能寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  pc_debug_iram0_en : 1;  /* bit[0]   : SM9 IRAM0 DEBUG的使能信号
                                                            0x0:不使能IRAM0的DEBUG功能
                                                            0x1:使能IRAM0的DEBUG功能 */
        unsigned int  reserved          : 31; /* bit[1-31]: 保留。 */
    } reg;
} SOC_SM9_PC_DEBUG_IRAM0_EN_UNION;
#endif
#define SOC_SM9_PC_DEBUG_IRAM0_EN_pc_debug_iram0_en_START  (0)
#define SOC_SM9_PC_DEBUG_IRAM0_EN_pc_debug_iram0_en_END    (0)


/*****************************************************************************
 结构名    : SOC_SM9_PC_DEBUG_IRAM0_UNION
 结构说明  : PC_DEBUG_IRAM0 寄存器结构定义。地址偏移量:0x0044，初值:0x00000000，宽度:32
 寄存器说明: IRAM0在DEBUG时的地址寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  pc_debug_iram0 : 12; /* bit[0-11] : SM9 IRAM0 DEBUG的地址信号
                                                          当IRAM0中的指针执行到该寄存器配置的地址时，停止运算（该地址本身的指令操作不执行） */
        unsigned int  reserved       : 20; /* bit[12-31]: 保留。 */
    } reg;
} SOC_SM9_PC_DEBUG_IRAM0_UNION;
#endif
#define SOC_SM9_PC_DEBUG_IRAM0_pc_debug_iram0_START  (0)
#define SOC_SM9_PC_DEBUG_IRAM0_pc_debug_iram0_END    (11)


/*****************************************************************************
 结构名    : SOC_SM9_MODULUS_P_UNION
 结构说明  : MODULUS_P 寄存器结构定义。地址偏移量:0x0400+(n)*4，初值:0x00000000，宽度:32
 寄存器说明: 模数P
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  modulus_p : 32; /* bit[0-31]: CPU配置模数P数据寄存器，连续配置8次32bit数据，P的高bit放置在高地址中。写入顺序为从最低32bit开始写，最高32bit最后写。
                                                    地址域的n范围[0,7] */
    } reg;
} SOC_SM9_MODULUS_P_UNION;
#endif
#define SOC_SM9_MODULUS_P_modulus_p_START  (0)
#define SOC_SM9_MODULUS_P_modulus_p_END    (31)


/*****************************************************************************
 结构名    : SOC_SM9_MODULUS_N_UNION
 结构说明  : MODULUS_N 寄存器结构定义。地址偏移量:0x0420+(n)*4，初值:0x00000000，宽度:32
 寄存器说明: 模数N
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  modulus_n : 32; /* bit[0-31]: CPU配置模数N数据寄存器，连续配置8次32bit数据，P的高bit放置在高地址中。写入顺序为从最低32bit开始写，最高32bit最后写。
                                                    地址域的n范围[0,7] */
    } reg;
} SOC_SM9_MODULUS_N_UNION;
#endif
#define SOC_SM9_MODULUS_N_modulus_n_START  (0)
#define SOC_SM9_MODULUS_N_modulus_n_END    (31)


/*****************************************************************************
 结构名    : SOC_SM9_IRAM_UNION
 结构说明  : IRAM 寄存器结构定义。地址偏移量:0x0800+(m)*4，初值:0x00000000，宽度:32
 寄存器说明: IRAM(4096*64bit)读写寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  iram : 32; /* bit[0-31]: CPU配置IRAM数据寄存器，芯片内部RAM为48bit位宽，软件按64bit为单位读写数据(n从偶数开始)。初始值是IRAM里的初始值，不一定是0。
                                               地址域的m范围[0,8191]，64位宽的数据在64bit内使用小端模式 */
    } reg;
} SOC_SM9_IRAM_UNION;
#endif
#define SOC_SM9_IRAM_iram_START  (0)
#define SOC_SM9_IRAM_iram_END    (31)


/*****************************************************************************
 结构名    : SOC_SM9_DRAM_UNION
 结构说明  : DRAM 寄存器结构定义。地址偏移量:0x8800+(k)*4，初值:0x00000000，宽度:32
 寄存器说明: DRAM(3520*256bit)读写寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  dram : 32; /* bit[0-31]: CPU配置DRAM数据寄存器，芯片内部RAM为256bit位宽，软件按256bit为单位读写数据(n从8的整数倍开始)。初始值是DRAM里的初始值，不一定是0。
                                               地址域的k范围[0,28159]，256位宽的数据在256bit内使用小端模式 */
    } reg;
} SOC_SM9_DRAM_UNION;
#endif
#define SOC_SM9_DRAM_dram_START  (0)
#define SOC_SM9_DRAM_dram_END    (31)






/*****************************************************************************
  8 OTHERS定义
*****************************************************************************/



/*****************************************************************************
  9 全局变量声明
*****************************************************************************/


/*****************************************************************************
  10 函数声明
*****************************************************************************/


#ifdef __cplusplus
    #if __cplusplus
        }
    #endif
#endif

#endif /* end of soc_sm9_interface.h */
