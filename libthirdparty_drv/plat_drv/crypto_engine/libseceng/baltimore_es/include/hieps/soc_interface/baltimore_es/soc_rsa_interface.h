/******************************************************************************

                 版权所有 (C), 2001-2019, 华为技术有限公司

 ******************************************************************************
  文 件 名   : soc_rsa_interface.h
  版 本 号   : 初稿
  作    者   : Excel2Code
  生成日期   : 2019-10-26 10:53:24
  最近修改   :
  功能描述   : 接口头文件
  函数列表   :
  修改历史   :
  1.日    期   : 2019年10月26日
    作    者   : l00249396
    修改内容   : 从《HiEPS V200 nmanager寄存器手册_RSA.xml》自动生成

******************************************************************************/

/*****************************************************************************
  1 其他头文件包含
*****************************************************************************/

#ifndef __SOC_RSA_INTERFACE_H__
#define __SOC_RSA_INTERFACE_H__

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
   位域定义UNION结构:  SOC_RSA_BUSY_UNION */
#define SOC_RSA_BUSY_ADDR(base)                       ((base) + (0x0000))

/* 寄存器说明：工作模式寄存器
   位域定义UNION结构:  SOC_RSA_WORK_MODE_UNION */
#define SOC_RSA_WORK_MODE_ADDR(base)                  ((base) + (0x0004))

/* 寄存器说明：启动操作寄存器
   位域定义UNION结构:  SOC_RSA_START_UNION */
#define SOC_RSA_START_ADDR(base)                      ((base) + (0x0008))

/* 寄存器说明：调试使能寄存器(内部调试用)
   位域定义UNION结构:  SOC_RSA_DEBUG_EN_UNION */
#define SOC_RSA_DEBUG_EN_ADDR(base)                   ((base) + (0x0010))

/* 寄存器说明：RSA_RNG_OPT配置寄存器(testchip内部使用)
   位域定义UNION结构:  SOC_RSA_RNG_OPTION_UNION */
#define SOC_RSA_RNG_OPTION_ADDR(base)                 ((base) + (0x0014))

/* 寄存器说明：NEW ALARM屏蔽寄存器
   位域定义UNION结构:  SOC_RSA_NEW_ALARM_MASK_UNION */
#define SOC_RSA_NEW_ALARM_MASK_ADDR(base)             ((base) + (0x0018))

/* 寄存器说明：中断屏蔽寄存器
   位域定义UNION结构:  SOC_RSA_INT_MASK_UNION */
#define SOC_RSA_INT_MASK_ADDR(base)                   ((base) + (0x0020))

/* 寄存器说明：中断状态寄存器(屏蔽后上报的状态)
   位域定义UNION结构:  SOC_RSA_INT_STATUS_UNION */
#define SOC_RSA_INT_STATUS_ADDR(base)                 ((base) + (0x0024))

/* 寄存器说明：中断屏蔽前状态寄存器(实际状态)
   位域定义UNION结构:  SOC_RSA_INT_NOMASK_STATUS_UNION */
#define SOC_RSA_INT_NOMASK_STATUS_ADDR(base)          ((base) + (0x0028))

/* 寄存器说明：中断清除寄存器
   位域定义UNION结构:  SOC_RSA_INT_CLR_UNION */
#define SOC_RSA_INT_CLR_ADDR(base)                    ((base) + (0x002C))

/* 寄存器说明：ALARM屏蔽寄存器
   位域定义UNION结构:  SOC_RSA_ALARM_MASK_UNION */
#define SOC_RSA_ALARM_MASK_ADDR(base)                 ((base) + (0x0030))

/* 寄存器说明：ALARM状态寄存器(屏蔽后上报的状态)
   位域定义UNION结构:  SOC_RSA_ALARM_STATUS_UNION */
#define SOC_RSA_ALARM_STATUS_ADDR(base)               ((base) + (0x0034))

/* 寄存器说明：ALARM屏蔽前状态寄存器(实际状态)
   位域定义UNION结构:  SOC_RSA_ALARM_NOMASK_STATUS_UNION */
#define SOC_RSA_ALARM_NOMASK_STATUS_ADDR(base)        ((base) + (0x0038))

/* 寄存器说明：ALARM清除寄存器
   位域定义UNION结构:  SOC_RSA_ALARM_CLR_UNION */
#define SOC_RSA_ALARM_CLR_ADDR(base)                  ((base) + (0x003C))

/* 寄存器说明：RSA结果标志寄存器
   位域定义UNION结构:  SOC_RSA_RESULT_FLAG_UNION */
#define SOC_RSA_RESULT_FLAG_ADDR(base)                ((base) + (0x0040))

/* 寄存器说明：RSA结果失败标志寄存器
   位域定义UNION结构:  SOC_RSA_FAILURE_FLAG_UNION */
#define SOC_RSA_FAILURE_FLAG_ADDR(base)               ((base) + (0x0044))

/* 寄存器说明：统计清零寄存器
   位域定义UNION结构:  SOC_RSA_STAT_CLR_UNION */
#define SOC_RSA_STAT_CLR_ADDR(base)                   ((base) + (0x0050))

/* 寄存器说明：RSA的密钥掩码寄存器
   位域定义UNION结构:  SOC_RSA_KEY_MSK_UNION */
#define SOC_RSA_KEY_MSK_ADDR(base)                    ((base) + (0x0054))

/* 寄存器说明：RSA的密钥备份寄存器
   位域定义UNION结构:  SOC_RSA_KEY_BACKUP_UNION */
#define SOC_RSA_KEY_BACKUP_ADDR(base)                 ((base) + (0x0058))

/* 寄存器说明：RSA的寄存器lock寄存器
   位域定义UNION结构:  SOC_RSA_LOCK_UNION */
#define SOC_RSA_LOCK_ADDR(base)                       ((base) + (0x005C))

/* 寄存器说明：RSA的密钥lock寄存器
   位域定义UNION结构:  SOC_RSA_KEY_LOCK_UNION */
#define SOC_RSA_KEY_LOCK_ADDR(base)                   ((base) + (0x0060))

/* 寄存器说明：RSA的版本寄存器
   位域定义UNION结构:  SOC_RSA_VERSION_ID_UNION */
#define SOC_RSA_VERSION_ID_ADDR(base)                 ((base) + (0x007C))

/* 寄存器说明：RSA模数的最高位为1寄存器
   位域定义UNION结构:  SOC_RSA_LSB_N_EQUAL_ONE_UNION */
#define SOC_RSA_LSB_N_EQUAL_ONE_ADDR(base)            ((base) + (0x0080))

/* 寄存器说明：MRAM(4096bit)读写寄存器
   位域定义UNION结构:  SOC_RSA_MRAM_UNION */
#define SOC_RSA_MRAM_ADDR(base, n)                    ((base) + (0x0200+(n)*4))

/* 寄存器说明：NRAM(4096bit)读写寄存器
   位域定义UNION结构:  SOC_RSA_NRAM_UNION */
#define SOC_RSA_NRAM_ADDR(base, n)                    ((base) + (0x0600+(n)*4))

/* 寄存器说明：KRAM(4096bit)读写寄存器
   位域定义UNION结构:  SOC_RSA_KRAM_UNION */
#define SOC_RSA_KRAM_ADDR(base, n)                    ((base) + (0x0A00+(n)*4))

/* 寄存器说明：RRAM(4096bit)读写寄存器
   位域定义UNION结构:  SOC_RSA_RRAM_UNION */
#define SOC_RSA_RRAM_ADDR(base, n)                    ((base) + (0x0E00+(n)*4))





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
 结构名    : SOC_RSA_BUSY_UNION
 结构说明  : BUSY 寄存器结构定义。地址偏移量:0x0000，初值:0x00000000，宽度:32
 寄存器说明: 忙状态寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  rsa_busy : 1;  /* bit[0]   : RSA模块空忙状态标志
                                                    0x1表示模块处于忙状态
                                                    0x0表示模块处于空闲状态
                                                   说明：CPU启动执行操作前查询该值，为0时才能启动执行某操作，硬件开始执行操作期间保持为忙状态，完成后变为闲状态，CPU可读取结果数据 */
        unsigned int  reserved : 31; /* bit[1-31]: 保留 */
    } reg;
} SOC_RSA_BUSY_UNION;
#endif
#define SOC_RSA_BUSY_rsa_busy_START  (0)
#define SOC_RSA_BUSY_rsa_busy_END    (0)


/*****************************************************************************
 结构名    : SOC_RSA_WORK_MODE_UNION
 结构说明  : WORK_MODE 寄存器结构定义。地址偏移量:0x0004，初值:0x00000400，宽度:32
 寄存器说明: 工作模式寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  opcode   : 4;  /* bit[0-3]  : RSA执行操作期间CPU不能配置该寄存器
                                                    BIT[3:0]：操作模式
                                                    4'0：RSA模幂
                                                    4'1：RSA密钥生成 (带公钥输入)
                                                    4'2：RSA密钥生成 (不带公钥输入)
                                                    4'd3：蒙哥马利模加；
                                                    4'd4：五元组转换；
                                                    4'd5：蒙哥马利模减；
                                                    4'd6：蒙哥马利模乘；
                                                    4'd7：模逆； 
                                                    4'd8：求模； 
                                                    4'd9：基本乘法；
                                                    4'd10：PQ产生
                                                    4'd12：点乘； 
                                                    4'd13：点加；
                                                    4'd15：对RAM进行清0操作 (软件根据需要确定是否需要清0操作)
                                                    其它值：为非法配置，逻辑会产生alarm告警。 */
        unsigned int  reserved_0: 4;  /* bit[4-7]  : 保留 */
        unsigned int  mode     : 8;  /* bit[8-15] : RSA执行操作期间CPU不能配置该寄存器
                                                    模式(操作对应的密钥长度的模式或清零RAM的模式)
                                                    RSA模幂时，典型密钥位宽对应配置值如下：
                                                     8: 512
                                                    16: 1024
                                                    18: 1152
                                                    31: 1984
                                                    32: 2048
                                                    48: 3072
                                                    64: 4096
                                                    备注：有效配置范围为8~64间任意整数，单位为64bit，其他为非法配置。
                                                    RSA密钥产生时，配置值对应密钥如下：
                                                     8: 512
                                                    16: 1024
                                                    18: 1152
                                                    31: 1984
                                                    32: 2048
                                                    48: 3072
                                                    64: 4096
                                                    备注：有效配置范围为8~64间任意整数，单位为64bit，其他为非法配置。
                                                    点乘：典型密钥位宽对应配置值如下：
                                                     4: 256 (点乘<=256bit时按256bit点乘操作，配置的数据也按256bit,不足的高位填0。如160/192/224位宽的点乘)
                                                     6: 384
                                                     9: 576 (点乘位宽为513~576bit时 按576bit点乘操作，配置的数据也按576bit,不足的高位填0)
                                                    备注：算法未说明的其他位宽不支持（无标准测试数据进行验证）。
                                                    对RAM进行清0操作时 RAM清零模式按bit定义如下
                                                     mode[0](对应寄存器bit8 ) 为1时清零MRAM
                                                     mode[1](对应寄存器bit9 ) 为1时清零KRAM
                                                     mode[2](对应寄存器bit10) 为1时清零NRAM
                                                     mode[3](对应寄存器bit11) 为1时清零RRAM
                                                     mode[4](对应寄存器bit12) 为1时清零PKA只内部使用的RAM(不包含MRAM/KRAM/NRAM/RRAM)
                                                     mode[7:5](对应寄存器bit13~15) 保留。
                                                    求模：基本模 a mod b 配置的长度可以到128，a的有效拍数可以是128，
                                                     但是b的最大有效拍数最大是64（超过64拍的空间需补零），
                                                     同时结果长度也是64。 */
        unsigned int  reserved_1: 16; /* bit[16-31]: 保留 */
    } reg;
} SOC_RSA_WORK_MODE_UNION;
#endif
#define SOC_RSA_WORK_MODE_opcode_START    (0)
#define SOC_RSA_WORK_MODE_opcode_END      (3)
#define SOC_RSA_WORK_MODE_mode_START      (8)
#define SOC_RSA_WORK_MODE_mode_END        (15)


/*****************************************************************************
 结构名    : SOC_RSA_START_UNION
 结构说明  : START 寄存器结构定义。地址偏移量:0x0008，初值:0x00000000，宽度:32
 寄存器说明: 启动操作寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  rsa_start : 4;  /* bit[0-3] : CPU配置启动
                                                    0xA ：启动执行操作；
                                                    其它：不启动执行。
                                                    说明：CPU配置启动后，硬件开始执行相应的操作。RSA执行操作期间CPU不能配置该寄存器 */
        unsigned int  reserved  : 28; /* bit[4-31]: 保留 */
    } reg;
} SOC_RSA_START_UNION;
#endif
#define SOC_RSA_START_rsa_start_START  (0)
#define SOC_RSA_START_rsa_start_END    (3)


/*****************************************************************************
 结构名    : SOC_RSA_DEBUG_EN_UNION
 结构说明  : DEBUG_EN 寄存器结构定义。地址偏移量:0x0010，初值:0x0000000A，宽度:32
 寄存器说明: 调试使能寄存器(内部调试用)
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  rsa_debug_en : 4;  /* bit[0-3] : CPU配置调试使能，在OTP RSA调试使能时该寄存器有效，否则固定为调试禁止
                                                       0x5：调试使能，未启动操作时KRAM的数据能读取；
                                                       0xa：调试禁止, KRAM的数据不能读取； */
        unsigned int  reserved     : 28; /* bit[4-31]: 保留 */
    } reg;
} SOC_RSA_DEBUG_EN_UNION;
#endif
#define SOC_RSA_DEBUG_EN_rsa_debug_en_START  (0)
#define SOC_RSA_DEBUG_EN_rsa_debug_en_END    (3)


/*****************************************************************************
 结构名    : SOC_RSA_RNG_OPTION_UNION
 结构说明  : RNG_OPTION 寄存器结构定义。地址偏移量:0x0014，初值:0x00000001，宽度:32
 寄存器说明: RSA_RNG_OPT配置寄存器(testchip内部使用)
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  rsa_rng_option : 2;  /* bit[0-1] : 配置RSA的ECC点乘随机数选项，用于内部测试用。
                                                         0：选择16bit随机数
                                                         1：选择32bit随机数
                                                         2：选择48bit随机数
                                                         3：选择64bit随机数 */
        unsigned int  reserved       : 30; /* bit[2-31]: 保留 */
    } reg;
} SOC_RSA_RNG_OPTION_UNION;
#endif
#define SOC_RSA_RNG_OPTION_rsa_rng_option_START  (0)
#define SOC_RSA_RNG_OPTION_rsa_rng_option_END    (1)


/*****************************************************************************
 结构名    : SOC_RSA_NEW_ALARM_MASK_UNION
 结构说明  : NEW_ALARM_MASK 寄存器结构定义。地址偏移量:0x0018，初值:0x00000005，宽度:32
 寄存器说明: NEW ALARM屏蔽寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  rsa_new_alarm_mask : 4;  /* bit[0-3] : 保护类ALARM源屏蔽
                                                             0x5：屏蔽，不输出ALARM
                                                             其他：不屏蔽 */
        unsigned int  reserved           : 28; /* bit[4-31]: 保留 */
    } reg;
} SOC_RSA_NEW_ALARM_MASK_UNION;
#endif
#define SOC_RSA_NEW_ALARM_MASK_rsa_new_alarm_mask_START  (0)
#define SOC_RSA_NEW_ALARM_MASK_rsa_new_alarm_mask_END    (3)


/*****************************************************************************
 结构名    : SOC_RSA_INT_MASK_UNION
 结构说明  : INT_MASK 寄存器结构定义。地址偏移量:0x0020，初值:0x00000001，宽度:32
 寄存器说明: 中断屏蔽寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  finish_int_mask : 1;  /* bit[0]    : 1：屏蔽该中断源
                                                           0：不屏蔽该中断源 */
        unsigned int  reserved_0      : 15; /* bit[1-15] : 保留 */
        unsigned int  reserved_1      : 16; /* bit[16-31]: 保留 */
    } reg;
} SOC_RSA_INT_MASK_UNION;
#endif
#define SOC_RSA_INT_MASK_finish_int_mask_START  (0)
#define SOC_RSA_INT_MASK_finish_int_mask_END    (0)


/*****************************************************************************
 结构名    : SOC_RSA_INT_STATUS_UNION
 结构说明  : INT_STATUS 寄存器结构定义。地址偏移量:0x0024，初值:0x00000000，宽度:32
 寄存器说明: 中断状态寄存器(屏蔽后上报的状态)
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  finish_int_status : 1;  /* bit[0]    : mask后处理完成中断 状态寄存器
                                                             1：完成中断有效，表示处理完成
                                                             0：完成中断无效，可能是逻辑还在处理，也有可能是处理完成，但是中断被mask掉，或未启动操作 */
        unsigned int  reserved_0        : 15; /* bit[1-15] : 保留 */
        unsigned int  reserved_1        : 16; /* bit[16-31]: 保留 */
    } reg;
} SOC_RSA_INT_STATUS_UNION;
#endif
#define SOC_RSA_INT_STATUS_finish_int_status_START  (0)
#define SOC_RSA_INT_STATUS_finish_int_status_END    (0)


/*****************************************************************************
 结构名    : SOC_RSA_INT_NOMASK_STATUS_UNION
 结构说明  : INT_NOMASK_STATUS 寄存器结构定义。地址偏移量:0x0028，初值:0x00000000，宽度:32
 寄存器说明: 中断屏蔽前状态寄存器(实际状态)
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  finish_int_nomsk_status : 1;  /* bit[0]   : mask前(即按无屏蔽中断) 处理完成中断 状态寄存器
                                                                  1：完成中断有效，表示处理完成
                                                                  0：完成中断无效，逻辑还在处理或未启动操作 */
        unsigned int  reserved                : 31; /* bit[1-31]: 保留 */
    } reg;
} SOC_RSA_INT_NOMASK_STATUS_UNION;
#endif
#define SOC_RSA_INT_NOMASK_STATUS_finish_int_nomsk_status_START  (0)
#define SOC_RSA_INT_NOMASK_STATUS_finish_int_nomsk_status_END    (0)


/*****************************************************************************
 结构名    : SOC_RSA_INT_CLR_UNION
 结构说明  : INT_CLR 寄存器结构定义。地址偏移量:0x002C，初值:0x00000000，宽度:32
 寄存器说明: 中断清除寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  finish_int_clr : 1;  /* bit[0]   : 说明：软件写0x1清除对应中断源，逻辑只在收到写0x1的时刻才对中断源进行清零。清零操作后0x1会存于该寄存器中，为了不影响调试建议对该寄存器写0x0恢复默认值。 */
        unsigned int  reserved_0     : 7;  /* bit[1-7] : 保留 */
        unsigned int  reserved_1     : 24; /* bit[8-31]: 保留 */
    } reg;
} SOC_RSA_INT_CLR_UNION;
#endif
#define SOC_RSA_INT_CLR_finish_int_clr_START  (0)
#define SOC_RSA_INT_CLR_finish_int_clr_END    (0)


/*****************************************************************************
 结构名    : SOC_RSA_ALARM_MASK_UNION
 结构说明  : ALARM_MASK 寄存器结构定义。地址偏移量:0x0030，初值:0x00000005，宽度:32
 寄存器说明: ALARM屏蔽寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  rsa_dfa_alarm_mask : 4;  /* bit[0-3] : DFA ALARM屏蔽
                                                             0x5：屏蔽，不输出ALARM
                                                             其他：不屏蔽 */
        unsigned int  reserved           : 28; /* bit[4-31]: 保留 */
    } reg;
} SOC_RSA_ALARM_MASK_UNION;
#endif
#define SOC_RSA_ALARM_MASK_rsa_dfa_alarm_mask_START  (0)
#define SOC_RSA_ALARM_MASK_rsa_dfa_alarm_mask_END    (3)


/*****************************************************************************
 结构名    : SOC_RSA_ALARM_STATUS_UNION
 结构说明  : ALARM_STATUS 寄存器结构定义。地址偏移量:0x0034，初值:0x00000000，宽度:32
 寄存器说明: ALARM状态寄存器(屏蔽后上报的状态)
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  rsa_dfa_alarm_status    : 1;  /* bit[0]   : DFA ALARM 状态
                                                                  1：检测到DFA错误或者
                                                                  0：未检测到DFA错误 */
        unsigned int  rsa_attack_alarm_status : 1;  /* bit[1]   : 关键信号被攻击的ALARM状态
                                                                  1：检测到关键信号被攻击
                                                                  0：未检测到关键信号被攻击 */
        unsigned int  reserved_0              : 6;  /* bit[2-7] : 保留 */
        unsigned int  reserved_1              : 24; /* bit[8-31]: 保留 */
    } reg;
} SOC_RSA_ALARM_STATUS_UNION;
#endif
#define SOC_RSA_ALARM_STATUS_rsa_dfa_alarm_status_START     (0)
#define SOC_RSA_ALARM_STATUS_rsa_dfa_alarm_status_END       (0)
#define SOC_RSA_ALARM_STATUS_rsa_attack_alarm_status_START  (1)
#define SOC_RSA_ALARM_STATUS_rsa_attack_alarm_status_END    (1)


/*****************************************************************************
 结构名    : SOC_RSA_ALARM_NOMASK_STATUS_UNION
 结构说明  : ALARM_NOMASK_STATUS 寄存器结构定义。地址偏移量:0x0038，初值:0x00000000，宽度:32
 寄存器说明: ALARM屏蔽前状态寄存器(实际状态)
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  rsa_dfa_alarm_nomask_status    : 1;  /* bit[0]   : DFA ALARM 状态
                                                                         1：检测到DFA错误或者
                                                                         0：未检测到DFA错误 */
        unsigned int  rsa_attack_alarm_nomask_status : 1;  /* bit[1]   : 关键信号被攻击的ALARM状态
                                                                         1：检测到关键信号被攻击
                                                                         0：未检测到关键信号被攻击 */
        unsigned int  reserved_0                     : 6;  /* bit[2-7] : 保留 */
        unsigned int  reserved_1                     : 24; /* bit[8-31]: 保留 */
    } reg;
} SOC_RSA_ALARM_NOMASK_STATUS_UNION;
#endif
#define SOC_RSA_ALARM_NOMASK_STATUS_rsa_dfa_alarm_nomask_status_START     (0)
#define SOC_RSA_ALARM_NOMASK_STATUS_rsa_dfa_alarm_nomask_status_END       (0)
#define SOC_RSA_ALARM_NOMASK_STATUS_rsa_attack_alarm_nomask_status_START  (1)
#define SOC_RSA_ALARM_NOMASK_STATUS_rsa_attack_alarm_nomask_status_END    (1)


/*****************************************************************************
 结构名    : SOC_RSA_ALARM_CLR_UNION
 结构说明  : ALARM_CLR 寄存器结构定义。地址偏移量:0x003C，初值:0x00000000，宽度:32
 寄存器说明: ALARM清除寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  rsa_dfa_alarm_clr    : 4;  /* bit[0-3] : 说明：软件写0x5清除DFA ALARM源，其他值无效，逻辑只在收到写0x5的时刻才对DFA ALRAM进行清零。 */
        unsigned int  rsa_attack_alarm_clr : 4;  /* bit[4-7] : 说明：软件写0x5清除关键信号保护ALARM源，其他值无效，逻辑只在收到写0x5的时刻才对ALRAM进行清零。 */
        unsigned int  reserved             : 24; /* bit[8-31]: 保留 */
    } reg;
} SOC_RSA_ALARM_CLR_UNION;
#endif
#define SOC_RSA_ALARM_CLR_rsa_dfa_alarm_clr_START     (0)
#define SOC_RSA_ALARM_CLR_rsa_dfa_alarm_clr_END       (3)
#define SOC_RSA_ALARM_CLR_rsa_attack_alarm_clr_START  (4)
#define SOC_RSA_ALARM_CLR_rsa_attack_alarm_clr_END    (7)


/*****************************************************************************
 结构名    : SOC_RSA_RESULT_FLAG_UNION
 结构说明  : RESULT_FLAG 寄存器结构定义。地址偏移量:0x0040，初值:0x00000000，宽度:32
 寄存器说明: RSA结果标志寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  rsa_result_flag : 4;  /* bit[0-3] : 结果标志
                                                          0x00：初始或运行状态，无结果
                                                          0x05：处理成功，清RAM操作时RAM数据无效，其它操作RAM中有结果数据。
                                                          0x0a：处理失败，无结果数据。(失败原因见寄存器RSA_FAILURE_FLAG)
                                                          其他：保留。
                                                          说明：配置RSA_START启动操作后在RSA_BUSY由忙变为不忙时再读寄存器。 */
        unsigned int  reserved        : 28; /* bit[4-31]: 保留。 */
    } reg;
} SOC_RSA_RESULT_FLAG_UNION;
#endif
#define SOC_RSA_RESULT_FLAG_rsa_result_flag_START  (0)
#define SOC_RSA_RESULT_FLAG_rsa_result_flag_END    (3)


/*****************************************************************************
 结构名    : SOC_RSA_FAILURE_FLAG_UNION
 结构说明  : FAILURE_FLAG 寄存器结构定义。地址偏移量:0x0044，初值:0x00000000，宽度:32
 寄存器说明: RSA结果失败标志寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  rsa_failure_flag : 3;  /* bit[0-2] : 结果失败原因寄存器
                                                           0x0：初始或运行状态，无结果
                                                           0x1: 模逆无结果
                                                           0x2: 随机数申请失败
                                                           0x3: 被DFA导致失败
                                                           0x4:点乘或点加结果为无穷远点
                                                           其它：保留。 */
        unsigned int  reserved         : 29; /* bit[3-31]: 保留。 */
    } reg;
} SOC_RSA_FAILURE_FLAG_UNION;
#endif
#define SOC_RSA_FAILURE_FLAG_rsa_failure_flag_START  (0)
#define SOC_RSA_FAILURE_FLAG_rsa_failure_flag_END    (2)


/*****************************************************************************
 结构名    : SOC_RSA_STAT_CLR_UNION
 结构说明  : STAT_CLR 寄存器结构定义。地址偏移量:0x0050，初值:0x00000000，宽度:32
 寄存器说明: 统计清零寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  rsa_stat_clr : 1;  /* bit[0]   : 统计寄存器清零寄存器；
                                                       说明：该寄存器是电平信号，软件写1对统计寄存器清零处理，软件通过写0来停止清零功能。 */
        unsigned int  reserved     : 31; /* bit[1-31]: 保留 */
    } reg;
} SOC_RSA_STAT_CLR_UNION;
#endif
#define SOC_RSA_STAT_CLR_rsa_stat_clr_START  (0)
#define SOC_RSA_STAT_CLR_rsa_stat_clr_END    (0)


/*****************************************************************************
 结构名    : SOC_RSA_KEY_MSK_UNION
 结构说明  : KEY_MSK 寄存器结构定义。地址偏移量:0x0054，初值:0x00000000，宽度:32
 寄存器说明: RSA的密钥掩码寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  rsa_key_msk : 32; /* bit[0-31]: RSA在读写密钥（包括读密钥生成的结果）时的密钥屏蔽寄存器，需要在读写前进行配置，配置值为软件读取的一个随机数。 */
    } reg;
} SOC_RSA_KEY_MSK_UNION;
#endif
#define SOC_RSA_KEY_MSK_rsa_key_msk_START  (0)
#define SOC_RSA_KEY_MSK_rsa_key_msk_END    (31)


/*****************************************************************************
 结构名    : SOC_RSA_KEY_BACKUP_UNION
 结构说明  : KEY_BACKUP 寄存器结构定义。地址偏移量:0x0058，初值:0xDEADBEEF，宽度:32
 寄存器说明: RSA的密钥备份寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  rsa_key_backup : 32; /* bit[0-31]: RSA在读写密钥（包括读密钥生成的结果）时的密钥备份寄存器，写密钥的时候需要在写之前配置，读的时候需要在读之后读取。 */
    } reg;
} SOC_RSA_KEY_BACKUP_UNION;
#endif
#define SOC_RSA_KEY_BACKUP_rsa_key_backup_START  (0)
#define SOC_RSA_KEY_BACKUP_rsa_key_backup_END    (31)


/*****************************************************************************
 结构名    : SOC_RSA_LOCK_UNION
 结构说明  : LOCK 寄存器结构定义。地址偏移量:0x005C，初值:0x00000005，宽度:32
 寄存器说明: RSA的寄存器lock寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  rsa_lock : 4;  /* bit[0-3] : RSA中其他寄存器的lock寄存器：
                                                   0x5：lock使能；
                                                   0xA：lock不使能；
                                                   其他值：非法，会产生alarm。
                                                   配置其他寄存器前要配置lock寄存器为不使能状态。 */
        unsigned int  reserved : 28; /* bit[4-31]: 保留 */
    } reg;
} SOC_RSA_LOCK_UNION;
#endif
#define SOC_RSA_LOCK_rsa_lock_START  (0)
#define SOC_RSA_LOCK_rsa_lock_END    (3)


/*****************************************************************************
 结构名    : SOC_RSA_KEY_LOCK_UNION
 结构说明  : KEY_LOCK 寄存器结构定义。地址偏移量:0x0060，初值:0x00000005，宽度:32
 寄存器说明: RSA的密钥lock寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  rsa_key_lock : 4;  /* bit[0-3] : RSA中密钥寄存器的lock寄存器：
                                                       0x5：lock使能；
                                                       0xA：lock不使能；
                                                       其他值：非法，会产生alarm。
                                                       配置密钥寄存器、密钥备份寄存器前要配置lock寄存器为不使能状态。
                                                       当需要debug密钥寄存器和密钥备份寄存器时，需要将本寄存器配置为不使能状态。 */
        unsigned int  reserved     : 28; /* bit[4-31]: 保留 */
    } reg;
} SOC_RSA_KEY_LOCK_UNION;
#endif
#define SOC_RSA_KEY_LOCK_rsa_key_lock_START  (0)
#define SOC_RSA_KEY_LOCK_rsa_key_lock_END    (3)


/*****************************************************************************
 结构名    : SOC_RSA_VERSION_ID_UNION
 结构说明  : VERSION_ID 寄存器结构定义。地址偏移量:0x007C，初值:0x20160720，宽度:32
 寄存器说明: RSA的版本寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  rs_version_id : 32; /* bit[0-31]: 不同的版本的初始值不一样 */
    } reg;
} SOC_RSA_VERSION_ID_UNION;
#endif
#define SOC_RSA_VERSION_ID_rs_version_id_START  (0)
#define SOC_RSA_VERSION_ID_rs_version_id_END    (31)


/*****************************************************************************
 结构名    : SOC_RSA_LSB_N_EQUAL_ONE_UNION
 结构说明  : LSB_N_EQUAL_ONE 寄存器结构定义。地址偏移量:0x0080，初值:0x0000000A，宽度:32
 寄存器说明: RSA模数的最高位为1寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved : 32; /* bit[0-31]: RSA密钥生成时，N的高位是否强制为1，默认为4'ha
                                                   4'ha:生成的模数N的高位不强制为1
                                                   4'h5:生成的模数N的高位必须为1
                                                   其它值非法 */
    } reg;
} SOC_RSA_LSB_N_EQUAL_ONE_UNION;
#endif


/*****************************************************************************
 结构名    : SOC_RSA_MRAM_UNION
 结构说明  : MRAM 寄存器结构定义。地址偏移量:0x0200+(n)*4，初值:0x00000000，宽度:32
 寄存器说明: MRAM(4096bit)读写寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  mram : 32; /* bit[0-31]: CPU配置MRAM数据寄存器，芯片内部RAM为64bit位宽，软件按64bit为单位读写数据(n从偶数开始)。不同操作配置的数据地址空间请见用户手册描述
                                               说明：运行过程中不能读写。初始值是MRAM里的初始值，不一定是0。
                                               地址域的n范围[0,127] */
    } reg;
} SOC_RSA_MRAM_UNION;
#endif
#define SOC_RSA_MRAM_mram_START  (0)
#define SOC_RSA_MRAM_mram_END    (31)


/*****************************************************************************
 结构名    : SOC_RSA_NRAM_UNION
 结构说明  : NRAM 寄存器结构定义。地址偏移量:0x0600+(n)*4，初值:0x00000000，宽度:32
 寄存器说明: NRAM(4096bit)读写寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  nram : 32; /* bit[0-31]: CPU配置NRAM数据寄存器，芯片内部RAM为64bit位宽，软件按64bit为单位读写数据(n从偶数开始)。不同操作配置的数据地址空间请见用户手册描述
                                               说明：运行过程中不能读写。初始值是NRAM里的初始值，不一定是0。
                                               地址域的n范围[0,127] */
    } reg;
} SOC_RSA_NRAM_UNION;
#endif
#define SOC_RSA_NRAM_nram_START  (0)
#define SOC_RSA_NRAM_nram_END    (31)


/*****************************************************************************
 结构名    : SOC_RSA_KRAM_UNION
 结构说明  : KRAM 寄存器结构定义。地址偏移量:0x0A00+(n)*4，初值:0x00000000，宽度:32
 寄存器说明: KRAM(4096bit)读写寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  kram : 32; /* bit[0-31]: CPU配置KRAM数据寄存器，芯片内部RAM为64bit位宽，软件按64bit为单位读写数据(n从偶数开始)。不同操作配置的数据地址空间请见用户手册描述
                                               说明：运行过程中不能读写。调试模式下 非运行过程中可读写。初始值是KRAM里的初始值，不一定是0。
                                               地址域的n范围[0,127] */
    } reg;
} SOC_RSA_KRAM_UNION;
#endif
#define SOC_RSA_KRAM_kram_START  (0)
#define SOC_RSA_KRAM_kram_END    (31)


/*****************************************************************************
 结构名    : SOC_RSA_RRAM_UNION
 结构说明  : RRAM 寄存器结构定义。地址偏移量:0x0E00+(n)*4，初值:0x00000000，宽度:32
 寄存器说明: RRAM(4096bit)读写寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  rram : 32; /* bit[0-31]: CPU配置RRAM数据寄存器，芯片内部RAM为64bit位宽，软件按64bit为单位读写数据(n从偶数开始)。不同操作配置的数据地址空间请见用户手册描述
                                               说明：运行过程中不能读写。初始值是RRAM里的初始值，不一定是0。
                                               地址域的n范围[0,127] */
    } reg;
} SOC_RSA_RRAM_UNION;
#endif
#define SOC_RSA_RRAM_rram_START  (0)
#define SOC_RSA_RRAM_rram_END    (31)






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

#endif /* end of soc_rsa_interface.h */
