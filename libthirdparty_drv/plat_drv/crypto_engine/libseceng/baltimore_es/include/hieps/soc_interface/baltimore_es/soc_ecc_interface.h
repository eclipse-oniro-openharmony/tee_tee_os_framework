/******************************************************************************

                 版权所有 (C), 2001-2019, 华为技术有限公司

 ******************************************************************************
  文 件 名   : soc_ecc_interface.h
  版 本 号   : 初稿
  作    者   : Excel2Code
  生成日期   : 2019-10-26 10:53:22
  最近修改   :
  功能描述   : 接口头文件
  函数列表   :
  修改历史   :
  1.日    期   : 2019年10月26日
    作    者   : l00249396
    修改内容   : 从《HiEPS V200 nmanager寄存器手册_ECC.xml》自动生成

******************************************************************************/

/*****************************************************************************
  1 其他头文件包含
*****************************************************************************/

#ifndef __SOC_ECC_INTERFACE_H__
#define __SOC_ECC_INTERFACE_H__

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
/* 寄存器说明：ECC运算忙碌状态指示寄存器
   位域定义UNION结构:  SOC_ECC_BUSY_UNION */
#define SOC_ECC_BUSY_ADDR(base)                       ((base) + (0x0000))

/* 寄存器说明：运算模式选择寄存器
   位域定义UNION结构:  SOC_ECC_MODE_UNION */
#define SOC_ECC_MODE_ADDR(base)                       ((base) + (0x0004))

/* 寄存器说明：ECC_启动寄存器
   位域定义UNION结构:  SOC_ECC_START_UNION */
#define SOC_ECC_START_ADDR(base)                      ((base) + (0x0008))

/* 寄存器说明：RAM数据清除使能寄存器
   位域定义UNION结构:  SOC_ECC_RAM_CLR_EN_UNION */
#define SOC_ECC_RAM_CLR_EN_ADDR(base)                 ((base) + (0x000C))

/* 寄存器说明：RAM数据清除完成寄存器
   位域定义UNION结构:  SOC_ECC_RAM_CLR_DONE_UNION */
#define SOC_ECC_RAM_CLR_DONE_ADDR(base)               ((base) + (0x0010))

/* 寄存器说明：ECC运算完成原始中断寄存器
   位域定义UNION结构:  SOC_ECC_ORI_INT_UNION */
#define SOC_ECC_ORI_INT_ADDR(base)                    ((base) + (0x0014))

/* 寄存器说明：ECC运算完成屏蔽寄存器
   位域定义UNION结构:  SOC_ECC_INT_MSK_UNION */
#define SOC_ECC_INT_MSK_ADDR(base)                    ((base) + (0x0018))

/* 寄存器说明：ECC运算完成屏蔽后寄存器
   位域定义UNION结构:  SOC_ECC_INT_ECC_UNION */
#define SOC_ECC_INT_ECC_ADDR(base)                    ((base) + (0x001C))

/* 寄存器说明：ECC完成中断清除寄存器
   位域定义UNION结构:  SOC_ECC_INT_CLR_UNION */
#define SOC_ECC_INT_CLR_ADDR(base)                    ((base) + (0x0020))

/* 寄存器说明：ECC DFA原始告警寄存器
   位域定义UNION结构:  SOC_ECC_ALARM_DFA_ORI_UNION */
#define SOC_ECC_ALARM_DFA_ORI_ADDR(base)              ((base) + (0x0024))

/* 寄存器说明：ECC DFA告警屏蔽寄存器
   位域定义UNION结构:  SOC_ECC_ALARM_DFA_MSK_UNION */
#define SOC_ECC_ALARM_DFA_MSK_ADDR(base)              ((base) + (0x0028))

/* 寄存器说明：ECC DFA屏蔽后告警
   位域定义UNION结构:  SOC_ECC_ALARM_DFA_UNION */
#define SOC_ECC_ALARM_DFA_ADDR(base)                  ((base) + (0x002C))

/* 寄存器说明：ECC DFA告警清除寄存器
   位域定义UNION结构:  SOC_ECC_ALARM_DFA_CLR_UNION */
#define SOC_ECC_ALARM_DFA_CLR_ADDR(base)              ((base) + (0x0030))

/* 寄存器说明：ECC 信号保护原始告警寄存器
   位域定义UNION结构:  SOC_ECC_ALARM_PRT_ORI_UNION */
#define SOC_ECC_ALARM_PRT_ORI_ADDR(base)              ((base) + (0x0034))

/* 寄存器说明：ECC 信号保护告警屏蔽寄存器
   位域定义UNION结构:  SOC_ECC_ALARM_PRT_MSK_UNION */
#define SOC_ECC_ALARM_PRT_MSK_ADDR(base)              ((base) + (0x0038))

/* 寄存器说明：ECC 信号保护屏蔽后告警
   位域定义UNION结构:  SOC_ECC_ALARM_PRT_UNION */
#define SOC_ECC_ALARM_PRT_ADDR(base)                  ((base) + (0x003C))

/* 寄存器说明：ECC 信号保护告警清除寄存器
   位域定义UNION结构:  SOC_ECC_ALARM_PRT_CLR_UNION */
#define SOC_ECC_ALARM_PRT_CLR_ADDR(base)              ((base) + (0x0040))

/* 寄存器说明：点运算结果为无穷远点指示寄存器
   位域定义UNION结构:  SOC_ECC_POINT_RESULT_INFI_UNION */
#define SOC_ECC_POINT_RESULT_INFI_ADDR(base)          ((base) + (0x0044))

/* 寄存器说明：ECC密钥掩码寄存器
   位域定义UNION结构:  SOC_ECC_KEY_MSK_UNION */
#define SOC_ECC_KEY_MSK_ADDR(base)                    ((base) + (0x0048))

/* 寄存器说明：ECC密钥备份寄存器
   位域定义UNION结构:  SOC_ECC_KEY_BACKUP_UNION */
#define SOC_ECC_KEY_BACKUP_ADDR(base)                 ((base) + (0x004C))

/* 寄存器说明：ECC功耗加扰使能寄存器
   位域定义UNION结构:  SOC_ECC_SCRAMB_EN_UNION */
#define SOC_ECC_SCRAMB_EN_ADDR(base)                  ((base) + (0x0050))

/* 寄存器说明：ECC lock寄存器
   位域定义UNION结构:  SOC_ECC_LOCK_UNION */
#define SOC_ECC_LOCK_ADDR(base)                       ((base) + (0x0054))

/* 寄存器说明：ECC 密钥lock寄存器
   位域定义UNION结构:  SOC_ECC_KEY_LOCK_UNION */
#define SOC_ECC_KEY_LOCK_ADDR(base)                   ((base) + (0x0058))

/* 寄存器说明：ECC debug阶段去掩寄存器
   位域定义UNION结构:  SOC_ECC_DEBUG_UNMASK_UNION */
#define SOC_ECC_DEBUG_UNMASK_ADDR(base)               ((base) + (0x005C))

/* 寄存器说明：操作数1寄存器
   位域定义UNION结构:  SOC_ECC_EC_PX1_UNION */
#define SOC_ECC_EC_PX1_ADDR(base, n)                  ((base) + (0x0100+4*(n)))

/* 寄存器说明：操作数2寄存器
   位域定义UNION结构:  SOC_ECC_EC_PY1_UNION */
#define SOC_ECC_EC_PY1_ADDR(base, n)                  ((base) + (0x0148+4*(n)))

/* 寄存器说明：操作数3寄存器
   位域定义UNION结构:  SOC_ECC_EC_PX2_UNION */
#define SOC_ECC_EC_PX2_ADDR(base, n)                  ((base) + (0x0190+4*(n)))

/* 寄存器说明：操作数4寄存器
   位域定义UNION结构:  SOC_ECC_EC_PY2_UNION */
#define SOC_ECC_EC_PY2_ADDR(base, n)                  ((base) + (0x01D8+4*(n)))

/* 寄存器说明：模数寄存器
   位域定义UNION结构:  SOC_ECC_OPRAND_N_UNION */
#define SOC_ECC_OPRAND_N_ADDR(base, n)                ((base) + (0x0220+4*(n)))

/* 寄存器说明：预处理值寄存器
   位域定义UNION结构:  SOC_ECC_OPRAND_C_UNION */
#define SOC_ECC_OPRAND_C_ADDR(base, n)                ((base) + (0x0268+4*(n)))

/* 寄存器说明：结果1寄存器
   位域定义UNION结构:  SOC_ECC_RESULT_X_UNION */
#define SOC_ECC_RESULT_X_ADDR(base, n)                ((base) + (0x02B0+4*(n)))

/* 寄存器说明：结果2寄存器
   位域定义UNION结构:  SOC_ECC_RESULT_Y_UNION */
#define SOC_ECC_RESULT_Y_ADDR(base, n)                ((base) + (0x02F8+4*(n)))

/* 寄存器说明：点乘乘数寄存器
   位域定义UNION结构:  SOC_ECC_MUL_K_UNION */
#define SOC_ECC_MUL_K_ADDR(base, n)                   ((base) + (0x0340+4*(n)))

/* 寄存器说明：椭圆曲线参数中P寄存器
   位域定义UNION结构:  SOC_ECC_EC_PARA_P_UNION */
#define SOC_ECC_EC_PARA_P_ADDR(base, n)               ((base) + (0x0388+4*(n)))

/* 寄存器说明：椭圆曲线参数中A寄存器
   位域定义UNION结构:  SOC_ECC_EC_PARA_A_UNION */
#define SOC_ECC_EC_PARA_A_ADDR(base, n)               ((base) + (0x03D0+4*(n)))

/* 寄存器说明：椭圆曲线参数中B寄存器
   位域定义UNION结构:  SOC_ECC_EC_PARA_B_UNION */
#define SOC_ECC_EC_PARA_B_ADDR(base, n)               ((base) + (0x0418+4*(n)))

/* 寄存器说明：椭圆曲线参数中N寄存器
   位域定义UNION结构:  SOC_ECC_EC_PARA_N_UNION */
#define SOC_ECC_EC_PARA_N_ADDR(base, n)               ((base) + (0x0460+4*(n)))

/* 寄存器说明：椭圆曲线参数中基点G的X坐标寄存器
   位域定义UNION结构:  SOC_ECC_EC_PARA_GX_UNION */
#define SOC_ECC_EC_PARA_GX_ADDR(base, n)              ((base) + (0x04A8+4*(n)))

/* 寄存器说明：椭圆曲线参数中基点G的Y坐标寄存器
   位域定义UNION结构:  SOC_ECC_EC_PARA_GY_UNION */
#define SOC_ECC_EC_PARA_GY_ADDR(base, n)              ((base) + (0x04F0+4*(n)))





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
 结构名    : SOC_ECC_BUSY_UNION
 结构说明  : BUSY 寄存器结构定义。地址偏移量:0x0000，初值:0x0000000A，宽度:32
 寄存器说明: ECC运算忙碌状态指示寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ecc_busy : 4;  /* bit[0-3] : ECC运算状态指示寄存器
                                                   A：ECC运算没有进行或已经结束；
                                                   5：ECC运算正在进行。 */
        unsigned int  reverved : 28; /* bit[4-31]:  */
    } reg;
} SOC_ECC_BUSY_UNION;
#endif
#define SOC_ECC_BUSY_ecc_busy_START  (0)
#define SOC_ECC_BUSY_ecc_busy_END    (3)
#define SOC_ECC_BUSY_reverved_START  (4)
#define SOC_ECC_BUSY_reverved_END    (31)


/*****************************************************************************
 结构名    : SOC_ECC_MODE_UNION
 结构说明  : MODE 寄存器结构定义。地址偏移量:0x0004，初值:0x00000040，宽度:32
 寄存器说明: 运算模式选择寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  mode     : 4;  /* bit[0-3] : ECC模式选择寄存器：
                                                   000：点乘运算；
                                                   001：点加运算；
                                                   010：模乘运算；
                                                   011：模加运算；
                                                   100：模减运算；
                                                   101：模逆运算；
                                                   其他值：非法值，将上报alarm。 */
        unsigned int  length   : 4;  /* bit[4-7] : ECC运算长度寄存器：
                                                   2：128 bits
                                                   3：192 bits
                                                   4：256 bits
                                                   其他值：非法，上报alarm */
        unsigned int  reverved : 24; /* bit[8-31]:  */
    } reg;
} SOC_ECC_MODE_UNION;
#endif
#define SOC_ECC_MODE_mode_START      (0)
#define SOC_ECC_MODE_mode_END        (3)
#define SOC_ECC_MODE_length_START    (4)
#define SOC_ECC_MODE_length_END      (7)
#define SOC_ECC_MODE_reverved_START  (8)
#define SOC_ECC_MODE_reverved_END    (31)


/*****************************************************************************
 结构名    : SOC_ECC_START_UNION
 结构说明  : START 寄存器结构定义。地址偏移量:0x0008，初值:0x0000000A，宽度:32
 寄存器说明: ECC_启动寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ecc_start : 4;  /* bit[0-3] : ECC运算启动信号
                                                    5：启动；
                                                    A：未启动。 */
        unsigned int  reverved  : 28; /* bit[4-31]:  */
    } reg;
} SOC_ECC_START_UNION;
#endif
#define SOC_ECC_START_ecc_start_START  (0)
#define SOC_ECC_START_ecc_start_END    (3)
#define SOC_ECC_START_reverved_START   (4)
#define SOC_ECC_START_reverved_END     (31)


/*****************************************************************************
 结构名    : SOC_ECC_RAM_CLR_EN_UNION
 结构说明  : RAM_CLR_EN 寄存器结构定义。地址偏移量:0x000C，初值:0x0000000A，宽度:32
 寄存器说明: RAM数据清除使能寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ecc_ram_clr_en : 4;  /* bit[0-3] : RAM清零寄存器：
                                                         5：使能清零功能；
                                                         A：不使能清零功能。 */
        unsigned int  reverved       : 28; /* bit[4-31]:  */
    } reg;
} SOC_ECC_RAM_CLR_EN_UNION;
#endif
#define SOC_ECC_RAM_CLR_EN_ecc_ram_clr_en_START  (0)
#define SOC_ECC_RAM_CLR_EN_ecc_ram_clr_en_END    (3)
#define SOC_ECC_RAM_CLR_EN_reverved_START        (4)
#define SOC_ECC_RAM_CLR_EN_reverved_END          (31)


/*****************************************************************************
 结构名    : SOC_ECC_RAM_CLR_DONE_UNION
 结构说明  : RAM_CLR_DONE 寄存器结构定义。地址偏移量:0x0010，初值:0x0000000A，宽度:32
 寄存器说明: RAM数据清除完成寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ecc_ram_clr_done : 4;  /* bit[0-3] : RAM清零完成指示寄存器：
                                                           5：RAM使能清零已经完成；
                                                           A：RAM使能清零功能未完成。 */
        unsigned int  reverved         : 28; /* bit[4-31]:  */
    } reg;
} SOC_ECC_RAM_CLR_DONE_UNION;
#endif
#define SOC_ECC_RAM_CLR_DONE_ecc_ram_clr_done_START  (0)
#define SOC_ECC_RAM_CLR_DONE_ecc_ram_clr_done_END    (3)
#define SOC_ECC_RAM_CLR_DONE_reverved_START          (4)
#define SOC_ECC_RAM_CLR_DONE_reverved_END            (31)


/*****************************************************************************
 结构名    : SOC_ECC_ORI_INT_UNION
 结构说明  : ORI_INT 寄存器结构定义。地址偏移量:0x0014，初值:0x0000000A，宽度:32
 寄存器说明: ECC运算完成原始中断寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ecc_ori_int : 4;  /* bit[0-3] : 原始中断状态寄存器：
                                                      A：ECC运算完成中断没有产生或运算还没有开始；
                                                      5：ECC运算完成中断产生。 */
        unsigned int  reverved    : 28; /* bit[4-31]:  */
    } reg;
} SOC_ECC_ORI_INT_UNION;
#endif
#define SOC_ECC_ORI_INT_ecc_ori_int_START  (0)
#define SOC_ECC_ORI_INT_ecc_ori_int_END    (3)
#define SOC_ECC_ORI_INT_reverved_START     (4)
#define SOC_ECC_ORI_INT_reverved_END       (31)


/*****************************************************************************
 结构名    : SOC_ECC_INT_MSK_UNION
 结构说明  : INT_MSK 寄存器结构定义。地址偏移量:0x0018，初值:0x00000005，宽度:32
 寄存器说明: ECC运算完成屏蔽寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ecc_int_msk : 4;  /* bit[0-3] : 中断屏蔽寄存器：
                                                      4'hA：不屏蔽原始中断；
                                                      4'h5：屏蔽原始中断；
                                                      其他：非法，会产生alarm。 */
        unsigned int  reverved    : 28; /* bit[4-31]:  */
    } reg;
} SOC_ECC_INT_MSK_UNION;
#endif
#define SOC_ECC_INT_MSK_ecc_int_msk_START  (0)
#define SOC_ECC_INT_MSK_ecc_int_msk_END    (3)
#define SOC_ECC_INT_MSK_reverved_START     (4)
#define SOC_ECC_INT_MSK_reverved_END       (31)


/*****************************************************************************
 结构名    : SOC_ECC_INT_ECC_UNION
 结构说明  : INT_ECC 寄存器结构定义。地址偏移量:0x001C，初值:0x0000000A，宽度:32
 寄存器说明: ECC运算完成屏蔽后寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  int_ecc  : 4;  /* bit[0-3] : 屏蔽后中断：
                                                   A：屏蔽后中断无效；
                                                   5：屏蔽后中断有效。 */
        unsigned int  reverved : 28; /* bit[4-31]:  */
    } reg;
} SOC_ECC_INT_ECC_UNION;
#endif
#define SOC_ECC_INT_ECC_int_ecc_START   (0)
#define SOC_ECC_INT_ECC_int_ecc_END     (3)
#define SOC_ECC_INT_ECC_reverved_START  (4)
#define SOC_ECC_INT_ECC_reverved_END    (31)


/*****************************************************************************
 结构名    : SOC_ECC_INT_CLR_UNION
 结构说明  : INT_CLR 寄存器结构定义。地址偏移量:0x0020，初值:0x0000000A，宽度:32
 寄存器说明: ECC完成中断清除寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ecc_int_clr : 4;  /* bit[0-3] : 中断清除寄存器：
                                                      0xA：不清除原始中断和屏蔽后中断；
                                                      0x5：清除原始中断和屏蔽后中断。
                                                      其他：非法，会产生alarm。 */
        unsigned int  reverved    : 28; /* bit[4-31]:  */
    } reg;
} SOC_ECC_INT_CLR_UNION;
#endif
#define SOC_ECC_INT_CLR_ecc_int_clr_START  (0)
#define SOC_ECC_INT_CLR_ecc_int_clr_END    (3)
#define SOC_ECC_INT_CLR_reverved_START     (4)
#define SOC_ECC_INT_CLR_reverved_END       (31)


/*****************************************************************************
 结构名    : SOC_ECC_ALARM_DFA_ORI_UNION
 结构说明  : ALARM_DFA_ORI 寄存器结构定义。地址偏移量:0x0024，初值:0x0000000A，宽度:32
 寄存器说明: ECC DFA原始告警寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  alarm_dfa_ori : 4;  /* bit[0-3] : 原始DFA告警状态寄存器：
                                                        A：ECC DFA告警没有产生或运算还没有开始；
                                                        5：ECC DFA告警产生。 */
        unsigned int  reverved      : 28; /* bit[4-31]:  */
    } reg;
} SOC_ECC_ALARM_DFA_ORI_UNION;
#endif
#define SOC_ECC_ALARM_DFA_ORI_alarm_dfa_ori_START  (0)
#define SOC_ECC_ALARM_DFA_ORI_alarm_dfa_ori_END    (3)
#define SOC_ECC_ALARM_DFA_ORI_reverved_START       (4)
#define SOC_ECC_ALARM_DFA_ORI_reverved_END         (31)


/*****************************************************************************
 结构名    : SOC_ECC_ALARM_DFA_MSK_UNION
 结构说明  : ALARM_DFA_MSK 寄存器结构定义。地址偏移量:0x0028，初值:0x0000000A，宽度:32
 寄存器说明: ECC DFA告警屏蔽寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  alarm_dfa_msk : 4;  /* bit[0-3] : 告警屏蔽寄存器：
                                                        4'hA：不屏蔽原始告警；
                                                        4'h5：屏蔽原始告警；
                                                        其他：非法，会产生alarm。 */
        unsigned int  reverved      : 28; /* bit[4-31]:  */
    } reg;
} SOC_ECC_ALARM_DFA_MSK_UNION;
#endif
#define SOC_ECC_ALARM_DFA_MSK_alarm_dfa_msk_START  (0)
#define SOC_ECC_ALARM_DFA_MSK_alarm_dfa_msk_END    (3)
#define SOC_ECC_ALARM_DFA_MSK_reverved_START       (4)
#define SOC_ECC_ALARM_DFA_MSK_reverved_END         (31)


/*****************************************************************************
 结构名    : SOC_ECC_ALARM_DFA_UNION
 结构说明  : ALARM_DFA 寄存器结构定义。地址偏移量:0x002C，初值:0x0000000A，宽度:32
 寄存器说明: ECC DFA屏蔽后告警
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  alarm_dfa : 4;  /* bit[0-3] : 屏蔽后告警：
                                                    A：ECC DFA告警没有产生或运算还没有开始；
                                                    5：ECC DFA告警产生。 */
        unsigned int  reverved  : 28; /* bit[4-31]:  */
    } reg;
} SOC_ECC_ALARM_DFA_UNION;
#endif
#define SOC_ECC_ALARM_DFA_alarm_dfa_START  (0)
#define SOC_ECC_ALARM_DFA_alarm_dfa_END    (3)
#define SOC_ECC_ALARM_DFA_reverved_START   (4)
#define SOC_ECC_ALARM_DFA_reverved_END     (31)


/*****************************************************************************
 结构名    : SOC_ECC_ALARM_DFA_CLR_UNION
 结构说明  : ALARM_DFA_CLR 寄存器结构定义。地址偏移量:0x0030，初值:0x0000000A，宽度:32
 寄存器说明: ECC DFA告警清除寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  alarm_dfa_clr : 4;  /* bit[0-3] : 告警清除寄存器：
                                                        4'hA：不清除告警；
                                                        4'h5：清除告警；
                                                        其他：非法，会产生alarm。 */
        unsigned int  reverved      : 28; /* bit[4-31]:  */
    } reg;
} SOC_ECC_ALARM_DFA_CLR_UNION;
#endif
#define SOC_ECC_ALARM_DFA_CLR_alarm_dfa_clr_START  (0)
#define SOC_ECC_ALARM_DFA_CLR_alarm_dfa_clr_END    (3)
#define SOC_ECC_ALARM_DFA_CLR_reverved_START       (4)
#define SOC_ECC_ALARM_DFA_CLR_reverved_END         (31)


/*****************************************************************************
 结构名    : SOC_ECC_ALARM_PRT_ORI_UNION
 结构说明  : ALARM_PRT_ORI 寄存器结构定义。地址偏移量:0x0034，初值:0x0000000A，宽度:32
 寄存器说明: ECC 信号保护原始告警寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  alarm_prt_ori : 4;  /* bit[0-3] : 原始PRT告警状态寄存器：
                                                        A：ECC PRT告警没有产生或运算还没有开始；
                                                        5：ECC PRT告警产生。 */
        unsigned int  reverved      : 28; /* bit[4-31]:  */
    } reg;
} SOC_ECC_ALARM_PRT_ORI_UNION;
#endif
#define SOC_ECC_ALARM_PRT_ORI_alarm_prt_ori_START  (0)
#define SOC_ECC_ALARM_PRT_ORI_alarm_prt_ori_END    (3)
#define SOC_ECC_ALARM_PRT_ORI_reverved_START       (4)
#define SOC_ECC_ALARM_PRT_ORI_reverved_END         (31)


/*****************************************************************************
 结构名    : SOC_ECC_ALARM_PRT_MSK_UNION
 结构说明  : ALARM_PRT_MSK 寄存器结构定义。地址偏移量:0x0038，初值:0x0000000A，宽度:32
 寄存器说明: ECC 信号保护告警屏蔽寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  alarm_prt_msk : 4;  /* bit[0-3] : 告警屏蔽寄存器：
                                                        4'hA：不屏蔽原始告警；
                                                        4'h5：屏蔽原始告警；
                                                        其他：非法，会产生alarm。 */
        unsigned int  reverved      : 28; /* bit[4-31]:  */
    } reg;
} SOC_ECC_ALARM_PRT_MSK_UNION;
#endif
#define SOC_ECC_ALARM_PRT_MSK_alarm_prt_msk_START  (0)
#define SOC_ECC_ALARM_PRT_MSK_alarm_prt_msk_END    (3)
#define SOC_ECC_ALARM_PRT_MSK_reverved_START       (4)
#define SOC_ECC_ALARM_PRT_MSK_reverved_END         (31)


/*****************************************************************************
 结构名    : SOC_ECC_ALARM_PRT_UNION
 结构说明  : ALARM_PRT 寄存器结构定义。地址偏移量:0x003C，初值:0x0000000A，宽度:32
 寄存器说明: ECC 信号保护屏蔽后告警
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  alarm_prt : 4;  /* bit[0-3] : 屏蔽后告警：
                                                    A：ECC PRT告警没有产生或运算还没有开始；
                                                    5：ECC PRT告警产生。 */
        unsigned int  reverved  : 28; /* bit[4-31]:  */
    } reg;
} SOC_ECC_ALARM_PRT_UNION;
#endif
#define SOC_ECC_ALARM_PRT_alarm_prt_START  (0)
#define SOC_ECC_ALARM_PRT_alarm_prt_END    (3)
#define SOC_ECC_ALARM_PRT_reverved_START   (4)
#define SOC_ECC_ALARM_PRT_reverved_END     (31)


/*****************************************************************************
 结构名    : SOC_ECC_ALARM_PRT_CLR_UNION
 结构说明  : ALARM_PRT_CLR 寄存器结构定义。地址偏移量:0x0040，初值:0x0000000A，宽度:32
 寄存器说明: ECC 信号保护告警清除寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  alarm_prt_clr : 4;  /* bit[0-3] : 告警清除寄存器：
                                                        4'hA：不清除告警；
                                                        4'h5：清除告警；
                                                        其他：非法，会产生alarm。 */
        unsigned int  reverved      : 28; /* bit[4-31]:  */
    } reg;
} SOC_ECC_ALARM_PRT_CLR_UNION;
#endif
#define SOC_ECC_ALARM_PRT_CLR_alarm_prt_clr_START  (0)
#define SOC_ECC_ALARM_PRT_CLR_alarm_prt_clr_END    (3)
#define SOC_ECC_ALARM_PRT_CLR_reverved_START       (4)
#define SOC_ECC_ALARM_PRT_CLR_reverved_END         (31)


/*****************************************************************************
 结构名    : SOC_ECC_POINT_RESULT_INFI_UNION
 结构说明  : POINT_RESULT_INFI 寄存器结构定义。地址偏移量:0x0044，初值:0x0000000A，宽度:32
 寄存器说明: 点运算结果为无穷远点指示寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  point_result_infi : 4;  /* bit[0-3] : 点运算结果为无穷远点指示寄存器：
                                                            5：点运算结果为无穷远点；
                                                            A：点运算结果不是无穷远点。 */
        unsigned int  reverved          : 28; /* bit[4-31]:  */
    } reg;
} SOC_ECC_POINT_RESULT_INFI_UNION;
#endif
#define SOC_ECC_POINT_RESULT_INFI_point_result_infi_START  (0)
#define SOC_ECC_POINT_RESULT_INFI_point_result_infi_END    (3)
#define SOC_ECC_POINT_RESULT_INFI_reverved_START           (4)
#define SOC_ECC_POINT_RESULT_INFI_reverved_END             (31)


/*****************************************************************************
 结构名    : SOC_ECC_KEY_MSK_UNION
 结构说明  : KEY_MSK 寄存器结构定义。地址偏移量:0x0048，初值:0x00000000，宽度:32
 寄存器说明: ECC密钥掩码寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ecc_key_msk : 32; /* bit[0-31]: ECC模块读写密钥时的掩码寄存器，该寄存器需要在读写密钥前进行配置。 */
    } reg;
} SOC_ECC_KEY_MSK_UNION;
#endif
#define SOC_ECC_KEY_MSK_ecc_key_msk_START  (0)
#define SOC_ECC_KEY_MSK_ecc_key_msk_END    (31)


/*****************************************************************************
 结构名    : SOC_ECC_KEY_BACKUP_UNION
 结构说明  : KEY_BACKUP 寄存器结构定义。地址偏移量:0x004C，初值:0x00000000，宽度:32
 寄存器说明: ECC密钥备份寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ecc_key_backup : 32; /* bit[0-31]: ECC模块读写密钥时的密钥备份寄存器，该寄存器在进行读写每32bit密钥前进行配置。 */
    } reg;
} SOC_ECC_KEY_BACKUP_UNION;
#endif
#define SOC_ECC_KEY_BACKUP_ecc_key_backup_START  (0)
#define SOC_ECC_KEY_BACKUP_ecc_key_backup_END    (31)


/*****************************************************************************
 结构名    : SOC_ECC_SCRAMB_EN_UNION
 结构说明  : SCRAMB_EN 寄存器结构定义。地址偏移量:0x0050，初值:0x0000000A，宽度:32
 寄存器说明: ECC功耗加扰使能寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ecc_scramb_en : 4;  /* bit[0-3] : ECC功耗加扰使能寄存器：
                                                        0x5：功耗加扰使能；
                                                        0xA：功耗加扰不使能；
                                                        其他值：非法值，将上报alarm。
                                                        ECC功耗加扰的配置为点加的配置；功耗加扰完成后不产生中断。 */
        unsigned int  reverved      : 28; /* bit[4-31]:  */
    } reg;
} SOC_ECC_SCRAMB_EN_UNION;
#endif
#define SOC_ECC_SCRAMB_EN_ecc_scramb_en_START  (0)
#define SOC_ECC_SCRAMB_EN_ecc_scramb_en_END    (3)
#define SOC_ECC_SCRAMB_EN_reverved_START       (4)
#define SOC_ECC_SCRAMB_EN_reverved_END         (31)


/*****************************************************************************
 结构名    : SOC_ECC_LOCK_UNION
 结构说明  : LOCK 寄存器结构定义。地址偏移量:0x0054，初值:0x00000005，宽度:32
 寄存器说明: ECC lock寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ecc_lock : 4;  /* bit[0-3] : ECC中其他寄存器的lock寄存器：
                                                   0x5：lock使能；
                                                   0xA：lock不使能；
                                                   其他值：非法值，将上报alarm。
                                                   配置其他寄存器前要配置lock寄存器为不使能状态。 */
        unsigned int  reverved : 28; /* bit[4-31]:  */
    } reg;
} SOC_ECC_LOCK_UNION;
#endif
#define SOC_ECC_LOCK_ecc_lock_START  (0)
#define SOC_ECC_LOCK_ecc_lock_END    (3)
#define SOC_ECC_LOCK_reverved_START  (4)
#define SOC_ECC_LOCK_reverved_END    (31)


/*****************************************************************************
 结构名    : SOC_ECC_KEY_LOCK_UNION
 结构说明  : KEY_LOCK 寄存器结构定义。地址偏移量:0x0058，初值:0x00000005，宽度:32
 寄存器说明: ECC 密钥lock寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ecc_key_lock : 4;  /* bit[0-3] : ECC中密钥寄存器和密钥备份寄存器的lock寄存器：
                                                       0x5：lock使能；
                                                       0xA：lock不使能；
                                                       其他值：非法值，将上报alarm。
                                                       配置密钥寄存器、密钥备份寄存器前要配置lock寄存器为不使能状态。
                                                       当需要debug密钥寄存器和密钥备份寄存器时，需要将本寄存器配置为不使能状态。 */
        unsigned int  reverved     : 28; /* bit[4-31]:  */
    } reg;
} SOC_ECC_KEY_LOCK_UNION;
#endif
#define SOC_ECC_KEY_LOCK_ecc_key_lock_START  (0)
#define SOC_ECC_KEY_LOCK_ecc_key_lock_END    (3)
#define SOC_ECC_KEY_LOCK_reverved_START      (4)
#define SOC_ECC_KEY_LOCK_reverved_END        (31)


/*****************************************************************************
 结构名    : SOC_ECC_DEBUG_UNMASK_UNION
 结构说明  : DEBUG_UNMASK 寄存器结构定义。地址偏移量:0x005C，初值:0x0000000A，宽度:32
 寄存器说明: ECC debug阶段去掩寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ecc_debug_unmask : 4;  /* bit[0-3] : ECC在debug阶段将内部掩码去除的寄存器：
                                                           0x5：去掩使能；
                                                           0xA：去掩不使能；
                                                           其他值：非法值，将上报alarm。
                                                           该寄存器只能在debug状态下生效，和otp送过来的debug_disable信号共同控制内部掩码的去掩，非debug状态下可读可写，但不起作用。 */
        unsigned int  reverved         : 28; /* bit[4-31]:  */
    } reg;
} SOC_ECC_DEBUG_UNMASK_UNION;
#endif
#define SOC_ECC_DEBUG_UNMASK_ecc_debug_unmask_START  (0)
#define SOC_ECC_DEBUG_UNMASK_ecc_debug_unmask_END    (3)
#define SOC_ECC_DEBUG_UNMASK_reverved_START          (4)
#define SOC_ECC_DEBUG_UNMASK_reverved_END            (31)


/*****************************************************************************
 结构名    : SOC_ECC_EC_PX1_UNION
 结构说明  : EC_PX1 寄存器结构定义。地址偏移量:0x0100+4*(n)，初值:0x00000000，宽度:32
 寄存器说明: 操作数1寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ec_px1 : 32; /* bit[0-31]: CPU配置数据寄存器，芯片内部RAM为64bit位宽，软件按64bit为单位读写数据(n从偶数开始)。不同操作配置的数据地址空间请见用户手册描述
                                                 说明：运行过程中不能读写。初始值是RAM里的初始值，不一定是0。
                                                 地址域的n范围[0,7]。
                                                 根据ecc_mode[2:0]来判定该寄存器的含义：
                                                 ecc_mode[2:0]=000(点乘)：点乘运算中椭圆曲线点的x坐标；
                                                 ecc_mode[2:0]=001(点加)：点加运算中第一个椭圆曲线点的x坐标；
                                                 ecc_mode[2:0]=010(模乘)：模乘运算中第一个操作数；
                                                 ecc_mode[2:0]=011(模加)：模加运算中第一个操作数；
                                                 ecc_mode[2:0]=100(模减)：模减运算中第一个操作数；
                                                 ecc_mode[2:0]=101(模逆)：模逆运算中的操作数；
                                                 ecc_mode[2:0]=其他：保留，无意义。 */
    } reg;
} SOC_ECC_EC_PX1_UNION;
#endif
#define SOC_ECC_EC_PX1_ec_px1_START  (0)
#define SOC_ECC_EC_PX1_ec_px1_END    (31)


/*****************************************************************************
 结构名    : SOC_ECC_EC_PY1_UNION
 结构说明  : EC_PY1 寄存器结构定义。地址偏移量:0x0148+4*(n)，初值:0x00000000，宽度:32
 寄存器说明: 操作数2寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ec_py1 : 32; /* bit[0-31]: 配置方式同ec_px1。
                                                 根据ecc_mode[2:0]来判定该数据的含义：
                                                 ecc_mode[2:0]=000(点乘)：点乘运算中椭圆曲线点的y坐标；
                                                 ecc_mode[2:0]=001(点加)：点加运算中第一个椭圆曲线点的y坐标；
                                                 ecc_mode[2:0]=010(模乘)：模乘运算中第二个操作数；
                                                 ecc_mode[2:0]=011(模加)：模加运算中第二个操作数；
                                                 ecc_mode[2:0]=100(模减)：模减运算中第二个操作数；
                                                 ecc_mode[2:0]=其他：保留，无意义。 */
    } reg;
} SOC_ECC_EC_PY1_UNION;
#endif
#define SOC_ECC_EC_PY1_ec_py1_START  (0)
#define SOC_ECC_EC_PY1_ec_py1_END    (31)


/*****************************************************************************
 结构名    : SOC_ECC_EC_PX2_UNION
 结构说明  : EC_PX2 寄存器结构定义。地址偏移量:0x0190+4*(n)，初值:0x00000000，宽度:32
 寄存器说明: 操作数3寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ec_px2 : 32; /* bit[0-31]: 配置方式同ec_px1。
                                                 根据ecc_mode[2:0]来判定该数据的含义：
                                                 ecc_mode[2:0]=001(点加)：点加运算中第二个椭圆曲线点的x坐标；
                                                 ecc_mode[2:0]=其他：保留，无意义。 */
    } reg;
} SOC_ECC_EC_PX2_UNION;
#endif
#define SOC_ECC_EC_PX2_ec_px2_START  (0)
#define SOC_ECC_EC_PX2_ec_px2_END    (31)


/*****************************************************************************
 结构名    : SOC_ECC_EC_PY2_UNION
 结构说明  : EC_PY2 寄存器结构定义。地址偏移量:0x01D8+4*(n)，初值:0x00000000，宽度:32
 寄存器说明: 操作数4寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ec_py2 : 32; /* bit[0-31]: 配置方式同ec_px1。
                                                 根据ecc_mode[2:0]来判定该数据的含义：
                                                 ecc_mode[2:0]=001(点加)：点加运算中第二个椭圆曲线点的y坐标；
                                                 ecc_mode[2:0]=其他：保留，无意义。 */
    } reg;
} SOC_ECC_EC_PY2_UNION;
#endif
#define SOC_ECC_EC_PY2_ec_py2_START  (0)
#define SOC_ECC_EC_PY2_ec_py2_END    (31)


/*****************************************************************************
 结构名    : SOC_ECC_OPRAND_N_UNION
 结构说明  : OPRAND_N 寄存器结构定义。地址偏移量:0x0220+4*(n)，初值:0x00000000，宽度:32
 寄存器说明: 模数寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  oprand_n : 32; /* bit[0-31]: 配置方式同ec_px1。
                                                   模运算处理中的模数，模数的值有两种情况：
                                                   （1） 如果ecc_mode[2:0]=000或者ecc_mode[2:0]=001，即进行的运算的椭圆曲线上的点乘或者点加运算，此处的operand_n [255:0]是椭圆曲线参数p[255:0]；
                                                   （2） 如果进行的不是椭圆曲线上的点加或者点乘，进行的是模处理操作，此处的operand_n [255:0]是256bit的模数。 */
    } reg;
} SOC_ECC_OPRAND_N_UNION;
#endif
#define SOC_ECC_OPRAND_N_oprand_n_START  (0)
#define SOC_ECC_OPRAND_N_oprand_n_END    (31)


/*****************************************************************************
 结构名    : SOC_ECC_OPRAND_C_UNION
 结构说明  : OPRAND_C 寄存器结构定义。地址偏移量:0x0268+4*(n)，初值:0x00000000，宽度:32
 寄存器说明: 预处理值寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  oprand_c : 32; /* bit[0-31]: 配置方式同ec_px1。
                                                   预处理值C = 2 (2*64*（len+1）) mod operand_n [255:0] 的值，软件预处理好之后通过写该寄存器放置在片内RAM中,这里的operand_n [255:0]为模数，operand_n [255:0]的值可能有两种情况，具体请参考operand_n [255:0]寄存器描述。 */
    } reg;
} SOC_ECC_OPRAND_C_UNION;
#endif
#define SOC_ECC_OPRAND_C_oprand_c_START  (0)
#define SOC_ECC_OPRAND_C_oprand_c_END    (31)


/*****************************************************************************
 结构名    : SOC_ECC_RESULT_X_UNION
 结构说明  : RESULT_X 寄存器结构定义。地址偏移量:0x02B0+4*(n)，初值:0x00000000，宽度:32
 寄存器说明: 结果1寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  result_x : 32; /* bit[0-31]: 配置方式同ec_px1。
                                                   根据ecc_mode[2:0]来判定该数据的含义：
                                                   ecc_mode[2:0]=000(点乘)：点乘运算结果中椭圆曲线点的x坐标；
                                                   ecc_mode[2:0]=001(点加)：点加运算结果中椭圆曲线点的x坐标；
                                                   ecc_mode[2:0]=010(模乘)：模乘运算结果；
                                                   ecc_mode[2:0]=011(模加)：模加运算结果；
                                                   ecc_mode[2:0]=100(模减)：模减运算结果；
                                                   ecc_mode[2:0]=101(模逆)：模逆运算结果；
                                                   ecc_mode[2:0]=其他：保留，无意义。 */
    } reg;
} SOC_ECC_RESULT_X_UNION;
#endif
#define SOC_ECC_RESULT_X_result_x_START  (0)
#define SOC_ECC_RESULT_X_result_x_END    (31)


/*****************************************************************************
 结构名    : SOC_ECC_RESULT_Y_UNION
 结构说明  : RESULT_Y 寄存器结构定义。地址偏移量:0x02F8+4*(n)，初值:0x00000000，宽度:32
 寄存器说明: 结果2寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  result_y : 32; /* bit[0-31]: 配置方式同ec_px1。
                                                   根据ecc_mode[2:0]来判定该数据的含义：
                                                   ecc_mode[2:0]=000(点乘)：点乘运算结果中椭圆曲线点的y坐标；
                                                   ecc_mode[2:0]=001(点加)：点加运算结果中椭圆曲线点的y坐标；
                                                   ecc_mode[2:0]=其他：保留，无意义。 */
    } reg;
} SOC_ECC_RESULT_Y_UNION;
#endif
#define SOC_ECC_RESULT_Y_result_y_START  (0)
#define SOC_ECC_RESULT_Y_result_y_END    (31)


/*****************************************************************************
 结构名    : SOC_ECC_MUL_K_UNION
 结构说明  : MUL_K 寄存器结构定义。地址偏移量:0x0340+4*(n)，初值:0x00000000，宽度:32
 寄存器说明: 点乘乘数寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  mul_k : 32; /* bit[0-31]: 配置方式同ec_px1。
                                                点乘算法中256bit的整数。 */
    } reg;
} SOC_ECC_MUL_K_UNION;
#endif
#define SOC_ECC_MUL_K_mul_k_START  (0)
#define SOC_ECC_MUL_K_mul_k_END    (31)


/*****************************************************************************
 结构名    : SOC_ECC_EC_PARA_P_UNION
 结构说明  : EC_PARA_P 寄存器结构定义。地址偏移量:0x0388+4*(n)，初值:0x00000000，宽度:32
 寄存器说明: 椭圆曲线参数中P寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ec_para_p : 32; /* bit[0-31]: 配置方式同ec_px1。
                                                    椭圆曲线参数中256bit的整数p。 */
    } reg;
} SOC_ECC_EC_PARA_P_UNION;
#endif
#define SOC_ECC_EC_PARA_P_ec_para_p_START  (0)
#define SOC_ECC_EC_PARA_P_ec_para_p_END    (31)


/*****************************************************************************
 结构名    : SOC_ECC_EC_PARA_A_UNION
 结构说明  : EC_PARA_A 寄存器结构定义。地址偏移量:0x03D0+4*(n)，初值:0x00000000，宽度:32
 寄存器说明: 椭圆曲线参数中A寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ec_para_a : 32; /* bit[0-31]: 配置方式同ec_px1。
                                                    椭圆曲线参数中256bit的整数a。 */
    } reg;
} SOC_ECC_EC_PARA_A_UNION;
#endif
#define SOC_ECC_EC_PARA_A_ec_para_a_START  (0)
#define SOC_ECC_EC_PARA_A_ec_para_a_END    (31)


/*****************************************************************************
 结构名    : SOC_ECC_EC_PARA_B_UNION
 结构说明  : EC_PARA_B 寄存器结构定义。地址偏移量:0x0418+4*(n)，初值:0x00000000，宽度:32
 寄存器说明: 椭圆曲线参数中B寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ec_para_b : 32; /* bit[0-31]: 配置方式同ec_px1。
                                                    椭圆曲线参数中256bit的整数b。 */
    } reg;
} SOC_ECC_EC_PARA_B_UNION;
#endif
#define SOC_ECC_EC_PARA_B_ec_para_b_START  (0)
#define SOC_ECC_EC_PARA_B_ec_para_b_END    (31)


/*****************************************************************************
 结构名    : SOC_ECC_EC_PARA_N_UNION
 结构说明  : EC_PARA_N 寄存器结构定义。地址偏移量:0x0460+4*(n)，初值:0x00000000，宽度:32
 寄存器说明: 椭圆曲线参数中N寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ec_para_n : 32; /* bit[0-31]: 配置方式同ec_px1。
                                                    椭圆曲线参数中256bit的整数n。 */
    } reg;
} SOC_ECC_EC_PARA_N_UNION;
#endif
#define SOC_ECC_EC_PARA_N_ec_para_n_START  (0)
#define SOC_ECC_EC_PARA_N_ec_para_n_END    (31)


/*****************************************************************************
 结构名    : SOC_ECC_EC_PARA_GX_UNION
 结构说明  : EC_PARA_GX 寄存器结构定义。地址偏移量:0x04A8+4*(n)，初值:0x00000000，宽度:32
 寄存器说明: 椭圆曲线参数中基点G的X坐标寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ec_para_gx : 32; /* bit[0-31]: 配置方式同ec_px1。
                                                     椭圆曲线参数中256bit的整数Gx。 */
    } reg;
} SOC_ECC_EC_PARA_GX_UNION;
#endif
#define SOC_ECC_EC_PARA_GX_ec_para_gx_START  (0)
#define SOC_ECC_EC_PARA_GX_ec_para_gx_END    (31)


/*****************************************************************************
 结构名    : SOC_ECC_EC_PARA_GY_UNION
 结构说明  : EC_PARA_GY 寄存器结构定义。地址偏移量:0x04F0+4*(n)，初值:0x00000000，宽度:32
 寄存器说明: 椭圆曲线参数中基点G的Y坐标寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ec_para_gy : 32; /* bit[0-31]: 配置方式同ec_px1。
                                                     椭圆曲线参数中256bit的整数Gy。 */
    } reg;
} SOC_ECC_EC_PARA_GY_UNION;
#endif
#define SOC_ECC_EC_PARA_GY_ec_para_gy_START  (0)
#define SOC_ECC_EC_PARA_GY_ec_para_gy_END    (31)






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

#endif /* end of soc_ecc_interface.h */
