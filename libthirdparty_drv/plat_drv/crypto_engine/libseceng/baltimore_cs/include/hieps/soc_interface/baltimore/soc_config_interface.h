/******************************************************************************

                 版权所有 (C), 2001-2019, 华为技术有限公司

 ******************************************************************************
  文 件 名   : soc_config_interface.h
  版 本 号   : 初稿
  作    者   : Excel2Code
  生成日期   : 2019-10-26 11:03:14
  最近修改   :
  功能描述   : 接口头文件
  函数列表   :
  修改历史   :
  1.日    期   : 2019年10月26日
    作    者   : l00249396
    修改内容   : 从《HiEPS V210 寄存器手册_CONFIG.xml》自动生成

******************************************************************************/

/*****************************************************************************
  1 其他头文件包含
*****************************************************************************/

#ifndef __SOC_CONFIG_INTERFACE_H__
#define __SOC_CONFIG_INTERFACE_H__

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
/* 寄存器说明：DDRENC控制寄存器
   位域定义UNION结构:  SOC_CONFIG_DDRENC_CTRL_UNION */
#define SOC_CONFIG_DDRENC_CTRL_ADDR(base)             ((base) + (0x00))

/* 寄存器说明：寄存efuse的相关控制信息
   位域定义UNION结构:  SOC_CONFIG_EFUSEC2HIEPS_CTRL_UNION */
#define SOC_CONFIG_EFUSEC2HIEPS_CTRL_ADDR(base)       ((base) + (0x04))

/* 寄存器说明：
   位域定义UNION结构:  SOC_CONFIG_REG_RESERVED1_UNION */
#define SOC_CONFIG_REG_RESERVED1_ADDR(base)           ((base) + (0x08))

/* 寄存器说明：
   位域定义UNION结构:  SOC_CONFIG_REG_RESERVED2_UNION */
#define SOC_CONFIG_REG_RESERVED2_ADDR(base)           ((base) + (0x0C))

/* 寄存器说明：
   位域定义UNION结构:  SOC_CONFIG_REG_RESERVED3_UNION */
#define SOC_CONFIG_REG_RESERVED3_ADDR(base)           ((base) + (0x10))

/* 寄存器说明：QIC 相关信号的控制寄存器。
   位域定义UNION结构:  SOC_CONFIG_QIC_CTRL_UNION */
#define SOC_CONFIG_QIC_CTRL_ADDR(base)                ((base) + (0x14))

/* 寄存器说明：
   位域定义UNION结构:  SOC_CONFIG_REG_RESERVED4_UNION */
#define SOC_CONFIG_REG_RESERVED4_ADDR(base)           ((base) + (0x18))

/* 寄存器说明：
   位域定义UNION结构:  SOC_CONFIG_REG_RESERVED5_UNION */
#define SOC_CONFIG_REG_RESERVED5_ADDR(base)           ((base) + (0x1C))

/* 寄存器说明：
   位域定义UNION结构:  SOC_CONFIG_REG_RESERVED6_UNION */
#define SOC_CONFIG_REG_RESERVED6_ADDR(base)           ((base) + (0x20))

/* 寄存器说明：脉冲转电平的中断清除寄存器
   位域定义UNION结构:  SOC_CONFIG_ALARM_CLR_UNION */
#define SOC_CONFIG_ALARM_CLR_ADDR(base)               ((base) + (0x24))

/* 寄存器说明：
   位域定义UNION结构:  SOC_CONFIG_REG_RESERVED7_UNION */
#define SOC_CONFIG_REG_RESERVED7_ADDR(base)           ((base) + (0x28))

/* 寄存器说明：
   位域定义UNION结构:  SOC_CONFIG_REG_RESERVED8_UNION */
#define SOC_CONFIG_REG_RESERVED8_ADDR(base)           ((base) + (0x2C))

/* 寄存器说明：
   位域定义UNION结构:  SOC_CONFIG_REG_RESERVED9_UNION */
#define SOC_CONFIG_REG_RESERVED9_ADDR(base)           ((base) + (0x30))

/* 寄存器说明：外设时钟使能寄存器0。
   位域定义UNION结构:  SOC_CONFIG_HIEPS_PEREN0_UNION */
#define SOC_CONFIG_HIEPS_PEREN0_ADDR(base)            ((base) + (0x100))

/* 寄存器说明：外设时钟禁止寄存器0。
   位域定义UNION结构:  SOC_CONFIG_HIEPS_PERDIS0_UNION */
#define SOC_CONFIG_HIEPS_PERDIS0_ADDR(base)           ((base) + (0x104))

/* 寄存器说明：外设时钟使能状态寄存器0。
   位域定义UNION结构:  SOC_CONFIG_HIEPS_PERCLKEN0_UNION */
#define SOC_CONFIG_HIEPS_PERCLKEN0_ADDR(base)         ((base) + (0x108))

/* 寄存器说明：'外设时钟最终状态寄存器0。
   位域定义UNION结构:  SOC_CONFIG_HIEPS_PERSTAT0_UNION */
#define SOC_CONFIG_HIEPS_PERSTAT0_ADDR(base)          ((base) + (0x10C))

/* 寄存器说明：外设软复位使能寄存器0。
   位域定义UNION结构:  SOC_CONFIG_PERRSTEN0_UNION */
#define SOC_CONFIG_PERRSTEN0_ADDR(base)               ((base) + (0x110))

/* 寄存器说明：外设软复位撤离寄存器0。
   位域定义UNION结构:  SOC_CONFIG_HIEPS_PERRSTDIS0_UNION */
#define SOC_CONFIG_HIEPS_PERRSTDIS0_ADDR(base)        ((base) + (0x114))

/* 寄存器说明：外设软复位状态寄存器0。
   位域定义UNION结构:  SOC_CONFIG_HIEPS_PERRSTSTAT0_UNION */
#define SOC_CONFIG_HIEPS_PERRSTSTAT0_ADDR(base)       ((base) + (0x118))

/* 寄存器说明：时钟分频比控制寄存器0。
   位域定义UNION结构:  SOC_CONFIG_HIEPS_DIV0_UNION */
#define SOC_CONFIG_HIEPS_DIV0_ADDR(base)              ((base) + (0x11C))

/* 寄存器说明：CRG控制寄存器0。
   位域定义UNION结构:  SOC_CONFIG_HIEPS_COMMON_CTRL0_UNION */
#define SOC_CONFIG_HIEPS_COMMON_CTRL0_ADDR(base)      ((base) + (0x120))

/* 寄存器说明：CRG控制寄存器1。
   位域定义UNION结构:  SOC_CONFIG_HIEPS_COMMON_CTRL1_UNION */
#define SOC_CONFIG_HIEPS_COMMON_CTRL1_ADDR(base)      ((base) + (0x124))

/* 寄存器说明：CRG防挂死控制寄存器。
   位域定义UNION结构:  SOC_CONFIG_HIEPS_IPCLKRST_BYPASS0_UNION */
#define SOC_CONFIG_HIEPS_IPCLKRST_BYPASS0_ADDR(base)  ((base) + (0x128))

/* 寄存器说明：
   位域定义UNION结构:  SOC_CONFIG_HIEPS_MEM_CTRL_ROM_UNION */
#define SOC_CONFIG_HIEPS_MEM_CTRL_ROM_ADDR(base)      ((base) + (0x200))

/* 寄存器说明：
   位域定义UNION结构:  SOC_CONFIG_HIEPS_MEM_CTRL_SPRAM_UNION */
#define SOC_CONFIG_HIEPS_MEM_CTRL_SPRAM_ADDR(base)    ((base) + (0x204))

/* 寄存器说明：
   位域定义UNION结构:  SOC_CONFIG_HIEPS_MEM_CTRL_HD_UNION */
#define SOC_CONFIG_HIEPS_MEM_CTRL_HD_ADDR(base)       ((base) + (0x208))

/* 寄存器说明：
   位域定义UNION结构:  SOC_CONFIG_HIEPS_MEM_CTRL_DPRAM_UNION */
#define SOC_CONFIG_HIEPS_MEM_CTRL_DPRAM_ADDR(base)    ((base) + (0x20C))

/* 寄存器说明：
   位域定义UNION结构:  SOC_CONFIG_HIEPS_MEM_CTRL_BPRAM_UNION */
#define SOC_CONFIG_HIEPS_MEM_CTRL_BPRAM_ADDR(base)    ((base) + (0x210))

/* 寄存器说明：中断MASK
   位域定义UNION结构:  SOC_CONFIG_HIEPS_INTR_MASK_UNION */
#define SOC_CONFIG_HIEPS_INTR_MASK_ADDR(base)         ((base) + (0x214))

/* 寄存器说明：
   位域定义UNION结构:  SOC_CONFIG_HIEPS_SEC_CTRL_UNION */
#define SOC_CONFIG_HIEPS_SEC_CTRL_ADDR(base)          ((base) + (0x218))

/* 寄存器说明：加密通道QIC控制寄存器
   位域定义UNION结构:  SOC_CONFIG_HIEPS_QIC_ENC_CTRL_UNION */
#define SOC_CONFIG_HIEPS_QIC_ENC_CTRL_ADDR(base)      ((base) + (0x21C))

/* 寄存器说明：ALARM的状态寄存寄存器
   位域定义UNION结构:  SOC_CONFIG_HIEPS_ALARM_STAT_UNION */
#define SOC_CONFIG_HIEPS_ALARM_STAT_ADDR(base)        ((base) + (0x220))

/* 寄存器说明：HIEPS系统状态
   位域定义UNION结构:  SOC_CONFIG_HIEPS_STAT_UNION */
#define SOC_CONFIG_HIEPS_STAT_ADDR(base)              ((base) + (0x224))

/* 寄存器说明：efuse解析状态
   位域定义UNION结构:  SOC_CONFIG_HIEPS_EFUSE_CTRL_STAT_UNION */
#define SOC_CONFIG_HIEPS_EFUSE_CTRL_STAT_ADDR(base)   ((base) + (0x228))

/* 寄存器说明：SCE1写通道的ID配置
   位域定义UNION结构:  SOC_CONFIG_HIEPS_MMU_WID_UNION */
#define SOC_CONFIG_HIEPS_MMU_WID_ADDR(base)           ((base) + (0x300))

/* 寄存器说明：SCE1读通道的ID配置
   位域定义UNION结构:  SOC_CONFIG_HIEPS_MMU_RID_UNION */
#define SOC_CONFIG_HIEPS_MMU_RID_ADDR(base)           ((base) + (0x304))

/* 寄存器说明：SCE1预取滑窗ID
   位域定义UNION结构:  SOC_CONFIG_HIEPS_MMU_PREID_UNION */
#define SOC_CONFIG_HIEPS_MMU_PREID_ADDR(base)         ((base) + (0x308))

/* 寄存器说明：SCE2写通道的ID配置
   位域定义UNION结构:  SOC_CONFIG_HIEPS_MMU2_WID_UNION */
#define SOC_CONFIG_HIEPS_MMU2_WID_ADDR(base)          ((base) + (0x30C))

/* 寄存器说明：SCE2读通道的ID配置
   位域定义UNION结构:  SOC_CONFIG_HIEPS_MMU2_RID_UNION */
#define SOC_CONFIG_HIEPS_MMU2_RID_ADDR(base)          ((base) + (0x310))

/* 寄存器说明：SCE2预取滑窗ID
   位域定义UNION结构:  SOC_CONFIG_HIEPS_MMU2_PREID_UNION */
#define SOC_CONFIG_HIEPS_MMU2_PREID_ADDR(base)        ((base) + (0x314))

/* 寄存器说明：总线桥优先级配置寄存器
   位域定义UNION结构:  SOC_CONFIG_SCE_MST_PRIORITY_UNION */
#define SOC_CONFIG_SCE_MST_PRIORITY_ADDR(base)        ((base) + (0x400))

/* 寄存器说明：hint信号配置
   位域定义UNION结构:  SOC_CONFIG_HIEPS_HINT_UNION */
#define SOC_CONFIG_HIEPS_HINT_ADDR(base)              ((base) + (0x404))

/* 寄存器说明：
   位域定义UNION结构:  SOC_CONFIG_REG_RESERVED10_UNION */
#define SOC_CONFIG_REG_RESERVED10_ADDR(base)          ((base) + (0x420))

/* 寄存器说明：
   位域定义UNION结构:  SOC_CONFIG_REG_RESERVED11_UNION */
#define SOC_CONFIG_REG_RESERVED11_ADDR(base)          ((base) + (0x424))

/* 寄存器说明：压缩状态寄存器
   位域定义UNION结构:  SOC_CONFIG_HIEPS_RCV_STATE_UNION */
#define SOC_CONFIG_HIEPS_RCV_STATE_ADDR(base)         ((base) + (0x500))

/* 寄存器说明：保留寄存器
   位域定义UNION结构:  SOC_CONFIG_REG_RW_RES1_UNION */
#define SOC_CONFIG_REG_RW_RES1_ADDR(base)             ((base) + (0x800))

/* 寄存器说明：保留寄存器
   位域定义UNION结构:  SOC_CONFIG_REG_RW_RES2_UNION */
#define SOC_CONFIG_REG_RW_RES2_ADDR(base)             ((base) + (0x804))

/* 寄存器说明：保留寄存器
   位域定义UNION结构:  SOC_CONFIG_REG_RO_RES1_UNION */
#define SOC_CONFIG_REG_RO_RES1_ADDR(base)             ((base) + (0x808))





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
 结构名    : SOC_CONFIG_DDRENC_CTRL_UNION
 结构说明  : DDRENC_CTRL 寄存器结构定义。地址偏移量:0x00，初值:0x0000000A，宽度:32
 寄存器说明: DDRENC控制寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  bypass_ddrenc : 4;  /* bit[0-3] : bypass_ddrenc:DDR加密模块的bypass enable信号
                                                        4'b0101:bypass；
                                                        4'b1010:加密；
                                                        配置成其他值则按照加密处理 */
        unsigned int  reserved      : 28; /* bit[4-31]:  */
    } reg;
} SOC_CONFIG_DDRENC_CTRL_UNION;
#endif
#define SOC_CONFIG_DDRENC_CTRL_bypass_ddrenc_START  (0)
#define SOC_CONFIG_DDRENC_CTRL_bypass_ddrenc_END    (3)


/*****************************************************************************
 结构名    : SOC_CONFIG_EFUSEC2HIEPS_CTRL_UNION
 结构说明  : EFUSEC2HIEPS_CTRL 寄存器结构定义。地址偏移量:0x04，初值:0x00000000，宽度:32
 寄存器说明: 寄存efuse的相关控制信息
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  efusec2hieps_ctrl : 32; /* bit[0-31]: bit【31】表示码字中alarm处理使能，1表示处理alarm，0表示不处理--reserved
                                                            bit【30:29】表示patch功能使能--reserved；
                                                            bit【28:27】表示dcu_en是选择dx输出的还是eps输出的，2‘b01表示选择eps，其它值为dx
                                                            bit【26：25】表示arc发送edc时，是否自动产生halt请求使arc进入halt状态--reserved
                                                            bit【24】为0表示不烧写允许mbist测试，烧写为1后不允许，不能进行寄存器上报，不能用于其它功能逻辑
                                                            bit【23:16】表示hieps_patch的0bit个数--reserved
                                                            bit【15】表示debug_rst和sercure_diasble进行相关处理的enable信号，为0表示不进行复位和钳位处理，为1表示进行复位和钳位处理
                                                            bit【14】，为0表示新trng，为1表示老trng
                                                            bit【13】，为0表示非sdm下不关掉spi和i2c的时钟，为1表示关掉spi和i2c的时钟--reserved
                                                            bit【12】，为0表示bypass ddrenc功能，为1表示不bypass ddrenc功能
                                                            其它reseverd */
    } reg;
} SOC_CONFIG_EFUSEC2HIEPS_CTRL_UNION;
#endif
#define SOC_CONFIG_EFUSEC2HIEPS_CTRL_efusec2hieps_ctrl_START  (0)
#define SOC_CONFIG_EFUSEC2HIEPS_CTRL_efusec2hieps_ctrl_END    (31)


/*****************************************************************************
 结构名    : SOC_CONFIG_REG_RESERVED1_UNION
 结构说明  : REG_RESERVED1 寄存器结构定义。地址偏移量:0x08，初值:0x00000000，宽度:32
 寄存器说明: 
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved : 32; /* bit[0-31]:  */
    } reg;
} SOC_CONFIG_REG_RESERVED1_UNION;
#endif


/*****************************************************************************
 结构名    : SOC_CONFIG_REG_RESERVED2_UNION
 结构说明  : REG_RESERVED2 寄存器结构定义。地址偏移量:0x0C，初值:0x00000000，宽度:32
 寄存器说明: 
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved : 32; /* bit[0-31]:  */
    } reg;
} SOC_CONFIG_REG_RESERVED2_UNION;
#endif


/*****************************************************************************
 结构名    : SOC_CONFIG_REG_RESERVED3_UNION
 结构说明  : REG_RESERVED3 寄存器结构定义。地址偏移量:0x10，初值:0x00000000，宽度:32
 寄存器说明: 
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved : 32; /* bit[0-31]: reserved */
    } reg;
} SOC_CONFIG_REG_RESERVED3_UNION;
#endif


/*****************************************************************************
 结构名    : SOC_CONFIG_QIC_CTRL_UNION
 结构说明  : QIC_CTRL 寄存器结构定义。地址偏移量:0x14，初值:0x00000000，宽度:32
 寄存器说明: QIC 相关信号的控制寄存器。
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  hieps2qic_unenc_awMainPress : 2;  /* bit[0-1]  : 静态配置，默认值为0，访问HIEPS QIC的非加密写通道的mainPress控制，控制QIC buffer水线的阈值档位，在QOS不起作用时（QIC已经反压EPS时才起作用），可以考虑配置mainPress。 */
        unsigned int  axi_unenc_awqos             : 4;  /* bit[2-5]  : 静态配置，HIEPS与QIC对接的非加密写通道的AXI master口的QOS值 */
        unsigned int  axi_unenc_region            : 4;  /* bit[6-9]  : 静态配置，HIEPS与QIC对接的AXI master口的region值，非加密通道 */
        unsigned int  reserved_0                  : 6;  /* bit[10-15]: reserved */
        unsigned int  reserved_1                  : 6;  /* bit[16-21]: reserved */
        unsigned int  reserved_2                  : 1;  /* bit[22]   : reserved */
        unsigned int  system_cache_hint_mux       : 1;  /* bit[23]   : 只允许静态配置，默认值为0
                                                                       0：卡控端口上的system cache hint为0，不走system cache；
                                                                       1：透传MMU输出的system cache hint信号到端口上。 */
        unsigned int  reserved_3                  : 1;  /* bit[24]   : reserved */
        unsigned int  hieps2qic_unenc_arMainPress : 2;  /* bit[25-26]: 静态配置，默认值为0，访问HIEPS QIC的非加密读通道的mainPress控制，控制QIC buffer水线的阈值档位，在QOS不起作用时（QIC已经反压EPS时才起作用），可以考虑配置mainPress。 */
        unsigned int  axi_unenc_arqos             : 4;  /* bit[27-30]: 静态配置，HIEPS与QIC对接的非加密读通道的AXI master口的QOS值 */
        unsigned int  reserved_4                  : 1;  /* bit[31]   :  */
    } reg;
} SOC_CONFIG_QIC_CTRL_UNION;
#endif
#define SOC_CONFIG_QIC_CTRL_hieps2qic_unenc_awMainPress_START  (0)
#define SOC_CONFIG_QIC_CTRL_hieps2qic_unenc_awMainPress_END    (1)
#define SOC_CONFIG_QIC_CTRL_axi_unenc_awqos_START              (2)
#define SOC_CONFIG_QIC_CTRL_axi_unenc_awqos_END                (5)
#define SOC_CONFIG_QIC_CTRL_axi_unenc_region_START             (6)
#define SOC_CONFIG_QIC_CTRL_axi_unenc_region_END               (9)
#define SOC_CONFIG_QIC_CTRL_system_cache_hint_mux_START        (23)
#define SOC_CONFIG_QIC_CTRL_system_cache_hint_mux_END          (23)
#define SOC_CONFIG_QIC_CTRL_hieps2qic_unenc_arMainPress_START  (25)
#define SOC_CONFIG_QIC_CTRL_hieps2qic_unenc_arMainPress_END    (26)
#define SOC_CONFIG_QIC_CTRL_axi_unenc_arqos_START              (27)
#define SOC_CONFIG_QIC_CTRL_axi_unenc_arqos_END                (30)


/*****************************************************************************
 结构名    : SOC_CONFIG_REG_RESERVED4_UNION
 结构说明  : REG_RESERVED4 寄存器结构定义。地址偏移量:0x18，初值:0x00000000，宽度:32
 寄存器说明: 
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved : 32; /* bit[0-31]: reserved */
    } reg;
} SOC_CONFIG_REG_RESERVED4_UNION;
#endif


/*****************************************************************************
 结构名    : SOC_CONFIG_REG_RESERVED5_UNION
 结构说明  : REG_RESERVED5 寄存器结构定义。地址偏移量:0x1C，初值:0x00000000，宽度:32
 寄存器说明: 
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved : 32; /* bit[0-31]: reserved */
    } reg;
} SOC_CONFIG_REG_RESERVED5_UNION;
#endif


/*****************************************************************************
 结构名    : SOC_CONFIG_REG_RESERVED6_UNION
 结构说明  : REG_RESERVED6 寄存器结构定义。地址偏移量:0x20，初值:0x00000000，宽度:32
 寄存器说明: 
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved : 32; /* bit[0-31]: reserved */
    } reg;
} SOC_CONFIG_REG_RESERVED6_UNION;
#endif


/*****************************************************************************
 结构名    : SOC_CONFIG_ALARM_CLR_UNION
 结构说明  : ALARM_CLR 寄存器结构定义。地址偏移量:0x24，初值:0x00000000，宽度:32
 寄存器说明: 脉冲转电平的中断清除寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  clr_ddrenc_alarm_pulse : 1;  /* bit[0]   : 1：清除alarm中断
                                                                 0：没有效果 */
        unsigned int  reserved               : 31; /* bit[1-31]: reserved */
    } reg;
} SOC_CONFIG_ALARM_CLR_UNION;
#endif
#define SOC_CONFIG_ALARM_CLR_clr_ddrenc_alarm_pulse_START  (0)
#define SOC_CONFIG_ALARM_CLR_clr_ddrenc_alarm_pulse_END    (0)


/*****************************************************************************
 结构名    : SOC_CONFIG_REG_RESERVED7_UNION
 结构说明  : REG_RESERVED7 寄存器结构定义。地址偏移量:0x28，初值:0x00000000，宽度:32
 寄存器说明: 
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved : 32; /* bit[0-31]: reserved */
    } reg;
} SOC_CONFIG_REG_RESERVED7_UNION;
#endif


/*****************************************************************************
 结构名    : SOC_CONFIG_REG_RESERVED8_UNION
 结构说明  : REG_RESERVED8 寄存器结构定义。地址偏移量:0x2C，初值:0x00000000，宽度:32
 寄存器说明: 
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved : 32; /* bit[0-31]: reserved */
    } reg;
} SOC_CONFIG_REG_RESERVED8_UNION;
#endif


/*****************************************************************************
 结构名    : SOC_CONFIG_REG_RESERVED9_UNION
 结构说明  : REG_RESERVED9 寄存器结构定义。地址偏移量:0x30，初值:0x00000000，宽度:32
 寄存器说明: 
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved : 32; /* bit[0-31]: reserved */
    } reg;
} SOC_CONFIG_REG_RESERVED9_UNION;
#endif


/*****************************************************************************
 结构名    : SOC_CONFIG_HIEPS_PEREN0_UNION
 结构说明  : HIEPS_PEREN0 寄存器结构定义。地址偏移量:0x100，初值:0x00000000，宽度:32
 寄存器说明: 外设时钟使能寄存器0。
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  gt_pclk_hieps_timer : 1;  /* bit[0]    : TIMER时钟的软门控 */
        unsigned int  gt_pclk_hieps_trng  : 1;  /* bit[1]    : TRNG时钟的软门控 */
        unsigned int  gt_clk_hieps_sce_km : 1;  /* bit[2]    : SCE、KM时钟的软门控 */
        unsigned int  gt_clk_hieps_pke    : 1;  /* bit[3]    : PKE时钟的软门控 */
        unsigned int  gt_clk_hieps_mmu    : 1;  /* bit[4]    : MMU的软门控 */
        unsigned int  gt_clk_ddr_crpt     : 1;  /* bit[5]    : DDR加密时钟的软门控 */
        unsigned int  gt_clk_hieps_cmp    : 1;  /* bit[6]    : 压缩模块时钟的软门控 */
        unsigned int  gt_clk_hieps_pke2   : 1;  /* bit[7]    : PKE2时钟的软门控 */
        unsigned int  gt_clk_hieps_sce2   : 1;  /* bit[8]    : SCE2时钟的软门控 */
        unsigned int  gt_aclk_hieps_qic   : 1;  /* bit[9]    : qic时钟的软门控 */
        unsigned int  reserved            : 22; /* bit[10-31]: 外设时钟使能控制：
                                                               0：写0无效果；
                                                               1：使能IP时钟。 */
    } reg;
} SOC_CONFIG_HIEPS_PEREN0_UNION;
#endif
#define SOC_CONFIG_HIEPS_PEREN0_gt_pclk_hieps_timer_START  (0)
#define SOC_CONFIG_HIEPS_PEREN0_gt_pclk_hieps_timer_END    (0)
#define SOC_CONFIG_HIEPS_PEREN0_gt_pclk_hieps_trng_START   (1)
#define SOC_CONFIG_HIEPS_PEREN0_gt_pclk_hieps_trng_END     (1)
#define SOC_CONFIG_HIEPS_PEREN0_gt_clk_hieps_sce_km_START  (2)
#define SOC_CONFIG_HIEPS_PEREN0_gt_clk_hieps_sce_km_END    (2)
#define SOC_CONFIG_HIEPS_PEREN0_gt_clk_hieps_pke_START     (3)
#define SOC_CONFIG_HIEPS_PEREN0_gt_clk_hieps_pke_END       (3)
#define SOC_CONFIG_HIEPS_PEREN0_gt_clk_hieps_mmu_START     (4)
#define SOC_CONFIG_HIEPS_PEREN0_gt_clk_hieps_mmu_END       (4)
#define SOC_CONFIG_HIEPS_PEREN0_gt_clk_ddr_crpt_START      (5)
#define SOC_CONFIG_HIEPS_PEREN0_gt_clk_ddr_crpt_END        (5)
#define SOC_CONFIG_HIEPS_PEREN0_gt_clk_hieps_cmp_START     (6)
#define SOC_CONFIG_HIEPS_PEREN0_gt_clk_hieps_cmp_END       (6)
#define SOC_CONFIG_HIEPS_PEREN0_gt_clk_hieps_pke2_START    (7)
#define SOC_CONFIG_HIEPS_PEREN0_gt_clk_hieps_pke2_END      (7)
#define SOC_CONFIG_HIEPS_PEREN0_gt_clk_hieps_sce2_START    (8)
#define SOC_CONFIG_HIEPS_PEREN0_gt_clk_hieps_sce2_END      (8)
#define SOC_CONFIG_HIEPS_PEREN0_gt_aclk_hieps_qic_START    (9)
#define SOC_CONFIG_HIEPS_PEREN0_gt_aclk_hieps_qic_END      (9)


/*****************************************************************************
 结构名    : SOC_CONFIG_HIEPS_PERDIS0_UNION
 结构说明  : HIEPS_PERDIS0 寄存器结构定义。地址偏移量:0x104，初值:0x00000000，宽度:32
 寄存器说明: 外设时钟禁止寄存器0。
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  gt_pclk_hieps_timer : 1;  /* bit[0]    : TIMER时钟的禁止控制 */
        unsigned int  gt_pclk_hieps_trng  : 1;  /* bit[1]    : TRNG时钟的禁止控制 */
        unsigned int  gt_clk_hieps_sce_km : 1;  /* bit[2]    : SCE、KM时钟的禁止控制 */
        unsigned int  gt_clk_hieps_pke    : 1;  /* bit[3]    : PKE时钟的禁止控制 */
        unsigned int  gt_clk_hieps_mmu    : 1;  /* bit[4]    : MMU的时钟禁止控制 */
        unsigned int  gt_clk_ddr_crpt     : 1;  /* bit[5]    : DDR加密时钟的禁止控制 */
        unsigned int  gt_clk_hieps_cmp    : 1;  /* bit[6]    : 压缩模块时钟的禁止控制 */
        unsigned int  gt_clk_hieps_pke2   : 1;  /* bit[7]    : PKE2时钟的禁止控制 */
        unsigned int  gt_clk_hieps_sce2   : 1;  /* bit[8]    : SCE2时钟的禁止控制 */
        unsigned int  gt_aclk_hieps_qic   : 1;  /* bit[9]    : qic时钟的禁止控制 */
        unsigned int  reserved            : 22; /* bit[10-31]: 外设时钟禁止控制：
                                                               0：写0无效果；
                                                               1：禁止IP时钟。 */
    } reg;
} SOC_CONFIG_HIEPS_PERDIS0_UNION;
#endif
#define SOC_CONFIG_HIEPS_PERDIS0_gt_pclk_hieps_timer_START  (0)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_pclk_hieps_timer_END    (0)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_pclk_hieps_trng_START   (1)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_pclk_hieps_trng_END     (1)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_clk_hieps_sce_km_START  (2)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_clk_hieps_sce_km_END    (2)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_clk_hieps_pke_START     (3)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_clk_hieps_pke_END       (3)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_clk_hieps_mmu_START     (4)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_clk_hieps_mmu_END       (4)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_clk_ddr_crpt_START      (5)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_clk_ddr_crpt_END        (5)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_clk_hieps_cmp_START     (6)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_clk_hieps_cmp_END       (6)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_clk_hieps_pke2_START    (7)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_clk_hieps_pke2_END      (7)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_clk_hieps_sce2_START    (8)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_clk_hieps_sce2_END      (8)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_aclk_hieps_qic_START    (9)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_aclk_hieps_qic_END      (9)


/*****************************************************************************
 结构名    : SOC_CONFIG_HIEPS_PERCLKEN0_UNION
 结构说明  : HIEPS_PERCLKEN0 寄存器结构定义。地址偏移量:0x108，初值:0x000003FF，宽度:32
 寄存器说明: 外设时钟使能状态寄存器0。
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  gt_pclk_hieps_timer : 1;  /* bit[0]    : TIMER时钟使能状态 */
        unsigned int  gt_pclk_hieps_trng  : 1;  /* bit[1]    : TRNG时钟使能状态 */
        unsigned int  gt_clk_hieps_sce_km : 1;  /* bit[2]    : SCE、KM时钟使能状态 */
        unsigned int  gt_clk_hieps_pke    : 1;  /* bit[3]    : PKE时钟使能状态 */
        unsigned int  gt_clk_hieps_mmu    : 1;  /* bit[4]    : MMU的时钟使能状态，同时控制bclk和cclk */
        unsigned int  gt_clk_ddr_crpt     : 1;  /* bit[5]    : DDR加密时钟的使能状态 */
        unsigned int  gt_clk_hieps_cmp    : 1;  /* bit[6]    : 压缩模块时钟的使能状态 */
        unsigned int  gt_clk_hieps_pke2   : 1;  /* bit[7]    : PKE2时钟的使能状态 */
        unsigned int  gt_clk_hieps_sce2   : 1;  /* bit[8]    : SCE2时钟的使能状态 */
        unsigned int  gt_aclk_hieps_qic   : 1;  /* bit[9]    : qic时钟的使能状态 */
        unsigned int  reserved            : 22; /* bit[10-31]: 外设时钟使能状态：
                                                               0：IP时钟使能撤销状态；
                                                               1：IP时钟使能状态。 */
    } reg;
} SOC_CONFIG_HIEPS_PERCLKEN0_UNION;
#endif
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_pclk_hieps_timer_START  (0)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_pclk_hieps_timer_END    (0)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_pclk_hieps_trng_START   (1)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_pclk_hieps_trng_END     (1)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_clk_hieps_sce_km_START  (2)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_clk_hieps_sce_km_END    (2)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_clk_hieps_pke_START     (3)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_clk_hieps_pke_END       (3)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_clk_hieps_mmu_START     (4)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_clk_hieps_mmu_END       (4)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_clk_ddr_crpt_START      (5)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_clk_ddr_crpt_END        (5)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_clk_hieps_cmp_START     (6)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_clk_hieps_cmp_END       (6)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_clk_hieps_pke2_START    (7)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_clk_hieps_pke2_END      (7)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_clk_hieps_sce2_START    (8)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_clk_hieps_sce2_END      (8)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_aclk_hieps_qic_START    (9)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_aclk_hieps_qic_END      (9)


/*****************************************************************************
 结构名    : SOC_CONFIG_HIEPS_PERSTAT0_UNION
 结构说明  : HIEPS_PERSTAT0 寄存器结构定义。地址偏移量:0x10C，初值:0x000003FF，宽度:32
 寄存器说明: '外设时钟最终状态寄存器0。
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  st_pclk_hieps_timer   : 1;  /* bit[0]    : TIMER的时钟状态 */
        unsigned int  st_pclk_hieps_trng    : 1;  /* bit[1]    : TRNG的时钟状态 */
        unsigned int  st_clk_hieps_sce_km   : 1;  /* bit[2]    : SCE和KM的时钟状态 */
        unsigned int  st_clk_hieps_pke      : 1;  /* bit[3]    : PKE的时钟状态 */
        unsigned int  st_clk_hieps_mmu_bclk : 1;  /* bit[4]    : 自动gating后mmu bclk的状态，mmu_bclk的状态，不带自动门控 */
        unsigned int  st_clk_ddr_crpt       : 1;  /* bit[5]    : DDR加密的时钟状态 */
        unsigned int  st_clk_hieps_cmp      : 1;  /* bit[6]    : 压缩模块的时钟状态 */
        unsigned int  st_clk_hieps_pke2     : 1;  /* bit[7]    : PKE2的时钟状态 */
        unsigned int  st_clk_hieps_sce2     : 1;  /* bit[8]    : SCE2的时钟状态 */
        unsigned int  st_aclk_hieps_qic     : 1;  /* bit[9]    : qic的时钟状态 */
        unsigned int  reserved              : 22; /* bit[10-31]: 外设时钟最终状态：
                                                                 0：IP时钟禁止状态；
                                                                 1：IP时钟使能状态。 */
    } reg;
} SOC_CONFIG_HIEPS_PERSTAT0_UNION;
#endif
#define SOC_CONFIG_HIEPS_PERSTAT0_st_pclk_hieps_timer_START    (0)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_pclk_hieps_timer_END      (0)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_pclk_hieps_trng_START     (1)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_pclk_hieps_trng_END       (1)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_clk_hieps_sce_km_START    (2)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_clk_hieps_sce_km_END      (2)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_clk_hieps_pke_START       (3)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_clk_hieps_pke_END         (3)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_clk_hieps_mmu_bclk_START  (4)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_clk_hieps_mmu_bclk_END    (4)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_clk_ddr_crpt_START        (5)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_clk_ddr_crpt_END          (5)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_clk_hieps_cmp_START       (6)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_clk_hieps_cmp_END         (6)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_clk_hieps_pke2_START      (7)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_clk_hieps_pke2_END        (7)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_clk_hieps_sce2_START      (8)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_clk_hieps_sce2_END        (8)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_aclk_hieps_qic_START      (9)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_aclk_hieps_qic_END        (9)


/*****************************************************************************
 结构名    : SOC_CONFIG_PERRSTEN0_UNION
 结构说明  : PERRSTEN0 寄存器结构定义。地址偏移量:0x110，初值:0x00000000，宽度:32
 寄存器说明: 外设软复位使能寄存器0。
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ip_prst_hieps_timer : 1;  /* bit[0]   : IP软复位使能：
                                                              0：IP软复位使能状态不变；
                                                              1：IP软复位使能。 */
        unsigned int  ip_prst_hieps_trng  : 1;  /* bit[1]   : 同bit0 */
        unsigned int  ip_rst_hieps_sce_km : 1;  /* bit[2]   : 同bit0 */
        unsigned int  ip_rst_hieps_pke    : 1;  /* bit[3]   : 同bit0 */
        unsigned int  ip_rst_hieps_mmu    : 1;  /* bit[4]   : 同bit0 */
        unsigned int  ip_rst_ddr_crpt     : 1;  /* bit[5]   : 同bit0 */
        unsigned int  ip_rst_hieps_cmp    : 1;  /* bit[6]   : 同bit0 */
        unsigned int  ip_rst_hieps_sce2   : 1;  /* bit[7]   : 同bit0 */
        unsigned int  ip_rst_hieps_pke2   : 1;  /* bit[8]   : 同bit0 */
        unsigned int  reserved            : 23; /* bit[9-31]: IP软复位使能：
                                                              0：IP软复位使能状态不变；
                                                              1：IP软复位使能。 */
    } reg;
} SOC_CONFIG_PERRSTEN0_UNION;
#endif
#define SOC_CONFIG_PERRSTEN0_ip_prst_hieps_timer_START  (0)
#define SOC_CONFIG_PERRSTEN0_ip_prst_hieps_timer_END    (0)
#define SOC_CONFIG_PERRSTEN0_ip_prst_hieps_trng_START   (1)
#define SOC_CONFIG_PERRSTEN0_ip_prst_hieps_trng_END     (1)
#define SOC_CONFIG_PERRSTEN0_ip_rst_hieps_sce_km_START  (2)
#define SOC_CONFIG_PERRSTEN0_ip_rst_hieps_sce_km_END    (2)
#define SOC_CONFIG_PERRSTEN0_ip_rst_hieps_pke_START     (3)
#define SOC_CONFIG_PERRSTEN0_ip_rst_hieps_pke_END       (3)
#define SOC_CONFIG_PERRSTEN0_ip_rst_hieps_mmu_START     (4)
#define SOC_CONFIG_PERRSTEN0_ip_rst_hieps_mmu_END       (4)
#define SOC_CONFIG_PERRSTEN0_ip_rst_ddr_crpt_START      (5)
#define SOC_CONFIG_PERRSTEN0_ip_rst_ddr_crpt_END        (5)
#define SOC_CONFIG_PERRSTEN0_ip_rst_hieps_cmp_START     (6)
#define SOC_CONFIG_PERRSTEN0_ip_rst_hieps_cmp_END       (6)
#define SOC_CONFIG_PERRSTEN0_ip_rst_hieps_sce2_START    (7)
#define SOC_CONFIG_PERRSTEN0_ip_rst_hieps_sce2_END      (7)
#define SOC_CONFIG_PERRSTEN0_ip_rst_hieps_pke2_START    (8)
#define SOC_CONFIG_PERRSTEN0_ip_rst_hieps_pke2_END      (8)


/*****************************************************************************
 结构名    : SOC_CONFIG_HIEPS_PERRSTDIS0_UNION
 结构说明  : HIEPS_PERRSTDIS0 寄存器结构定义。地址偏移量:0x114，初值:0x00000000，宽度:32
 寄存器说明: 外设软复位撤离寄存器0。
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ip_prst_hieps_timer : 1;  /* bit[0]   : IP软复位撤离：
                                                              0：IP软复位使能状态不变；
                                                              1：IP软复位撤离。 */
        unsigned int  ip_prst_hieps_trng  : 1;  /* bit[1]   : 同bit0 */
        unsigned int  ip_rst_hieps_sce_km : 1;  /* bit[2]   : 同bit0 */
        unsigned int  ip_rst_hieps_pke    : 1;  /* bit[3]   : 同bit0 */
        unsigned int  ip_rst_hieps_mmu    : 1;  /* bit[4]   : 同bit0 */
        unsigned int  ip_rst_ddr_crpt     : 1;  /* bit[5]   : 同bit0 */
        unsigned int  ip_rst_hieps_cmp    : 1;  /* bit[6]   : 同bit0 */
        unsigned int  ip_rst_hieps_sce2   : 1;  /* bit[7]   : 同bit0 */
        unsigned int  ip_rst_hieps_pke2   : 1;  /* bit[8]   : 同bit0 */
        unsigned int  reserved            : 23; /* bit[9-31]: IP软复位撤离：
                                                              0：IP软复位使能状态不变；
                                                              1：IP软复位撤离。 */
    } reg;
} SOC_CONFIG_HIEPS_PERRSTDIS0_UNION;
#endif
#define SOC_CONFIG_HIEPS_PERRSTDIS0_ip_prst_hieps_timer_START  (0)
#define SOC_CONFIG_HIEPS_PERRSTDIS0_ip_prst_hieps_timer_END    (0)
#define SOC_CONFIG_HIEPS_PERRSTDIS0_ip_prst_hieps_trng_START   (1)
#define SOC_CONFIG_HIEPS_PERRSTDIS0_ip_prst_hieps_trng_END     (1)
#define SOC_CONFIG_HIEPS_PERRSTDIS0_ip_rst_hieps_sce_km_START  (2)
#define SOC_CONFIG_HIEPS_PERRSTDIS0_ip_rst_hieps_sce_km_END    (2)
#define SOC_CONFIG_HIEPS_PERRSTDIS0_ip_rst_hieps_pke_START     (3)
#define SOC_CONFIG_HIEPS_PERRSTDIS0_ip_rst_hieps_pke_END       (3)
#define SOC_CONFIG_HIEPS_PERRSTDIS0_ip_rst_hieps_mmu_START     (4)
#define SOC_CONFIG_HIEPS_PERRSTDIS0_ip_rst_hieps_mmu_END       (4)
#define SOC_CONFIG_HIEPS_PERRSTDIS0_ip_rst_ddr_crpt_START      (5)
#define SOC_CONFIG_HIEPS_PERRSTDIS0_ip_rst_ddr_crpt_END        (5)
#define SOC_CONFIG_HIEPS_PERRSTDIS0_ip_rst_hieps_cmp_START     (6)
#define SOC_CONFIG_HIEPS_PERRSTDIS0_ip_rst_hieps_cmp_END       (6)
#define SOC_CONFIG_HIEPS_PERRSTDIS0_ip_rst_hieps_sce2_START    (7)
#define SOC_CONFIG_HIEPS_PERRSTDIS0_ip_rst_hieps_sce2_END      (7)
#define SOC_CONFIG_HIEPS_PERRSTDIS0_ip_rst_hieps_pke2_START    (8)
#define SOC_CONFIG_HIEPS_PERRSTDIS0_ip_rst_hieps_pke2_END      (8)


/*****************************************************************************
 结构名    : SOC_CONFIG_HIEPS_PERRSTSTAT0_UNION
 结构说明  : HIEPS_PERRSTSTAT0 寄存器结构定义。地址偏移量:0x118，初值:0x00000000，宽度:32
 寄存器说明: 外设软复位状态寄存器0。
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ip_prst_hieps_timer : 1;  /* bit[0]   : 默认解复位 */
        unsigned int  ip_prst_hieps_trng  : 1;  /* bit[1]   : 默认解复位 */
        unsigned int  ip_rst_hieps_sce_km : 1;  /* bit[2]   : 默认解复位 */
        unsigned int  ip_rst_hieps_pke    : 1;  /* bit[3]   : 默认解复位 */
        unsigned int  ip_rst_hieps_mmu    : 1;  /* bit[4]   : 默认解复位 */
        unsigned int  ip_rst_ddr_crpt     : 1;  /* bit[5]   : 默认解复位 */
        unsigned int  ip_rst_hieps_cmp    : 1;  /* bit[6]   : 默认解复位 */
        unsigned int  ip_rst_hieps_sce2   : 1;  /* bit[7]   : 默认解复位 */
        unsigned int  ip_rst_hieps_pke2   : 1;  /* bit[8]   : 默认解复位 */
        unsigned int  reserved            : 23; /* bit[9-31]: IP软复位使能状态：
                                                              0：IP处于复位撤离状态；
                                                              1：IP处于软复位使能状态。 */
    } reg;
} SOC_CONFIG_HIEPS_PERRSTSTAT0_UNION;
#endif
#define SOC_CONFIG_HIEPS_PERRSTSTAT0_ip_prst_hieps_timer_START  (0)
#define SOC_CONFIG_HIEPS_PERRSTSTAT0_ip_prst_hieps_timer_END    (0)
#define SOC_CONFIG_HIEPS_PERRSTSTAT0_ip_prst_hieps_trng_START   (1)
#define SOC_CONFIG_HIEPS_PERRSTSTAT0_ip_prst_hieps_trng_END     (1)
#define SOC_CONFIG_HIEPS_PERRSTSTAT0_ip_rst_hieps_sce_km_START  (2)
#define SOC_CONFIG_HIEPS_PERRSTSTAT0_ip_rst_hieps_sce_km_END    (2)
#define SOC_CONFIG_HIEPS_PERRSTSTAT0_ip_rst_hieps_pke_START     (3)
#define SOC_CONFIG_HIEPS_PERRSTSTAT0_ip_rst_hieps_pke_END       (3)
#define SOC_CONFIG_HIEPS_PERRSTSTAT0_ip_rst_hieps_mmu_START     (4)
#define SOC_CONFIG_HIEPS_PERRSTSTAT0_ip_rst_hieps_mmu_END       (4)
#define SOC_CONFIG_HIEPS_PERRSTSTAT0_ip_rst_ddr_crpt_START      (5)
#define SOC_CONFIG_HIEPS_PERRSTSTAT0_ip_rst_ddr_crpt_END        (5)
#define SOC_CONFIG_HIEPS_PERRSTSTAT0_ip_rst_hieps_cmp_START     (6)
#define SOC_CONFIG_HIEPS_PERRSTSTAT0_ip_rst_hieps_cmp_END       (6)
#define SOC_CONFIG_HIEPS_PERRSTSTAT0_ip_rst_hieps_sce2_START    (7)
#define SOC_CONFIG_HIEPS_PERRSTSTAT0_ip_rst_hieps_sce2_END      (7)
#define SOC_CONFIG_HIEPS_PERRSTSTAT0_ip_rst_hieps_pke2_START    (8)
#define SOC_CONFIG_HIEPS_PERRSTSTAT0_ip_rst_hieps_pke2_END      (8)


/*****************************************************************************
 结构名    : SOC_CONFIG_HIEPS_DIV0_UNION
 结构说明  : HIEPS_DIV0 寄存器结构定义。地址偏移量:0x11C，初值:0x00000007，宽度:32
 寄存器说明: 时钟分频比控制寄存器0。
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  div_hieps_ahb_bus_tp    : 2;  /* bit[0-1]  : 默认为3，代表4分频 */
        unsigned int  div_hieps_timer         : 2;  /* bit[2-3]  : 默认为1，代表19.2Mhz的2分频9.6MHz。 */
        unsigned int  sc_gt_clk_hieps_ahb_bus : 1;  /* bit[4]    : ahb时钟门控控制，控制输出到testpoint上的ahb分频时钟 */
        unsigned int  reserved_0              : 11; /* bit[5-15] : 保留。 */
        unsigned int  reserved_1              : 16; /* bit[16-31]: bitmasken:每个比特位的使能位,
                                                                   只有当bitmasken对应的比特位为1'b1，相应的比特位才起作用。bitmasken[0]就是[0]的mask使能位。写1有效。 */
    } reg;
} SOC_CONFIG_HIEPS_DIV0_UNION;
#endif
#define SOC_CONFIG_HIEPS_DIV0_div_hieps_ahb_bus_tp_START     (0)
#define SOC_CONFIG_HIEPS_DIV0_div_hieps_ahb_bus_tp_END       (1)
#define SOC_CONFIG_HIEPS_DIV0_div_hieps_timer_START          (2)
#define SOC_CONFIG_HIEPS_DIV0_div_hieps_timer_END            (3)
#define SOC_CONFIG_HIEPS_DIV0_sc_gt_clk_hieps_ahb_bus_START  (4)
#define SOC_CONFIG_HIEPS_DIV0_sc_gt_clk_hieps_ahb_bus_END    (4)


/*****************************************************************************
 结构名    : SOC_CONFIG_HIEPS_COMMON_CTRL0_UNION
 结构说明  : HIEPS_COMMON_CTRL0 寄存器结构定义。地址偏移量:0x120，初值:0x0000000C，宽度:32
 寄存器说明: CRG控制寄存器0。
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  timer0_soft_en      : 1;  /* bit[0]    : timer1计数使能的软件开关，默认关闭。 */
        unsigned int  timer1_soft_en      : 1;  /* bit[1]    : timer0计数使能的软件开关，默认关闭。 */
        unsigned int  hieps_timer0_en_sel : 1;  /* bit[2]    : 32k还是19.2Mhz分频时钟；
                                                               默认timer的计数使能时钟为9.6Mhz
                                                               0：32K计数使能
                                                               1：选择19.2M的分频时钟 */
        unsigned int  hieps_timer1_en_sel : 1;  /* bit[3]    : 32k还是19.2Mhz分频时钟；
                                                               默认timer的计数使能时钟为9.6Mhz
                                                               0：32K计数使能
                                                               1：选择19.2M的分频时钟 */
        unsigned int  reserved_0          : 12; /* bit[4-15] : 保留。 */
        unsigned int  reserved_1          : 16; /* bit[16-31]: bitmasken:每个比特位的使能位,
                                                               只有当bitmasken对应的比特位为1'b1，相应的比特位才起作用。bitmasken[0]就是[0]的mask使能位。写1有效。 */
    } reg;
} SOC_CONFIG_HIEPS_COMMON_CTRL0_UNION;
#endif
#define SOC_CONFIG_HIEPS_COMMON_CTRL0_timer0_soft_en_START       (0)
#define SOC_CONFIG_HIEPS_COMMON_CTRL0_timer0_soft_en_END         (0)
#define SOC_CONFIG_HIEPS_COMMON_CTRL0_timer1_soft_en_START       (1)
#define SOC_CONFIG_HIEPS_COMMON_CTRL0_timer1_soft_en_END         (1)
#define SOC_CONFIG_HIEPS_COMMON_CTRL0_hieps_timer0_en_sel_START  (2)
#define SOC_CONFIG_HIEPS_COMMON_CTRL0_hieps_timer0_en_sel_END    (2)
#define SOC_CONFIG_HIEPS_COMMON_CTRL0_hieps_timer1_en_sel_START  (3)
#define SOC_CONFIG_HIEPS_COMMON_CTRL0_hieps_timer1_en_sel_END    (3)


/*****************************************************************************
 结构名    : SOC_CONFIG_HIEPS_COMMON_CTRL1_UNION
 结构说明  : HIEPS_COMMON_CTRL1 寄存器结构定义。地址偏移量:0x124，初值:0x00000000，宽度:32
 寄存器说明: CRG控制寄存器1。
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved_0: 16; /* bit[0-15] : 保留。 */
        unsigned int  reserved_1: 16; /* bit[16-31]: bitmasken:每个比特位的使能位,
                                                     只有当bitmasken对应的比特位为1'b1，相应的比特位才起作用。bitmasken[0]就是[0]的mask使能位。写1有效。 */
    } reg;
} SOC_CONFIG_HIEPS_COMMON_CTRL1_UNION;
#endif


/*****************************************************************************
 结构名    : SOC_CONFIG_HIEPS_IPCLKRST_BYPASS0_UNION
 结构说明  : HIEPS_IPCLKRST_BYPASS0 寄存器结构定义。地址偏移量:0x128，初值:0x00000000，宽度:32
 寄存器说明: CRG防挂死控制寄存器。
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  hieps_timer_clkrst_bypass  : 1;  /* bit[0]   : 防挂死指示是否bypass
                                                                     1：防挂死flag置高，访问slave，防挂死逻辑被bypass
                                                                     0：防挂死逻辑生效 */
        unsigned int  hieps_trng_clkrst_bypass   : 1;  /* bit[1]   : 同bit0 */
        unsigned int  hieps_sce_km_clkrst_bypass : 1;  /* bit[2]   : 同bit0 */
        unsigned int  hieps_pke_clkrst_bypass    : 1;  /* bit[3]   : 同bit0 */
        unsigned int  hieps_mmu_clkrst_bypass    : 1;  /* bit[4]   : 同bit0 */
        unsigned int  hieps_sce2_clkrst_bypass   : 1;  /* bit[5]   : 同bit0 */
        unsigned int  hieps_pke2_clkrst_bypass   : 1;  /* bit[6]   : 同bit0 */
        unsigned int  reserved                   : 25; /* bit[7-31]:  */
    } reg;
} SOC_CONFIG_HIEPS_IPCLKRST_BYPASS0_UNION;
#endif
#define SOC_CONFIG_HIEPS_IPCLKRST_BYPASS0_hieps_timer_clkrst_bypass_START   (0)
#define SOC_CONFIG_HIEPS_IPCLKRST_BYPASS0_hieps_timer_clkrst_bypass_END     (0)
#define SOC_CONFIG_HIEPS_IPCLKRST_BYPASS0_hieps_trng_clkrst_bypass_START    (1)
#define SOC_CONFIG_HIEPS_IPCLKRST_BYPASS0_hieps_trng_clkrst_bypass_END      (1)
#define SOC_CONFIG_HIEPS_IPCLKRST_BYPASS0_hieps_sce_km_clkrst_bypass_START  (2)
#define SOC_CONFIG_HIEPS_IPCLKRST_BYPASS0_hieps_sce_km_clkrst_bypass_END    (2)
#define SOC_CONFIG_HIEPS_IPCLKRST_BYPASS0_hieps_pke_clkrst_bypass_START     (3)
#define SOC_CONFIG_HIEPS_IPCLKRST_BYPASS0_hieps_pke_clkrst_bypass_END       (3)
#define SOC_CONFIG_HIEPS_IPCLKRST_BYPASS0_hieps_mmu_clkrst_bypass_START     (4)
#define SOC_CONFIG_HIEPS_IPCLKRST_BYPASS0_hieps_mmu_clkrst_bypass_END       (4)
#define SOC_CONFIG_HIEPS_IPCLKRST_BYPASS0_hieps_sce2_clkrst_bypass_START    (5)
#define SOC_CONFIG_HIEPS_IPCLKRST_BYPASS0_hieps_sce2_clkrst_bypass_END      (5)
#define SOC_CONFIG_HIEPS_IPCLKRST_BYPASS0_hieps_pke2_clkrst_bypass_START    (6)
#define SOC_CONFIG_HIEPS_IPCLKRST_BYPASS0_hieps_pke2_clkrst_bypass_END      (6)


/*****************************************************************************
 结构名    : SOC_CONFIG_HIEPS_MEM_CTRL_ROM_UNION
 结构说明  : HIEPS_MEM_CTRL_ROM 寄存器结构定义。地址偏移量:0x200，初值:0x00000000，宽度:32
 寄存器说明: 
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  hieps_rom_ctrl_ckhe : 1;  /* bit[0]   : ROM 控制：
                                                              bit[5]控制CKHE，默认为0 */
        unsigned int  hieps_rom_ctrl_ckle : 1;  /* bit[1]   : ROM 控制
                                                              bit[4]控制CKLE，默认为0； */
        unsigned int  hieps_rom_ctrl_skp  : 2;  /* bit[2-3] : ROM 控制
                                                              bit[3:2]控制SKP，默认为00； */
        unsigned int  hieps_rom_ctrl_dt   : 2;  /* bit[4-5] : ROM 控制
                                                              bit[1:0]控制DT，默认为00 */
        unsigned int  reserved            : 26; /* bit[6-31]: 不使用 */
    } reg;
} SOC_CONFIG_HIEPS_MEM_CTRL_ROM_UNION;
#endif
#define SOC_CONFIG_HIEPS_MEM_CTRL_ROM_hieps_rom_ctrl_ckhe_START  (0)
#define SOC_CONFIG_HIEPS_MEM_CTRL_ROM_hieps_rom_ctrl_ckhe_END    (0)
#define SOC_CONFIG_HIEPS_MEM_CTRL_ROM_hieps_rom_ctrl_ckle_START  (1)
#define SOC_CONFIG_HIEPS_MEM_CTRL_ROM_hieps_rom_ctrl_ckle_END    (1)
#define SOC_CONFIG_HIEPS_MEM_CTRL_ROM_hieps_rom_ctrl_skp_START   (2)
#define SOC_CONFIG_HIEPS_MEM_CTRL_ROM_hieps_rom_ctrl_skp_END     (3)
#define SOC_CONFIG_HIEPS_MEM_CTRL_ROM_hieps_rom_ctrl_dt_START    (4)
#define SOC_CONFIG_HIEPS_MEM_CTRL_ROM_hieps_rom_ctrl_dt_END      (5)


/*****************************************************************************
 结构名    : SOC_CONFIG_HIEPS_MEM_CTRL_SPRAM_UNION
 结构说明  : HIEPS_MEM_CTRL_SPRAM 寄存器结构定义。地址偏移量:0x204，初值:0x00015858，宽度:32
 寄存器说明: 
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  hieps_spram_mem_ctrl : 26; /* bit[0-25] : memory控制
                                                                bit[0]控制SLP；
                                                                0：无效
                                                                1：进入sleep模式
                                                                bit[1]控制DSLP；
                                                                0：无效
                                                                1：进入deep sleep模式
                                                                bit[2]控制SD；
                                                                0：无效
                                                                1：进入shut down模式
                                                                bit[5:3]控制TSELR，调节读，默认值011；
                                                                bit[7:6]控制TSELW，调节写，默认值01；
                                                                bit[10:8]控制TEST，测试pin，默认值000；
                                                                bit[13:11]控制TSELR，调节读，默认值011；
                                                                bit[15:14]控制TSELW，调节写，默认值01；
                                                                bit[17：16]控制TRA，读assist，仅针对DR类型mem，默认值01；
                                                                其他bit未使用 */
        unsigned int  reserved             : 6;  /* bit[26-31]: 控制RSA/SM9 SPRAM
                                                                SPS类型使用bit[5:3][7:6]
                                                                SPA类型使用bit[13:11][15:14] */
    } reg;
} SOC_CONFIG_HIEPS_MEM_CTRL_SPRAM_UNION;
#endif
#define SOC_CONFIG_HIEPS_MEM_CTRL_SPRAM_hieps_spram_mem_ctrl_START  (0)
#define SOC_CONFIG_HIEPS_MEM_CTRL_SPRAM_hieps_spram_mem_ctrl_END    (25)


/*****************************************************************************
 结构名    : SOC_CONFIG_HIEPS_MEM_CTRL_HD_UNION
 结构说明  : HIEPS_MEM_CTRL_HD 寄存器结构定义。地址偏移量:0x208，初值:0x00015858，宽度:32
 寄存器说明: 
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  hieps_hd_mem_ctrl : 26; /* bit[0-25] : memory控制
                                                             bit[0]控制SLP；
                                                             0：无效
                                                             1：进入sleep模式
                                                             bit[1]控制DSLP；
                                                             0：无效
                                                             1：进入deep sleep模式
                                                             bit[2]控制SD；
                                                             0：无效
                                                             1：进入shut down模式
                                                             bit[5:3]控制TSELR，调节读，默认值011；
                                                             bit[7:6]控制TSELW，调节写，默认值01；
                                                             bit[10:8]控制TEST，测试pin，默认值000；
                                                             bit[13:11]控制TSELR，调节读，默认值011；
                                                             bit[15:14]控制TSELW，调节写，默认值01；
                                                             bit[17：16]控制TRA，读assist，仅针对DR类型mem，默认值01；
                                                             其他bit未使用 */
        unsigned int  reserved          : 6;  /* bit[26-31]: 控制ARC HD类型的RAM
                                                             SPS类型使用bit[5:3][7:6]
                                                             SPA类型使用bit[13:11][15:14]
                                                             不使用 */
    } reg;
} SOC_CONFIG_HIEPS_MEM_CTRL_HD_UNION;
#endif
#define SOC_CONFIG_HIEPS_MEM_CTRL_HD_hieps_hd_mem_ctrl_START  (0)
#define SOC_CONFIG_HIEPS_MEM_CTRL_HD_hieps_hd_mem_ctrl_END    (25)


/*****************************************************************************
 结构名    : SOC_CONFIG_HIEPS_MEM_CTRL_DPRAM_UNION
 结构说明  : HIEPS_MEM_CTRL_DPRAM 寄存器结构定义。地址偏移量:0x20C，初值:0x00000850，宽度:32
 寄存器说明: 
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  hieps_dpram_mem_ctrl : 16; /* bit[0-15] : memory控制
                                                                bit[0]控制LS；
                                                                0：无效
                                                                1：进入sleep模式
                                                                bit[1]控制DSLP；
                                                                0：无效
                                                                1：进入deep sleep模式
                                                                bit[2]控制SD；
                                                                0：无效
                                                                1：进入shut down模式
                                                                bit[5:4]控制TSELR，调节读，默认值01；
                                                                bit[7:6]控制TSELW，调节写，默认值01；
                                                                bit[10:8]控制TEST，测试pin，默认值000；
                                                                bit[12:11]：控制TRA，读assist，仅针对DR类型mem，默认值01
                                                                其他bit未使用。 */
        unsigned int  reserved             : 16; /* bit[16-31]: 控制RSA/ECC/SM9 TPRAM */
    } reg;
} SOC_CONFIG_HIEPS_MEM_CTRL_DPRAM_UNION;
#endif
#define SOC_CONFIG_HIEPS_MEM_CTRL_DPRAM_hieps_dpram_mem_ctrl_START  (0)
#define SOC_CONFIG_HIEPS_MEM_CTRL_DPRAM_hieps_dpram_mem_ctrl_END    (15)


/*****************************************************************************
 结构名    : SOC_CONFIG_HIEPS_MEM_CTRL_BPRAM_UNION
 结构说明  : HIEPS_MEM_CTRL_BPRAM 寄存器结构定义。地址偏移量:0x210，初值:0x00004858，宽度:32
 寄存器说明: 
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  hieps_bpram_mem_ctrl : 16; /* bit[0-15] : memory控制
                                                                bit[0]控制LS；
                                                                0：无效
                                                                1：进入sleep模式
                                                                bit[1]控制DSLP；
                                                                0：无效
                                                                1：进入deep sleep模式
                                                                bit[2]控制SD；
                                                                0：无效
                                                                1：进入shut down模式
                                                                bit[5:3]控制TSELR，调节读，默认值011；
                                                                bit[7:6]控制TSELW，调节写，默认值01；
                                                                bit[10:8]控制TEST，测试pin，默认值000；
                                                                bit[12:11]：控制TRA，读assist，仅针对DR类型mem，默认值01
                                                                bit[15:14]：TSELM，默认值01
                                                                其他bit未使用。 */
        unsigned int  reserved             : 16; /* bit[16-31]: 控制SM9 BPRAM */
    } reg;
} SOC_CONFIG_HIEPS_MEM_CTRL_BPRAM_UNION;
#endif
#define SOC_CONFIG_HIEPS_MEM_CTRL_BPRAM_hieps_bpram_mem_ctrl_START  (0)
#define SOC_CONFIG_HIEPS_MEM_CTRL_BPRAM_hieps_bpram_mem_ctrl_END    (15)


/*****************************************************************************
 结构名    : SOC_CONFIG_HIEPS_INTR_MASK_UNION
 结构说明  : HIEPS_INTR_MASK 寄存器结构定义。地址偏移量:0x214，初值:0x00001F7E，宽度:32
 寄存器说明: 中断MASK
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved_0            : 1;  /* bit[0]    : reserved */
        unsigned int  cfg_alarm_km_mask     : 1;  /* bit[1]    : 1：:屏蔽，不送给外部中断，默认屏蔽
                                                                 0：不屏蔽 */
        unsigned int  cfg_alarm_sce_mask    : 1;  /* bit[2]    : 默认屏蔽 */
        unsigned int  cfg_alarm_rsa_mask    : 1;  /* bit[3]    : 默认屏蔽 */
        unsigned int  cfg_alarm_ecc_mask    : 1;  /* bit[4]    : 默认屏蔽 */
        unsigned int  cfg_alarm_trng_mask   : 1;  /* bit[5]    : 默认屏蔽 */
        unsigned int  cfg_int_trng_mask     : 1;  /* bit[6]    : 默认屏蔽 */
        unsigned int  reserved_1            : 1;  /* bit[7]    : reserved */
        unsigned int  cfg_alarm_sm9_mask    : 1;  /* bit[8]    : 默认屏蔽 */
        unsigned int  cfg_alarm_ddrenc_mask : 1;  /* bit[9]    : 默认屏蔽 */
        unsigned int  cfg_alarm_sce2_mask   : 1;  /* bit[10]   : 默认屏蔽 */
        unsigned int  cfg_alarm_rsa3_mask   : 1;  /* bit[11]   : 默认屏蔽 */
        unsigned int  cfg_alarm_rsa2_mask   : 1;  /* bit[12]   : 默认屏蔽 */
        unsigned int  reserved_2            : 1;  /* bit[13]   : reserved */
        unsigned int  reserved_3            : 1;  /* bit[14]   : reserved */
        unsigned int  reserved_4            : 1;  /* bit[15]   : reserved */
        unsigned int  reserved_5            : 1;  /* bit[16]   : reserved */
        unsigned int  reserved_6            : 15; /* bit[17-31]: 本组清除的ALARM信号为送给AP的ALARM */
    } reg;
} SOC_CONFIG_HIEPS_INTR_MASK_UNION;
#endif
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_alarm_km_mask_START      (1)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_alarm_km_mask_END        (1)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_alarm_sce_mask_START     (2)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_alarm_sce_mask_END       (2)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_alarm_rsa_mask_START     (3)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_alarm_rsa_mask_END       (3)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_alarm_ecc_mask_START     (4)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_alarm_ecc_mask_END       (4)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_alarm_trng_mask_START    (5)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_alarm_trng_mask_END      (5)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_int_trng_mask_START      (6)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_int_trng_mask_END        (6)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_alarm_sm9_mask_START     (8)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_alarm_sm9_mask_END       (8)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_alarm_ddrenc_mask_START  (9)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_alarm_ddrenc_mask_END    (9)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_alarm_sce2_mask_START    (10)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_alarm_sce2_mask_END      (10)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_alarm_rsa3_mask_START    (11)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_alarm_rsa3_mask_END      (11)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_alarm_rsa2_mask_START    (12)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_alarm_rsa2_mask_END      (12)


/*****************************************************************************
 结构名    : SOC_CONFIG_HIEPS_SEC_CTRL_UNION
 结构说明  : HIEPS_SEC_CTRL 寄存器结构定义。地址偏移量:0x218，初值:0x00000028，宽度:32
 寄存器说明: 
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  hieps2lm_busy        : 3;  /* bit[0-2] : 每bit独立表示；由软件分配监控哪个模块的功耗状态。
                                                               1：表征给load_monitor的状态为busy；
                                                               0：表征给load_monitor的状态为idle。 */
        unsigned int  hieps_perf_stat_en   : 1;  /* bit[3]   : 只能静态配置。
                                                               默认开；非加密通道
                                                               1：允许perf_stat监控EPS AXI总线操作；
                                                               0：不允许perf_stat监控EPS AXI总线操作 */
        unsigned int  hieps2qic_disable    : 1;  /* bit[4]   : 只能静态配置。
                                                               关闭后，无法查询HiEPS QIC是否有操作（pending trans）；
                                                               1：关闭，不可查询；
                                                               0：默认为0 ，可查询 */
        unsigned int  hieps_perf_stat_en_1 : 1;  /* bit[5]   : 只能静态配置。
                                                               默认开；加密通道
                                                               1：允许perf_stat监控EPS AXI总线操作；
                                                               0：不允许perf_stat监控EPS AXI总线操作 */
        unsigned int  cfg_trust2prot_en    : 1;  /* bit[6]   : 控制MMU出口处的操作权限：
                                                               1：MMU出口的权限为protected；
                                                               0：MMU出口的权限为Non-trusted； */
        unsigned int  eps_debug_rma_en     : 1;  /* bit[7]   : RMA 模式下的调试权限卡控信号
                                                               0：卡控
                                                               1：不卡控 */
        unsigned int  hieps2dmss_sec_lock  : 1;  /* bit[8]   : bus monitor是否允许debug的使能控制；
                                                               0：允许bus monitor 监控EPS和MEDIA2
                                                               1：不允许bus monitor 监控EPS和MEDIA2 */
        unsigned int  reserved             : 23; /* bit[9-31]:  */
    } reg;
} SOC_CONFIG_HIEPS_SEC_CTRL_UNION;
#endif
#define SOC_CONFIG_HIEPS_SEC_CTRL_hieps2lm_busy_START         (0)
#define SOC_CONFIG_HIEPS_SEC_CTRL_hieps2lm_busy_END           (2)
#define SOC_CONFIG_HIEPS_SEC_CTRL_hieps_perf_stat_en_START    (3)
#define SOC_CONFIG_HIEPS_SEC_CTRL_hieps_perf_stat_en_END      (3)
#define SOC_CONFIG_HIEPS_SEC_CTRL_hieps2qic_disable_START     (4)
#define SOC_CONFIG_HIEPS_SEC_CTRL_hieps2qic_disable_END       (4)
#define SOC_CONFIG_HIEPS_SEC_CTRL_hieps_perf_stat_en_1_START  (5)
#define SOC_CONFIG_HIEPS_SEC_CTRL_hieps_perf_stat_en_1_END    (5)
#define SOC_CONFIG_HIEPS_SEC_CTRL_cfg_trust2prot_en_START     (6)
#define SOC_CONFIG_HIEPS_SEC_CTRL_cfg_trust2prot_en_END       (6)
#define SOC_CONFIG_HIEPS_SEC_CTRL_eps_debug_rma_en_START      (7)
#define SOC_CONFIG_HIEPS_SEC_CTRL_eps_debug_rma_en_END        (7)
#define SOC_CONFIG_HIEPS_SEC_CTRL_hieps2dmss_sec_lock_START   (8)
#define SOC_CONFIG_HIEPS_SEC_CTRL_hieps2dmss_sec_lock_END     (8)


/*****************************************************************************
 结构名    : SOC_CONFIG_HIEPS_QIC_ENC_CTRL_UNION
 结构说明  : HIEPS_QIC_ENC_CTRL 寄存器结构定义。地址偏移量:0x21C，初值:0x00000000，宽度:32
 寄存器说明: 加密通道QIC控制寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  hieps2qic_enc_awMainPress : 2;  /* bit[0-1]  : 静态配置，默认值为0，ARC访问HIEPS QIC的加密写通道的mainPress控制，控制QIC buffer水线的阈值档位，在QOS不起作用时（QIC已经反压EPS时才起作用），可以考虑配置mainPress。 */
        unsigned int  axi_enc_awqos             : 4;  /* bit[2-5]  : 静态配置，HIEPS与QIC对接的加密写通道的AXI master口的QOS值 */
        unsigned int  axi_enc_region            : 4;  /* bit[6-9]  : 静态配置，HIEPS与QIC对接的AXI master口的region值，加密通道 */
        unsigned int  hieps2qic_enc_arMainPress : 2;  /* bit[10-11]: 静态配置，默认值为0，ARC访问HIEPS QIC的加密读通道的mainPress控制，控制QIC buffer水线的阈值档位，在QOS不起作用时（QIC已经反压EPS时才起作用），可以考虑配置mainPress。 */
        unsigned int  axi_enc_arqos             : 4;  /* bit[12-15]: 静态配置，HIEPS与QIC对接的加密读通道的AXI master口的QOS值 */
        unsigned int  reserved                  : 16; /* bit[16-31]:  */
    } reg;
} SOC_CONFIG_HIEPS_QIC_ENC_CTRL_UNION;
#endif
#define SOC_CONFIG_HIEPS_QIC_ENC_CTRL_hieps2qic_enc_awMainPress_START  (0)
#define SOC_CONFIG_HIEPS_QIC_ENC_CTRL_hieps2qic_enc_awMainPress_END    (1)
#define SOC_CONFIG_HIEPS_QIC_ENC_CTRL_axi_enc_awqos_START              (2)
#define SOC_CONFIG_HIEPS_QIC_ENC_CTRL_axi_enc_awqos_END                (5)
#define SOC_CONFIG_HIEPS_QIC_ENC_CTRL_axi_enc_region_START             (6)
#define SOC_CONFIG_HIEPS_QIC_ENC_CTRL_axi_enc_region_END               (9)
#define SOC_CONFIG_HIEPS_QIC_ENC_CTRL_hieps2qic_enc_arMainPress_START  (10)
#define SOC_CONFIG_HIEPS_QIC_ENC_CTRL_hieps2qic_enc_arMainPress_END    (11)
#define SOC_CONFIG_HIEPS_QIC_ENC_CTRL_axi_enc_arqos_START              (12)
#define SOC_CONFIG_HIEPS_QIC_ENC_CTRL_axi_enc_arqos_END                (15)


/*****************************************************************************
 结构名    : SOC_CONFIG_HIEPS_ALARM_STAT_UNION
 结构说明  : HIEPS_ALARM_STAT 寄存器结构定义。地址偏移量:0x220，初值:0x00000000，宽度:32
 寄存器说明: ALARM的状态寄存寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  alarm_km_stat     : 1;  /* bit[0]    : alarm的状态；
                                                             1：有alarm
                                                             0:无alarm */
        unsigned int  alarm_sce_stat    : 1;  /* bit[1]    : 同bit0 */
        unsigned int  alarm_rsa_stat    : 1;  /* bit[2]    : 同bit0 */
        unsigned int  alarm_ecc_stat    : 1;  /* bit[3]    : 同bit0 */
        unsigned int  alarm_trng_stat   : 1;  /* bit[4]    : 同bit0 */
        unsigned int  int_trng_stat     : 1;  /* bit[5]    : 同bit0 */
        unsigned int  alarm_sm9_stat    : 1;  /* bit[6]    : 同bit0 */
        unsigned int  alarm_ddrenc_stat : 1;  /* bit[7]    : 同bit0 */
        unsigned int  alarm_sce2_stat   : 1;  /* bit[8]    : 同bit0 */
        unsigned int  alarm_rsa3_stat   : 1;  /* bit[9]    : 同bit0 */
        unsigned int  alarm_rsa2_stat   : 1;  /* bit[10]   : 同bit0 */
        unsigned int  reserved          : 21; /* bit[11-31]: 该组寄存器上报的ALARM信号为mask之后的ALARM */
    } reg;
} SOC_CONFIG_HIEPS_ALARM_STAT_UNION;
#endif
#define SOC_CONFIG_HIEPS_ALARM_STAT_alarm_km_stat_START      (0)
#define SOC_CONFIG_HIEPS_ALARM_STAT_alarm_km_stat_END        (0)
#define SOC_CONFIG_HIEPS_ALARM_STAT_alarm_sce_stat_START     (1)
#define SOC_CONFIG_HIEPS_ALARM_STAT_alarm_sce_stat_END       (1)
#define SOC_CONFIG_HIEPS_ALARM_STAT_alarm_rsa_stat_START     (2)
#define SOC_CONFIG_HIEPS_ALARM_STAT_alarm_rsa_stat_END       (2)
#define SOC_CONFIG_HIEPS_ALARM_STAT_alarm_ecc_stat_START     (3)
#define SOC_CONFIG_HIEPS_ALARM_STAT_alarm_ecc_stat_END       (3)
#define SOC_CONFIG_HIEPS_ALARM_STAT_alarm_trng_stat_START    (4)
#define SOC_CONFIG_HIEPS_ALARM_STAT_alarm_trng_stat_END      (4)
#define SOC_CONFIG_HIEPS_ALARM_STAT_int_trng_stat_START      (5)
#define SOC_CONFIG_HIEPS_ALARM_STAT_int_trng_stat_END        (5)
#define SOC_CONFIG_HIEPS_ALARM_STAT_alarm_sm9_stat_START     (6)
#define SOC_CONFIG_HIEPS_ALARM_STAT_alarm_sm9_stat_END       (6)
#define SOC_CONFIG_HIEPS_ALARM_STAT_alarm_ddrenc_stat_START  (7)
#define SOC_CONFIG_HIEPS_ALARM_STAT_alarm_ddrenc_stat_END    (7)
#define SOC_CONFIG_HIEPS_ALARM_STAT_alarm_sce2_stat_START    (8)
#define SOC_CONFIG_HIEPS_ALARM_STAT_alarm_sce2_stat_END      (8)
#define SOC_CONFIG_HIEPS_ALARM_STAT_alarm_rsa3_stat_START    (9)
#define SOC_CONFIG_HIEPS_ALARM_STAT_alarm_rsa3_stat_END      (9)
#define SOC_CONFIG_HIEPS_ALARM_STAT_alarm_rsa2_stat_START    (10)
#define SOC_CONFIG_HIEPS_ALARM_STAT_alarm_rsa2_stat_END      (10)


/*****************************************************************************
 结构名    : SOC_CONFIG_HIEPS_STAT_UNION
 结构说明  : HIEPS_STAT 寄存器结构定义。地址偏移量:0x224，初值:0x00000000，宽度:32
 寄存器说明: HIEPS系统状态
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  hieps_lcs_4bit : 4;  /* bit[0-3] : HIEPS的生命周期状态：
                                                         4'b0000:ICCT
                                                         4'b0001:ICDT
                                                         4'b0011:UM
                                                         4'b0111:当lcs_rma为1时,0111表示RMA；当lcs_rma为0,0111表示SDMRM
                                                         others:SDM */
        unsigned int  hw_rd_finish   : 1;  /* bit[4]   : efuse送给eps的信号是否有效
                                                         1：有效 */
        unsigned int  lcs_rma        : 1;  /* bit[5]   : Lcs_ram的生命周期判断：
                                                         1：RMA生命周期
                                                         0：其它生命周期 */
        unsigned int  reserved       : 26; /* bit[6-31]:  */
    } reg;
} SOC_CONFIG_HIEPS_STAT_UNION;
#endif
#define SOC_CONFIG_HIEPS_STAT_hieps_lcs_4bit_START  (0)
#define SOC_CONFIG_HIEPS_STAT_hieps_lcs_4bit_END    (3)
#define SOC_CONFIG_HIEPS_STAT_hw_rd_finish_START    (4)
#define SOC_CONFIG_HIEPS_STAT_hw_rd_finish_END      (4)
#define SOC_CONFIG_HIEPS_STAT_lcs_rma_START         (5)
#define SOC_CONFIG_HIEPS_STAT_lcs_rma_END           (5)


/*****************************************************************************
 结构名    : SOC_CONFIG_HIEPS_EFUSE_CTRL_STAT_UNION
 结构说明  : HIEPS_EFUSE_CTRL_STAT 寄存器结构定义。地址偏移量:0x228，初值:0x00000A00，宽度:32
 寄存器说明: efuse解析状态
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  eps_debug_disable       : 4;  /* bit[0-3]  : EPS UM模式下的调试卡控信号：
                                                                   4'h0:允许调试，
                                                                   其他值不允许调试。 */
        unsigned int  km_debug_disable        : 4;  /* bit[4-7]  : KM的key的寄存器上报卡控信号：
                                                                   0：能上报
                                                                   其它值不上报 */
        unsigned int  misc2crypto_smx_disable : 4;  /* bit[8-11] : 国密引擎的屏蔽使能：
                                                                   4'h5:国密算法不能使用
                                                                   4'ha:国密算法可以使用 */
        unsigned int  reserved                : 20; /* bit[12-31]:  */
    } reg;
} SOC_CONFIG_HIEPS_EFUSE_CTRL_STAT_UNION;
#endif
#define SOC_CONFIG_HIEPS_EFUSE_CTRL_STAT_eps_debug_disable_START        (0)
#define SOC_CONFIG_HIEPS_EFUSE_CTRL_STAT_eps_debug_disable_END          (3)
#define SOC_CONFIG_HIEPS_EFUSE_CTRL_STAT_km_debug_disable_START         (4)
#define SOC_CONFIG_HIEPS_EFUSE_CTRL_STAT_km_debug_disable_END           (7)
#define SOC_CONFIG_HIEPS_EFUSE_CTRL_STAT_misc2crypto_smx_disable_START  (8)
#define SOC_CONFIG_HIEPS_EFUSE_CTRL_STAT_misc2crypto_smx_disable_END    (11)


/*****************************************************************************
 结构名    : SOC_CONFIG_HIEPS_MMU_WID_UNION
 结构说明  : HIEPS_MMU_WID 寄存器结构定义。地址偏移量:0x300，初值:0x00010000，宽度:32
 寄存器说明: SCE1写通道的ID配置
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  awmmusid_s0    : 8;  /* bit[0-7]  : SCE1写通道Stream ID。
                                                          Media2中SMMU的master统一分配。 */
        unsigned int  awmmussid_s0   : 8;  /* bit[8-15] : SCE1写通道Sub Stream ID */
        unsigned int  awmmusecsid_s0 : 1;  /* bit[16]   : SCE1写通道Stream ID Secure flag信号。
                                                          0: 当前页表操作是non-secure的。
                                                          1: 当前页表操作是secure的。 */
        unsigned int  awmmussidv_s0  : 1;  /* bit[17]   : SCE1写通道Sub Stream ID valid指示信号。
                                                          0: SSID无效，不使用SSID进行动态页表切换。
                                                          1: SSID有效，使用SSID进行动态页表切换。 */
        unsigned int  reserved       : 14; /* bit[18-31]: reserved */
    } reg;
} SOC_CONFIG_HIEPS_MMU_WID_UNION;
#endif
#define SOC_CONFIG_HIEPS_MMU_WID_awmmusid_s0_START     (0)
#define SOC_CONFIG_HIEPS_MMU_WID_awmmusid_s0_END       (7)
#define SOC_CONFIG_HIEPS_MMU_WID_awmmussid_s0_START    (8)
#define SOC_CONFIG_HIEPS_MMU_WID_awmmussid_s0_END      (15)
#define SOC_CONFIG_HIEPS_MMU_WID_awmmusecsid_s0_START  (16)
#define SOC_CONFIG_HIEPS_MMU_WID_awmmusecsid_s0_END    (16)
#define SOC_CONFIG_HIEPS_MMU_WID_awmmussidv_s0_START   (17)
#define SOC_CONFIG_HIEPS_MMU_WID_awmmussidv_s0_END     (17)


/*****************************************************************************
 结构名    : SOC_CONFIG_HIEPS_MMU_RID_UNION
 结构说明  : HIEPS_MMU_RID 寄存器结构定义。地址偏移量:0x304，初值:0x00010000，宽度:32
 寄存器说明: SCE1读通道的ID配置
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  armmusid_s0    : 8;  /* bit[0-7]  : SCE1读通道Stream ID。
                                                          Media2中SMMU的master统一分配。 */
        unsigned int  armmussid_s0   : 8;  /* bit[8-15] : SCE1读通道Sub Stream ID */
        unsigned int  armmusecsid_s0 : 1;  /* bit[16]   : SCE1读通道Stream ID Secure flag信号。
                                                          0: 当前页表操作是non-secure的。
                                                          1: 当前页表操作是secure的。 */
        unsigned int  armmussidv_s0  : 1;  /* bit[17]   : SCE1读通道Sub Stream ID valid指示信号。
                                                          0: SSID无效，不使用SSID进行动态页表切换。
                                                          1: SSID有效，使用SSID进行动态页表切换。 */
        unsigned int  reserved       : 14; /* bit[18-31]: reserved */
    } reg;
} SOC_CONFIG_HIEPS_MMU_RID_UNION;
#endif
#define SOC_CONFIG_HIEPS_MMU_RID_armmusid_s0_START     (0)
#define SOC_CONFIG_HIEPS_MMU_RID_armmusid_s0_END       (7)
#define SOC_CONFIG_HIEPS_MMU_RID_armmussid_s0_START    (8)
#define SOC_CONFIG_HIEPS_MMU_RID_armmussid_s0_END      (15)
#define SOC_CONFIG_HIEPS_MMU_RID_armmusecsid_s0_START  (16)
#define SOC_CONFIG_HIEPS_MMU_RID_armmusecsid_s0_END    (16)
#define SOC_CONFIG_HIEPS_MMU_RID_armmussidv_s0_START   (17)
#define SOC_CONFIG_HIEPS_MMU_RID_armmussidv_s0_END     (17)


/*****************************************************************************
 结构名    : SOC_CONFIG_HIEPS_MMU_PREID_UNION
 结构说明  : HIEPS_MMU_PREID 寄存器结构定义。地址偏移量:0x308，初值:0x00000001，宽度:32
 寄存器说明: SCE1预取滑窗ID
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  armmuswid_s0 : 8;  /* bit[0-7]  : SCE1读通道预取滑窗ID */
        unsigned int  awmmuswid_s0 : 8;  /* bit[8-15] : SCE1写通道预取滑窗ID */
        unsigned int  reserved     : 16; /* bit[16-31]: reserved */
    } reg;
} SOC_CONFIG_HIEPS_MMU_PREID_UNION;
#endif
#define SOC_CONFIG_HIEPS_MMU_PREID_armmuswid_s0_START  (0)
#define SOC_CONFIG_HIEPS_MMU_PREID_armmuswid_s0_END    (7)
#define SOC_CONFIG_HIEPS_MMU_PREID_awmmuswid_s0_START  (8)
#define SOC_CONFIG_HIEPS_MMU_PREID_awmmuswid_s0_END    (15)


/*****************************************************************************
 结构名    : SOC_CONFIG_HIEPS_MMU2_WID_UNION
 结构说明  : HIEPS_MMU2_WID 寄存器结构定义。地址偏移量:0x30C，初值:0x00010000，宽度:32
 寄存器说明: SCE2写通道的ID配置
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  awmmusid_s1    : 8;  /* bit[0-7]  : SCE2写通道Stream ID。
                                                          Media2中SMMU的master统一分配。 */
        unsigned int  awmmussid_s1   : 8;  /* bit[8-15] : SCE2写通道Sub Stream ID */
        unsigned int  awmmusecsid_s1 : 1;  /* bit[16]   : SCE2写通道Stream ID Secure flag信号。
                                                          0: 当前页表操作是non-secure的。
                                                          1: 当前页表操作是secure的。 */
        unsigned int  awmmussidv_s1  : 1;  /* bit[17]   : SCE2写通道Sub Stream ID valid指示信号。
                                                          0: SSID无效，不使用SSID进行动态页表切换。
                                                          1: SSID有效，使用SSID进行动态页表切换。 */
        unsigned int  reserved       : 14; /* bit[18-31]: reserved */
    } reg;
} SOC_CONFIG_HIEPS_MMU2_WID_UNION;
#endif
#define SOC_CONFIG_HIEPS_MMU2_WID_awmmusid_s1_START     (0)
#define SOC_CONFIG_HIEPS_MMU2_WID_awmmusid_s1_END       (7)
#define SOC_CONFIG_HIEPS_MMU2_WID_awmmussid_s1_START    (8)
#define SOC_CONFIG_HIEPS_MMU2_WID_awmmussid_s1_END      (15)
#define SOC_CONFIG_HIEPS_MMU2_WID_awmmusecsid_s1_START  (16)
#define SOC_CONFIG_HIEPS_MMU2_WID_awmmusecsid_s1_END    (16)
#define SOC_CONFIG_HIEPS_MMU2_WID_awmmussidv_s1_START   (17)
#define SOC_CONFIG_HIEPS_MMU2_WID_awmmussidv_s1_END     (17)


/*****************************************************************************
 结构名    : SOC_CONFIG_HIEPS_MMU2_RID_UNION
 结构说明  : HIEPS_MMU2_RID 寄存器结构定义。地址偏移量:0x310，初值:0x00010000，宽度:32
 寄存器说明: SCE2读通道的ID配置
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  armmusid_s1    : 8;  /* bit[0-7]  : SCE2读通道Stream ID。
                                                          Media2中SMMU的master统一分配。 */
        unsigned int  armmussid_s1   : 8;  /* bit[8-15] : SCE2读通道Sub Stream ID */
        unsigned int  armmusecsid_s1 : 1;  /* bit[16]   : SCE2读通道Stream ID Secure flag信号。
                                                          0: 当前页表操作是non-secure的。
                                                          1: 当前页表操作是secure的。 */
        unsigned int  armmussidv_s1  : 1;  /* bit[17]   : SCE2读通道Sub Stream ID valid指示信号。
                                                          0: SSID无效，不使用SSID进行动态页表切换。
                                                          1: SSID有效，使用SSID进行动态页表切换。 */
        unsigned int  reserved       : 14; /* bit[18-31]: reserved */
    } reg;
} SOC_CONFIG_HIEPS_MMU2_RID_UNION;
#endif
#define SOC_CONFIG_HIEPS_MMU2_RID_armmusid_s1_START     (0)
#define SOC_CONFIG_HIEPS_MMU2_RID_armmusid_s1_END       (7)
#define SOC_CONFIG_HIEPS_MMU2_RID_armmussid_s1_START    (8)
#define SOC_CONFIG_HIEPS_MMU2_RID_armmussid_s1_END      (15)
#define SOC_CONFIG_HIEPS_MMU2_RID_armmusecsid_s1_START  (16)
#define SOC_CONFIG_HIEPS_MMU2_RID_armmusecsid_s1_END    (16)
#define SOC_CONFIG_HIEPS_MMU2_RID_armmussidv_s1_START   (17)
#define SOC_CONFIG_HIEPS_MMU2_RID_armmussidv_s1_END     (17)


/*****************************************************************************
 结构名    : SOC_CONFIG_HIEPS_MMU2_PREID_UNION
 结构说明  : HIEPS_MMU2_PREID 寄存器结构定义。地址偏移量:0x314，初值:0x00000203，宽度:32
 寄存器说明: SCE2预取滑窗ID
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  armmuswid_s1 : 8;  /* bit[0-7]  : SCE2读通道预取滑窗ID */
        unsigned int  awmmuswid_s1 : 8;  /* bit[8-15] : SCE2写通道预取滑窗ID */
        unsigned int  reserved     : 16; /* bit[16-31]: reserved */
    } reg;
} SOC_CONFIG_HIEPS_MMU2_PREID_UNION;
#endif
#define SOC_CONFIG_HIEPS_MMU2_PREID_armmuswid_s1_START  (0)
#define SOC_CONFIG_HIEPS_MMU2_PREID_armmuswid_s1_END    (7)
#define SOC_CONFIG_HIEPS_MMU2_PREID_awmmuswid_s1_START  (8)
#define SOC_CONFIG_HIEPS_MMU2_PREID_awmmuswid_s1_END    (15)


/*****************************************************************************
 结构名    : SOC_CONFIG_SCE_MST_PRIORITY_UNION
 结构说明  : SCE_MST_PRIORITY 寄存器结构定义。地址偏移量:0x400，初值:0x00000001，宽度:32
 寄存器说明: 总线桥优先级配置寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sce_mst_priority_sce2to2  : 1;  /* bit[0]   : AXI 2to2桥SCE优先级配置 bit[0]和bit[1]配合使用，配置为1的优先级高于配置为0的优先级，如果两个口配置优先级相同，则SCE1优先级高 */
        unsigned int  sce2_mst_priority_sce2to2 : 1;  /* bit[1]   : AXI 2to2桥SCE2优先级配置 bit[0]和bit[1]配合使用，配置为1的优先级高于配置为0的优先级，如果两个口配置优先级相同，则SCE1优先级高 */
        unsigned int  reserved                  : 30; /* bit[2-31]: reserved */
    } reg;
} SOC_CONFIG_SCE_MST_PRIORITY_UNION;
#endif
#define SOC_CONFIG_SCE_MST_PRIORITY_sce_mst_priority_sce2to2_START   (0)
#define SOC_CONFIG_SCE_MST_PRIORITY_sce_mst_priority_sce2to2_END     (0)
#define SOC_CONFIG_SCE_MST_PRIORITY_sce2_mst_priority_sce2to2_START  (1)
#define SOC_CONFIG_SCE_MST_PRIORITY_sce2_mst_priority_sce2to2_END    (1)


/*****************************************************************************
 结构名    : SOC_CONFIG_HIEPS_HINT_UNION
 结构说明  : HIEPS_HINT 寄存器结构定义。地址偏移量:0x404，初值:0x00000000，宽度:32
 寄存器说明: hint信号配置
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved_0  : 4;  /* bit[0-3]  : Arc读通道的hint信号配置: 在axcache为non_cacheable的情况下，4’h0表示不访问system cache，其它值可访问到system cache */
        unsigned int  reserved_1  : 4;  /* bit[4-7]  : Arc写通道的hint信号配置: 在axcache为non_cacheable的情况下，4’h0表示不访问system cache，其它值可访问到system cache */
        unsigned int  sce_arhint  : 4;  /* bit[8-11] : Sce读通道的hint信号配置: 在axcache为non_cacheable的情况下，4’h0表示不访问system cache，其它值可访问到system cache */
        unsigned int  sce_awhint  : 4;  /* bit[12-15]: Sce写通道的hint信号配置: 在axcache为non_cacheable的情况下，4’h0表示不访问system cache，其它值可访问到system cache */
        unsigned int  sce2_arhint : 4;  /* bit[16-19]: Sce2读通道的hint信号配置: 在axcache为non_cacheable的情况下，4’h0表示不访问system cache，其它值可访问到system cache */
        unsigned int  sce2_awhint : 4;  /* bit[20-23]: Sce2写通道的hint信号配置: 在axcache为non_cacheable的情况下，4’h0表示不访问system cache，其它值可访问到system cache */
        unsigned int  reserved_2  : 8;  /* bit[24-31]: reserved */
    } reg;
} SOC_CONFIG_HIEPS_HINT_UNION;
#endif
#define SOC_CONFIG_HIEPS_HINT_sce_arhint_START   (8)
#define SOC_CONFIG_HIEPS_HINT_sce_arhint_END     (11)
#define SOC_CONFIG_HIEPS_HINT_sce_awhint_START   (12)
#define SOC_CONFIG_HIEPS_HINT_sce_awhint_END     (15)
#define SOC_CONFIG_HIEPS_HINT_sce2_arhint_START  (16)
#define SOC_CONFIG_HIEPS_HINT_sce2_arhint_END    (19)
#define SOC_CONFIG_HIEPS_HINT_sce2_awhint_START  (20)
#define SOC_CONFIG_HIEPS_HINT_sce2_awhint_END    (23)


/*****************************************************************************
 结构名    : SOC_CONFIG_REG_RESERVED10_UNION
 结构说明  : REG_RESERVED10 寄存器结构定义。地址偏移量:0x420，初值:0x00000000，宽度:32
 寄存器说明: 
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved : 32; /* bit[0-31]: reserved */
    } reg;
} SOC_CONFIG_REG_RESERVED10_UNION;
#endif


/*****************************************************************************
 结构名    : SOC_CONFIG_REG_RESERVED11_UNION
 结构说明  : REG_RESERVED11 寄存器结构定义。地址偏移量:0x424，初值:0x00000000，宽度:32
 寄存器说明: 
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved : 32; /* bit[0-31]: reserved */
    } reg;
} SOC_CONFIG_REG_RESERVED11_UNION;
#endif


/*****************************************************************************
 结构名    : SOC_CONFIG_HIEPS_RCV_STATE_UNION
 结构说明  : HIEPS_RCV_STATE 寄存器结构定义。地址偏移量:0x500，初值:0x00000000，宽度:32
 寄存器说明: 压缩状态寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  hieps_rcv_state : 32; /* bit[0-31]: bit0:hieps_kdr_rcv_state kdr解压缩完成状态指示
                                                          bit1:hieps_gid_rcv_state gid解压缩完成状态指示
                                                          bit2:hieps_gm_posk_rcv_stategm posk解压缩完成状态指示
                                                          bit3:hieps_gm_rotpk_rcv_stategm rotpk解压缩完成状态指示
                                                          bit4:hieps_gj_rotpk_rcv_stategj rotpk解压缩完成状态指示
                                                          bit5:hieps_patch_rcv_state patch解压缩完成状态指示
                                                          bit6-31:reserved */
    } reg;
} SOC_CONFIG_HIEPS_RCV_STATE_UNION;
#endif
#define SOC_CONFIG_HIEPS_RCV_STATE_hieps_rcv_state_START  (0)
#define SOC_CONFIG_HIEPS_RCV_STATE_hieps_rcv_state_END    (31)


/*****************************************************************************
 结构名    : SOC_CONFIG_REG_RW_RES1_UNION
 结构说明  : REG_RW_RES1 寄存器结构定义。地址偏移量:0x800，初值:0x00000000，宽度:32
 寄存器说明: 保留寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reg_rw_res1 : 32; /* bit[0-31]: 保留 */
    } reg;
} SOC_CONFIG_REG_RW_RES1_UNION;
#endif
#define SOC_CONFIG_REG_RW_RES1_reg_rw_res1_START  (0)
#define SOC_CONFIG_REG_RW_RES1_reg_rw_res1_END    (31)


/*****************************************************************************
 结构名    : SOC_CONFIG_REG_RW_RES2_UNION
 结构说明  : REG_RW_RES2 寄存器结构定义。地址偏移量:0x804，初值:0x00000000，宽度:32
 寄存器说明: 保留寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reg_rw_res2 : 32; /* bit[0-31]: 保留 */
    } reg;
} SOC_CONFIG_REG_RW_RES2_UNION;
#endif
#define SOC_CONFIG_REG_RW_RES2_reg_rw_res2_START  (0)
#define SOC_CONFIG_REG_RW_RES2_reg_rw_res2_END    (31)


/*****************************************************************************
 结构名    : SOC_CONFIG_REG_RO_RES1_UNION
 结构说明  : REG_RO_RES1 寄存器结构定义。地址偏移量:0x808，初值:0x00000000，宽度:32
 寄存器说明: 保留寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reg_ro_res1 : 32; /* bit[0-31]: 保留 */
    } reg;
} SOC_CONFIG_REG_RO_RES1_UNION;
#endif
#define SOC_CONFIG_REG_RO_RES1_reg_ro_res1_START  (0)
#define SOC_CONFIG_REG_RO_RES1_reg_ro_res1_END    (31)






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

#endif /* end of soc_config_interface.h */
