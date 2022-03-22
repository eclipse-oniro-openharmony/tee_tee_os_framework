/******************************************************************************

                 版权所有 (C), 2001-2019, 华为技术有限公司

 ******************************************************************************
  文 件 名   : soc_etzpc_interface.h
  版 本 号   : 初稿
  作    者   : Excel2Code
  生成日期   : 2019-10-26 11:03:09
  最近修改   :
  功能描述   : 接口头文件
  函数列表   :
  修改历史   :
  1.日    期   : 2019年10月26日
    作    者   : l00249396
    修改内容   : 从《HiEPS V210 寄存器手册_ETZPC.xml》自动生成

******************************************************************************/

/*****************************************************************************
  1 其他头文件包含
*****************************************************************************/

#ifndef __SOC_ETZPC_INTERFACE_H__
#define __SOC_ETZPC_INTERFACE_H__

#ifdef __cplusplus
    #if __cplusplus
        extern "C" {
    #endif
#endif



/*****************************************************************************
  2 宏定义
*****************************************************************************/

/****************************************************************************
                     (1/1) ETZPC
 ****************************************************************************/
/* 寄存器说明：用于控制安全保护的区域大小
            接驳TZMA进行对secram的控制，以4KB为单位
            0x00000000 = no secure region
            0x00000001 = 4KB secure region
            0x00000002 = 8KB secure region
            …
            0x000001FF = 2044KB secure region
            0x00000200 或以上的配置将对整个secram空间分配成安全空间。
   位域定义UNION结构:  SOC_ETZPC_R0SIZE_UNION */
#define SOC_ETZPC_R0SIZE_ADDR(base)                   ((base) + (0x000))

/* 寄存器说明：IP安全属性状态寄存器0。
   位域定义UNION结构:  SOC_ETZPC_DECPROT0STAT_UNION */
#define SOC_ETZPC_DECPROT0STAT_ADDR(base)             ((base) + (0x800))

/* 寄存器说明：IP安全属性置位寄存器0。
   位域定义UNION结构:  SOC_ETZPC_DECPROT0SET_UNION */
#define SOC_ETZPC_DECPROT0SET_ADDR(base)              ((base) + (0x804))

/* 寄存器说明：IP安全属性清零寄存器0。
   位域定义UNION结构:  SOC_ETZPC_DECPROT0CLR_UNION */
#define SOC_ETZPC_DECPROT0CLR_ADDR(base)              ((base) + (0x808))

/* 寄存器说明：IP安全属性状态寄存器1。
   位域定义UNION结构:  SOC_ETZPC_DECPROT1STAT_UNION */
#define SOC_ETZPC_DECPROT1STAT_ADDR(base)             ((base) + (0x80C))

/* 寄存器说明：IP安全属性置位寄存器1。
   位域定义UNION结构:  SOC_ETZPC_DECPROT1SET_UNION */
#define SOC_ETZPC_DECPROT1SET_ADDR(base)              ((base) + (0x810))

/* 寄存器说明：IP安全属性清零寄存器1。
   位域定义UNION结构:  SOC_ETZPC_DECPROT1CLR_UNION */
#define SOC_ETZPC_DECPROT1CLR_ADDR(base)              ((base) + (0x814))

/* 寄存器说明：IP安全属性状态寄存器2。
   位域定义UNION结构:  SOC_ETZPC_DECPROT2STAT_UNION */
#define SOC_ETZPC_DECPROT2STAT_ADDR(base)             ((base) + (0x818))

/* 寄存器说明：IP安全属性置位寄存器2。
   位域定义UNION结构:  SOC_ETZPC_DECPROT2SET_UNION */
#define SOC_ETZPC_DECPROT2SET_ADDR(base)              ((base) + (0x81C))

/* 寄存器说明：IP安全属性清零寄存器2。
   位域定义UNION结构:  SOC_ETZPC_DECPROT2CLR_UNION */
#define SOC_ETZPC_DECPROT2CLR_ADDR(base)              ((base) + (0x820))

/* 寄存器说明：IP安全属性状态寄存器3。
   位域定义UNION结构:  SOC_ETZPC_DECPROT3STAT_UNION */
#define SOC_ETZPC_DECPROT3STAT_ADDR(base)             ((base) + (0x824))

/* 寄存器说明：IP安全属性置位寄存器3。
   位域定义UNION结构:  SOC_ETZPC_DECPROT3SET_UNION */
#define SOC_ETZPC_DECPROT3SET_ADDR(base)              ((base) + (0x828))

/* 寄存器说明：IP安全属性清零寄存器3。
   位域定义UNION结构:  SOC_ETZPC_DECPROT3CLR_UNION */
#define SOC_ETZPC_DECPROT3CLR_ADDR(base)              ((base) + (0x82C))

/* 寄存器说明：IP安全属性状态寄存器4。
   位域定义UNION结构:  SOC_ETZPC_DECPROT4STAT_UNION */
#define SOC_ETZPC_DECPROT4STAT_ADDR(base)             ((base) + (0x830))

/* 寄存器说明：IP安全属性置位寄存器4。
   位域定义UNION结构:  SOC_ETZPC_DECPROT4SET_UNION */
#define SOC_ETZPC_DECPROT4SET_ADDR(base)              ((base) + (0x834))

/* 寄存器说明：IP安全属性清零寄存器4。
   位域定义UNION结构:  SOC_ETZPC_DECPROT4CLR_UNION */
#define SOC_ETZPC_DECPROT4CLR_ADDR(base)              ((base) + (0x838))

/* 寄存器说明：IP安全属性状态寄存器5。
   位域定义UNION结构:  SOC_ETZPC_DECPROT5STAT_UNION */
#define SOC_ETZPC_DECPROT5STAT_ADDR(base)             ((base) + (0x83C))

/* 寄存器说明：IP安全属性置位寄存器5。
   位域定义UNION结构:  SOC_ETZPC_DECPROT5SET_UNION */
#define SOC_ETZPC_DECPROT5SET_ADDR(base)              ((base) + (0x840))

/* 寄存器说明：IP安全属性清零寄存器5。
   位域定义UNION结构:  SOC_ETZPC_DECPROT5CLR_UNION */
#define SOC_ETZPC_DECPROT5CLR_ADDR(base)              ((base) + (0x844))

/* 寄存器说明：IP安全属性状态寄存器6。
   位域定义UNION结构:  SOC_ETZPC_DECPROT6STAT_UNION */
#define SOC_ETZPC_DECPROT6STAT_ADDR(base)             ((base) + (0x848))

/* 寄存器说明：IP安全属性置位寄存器6。
   位域定义UNION结构:  SOC_ETZPC_DECPROT6SET_UNION */
#define SOC_ETZPC_DECPROT6SET_ADDR(base)              ((base) + (0x84C))

/* 寄存器说明：IP安全属性清零寄存器6。
   位域定义UNION结构:  SOC_ETZPC_DECPROT6CLR_UNION */
#define SOC_ETZPC_DECPROT6CLR_ADDR(base)              ((base) + (0x850))

/* 寄存器说明：IP安全属性状态寄存器7。
   位域定义UNION结构:  SOC_ETZPC_DECPROT7STAT_UNION */
#define SOC_ETZPC_DECPROT7STAT_ADDR(base)             ((base) + (0x854))

/* 寄存器说明：IP安全属性置位寄存器7。
   位域定义UNION结构:  SOC_ETZPC_DECPROT7SET_UNION */
#define SOC_ETZPC_DECPROT7SET_ADDR(base)              ((base) + (0x858))

/* 寄存器说明：IP安全属性清零寄存器7。
   位域定义UNION结构:  SOC_ETZPC_DECPROT7CLR_UNION */
#define SOC_ETZPC_DECPROT7CLR_ADDR(base)              ((base) + (0x85C))

/* 寄存器说明：IP安全属性状态寄存器8。
   位域定义UNION结构:  SOC_ETZPC_DECPROT8STAT_UNION */
#define SOC_ETZPC_DECPROT8STAT_ADDR(base)             ((base) + (0x860))

/* 寄存器说明：IP安全属性置位寄存器8。
   位域定义UNION结构:  SOC_ETZPC_DECPROT8SET_UNION */
#define SOC_ETZPC_DECPROT8SET_ADDR(base)              ((base) + (0x864))

/* 寄存器说明：IP安全属性清零寄存器8。
   位域定义UNION结构:  SOC_ETZPC_DECPROT8CLR_UNION */
#define SOC_ETZPC_DECPROT8CLR_ADDR(base)              ((base) + (0x868))

/* 寄存器说明：控制reg0寄存器的信息。
   位域定义UNION结构:  SOC_ETZPC_REG0_STAT_UNION */
#define SOC_ETZPC_REG0_STAT_ADDR(base)                ((base) + (0x86C))

/* 寄存器说明：控制reg1寄存器的信息。
   位域定义UNION结构:  SOC_ETZPC_REG1_STAT_UNION */
#define SOC_ETZPC_REG1_STAT_ADDR(base)                ((base) + (0x870))

/* 寄存器说明：寄存PATCH校验信息的寄存器0
   位域定义UNION结构:  SOC_ETZPC_EFUSEC2HIEPS_PATCH0_SEC_UNION */
#define SOC_ETZPC_EFUSEC2HIEPS_PATCH0_SEC_ADDR(base)  ((base) + (0x874))

/* 寄存器说明：寄存PATCH校验信息的寄存器1
   位域定义UNION结构:  SOC_ETZPC_EFUSEC2HIEPS_PATCH1_SEC_UNION */
#define SOC_ETZPC_EFUSEC2HIEPS_PATCH1_SEC_ADDR(base)  ((base) + (0x878))

/* 寄存器说明：寄存PATCH校验信息的寄存器2
   位域定义UNION结构:  SOC_ETZPC_EFUSEC2HIEPS_PATCH2_SEC_UNION */
#define SOC_ETZPC_EFUSEC2HIEPS_PATCH2_SEC_ADDR(base)  ((base) + (0x87C))

/* 寄存器说明：寄存PATCH校验信息的寄存器3
   位域定义UNION结构:  SOC_ETZPC_EFUSEC2HIEPS_PATCH3_SEC_UNION */
#define SOC_ETZPC_EFUSEC2HIEPS_PATCH3_SEC_ADDR(base)  ((base) + (0x880))

/* 寄存器说明：寄存PATCH校验信息的寄存器4
   位域定义UNION结构:  SOC_ETZPC_EFUSEC2HIEPS_PATCH4_SEC_UNION */
#define SOC_ETZPC_EFUSEC2HIEPS_PATCH4_SEC_ADDR(base)  ((base) + (0x884))

/* 寄存器说明：寄存PATCH校验信息的寄存器5
   位域定义UNION结构:  SOC_ETZPC_EFUSEC2HIEPS_PATCH5_SEC_UNION */
#define SOC_ETZPC_EFUSEC2HIEPS_PATCH5_SEC_ADDR(base)  ((base) + (0x888))

/* 寄存器说明：寄存PATCH校验信息的寄存器6
   位域定义UNION结构:  SOC_ETZPC_EFUSEC2HIEPS_PATCH6_SEC_UNION */
#define SOC_ETZPC_EFUSEC2HIEPS_PATCH6_SEC_ADDR(base)  ((base) + (0x88C))

/* 寄存器说明：寄存PATCH校验信息的寄存器7
   位域定义UNION结构:  SOC_ETZPC_EFUSEC2HIEPS_PATCH7_SEC_UNION */
#define SOC_ETZPC_EFUSEC2HIEPS_PATCH7_SEC_ADDR(base)  ((base) + (0x890))





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
                     (1/1) ETZPC
 ****************************************************************************/
/*****************************************************************************
 结构名    : SOC_ETZPC_R0SIZE_UNION
 结构说明  : R0SIZE 寄存器结构定义。地址偏移量:0x000，初值:0x000003FF，宽度:32
 寄存器说明: 用于控制安全保护的区域大小
            接驳TZMA进行对secram的控制，以4KB为单位
            0x00000000 = no secure region
            0x00000001 = 4KB secure region
            0x00000002 = 8KB secure region
            …
            0x000001FF = 2044KB secure region
            0x00000200 或以上的配置将对整个secram空间分配成安全空间。
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved_0: 10; /* bit[0-9]  : 保留。 */
        unsigned int  reserved_1: 22; /* bit[10-31]: 保留。HiEPS未使用。 */
    } reg;
} SOC_ETZPC_R0SIZE_UNION;
#endif


/*****************************************************************************
 结构名    : SOC_ETZPC_DECPROT0STAT_UNION
 结构说明  : DECPROT0STAT 寄存器结构定义。地址偏移量:0x800，初值:0x00000000，宽度:32
 寄存器说明: IP安全属性状态寄存器0。
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved_0       : 1;  /* bit[0] : 保留。HIEPS未使用。 */
        unsigned int  reserved_1       : 1;  /* bit[1] : 保留。HIEPS未使用。 */
        unsigned int  reserved_2       : 1;  /* bit[2] : 保留。HIEPS未使用。 */
        unsigned int  reserved_3       : 1;  /* bit[3] : 保留。HIEPS未使用。 */
        unsigned int  tz_secure_km_0   : 1;  /* bit[4] : KM 的状态寄存 */
        unsigned int  tz_secure_km_1   : 1;  /* bit[5] : KM 的状态寄存 */
        unsigned int  tz_secure_km_2   : 1;  /* bit[6] : KM 的状态寄存 */
        unsigned int  tz_secure_km_3   : 1;  /* bit[7] : KM 的状态寄存 */
        unsigned int  tz_secure_sce_0  : 1;  /* bit[8] : SCE 的状态寄存 */
        unsigned int  tz_secure_sce_1  : 1;  /* bit[9] : SCE 的状态寄存 */
        unsigned int  tz_secure_sce_2  : 1;  /* bit[10]: SCE 的状态寄存 */
        unsigned int  tz_secure_sce_3  : 1;  /* bit[11]: SCE 的状态寄存 */
        unsigned int  tz_secure_pke_0  : 1;  /* bit[12]: PKE 的状态寄存 */
        unsigned int  tz_secure_pke_1  : 1;  /* bit[13]: PKE 的状态寄存 */
        unsigned int  tz_secure_pke_2  : 1;  /* bit[14]: PKE 的状态寄存 */
        unsigned int  tz_secure_pke_3  : 1;  /* bit[15]: PKE 的状态寄存 */
        unsigned int  reserved_4       : 1;  /* bit[16]: 保留。HIEPS未使用。 */
        unsigned int  reserved_5       : 1;  /* bit[17]: 保留。HIEPS未使用。 */
        unsigned int  reserved_6       : 1;  /* bit[18]: 保留。HIEPS未使用。 */
        unsigned int  reserved_7       : 1;  /* bit[19]: 保留。HIEPS未使用。 */
        unsigned int  tz_secure_sce2_0 : 1;  /* bit[20]: SCE2 的状态寄存 */
        unsigned int  tz_secure_sce2_1 : 1;  /* bit[21]: SCE2 的状态寄存 */
        unsigned int  tz_secure_sce2_2 : 1;  /* bit[22]: SCE2 的状态寄存 */
        unsigned int  tz_secure_sce2_3 : 1;  /* bit[23]: SCE2 的状态寄存 */
        unsigned int  tz_secure_pke2_0 : 1;  /* bit[24]: PKE2 的状态寄存 */
        unsigned int  tz_secure_pke2_1 : 1;  /* bit[25]: PKE2 的状态寄存 */
        unsigned int  tz_secure_pke2_2 : 1;  /* bit[26]: PKE2 的状态寄存 */
        unsigned int  tz_secure_pke2_3 : 1;  /* bit[27]: PKE2 的状态寄存 */
        unsigned int  reserved_8       : 1;  /* bit[28]: 保留。HIEPS未使用。 */
        unsigned int  reserved_9       : 1;  /* bit[29]: 保留。HIEPS未使用。 */
        unsigned int  reserved_10      : 1;  /* bit[30]: 保留。HIEPS未使用。 */
        unsigned int  reserved_11      : 1;  /* bit[31]: 保留。HiEPS未使用。 */
    } reg;
} SOC_ETZPC_DECPROT0STAT_UNION;
#endif
#define SOC_ETZPC_DECPROT0STAT_tz_secure_km_0_START    (4)
#define SOC_ETZPC_DECPROT0STAT_tz_secure_km_0_END      (4)
#define SOC_ETZPC_DECPROT0STAT_tz_secure_km_1_START    (5)
#define SOC_ETZPC_DECPROT0STAT_tz_secure_km_1_END      (5)
#define SOC_ETZPC_DECPROT0STAT_tz_secure_km_2_START    (6)
#define SOC_ETZPC_DECPROT0STAT_tz_secure_km_2_END      (6)
#define SOC_ETZPC_DECPROT0STAT_tz_secure_km_3_START    (7)
#define SOC_ETZPC_DECPROT0STAT_tz_secure_km_3_END      (7)
#define SOC_ETZPC_DECPROT0STAT_tz_secure_sce_0_START   (8)
#define SOC_ETZPC_DECPROT0STAT_tz_secure_sce_0_END     (8)
#define SOC_ETZPC_DECPROT0STAT_tz_secure_sce_1_START   (9)
#define SOC_ETZPC_DECPROT0STAT_tz_secure_sce_1_END     (9)
#define SOC_ETZPC_DECPROT0STAT_tz_secure_sce_2_START   (10)
#define SOC_ETZPC_DECPROT0STAT_tz_secure_sce_2_END     (10)
#define SOC_ETZPC_DECPROT0STAT_tz_secure_sce_3_START   (11)
#define SOC_ETZPC_DECPROT0STAT_tz_secure_sce_3_END     (11)
#define SOC_ETZPC_DECPROT0STAT_tz_secure_pke_0_START   (12)
#define SOC_ETZPC_DECPROT0STAT_tz_secure_pke_0_END     (12)
#define SOC_ETZPC_DECPROT0STAT_tz_secure_pke_1_START   (13)
#define SOC_ETZPC_DECPROT0STAT_tz_secure_pke_1_END     (13)
#define SOC_ETZPC_DECPROT0STAT_tz_secure_pke_2_START   (14)
#define SOC_ETZPC_DECPROT0STAT_tz_secure_pke_2_END     (14)
#define SOC_ETZPC_DECPROT0STAT_tz_secure_pke_3_START   (15)
#define SOC_ETZPC_DECPROT0STAT_tz_secure_pke_3_END     (15)
#define SOC_ETZPC_DECPROT0STAT_tz_secure_sce2_0_START  (20)
#define SOC_ETZPC_DECPROT0STAT_tz_secure_sce2_0_END    (20)
#define SOC_ETZPC_DECPROT0STAT_tz_secure_sce2_1_START  (21)
#define SOC_ETZPC_DECPROT0STAT_tz_secure_sce2_1_END    (21)
#define SOC_ETZPC_DECPROT0STAT_tz_secure_sce2_2_START  (22)
#define SOC_ETZPC_DECPROT0STAT_tz_secure_sce2_2_END    (22)
#define SOC_ETZPC_DECPROT0STAT_tz_secure_sce2_3_START  (23)
#define SOC_ETZPC_DECPROT0STAT_tz_secure_sce2_3_END    (23)
#define SOC_ETZPC_DECPROT0STAT_tz_secure_pke2_0_START  (24)
#define SOC_ETZPC_DECPROT0STAT_tz_secure_pke2_0_END    (24)
#define SOC_ETZPC_DECPROT0STAT_tz_secure_pke2_1_START  (25)
#define SOC_ETZPC_DECPROT0STAT_tz_secure_pke2_1_END    (25)
#define SOC_ETZPC_DECPROT0STAT_tz_secure_pke2_2_START  (26)
#define SOC_ETZPC_DECPROT0STAT_tz_secure_pke2_2_END    (26)
#define SOC_ETZPC_DECPROT0STAT_tz_secure_pke2_3_START  (27)
#define SOC_ETZPC_DECPROT0STAT_tz_secure_pke2_3_END    (27)


/*****************************************************************************
 结构名    : SOC_ETZPC_DECPROT0SET_UNION
 结构说明  : DECPROT0SET 寄存器结构定义。地址偏移量:0x804，初值:0x00000000，宽度:32
 寄存器说明: IP安全属性置位寄存器0。
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved_0 : 1;  /* bit[0] : 保留。HIEPS未使用。 */
        unsigned int  reserved_1 : 1;  /* bit[1] : 保留。HIEPS未使用。 */
        unsigned int  reserved_2 : 1;  /* bit[2] : 保留。HIEPS未使用。 */
        unsigned int  reserved_3 : 1;  /* bit[3] : 保留。HIEPS未使用。 */
        unsigned int  km_set_0   : 1;  /* bit[4] : KM 的安全置位寄存器 */
        unsigned int  km_set_1   : 1;  /* bit[5] : KM 的安全置位寄存器 */
        unsigned int  km_set_2   : 1;  /* bit[6] : KM 的安全置位寄存器 */
        unsigned int  km_set_3   : 1;  /* bit[7] : KM 的安全置位寄存器 */
        unsigned int  sce_set_0  : 1;  /* bit[8] : SCE 的安全置位寄存器 */
        unsigned int  sce_set_1  : 1;  /* bit[9] : SCE 的安全置位寄存器 */
        unsigned int  sce_set_2  : 1;  /* bit[10]: SCE 的安全置位寄存器 */
        unsigned int  sce_set_3  : 1;  /* bit[11]: SCE 的安全置位寄存器 */
        unsigned int  pke_set_0  : 1;  /* bit[12]: PKE 的安全置位寄存器 */
        unsigned int  pke_set_1  : 1;  /* bit[13]: PKE 的安全置位寄存器 */
        unsigned int  pke_set_2  : 1;  /* bit[14]: PKE 的安全置位寄存器 */
        unsigned int  pke_set_3  : 1;  /* bit[15]: PKE 的安全置位寄存器 */
        unsigned int  reserved_4 : 1;  /* bit[16]: 保留。HIEPS未使用。 */
        unsigned int  reserved_5 : 1;  /* bit[17]: 保留。HIEPS未使用。 */
        unsigned int  reserved_6 : 1;  /* bit[18]: 保留。HIEPS未使用。 */
        unsigned int  reserved_7 : 1;  /* bit[19]: 保留。HIEPS未使用。 */
        unsigned int  sce2_set_0 : 1;  /* bit[20]: SCE2 的安全置位寄存器 */
        unsigned int  sce2_set_1 : 1;  /* bit[21]: SCE2 的安全置位寄存器 */
        unsigned int  sce2_set_2 : 1;  /* bit[22]: SCE2 的安全置位寄存器 */
        unsigned int  sce2_set_3 : 1;  /* bit[23]: SCE2 的安全置位寄存器 */
        unsigned int  pke2_set_0 : 1;  /* bit[24]: PKE2 的安全置位寄存器 */
        unsigned int  pke2_set_1 : 1;  /* bit[25]: PKE2 的安全置位寄存器 */
        unsigned int  pke2_set_2 : 1;  /* bit[26]: PKE2 的安全置位寄存器 */
        unsigned int  pke2_set_3 : 1;  /* bit[27]: PKE2 的安全置位寄存器 */
        unsigned int  reserved_8 : 1;  /* bit[28]: 保留。HIEPS未使用。 */
        unsigned int  reserved_9 : 1;  /* bit[29]: 保留。HIEPS未使用。 */
        unsigned int  reserved_10: 1;  /* bit[30]: 保留。HIEPS未使用。 */
        unsigned int  reserved_11: 1;  /* bit[31]: 保留。HIEPS未使用。 */
    } reg;
} SOC_ETZPC_DECPROT0SET_UNION;
#endif
#define SOC_ETZPC_DECPROT0SET_km_set_0_START    (4)
#define SOC_ETZPC_DECPROT0SET_km_set_0_END      (4)
#define SOC_ETZPC_DECPROT0SET_km_set_1_START    (5)
#define SOC_ETZPC_DECPROT0SET_km_set_1_END      (5)
#define SOC_ETZPC_DECPROT0SET_km_set_2_START    (6)
#define SOC_ETZPC_DECPROT0SET_km_set_2_END      (6)
#define SOC_ETZPC_DECPROT0SET_km_set_3_START    (7)
#define SOC_ETZPC_DECPROT0SET_km_set_3_END      (7)
#define SOC_ETZPC_DECPROT0SET_sce_set_0_START   (8)
#define SOC_ETZPC_DECPROT0SET_sce_set_0_END     (8)
#define SOC_ETZPC_DECPROT0SET_sce_set_1_START   (9)
#define SOC_ETZPC_DECPROT0SET_sce_set_1_END     (9)
#define SOC_ETZPC_DECPROT0SET_sce_set_2_START   (10)
#define SOC_ETZPC_DECPROT0SET_sce_set_2_END     (10)
#define SOC_ETZPC_DECPROT0SET_sce_set_3_START   (11)
#define SOC_ETZPC_DECPROT0SET_sce_set_3_END     (11)
#define SOC_ETZPC_DECPROT0SET_pke_set_0_START   (12)
#define SOC_ETZPC_DECPROT0SET_pke_set_0_END     (12)
#define SOC_ETZPC_DECPROT0SET_pke_set_1_START   (13)
#define SOC_ETZPC_DECPROT0SET_pke_set_1_END     (13)
#define SOC_ETZPC_DECPROT0SET_pke_set_2_START   (14)
#define SOC_ETZPC_DECPROT0SET_pke_set_2_END     (14)
#define SOC_ETZPC_DECPROT0SET_pke_set_3_START   (15)
#define SOC_ETZPC_DECPROT0SET_pke_set_3_END     (15)
#define SOC_ETZPC_DECPROT0SET_sce2_set_0_START  (20)
#define SOC_ETZPC_DECPROT0SET_sce2_set_0_END    (20)
#define SOC_ETZPC_DECPROT0SET_sce2_set_1_START  (21)
#define SOC_ETZPC_DECPROT0SET_sce2_set_1_END    (21)
#define SOC_ETZPC_DECPROT0SET_sce2_set_2_START  (22)
#define SOC_ETZPC_DECPROT0SET_sce2_set_2_END    (22)
#define SOC_ETZPC_DECPROT0SET_sce2_set_3_START  (23)
#define SOC_ETZPC_DECPROT0SET_sce2_set_3_END    (23)
#define SOC_ETZPC_DECPROT0SET_pke2_set_0_START  (24)
#define SOC_ETZPC_DECPROT0SET_pke2_set_0_END    (24)
#define SOC_ETZPC_DECPROT0SET_pke2_set_1_START  (25)
#define SOC_ETZPC_DECPROT0SET_pke2_set_1_END    (25)
#define SOC_ETZPC_DECPROT0SET_pke2_set_2_START  (26)
#define SOC_ETZPC_DECPROT0SET_pke2_set_2_END    (26)
#define SOC_ETZPC_DECPROT0SET_pke2_set_3_START  (27)
#define SOC_ETZPC_DECPROT0SET_pke2_set_3_END    (27)


/*****************************************************************************
 结构名    : SOC_ETZPC_DECPROT0CLR_UNION
 结构说明  : DECPROT0CLR 寄存器结构定义。地址偏移量:0x808，初值:0x00000000，宽度:32
 寄存器说明: IP安全属性清零寄存器0。
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved_0 : 1;  /* bit[0] : 保留。HIEPS未使用。 */
        unsigned int  reserved_1 : 1;  /* bit[1] : 保留。HIEPS未使用。 */
        unsigned int  reserved_2 : 1;  /* bit[2] : 保留。HIEPS未使用。 */
        unsigned int  reserved_3 : 1;  /* bit[3] : 保留。HIEPS未使用。 */
        unsigned int  km_clr_0   : 1;  /* bit[4] : KM 的安全清零寄存器 */
        unsigned int  km_clr_1   : 1;  /* bit[5] : KM 的安全清零寄存器 */
        unsigned int  km_clr_2   : 1;  /* bit[6] : KM 的安全清零寄存器 */
        unsigned int  km_clr_3   : 1;  /* bit[7] : KM 的安全清零寄存器 */
        unsigned int  sce_clr_0  : 1;  /* bit[8] : SCE 的安全清零寄存器 */
        unsigned int  sce_clr_1  : 1;  /* bit[9] : SCE 的安全清零寄存器 */
        unsigned int  sce_clr_2  : 1;  /* bit[10]: SCE 的安全清零寄存器 */
        unsigned int  sce_clr_3  : 1;  /* bit[11]: SCE 的安全清零寄存器 */
        unsigned int  pke_clr_0  : 1;  /* bit[12]: PKE 的安全清零寄存器 */
        unsigned int  pke_clr_1  : 1;  /* bit[13]: PKE 的安全清零寄存器 */
        unsigned int  pke_clr_2  : 1;  /* bit[14]: PKE 的安全清零寄存器 */
        unsigned int  pke_clr_3  : 1;  /* bit[15]: PKE 的安全清零寄存器 */
        unsigned int  reserved_4 : 1;  /* bit[16]: 保留。HIEPS未使用。 */
        unsigned int  reserved_5 : 1;  /* bit[17]: 保留。HIEPS未使用。 */
        unsigned int  reserved_6 : 1;  /* bit[18]: 保留。HIEPS未使用。 */
        unsigned int  reserved_7 : 1;  /* bit[19]: 保留。HIEPS未使用。 */
        unsigned int  sce2_clr_0 : 1;  /* bit[20]: SCE2 的安全清零寄存器 */
        unsigned int  sce2_clr_1 : 1;  /* bit[21]: SCE2 的安全清零寄存器 */
        unsigned int  sce2_clr_2 : 1;  /* bit[22]: SCE2 的安全清零寄存器 */
        unsigned int  sce2_clr_3 : 1;  /* bit[23]: SCE2 的安全清零寄存器 */
        unsigned int  pke2_clr_0 : 1;  /* bit[24]: PKE2 的安全清零寄存器 */
        unsigned int  pke2_clr_1 : 1;  /* bit[25]: PKE2 的安全清零寄存器 */
        unsigned int  pke2_clr_2 : 1;  /* bit[26]: PKE2 的安全清零寄存器 */
        unsigned int  pke2_clr_3 : 1;  /* bit[27]: PKE2 的安全清零寄存器 */
        unsigned int  reserved_8 : 1;  /* bit[28]: 保留。HIEPS未使用。 */
        unsigned int  reserved_9 : 1;  /* bit[29]: 保留。HIEPS未使用。 */
        unsigned int  reserved_10: 1;  /* bit[30]: 保留。HIEPS未使用。 */
        unsigned int  reserved_11: 1;  /* bit[31]: 保留。HIEPS未使用。 */
    } reg;
} SOC_ETZPC_DECPROT0CLR_UNION;
#endif
#define SOC_ETZPC_DECPROT0CLR_km_clr_0_START    (4)
#define SOC_ETZPC_DECPROT0CLR_km_clr_0_END      (4)
#define SOC_ETZPC_DECPROT0CLR_km_clr_1_START    (5)
#define SOC_ETZPC_DECPROT0CLR_km_clr_1_END      (5)
#define SOC_ETZPC_DECPROT0CLR_km_clr_2_START    (6)
#define SOC_ETZPC_DECPROT0CLR_km_clr_2_END      (6)
#define SOC_ETZPC_DECPROT0CLR_km_clr_3_START    (7)
#define SOC_ETZPC_DECPROT0CLR_km_clr_3_END      (7)
#define SOC_ETZPC_DECPROT0CLR_sce_clr_0_START   (8)
#define SOC_ETZPC_DECPROT0CLR_sce_clr_0_END     (8)
#define SOC_ETZPC_DECPROT0CLR_sce_clr_1_START   (9)
#define SOC_ETZPC_DECPROT0CLR_sce_clr_1_END     (9)
#define SOC_ETZPC_DECPROT0CLR_sce_clr_2_START   (10)
#define SOC_ETZPC_DECPROT0CLR_sce_clr_2_END     (10)
#define SOC_ETZPC_DECPROT0CLR_sce_clr_3_START   (11)
#define SOC_ETZPC_DECPROT0CLR_sce_clr_3_END     (11)
#define SOC_ETZPC_DECPROT0CLR_pke_clr_0_START   (12)
#define SOC_ETZPC_DECPROT0CLR_pke_clr_0_END     (12)
#define SOC_ETZPC_DECPROT0CLR_pke_clr_1_START   (13)
#define SOC_ETZPC_DECPROT0CLR_pke_clr_1_END     (13)
#define SOC_ETZPC_DECPROT0CLR_pke_clr_2_START   (14)
#define SOC_ETZPC_DECPROT0CLR_pke_clr_2_END     (14)
#define SOC_ETZPC_DECPROT0CLR_pke_clr_3_START   (15)
#define SOC_ETZPC_DECPROT0CLR_pke_clr_3_END     (15)
#define SOC_ETZPC_DECPROT0CLR_sce2_clr_0_START  (20)
#define SOC_ETZPC_DECPROT0CLR_sce2_clr_0_END    (20)
#define SOC_ETZPC_DECPROT0CLR_sce2_clr_1_START  (21)
#define SOC_ETZPC_DECPROT0CLR_sce2_clr_1_END    (21)
#define SOC_ETZPC_DECPROT0CLR_sce2_clr_2_START  (22)
#define SOC_ETZPC_DECPROT0CLR_sce2_clr_2_END    (22)
#define SOC_ETZPC_DECPROT0CLR_sce2_clr_3_START  (23)
#define SOC_ETZPC_DECPROT0CLR_sce2_clr_3_END    (23)
#define SOC_ETZPC_DECPROT0CLR_pke2_clr_0_START  (24)
#define SOC_ETZPC_DECPROT0CLR_pke2_clr_0_END    (24)
#define SOC_ETZPC_DECPROT0CLR_pke2_clr_1_START  (25)
#define SOC_ETZPC_DECPROT0CLR_pke2_clr_1_END    (25)
#define SOC_ETZPC_DECPROT0CLR_pke2_clr_2_START  (26)
#define SOC_ETZPC_DECPROT0CLR_pke2_clr_2_END    (26)
#define SOC_ETZPC_DECPROT0CLR_pke2_clr_3_START  (27)
#define SOC_ETZPC_DECPROT0CLR_pke2_clr_3_END    (27)


/*****************************************************************************
 结构名    : SOC_ETZPC_DECPROT1STAT_UNION
 结构说明  : DECPROT1STAT 寄存器结构定义。地址偏移量:0x80C，初值:0x00000000，宽度:32
 寄存器说明: IP安全属性状态寄存器1。
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  config_state_0  : 1;  /* bit[0] : CONFIG的安全状态寄存器 */
        unsigned int  config_state_1  : 1;  /* bit[1] : CONFIG的安全状态寄存器 */
        unsigned int  config_state_2  : 1;  /* bit[2] : CONFIG的安全状态寄存器 */
        unsigned int  config_state_3  : 1;  /* bit[3] : CONFIG的安全状态寄存器 */
        unsigned int  reserved_0      : 1;  /* bit[4] : 保留。HIEPS未使用。 */
        unsigned int  reserved_1      : 1;  /* bit[5] : 保留。HIEPS未使用。 */
        unsigned int  reserved_2      : 1;  /* bit[6] : 保留。HIEPS未使用。 */
        unsigned int  reserved_3      : 1;  /* bit[7] : 保留。HIEPS未使用。 */
        unsigned int  trng_state_0    : 1;  /* bit[8] : TRNG的安全状态寄存器 */
        unsigned int  trng_state_1    : 1;  /* bit[9] : TRNG的安全状态寄存器 */
        unsigned int  trng_state_2    : 1;  /* bit[10]: TRNG的安全状态寄存器 */
        unsigned int  trng_state_3    : 1;  /* bit[11]: TRNG的安全状态寄存器 */
        unsigned int  timer_state_0   : 1;  /* bit[12]: TIMER的安全状态寄存器 */
        unsigned int  timer_state_1   : 1;  /* bit[13]: TIMER的安全状态寄存器 */
        unsigned int  timer_state_2   : 1;  /* bit[14]: TIMER的安全状态寄存器 */
        unsigned int  timer_state_3   : 1;  /* bit[15]: TIMER的安全状态寄存器 */
        unsigned int  tz_secure_mmu_0 : 1;  /* bit[16]: MMU 的状态寄存 */
        unsigned int  tz_secure_mmu_1 : 1;  /* bit[17]: MMU 的状态寄存 */
        unsigned int  tz_secure_mmu_2 : 1;  /* bit[18]: MMU 的状态寄存 */
        unsigned int  tz_secure_mmu_3 : 1;  /* bit[19]: MMU 的状态寄存 */
        unsigned int  reserved_4      : 1;  /* bit[20]: 保留。HIEPS未使用。 */
        unsigned int  reserved_5      : 1;  /* bit[21]: 保留。HIEPS未使用。 */
        unsigned int  reserved_6      : 1;  /* bit[22]: 保留。HIEPS未使用。 */
        unsigned int  reserved_7      : 1;  /* bit[23]: 保留。HIEPS未使用。 */
        unsigned int  reserved_8      : 1;  /* bit[24]: 保留。HIEPS未使用。 */
        unsigned int  reserved_9      : 1;  /* bit[25]: 保留。HIEPS未使用。 */
        unsigned int  reserved_10     : 1;  /* bit[26]: 保留。HIEPS未使用。 */
        unsigned int  reserved_11     : 1;  /* bit[27]: 保留。HIEPS未使用。 */
        unsigned int  reserved_12     : 1;  /* bit[28]: 保留。HIEPS未使用。 */
        unsigned int  reserved_13     : 1;  /* bit[29]: 保留。HIEPS未使用。 */
        unsigned int  reserved_14     : 1;  /* bit[30]: 保留。HIEPS未使用。 */
        unsigned int  reserved_15     : 1;  /* bit[31]: 保留。HIEPS未使用 */
    } reg;
} SOC_ETZPC_DECPROT1STAT_UNION;
#endif
#define SOC_ETZPC_DECPROT1STAT_config_state_0_START   (0)
#define SOC_ETZPC_DECPROT1STAT_config_state_0_END     (0)
#define SOC_ETZPC_DECPROT1STAT_config_state_1_START   (1)
#define SOC_ETZPC_DECPROT1STAT_config_state_1_END     (1)
#define SOC_ETZPC_DECPROT1STAT_config_state_2_START   (2)
#define SOC_ETZPC_DECPROT1STAT_config_state_2_END     (2)
#define SOC_ETZPC_DECPROT1STAT_config_state_3_START   (3)
#define SOC_ETZPC_DECPROT1STAT_config_state_3_END     (3)
#define SOC_ETZPC_DECPROT1STAT_trng_state_0_START     (8)
#define SOC_ETZPC_DECPROT1STAT_trng_state_0_END       (8)
#define SOC_ETZPC_DECPROT1STAT_trng_state_1_START     (9)
#define SOC_ETZPC_DECPROT1STAT_trng_state_1_END       (9)
#define SOC_ETZPC_DECPROT1STAT_trng_state_2_START     (10)
#define SOC_ETZPC_DECPROT1STAT_trng_state_2_END       (10)
#define SOC_ETZPC_DECPROT1STAT_trng_state_3_START     (11)
#define SOC_ETZPC_DECPROT1STAT_trng_state_3_END       (11)
#define SOC_ETZPC_DECPROT1STAT_timer_state_0_START    (12)
#define SOC_ETZPC_DECPROT1STAT_timer_state_0_END      (12)
#define SOC_ETZPC_DECPROT1STAT_timer_state_1_START    (13)
#define SOC_ETZPC_DECPROT1STAT_timer_state_1_END      (13)
#define SOC_ETZPC_DECPROT1STAT_timer_state_2_START    (14)
#define SOC_ETZPC_DECPROT1STAT_timer_state_2_END      (14)
#define SOC_ETZPC_DECPROT1STAT_timer_state_3_START    (15)
#define SOC_ETZPC_DECPROT1STAT_timer_state_3_END      (15)
#define SOC_ETZPC_DECPROT1STAT_tz_secure_mmu_0_START  (16)
#define SOC_ETZPC_DECPROT1STAT_tz_secure_mmu_0_END    (16)
#define SOC_ETZPC_DECPROT1STAT_tz_secure_mmu_1_START  (17)
#define SOC_ETZPC_DECPROT1STAT_tz_secure_mmu_1_END    (17)
#define SOC_ETZPC_DECPROT1STAT_tz_secure_mmu_2_START  (18)
#define SOC_ETZPC_DECPROT1STAT_tz_secure_mmu_2_END    (18)
#define SOC_ETZPC_DECPROT1STAT_tz_secure_mmu_3_START  (19)
#define SOC_ETZPC_DECPROT1STAT_tz_secure_mmu_3_END    (19)


/*****************************************************************************
 结构名    : SOC_ETZPC_DECPROT1SET_UNION
 结构说明  : DECPROT1SET 寄存器结构定义。地址偏移量:0x810，初值:0x00000000，宽度:32
 寄存器说明: IP安全属性置位寄存器1。
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  config_set_0 : 1;  /* bit[0] : CONFIG的安全属性置位寄存器 */
        unsigned int  config_set_1 : 1;  /* bit[1] : CONFIG的安全属性置位寄存器 */
        unsigned int  config_set_2 : 1;  /* bit[2] : CONFIG的安全属性置位寄存器 */
        unsigned int  config_set_3 : 1;  /* bit[3] : CONFIG的安全属性置位寄存器 */
        unsigned int  reserved_0   : 1;  /* bit[4] : 保留。HIEPS未使用。 */
        unsigned int  reserved_1   : 1;  /* bit[5] : 保留。HIEPS未使用。 */
        unsigned int  reserved_2   : 1;  /* bit[6] : 保留。HIEPS未使用。 */
        unsigned int  reserved_3   : 1;  /* bit[7] : 保留。HIEPS未使用。 */
        unsigned int  trng_set_0   : 1;  /* bit[8] : TRNG的安全属性置位寄存器 */
        unsigned int  trng_set_1   : 1;  /* bit[9] : TRNG的安全属性置位寄存器 */
        unsigned int  trng_set_2   : 1;  /* bit[10]: TRNG的安全属性置位寄存器 */
        unsigned int  trng_set_3   : 1;  /* bit[11]: TRNG的安全属性置位寄存器 */
        unsigned int  timer_set_0  : 1;  /* bit[12]: TIMER的安全属性置位寄存器 */
        unsigned int  timer_set_1  : 1;  /* bit[13]: TIMER的安全属性置位寄存器 */
        unsigned int  timer_set_2  : 1;  /* bit[14]: TIMER的安全属性置位寄存器 */
        unsigned int  timer_set_3  : 1;  /* bit[15]: TIMER的安全属性置位寄存器 */
        unsigned int  mmu_set_0    : 1;  /* bit[16]: MMU 的安全属性置位寄存器 */
        unsigned int  mmu_set_1    : 1;  /* bit[17]: MMU 的安全属性置位寄存器 */
        unsigned int  mmu_set_2    : 1;  /* bit[18]: MMU 的安全属性置位寄存器 */
        unsigned int  mmu_set_3    : 1;  /* bit[19]: MMU 的安全属性置位寄存器 */
        unsigned int  reserved_4   : 1;  /* bit[20]: 保留。HIEPS未使用。 */
        unsigned int  reserved_5   : 1;  /* bit[21]: 保留。HIEPS未使用。 */
        unsigned int  reserved_6   : 1;  /* bit[22]: 保留。HIEPS未使用。 */
        unsigned int  reserved_7   : 1;  /* bit[23]: 保留。HIEPS未使用。 */
        unsigned int  reserved_8   : 1;  /* bit[24]: 保留。HIEPS未使用。 */
        unsigned int  reserved_9   : 1;  /* bit[25]: 保留。HIEPS未使用。 */
        unsigned int  reserved_10  : 1;  /* bit[26]: 保留。HIEPS未使用。 */
        unsigned int  reserved_11  : 1;  /* bit[27]: 保留。HIEPS未使用。 */
        unsigned int  reserved_12  : 1;  /* bit[28]: 保留。HIEPS未使用。 */
        unsigned int  reserved_13  : 1;  /* bit[29]: 保留。HIEPS未使用。 */
        unsigned int  reserved_14  : 1;  /* bit[30]: 保留。HIEPS未使用。 */
        unsigned int  reserved_15  : 1;  /* bit[31]: 保留。HIEPS未使用。 */
    } reg;
} SOC_ETZPC_DECPROT1SET_UNION;
#endif
#define SOC_ETZPC_DECPROT1SET_config_set_0_START  (0)
#define SOC_ETZPC_DECPROT1SET_config_set_0_END    (0)
#define SOC_ETZPC_DECPROT1SET_config_set_1_START  (1)
#define SOC_ETZPC_DECPROT1SET_config_set_1_END    (1)
#define SOC_ETZPC_DECPROT1SET_config_set_2_START  (2)
#define SOC_ETZPC_DECPROT1SET_config_set_2_END    (2)
#define SOC_ETZPC_DECPROT1SET_config_set_3_START  (3)
#define SOC_ETZPC_DECPROT1SET_config_set_3_END    (3)
#define SOC_ETZPC_DECPROT1SET_trng_set_0_START    (8)
#define SOC_ETZPC_DECPROT1SET_trng_set_0_END      (8)
#define SOC_ETZPC_DECPROT1SET_trng_set_1_START    (9)
#define SOC_ETZPC_DECPROT1SET_trng_set_1_END      (9)
#define SOC_ETZPC_DECPROT1SET_trng_set_2_START    (10)
#define SOC_ETZPC_DECPROT1SET_trng_set_2_END      (10)
#define SOC_ETZPC_DECPROT1SET_trng_set_3_START    (11)
#define SOC_ETZPC_DECPROT1SET_trng_set_3_END      (11)
#define SOC_ETZPC_DECPROT1SET_timer_set_0_START   (12)
#define SOC_ETZPC_DECPROT1SET_timer_set_0_END     (12)
#define SOC_ETZPC_DECPROT1SET_timer_set_1_START   (13)
#define SOC_ETZPC_DECPROT1SET_timer_set_1_END     (13)
#define SOC_ETZPC_DECPROT1SET_timer_set_2_START   (14)
#define SOC_ETZPC_DECPROT1SET_timer_set_2_END     (14)
#define SOC_ETZPC_DECPROT1SET_timer_set_3_START   (15)
#define SOC_ETZPC_DECPROT1SET_timer_set_3_END     (15)
#define SOC_ETZPC_DECPROT1SET_mmu_set_0_START     (16)
#define SOC_ETZPC_DECPROT1SET_mmu_set_0_END       (16)
#define SOC_ETZPC_DECPROT1SET_mmu_set_1_START     (17)
#define SOC_ETZPC_DECPROT1SET_mmu_set_1_END       (17)
#define SOC_ETZPC_DECPROT1SET_mmu_set_2_START     (18)
#define SOC_ETZPC_DECPROT1SET_mmu_set_2_END       (18)
#define SOC_ETZPC_DECPROT1SET_mmu_set_3_START     (19)
#define SOC_ETZPC_DECPROT1SET_mmu_set_3_END       (19)


/*****************************************************************************
 结构名    : SOC_ETZPC_DECPROT1CLR_UNION
 结构说明  : DECPROT1CLR 寄存器结构定义。地址偏移量:0x814，初值:0x00000000，宽度:32
 寄存器说明: IP安全属性清零寄存器1。
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  config_clr_0 : 1;  /* bit[0] : CONFIG的安全属性清零寄存器 */
        unsigned int  config_clr_1 : 1;  /* bit[1] : CONFIG的安全属性清零寄存器 */
        unsigned int  config_clr_2 : 1;  /* bit[2] : CONFIG的安全属性清零寄存器 */
        unsigned int  config_clr_3 : 1;  /* bit[3] : CONFIG的安全属性清零寄存器 */
        unsigned int  reserved_0   : 1;  /* bit[4] : 保留。HIEPS未使用。 */
        unsigned int  reserved_1   : 1;  /* bit[5] : 保留。HIEPS未使用。 */
        unsigned int  reserved_2   : 1;  /* bit[6] : 保留。HIEPS未使用。 */
        unsigned int  reserved_3   : 1;  /* bit[7] : 保留。HIEPS未使用。 */
        unsigned int  trng_clr_0   : 1;  /* bit[8] : TRNG的安全属性清零寄存器 */
        unsigned int  trng_clr_1   : 1;  /* bit[9] : TRNG的安全属性清零寄存器 */
        unsigned int  trng_clr_2   : 1;  /* bit[10]: TRNG的安全属性清零寄存器 */
        unsigned int  trng_clr_3   : 1;  /* bit[11]: TRNG的安全属性清零寄存器 */
        unsigned int  timer_clr_0  : 1;  /* bit[12]: TIMER的安全属性清零寄存器 */
        unsigned int  timer_clr_1  : 1;  /* bit[13]: TIMER的安全属性清零寄存器 */
        unsigned int  timer_clr_2  : 1;  /* bit[14]: TIMER的安全属性清零寄存器 */
        unsigned int  timer_clr_3  : 1;  /* bit[15]: TIMER的安全属性清零寄存器 */
        unsigned int  mmu_clr_0    : 1;  /* bit[16]: MMU 的安全清零寄存器 */
        unsigned int  mmu_clr_1    : 1;  /* bit[17]: MMU 的安全清零寄存器 */
        unsigned int  mmu_clr_2    : 1;  /* bit[18]: MMU 的安全清零寄存器 */
        unsigned int  mmu_clr_3    : 1;  /* bit[19]: MMU 的安全清零寄存器 */
        unsigned int  reserved_4   : 1;  /* bit[20]: 保留。HIEPS未使用。 */
        unsigned int  reserved_5   : 1;  /* bit[21]: 保留。HIEPS未使用。 */
        unsigned int  reserved_6   : 1;  /* bit[22]: 保留。HIEPS未使用。 */
        unsigned int  reserved_7   : 1;  /* bit[23]: 保留。HIEPS未使用。 */
        unsigned int  reserved_8   : 1;  /* bit[24]: 保留。HIEPS未使用。 */
        unsigned int  reserved_9   : 1;  /* bit[25]: 保留。HIEPS未使用。 */
        unsigned int  reserved_10  : 1;  /* bit[26]: 保留。HIEPS未使用。 */
        unsigned int  reserved_11  : 1;  /* bit[27]: 保留。HIEPS未使用。 */
        unsigned int  reserved_12  : 1;  /* bit[28]: 保留。HIEPS未使用。 */
        unsigned int  reserved_13  : 1;  /* bit[29]: 保留。HIEPS未使用。 */
        unsigned int  reserved_14  : 1;  /* bit[30]: 保留。HIEPS未使用。 */
        unsigned int  reserved_15  : 1;  /* bit[31]: 保留。HIEPS未使用。 */
    } reg;
} SOC_ETZPC_DECPROT1CLR_UNION;
#endif
#define SOC_ETZPC_DECPROT1CLR_config_clr_0_START  (0)
#define SOC_ETZPC_DECPROT1CLR_config_clr_0_END    (0)
#define SOC_ETZPC_DECPROT1CLR_config_clr_1_START  (1)
#define SOC_ETZPC_DECPROT1CLR_config_clr_1_END    (1)
#define SOC_ETZPC_DECPROT1CLR_config_clr_2_START  (2)
#define SOC_ETZPC_DECPROT1CLR_config_clr_2_END    (2)
#define SOC_ETZPC_DECPROT1CLR_config_clr_3_START  (3)
#define SOC_ETZPC_DECPROT1CLR_config_clr_3_END    (3)
#define SOC_ETZPC_DECPROT1CLR_trng_clr_0_START    (8)
#define SOC_ETZPC_DECPROT1CLR_trng_clr_0_END      (8)
#define SOC_ETZPC_DECPROT1CLR_trng_clr_1_START    (9)
#define SOC_ETZPC_DECPROT1CLR_trng_clr_1_END      (9)
#define SOC_ETZPC_DECPROT1CLR_trng_clr_2_START    (10)
#define SOC_ETZPC_DECPROT1CLR_trng_clr_2_END      (10)
#define SOC_ETZPC_DECPROT1CLR_trng_clr_3_START    (11)
#define SOC_ETZPC_DECPROT1CLR_trng_clr_3_END      (11)
#define SOC_ETZPC_DECPROT1CLR_timer_clr_0_START   (12)
#define SOC_ETZPC_DECPROT1CLR_timer_clr_0_END     (12)
#define SOC_ETZPC_DECPROT1CLR_timer_clr_1_START   (13)
#define SOC_ETZPC_DECPROT1CLR_timer_clr_1_END     (13)
#define SOC_ETZPC_DECPROT1CLR_timer_clr_2_START   (14)
#define SOC_ETZPC_DECPROT1CLR_timer_clr_2_END     (14)
#define SOC_ETZPC_DECPROT1CLR_timer_clr_3_START   (15)
#define SOC_ETZPC_DECPROT1CLR_timer_clr_3_END     (15)
#define SOC_ETZPC_DECPROT1CLR_mmu_clr_0_START     (16)
#define SOC_ETZPC_DECPROT1CLR_mmu_clr_0_END       (16)
#define SOC_ETZPC_DECPROT1CLR_mmu_clr_1_START     (17)
#define SOC_ETZPC_DECPROT1CLR_mmu_clr_1_END       (17)
#define SOC_ETZPC_DECPROT1CLR_mmu_clr_2_START     (18)
#define SOC_ETZPC_DECPROT1CLR_mmu_clr_2_END       (18)
#define SOC_ETZPC_DECPROT1CLR_mmu_clr_3_START     (19)
#define SOC_ETZPC_DECPROT1CLR_mmu_clr_3_END       (19)


/*****************************************************************************
 结构名    : SOC_ETZPC_DECPROT2STAT_UNION
 结构说明  : DECPROT2STAT 寄存器结构定义。地址偏移量:0x818，初值:0x00000000，宽度:32
 寄存器说明: IP安全属性状态寄存器2。
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved_0: 1;  /* bit[0] : 保留。HIEPS未使用。 */
        unsigned int  reserved_1: 1;  /* bit[1] : 保留。HIEPS未使用。 */
        unsigned int  reserved_2: 1;  /* bit[2] : 保留。HIEPS未使用。 */
        unsigned int  reserved_3: 1;  /* bit[3] : 保留。HIEPS未使用。 */
        unsigned int  reserved_4: 1;  /* bit[4] : 保留。HIEPS未使用。 */
        unsigned int  reserved_5: 1;  /* bit[5] : 保留。HIEPS未使用。 */
        unsigned int  reserved_6: 1;  /* bit[6] : 保留。HIEPS未使用。 */
        unsigned int  reserved_7: 1;  /* bit[7] : 保留。HIEPS未使用。 */
        unsigned int  reserved_8: 1;  /* bit[8] : 保留。HIEPS未使用。 */
        unsigned int  reserved_9: 1;  /* bit[9] : 保留。HIEPS未使用。 */
        unsigned int  reserved_10: 1;  /* bit[10]: 保留。HIEPS未使用。 */
        unsigned int  reserved_11: 1;  /* bit[11]: 保留。HIEPS未使用。 */
        unsigned int  reserved_12: 1;  /* bit[12]: 保留。HIEPS未使用。 */
        unsigned int  reserved_13: 1;  /* bit[13]: 保留。HIEPS未使用。 */
        unsigned int  reserved_14: 1;  /* bit[14]: 保留。HIEPS未使用。 */
        unsigned int  reserved_15: 1;  /* bit[15]: 保留。HIEPS未使用。 */
        unsigned int  reserved_16: 1;  /* bit[16]: 保留。HIEPS未使用。 */
        unsigned int  reserved_17: 1;  /* bit[17]: 保留。HIEPS未使用。 */
        unsigned int  reserved_18: 1;  /* bit[18]: 保留。HIEPS未使用。 */
        unsigned int  reserved_19: 1;  /* bit[19]: 保留。HIEPS未使用。 */
        unsigned int  reserved_20: 1;  /* bit[20]: 保留。HIEPS未使用。 */
        unsigned int  reserved_21: 1;  /* bit[21]: 保留。HIEPS未使用。 */
        unsigned int  reserved_22: 1;  /* bit[22]: 保留。HIEPS未使用。 */
        unsigned int  reserved_23: 1;  /* bit[23]: 保留。HIEPS未使用。 */
        unsigned int  reserved_24: 1;  /* bit[24]: 保留。HIEPS未使用。 */
        unsigned int  reserved_25: 1;  /* bit[25]: 保留。HIEPS未使用。 */
        unsigned int  reserved_26: 1;  /* bit[26]: 保留。HIEPS未使用。 */
        unsigned int  reserved_27: 1;  /* bit[27]: 保留。HIEPS未使用。 */
        unsigned int  reserved_28: 1;  /* bit[28]: 保留。HIEPS未使用。 */
        unsigned int  reserved_29: 1;  /* bit[29]: 保留。HIEPS未使用。 */
        unsigned int  reserved_30: 1;  /* bit[30]: 保留。HIEPS未使用。 */
        unsigned int  reserved_31: 1;  /* bit[31]: 保留。HIEPS未使用。 */
    } reg;
} SOC_ETZPC_DECPROT2STAT_UNION;
#endif


/*****************************************************************************
 结构名    : SOC_ETZPC_DECPROT2SET_UNION
 结构说明  : DECPROT2SET 寄存器结构定义。地址偏移量:0x81C，初值:0x00000000，宽度:32
 寄存器说明: IP安全属性置位寄存器2。
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved_0: 1;  /* bit[0] : 保留。HIEPS未使用。 */
        unsigned int  reserved_1: 1;  /* bit[1] : 保留。HIEPS未使用。 */
        unsigned int  reserved_2: 1;  /* bit[2] : 保留。HIEPS未使用。 */
        unsigned int  reserved_3: 1;  /* bit[3] : 保留。HIEPS未使用。 */
        unsigned int  reserved_4: 1;  /* bit[4] : 保留。HIEPS未使用。 */
        unsigned int  reserved_5: 1;  /* bit[5] : 保留。HIEPS未使用。 */
        unsigned int  reserved_6: 1;  /* bit[6] : 保留。HIEPS未使用。 */
        unsigned int  reserved_7: 1;  /* bit[7] : 保留。HIEPS未使用。 */
        unsigned int  reserved_8: 1;  /* bit[8] : 保留。HIEPS未使用。 */
        unsigned int  reserved_9: 1;  /* bit[9] : 保留。HIEPS未使用。 */
        unsigned int  reserved_10: 1;  /* bit[10]: 保留。HIEPS未使用。 */
        unsigned int  reserved_11: 1;  /* bit[11]: 保留。HIEPS未使用。 */
        unsigned int  reserved_12: 1;  /* bit[12]: 保留。HIEPS未使用。 */
        unsigned int  reserved_13: 1;  /* bit[13]: 保留。HIEPS未使用。 */
        unsigned int  reserved_14: 1;  /* bit[14]: 保留。HIEPS未使用。 */
        unsigned int  reserved_15: 1;  /* bit[15]: 保留。HIEPS未使用。 */
        unsigned int  reserved_16: 1;  /* bit[16]: 保留。HIEPS未使用。 */
        unsigned int  reserved_17: 1;  /* bit[17]: 保留。HIEPS未使用。 */
        unsigned int  reserved_18: 1;  /* bit[18]: 保留。HIEPS未使用。 */
        unsigned int  reserved_19: 1;  /* bit[19]: 保留。HIEPS未使用。 */
        unsigned int  reserved_20: 1;  /* bit[20]: 保留。HIEPS未使用。 */
        unsigned int  reserved_21: 1;  /* bit[21]: 保留。HIEPS未使用。 */
        unsigned int  reserved_22: 1;  /* bit[22]: 保留。HIEPS未使用。 */
        unsigned int  reserved_23: 1;  /* bit[23]: 保留。HIEPS未使用。 */
        unsigned int  reserved_24: 1;  /* bit[24]: 保留。HIEPS未使用。 */
        unsigned int  reserved_25: 1;  /* bit[25]: 保留。HIEPS未使用。 */
        unsigned int  reserved_26: 1;  /* bit[26]: 保留。HIEPS未使用。 */
        unsigned int  reserved_27: 1;  /* bit[27]: 保留。HIEPS未使用。 */
        unsigned int  reserved_28: 1;  /* bit[28]: 保留。HIEPS未使用。 */
        unsigned int  reserved_29: 1;  /* bit[29]: 保留。HIEPS未使用。 */
        unsigned int  reserved_30: 1;  /* bit[30]: 保留。HIEPS未使用。 */
        unsigned int  reserved_31: 1;  /* bit[31]: 保留。HIEPS未使用。 */
    } reg;
} SOC_ETZPC_DECPROT2SET_UNION;
#endif


/*****************************************************************************
 结构名    : SOC_ETZPC_DECPROT2CLR_UNION
 结构说明  : DECPROT2CLR 寄存器结构定义。地址偏移量:0x820，初值:0x00000000，宽度:32
 寄存器说明: IP安全属性清零寄存器2。
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved_0: 1;  /* bit[0] : 保留。HIEPS未使用。 */
        unsigned int  reserved_1: 1;  /* bit[1] : 保留。HIEPS未使用。 */
        unsigned int  reserved_2: 1;  /* bit[2] : 保留。HIEPS未使用。 */
        unsigned int  reserved_3: 1;  /* bit[3] : 保留。HIEPS未使用。 */
        unsigned int  reserved_4: 1;  /* bit[4] : 保留。HIEPS未使用。 */
        unsigned int  reserved_5: 1;  /* bit[5] : 保留。HIEPS未使用。 */
        unsigned int  reserved_6: 1;  /* bit[6] : 保留。HIEPS未使用。 */
        unsigned int  reserved_7: 1;  /* bit[7] : 保留。HIEPS未使用。 */
        unsigned int  reserved_8: 1;  /* bit[8] : 保留。HIEPS未使用。 */
        unsigned int  reserved_9: 1;  /* bit[9] : 保留。HIEPS未使用。 */
        unsigned int  reserved_10: 1;  /* bit[10]: 保留。HIEPS未使用。 */
        unsigned int  reserved_11: 1;  /* bit[11]: 保留。HIEPS未使用。 */
        unsigned int  reserved_12: 1;  /* bit[12]: 保留。HIEPS未使用。 */
        unsigned int  reserved_13: 1;  /* bit[13]: 保留。HIEPS未使用。 */
        unsigned int  reserved_14: 1;  /* bit[14]: 保留。HIEPS未使用。 */
        unsigned int  reserved_15: 1;  /* bit[15]: 保留。HIEPS未使用。 */
        unsigned int  reserved_16: 1;  /* bit[16]: 保留。HIEPS未使用。 */
        unsigned int  reserved_17: 1;  /* bit[17]: 保留。HIEPS未使用。 */
        unsigned int  reserved_18: 1;  /* bit[18]: 保留。HIEPS未使用。 */
        unsigned int  reserved_19: 1;  /* bit[19]: 保留。HIEPS未使用。 */
        unsigned int  reserved_20: 1;  /* bit[20]: 保留。HIEPS未使用。 */
        unsigned int  reserved_21: 1;  /* bit[21]: 保留。HIEPS未使用。 */
        unsigned int  reserved_22: 1;  /* bit[22]: 保留。HIEPS未使用。 */
        unsigned int  reserved_23: 1;  /* bit[23]: 保留。HIEPS未使用。 */
        unsigned int  reserved_24: 1;  /* bit[24]: 保留。HIEPS未使用。 */
        unsigned int  reserved_25: 1;  /* bit[25]: 保留。HIEPS未使用。 */
        unsigned int  reserved_26: 1;  /* bit[26]: 保留。HIEPS未使用。 */
        unsigned int  reserved_27: 1;  /* bit[27]: 保留。HIEPS未使用。 */
        unsigned int  reserved_28: 1;  /* bit[28]: 保留。HIEPS未使用。 */
        unsigned int  reserved_29: 1;  /* bit[29]: 保留。HIEPS未使用。 */
        unsigned int  reserved_30: 1;  /* bit[30]: 保留。HIEPS未使用。 */
        unsigned int  reserved_31: 1;  /* bit[31]: 保留。HIEPS未使用。 */
    } reg;
} SOC_ETZPC_DECPROT2CLR_UNION;
#endif


/*****************************************************************************
 结构名    : SOC_ETZPC_DECPROT3STAT_UNION
 结构说明  : DECPROT3STAT 寄存器结构定义。地址偏移量:0x824，初值:0x00000000，宽度:32
 寄存器说明: IP安全属性状态寄存器3。
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved_0: 1;  /* bit[0] : 保留。HIEPS未使用。 */
        unsigned int  reserved_1: 1;  /* bit[1] : 保留。HIEPS未使用。 */
        unsigned int  reserved_2: 1;  /* bit[2] : 保留。HIEPS未使用。 */
        unsigned int  reserved_3: 1;  /* bit[3] : 保留。HIEPS未使用。 */
        unsigned int  reserved_4: 1;  /* bit[4] : 保留。HIEPS未使用。 */
        unsigned int  reserved_5: 1;  /* bit[5] : 保留。HIEPS未使用。 */
        unsigned int  reserved_6: 1;  /* bit[6] : 保留。HIEPS未使用。 */
        unsigned int  reserved_7: 1;  /* bit[7] : 保留。HIEPS未使用。 */
        unsigned int  reserved_8: 1;  /* bit[8] : 保留。HIEPS未使用。 */
        unsigned int  reserved_9: 1;  /* bit[9] : 保留。HIEPS未使用。 */
        unsigned int  reserved_10: 1;  /* bit[10]: 保留。HIEPS未使用。 */
        unsigned int  reserved_11: 1;  /* bit[11]: 保留。HIEPS未使用。 */
        unsigned int  reserved_12: 1;  /* bit[12]: 保留。HIEPS未使用。 */
        unsigned int  reserved_13: 1;  /* bit[13]: 保留。HIEPS未使用。 */
        unsigned int  reserved_14: 1;  /* bit[14]: 保留。HIEPS未使用。 */
        unsigned int  reserved_15: 1;  /* bit[15]: 保留。HIEPS未使用。 */
        unsigned int  reserved_16: 1;  /* bit[16]: 保留。HIEPS未使用。 */
        unsigned int  reserved_17: 1;  /* bit[17]: 保留。HIEPS未使用。 */
        unsigned int  reserved_18: 1;  /* bit[18]: 保留。HIEPS未使用。 */
        unsigned int  reserved_19: 1;  /* bit[19]: 保留。HIEPS未使用。 */
        unsigned int  reserved_20: 1;  /* bit[20]: 保留。HIEPS未使用。 */
        unsigned int  reserved_21: 1;  /* bit[21]: 保留。HIEPS未使用。 */
        unsigned int  reserved_22: 1;  /* bit[22]: 保留。HIEPS未使用。 */
        unsigned int  reserved_23: 1;  /* bit[23]: 保留。HIEPS未使用。 */
        unsigned int  reserved_24: 1;  /* bit[24]: 保留。HIEPS未使用。 */
        unsigned int  reserved_25: 1;  /* bit[25]: 保留。HIEPS未使用。 */
        unsigned int  reserved_26: 1;  /* bit[26]: 保留。HIEPS未使用。 */
        unsigned int  reserved_27: 1;  /* bit[27]: 保留。HIEPS未使用。 */
        unsigned int  reserved_28: 1;  /* bit[28]: 保留。HIEPS未使用。 */
        unsigned int  reserved_29: 1;  /* bit[29]: 保留。HIEPS未使用。 */
        unsigned int  reserved_30: 1;  /* bit[30]: 保留。HIEPS未使用。 */
        unsigned int  reserved_31: 1;  /* bit[31]: 保留。HIEPS未使用。 */
    } reg;
} SOC_ETZPC_DECPROT3STAT_UNION;
#endif


/*****************************************************************************
 结构名    : SOC_ETZPC_DECPROT3SET_UNION
 结构说明  : DECPROT3SET 寄存器结构定义。地址偏移量:0x828，初值:0x00000000，宽度:32
 寄存器说明: IP安全属性置位寄存器3。
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved_0: 1;  /* bit[0] : 保留。HIEPS未使用。 */
        unsigned int  reserved_1: 1;  /* bit[1] : 保留。HIEPS未使用。 */
        unsigned int  reserved_2: 1;  /* bit[2] : 保留。HIEPS未使用。 */
        unsigned int  reserved_3: 1;  /* bit[3] : 保留。HIEPS未使用。 */
        unsigned int  reserved_4: 1;  /* bit[4] : 保留。HIEPS未使用。 */
        unsigned int  reserved_5: 1;  /* bit[5] : 保留。HIEPS未使用。 */
        unsigned int  reserved_6: 1;  /* bit[6] : 保留。HIEPS未使用。 */
        unsigned int  reserved_7: 1;  /* bit[7] : 保留。HIEPS未使用。 */
        unsigned int  reserved_8: 1;  /* bit[8] : 保留。HIEPS未使用。 */
        unsigned int  reserved_9: 1;  /* bit[9] : 保留。HIEPS未使用。 */
        unsigned int  reserved_10: 1;  /* bit[10]: 保留。HIEPS未使用。 */
        unsigned int  reserved_11: 1;  /* bit[11]: 保留。HIEPS未使用。 */
        unsigned int  reserved_12: 1;  /* bit[12]: 保留。HIEPS未使用。 */
        unsigned int  reserved_13: 1;  /* bit[13]: 保留。HIEPS未使用。 */
        unsigned int  reserved_14: 1;  /* bit[14]: 保留。HIEPS未使用。 */
        unsigned int  reserved_15: 1;  /* bit[15]: 保留。HIEPS未使用。 */
        unsigned int  reserved_16: 1;  /* bit[16]: 保留。HIEPS未使用。 */
        unsigned int  reserved_17: 1;  /* bit[17]: 保留。HIEPS未使用。 */
        unsigned int  reserved_18: 1;  /* bit[18]: 保留。HIEPS未使用。 */
        unsigned int  reserved_19: 1;  /* bit[19]: 保留。HIEPS未使用。 */
        unsigned int  reserved_20: 1;  /* bit[20]: 保留。HIEPS未使用。 */
        unsigned int  reserved_21: 1;  /* bit[21]: 保留。HIEPS未使用。 */
        unsigned int  reserved_22: 1;  /* bit[22]: 保留。HIEPS未使用。 */
        unsigned int  reserved_23: 1;  /* bit[23]: 保留。HIEPS未使用。 */
        unsigned int  reserved_24: 1;  /* bit[24]: 保留。HIEPS未使用。 */
        unsigned int  reserved_25: 1;  /* bit[25]: 保留。HIEPS未使用。 */
        unsigned int  reserved_26: 1;  /* bit[26]: 保留。HIEPS未使用。 */
        unsigned int  reserved_27: 1;  /* bit[27]: 保留。HIEPS未使用。 */
        unsigned int  reserved_28: 1;  /* bit[28]: 保留。HIEPS未使用。 */
        unsigned int  reserved_29: 1;  /* bit[29]: 保留。HIEPS未使用。 */
        unsigned int  reserved_30: 1;  /* bit[30]: 保留。HIEPS未使用。 */
        unsigned int  reserved_31: 1;  /* bit[31]: 保留。HIEPS未使用。 */
    } reg;
} SOC_ETZPC_DECPROT3SET_UNION;
#endif


/*****************************************************************************
 结构名    : SOC_ETZPC_DECPROT3CLR_UNION
 结构说明  : DECPROT3CLR 寄存器结构定义。地址偏移量:0x82C，初值:0x00000000，宽度:32
 寄存器说明: IP安全属性清零寄存器3。
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved_0: 1;  /* bit[0] : 保留。HIEPS未使用。 */
        unsigned int  reserved_1: 1;  /* bit[1] : 保留。HIEPS未使用。 */
        unsigned int  reserved_2: 1;  /* bit[2] : 保留。HIEPS未使用。 */
        unsigned int  reserved_3: 1;  /* bit[3] : 保留。HIEPS未使用。 */
        unsigned int  reserved_4: 1;  /* bit[4] : 保留。HIEPS未使用。 */
        unsigned int  reserved_5: 1;  /* bit[5] : 保留。HIEPS未使用。 */
        unsigned int  reserved_6: 1;  /* bit[6] : 保留。HIEPS未使用。 */
        unsigned int  reserved_7: 1;  /* bit[7] : 保留。HIEPS未使用。 */
        unsigned int  reserved_8: 1;  /* bit[8] : 保留。HIEPS未使用。 */
        unsigned int  reserved_9: 1;  /* bit[9] : 保留。HIEPS未使用。 */
        unsigned int  reserved_10: 1;  /* bit[10]: 保留。HIEPS未使用。 */
        unsigned int  reserved_11: 1;  /* bit[11]: 保留。HIEPS未使用。 */
        unsigned int  reserved_12: 1;  /* bit[12]: 保留。HIEPS未使用。 */
        unsigned int  reserved_13: 1;  /* bit[13]: 保留。HIEPS未使用。 */
        unsigned int  reserved_14: 1;  /* bit[14]: 保留。HIEPS未使用。 */
        unsigned int  reserved_15: 1;  /* bit[15]: 保留。HIEPS未使用。 */
        unsigned int  reserved_16: 1;  /* bit[16]: 保留。HIEPS未使用。 */
        unsigned int  reserved_17: 1;  /* bit[17]: 保留。HIEPS未使用。 */
        unsigned int  reserved_18: 1;  /* bit[18]: 保留。HIEPS未使用。 */
        unsigned int  reserved_19: 1;  /* bit[19]: 保留。HIEPS未使用。 */
        unsigned int  reserved_20: 1;  /* bit[20]: 保留。HIEPS未使用。 */
        unsigned int  reserved_21: 1;  /* bit[21]: 保留。HIEPS未使用。 */
        unsigned int  reserved_22: 1;  /* bit[22]: 保留。HIEPS未使用。 */
        unsigned int  reserved_23: 1;  /* bit[23]: 保留。HIEPS未使用。 */
        unsigned int  reserved_24: 1;  /* bit[24]: 保留。HIEPS未使用。 */
        unsigned int  reserved_25: 1;  /* bit[25]: 保留。HIEPS未使用。 */
        unsigned int  reserved_26: 1;  /* bit[26]: 保留。HIEPS未使用。 */
        unsigned int  reserved_27: 1;  /* bit[27]: 保留。HIEPS未使用。 */
        unsigned int  reserved_28: 1;  /* bit[28]: 保留。HIEPS未使用。 */
        unsigned int  reserved_29: 1;  /* bit[29]: 保留。HIEPS未使用。 */
        unsigned int  reserved_30: 1;  /* bit[30]: 保留。HIEPS未使用。 */
        unsigned int  reserved_31: 1;  /* bit[31]: 保留。HIEPS未使用。 */
    } reg;
} SOC_ETZPC_DECPROT3CLR_UNION;
#endif


/*****************************************************************************
 结构名    : SOC_ETZPC_DECPROT4STAT_UNION
 结构说明  : DECPROT4STAT 寄存器结构定义。地址偏移量:0x830，初值:0x00000000，宽度:32
 寄存器说明: IP安全属性状态寄存器4。
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  tz_sce_axi_mst_wr_stat_0  : 1;  /* bit[0] : SCE AXI master的读操作权限:
                                                                  ? 3’b000:trusted stream secure world 
                                                                  ? 3’b001:non-trusted stream non-secure world
                                                                  ? 3’b010:protected stream non-secure world 
                                                                  ? 3’b100:trusted stream secure world
                                                                  其他值：non-trusted stream */
        unsigned int  tz_sce_axi_mst_wr_stat_1  : 1;  /* bit[1] : SCE AXI master的读操作权限:
                                                                  ? 3’b000:trusted stream secure world 
                                                                  ? 3’b001:non-trusted stream non-secure world
                                                                  ? 3’b010:protected stream non-secure world 
                                                                  ? 3’b100:trusted stream secure world
                                                                  其他值：non-trusted stream */
        unsigned int  tz_sce_axi_mst_wr_stat_2  : 1;  /* bit[2] : SCE AXI master的读操作权限:
                                                                  ? 3’b000:trusted stream secure world 
                                                                  ? 3’b001:non-trusted stream non-secure world
                                                                  ? 3’b010:protected stream non-secure world 
                                                                  ? 3’b100:trusted stream secure world
                                                                  其他值：non-trusted stream */
        unsigned int  tz_sce_axi_mst_rd_stat_0  : 1;  /* bit[3] : SCE AXI master的读操作权限:
                                                                  ? 3’b000:trusted stream secure world 
                                                                  ? 3’b001:non-trusted stream non-secure world
                                                                  ? 3’b010:protected stream non-secure world 
                                                                  ? 3’b100:trusted stream secure world
                                                                  其他值：non-trusted stream */
        unsigned int  tz_sce_axi_mst_rd_stat_1  : 1;  /* bit[4] : SCE AXI master的读操作权限:
                                                                  ? 3’b000:trusted stream secure world 
                                                                  ? 3’b001:non-trusted stream non-secure world
                                                                  ? 3’b010:protected stream non-secure world 
                                                                  ? 3’b100:trusted stream secure world
                                                                  其他值：non-trusted stream */
        unsigned int  tz_sce_axi_mst_rd_stat_2  : 1;  /* bit[5] : SCE AXI master的读操作权限:
                                                                  ? 3’b000:trusted stream secure world 
                                                                  ? 3’b001:non-trusted stream non-secure world
                                                                  ? 3’b010:protected stream non-secure world 
                                                                  ? 3’b100:trusted stream secure world
                                                                  其他值：non-trusted stream */
        unsigned int  tz_sce2_axi_mst_wr_stat_0 : 1;  /* bit[6] : SCE2 AXI master的读操作权限:
                                                                  ? 3’b000:trusted stream secure world 
                                                                  ? 3’b001:non-trusted stream non-secure world
                                                                  ? 3’b010:protected stream non-secure world 
                                                                  ? 3’b100:trusted stream secure world
                                                                  其他值：non-trusted stream */
        unsigned int  tz_sce2_axi_mst_wr_stat_1 : 1;  /* bit[7] : SCE2 AXI master的读操作权限:
                                                                  ? 3’b000:trusted stream secure world 
                                                                  ? 3’b001:non-trusted stream non-secure world
                                                                  ? 3’b010:protected stream non-secure world 
                                                                  ? 3’b100:trusted stream secure world
                                                                  其他值：non-trusted stream */
        unsigned int  tz_sce2_axi_mst_wr_stat_2 : 1;  /* bit[8] : SCE2 AXI master的读操作权限:
                                                                  ? 3’b000:trusted stream secure world 
                                                                  ? 3’b001:non-trusted stream non-secure world
                                                                  ? 3’b010:protected stream non-secure world 
                                                                  ? 3’b100:trusted stream secure world
                                                                  其他值：non-trusted stream */
        unsigned int  tz_sce2_axi_mst_rd_stat_0 : 1;  /* bit[9] : SCE2 AXI master的读操作权限:
                                                                  ? 3’b000:trusted stream secure world 
                                                                  ? 3’b001:non-trusted stream non-secure world
                                                                  ? 3’b010:protected stream non-secure world 
                                                                  ? 3’b100:trusted stream secure world
                                                                  其他值：non-trusted stream */
        unsigned int  tz_sce2_axi_mst_rd_stat_1 : 1;  /* bit[10]: SCE2 AXI master的读操作权限:
                                                                  ? 3’b000:trusted stream secure world 
                                                                  ? 3’b001:non-trusted stream non-secure world
                                                                  ? 3’b010:protected stream non-secure world 
                                                                  ? 3’b100:trusted stream secure world
                                                                  其他值：non-trusted stream */
        unsigned int  tz_sce2_axi_mst_rd_stat_2 : 1;  /* bit[11]: SCE2 AXI master的读操作权限:
                                                                  ? 3’b000:trusted stream secure world 
                                                                  ? 3’b001:non-trusted stream non-secure world
                                                                  ? 3’b010:protected stream non-secure world 
                                                                  ? 3’b100:trusted stream secure world
                                                                  其他值：non-trusted stream */
        unsigned int  reserved_0                : 1;  /* bit[12]: 保留。HIEPS未使用。 */
        unsigned int  reserved_1                : 1;  /* bit[13]: 保留。HIEPS未使用。 */
        unsigned int  reserved_2                : 1;  /* bit[14]: 保留。HIEPS未使用。 */
        unsigned int  reserved_3                : 1;  /* bit[15]: 保留。HIEPS未使用。 */
        unsigned int  reserved_4                : 1;  /* bit[16]: 保留。HIEPS未使用。 */
        unsigned int  reserved_5                : 1;  /* bit[17]: 保留。HIEPS未使用。 */
        unsigned int  reserved_6                : 1;  /* bit[18]: 保留。HIEPS未使用。 */
        unsigned int  reserved_7                : 1;  /* bit[19]: 保留。HIEPS未使用。 */
        unsigned int  reserved_8                : 1;  /* bit[20]: 保留。HIEPS未使用。 */
        unsigned int  reserved_9                : 1;  /* bit[21]: 保留。HIEPS未使用。 */
        unsigned int  reserved_10               : 1;  /* bit[22]: 保留。HIEPS未使用。 */
        unsigned int  reserved_11               : 1;  /* bit[23]: 保留。HIEPS未使用。 */
        unsigned int  reserved_12               : 1;  /* bit[24]: 保留。HIEPS未使用。 */
        unsigned int  reserved_13               : 1;  /* bit[25]: 保留。HIEPS未使用。 */
        unsigned int  reserved_14               : 1;  /* bit[26]: 保留。HIEPS未使用。 */
        unsigned int  reserved_15               : 1;  /* bit[27]: 保留。HIEPS未使用。 */
        unsigned int  reserved_16               : 1;  /* bit[28]: 保留。HIEPS未使用。 */
        unsigned int  reserved_17               : 1;  /* bit[29]: 保留。HIEPS未使用。 */
        unsigned int  reserved_18               : 1;  /* bit[30]: 保留。HIEPS未使用。 */
        unsigned int  reserved_19               : 1;  /* bit[31]: 保留。HIEPS未使用。 */
    } reg;
} SOC_ETZPC_DECPROT4STAT_UNION;
#endif
#define SOC_ETZPC_DECPROT4STAT_tz_sce_axi_mst_wr_stat_0_START   (0)
#define SOC_ETZPC_DECPROT4STAT_tz_sce_axi_mst_wr_stat_0_END     (0)
#define SOC_ETZPC_DECPROT4STAT_tz_sce_axi_mst_wr_stat_1_START   (1)
#define SOC_ETZPC_DECPROT4STAT_tz_sce_axi_mst_wr_stat_1_END     (1)
#define SOC_ETZPC_DECPROT4STAT_tz_sce_axi_mst_wr_stat_2_START   (2)
#define SOC_ETZPC_DECPROT4STAT_tz_sce_axi_mst_wr_stat_2_END     (2)
#define SOC_ETZPC_DECPROT4STAT_tz_sce_axi_mst_rd_stat_0_START   (3)
#define SOC_ETZPC_DECPROT4STAT_tz_sce_axi_mst_rd_stat_0_END     (3)
#define SOC_ETZPC_DECPROT4STAT_tz_sce_axi_mst_rd_stat_1_START   (4)
#define SOC_ETZPC_DECPROT4STAT_tz_sce_axi_mst_rd_stat_1_END     (4)
#define SOC_ETZPC_DECPROT4STAT_tz_sce_axi_mst_rd_stat_2_START   (5)
#define SOC_ETZPC_DECPROT4STAT_tz_sce_axi_mst_rd_stat_2_END     (5)
#define SOC_ETZPC_DECPROT4STAT_tz_sce2_axi_mst_wr_stat_0_START  (6)
#define SOC_ETZPC_DECPROT4STAT_tz_sce2_axi_mst_wr_stat_0_END    (6)
#define SOC_ETZPC_DECPROT4STAT_tz_sce2_axi_mst_wr_stat_1_START  (7)
#define SOC_ETZPC_DECPROT4STAT_tz_sce2_axi_mst_wr_stat_1_END    (7)
#define SOC_ETZPC_DECPROT4STAT_tz_sce2_axi_mst_wr_stat_2_START  (8)
#define SOC_ETZPC_DECPROT4STAT_tz_sce2_axi_mst_wr_stat_2_END    (8)
#define SOC_ETZPC_DECPROT4STAT_tz_sce2_axi_mst_rd_stat_0_START  (9)
#define SOC_ETZPC_DECPROT4STAT_tz_sce2_axi_mst_rd_stat_0_END    (9)
#define SOC_ETZPC_DECPROT4STAT_tz_sce2_axi_mst_rd_stat_1_START  (10)
#define SOC_ETZPC_DECPROT4STAT_tz_sce2_axi_mst_rd_stat_1_END    (10)
#define SOC_ETZPC_DECPROT4STAT_tz_sce2_axi_mst_rd_stat_2_START  (11)
#define SOC_ETZPC_DECPROT4STAT_tz_sce2_axi_mst_rd_stat_2_END    (11)


/*****************************************************************************
 结构名    : SOC_ETZPC_DECPROT4SET_UNION
 结构说明  : DECPROT4SET 寄存器结构定义。地址偏移量:0x834，初值:0x00000000，宽度:32
 寄存器说明: IP安全属性置位寄存器4。
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  tz_sce_axi_mst_wr_set_0  : 1;  /* bit[0] : SCE AXI MST 写操作的权限置位寄存器 */
        unsigned int  tz_sce_axi_mst_wr_set_1  : 1;  /* bit[1] : SCE AXI MST 写操作的权限置位寄存器 */
        unsigned int  tz_sce_axi_mst_wr_set_2  : 1;  /* bit[2] : SCE AXI MST 写操作的权限置位寄存器 */
        unsigned int  tz_sce_axi_mst_rd_set_0  : 1;  /* bit[3] : SCE AXI MST 读操作的权限置位寄存器 */
        unsigned int  tz_sce_axi_mst_rd_set_1  : 1;  /* bit[4] : SCE AXI MST 读操作的权限置位寄存器 */
        unsigned int  tz_sce_axi_mst_rd_set_2  : 1;  /* bit[5] : SCE AXI MST 读操作的权限置位寄存器 */
        unsigned int  tz_sce2_axi_mst_wr_set_0 : 1;  /* bit[6] : SCE2 AXI MST 写操作的权限置位寄存器 */
        unsigned int  tz_sce2_axi_mst_wr_set_1 : 1;  /* bit[7] : SCE2 AXI MST 写操作的权限置位寄存器 */
        unsigned int  tz_sce2_axi_mst_wr_set_2 : 1;  /* bit[8] : SCE2 AXI MST 写操作的权限置位寄存器 */
        unsigned int  tz_sce2_axi_mst_rd_set_0 : 1;  /* bit[9] : SCE2 AXI MST 读操作的权限置位寄存器 */
        unsigned int  tz_sce2_axi_mst_rd_set_1 : 1;  /* bit[10]: SCE2 AXI MST 读操作的权限置位寄存器 */
        unsigned int  tz_sce2_axi_mst_rd_set_2 : 1;  /* bit[11]: SCE2 AXI MST 读操作的权限置位寄存器 */
        unsigned int  reserved_0               : 1;  /* bit[12]: 保留。HIEPS未使用。 */
        unsigned int  reserved_1               : 1;  /* bit[13]: 保留。HIEPS未使用。 */
        unsigned int  reserved_2               : 1;  /* bit[14]: 保留。HIEPS未使用。 */
        unsigned int  reserved_3               : 1;  /* bit[15]: 保留。HIEPS未使用。 */
        unsigned int  reserved_4               : 1;  /* bit[16]: 保留。HIEPS未使用。 */
        unsigned int  reserved_5               : 1;  /* bit[17]: 保留。HIEPS未使用。 */
        unsigned int  reserved_6               : 1;  /* bit[18]: 保留。HIEPS未使用。 */
        unsigned int  reserved_7               : 1;  /* bit[19]: 保留。HIEPS未使用。 */
        unsigned int  reserved_8               : 1;  /* bit[20]: 保留。HIEPS未使用。 */
        unsigned int  reserved_9               : 1;  /* bit[21]: 保留。HIEPS未使用。 */
        unsigned int  reserved_10              : 1;  /* bit[22]: 保留。HIEPS未使用。 */
        unsigned int  reserved_11              : 1;  /* bit[23]: 保留。HIEPS未使用。 */
        unsigned int  reserved_12              : 1;  /* bit[24]: 保留。HIEPS未使用。 */
        unsigned int  reserved_13              : 1;  /* bit[25]: 保留。HIEPS未使用。 */
        unsigned int  reserved_14              : 1;  /* bit[26]: 保留。HIEPS未使用。 */
        unsigned int  reserved_15              : 1;  /* bit[27]: 保留。HIEPS未使用。 */
        unsigned int  reserved_16              : 1;  /* bit[28]: 保留。HIEPS未使用。 */
        unsigned int  reserved_17              : 1;  /* bit[29]: 保留。HIEPS未使用。 */
        unsigned int  reserved_18              : 1;  /* bit[30]: 保留。HIEPS未使用。 */
        unsigned int  reserved_19              : 1;  /* bit[31]: 保留。HIEPS未使用。 */
    } reg;
} SOC_ETZPC_DECPROT4SET_UNION;
#endif
#define SOC_ETZPC_DECPROT4SET_tz_sce_axi_mst_wr_set_0_START   (0)
#define SOC_ETZPC_DECPROT4SET_tz_sce_axi_mst_wr_set_0_END     (0)
#define SOC_ETZPC_DECPROT4SET_tz_sce_axi_mst_wr_set_1_START   (1)
#define SOC_ETZPC_DECPROT4SET_tz_sce_axi_mst_wr_set_1_END     (1)
#define SOC_ETZPC_DECPROT4SET_tz_sce_axi_mst_wr_set_2_START   (2)
#define SOC_ETZPC_DECPROT4SET_tz_sce_axi_mst_wr_set_2_END     (2)
#define SOC_ETZPC_DECPROT4SET_tz_sce_axi_mst_rd_set_0_START   (3)
#define SOC_ETZPC_DECPROT4SET_tz_sce_axi_mst_rd_set_0_END     (3)
#define SOC_ETZPC_DECPROT4SET_tz_sce_axi_mst_rd_set_1_START   (4)
#define SOC_ETZPC_DECPROT4SET_tz_sce_axi_mst_rd_set_1_END     (4)
#define SOC_ETZPC_DECPROT4SET_tz_sce_axi_mst_rd_set_2_START   (5)
#define SOC_ETZPC_DECPROT4SET_tz_sce_axi_mst_rd_set_2_END     (5)
#define SOC_ETZPC_DECPROT4SET_tz_sce2_axi_mst_wr_set_0_START  (6)
#define SOC_ETZPC_DECPROT4SET_tz_sce2_axi_mst_wr_set_0_END    (6)
#define SOC_ETZPC_DECPROT4SET_tz_sce2_axi_mst_wr_set_1_START  (7)
#define SOC_ETZPC_DECPROT4SET_tz_sce2_axi_mst_wr_set_1_END    (7)
#define SOC_ETZPC_DECPROT4SET_tz_sce2_axi_mst_wr_set_2_START  (8)
#define SOC_ETZPC_DECPROT4SET_tz_sce2_axi_mst_wr_set_2_END    (8)
#define SOC_ETZPC_DECPROT4SET_tz_sce2_axi_mst_rd_set_0_START  (9)
#define SOC_ETZPC_DECPROT4SET_tz_sce2_axi_mst_rd_set_0_END    (9)
#define SOC_ETZPC_DECPROT4SET_tz_sce2_axi_mst_rd_set_1_START  (10)
#define SOC_ETZPC_DECPROT4SET_tz_sce2_axi_mst_rd_set_1_END    (10)
#define SOC_ETZPC_DECPROT4SET_tz_sce2_axi_mst_rd_set_2_START  (11)
#define SOC_ETZPC_DECPROT4SET_tz_sce2_axi_mst_rd_set_2_END    (11)


/*****************************************************************************
 结构名    : SOC_ETZPC_DECPROT4CLR_UNION
 结构说明  : DECPROT4CLR 寄存器结构定义。地址偏移量:0x838，初值:0x00000000，宽度:32
 寄存器说明: IP安全属性清零寄存器4。
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  tz_sce_axi_mst_wr_clr_0  : 1;  /* bit[0] : SCE AXI MST 写操作的权限清零寄存器 */
        unsigned int  tz_sce_axi_mst_wr_clr_1  : 1;  /* bit[1] : SCE AXI MST 写操作的权限清零寄存器 */
        unsigned int  tz_sce_axi_mst_wr_clr_2  : 1;  /* bit[2] : SCE AXI MST 写操作的权限清零寄存器 */
        unsigned int  tz_sce_axi_mst_rd_clr_0  : 1;  /* bit[3] : SCE AXI MST 读操作的权限清零寄存器 */
        unsigned int  tz_sce_axi_mst_rd_clr_1  : 1;  /* bit[4] : SCE AXI MST 读操作的权限清零寄存器 */
        unsigned int  tz_sce_axi_mst_rd_clr_2  : 1;  /* bit[5] : SCE AXI MST 读操作的权限清零寄存器 */
        unsigned int  tz_sce2_axi_mst_wr_clr_0 : 1;  /* bit[6] : SCE2 AXI MST 写操作的权限清零寄存器 */
        unsigned int  tz_sce2_axi_mst_wr_clr_1 : 1;  /* bit[7] : SCE2 AXI MST 写操作的权限清零寄存器 */
        unsigned int  tz_sce2_axi_mst_wr_clr_2 : 1;  /* bit[8] : SCE2 AXI MST 写操作的权限清零寄存器 */
        unsigned int  tz_sce2_axi_mst_rd_clr_0 : 1;  /* bit[9] : SCE2 AXI MST 读操作的权限清零寄存器 */
        unsigned int  tz_sce2_axi_mst_rd_clr_1 : 1;  /* bit[10]: SCE2 AXI MST 读操作的权限清零寄存器 */
        unsigned int  tz_sce2_axi_mst_rd_clr_2 : 1;  /* bit[11]: SCE2 AXI MST 读操作的权限清零寄存器 */
        unsigned int  reserved_0               : 1;  /* bit[12]: 保留。HIEPS未使用。 */
        unsigned int  reserved_1               : 1;  /* bit[13]: 保留。HIEPS未使用。 */
        unsigned int  reserved_2               : 1;  /* bit[14]: 保留。HIEPS未使用。 */
        unsigned int  reserved_3               : 1;  /* bit[15]: 保留。HIEPS未使用。 */
        unsigned int  reserved_4               : 1;  /* bit[16]: 保留。HIEPS未使用。 */
        unsigned int  reserved_5               : 1;  /* bit[17]: 保留。HIEPS未使用。 */
        unsigned int  reserved_6               : 1;  /* bit[18]: 保留。HIEPS未使用。 */
        unsigned int  reserved_7               : 1;  /* bit[19]: 保留。HIEPS未使用。 */
        unsigned int  reserved_8               : 1;  /* bit[20]: 保留。HIEPS未使用。 */
        unsigned int  reserved_9               : 1;  /* bit[21]: 保留。HIEPS未使用。 */
        unsigned int  reserved_10              : 1;  /* bit[22]: 保留。HIEPS未使用。 */
        unsigned int  reserved_11              : 1;  /* bit[23]: 保留。HIEPS未使用。 */
        unsigned int  reserved_12              : 1;  /* bit[24]: 保留。HIEPS未使用。 */
        unsigned int  reserved_13              : 1;  /* bit[25]: 保留。HIEPS未使用。 */
        unsigned int  reserved_14              : 1;  /* bit[26]: 保留。HIEPS未使用。 */
        unsigned int  reserved_15              : 1;  /* bit[27]: 保留。HIEPS未使用。 */
        unsigned int  reserved_16              : 1;  /* bit[28]: 保留。HIEPS未使用。 */
        unsigned int  reserved_17              : 1;  /* bit[29]: 保留。HIEPS未使用。 */
        unsigned int  reserved_18              : 1;  /* bit[30]: 保留。HIEPS未使用。 */
        unsigned int  reserved_19              : 1;  /* bit[31]: 保留。HIEPS未使用。 */
    } reg;
} SOC_ETZPC_DECPROT4CLR_UNION;
#endif
#define SOC_ETZPC_DECPROT4CLR_tz_sce_axi_mst_wr_clr_0_START   (0)
#define SOC_ETZPC_DECPROT4CLR_tz_sce_axi_mst_wr_clr_0_END     (0)
#define SOC_ETZPC_DECPROT4CLR_tz_sce_axi_mst_wr_clr_1_START   (1)
#define SOC_ETZPC_DECPROT4CLR_tz_sce_axi_mst_wr_clr_1_END     (1)
#define SOC_ETZPC_DECPROT4CLR_tz_sce_axi_mst_wr_clr_2_START   (2)
#define SOC_ETZPC_DECPROT4CLR_tz_sce_axi_mst_wr_clr_2_END     (2)
#define SOC_ETZPC_DECPROT4CLR_tz_sce_axi_mst_rd_clr_0_START   (3)
#define SOC_ETZPC_DECPROT4CLR_tz_sce_axi_mst_rd_clr_0_END     (3)
#define SOC_ETZPC_DECPROT4CLR_tz_sce_axi_mst_rd_clr_1_START   (4)
#define SOC_ETZPC_DECPROT4CLR_tz_sce_axi_mst_rd_clr_1_END     (4)
#define SOC_ETZPC_DECPROT4CLR_tz_sce_axi_mst_rd_clr_2_START   (5)
#define SOC_ETZPC_DECPROT4CLR_tz_sce_axi_mst_rd_clr_2_END     (5)
#define SOC_ETZPC_DECPROT4CLR_tz_sce2_axi_mst_wr_clr_0_START  (6)
#define SOC_ETZPC_DECPROT4CLR_tz_sce2_axi_mst_wr_clr_0_END    (6)
#define SOC_ETZPC_DECPROT4CLR_tz_sce2_axi_mst_wr_clr_1_START  (7)
#define SOC_ETZPC_DECPROT4CLR_tz_sce2_axi_mst_wr_clr_1_END    (7)
#define SOC_ETZPC_DECPROT4CLR_tz_sce2_axi_mst_wr_clr_2_START  (8)
#define SOC_ETZPC_DECPROT4CLR_tz_sce2_axi_mst_wr_clr_2_END    (8)
#define SOC_ETZPC_DECPROT4CLR_tz_sce2_axi_mst_rd_clr_0_START  (9)
#define SOC_ETZPC_DECPROT4CLR_tz_sce2_axi_mst_rd_clr_0_END    (9)
#define SOC_ETZPC_DECPROT4CLR_tz_sce2_axi_mst_rd_clr_1_START  (10)
#define SOC_ETZPC_DECPROT4CLR_tz_sce2_axi_mst_rd_clr_1_END    (10)
#define SOC_ETZPC_DECPROT4CLR_tz_sce2_axi_mst_rd_clr_2_START  (11)
#define SOC_ETZPC_DECPROT4CLR_tz_sce2_axi_mst_rd_clr_2_END    (11)


/*****************************************************************************
 结构名    : SOC_ETZPC_DECPROT5STAT_UNION
 结构说明  : DECPROT5STAT 寄存器结构定义。地址偏移量:0x83C，初值:0x00300000，宽度:32
 寄存器说明: IP安全属性状态寄存器5。
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved_0: 1;  /* bit[0] : 保留。HIEPS未使用。 */
        unsigned int  reserved_1: 1;  /* bit[1] : 保留。HIEPS未使用。 */
        unsigned int  reserved_2: 1;  /* bit[2] : 保留。HIEPS未使用。 */
        unsigned int  reserved_3: 1;  /* bit[3] : 保留。HIEPS未使用。 */
        unsigned int  reserved_4: 1;  /* bit[4] : 保留。HIEPS未使用。 */
        unsigned int  reserved_5: 1;  /* bit[5] : 保留。HIEPS未使用。 */
        unsigned int  reserved_6: 1;  /* bit[6] : 保留。HIEPS未使用。 */
        unsigned int  reserved_7: 1;  /* bit[7] : 保留。HIEPS未使用。 */
        unsigned int  reserved_8: 1;  /* bit[8] : 保留。HIEPS未使用。 */
        unsigned int  reserved_9: 1;  /* bit[9] : 保留。HIEPS未使用。 */
        unsigned int  reserved_10: 1;  /* bit[10]: 保留。HIEPS未使用。 */
        unsigned int  reserved_11: 1;  /* bit[11]: 保留。HIEPS未使用。 */
        unsigned int  reserved_12: 1;  /* bit[12]: 保留。HIEPS未使用。 */
        unsigned int  reserved_13: 1;  /* bit[13]: 保留。HIEPS未使用。 */
        unsigned int  reserved_14: 1;  /* bit[14]: 保留。HIEPS未使用。 */
        unsigned int  reserved_15: 1;  /* bit[15]: 保留。HIEPS未使用。 */
        unsigned int  reserved_16: 1;  /* bit[16]: 保留。HIEPS未使用。 */
        unsigned int  reserved_17: 1;  /* bit[17]: 保留。HIEPS未使用。 */
        unsigned int  reserved_18: 1;  /* bit[18]: 保留。HIEPS未使用。 */
        unsigned int  reserved_19: 1;  /* bit[19]: 保留。HIEPS未使用。 */
        unsigned int  reserved_20: 1;  /* bit[20]: 保留。HIEPS未使用。 */
        unsigned int  reserved_21: 1;  /* bit[21]: 保留。HIEPS未使用。 */
        unsigned int  reserved_22: 1;  /* bit[22]: 保留。HIEPS未使用。 */
        unsigned int  reserved_23: 1;  /* bit[23]: 保留。HIEPS未使用。 */
        unsigned int  reserved_24: 1;  /* bit[24]: 保留。HIEPS未使用。 */
        unsigned int  reserved_25: 1;  /* bit[25]: 保留。HIEPS未使用。 */
        unsigned int  reserved_26: 1;  /* bit[26]: 保留。HIEPS未使用。 */
        unsigned int  reserved_27: 1;  /* bit[27]: 保留。HIEPS未使用。 */
        unsigned int  reserved_28: 1;  /* bit[28]: 保留。HIEPS未使用。 */
        unsigned int  reserved_29: 1;  /* bit[29]: 保留。HIEPS未使用。 */
        unsigned int  reserved_30: 1;  /* bit[30]: 保留。HIEPS未使用。 */
        unsigned int  reserved_31: 1;  /* bit[31]: 保留。HIEPS未使用。 */
    } reg;
} SOC_ETZPC_DECPROT5STAT_UNION;
#endif


/*****************************************************************************
 结构名    : SOC_ETZPC_DECPROT5SET_UNION
 结构说明  : DECPROT5SET 寄存器结构定义。地址偏移量:0x840，初值:0x00000000，宽度:32
 寄存器说明: IP安全属性置位寄存器5。
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved_0: 1;  /* bit[0] : 保留。HIEPS未使用。 */
        unsigned int  reserved_1: 1;  /* bit[1] : 保留。HIEPS未使用。 */
        unsigned int  reserved_2: 1;  /* bit[2] : 保留。HIEPS未使用。 */
        unsigned int  reserved_3: 1;  /* bit[3] : 保留。HIEPS未使用。 */
        unsigned int  reserved_4: 1;  /* bit[4] : 保留。HIEPS未使用。 */
        unsigned int  reserved_5: 1;  /* bit[5] : 保留。HIEPS未使用。 */
        unsigned int  reserved_6: 1;  /* bit[6] : 保留。HIEPS未使用。 */
        unsigned int  reserved_7: 1;  /* bit[7] : 保留。HIEPS未使用。 */
        unsigned int  reserved_8: 1;  /* bit[8] : 保留。HIEPS未使用。 */
        unsigned int  reserved_9: 1;  /* bit[9] : 保留。HIEPS未使用。 */
        unsigned int  reserved_10: 1;  /* bit[10]: 保留。HIEPS未使用。 */
        unsigned int  reserved_11: 1;  /* bit[11]: 保留。HIEPS未使用。 */
        unsigned int  reserved_12: 1;  /* bit[12]: 保留。HIEPS未使用。 */
        unsigned int  reserved_13: 1;  /* bit[13]: 保留。HIEPS未使用。 */
        unsigned int  reserved_14: 1;  /* bit[14]: 保留。HIEPS未使用。 */
        unsigned int  reserved_15: 1;  /* bit[15]: 保留。HIEPS未使用。 */
        unsigned int  reserved_16: 1;  /* bit[16]: 保留。HIEPS未使用。 */
        unsigned int  reserved_17: 1;  /* bit[17]: 保留。HIEPS未使用。 */
        unsigned int  reserved_18: 1;  /* bit[18]: 保留。HIEPS未使用。 */
        unsigned int  reserved_19: 1;  /* bit[19]: 保留。HIEPS未使用。 */
        unsigned int  reserved_20: 1;  /* bit[20]: 保留。HIEPS未使用。 */
        unsigned int  reserved_21: 1;  /* bit[21]: 保留。HIEPS未使用。 */
        unsigned int  reserved_22: 1;  /* bit[22]: 保留。HIEPS未使用。 */
        unsigned int  reserved_23: 1;  /* bit[23]: 保留。HIEPS未使用。 */
        unsigned int  reserved_24: 1;  /* bit[24]: 保留。HIEPS未使用。 */
        unsigned int  reserved_25: 1;  /* bit[25]: 保留。HIEPS未使用。 */
        unsigned int  reserved_26: 1;  /* bit[26]: 保留。HIEPS未使用。 */
        unsigned int  reserved_27: 1;  /* bit[27]: 保留。HIEPS未使用。 */
        unsigned int  reserved_28: 1;  /* bit[28]: 保留。HIEPS未使用。 */
        unsigned int  reserved_29: 1;  /* bit[29]: 保留。HIEPS未使用。 */
        unsigned int  reserved_30: 1;  /* bit[30]: 保留。HIEPS未使用。 */
        unsigned int  reserved_31: 1;  /* bit[31]: 保留。HIEPS未使用。 */
    } reg;
} SOC_ETZPC_DECPROT5SET_UNION;
#endif


/*****************************************************************************
 结构名    : SOC_ETZPC_DECPROT5CLR_UNION
 结构说明  : DECPROT5CLR 寄存器结构定义。地址偏移量:0x844，初值:0x00000000，宽度:32
 寄存器说明: IP安全属性清零寄存器5。
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved_0: 1;  /* bit[0] : 保留。HIEPS未使用。 */
        unsigned int  reserved_1: 1;  /* bit[1] : 保留。HIEPS未使用。 */
        unsigned int  reserved_2: 1;  /* bit[2] : 保留。HIEPS未使用。 */
        unsigned int  reserved_3: 1;  /* bit[3] : 保留。HIEPS未使用。 */
        unsigned int  reserved_4: 1;  /* bit[4] : 保留。HIEPS未使用。 */
        unsigned int  reserved_5: 1;  /* bit[5] : 保留。HIEPS未使用。 */
        unsigned int  reserved_6: 1;  /* bit[6] : 保留。HIEPS未使用。 */
        unsigned int  reserved_7: 1;  /* bit[7] : 保留。HIEPS未使用。 */
        unsigned int  reserved_8: 1;  /* bit[8] : 保留。HIEPS未使用。 */
        unsigned int  reserved_9: 1;  /* bit[9] : 保留。HIEPS未使用。 */
        unsigned int  reserved_10: 1;  /* bit[10]: 保留。HIEPS未使用。 */
        unsigned int  reserved_11: 1;  /* bit[11]: 保留。HIEPS未使用。 */
        unsigned int  reserved_12: 1;  /* bit[12]: 保留。HIEPS未使用。 */
        unsigned int  reserved_13: 1;  /* bit[13]: 保留。HIEPS未使用。 */
        unsigned int  reserved_14: 1;  /* bit[14]: 保留。HIEPS未使用。 */
        unsigned int  reserved_15: 1;  /* bit[15]: 保留。HIEPS未使用。 */
        unsigned int  reserved_16: 1;  /* bit[16]: 保留。HIEPS未使用。 */
        unsigned int  reserved_17: 1;  /* bit[17]: 保留。HIEPS未使用。 */
        unsigned int  reserved_18: 1;  /* bit[18]: 保留。HIEPS未使用。 */
        unsigned int  reserved_19: 1;  /* bit[19]: 保留。HIEPS未使用。 */
        unsigned int  reserved_20: 1;  /* bit[20]: 保留。HIEPS未使用。 */
        unsigned int  reserved_21: 1;  /* bit[21]: 保留。HIEPS未使用。 */
        unsigned int  reserved_22: 1;  /* bit[22]: 保留。HIEPS未使用。 */
        unsigned int  reserved_23: 1;  /* bit[23]: 保留。HIEPS未使用。 */
        unsigned int  reserved_24: 1;  /* bit[24]: 保留。HIEPS未使用。 */
        unsigned int  reserved_25: 1;  /* bit[25]: 保留。HIEPS未使用。 */
        unsigned int  reserved_26: 1;  /* bit[26]: 保留。HIEPS未使用。 */
        unsigned int  reserved_27: 1;  /* bit[27]: 保留。HIEPS未使用。 */
        unsigned int  reserved_28: 1;  /* bit[28]: 保留。HIEPS未使用。 */
        unsigned int  reserved_29: 1;  /* bit[29]: 保留。HIEPS未使用。 */
        unsigned int  reserved_30: 1;  /* bit[30]: 保留。HIEPS未使用。 */
        unsigned int  reserved_31: 1;  /* bit[31]: 保留。HIEPS未使用。 */
    } reg;
} SOC_ETZPC_DECPROT5CLR_UNION;
#endif


/*****************************************************************************
 结构名    : SOC_ETZPC_DECPROT6STAT_UNION
 结构说明  : DECPROT6STAT 寄存器结构定义。地址偏移量:0x848，初值:0x0007FEE0，宽度:32
 寄存器说明: IP安全属性状态寄存器6。
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved_0: 1;  /* bit[0] : 保留。HIEPS未使用。 */
        unsigned int  reserved_1: 1;  /* bit[1] : 保留。HIEPS未使用。 */
        unsigned int  reserved_2: 1;  /* bit[2] : 保留。HIEPS未使用。 */
        unsigned int  reserved_3: 1;  /* bit[3] : 保留。HIEPS未使用。 */
        unsigned int  reserved_4: 1;  /* bit[4] : 保留。HIEPS未使用。 */
        unsigned int  reserved_5: 1;  /* bit[5] : 保留。HIEPS未使用。 */
        unsigned int  reserved_6: 1;  /* bit[6] : 保留。HIEPS未使用。 */
        unsigned int  reserved_7: 1;  /* bit[7] : 保留。HIEPS未使用。 */
        unsigned int  reserved_8: 1;  /* bit[8] : 保留。HIEPS未使用。 */
        unsigned int  reserved_9: 1;  /* bit[9] : 保留。HIEPS未使用。 */
        unsigned int  reserved_10: 1;  /* bit[10]: 保留。HIEPS未使用。 */
        unsigned int  reserved_11: 1;  /* bit[11]: 保留。HIEPS未使用。 */
        unsigned int  reserved_12: 1;  /* bit[12]: 保留。HIEPS未使用。 */
        unsigned int  reserved_13: 1;  /* bit[13]: 保留。HIEPS未使用。 */
        unsigned int  reserved_14: 1;  /* bit[14]: 保留。HIEPS未使用。 */
        unsigned int  reserved_15: 1;  /* bit[15]: 保留。HIEPS未使用。 */
        unsigned int  reserved_16: 1;  /* bit[16]: 保留。HIEPS未使用。 */
        unsigned int  reserved_17: 1;  /* bit[17]: 保留。HIEPS未使用。 */
        unsigned int  reserved_18: 1;  /* bit[18]: 保留。HIEPS未使用。 */
        unsigned int  reserved_19: 1;  /* bit[19]: 保留。HIEPS未使用。 */
        unsigned int  reserved_20: 1;  /* bit[20]: 保留。HIEPS未使用。 */
        unsigned int  reserved_21: 1;  /* bit[21]: 保留。HIEPS未使用。 */
        unsigned int  reserved_22: 1;  /* bit[22]: 保留。HIEPS未使用。 */
        unsigned int  reserved_23: 1;  /* bit[23]: 保留。HIEPS未使用。 */
        unsigned int  reserved_24: 1;  /* bit[24]: 保留。HIEPS未使用。 */
        unsigned int  reserved_25: 1;  /* bit[25]: 保留。HIEPS未使用。 */
        unsigned int  reserved_26: 1;  /* bit[26]: 保留。HIEPS未使用。 */
        unsigned int  reserved_27: 1;  /* bit[27]: 保留。HIEPS未使用。 */
        unsigned int  reserved_28: 1;  /* bit[28]: 保留。HIEPS未使用。 */
        unsigned int  reserved_29: 1;  /* bit[29]: 保留。HIEPS未使用。 */
        unsigned int  reserved_30: 1;  /* bit[30]: 保留。HIEPS未使用。 */
        unsigned int  reserved_31: 1;  /* bit[31]: 保留。HIEPS未使用。 */
    } reg;
} SOC_ETZPC_DECPROT6STAT_UNION;
#endif


/*****************************************************************************
 结构名    : SOC_ETZPC_DECPROT6SET_UNION
 结构说明  : DECPROT6SET 寄存器结构定义。地址偏移量:0x84C，初值:0x00000000，宽度:32
 寄存器说明: IP安全属性置位寄存器6。
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved_0: 1;  /* bit[0] : 保留。HIEPS未使用。 */
        unsigned int  reserved_1: 1;  /* bit[1] : 保留。HIEPS未使用。 */
        unsigned int  reserved_2: 1;  /* bit[2] : 保留。HIEPS未使用。 */
        unsigned int  reserved_3: 1;  /* bit[3] : 保留。HIEPS未使用。 */
        unsigned int  reserved_4: 1;  /* bit[4] : 保留。HIEPS未使用。 */
        unsigned int  reserved_5: 1;  /* bit[5] : 保留。HIEPS未使用。 */
        unsigned int  reserved_6: 1;  /* bit[6] : 保留。HIEPS未使用。 */
        unsigned int  reserved_7: 1;  /* bit[7] : 保留。HIEPS未使用。 */
        unsigned int  reserved_8: 1;  /* bit[8] : 保留。HIEPS未使用。 */
        unsigned int  reserved_9: 1;  /* bit[9] : 保留。HIEPS未使用。 */
        unsigned int  reserved_10: 1;  /* bit[10]: 保留。HIEPS未使用。 */
        unsigned int  reserved_11: 1;  /* bit[11]: 保留。HIEPS未使用。 */
        unsigned int  reserved_12: 1;  /* bit[12]: 保留。HIEPS未使用。 */
        unsigned int  reserved_13: 1;  /* bit[13]: 保留。HIEPS未使用。 */
        unsigned int  reserved_14: 1;  /* bit[14]: 保留。HIEPS未使用。 */
        unsigned int  reserved_15: 1;  /* bit[15]: 保留。HIEPS未使用。 */
        unsigned int  reserved_16: 1;  /* bit[16]: 保留。HIEPS未使用。 */
        unsigned int  reserved_17: 1;  /* bit[17]: 保留。HIEPS未使用。 */
        unsigned int  reserved_18: 1;  /* bit[18]: 保留。HIEPS未使用。 */
        unsigned int  reserved_19: 1;  /* bit[19]: 保留。HIEPS未使用。 */
        unsigned int  reserved_20: 1;  /* bit[20]: 保留。HIEPS未使用。 */
        unsigned int  reserved_21: 1;  /* bit[21]: 保留。HIEPS未使用。 */
        unsigned int  reserved_22: 1;  /* bit[22]: 保留。HIEPS未使用。 */
        unsigned int  reserved_23: 1;  /* bit[23]: 保留。HIEPS未使用。 */
        unsigned int  reserved_24: 1;  /* bit[24]: 保留。HIEPS未使用。 */
        unsigned int  reserved_25: 1;  /* bit[25]: 保留。HIEPS未使用。 */
        unsigned int  reserved_26: 1;  /* bit[26]: 保留。HIEPS未使用。 */
        unsigned int  reserved_27: 1;  /* bit[27]: 保留。HIEPS未使用。 */
        unsigned int  reserved_28: 1;  /* bit[28]: 保留。HIEPS未使用。 */
        unsigned int  reserved_29: 1;  /* bit[29]: 保留。HIEPS未使用。 */
        unsigned int  reserved_30: 1;  /* bit[30]: 保留。HIEPS未使用。 */
        unsigned int  reserved_31: 1;  /* bit[31]: 保留。HIEPS未使用。 */
    } reg;
} SOC_ETZPC_DECPROT6SET_UNION;
#endif


/*****************************************************************************
 结构名    : SOC_ETZPC_DECPROT6CLR_UNION
 结构说明  : DECPROT6CLR 寄存器结构定义。地址偏移量:0x850，初值:0x00000000，宽度:32
 寄存器说明: IP安全属性清零寄存器6。
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved_0: 1;  /* bit[0] : 保留。HIEPS未使用。 */
        unsigned int  reserved_1: 1;  /* bit[1] : 保留。HIEPS未使用。 */
        unsigned int  reserved_2: 1;  /* bit[2] : 保留。HIEPS未使用。 */
        unsigned int  reserved_3: 1;  /* bit[3] : 保留。HIEPS未使用。 */
        unsigned int  reserved_4: 1;  /* bit[4] : 保留。HIEPS未使用。 */
        unsigned int  reserved_5: 1;  /* bit[5] : 保留。HIEPS未使用。 */
        unsigned int  reserved_6: 1;  /* bit[6] : 保留。HIEPS未使用。 */
        unsigned int  reserved_7: 1;  /* bit[7] : 保留。HIEPS未使用。 */
        unsigned int  reserved_8: 1;  /* bit[8] : 保留。HIEPS未使用。 */
        unsigned int  reserved_9: 1;  /* bit[9] : 保留。HIEPS未使用。 */
        unsigned int  reserved_10: 1;  /* bit[10]: 保留。HIEPS未使用。 */
        unsigned int  reserved_11: 1;  /* bit[11]: 保留。HIEPS未使用。 */
        unsigned int  reserved_12: 1;  /* bit[12]: 保留。HIEPS未使用。 */
        unsigned int  reserved_13: 1;  /* bit[13]: 保留。HIEPS未使用。 */
        unsigned int  reserved_14: 1;  /* bit[14]: 保留。HIEPS未使用。 */
        unsigned int  reserved_15: 1;  /* bit[15]: 保留。HIEPS未使用。 */
        unsigned int  reserved_16: 1;  /* bit[16]: 保留。HIEPS未使用。 */
        unsigned int  reserved_17: 1;  /* bit[17]: 保留。HIEPS未使用。 */
        unsigned int  reserved_18: 1;  /* bit[18]: 保留。HIEPS未使用。 */
        unsigned int  reserved_19: 1;  /* bit[19]: 保留。HIEPS未使用。 */
        unsigned int  reserved_20: 1;  /* bit[20]: 保留。HIEPS未使用。 */
        unsigned int  reserved_21: 1;  /* bit[21]: 保留。HIEPS未使用。 */
        unsigned int  reserved_22: 1;  /* bit[22]: 保留。HIEPS未使用。 */
        unsigned int  reserved_23: 1;  /* bit[23]: 保留。HIEPS未使用。 */
        unsigned int  reserved_24: 1;  /* bit[24]: 保留。HIEPS未使用。 */
        unsigned int  reserved_25: 1;  /* bit[25]: 保留。HIEPS未使用。 */
        unsigned int  reserved_26: 1;  /* bit[26]: 保留。HIEPS未使用。 */
        unsigned int  reserved_27: 1;  /* bit[27]: 保留。HIEPS未使用。 */
        unsigned int  reserved_28: 1;  /* bit[28]: 保留。HIEPS未使用。 */
        unsigned int  reserved_29: 1;  /* bit[29]: 保留。HIEPS未使用。 */
        unsigned int  reserved_30: 1;  /* bit[30]: 保留。HIEPS未使用。 */
        unsigned int  reserved_31: 1;  /* bit[31]: 保留。HIEPS未使用。 */
    } reg;
} SOC_ETZPC_DECPROT6CLR_UNION;
#endif


/*****************************************************************************
 结构名    : SOC_ETZPC_DECPROT7STAT_UNION
 结构说明  : DECPROT7STAT 寄存器结构定义。地址偏移量:0x854，初值:0x00000000，宽度:32
 寄存器说明: IP安全属性状态寄存器7。
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved_0: 1;  /* bit[0]   : 保留。HIEPS未使用。 */
        unsigned int  reserved_1: 1;  /* bit[1]   : 保留。HIEPS未使用。 */
        unsigned int  reserved_2: 1;  /* bit[2]   : 保留。HIEPS未使用。 */
        unsigned int  reserved_3: 1;  /* bit[3]   : 保留。HIEPS未使用。 */
        unsigned int  reserved_4: 28; /* bit[4-31]: 保留。HIEPS未使用。 */
    } reg;
} SOC_ETZPC_DECPROT7STAT_UNION;
#endif


/*****************************************************************************
 结构名    : SOC_ETZPC_DECPROT7SET_UNION
 结构说明  : DECPROT7SET 寄存器结构定义。地址偏移量:0x858，初值:0x00000000，宽度:32
 寄存器说明: IP安全属性置位寄存器7。
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved_0: 1;  /* bit[0]   : 保留。HIEPS未使用。 */
        unsigned int  reserved_1: 1;  /* bit[1]   : 保留。HIEPS未使用。 */
        unsigned int  reserved_2: 1;  /* bit[2]   : 保留。HIEPS未使用。 */
        unsigned int  reserved_3: 1;  /* bit[3]   : 保留。HIEPS未使用。 */
        unsigned int  reserved_4: 28; /* bit[4-31]: 保留。HIEPS未使用。 */
    } reg;
} SOC_ETZPC_DECPROT7SET_UNION;
#endif


/*****************************************************************************
 结构名    : SOC_ETZPC_DECPROT7CLR_UNION
 结构说明  : DECPROT7CLR 寄存器结构定义。地址偏移量:0x85C，初值:0x00000000，宽度:32
 寄存器说明: IP安全属性清零寄存器7。
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved_0: 1;  /* bit[0]   : 保留。HIEPS未使用。 */
        unsigned int  reserved_1: 1;  /* bit[1]   : 保留。HIEPS未使用。 */
        unsigned int  reserved_2: 1;  /* bit[2]   : 保留。HIEPS未使用。 */
        unsigned int  reserved_3: 1;  /* bit[3]   : 保留。HIEPS未使用。 */
        unsigned int  reserved_4: 28; /* bit[4-31]: 保留。HIEPS未使用。 */
    } reg;
} SOC_ETZPC_DECPROT7CLR_UNION;
#endif


/*****************************************************************************
 结构名    : SOC_ETZPC_DECPROT8STAT_UNION
 结构说明  : DECPROT8STAT 寄存器结构定义。地址偏移量:0x860，初值:0x00000007，宽度:32
 寄存器说明: IP安全属性状态寄存器8。
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved_0: 8;  /* bit[0-7] : 保留。HIEPS未使用。 */
        unsigned int  reserved_1: 23; /* bit[8-30]: 保留。HIEPS未使用。 */
        unsigned int  reserved_2: 1;  /* bit[31]  : 保留。HIEPS未使用。 */
    } reg;
} SOC_ETZPC_DECPROT8STAT_UNION;
#endif


/*****************************************************************************
 结构名    : SOC_ETZPC_DECPROT8SET_UNION
 结构说明  : DECPROT8SET 寄存器结构定义。地址偏移量:0x864，初值:0x00000000，宽度:32
 寄存器说明: IP安全属性置位寄存器8。
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved_0: 8;  /* bit[0-7] : 保留。HIEPS未使用。 */
        unsigned int  reserved_1: 23; /* bit[8-30]: 保留。HIEPS未使用。 */
        unsigned int  reserved_2: 1;  /* bit[31]  : 保留。HIEPS未使用。 */
    } reg;
} SOC_ETZPC_DECPROT8SET_UNION;
#endif


/*****************************************************************************
 结构名    : SOC_ETZPC_DECPROT8CLR_UNION
 结构说明  : DECPROT8CLR 寄存器结构定义。地址偏移量:0x868，初值:0x00000000，宽度:32
 寄存器说明: IP安全属性清零寄存器8。
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved_0: 8;  /* bit[0-7] : 保留。HIEPS未使用。 */
        unsigned int  reserved_1: 23; /* bit[8-30]: 保留。HIEPS未使用。 */
        unsigned int  reserved_2: 1;  /* bit[31]  : 保留。HIEPS未使用。 */
    } reg;
} SOC_ETZPC_DECPROT8CLR_UNION;
#endif


/*****************************************************************************
 结构名    : SOC_ETZPC_REG0_STAT_UNION
 结构说明  : REG0_STAT 寄存器结构定义。地址偏移量:0x86C，初值:0x00000000，宽度:32
 寄存器说明: 控制reg0寄存器的信息。
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved : 32; /* bit[0-31]: 保留。 */
    } reg;
} SOC_ETZPC_REG0_STAT_UNION;
#endif


/*****************************************************************************
 结构名    : SOC_ETZPC_REG1_STAT_UNION
 结构说明  : REG1_STAT 寄存器结构定义。地址偏移量:0x870，初值:0x00000000，宽度:32
 寄存器说明: 控制reg1寄存器的信息。
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved : 32; /* bit[0-31]: 保留。 */
    } reg;
} SOC_ETZPC_REG1_STAT_UNION;
#endif


/*****************************************************************************
 结构名    : SOC_ETZPC_EFUSEC2HIEPS_PATCH0_SEC_UNION
 结构说明  : EFUSEC2HIEPS_PATCH0_SEC 寄存器结构定义。地址偏移量:0x874，初值:0x00000000，宽度:32
 寄存器说明: 寄存PATCH校验信息的寄存器0
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  efusec2hieps_patch0_sec : 32; /* bit[0-31]: 保留。虽然不再使用，但是硬件逻辑保持不变 */
    } reg;
} SOC_ETZPC_EFUSEC2HIEPS_PATCH0_SEC_UNION;
#endif
#define SOC_ETZPC_EFUSEC2HIEPS_PATCH0_SEC_efusec2hieps_patch0_sec_START  (0)
#define SOC_ETZPC_EFUSEC2HIEPS_PATCH0_SEC_efusec2hieps_patch0_sec_END    (31)


/*****************************************************************************
 结构名    : SOC_ETZPC_EFUSEC2HIEPS_PATCH1_SEC_UNION
 结构说明  : EFUSEC2HIEPS_PATCH1_SEC 寄存器结构定义。地址偏移量:0x878，初值:0x00000000，宽度:32
 寄存器说明: 寄存PATCH校验信息的寄存器1
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  efusec2hieps_patch1_sec : 32; /* bit[0-31]: 保留。虽然不再使用，但是硬件逻辑保持不变 */
    } reg;
} SOC_ETZPC_EFUSEC2HIEPS_PATCH1_SEC_UNION;
#endif
#define SOC_ETZPC_EFUSEC2HIEPS_PATCH1_SEC_efusec2hieps_patch1_sec_START  (0)
#define SOC_ETZPC_EFUSEC2HIEPS_PATCH1_SEC_efusec2hieps_patch1_sec_END    (31)


/*****************************************************************************
 结构名    : SOC_ETZPC_EFUSEC2HIEPS_PATCH2_SEC_UNION
 结构说明  : EFUSEC2HIEPS_PATCH2_SEC 寄存器结构定义。地址偏移量:0x87C，初值:0x00000000，宽度:32
 寄存器说明: 寄存PATCH校验信息的寄存器2
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  efusec2hieps_patch2_sec : 32; /* bit[0-31]: 保留。虽然不再使用，但是硬件逻辑保持不变 */
    } reg;
} SOC_ETZPC_EFUSEC2HIEPS_PATCH2_SEC_UNION;
#endif
#define SOC_ETZPC_EFUSEC2HIEPS_PATCH2_SEC_efusec2hieps_patch2_sec_START  (0)
#define SOC_ETZPC_EFUSEC2HIEPS_PATCH2_SEC_efusec2hieps_patch2_sec_END    (31)


/*****************************************************************************
 结构名    : SOC_ETZPC_EFUSEC2HIEPS_PATCH3_SEC_UNION
 结构说明  : EFUSEC2HIEPS_PATCH3_SEC 寄存器结构定义。地址偏移量:0x880，初值:0x00000000，宽度:32
 寄存器说明: 寄存PATCH校验信息的寄存器3
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  efusec2hieps_patch3_sec : 32; /* bit[0-31]: 保留。虽然不再使用，但是硬件逻辑保持不变 */
    } reg;
} SOC_ETZPC_EFUSEC2HIEPS_PATCH3_SEC_UNION;
#endif
#define SOC_ETZPC_EFUSEC2HIEPS_PATCH3_SEC_efusec2hieps_patch3_sec_START  (0)
#define SOC_ETZPC_EFUSEC2HIEPS_PATCH3_SEC_efusec2hieps_patch3_sec_END    (31)


/*****************************************************************************
 结构名    : SOC_ETZPC_EFUSEC2HIEPS_PATCH4_SEC_UNION
 结构说明  : EFUSEC2HIEPS_PATCH4_SEC 寄存器结构定义。地址偏移量:0x884，初值:0x00000000，宽度:32
 寄存器说明: 寄存PATCH校验信息的寄存器4
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  efusec2hieps_patch4_sec : 32; /* bit[0-31]: 保留。虽然不再使用，但是硬件逻辑保持不变 */
    } reg;
} SOC_ETZPC_EFUSEC2HIEPS_PATCH4_SEC_UNION;
#endif
#define SOC_ETZPC_EFUSEC2HIEPS_PATCH4_SEC_efusec2hieps_patch4_sec_START  (0)
#define SOC_ETZPC_EFUSEC2HIEPS_PATCH4_SEC_efusec2hieps_patch4_sec_END    (31)


/*****************************************************************************
 结构名    : SOC_ETZPC_EFUSEC2HIEPS_PATCH5_SEC_UNION
 结构说明  : EFUSEC2HIEPS_PATCH5_SEC 寄存器结构定义。地址偏移量:0x888，初值:0x00000000，宽度:32
 寄存器说明: 寄存PATCH校验信息的寄存器5
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  efusec2hieps_patch5_sec : 32; /* bit[0-31]: 保留。虽然不再使用，但是硬件逻辑保持不变 */
    } reg;
} SOC_ETZPC_EFUSEC2HIEPS_PATCH5_SEC_UNION;
#endif
#define SOC_ETZPC_EFUSEC2HIEPS_PATCH5_SEC_efusec2hieps_patch5_sec_START  (0)
#define SOC_ETZPC_EFUSEC2HIEPS_PATCH5_SEC_efusec2hieps_patch5_sec_END    (31)


/*****************************************************************************
 结构名    : SOC_ETZPC_EFUSEC2HIEPS_PATCH6_SEC_UNION
 结构说明  : EFUSEC2HIEPS_PATCH6_SEC 寄存器结构定义。地址偏移量:0x88C，初值:0x00000000，宽度:32
 寄存器说明: 寄存PATCH校验信息的寄存器6
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  efusec2hieps_patch6_sec : 32; /* bit[0-31]: 保留。虽然不再使用，但是硬件逻辑保持不变 */
    } reg;
} SOC_ETZPC_EFUSEC2HIEPS_PATCH6_SEC_UNION;
#endif
#define SOC_ETZPC_EFUSEC2HIEPS_PATCH6_SEC_efusec2hieps_patch6_sec_START  (0)
#define SOC_ETZPC_EFUSEC2HIEPS_PATCH6_SEC_efusec2hieps_patch6_sec_END    (31)


/*****************************************************************************
 结构名    : SOC_ETZPC_EFUSEC2HIEPS_PATCH7_SEC_UNION
 结构说明  : EFUSEC2HIEPS_PATCH7_SEC 寄存器结构定义。地址偏移量:0x890，初值:0x00000000，宽度:32
 寄存器说明: 寄存PATCH校验信息的寄存器7
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  efusec2hieps_patch7_sec : 32; /* bit[0-31]: 保留。虽然不再使用，但是硬件逻辑保持不变 */
    } reg;
} SOC_ETZPC_EFUSEC2HIEPS_PATCH7_SEC_UNION;
#endif
#define SOC_ETZPC_EFUSEC2HIEPS_PATCH7_SEC_efusec2hieps_patch7_sec_START  (0)
#define SOC_ETZPC_EFUSEC2HIEPS_PATCH7_SEC_efusec2hieps_patch7_sec_END    (31)






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

#endif /* end of soc_etzpc_interface.h */
