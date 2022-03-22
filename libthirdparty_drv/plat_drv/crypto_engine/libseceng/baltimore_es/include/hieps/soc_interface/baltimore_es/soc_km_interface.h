/******************************************************************************

                 版权所有 (C), 2001-2019, 华为技术有限公司

 ******************************************************************************
  文 件 名   : soc_km_interface.h
  版 本 号   : 初稿
  作    者   : Excel2Code
  生成日期   : 2019-10-26 10:53:23
  最近修改   :
  功能描述   : 接口头文件
  函数列表   :
  修改历史   :
  1.日    期   : 2019年10月26日
    作    者   : l00249396
    修改内容   : 从《HiEPS V200 nManager寄存器手册_KM.xml》自动生成

******************************************************************************/

/*****************************************************************************
  1 其他头文件包含
*****************************************************************************/

#ifndef __SOC_KM_INTERFACE_H__
#define __SOC_KM_INTERFACE_H__

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
/* 寄存器说明：KM STR寄存器
   位域定义UNION结构:  SOC_KM_STR_UNION */
#define SOC_KM_STR_ADDR(base)                         ((base) + (0x0000))

/* 寄存器说明：密钥路由寄存器
   位域定义UNION结构:  SOC_KM_MODE_UNION */
#define SOC_KM_MODE_ADDR(base)                        ((base) + (0x0004))

/* 寄存器说明：派生密钥清零信号
   位域定义UNION结构:  SOC_KM_DERIVE_KEY_CLR_UNION */
#define SOC_KM_DERIVE_KEY_CLR_ADDR(base)              ((base) + (0x0008))

/* 寄存器说明：密钥解密完成标志
   位域定义UNION结构:  SOC_KM_KEY_DECRY_DONE_UNION */
#define SOC_KM_KEY_DECRY_DONE_ADDR(base)              ((base) + (0x000C))

/* 寄存器说明：密钥派生完成标志
   位域定义UNION结构:  SOC_KM_KEY_DERIVE_DONE_UNION */
#define SOC_KM_KEY_DERIVE_DONE_ADDR(base)             ((base) + (0x0010))

/* 寄存器说明：密钥派生完成信号清零
   位域定义UNION结构:  SOC_KM_KEY_DERIVE_DONE_CLR_UNION */
#define SOC_KM_KEY_DERIVE_DONE_CLR_ADDR(base)         ((base) + (0x0014))

/* 寄存器说明：KM的测试信号
   位域定义UNION结构:  SOC_KM_DFX_UNION */
#define SOC_KM_DFX_ADDR(base)                         ((base) + (0x0018))

/* 寄存器说明：KM寄存器锁定信号
   位域定义UNION结构:  SOC_KM_REG_LOCK_UNION */
#define SOC_KM_REG_LOCK_ADDR(base)                    ((base) + (0x001C))

/* 寄存器说明：CPU配置的AES KEY
   位域定义UNION结构:  SOC_KM_AES_KEY_UNION */
#define SOC_KM_AES_KEY_ADDR(base, n)                  ((base) + (0x0020+(n)*4))

/* 寄存器说明：CPU配置的DES KEY
   位域定义UNION结构:  SOC_KM_DES_KEY_UNION */
#define SOC_KM_DES_KEY_ADDR(base, n)                  ((base) + (0x0040+(n)*4))

/* 寄存器说明：CPU配置的SM4 KEY
   位域定义UNION结构:  SOC_KM_SM4_KEY_UNION */
#define SOC_KM_SM4_KEY_ADDR(base, n)                  ((base) + (0x0060+(n)*4))

/* 寄存器说明：解密前的kdr
   位域定义UNION结构:  SOC_KM_KDR_IN_UNION */
#define SOC_KM_KDR_IN_ADDR(base, n)                   ((base) + (0x0080+(n)*4))

/* 寄存器说明：解密后的kdr
   位域定义UNION结构:  SOC_KM_KDR_OUT_UNION */
#define SOC_KM_KDR_OUT_ADDR(base, n)                  ((base) + (0x00A0+(n)*4))

/* 寄存器说明：明文的cek
   位域定义UNION结构:  SOC_KM_CEK_IN_UNION */
#define SOC_KM_CEK_IN_ADDR(base, n)                   ((base) + (0x00C0+(n)*4))

/* 寄存器说明：派生KEY
   位域定义UNION结构:  SOC_KM_DERIVE_KEY_UNION */
#define SOC_KM_DERIVE_KEY_ADDR(base, n)               ((base) + (0x0120+(n)*4))

/* 寄存器说明：解密前的gid
   位域定义UNION结构:  SOC_KM_GID_IN_UNION */
#define SOC_KM_GID_IN_ADDR(base, n)                   ((base) + (0x0140+(n)*4))

/* 寄存器说明：解密后的gid
   位域定义UNION结构:  SOC_KM_GID_OUT_UNION */
#define SOC_KM_GID_OUT_ADDR(base, n)                  ((base) + (0x0160+(n)*4))

/* 寄存器说明：解密前的pos
   位域定义UNION结构:  SOC_KM_POS_IN_UNION */
#define SOC_KM_POS_IN_ADDR(base, n)                   ((base) + (0x0180+(n)*4))

/* 寄存器说明：解密后的pos
   位域定义UNION结构:  SOC_KM_POS_OUT_UNION */
#define SOC_KM_POS_OUT_ADDR(base, n)                  ((base) + (0x01A0+(n)*4))

/* 寄存器说明：EPS_GJ_ROTPK的明文
   位域定义UNION结构:  SOC_KM_ROTPK_GJ_UNION */
#define SOC_KM_ROTPK_GJ_ADDR(base, n)                 ((base) + (0x01C0+(n)*4))

/* 寄存器说明：EPS_GM_ROTPK的明文
   位域定义UNION结构:  SOC_KM_ROTPK_GM_UNION */
#define SOC_KM_ROTPK_GM_ADDR(base, n)                 ((base) + (0x01E0+(n)*4))

/* 寄存器说明：告警清零信号
   位域定义UNION结构:  SOC_KM_ALARM_CLR_UNION */
#define SOC_KM_ALARM_CLR_ADDR(base)                   ((base) + (0x0200))

/* 寄存器说明：告警屏蔽信号
   位域定义UNION结构:  SOC_KM_ALARM_MASK_EN_UNION */
#define SOC_KM_ALARM_MASK_EN_ADDR(base)               ((base) + (0x0204))

/* 寄存器说明：alarm信号（屏蔽前）
   位域定义UNION结构:  SOC_KM_ALARM_UNION */
#define SOC_KM_ALARM_ADDR(base)                       ((base) + (0x0208))

/* 寄存器说明：alarm信号（屏蔽后）
   位域定义UNION结构:  SOC_KM_ALARM_MASK_UNION */
#define SOC_KM_ALARM_MASK_ADDR(base)                  ((base) + (0x020C))

/* 寄存器说明：密钥锁定寄存器
   位域定义UNION结构:  SOC_KM_KEY_REG_LOCK_UNION */
#define SOC_KM_KEY_REG_LOCK_ADDR(base)                ((base) + (0x0210))

/* 寄存器说明：AES密钥掩码寄存器
   位域定义UNION结构:  SOC_KM_AESKEY_MASK_VALUE_UNION */
#define SOC_KM_AESKEY_MASK_VALUE_ADDR(base)           ((base) + (0x0214))

/* 寄存器说明：DES密钥掩码寄存器
   位域定义UNION结构:  SOC_KM_DESKEY_MASK_VALUE_UNION */
#define SOC_KM_DESKEY_MASK_VALUE_ADDR(base)           ((base) + (0x0218))

/* 寄存器说明：SM4密钥掩码寄存器
   位域定义UNION结构:  SOC_KM_SM4KEY_MASK_VALUE_UNION */
#define SOC_KM_SM4KEY_MASK_VALUE_ADDR(base)           ((base) + (0x021C))

/* 寄存器说明：AES密钥校验值寄存器
   位域定义UNION结构:  SOC_KM_AES_KEY_PARITY_UNION */
#define SOC_KM_AES_KEY_PARITY_ADDR(base)              ((base) + (0x0220))

/* 寄存器说明：DES密钥校验值寄存器
   位域定义UNION结构:  SOC_KM_DES_KEY_PARITY_UNION */
#define SOC_KM_DES_KEY_PARITY_ADDR(base)              ((base) + (0x0224))

/* 寄存器说明：SM4密钥校验值寄存器
   位域定义UNION结构:  SOC_KM_SM4_KEY_PARITY_UNION */
#define SOC_KM_SM4_KEY_PARITY_ADDR(base)              ((base) + (0x0228))

/* 寄存器说明：密文KDR密钥校验值寄存器
   位域定义UNION结构:  SOC_KM_KDR_IN_PARITY_UNION */
#define SOC_KM_KDR_IN_PARITY_ADDR(base)               ((base) + (0x022C))

/* 寄存器说明：明文KDR密钥校验值寄存器
   位域定义UNION结构:  SOC_KM_KDR_OUT_PARITY_UNION */
#define SOC_KM_KDR_OUT_PARITY_ADDR(base)              ((base) + (0x0230))

/* 寄存器说明：明文CEK密钥校验值寄存器
   位域定义UNION结构:  SOC_KM_CEK_IN_PARITY_UNION */
#define SOC_KM_CEK_IN_PARITY_ADDR(base)               ((base) + (0x0234))

/* 寄存器说明：派生KEY密钥校验值寄存器
   位域定义UNION结构:  SOC_KM_DERIVE_KEY_PARITY_UNION */
#define SOC_KM_DERIVE_KEY_PARITY_ADDR(base)           ((base) + (0x0238))

/* 寄存器说明：CEK密钥掩码寄存器
   位域定义UNION结构:  SOC_KM_CEK_MASK_VALUE_UNION */
#define SOC_KM_CEK_MASK_VALUE_ADDR(base)              ((base) + (0x0248))

/* 寄存器说明：密钥掩码寄存器
   位域定义UNION结构:  SOC_KM_KEY_MASK_VALUE_UNION */
#define SOC_KM_KEY_MASK_VALUE_ADDR(base)              ((base) + (0x024C))

/* 寄存器说明：密文GID密钥校验值寄存器
   位域定义UNION结构:  SOC_KM_GID_IN_PARITY_UNION */
#define SOC_KM_GID_IN_PARITY_ADDR(base)               ((base) + (0x0254))

/* 寄存器说明：明文GID密钥校验值寄存器
   位域定义UNION结构:  SOC_KM_GID_OUT_PARITY_UNION */
#define SOC_KM_GID_OUT_PARITY_ADDR(base)              ((base) + (0x0258))

/* 寄存器说明：密文POS密钥校验值寄存器
   位域定义UNION结构:  SOC_KM_POS_IN_PARITY_UNION */
#define SOC_KM_POS_IN_PARITY_ADDR(base)               ((base) + (0x025C))

/* 寄存器说明：明文POS密钥校验值寄存器
   位域定义UNION结构:  SOC_KM_POS_OUT_PARITY_UNION */
#define SOC_KM_POS_OUT_PARITY_ADDR(base)              ((base) + (0x0260))

/* 寄存器说明：EPS_GJ_ROTPK校验值寄存器
   位域定义UNION结构:  SOC_KM_ROTPK_GJ_PARITY_UNION */
#define SOC_KM_ROTPK_GJ_PARITY_ADDR(base)             ((base) + (0x0264))

/* 寄存器说明：EPS_GM_ROTPK校验值寄存器
   位域定义UNION结构:  SOC_KM_ROTPK_GM_PARITY_UNION */
#define SOC_KM_ROTPK_GM_PARITY_ADDR(base)             ((base) + (0x0268))

/* 寄存器说明：DDR加密密钥
   位域定义UNION结构:  SOC_KM_DDRENC_KEY_UNION */
#define SOC_KM_DDRENC_KEY_ADDR(base, n)               ((base) + (0x026C+(n)*4))

/* 寄存器说明：配置的XTS KEY2
   位域定义UNION结构:  SOC_KM_AES_KEY2_UNION */
#define SOC_KM_AES_KEY2_ADDR(base, n)                 ((base) + (0x0280+(n)*4))

/* 寄存器说明：XTS KEY2的密钥掩码寄存器
   位域定义UNION结构:  SOC_KM_AESKEY2_MASK_VALUE_UNION */
#define SOC_KM_AESKEY2_MASK_VALUE_ADDR(base)          ((base) + (0x02A0))

/* 寄存器说明：XTS KEY2的密钥校验值寄存器
   位域定义UNION结构:  SOC_KM_AES_KEY2_PARITY_UNION */
#define SOC_KM_AES_KEY2_PARITY_ADDR(base)             ((base) + (0x02A4))

/* 寄存器说明：
   位域定义UNION结构:  SOC_KM_DEBUG_SD_UNION */
#define SOC_KM_DEBUG_SD_ADDR(base)                    ((base) + (0x02A8))

/* 寄存器说明：派生不可读key
   位域定义UNION结构:  SOC_KM_DERIVE_KEY_SEC_UNION */
#define SOC_KM_DERIVE_KEY_SEC_ADDR(base, n)           ((base) + (0x02C0+(n)*4))

/* 寄存器说明：派生不可读key的掩码
   位域定义UNION结构:  SOC_KM_DERIVE_KEY_SEC_M_UNION */
#define SOC_KM_DERIVE_KEY_SEC_M_ADDR(base, n)         ((base) + (0x0300+(n)*4))





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
 结构名    : SOC_KM_STR_UNION
 结构说明  : STR 寄存器结构定义。地址偏移量:0x0000，初值:0x00000000，宽度:32
 寄存器说明: KM STR寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  km_str   : 1;  /* bit[0]   : 密钥解密开始工作标志
                                                   1为开始 */
        unsigned int  reserved : 31; /* bit[1-31]:  */
    } reg;
} SOC_KM_STR_UNION;
#endif
#define SOC_KM_STR_km_str_START    (0)
#define SOC_KM_STR_km_str_END      (0)


/*****************************************************************************
 结构名    : SOC_KM_MODE_UNION
 结构说明  : MODE 寄存器结构定义。地址偏移量:0x0004，初值:0x00000000，宽度:32
 寄存器说明: 密钥路由寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  des_key_sel       : 1;  /* bit[0]    : DES_KEY选择
                                                             0:选择CPU配置的明文KEY做为密钥
                                                             1:选择派生出来的KEY做为密钥 */
        unsigned int  reserved_0        : 3;  /* bit[1-3]  :  */
        unsigned int  aes_key_sel       : 3;  /* bit[4-6]  : AES_KEY选择
                                                             0: 选择明文CEK做为密钥
                                                             1: 选择解密后的kdr做为密钥，用来派生新key
                                                             2: 选择GID用来做密钥，用来派生新key或者直接加解密
                                                             3: 选择逻辑KEY做为密钥
                                                             4: 选择cpu配置的明文key做为密钥
                                                             5: 选择派生出来的key做为密钥
                                                             6: 选择POS用来做密钥，用来派生新key或者直接加解密
                                                             其他配置值非法 */
        unsigned int  reserved_1        : 1;  /* bit[7]    :  */
        unsigned int  sm4_key_sel       : 3;  /* bit[8-10] : SM4_KEY选择
                                                             0:选择明文CEK做为密钥
                                                             1:选择cpu配置的明文key做为密钥
                                                             2:选择派生出来的KEY做为密钥
                                                             3:选择GID用来做密钥，用来正常加解密
                                                             4:选择POS用来做密钥，用来正常加解密
                                                             其他配置值非法 */
        unsigned int  reserved_2        : 1;  /* bit[11]   :  */
        unsigned int  km_mode           : 2;  /* bit[12-13]: 密钥管理的模式
                                                             0: 正常加解密
                                                             1: 密钥派生
                                                             2: 密钥解密
                                                             3: RTL KEY直接加密
                                                             其他配置值非法 */
        unsigned int  ddrenc_key_derive : 1;  /* bit[14]   : 指示当前的密钥派生是否为DDR加密KEY的派生
                                                             0: 非DDR加密KEY的派生
                                                             1: DDR加密KEY的派生 */
        unsigned int  kdr_inv           : 1;  /* bit[15]   : 指示使用kdr派生时，是否需要对kdr取反。取反时派生结果不可读。
                                                             0: 不对kdr取反
                                                             1: 对kdr取反 */
        unsigned int  reserved_3        : 16; /* bit[16-31]:  */
    } reg;
} SOC_KM_MODE_UNION;
#endif
#define SOC_KM_MODE_des_key_sel_START        (0)
#define SOC_KM_MODE_des_key_sel_END          (0)
#define SOC_KM_MODE_aes_key_sel_START        (4)
#define SOC_KM_MODE_aes_key_sel_END          (6)
#define SOC_KM_MODE_sm4_key_sel_START        (8)
#define SOC_KM_MODE_sm4_key_sel_END          (10)
#define SOC_KM_MODE_km_mode_START            (12)
#define SOC_KM_MODE_km_mode_END              (13)
#define SOC_KM_MODE_ddrenc_key_derive_START  (14)
#define SOC_KM_MODE_ddrenc_key_derive_END    (14)
#define SOC_KM_MODE_kdr_inv_START            (15)
#define SOC_KM_MODE_kdr_inv_END              (15)


/*****************************************************************************
 结构名    : SOC_KM_DERIVE_KEY_CLR_UNION
 结构说明  : DERIVE_KEY_CLR 寄存器结构定义。地址偏移量:0x0008，初值:0x00000000，宽度:32
 寄存器说明: 派生密钥清零信号
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  derive_key_clr     : 1;  /* bit[0]   : 对派生出的密钥清零（派生密钥可读时）
                                                             只要配置该寄存器就会清零 */
        unsigned int  derive_key_sec_clr : 1;  /* bit[1]   : 对派生出的密钥清零（派生密钥不可读时）
                                                             只要配置该寄存器就会清零 */
        unsigned int  reserved           : 30; /* bit[2-31]:  */
    } reg;
} SOC_KM_DERIVE_KEY_CLR_UNION;
#endif
#define SOC_KM_DERIVE_KEY_CLR_derive_key_clr_START      (0)
#define SOC_KM_DERIVE_KEY_CLR_derive_key_clr_END        (0)
#define SOC_KM_DERIVE_KEY_CLR_derive_key_sec_clr_START  (1)
#define SOC_KM_DERIVE_KEY_CLR_derive_key_sec_clr_END    (1)


/*****************************************************************************
 结构名    : SOC_KM_KEY_DECRY_DONE_UNION
 结构说明  : KEY_DECRY_DONE 寄存器结构定义。地址偏移量:0x000C，初值:0x00000000，宽度:32
 寄存器说明: 密钥解密完成标志
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  key_decry_done : 1;  /* bit[0]   : 密钥解密完成标志
                                                         0:密钥解密未完成
                                                         1:密钥解密完成 */
        unsigned int  reserved       : 31; /* bit[1-31]:  */
    } reg;
} SOC_KM_KEY_DECRY_DONE_UNION;
#endif
#define SOC_KM_KEY_DECRY_DONE_key_decry_done_START  (0)
#define SOC_KM_KEY_DECRY_DONE_key_decry_done_END    (0)


/*****************************************************************************
 结构名    : SOC_KM_KEY_DERIVE_DONE_UNION
 结构说明  : KEY_DERIVE_DONE 寄存器结构定义。地址偏移量:0x0010，初值:0x00000000，宽度:32
 寄存器说明: 密钥派生完成标志
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  key_derive_done : 1;  /* bit[0]   : 密钥派生完成标志
                                                          0:密钥派生未完成
                                                          1:密钥派生完成 */
        unsigned int  reserved        : 31; /* bit[1-31]:  */
    } reg;
} SOC_KM_KEY_DERIVE_DONE_UNION;
#endif
#define SOC_KM_KEY_DERIVE_DONE_key_derive_done_START  (0)
#define SOC_KM_KEY_DERIVE_DONE_key_derive_done_END    (0)


/*****************************************************************************
 结构名    : SOC_KM_KEY_DERIVE_DONE_CLR_UNION
 结构说明  : KEY_DERIVE_DONE_CLR 寄存器结构定义。地址偏移量:0x0014，初值:0x00000000，宽度:32
 寄存器说明: 密钥派生完成信号清零
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  key_derive_done_clr : 1;  /* bit[0]   : 对派生出的密钥完成信号进行清零
                                                              只要配置该寄存器就会清零 */
        unsigned int  reserved            : 31; /* bit[1-31]:  */
    } reg;
} SOC_KM_KEY_DERIVE_DONE_CLR_UNION;
#endif
#define SOC_KM_KEY_DERIVE_DONE_CLR_key_derive_done_clr_START  (0)
#define SOC_KM_KEY_DERIVE_DONE_CLR_key_derive_done_clr_END    (0)


/*****************************************************************************
 结构名    : SOC_KM_DFX_UNION
 结构说明  : DFX 寄存器结构定义。地址偏移量:0x0018，初值:0x00000001，宽度:32
 寄存器说明: KM的测试信号
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  key_decry_state : 16; /* bit[0-15] : 密钥解密的状态机处于哪个状态，用于调试定位问题
                                                           0x0001:KEY_DECRY_IDLE
                                                           0x0002:KEY_DECRY_STR
                                                           0x0004:KDR_RD
                                                           0x0080:KEY_DECRY
                                                           0x0100:DECRY_STORE
                                                           0x0200:DECRY_ALARM */
        unsigned int  keyid_cnt       : 1;  /* bit[16]   : 固定为0 */
        unsigned int  reserved_0      : 3;  /* bit[17-19]:  */
        unsigned int  key_lenth_cnt   : 2;  /* bit[20-21]: key_lenth_cnt，用于调试定位 */
        unsigned int  reserved_1      : 10; /* bit[22-31]:  */
    } reg;
} SOC_KM_DFX_UNION;
#endif
#define SOC_KM_DFX_key_decry_state_START  (0)
#define SOC_KM_DFX_key_decry_state_END    (15)
#define SOC_KM_DFX_keyid_cnt_START        (16)
#define SOC_KM_DFX_keyid_cnt_END          (16)
#define SOC_KM_DFX_key_lenth_cnt_START    (20)
#define SOC_KM_DFX_key_lenth_cnt_END      (21)


/*****************************************************************************
 结构名    : SOC_KM_REG_LOCK_UNION
 结构说明  : REG_LOCK 寄存器结构定义。地址偏移量:0x001C，初值:0x00000005，宽度:32
 寄存器说明: KM寄存器锁定信号
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  km_reg_lock : 4;  /* bit[0-3] : 寄存器的读写锁定，默认为0x5
                                                      0x5：锁定，任何寄存器均不可写
                                                      0xa：未锁定，寄存器可写
                                                      其他值非法 */
        unsigned int  reserved    : 28; /* bit[4-31]:  */
    } reg;
} SOC_KM_REG_LOCK_UNION;
#endif
#define SOC_KM_REG_LOCK_km_reg_lock_START  (0)
#define SOC_KM_REG_LOCK_km_reg_lock_END    (3)


/*****************************************************************************
 结构名    : SOC_KM_AES_KEY_UNION
 结构说明  : AES_KEY 寄存器结构定义。地址偏移量:0x0020+(n)*4，初值:0x00000000，宽度:32
 寄存器说明: CPU配置的AES KEY
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  aes_key : 32; /* bit[0-31]: n=0时，对应key的高32位,n的范围0-7，所有key为小端方式，调试模式可读 */
    } reg;
} SOC_KM_AES_KEY_UNION;
#endif
#define SOC_KM_AES_KEY_aes_key_START  (0)
#define SOC_KM_AES_KEY_aes_key_END    (31)


/*****************************************************************************
 结构名    : SOC_KM_DES_KEY_UNION
 结构说明  : DES_KEY 寄存器结构定义。地址偏移量:0x0040+(n)*4，初值:0x00000000，宽度:32
 寄存器说明: CPU配置的DES KEY
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  aes_key : 32; /* bit[0-31]: n=0,2,4时，对应des_key_x的高32位,n的范围0-5，所有key为小端方式
                                                  n=0,1,对应des_key1
                                                  n=2,3,对应des_key2
                                                  n=4,5,对应des_key3
                                                  ，调试模式可读 */
    } reg;
} SOC_KM_DES_KEY_UNION;
#endif
#define SOC_KM_DES_KEY_aes_key_START  (0)
#define SOC_KM_DES_KEY_aes_key_END    (31)


/*****************************************************************************
 结构名    : SOC_KM_SM4_KEY_UNION
 结构说明  : SM4_KEY 寄存器结构定义。地址偏移量:0x0060+(n)*4，初值:0x00000000，宽度:32
 寄存器说明: CPU配置的SM4 KEY
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  aes_key : 32; /* bit[0-31]: n=0时，对应key的高32位,n的范围0-3，所有key为小端方式，调试模式可读 */
    } reg;
} SOC_KM_SM4_KEY_UNION;
#endif
#define SOC_KM_SM4_KEY_aes_key_START  (0)
#define SOC_KM_SM4_KEY_aes_key_END    (31)


/*****************************************************************************
 结构名    : SOC_KM_KDR_IN_UNION
 结构说明  : KDR_IN 寄存器结构定义。地址偏移量:0x0080+(n)*4，初值:0x00000000，宽度:32
 寄存器说明: 解密前的kdr
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  kdr_in : 32; /* bit[0-31]: n=0时，对应key的高32位,n的范围0-7,解密前的kdr，所有key为小端方式 */
    } reg;
} SOC_KM_KDR_IN_UNION;
#endif
#define SOC_KM_KDR_IN_kdr_in_START  (0)
#define SOC_KM_KDR_IN_kdr_in_END    (31)


/*****************************************************************************
 结构名    : SOC_KM_KDR_OUT_UNION
 结构说明  : KDR_OUT 寄存器结构定义。地址偏移量:0x00A0+(n)*4，初值:0x00000000，宽度:32
 寄存器说明: 解密后的kdr
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  kdr_out : 32; /* bit[0-31]: n=0时，对应key的高32位,n的范围0-7,密文kdr密钥解密后的输出值，所有key为小端方式 */
    } reg;
} SOC_KM_KDR_OUT_UNION;
#endif
#define SOC_KM_KDR_OUT_kdr_out_START  (0)
#define SOC_KM_KDR_OUT_kdr_out_END    (31)


/*****************************************************************************
 结构名    : SOC_KM_CEK_IN_UNION
 结构说明  : CEK_IN 寄存器结构定义。地址偏移量:0x00C0+(n)*4，初值:0x00000000，宽度:32
 寄存器说明: 明文的cek
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  cek_in : 32; /* bit[0-31]: n=0时，对应key的高32位,n的范围0-3,所有key为小端方式，，调试模式可读 */
    } reg;
} SOC_KM_CEK_IN_UNION;
#endif
#define SOC_KM_CEK_IN_cek_in_START  (0)
#define SOC_KM_CEK_IN_cek_in_END    (31)


/*****************************************************************************
 结构名    : SOC_KM_DERIVE_KEY_UNION
 结构说明  : DERIVE_KEY 寄存器结构定义。地址偏移量:0x0120+(n)*4，初值:0x00000000，宽度:32
 寄存器说明: 派生KEY
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  derive_key : 32; /* bit[0-31]: n=0时，对应key的高32位,n的范围0-3，所有key为小端方式。 */
    } reg;
} SOC_KM_DERIVE_KEY_UNION;
#endif
#define SOC_KM_DERIVE_KEY_derive_key_START  (0)
#define SOC_KM_DERIVE_KEY_derive_key_END    (31)


/*****************************************************************************
 结构名    : SOC_KM_GID_IN_UNION
 结构说明  : GID_IN 寄存器结构定义。地址偏移量:0x0140+(n)*4，初值:0x00000000，宽度:32
 寄存器说明: 解密前的gid
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  gid_in : 32; /* bit[0-31]: n=0时，对应key的高32位,n的范围0-3,解密前的gid，所有key为小端方式 */
    } reg;
} SOC_KM_GID_IN_UNION;
#endif
#define SOC_KM_GID_IN_gid_in_START  (0)
#define SOC_KM_GID_IN_gid_in_END    (31)


/*****************************************************************************
 结构名    : SOC_KM_GID_OUT_UNION
 结构说明  : GID_OUT 寄存器结构定义。地址偏移量:0x0160+(n)*4，初值:0x00000000，宽度:32
 寄存器说明: 解密后的gid
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  gid_out : 32; /* bit[0-31]: n=0时，对应key的高32位,n的范围0-3,密文gid密钥解密后的输出值，所有key为小端方式 */
    } reg;
} SOC_KM_GID_OUT_UNION;
#endif
#define SOC_KM_GID_OUT_gid_out_START  (0)
#define SOC_KM_GID_OUT_gid_out_END    (31)


/*****************************************************************************
 结构名    : SOC_KM_POS_IN_UNION
 结构说明  : POS_IN 寄存器结构定义。地址偏移量:0x0180+(n)*4，初值:0x00000000，宽度:32
 寄存器说明: 解密前的pos
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  pos_in : 32; /* bit[0-31]: n=0时，对应key的高32位,n的范围0-3,解密前的pos，所有key为小端方式 */
    } reg;
} SOC_KM_POS_IN_UNION;
#endif
#define SOC_KM_POS_IN_pos_in_START  (0)
#define SOC_KM_POS_IN_pos_in_END    (31)


/*****************************************************************************
 结构名    : SOC_KM_POS_OUT_UNION
 结构说明  : POS_OUT 寄存器结构定义。地址偏移量:0x01A0+(n)*4，初值:0x00000000，宽度:32
 寄存器说明: 解密后的pos
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  pos_out : 32; /* bit[0-31]: n=0时，对应key的高32位,n的范围0-3,密文pos密钥解密后的输出值，所有key为小端方式 */
    } reg;
} SOC_KM_POS_OUT_UNION;
#endif
#define SOC_KM_POS_OUT_pos_out_START  (0)
#define SOC_KM_POS_OUT_pos_out_END    (31)


/*****************************************************************************
 结构名    : SOC_KM_ROTPK_GJ_UNION
 结构说明  : ROTPK_GJ 寄存器结构定义。地址偏移量:0x01C0+(n)*4，初值:0x00000000，宽度:32
 寄存器说明: EPS_GJ_ROTPK的明文
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  rotpk_gj_out : 32; /* bit[0-31]: n=0时，对应key的高32位,n的范围0-7,EPS_GJ_ROTPK的输出值，所有key为小端方式 */
    } reg;
} SOC_KM_ROTPK_GJ_UNION;
#endif
#define SOC_KM_ROTPK_GJ_rotpk_gj_out_START  (0)
#define SOC_KM_ROTPK_GJ_rotpk_gj_out_END    (31)


/*****************************************************************************
 结构名    : SOC_KM_ROTPK_GM_UNION
 结构说明  : ROTPK_GM 寄存器结构定义。地址偏移量:0x01E0+(n)*4，初值:0x00000000，宽度:32
 寄存器说明: EPS_GM_ROTPK的明文
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  rotpk_gm_out : 32; /* bit[0-31]: n=0时，对应key的高32位,n的范围0-7,EPS_GM_ROTPK的输出值，所有key为小端方式 */
    } reg;
} SOC_KM_ROTPK_GM_UNION;
#endif
#define SOC_KM_ROTPK_GM_rotpk_gm_out_START  (0)
#define SOC_KM_ROTPK_GM_rotpk_gm_out_END    (31)


/*****************************************************************************
 结构名    : SOC_KM_ALARM_CLR_UNION
 结构说明  : ALARM_CLR 寄存器结构定义。地址偏移量:0x0200，初值:0x0000AAAA，宽度:32
 寄存器说明: 告警清零信号
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  alarm_critical_clr   : 4;  /* bit[0-3]  : 对km各个模块产生的alarm信号清零
                                                                4'h5:对告警信号清零
                                                                4'ha:不对告警信号清零
                                                                其他值非法 */
        unsigned int  alarm_reg_check_clr  : 4;  /* bit[4-7]  : 对寄存器合法性检查产生的alarm信号清零
                                                                4'h5:对告警信号清零
                                                                4'ha:不对告警信号清零
                                                                其他值非法 */
        unsigned int  alarm_reg_access_clr : 4;  /* bit[8-11] : 对LOCK后读写寄存器产生的alarm信号信号清零
                                                                4'h5:对告警信号清零
                                                                4'ha:不对告警信号清零
                                                                其他值非法 */
        unsigned int  alarm_key_check_clr  : 4;  /* bit[12-15]: 对KEY 检查产生的alarm信号信号清零
                                                                4'h5:对告警信号清零
                                                                4'ha:不对告警信号清零
                                                                其他值非法 */
        unsigned int  reserved             : 16; /* bit[16-31]:  */
    } reg;
} SOC_KM_ALARM_CLR_UNION;
#endif
#define SOC_KM_ALARM_CLR_alarm_critical_clr_START    (0)
#define SOC_KM_ALARM_CLR_alarm_critical_clr_END      (3)
#define SOC_KM_ALARM_CLR_alarm_reg_check_clr_START   (4)
#define SOC_KM_ALARM_CLR_alarm_reg_check_clr_END     (7)
#define SOC_KM_ALARM_CLR_alarm_reg_access_clr_START  (8)
#define SOC_KM_ALARM_CLR_alarm_reg_access_clr_END    (11)
#define SOC_KM_ALARM_CLR_alarm_key_check_clr_START   (12)
#define SOC_KM_ALARM_CLR_alarm_key_check_clr_END     (15)


/*****************************************************************************
 结构名    : SOC_KM_ALARM_MASK_EN_UNION
 结构说明  : ALARM_MASK_EN 寄存器结构定义。地址偏移量:0x0204，初值:0x00005555，宽度:32
 寄存器说明: 告警屏蔽信号
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  alarm_critical_mask_en   : 4;  /* bit[0-3]  : 对km各个模块产生的alarm信号屏蔽,默认屏蔽
                                                                    4'h5:对告警信号屏蔽
                                                                    4'ha:不对告警信号不屏蔽,
                                                                    其他值非法 */
        unsigned int  alarm_reg_check_mask_en  : 4;  /* bit[4-7]  : 对寄存器合法性检查产生的alarm信号屏蔽,默认屏蔽
                                                                    4'h5:对告警信号屏蔽
                                                                    4'ha:不对告警信号不屏蔽,
                                                                    其他值非法 */
        unsigned int  alarm_reg_access_mask_en : 4;  /* bit[8-11] : 对LOCK后读写寄存器产生的alarm信号信号屏蔽，默认屏蔽
                                                                    4'h5:对告警信号屏蔽
                                                                    4'ha:不对告警信号不屏蔽,
                                                                    其他值非法 */
        unsigned int  alarm_key_check_mask_en  : 4;  /* bit[12-15]: KEY检查产生的alarm信号信号屏蔽，默认屏蔽
                                                                    4'h5:对告警信号屏蔽
                                                                    4'ha:不对告警信号不屏蔽,
                                                                    其他值非法 */
        unsigned int  reserved                 : 16; /* bit[16-31]:  */
    } reg;
} SOC_KM_ALARM_MASK_EN_UNION;
#endif
#define SOC_KM_ALARM_MASK_EN_alarm_critical_mask_en_START    (0)
#define SOC_KM_ALARM_MASK_EN_alarm_critical_mask_en_END      (3)
#define SOC_KM_ALARM_MASK_EN_alarm_reg_check_mask_en_START   (4)
#define SOC_KM_ALARM_MASK_EN_alarm_reg_check_mask_en_END     (7)
#define SOC_KM_ALARM_MASK_EN_alarm_reg_access_mask_en_START  (8)
#define SOC_KM_ALARM_MASK_EN_alarm_reg_access_mask_en_END    (11)
#define SOC_KM_ALARM_MASK_EN_alarm_key_check_mask_en_START   (12)
#define SOC_KM_ALARM_MASK_EN_alarm_key_check_mask_en_END     (15)


/*****************************************************************************
 结构名    : SOC_KM_ALARM_UNION
 结构说明  : ALARM 寄存器结构定义。地址偏移量:0x0208，初值:0x00000000，宽度:32
 寄存器说明: alarm信号（屏蔽前）
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  alarm_critical   : 1;  /* bit[0]   : km各个模块产生的alarm信号
                                                           1:表示有alarm
                                                           0:没有alarm */
        unsigned int  alarm_reg_check  : 1;  /* bit[1]   : 寄存器合法性检查产生的alarm信号
                                                           1:表示有alarm
                                                           0:没有alarm */
        unsigned int  alarm_reg_access : 1;  /* bit[2]   : LOCK后读写寄存器产生的alarm信号
                                                           1:表示有alarm
                                                           0:没有alarm */
        unsigned int  alarm_key_check  : 1;  /* bit[3]   : KEY检查产生的alarm信号
                                                           1:表示有alarm
                                                           0:没有alarm */
        unsigned int  reserved         : 28; /* bit[4-31]:  */
    } reg;
} SOC_KM_ALARM_UNION;
#endif
#define SOC_KM_ALARM_alarm_critical_START    (0)
#define SOC_KM_ALARM_alarm_critical_END      (0)
#define SOC_KM_ALARM_alarm_reg_check_START   (1)
#define SOC_KM_ALARM_alarm_reg_check_END     (1)
#define SOC_KM_ALARM_alarm_reg_access_START  (2)
#define SOC_KM_ALARM_alarm_reg_access_END    (2)
#define SOC_KM_ALARM_alarm_key_check_START   (3)
#define SOC_KM_ALARM_alarm_key_check_END     (3)


/*****************************************************************************
 结构名    : SOC_KM_ALARM_MASK_UNION
 结构说明  : ALARM_MASK 寄存器结构定义。地址偏移量:0x020C，初值:0x00000000，宽度:32
 寄存器说明: alarm信号（屏蔽后）
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  alarm_critical_mask   : 1;  /* bit[0]   : km各个模块产生的alarm信号
                                                                1:表示有alarm
                                                                0:没有alarm */
        unsigned int  alarm_reg_check_mask  : 1;  /* bit[1]   : 寄存器合法性检查产生的alarm信号
                                                                1:表示有alarm
                                                                0:没有alarm */
        unsigned int  alarm_reg_access_mask : 1;  /* bit[2]   : LOCK后读写寄存器产生的alarm信号
                                                                1:表示有alarm
                                                                0:没有alarm */
        unsigned int  alarm_key_check       : 1;  /* bit[3]   : KEY检查产生的alarm信号
                                                                1:表示有alarm
                                                                0:没有alarm */
        unsigned int  reserved              : 28; /* bit[4-31]:  */
    } reg;
} SOC_KM_ALARM_MASK_UNION;
#endif
#define SOC_KM_ALARM_MASK_alarm_critical_mask_START    (0)
#define SOC_KM_ALARM_MASK_alarm_critical_mask_END      (0)
#define SOC_KM_ALARM_MASK_alarm_reg_check_mask_START   (1)
#define SOC_KM_ALARM_MASK_alarm_reg_check_mask_END     (1)
#define SOC_KM_ALARM_MASK_alarm_reg_access_mask_START  (2)
#define SOC_KM_ALARM_MASK_alarm_reg_access_mask_END    (2)
#define SOC_KM_ALARM_MASK_alarm_key_check_START        (3)
#define SOC_KM_ALARM_MASK_alarm_key_check_END          (3)


/*****************************************************************************
 结构名    : SOC_KM_KEY_REG_LOCK_UNION
 结构说明  : KEY_REG_LOCK 寄存器结构定义。地址偏移量:0x0210，初值:0x00000005，宽度:32
 寄存器说明: 密钥锁定寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  key_lock : 4;  /* bit[0-3] : key寄存器的读写锁定，默认为0x5
                                                   0x5：锁定，任何key寄存器均不可读写
                                                   0xa：未锁定，key寄存器可读写
                                                   其他值非法 */
        unsigned int  reserved : 28; /* bit[4-31]:  */
    } reg;
} SOC_KM_KEY_REG_LOCK_UNION;
#endif
#define SOC_KM_KEY_REG_LOCK_key_lock_START  (0)
#define SOC_KM_KEY_REG_LOCK_key_lock_END    (3)


/*****************************************************************************
 结构名    : SOC_KM_AESKEY_MASK_VALUE_UNION
 结构说明  : AESKEY_MASK_VALUE 寄存器结构定义。地址偏移量:0x0214，初值:0x00000000，宽度:32
 寄存器说明: AES密钥掩码寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  aeskey_mask_value : 32; /* bit[0-31]: key的掩码值 */
    } reg;
} SOC_KM_AESKEY_MASK_VALUE_UNION;
#endif
#define SOC_KM_AESKEY_MASK_VALUE_aeskey_mask_value_START  (0)
#define SOC_KM_AESKEY_MASK_VALUE_aeskey_mask_value_END    (31)


/*****************************************************************************
 结构名    : SOC_KM_DESKEY_MASK_VALUE_UNION
 结构说明  : DESKEY_MASK_VALUE 寄存器结构定义。地址偏移量:0x0218，初值:0x00000000，宽度:32
 寄存器说明: DES密钥掩码寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  deskey_mask_value : 32; /* bit[0-31]: key的掩码值 */
    } reg;
} SOC_KM_DESKEY_MASK_VALUE_UNION;
#endif
#define SOC_KM_DESKEY_MASK_VALUE_deskey_mask_value_START  (0)
#define SOC_KM_DESKEY_MASK_VALUE_deskey_mask_value_END    (31)


/*****************************************************************************
 结构名    : SOC_KM_SM4KEY_MASK_VALUE_UNION
 结构说明  : SM4KEY_MASK_VALUE 寄存器结构定义。地址偏移量:0x021C，初值:0x00000000，宽度:32
 寄存器说明: SM4密钥掩码寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sm4key_mask_value : 32; /* bit[0-31]: key的掩码值 */
    } reg;
} SOC_KM_SM4KEY_MASK_VALUE_UNION;
#endif
#define SOC_KM_SM4KEY_MASK_VALUE_sm4key_mask_value_START  (0)
#define SOC_KM_SM4KEY_MASK_VALUE_sm4key_mask_value_END    (31)


/*****************************************************************************
 结构名    : SOC_KM_AES_KEY_PARITY_UNION
 结构说明  : AES_KEY_PARITY 寄存器结构定义。地址偏移量:0x0220，初值:0x00000000，宽度:32
 寄存器说明: AES密钥校验值寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  aes_key_parity : 32; /* bit[0-31]: AES密钥校验值寄存器 */
    } reg;
} SOC_KM_AES_KEY_PARITY_UNION;
#endif
#define SOC_KM_AES_KEY_PARITY_aes_key_parity_START  (0)
#define SOC_KM_AES_KEY_PARITY_aes_key_parity_END    (31)


/*****************************************************************************
 结构名    : SOC_KM_DES_KEY_PARITY_UNION
 结构说明  : DES_KEY_PARITY 寄存器结构定义。地址偏移量:0x0224，初值:0x00000000，宽度:32
 寄存器说明: DES密钥校验值寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  des_key_parity : 32; /* bit[0-31]: DES密钥校验值寄存器 */
    } reg;
} SOC_KM_DES_KEY_PARITY_UNION;
#endif
#define SOC_KM_DES_KEY_PARITY_des_key_parity_START  (0)
#define SOC_KM_DES_KEY_PARITY_des_key_parity_END    (31)


/*****************************************************************************
 结构名    : SOC_KM_SM4_KEY_PARITY_UNION
 结构说明  : SM4_KEY_PARITY 寄存器结构定义。地址偏移量:0x0228，初值:0x00000000，宽度:32
 寄存器说明: SM4密钥校验值寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sm4_key_parity : 32; /* bit[0-31]: SM4密钥校验值寄存器 */
    } reg;
} SOC_KM_SM4_KEY_PARITY_UNION;
#endif
#define SOC_KM_SM4_KEY_PARITY_sm4_key_parity_START  (0)
#define SOC_KM_SM4_KEY_PARITY_sm4_key_parity_END    (31)


/*****************************************************************************
 结构名    : SOC_KM_KDR_IN_PARITY_UNION
 结构说明  : KDR_IN_PARITY 寄存器结构定义。地址偏移量:0x022C，初值:0x00000000，宽度:32
 寄存器说明: 密文KDR密钥校验值寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  kdr_in_parity : 32; /* bit[0-31]: 密文KDR密钥校验值寄存器 */
    } reg;
} SOC_KM_KDR_IN_PARITY_UNION;
#endif
#define SOC_KM_KDR_IN_PARITY_kdr_in_parity_START  (0)
#define SOC_KM_KDR_IN_PARITY_kdr_in_parity_END    (31)


/*****************************************************************************
 结构名    : SOC_KM_KDR_OUT_PARITY_UNION
 结构说明  : KDR_OUT_PARITY 寄存器结构定义。地址偏移量:0x0230，初值:0x00000000，宽度:32
 寄存器说明: 明文KDR密钥校验值寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  kdr_out_parity : 32; /* bit[0-31]: 明文KDR密钥校验值寄存器 */
    } reg;
} SOC_KM_KDR_OUT_PARITY_UNION;
#endif
#define SOC_KM_KDR_OUT_PARITY_kdr_out_parity_START  (0)
#define SOC_KM_KDR_OUT_PARITY_kdr_out_parity_END    (31)


/*****************************************************************************
 结构名    : SOC_KM_CEK_IN_PARITY_UNION
 结构说明  : CEK_IN_PARITY 寄存器结构定义。地址偏移量:0x0234，初值:0x00000000，宽度:32
 寄存器说明: 明文CEK密钥校验值寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  cek_in_parity : 32; /* bit[0-31]: 明文CEK密钥校验值寄存器 */
    } reg;
} SOC_KM_CEK_IN_PARITY_UNION;
#endif
#define SOC_KM_CEK_IN_PARITY_cek_in_parity_START  (0)
#define SOC_KM_CEK_IN_PARITY_cek_in_parity_END    (31)


/*****************************************************************************
 结构名    : SOC_KM_DERIVE_KEY_PARITY_UNION
 结构说明  : DERIVE_KEY_PARITY 寄存器结构定义。地址偏移量:0x0238，初值:0x00000000，宽度:32
 寄存器说明: 派生KEY密钥校验值寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  derive_key_parity : 32; /* bit[0-31]: 派生出来的key的密钥校验值寄存器 */
    } reg;
} SOC_KM_DERIVE_KEY_PARITY_UNION;
#endif
#define SOC_KM_DERIVE_KEY_PARITY_derive_key_parity_START  (0)
#define SOC_KM_DERIVE_KEY_PARITY_derive_key_parity_END    (31)


/*****************************************************************************
 结构名    : SOC_KM_CEK_MASK_VALUE_UNION
 结构说明  : CEK_MASK_VALUE 寄存器结构定义。地址偏移量:0x0248，初值:0x00000000，宽度:32
 寄存器说明: CEK密钥掩码寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  cek_mask_value : 32; /* bit[0-31]: 配置的cek的掩码值 */
    } reg;
} SOC_KM_CEK_MASK_VALUE_UNION;
#endif
#define SOC_KM_CEK_MASK_VALUE_cek_mask_value_START  (0)
#define SOC_KM_CEK_MASK_VALUE_cek_mask_value_END    (31)


/*****************************************************************************
 结构名    : SOC_KM_KEY_MASK_VALUE_UNION
 结构说明  : KEY_MASK_VALUE 寄存器结构定义。地址偏移量:0x024C，初值:0x00000000，宽度:32
 寄存器说明: 密钥掩码寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  key_mask_value : 32; /* bit[0-31]: 上报的key的掩码值 */
    } reg;
} SOC_KM_KEY_MASK_VALUE_UNION;
#endif
#define SOC_KM_KEY_MASK_VALUE_key_mask_value_START  (0)
#define SOC_KM_KEY_MASK_VALUE_key_mask_value_END    (31)


/*****************************************************************************
 结构名    : SOC_KM_GID_IN_PARITY_UNION
 结构说明  : GID_IN_PARITY 寄存器结构定义。地址偏移量:0x0254，初值:0x00000000，宽度:32
 寄存器说明: 密文GID密钥校验值寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  gid_in_parity : 32; /* bit[0-31]: 密文GID密钥校验值寄存器 */
    } reg;
} SOC_KM_GID_IN_PARITY_UNION;
#endif
#define SOC_KM_GID_IN_PARITY_gid_in_parity_START  (0)
#define SOC_KM_GID_IN_PARITY_gid_in_parity_END    (31)


/*****************************************************************************
 结构名    : SOC_KM_GID_OUT_PARITY_UNION
 结构说明  : GID_OUT_PARITY 寄存器结构定义。地址偏移量:0x0258，初值:0x00000000，宽度:32
 寄存器说明: 明文GID密钥校验值寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  gid_out_parity : 32; /* bit[0-31]: 明文GID密钥校验值寄存器 */
    } reg;
} SOC_KM_GID_OUT_PARITY_UNION;
#endif
#define SOC_KM_GID_OUT_PARITY_gid_out_parity_START  (0)
#define SOC_KM_GID_OUT_PARITY_gid_out_parity_END    (31)


/*****************************************************************************
 结构名    : SOC_KM_POS_IN_PARITY_UNION
 结构说明  : POS_IN_PARITY 寄存器结构定义。地址偏移量:0x025C，初值:0x00000000，宽度:32
 寄存器说明: 密文POS密钥校验值寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  pos_in_parity : 32; /* bit[0-31]: 密文POS密钥校验值寄存器 */
    } reg;
} SOC_KM_POS_IN_PARITY_UNION;
#endif
#define SOC_KM_POS_IN_PARITY_pos_in_parity_START  (0)
#define SOC_KM_POS_IN_PARITY_pos_in_parity_END    (31)


/*****************************************************************************
 结构名    : SOC_KM_POS_OUT_PARITY_UNION
 结构说明  : POS_OUT_PARITY 寄存器结构定义。地址偏移量:0x0260，初值:0x00000000，宽度:32
 寄存器说明: 明文POS密钥校验值寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  pos_out_parity : 32; /* bit[0-31]: 明文POS密钥校验值寄存器 */
    } reg;
} SOC_KM_POS_OUT_PARITY_UNION;
#endif
#define SOC_KM_POS_OUT_PARITY_pos_out_parity_START  (0)
#define SOC_KM_POS_OUT_PARITY_pos_out_parity_END    (31)


/*****************************************************************************
 结构名    : SOC_KM_ROTPK_GJ_PARITY_UNION
 结构说明  : ROTPK_GJ_PARITY 寄存器结构定义。地址偏移量:0x0264，初值:0x00000000，宽度:32
 寄存器说明: EPS_GJ_ROTPK校验值寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  rotpk_gj_parity : 32; /* bit[0-31]: EPS_GJ_ROTPK校验值寄存器 */
    } reg;
} SOC_KM_ROTPK_GJ_PARITY_UNION;
#endif
#define SOC_KM_ROTPK_GJ_PARITY_rotpk_gj_parity_START  (0)
#define SOC_KM_ROTPK_GJ_PARITY_rotpk_gj_parity_END    (31)


/*****************************************************************************
 结构名    : SOC_KM_ROTPK_GM_PARITY_UNION
 结构说明  : ROTPK_GM_PARITY 寄存器结构定义。地址偏移量:0x0268，初值:0x00000000，宽度:32
 寄存器说明: EPS_GM_ROTPK校验值寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  rotpk_gm_parity : 32; /* bit[0-31]: EPS_GM_ROTPK校验值寄存器 */
    } reg;
} SOC_KM_ROTPK_GM_PARITY_UNION;
#endif
#define SOC_KM_ROTPK_GM_PARITY_rotpk_gm_parity_START  (0)
#define SOC_KM_ROTPK_GM_PARITY_rotpk_gm_parity_END    (31)


/*****************************************************************************
 结构名    : SOC_KM_DDRENC_KEY_UNION
 结构说明  : DDRENC_KEY 寄存器结构定义。地址偏移量:0x026C+(n)*4，初值:0x00000000，宽度:32
 寄存器说明: DDR加密密钥
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ddrenc_key : 32; /* bit[0-31]: n=0时，对应key的高32位,n的范围0-3,DDR加密使用的密钥，所有key为小端方式 */
    } reg;
} SOC_KM_DDRENC_KEY_UNION;
#endif
#define SOC_KM_DDRENC_KEY_ddrenc_key_START  (0)
#define SOC_KM_DDRENC_KEY_ddrenc_key_END    (31)


/*****************************************************************************
 结构名    : SOC_KM_AES_KEY2_UNION
 结构说明  : AES_KEY2 寄存器结构定义。地址偏移量:0x0280+(n)*4，初值:0x0000，宽度:32
 寄存器说明: 配置的XTS KEY2
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  aes_key2 : 32; /* bit[0-31]: n=0时，对应key的高32位,n的范围0-7，所有key为小端方式，调试模式可读 */
    } reg;
} SOC_KM_AES_KEY2_UNION;
#endif
#define SOC_KM_AES_KEY2_aes_key2_START  (0)
#define SOC_KM_AES_KEY2_aes_key2_END    (31)


/*****************************************************************************
 结构名    : SOC_KM_AESKEY2_MASK_VALUE_UNION
 结构说明  : AESKEY2_MASK_VALUE 寄存器结构定义。地址偏移量:0x02A0，初值:0x0000，宽度:32
 寄存器说明: XTS KEY2的密钥掩码寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  aes_key2_mask_value : 32; /* bit[0-31]: XTS KEY2的密钥掩码寄存器 */
    } reg;
} SOC_KM_AESKEY2_MASK_VALUE_UNION;
#endif
#define SOC_KM_AESKEY2_MASK_VALUE_aes_key2_mask_value_START  (0)
#define SOC_KM_AESKEY2_MASK_VALUE_aes_key2_mask_value_END    (31)


/*****************************************************************************
 结构名    : SOC_KM_AES_KEY2_PARITY_UNION
 结构说明  : AES_KEY2_PARITY 寄存器结构定义。地址偏移量:0x02A4，初值:0x0000，宽度:32
 寄存器说明: XTS KEY2的密钥校验值寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  aes_key2_parity : 32; /* bit[0-31]: XTS KEY2的密钥校验值寄存器 */
    } reg;
} SOC_KM_AES_KEY2_PARITY_UNION;
#endif
#define SOC_KM_AES_KEY2_PARITY_aes_key2_parity_START  (0)
#define SOC_KM_AES_KEY2_PARITY_aes_key2_parity_END    (31)


/*****************************************************************************
 结构名    : SOC_KM_DEBUG_SD_UNION
 结构说明  : DEBUG_SD 寄存器结构定义。地址偏移量:0x02A8，初值:0x00000000，宽度:32
 寄存器说明: 
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  DEBUG_SD : 1;  /* bit[0]   : 临时SD状态查询寄存器。
                                                   0：非SD
                                                   1：SD */
        unsigned int  reserved : 31; /* bit[1-31]:  */
    } reg;
} SOC_KM_DEBUG_SD_UNION;
#endif
#define SOC_KM_DEBUG_SD_DEBUG_SD_START  (0)
#define SOC_KM_DEBUG_SD_DEBUG_SD_END    (0)


/*****************************************************************************
 结构名    : SOC_KM_DERIVE_KEY_SEC_UNION
 结构说明  : DERIVE_KEY_SEC 寄存器结构定义。地址偏移量:0x02C0+(n)*4，初值:0x0000，宽度:32
 寄存器说明: 派生不可读key
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  derive_key_sec : 32; /* bit[0-31]: n=0时，对应key的高32位,n的范围0-15，所有key为小端方式。 */
    } reg;
} SOC_KM_DERIVE_KEY_SEC_UNION;
#endif
#define SOC_KM_DERIVE_KEY_SEC_derive_key_sec_START  (0)
#define SOC_KM_DERIVE_KEY_SEC_derive_key_sec_END    (31)


/*****************************************************************************
 结构名    : SOC_KM_DERIVE_KEY_SEC_M_UNION
 结构说明  : DERIVE_KEY_SEC_M 寄存器结构定义。地址偏移量:0x0300+(n)*4，初值:0x0000，宽度:32
 寄存器说明: 派生不可读key的掩码
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  derive_key_sec_m : 32; /* bit[0-31]: n=0时，对应key的高32位,n的范围0-15，所有key为小端方式。 */
    } reg;
} SOC_KM_DERIVE_KEY_SEC_M_UNION;
#endif
#define SOC_KM_DERIVE_KEY_SEC_M_derive_key_sec_m_START  (0)
#define SOC_KM_DERIVE_KEY_SEC_M_derive_key_sec_m_END    (31)






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

#endif /* end of soc_km_interface.h */
