/******************************************************************************

                 版权所有 (C), 2001-2019, 华为技术有限公司

 ******************************************************************************
  文 件 名   : soc_sce_interface.h
  版 本 号   : 初稿
  作    者   : Excel2Code
  生成日期   : 2019-10-26 10:53:28
  最近修改   :
  功能描述   : 接口头文件
  函数列表   :
  修改历史   :
  1.日    期   : 2019年10月26日
    作    者   : l00249396
    修改内容   : 从《HiEPS V200 nManager寄存器手册_SCE.xml》自动生成

******************************************************************************/

/*****************************************************************************
  1 其他头文件包含
*****************************************************************************/

#ifndef __SOC_SCE_INTERFACE_H__
#define __SOC_SCE_INTERFACE_H__

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
/* 寄存器说明：加解密IP选择,加解密工作方式寄存器
   位域定义UNION结构:  SOC_SCE_MODE_UNION */
#define SOC_SCE_MODE_ADDR(base)                       ((base) + (0x0000))

/* 寄存器说明：引擎接收方向数据长度
   位域定义UNION结构:  SOC_SCE_RX_DAT_LEN_UNION */
#define SOC_SCE_RX_DAT_LEN_ADDR(base)                 ((base) + (0x0004))

/* 寄存器说明：引擎参数配置
   位域定义UNION结构:  SOC_SCE_CFG_UNION */
#define SOC_SCE_CFG_ADDR(base)                        ((base) + (0x0008))

/* 寄存器说明：引擎状态寄存器
   位域定义UNION结构:  SOC_SCE_BUSY_DONE_UNION */
#define SOC_SCE_BUSY_DONE_ADDR(base)                  ((base) + (0x000C))

/* 寄存器说明：FIFO水线上报
   位域定义UNION结构:  SOC_SCE_FIFO_LINE_UNION */
#define SOC_SCE_FIFO_LINE_ADDR(base)                  ((base) + (0x0010))

/* 寄存器说明：加解密引擎开始标志
   位域定义UNION结构:  SOC_SCE_STR_RUN_UNION */
#define SOC_SCE_STR_RUN_ADDR(base)                    ((base) + (0x0014))

/* 寄存器说明：对称加解密引擎的原始alarm信号（屏蔽前）
   位域定义UNION结构:  SOC_SCE_ALARM_UNION */
#define SOC_SCE_ALARM_ADDR(base)                      ((base) + (0x0018))

/* 寄存器说明：对称加解密引擎alarm 屏蔽使能
   位域定义UNION结构:  SOC_SCE_ALARM_MASK_EN_UNION */
#define SOC_SCE_ALARM_MASK_EN_ADDR(base)              ((base) + (0x001C))

/* 寄存器说明：对称加解密引擎alarm清零信号
   位域定义UNION结构:  SOC_SCE_ALARM_CLR_UNION */
#define SOC_SCE_ALARM_CLR_ADDR(base)                  ((base) + (0x0020))

/* 寄存器说明：对称加解密引擎的alarm信号（屏蔽后）
   位域定义UNION结构:  SOC_SCE_ALARM_MASK_UNION */
#define SOC_SCE_ALARM_MASK_ADDR(base)                 ((base) + (0x0024))

/* 寄存器说明：引擎发送方向数据长度
   位域定义UNION结构:  SOC_SCE_TX_DAT_LEN_UNION */
#define SOC_SCE_TX_DAT_LEN_ADDR(base)                 ((base) + (0x0030))

/* 寄存器说明：SCE寄存器锁定信号
   位域定义UNION结构:  SOC_SCE_REG_LOCK_UNION */
#define SOC_SCE_REG_LOCK_ADDR(base)                   ((base) + (0x0034))

/* 寄存器说明：引擎接收的一个数据分组
   位域定义UNION结构:  SOC_SCE_DIN_UNION */
#define SOC_SCE_DIN_ADDR(base, n)                     ((base) + (0x0040+(n)*4))

/* 寄存器说明：引擎接收的IV IN
   位域定义UNION结构:  SOC_SCE_IVIN_UNION */
#define SOC_SCE_IVIN_ADDR(base, n)                    ((base) + (0x0080+(n)*4))

/* 寄存器说明：引擎计算出的一个数据分组
   位域定义UNION结构:  SOC_SCE_DOUT_UNION */
#define SOC_SCE_DOUT_ADDR(base, n)                    ((base) + (0x00C0+(n)*4))

/* 寄存器说明：引擎计算出的IV OUT
   位域定义UNION结构:  SOC_SCE_IVOUT_UNION */
#define SOC_SCE_IVOUT_ADDR(base, n)                   ((base) + (0x0100+(n)*4))

/* 寄存器说明：功耗加使能标志
   位域定义UNION结构:  SOC_SCE_POWER_DISTURB_EN_UNION */
#define SOC_SCE_POWER_DISTURB_EN_ADDR(base)           ((base) + (0x0140))

/* 寄存器说明：功耗加扰启动标志
   位域定义UNION结构:  SOC_SCE_POWER_DISTURB_RUN_UNION */
#define SOC_SCE_POWER_DISTURB_RUN_ADDR(base)          ((base) + (0x0144))

/* 寄存器说明：利用MD5进行功耗加扰时的初始数据值
   位域定义UNION结构:  SOC_SCE_POWER_DISTURB_DIN_UNION */
#define SOC_SCE_POWER_DISTURB_DIN_ADDR(base, n)       ((base) + (0x0180+(n)*4))

/* 寄存器说明：伪round使能信号
   位域定义UNION结构:  SOC_SCE_REDROUND_EN_UNION */
#define SOC_SCE_REDROUND_EN_ADDR(base)                ((base) + (0x01C0))

/* 寄存器说明：伪round轮数
   位域定义UNION结构:  SOC_SCE_REDROUND_NUM_UNION */
#define SOC_SCE_REDROUND_NUM_ADDR(base)               ((base) + (0x01C4))

/* 寄存器说明：SM4掩码随机数是否变化检测使能
   位域定义UNION结构:  SOC_SCE_RNG_ACTIVE_CHECK_EN_UNION */
#define SOC_SCE_RNG_ACTIVE_CHECK_EN_ADDR(base)        ((base) + (0x01C8))

/* 寄存器说明：HASH分段时是否padding的标志
   位域定义UNION结构:  SOC_SCE_HASH_PADDING_EN_UNION */
#define SOC_SCE_HASH_PADDING_EN_ADDR(base)            ((base) + (0x01CC))

/* 寄存器说明：EFUSEC输出至SCE的信号
   位域定义UNION结构:  SOC_SCE_EFUSEC_DBG_UNION */
#define SOC_SCE_EFUSEC_DBG_ADDR(base)                 ((base) + (0x01D0))

/* 寄存器说明：对称IP使能
   位域定义UNION结构:  SOC_SCE_IP_EN_UNION */
#define SOC_SCE_IP_EN_ADDR(base)                      ((base) + (0x01D4))

/* 寄存器说明：进行hash计算的总的数据长度
   位域定义UNION结构:  SOC_SCE_HASH_DATA_LENTH_ALL_UNION */
#define SOC_SCE_HASH_DATA_LENTH_ALL_ADDR(base)        ((base) + (0x0200))

/* 寄存器说明：CTR模式引擎接收的计数器的初值
   位域定义UNION结构:  SOC_SCE_CNTIN_UNION */
#define SOC_SCE_CNTIN_ADDR(base, n)                   ((base) + (0x0240+(n)*4))

/* 寄存器说明：CTR模式引擎输出的计数器的初值
   位域定义UNION结构:  SOC_SCE_CNTOUT_UNION */
#define SOC_SCE_CNTOUT_ADDR(base, n)                  ((base) + (0x0280+(n)*4))

/* 寄存器说明：引擎取数据的源地址
   位域定义UNION结构:  SOC_SCE_SRC_ADDR_UNION */
#define SOC_SCE_SRC_ADDR_ADDR(base)                   ((base) + (0x02C0))

/* 寄存器说明：引擎送数据的目的地址
   位域定义UNION结构:  SOC_SCE_DES_ADDR_UNION */
#define SOC_SCE_DES_ADDR_ADDR(base)                   ((base) + (0x02C4))

/* 寄存器说明：数据块指示信号
   位域定义UNION结构:  SOC_SCE_IV_BYPASS_UNION */
#define SOC_SCE_IV_BYPASS_ADDR(base)                  ((base) + (0x02CC))

/* 寄存器说明：中断屏蔽寄存器
   位域定义UNION结构:  SOC_SCE_INT_SCE_MASK_EN_UNION */
#define SOC_SCE_INT_SCE_MASK_EN_ADDR(base)            ((base) + (0x02D0))

/* 寄存器说明：中断状态寄存器(屏蔽后上报的状态)
   位域定义UNION结构:  SOC_SCE_INT_SCE_MASK_UNION */
#define SOC_SCE_INT_SCE_MASK_ADDR(base)               ((base) + (0x02D4))

/* 寄存器说明：中断屏蔽前状态寄存器(实际状态)
   位域定义UNION结构:  SOC_SCE_INT_SCE_UNION */
#define SOC_SCE_INT_SCE_ADDR(base)                    ((base) + (0x02D8))

/* 寄存器说明：中断清除寄存器
   位域定义UNION结构:  SOC_SCE_INT_SCE_CLR_UNION */
#define SOC_SCE_INT_SCE_CLR_ADDR(base)                ((base) + (0x02DC))

/* 寄存器说明：收端fifo的写数据
   位域定义UNION结构:  SOC_SCE_FIFO_RX_WDATA_UNION */
#define SOC_SCE_FIFO_RX_WDATA_ADDR(base)              ((base) + (0x02E0))

/* 寄存器说明：收端fifo的读数据
   位域定义UNION结构:  SOC_SCE_FIFO_RX_RDATA_UNION */
#define SOC_SCE_FIFO_RX_RDATA_ADDR(base)              ((base) + (0x02E4))

/* 寄存器说明：发端fifo的写数据
   位域定义UNION结构:  SOC_SCE_FIFO_TX_WDATA_UNION */
#define SOC_SCE_FIFO_TX_WDATA_ADDR(base)              ((base) + (0x02E8))

/* 寄存器说明：发端fifo的读数据
   位域定义UNION结构:  SOC_SCE_FIFO_TX_RDATA_UNION */
#define SOC_SCE_FIFO_TX_RDATA_ADDR(base)              ((base) + (0x02EC))

/* 寄存器说明：gm的控制信号
   位域定义UNION结构:  SOC_SCE_PROT_UNION */
#define SOC_SCE_PROT_ADDR(base)                       ((base) + (0x02F0))

/* 寄存器说明：testpoint选择信号
   位域定义UNION结构:  SOC_SCE_TP_MUX_UNION */
#define SOC_SCE_TP_MUX_ADDR(base)                     ((base) + (0x02F4))

/* 寄存器说明：SCE AXI读写通路是否支持cacheable操作的标志
   位域定义UNION结构:  SOC_SCE_CACHE_CTRL_UNION */
#define SOC_SCE_CACHE_CTRL_ADDR(base)                 ((base) + (0x300))

/* 寄存器说明：CTRL_RX已经接收到的burst个数
   位域定义UNION结构:  SOC_SCE_RX_RES_BURST_UNION */
#define SOC_SCE_RX_RES_BURST_ADDR(base)               ((base) + (0x304))

/* 寄存器说明：CTRL_RX已经接收到的word个数
   位域定义UNION结构:  SOC_SCE_RX_RES_WORD_UNION */
#define SOC_SCE_RX_RES_WORD_ADDR(base)                ((base) + (0x308))

/* 寄存器说明：CTRL_TX还没有被接收的burst个数
   位域定义UNION结构:  SOC_SCE_TX_REMAIN_BURST_UNION */
#define SOC_SCE_TX_REMAIN_BURST_ADDR(base)            ((base) + (0x30C))

/* 寄存器说明：CTRL_TX还没有被接收的word个数
   位域定义UNION结构:  SOC_SCE_TX_REMAIN_WORD_UNION */
#define SOC_SCE_TX_REMAIN_WORD_ADDR(base)             ((base) + (0x310))

/* 寄存器说明：相关数据长度
   位域定义UNION结构:  SOC_SCE_AAD_LEN_UNION */
#define SOC_SCE_AAD_LEN_ADDR(base)                    ((base) + (0x0314))

/* 寄存器说明：T_Q数据长度
   位域定义UNION结构:  SOC_SCE_T_Q_LENTH_UNION */
#define SOC_SCE_T_Q_LENTH_ADDR(base)                  ((base) + (0x0318))

/* 寄存器说明：CCM校验错误标志
   位域定义UNION结构:  SOC_SCE_CCM_VER_FAIL_UNION */
#define SOC_SCE_CCM_VER_FAIL_ADDR(base)               ((base) + (0x031c))

/* 寄存器说明：CCM校验错误标志位clr信号
   位域定义UNION结构:  SOC_SCE_CCM_VER_FAIL_CLR_UNION */
#define SOC_SCE_CCM_VER_FAIL_CLR_ADDR(base)           ((base) + (0x0320))

/* 寄存器说明：XTS KEY1的密钥校验值寄存器
   位域定义UNION结构:  SOC_SCE_AES_KEY_PARITY_UNION */
#define SOC_SCE_AES_KEY_PARITY_ADDR(base)             ((base) + (0x0324))

/* 寄存器说明：XTS KEY2的密钥校验值寄存器
   位域定义UNION结构:  SOC_SCE_AES_KEY2_PARITY_UNION */
#define SOC_SCE_AES_KEY2_PARITY_ADDR(base)            ((base) + (0x0328))

/* 寄存器说明：KEY_REG_LOCK
   位域定义UNION结构:  SOC_SCE_KEY_REG_LOCK_UNION */
#define SOC_SCE_KEY_REG_LOCK_ADDR(base)               ((base) + (0x32c))

/* 寄存器说明：GCM初始值
   位域定义UNION结构:  SOC_SCE_gcm_counter0_UNION */
#define SOC_SCE_gcm_counter0_ADDR(base, n)            ((base) + (0x0340+(n)*4))

/* 寄存器说明：ccm_q
   位域定义UNION结构:  SOC_SCE_ccm_q_UNION */
#define SOC_SCE_ccm_q_ADDR(base, n)                   ((base) + (0x0380+(n)*4))

/* 寄存器说明：ccm_nonce
   位域定义UNION结构:  SOC_SCE_ccm_nonce_UNION */
#define SOC_SCE_ccm_nonce_ADDR(base, n)               ((base) + (0x03c0+(n)*4))

/* 寄存器说明：tweak_value初始值
   位域定义UNION结构:  SOC_SCE_tweak_value_UNION */
#define SOC_SCE_tweak_value_ADDR(base, n)             ((base) + (0x0400+(n)*4))

/* 寄存器说明：tweak_value初始值
   位域定义UNION结构:  SOC_SCE_xts_multi_data_UNION */
#define SOC_SCE_xts_multi_data_ADDR(base, n)          ((base) + (0x0440+(n)*4))

/* 寄存器说明：previous_ghash_digest
   位域定义UNION结构:  SOC_SCE_previous_ghash_digest_UNION */
#define SOC_SCE_previous_ghash_digest_ADDR(base, n)   ((base) + (0x0480+(n)*4))

/* 寄存器说明：aes_tag_out
   位域定义UNION结构:  SOC_SCE_aes_tag_out_UNION */
#define SOC_SCE_aes_tag_out_ADDR(base, n)             ((base) + (0x04c0+(n)*4))

/* 寄存器说明：ccm_tag_out_4ver
   位域定义UNION结构:  SOC_SCE_ccm_tag_out_4ver_UNION */
#define SOC_SCE_ccm_tag_out_4ver_ADDR(base, n)        ((base) + (0x0500+(n)*4))

/* 寄存器说明：AES_KEY1
   位域定义UNION结构:  SOC_SCE_AES_KEY1_UNION */
#define SOC_SCE_AES_KEY1_ADDR(base, n)                ((base) + (0x0540+(n)*4))

/* 寄存器说明：XTS KEY1的密钥掩码寄存器
   位域定义UNION结构:  SOC_SCE_AESKEY1_MASK_VALUE_UNION */
#define SOC_SCE_AESKEY1_MASK_VALUE_ADDR(base)         ((base) + (0x0580))

/* 寄存器说明：AES_KEY2
   位域定义UNION结构:  SOC_SCE_AES_KEY2_UNION */
#define SOC_SCE_AES_KEY2_ADDR(base, n)                ((base) + (0x05C0+(n)*4))

/* 寄存器说明：XTS KEY2的密钥掩码寄存器
   位域定义UNION结构:  SOC_SCE_AESKEY2_MASK_VALUE_UNION */
#define SOC_SCE_AESKEY2_MASK_VALUE_ADDR(base)         ((base) + (0x06a0))





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
 结构名    : SOC_SCE_MODE_UNION
 结构说明  : MODE 寄存器结构定义。地址偏移量:0x0000，初值:0x00000000，宽度:32
 寄存器说明: 加解密IP选择,加解密工作方式寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sce_rx_dma_mode : 1;  /* bit[0]   : SCE接收方向工作方式
                                                          0:CPU 方式
                                                          1:MASTER方式 */
        unsigned int  reserved_0      : 3;  /* bit[1-3] :  */
        unsigned int  sce_ip_sel      : 4;  /* bit[4-7] : 加解密IP选择
                                                          4’h0:AES
                                                          4’h1:SM4
                                                          4’h2:DES
                                                          4’h4:SHA1
                                                          4’h5:MD5
                                                          4’h6:SHA256
                                                          4’h7:SM3
                                                          4’hc:SHA512 */
        unsigned int  sce_tx_dma_mode : 1;  /* bit[8]   : SCE发送方向工作方式
                                                          0:CPU 方式
                                                          1:MASTER方式 */
        unsigned int  reserved_1      : 23; /* bit[9-31]:  */
    } reg;
} SOC_SCE_MODE_UNION;
#endif
#define SOC_SCE_MODE_sce_rx_dma_mode_START  (0)
#define SOC_SCE_MODE_sce_rx_dma_mode_END    (0)
#define SOC_SCE_MODE_sce_ip_sel_START       (4)
#define SOC_SCE_MODE_sce_ip_sel_END         (7)
#define SOC_SCE_MODE_sce_tx_dma_mode_START  (8)
#define SOC_SCE_MODE_sce_tx_dma_mode_END    (8)


/*****************************************************************************
 结构名    : SOC_SCE_RX_DAT_LEN_UNION
 结构说明  : RX_DAT_LEN 寄存器结构定义。地址偏移量:0x0004，初值:0x00000000，宽度:32
 寄存器说明: 引擎接收方向数据长度
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sce_rx_dat_len : 32; /* bit[0-31]: 引擎接收方向数据长度
                                                         以字节为单位，支持范围为1-10M字节 */
    } reg;
} SOC_SCE_RX_DAT_LEN_UNION;
#endif
#define SOC_SCE_RX_DAT_LEN_sce_rx_dat_len_START  (0)
#define SOC_SCE_RX_DAT_LEN_sce_rx_dat_len_END    (31)


/*****************************************************************************
 结构名    : SOC_SCE_CFG_UNION
 结构说明  : CFG 寄存器结构定义。地址偏移量:0x0008，初值:0x00000100，宽度:32
 寄存器说明: 引擎参数配置
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  lowpower_en       : 1;  /* bit[0]    : SM4低功耗模式使能。
                                                             1:开启低功耗模式
                                                             0:不开启低功耗模式 */
        unsigned int  reserved_0        : 3;  /* bit[1-3]  :  */
        unsigned int  sce_decrypt       : 1;  /* bit[4]    : 加解密标志，
                                                             1:表示加密，
                                                             0:表示解密 */
        unsigned int  reserved_1        : 3;  /* bit[5-7]  :  */
        unsigned int  sce_mode          : 4;  /* bit[8-11] : 对称加密引擎的工作模式
                                                             0001:ECB;
                                                             0010:CBC
                                                             0100:CMAC 
                                                             0011:CBC MAC
                                                             0101:XTS
                                                             0111:CTR
                                                             1000：GCM附加数据的计算模式；
                                                             1001：GCM IV初始化的计算模式；
                                                             1010：GMAC运算模式；
                                                             1011：GCM加解密运算模式；
                                                             1100：CCM相关数据第一部分运算；
                                                             1101：CCM相关数据第二部分运算；
                                                             1110：CCM加密运算
                                                             1111：CCM解密运算
                                                             其它非法。
                                                             
                                                             在sce中被扩展为5bit，只关注上边的描述即可。
                                                             00001：ECB模式；
                                                             00010：CBC模式；
                                                             01000：CBC MAC模式；
                                                             00100：CMAC模式；
                                                             01111：CTR模式；
                                                             10000：GCM附加数据的计算模式；
                                                             10001：GCM IV初始化的计算模式；
                                                             10010：GMAC运算模式；
                                                             10011：GCM加解密运算模式；
                                                             10100：CCM相关数据第一部分运算；
                                                             10101：CCM相关数据第二部分运算；
                                                             10110：CCM加密运算
                                                             10111：CCM解密运算
                                                             11000：XTS加解密运算模式 */
        unsigned int  sce_key_length    : 2;  /* bit[12-13]: 密钥长度指示
                                                             00:128bit
                                                             01:192bit
                                                             10:256bit,
                                                             其它配置值非法
                                                             除过AES,其他IP不用配置此寄存器。 */
        unsigned int  reserved_2        : 2;  /* bit[14-15]: 上报固定为0 */
        unsigned int  mask_disable      : 1;  /* bit[16]   : 去掩码寄存器，仅在debug模式下有效
                                                             1:去掩码
                                                             0:不去掩码 */
        unsigned int  reserved_3        : 3;  /* bit[17-19]: 上报固定为0 */
        unsigned int  sce_dfa_en        : 1;  /* bit[20]   : DFA使能寄存器
                                                             1:DFA使能
                                                             0:DFA不使能 */
        unsigned int  reserved_4        : 3;  /* bit[21-23]: 上报固定为0 */
        unsigned int  tdes              : 1;  /* bit[24]   : DES/3DES操作选择：
                                                             0:DES操作；
                                                             1:3DES操作 */
        unsigned int  reserved_5        : 3;  /* bit[25-27]: 上报固定为0 */
        unsigned int  tx_big_little_end : 1;  /* bit[28]   : 发送方向数据来源的大小端标志
                                                             0:外部数据为小端，会将从SCE送出的数据进行word内字节序倒换，转换为大端模式
                                                             1:外部数据为大端，不会将从SCE送出的数据进行word内字节序倒换 */
        unsigned int  rx_big_little_end : 1;  /* bit[29]   : 接收方向数据来源的大小端标志,默认小端
                                                             0:外部数据为小端，会对送进SCE的数据进行word内字节序倒换，转换为大端模式
                                                             1:外部数据为大端，不对送进SCE的数据word内进行字节序倒换 */
        unsigned int  sce_padding_sel   : 1;  /* bit[30]   : AES\DES\SM4的padding方式选择，默认为00
                                                             1:padding 00
                                                             0:padding 80
                                                             其他值非法 */
        unsigned int  reserved_6        : 1;  /* bit[31]   : 上报固定为0 */
    } reg;
} SOC_SCE_CFG_UNION;
#endif
#define SOC_SCE_CFG_lowpower_en_START        (0)
#define SOC_SCE_CFG_lowpower_en_END          (0)
#define SOC_SCE_CFG_sce_decrypt_START        (4)
#define SOC_SCE_CFG_sce_decrypt_END          (4)
#define SOC_SCE_CFG_sce_mode_START           (8)
#define SOC_SCE_CFG_sce_mode_END             (11)
#define SOC_SCE_CFG_sce_key_length_START     (12)
#define SOC_SCE_CFG_sce_key_length_END       (13)
#define SOC_SCE_CFG_mask_disable_START       (16)
#define SOC_SCE_CFG_mask_disable_END         (16)
#define SOC_SCE_CFG_sce_dfa_en_START         (20)
#define SOC_SCE_CFG_sce_dfa_en_END           (20)
#define SOC_SCE_CFG_tdes_START               (24)
#define SOC_SCE_CFG_tdes_END                 (24)
#define SOC_SCE_CFG_tx_big_little_end_START  (28)
#define SOC_SCE_CFG_tx_big_little_end_END    (28)
#define SOC_SCE_CFG_rx_big_little_end_START  (29)
#define SOC_SCE_CFG_rx_big_little_end_END    (29)
#define SOC_SCE_CFG_sce_padding_sel_START    (30)
#define SOC_SCE_CFG_sce_padding_sel_END      (30)


/*****************************************************************************
 结构名    : SOC_SCE_BUSY_DONE_UNION
 结构说明  : BUSY_DONE 寄存器结构定义。地址偏移量:0x000C，初值:0x00000000，宽度:32
 寄存器说明: 引擎状态寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved_0   : 4;  /* bit[0-3]  :  */
        unsigned int  sce_busy_reg : 1;  /* bit[4]    : sce 忙信号
                                                        1:表示busy */
        unsigned int  reserved_1   : 3;  /* bit[5-7]  :  */
        unsigned int  sce_done_reg : 1;  /* bit[8]    : 计算完成信号
                                                        1:表示完成 */
        unsigned int  reserved_2   : 3;  /* bit[9-11] :  */
        unsigned int  ctrl_rx_busy : 1;  /* bit[12]   : CTRL_RX模块busy状态的标志
                                                        1:表示busy */
        unsigned int  reserved_3   : 3;  /* bit[13-15]:  */
        unsigned int  ctrl_tx_busy : 1;  /* bit[16]   : CTRL_TX模块busy状态的标志
                                                        1:表示busy */
        unsigned int  reserved_4   : 15; /* bit[17-31]:  */
    } reg;
} SOC_SCE_BUSY_DONE_UNION;
#endif
#define SOC_SCE_BUSY_DONE_sce_busy_reg_START  (4)
#define SOC_SCE_BUSY_DONE_sce_busy_reg_END    (4)
#define SOC_SCE_BUSY_DONE_sce_done_reg_START  (8)
#define SOC_SCE_BUSY_DONE_sce_done_reg_END    (8)
#define SOC_SCE_BUSY_DONE_ctrl_rx_busy_START  (12)
#define SOC_SCE_BUSY_DONE_ctrl_rx_busy_END    (12)
#define SOC_SCE_BUSY_DONE_ctrl_tx_busy_START  (16)
#define SOC_SCE_BUSY_DONE_ctrl_tx_busy_END    (16)


/*****************************************************************************
 结构名    : SOC_SCE_FIFO_LINE_UNION
 结构说明  : FIFO_LINE 寄存器结构定义。地址偏移量:0x0010，初值:0x00680600，宽度:32
 寄存器说明: FIFO水线上报
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved_0     : 4;  /* bit[0-3]  : reserved */
        unsigned int  reserved_1     : 4;  /* bit[4-7]  : reserved */
        unsigned int  fifo_rx_afull  : 1;  /* bit[8]    : fifo_rx_afull */
        unsigned int  fifo_rx_aempty : 1;  /* bit[9]    : fifo_rx_aempty */
        unsigned int  fifo_rx_empty  : 1;  /* bit[10]   : fifo_rx_empty */
        unsigned int  fifo_rx_full   : 1;  /* bit[11]   : fifo_rx_full */
        unsigned int  fifo_rx_cnt    : 8;  /* bit[12-19]: fifo_rx_cnt表示有多少空间可以写 */
        unsigned int  fifo_tx_afull  : 1;  /* bit[20]   : fifo_tx_afull */
        unsigned int  fifo_tx_aempty : 1;  /* bit[21]   : fifo_tx_aempty */
        unsigned int  fifo_tx_empty  : 1;  /* bit[22]   : fifo_tx_empty */
        unsigned int  fifo_tx_full   : 1;  /* bit[23]   : fifo_tx_full */
        unsigned int  fifo_tx_cnt    : 8;  /* bit[24-31]: fifo_tx_cnt */
    } reg;
} SOC_SCE_FIFO_LINE_UNION;
#endif
#define SOC_SCE_FIFO_LINE_fifo_rx_afull_START   (8)
#define SOC_SCE_FIFO_LINE_fifo_rx_afull_END     (8)
#define SOC_SCE_FIFO_LINE_fifo_rx_aempty_START  (9)
#define SOC_SCE_FIFO_LINE_fifo_rx_aempty_END    (9)
#define SOC_SCE_FIFO_LINE_fifo_rx_empty_START   (10)
#define SOC_SCE_FIFO_LINE_fifo_rx_empty_END     (10)
#define SOC_SCE_FIFO_LINE_fifo_rx_full_START    (11)
#define SOC_SCE_FIFO_LINE_fifo_rx_full_END      (11)
#define SOC_SCE_FIFO_LINE_fifo_rx_cnt_START     (12)
#define SOC_SCE_FIFO_LINE_fifo_rx_cnt_END       (19)
#define SOC_SCE_FIFO_LINE_fifo_tx_afull_START   (20)
#define SOC_SCE_FIFO_LINE_fifo_tx_afull_END     (20)
#define SOC_SCE_FIFO_LINE_fifo_tx_aempty_START  (21)
#define SOC_SCE_FIFO_LINE_fifo_tx_aempty_END    (21)
#define SOC_SCE_FIFO_LINE_fifo_tx_empty_START   (22)
#define SOC_SCE_FIFO_LINE_fifo_tx_empty_END     (22)
#define SOC_SCE_FIFO_LINE_fifo_tx_full_START    (23)
#define SOC_SCE_FIFO_LINE_fifo_tx_full_END      (23)
#define SOC_SCE_FIFO_LINE_fifo_tx_cnt_START     (24)
#define SOC_SCE_FIFO_LINE_fifo_tx_cnt_END       (31)


/*****************************************************************************
 结构名    : SOC_SCE_STR_RUN_UNION
 结构说明  : STR_RUN 寄存器结构定义。地址偏移量:0x0014，初值:0x00000000，宽度:32
 寄存器说明: 加解密引擎开始标志
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sce_run  : 1;  /* bit[0]   : 分组开始计算的标志
                                                   1:开始分组计算 */
        unsigned int  reserved_0: 3;  /* bit[1-3] :  */
        unsigned int  sce_str  : 1;  /* bit[4]   : 开始采样配置参数标志
                                                   1:开始采样配置参数标志 */
        unsigned int  reserved_1: 3;  /* bit[5-7] :  */
        unsigned int  reserved_2: 24; /* bit[8-31]:  */
    } reg;
} SOC_SCE_STR_RUN_UNION;
#endif
#define SOC_SCE_STR_RUN_sce_run_START   (0)
#define SOC_SCE_STR_RUN_sce_run_END     (0)
#define SOC_SCE_STR_RUN_sce_str_START   (4)
#define SOC_SCE_STR_RUN_sce_str_END     (4)


/*****************************************************************************
 结构名    : SOC_SCE_ALARM_UNION
 结构说明  : ALARM 寄存器结构定义。地址偏移量:0x0018，初值:0x00000000，宽度:32
 寄存器说明: 对称加解密引擎的原始alarm信号（屏蔽前）
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  aes_alarm         : 4;  /* bit[0-3]  : aes_alarm
                                                             任意bit为1:表示有alarm
                                                             0:没有alarm */
        unsigned int  sm4_alarm         : 4;  /* bit[4-7]  : sm4_alarm
                                                             任意bit为1:表示有alarm
                                                             0:没有alarm */
        unsigned int  des_alarm         : 4;  /* bit[8-11] : des_alarm信号
                                                             任意bit为1:表示有alarm
                                                             0:没有alarm */
        unsigned int  sce_alarm         : 1;  /* bit[12]   : sce顶层产生的alarm信号
                                                             1:表示有alarm
                                                             0:没有alarm */
        unsigned int  reg_check_alarm   : 1;  /* bit[13]   : 寄存器合法性检查产生的alarm信号
                                                             1:表示有alarm
                                                             0:没有alarm */
        unsigned int  reg_access_alarm  : 1;  /* bit[14]   : LOCK后读写寄存器产生的alarm信号
                                                             1:表示有alarm
                                                             0:没有alarm */
        unsigned int  rx_response_alarm : 1;  /* bit[15]   : CTRL_RX模块response合法性检查产生的alarm信号
                                                             1:表示有alarm
                                                             0:没有alarm */
        unsigned int  tx_response_alarm : 1;  /* bit[16]   : CTRL_TX模块response合法性检查产生的alarm信号
                                                             1:表示有alarm
                                                             0:没有alarm */
        unsigned int  reserved          : 15; /* bit[17-31]:  */
    } reg;
} SOC_SCE_ALARM_UNION;
#endif
#define SOC_SCE_ALARM_aes_alarm_START          (0)
#define SOC_SCE_ALARM_aes_alarm_END            (3)
#define SOC_SCE_ALARM_sm4_alarm_START          (4)
#define SOC_SCE_ALARM_sm4_alarm_END            (7)
#define SOC_SCE_ALARM_des_alarm_START          (8)
#define SOC_SCE_ALARM_des_alarm_END            (11)
#define SOC_SCE_ALARM_sce_alarm_START          (12)
#define SOC_SCE_ALARM_sce_alarm_END            (12)
#define SOC_SCE_ALARM_reg_check_alarm_START    (13)
#define SOC_SCE_ALARM_reg_check_alarm_END      (13)
#define SOC_SCE_ALARM_reg_access_alarm_START   (14)
#define SOC_SCE_ALARM_reg_access_alarm_END     (14)
#define SOC_SCE_ALARM_rx_response_alarm_START  (15)
#define SOC_SCE_ALARM_rx_response_alarm_END    (15)
#define SOC_SCE_ALARM_tx_response_alarm_START  (16)
#define SOC_SCE_ALARM_tx_response_alarm_END    (16)


/*****************************************************************************
 结构名    : SOC_SCE_ALARM_MASK_EN_UNION
 结构说明  : ALARM_MASK_EN 寄存器结构定义。地址偏移量:0x001C，初值:0x55555555，宽度:32
 寄存器说明: 对称加解密引擎alarm 屏蔽使能
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  aes_alaram_mask_en        : 4;  /* bit[0-3]  : aes_alarm屏蔽信号
                                                                     0x5:对alarm进行屏蔽
                                                                     0xa:不对alarm进行屏蔽
                                                                     其它配置值非法 */
        unsigned int  sm4_alaram_mask_en        : 4;  /* bit[4-7]  : sm4_alarm屏蔽信号
                                                                     0x5:对alarm进行屏蔽
                                                                     0xa:不对alarm进行屏蔽
                                                                     其它配置值非法 */
        unsigned int  des_alaram_mask_en        : 4;  /* bit[8-11] : des_alarm 屏蔽信号
                                                                     0x5:对alarm进行屏蔽
                                                                     0xa:不对alarm进行屏蔽
                                                                     其它配置值非法 */
        unsigned int  alarm_mask_en             : 4;  /* bit[12-15]: 只对sce顶层关键信号产生的alarm 屏蔽,默认屏蔽
                                                                     0x5:对alarm进行屏蔽
                                                                     0xa:不对alarm进行屏蔽
                                                                     其它配置值非法 */
        unsigned int  reg_check_alarm_mask_en   : 4;  /* bit[16-19]: 寄存器合法性检查产生的alarm信号屏蔽，默认屏蔽
                                                                     0x5:对alarm进行屏蔽
                                                                     0xa:不对alarm进行屏蔽
                                                                     其它配置值非法 */
        unsigned int  reg_access_alarm_mask_en  : 4;  /* bit[20-23]: LOCK后读写寄存器产生的alarm信号屏蔽，默认屏蔽
                                                                     0x5:对alarm进行屏蔽
                                                                     0xa:不对alarm进行屏蔽
                                                                     其它配置值非法 */
        unsigned int  rx_response_alarm_mask_en : 4;  /* bit[24-27]: CTRL_RX模块response合法性检查产生的alarm信号屏蔽，默认不屏蔽
                                                                     0x5:对alarm进行屏蔽
                                                                     0xa:不对alarm进行屏蔽
                                                                     其它配置值非法 */
        unsigned int  tx_response_alarm_mask_en : 4;  /* bit[28-31]: CTRL_TX模块response合法性检查产生的alarm信号屏蔽，默认不屏蔽
                                                                     0x5:对alarm进行屏蔽
                                                                     0xa:不对alarm进行屏蔽
                                                                     其它配置值非法 */
    } reg;
} SOC_SCE_ALARM_MASK_EN_UNION;
#endif
#define SOC_SCE_ALARM_MASK_EN_aes_alaram_mask_en_START         (0)
#define SOC_SCE_ALARM_MASK_EN_aes_alaram_mask_en_END           (3)
#define SOC_SCE_ALARM_MASK_EN_sm4_alaram_mask_en_START         (4)
#define SOC_SCE_ALARM_MASK_EN_sm4_alaram_mask_en_END           (7)
#define SOC_SCE_ALARM_MASK_EN_des_alaram_mask_en_START         (8)
#define SOC_SCE_ALARM_MASK_EN_des_alaram_mask_en_END           (11)
#define SOC_SCE_ALARM_MASK_EN_alarm_mask_en_START              (12)
#define SOC_SCE_ALARM_MASK_EN_alarm_mask_en_END                (15)
#define SOC_SCE_ALARM_MASK_EN_reg_check_alarm_mask_en_START    (16)
#define SOC_SCE_ALARM_MASK_EN_reg_check_alarm_mask_en_END      (19)
#define SOC_SCE_ALARM_MASK_EN_reg_access_alarm_mask_en_START   (20)
#define SOC_SCE_ALARM_MASK_EN_reg_access_alarm_mask_en_END     (23)
#define SOC_SCE_ALARM_MASK_EN_rx_response_alarm_mask_en_START  (24)
#define SOC_SCE_ALARM_MASK_EN_rx_response_alarm_mask_en_END    (27)
#define SOC_SCE_ALARM_MASK_EN_tx_response_alarm_mask_en_START  (28)
#define SOC_SCE_ALARM_MASK_EN_tx_response_alarm_mask_en_END    (31)


/*****************************************************************************
 结构名    : SOC_SCE_ALARM_CLR_UNION
 结构说明  : ALARM_CLR 寄存器结构定义。地址偏移量:0x0020，初值:0xAAAAAAAA，宽度:32
 寄存器说明: 对称加解密引擎alarm清零信号
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  aes_alaram_clr        : 4;  /* bit[0-3]  : aes_alarm清零信号
                                                                 0x5:对alarm进行清零
                                                                 0xa:不对alarm进行清零
                                                                 其它配置值非法 */
        unsigned int  sm4_alaram_clr        : 4;  /* bit[4-7]  : sm4_alarm清零信号
                                                                 0x5:对alarm进行清零
                                                                 0xa:不对alarm进行清零
                                                                 其它配置值非法 */
        unsigned int  des_alaram_clr        : 4;  /* bit[8-11] : des_alarm 清零信号
                                                                 0x5:对alarm进行清零
                                                                 0xa:不对alarm进行清零
                                                                 其它配置值非法 */
        unsigned int  alaram_clr            : 4;  /* bit[12-15]: 只对sce关键信号产生的alarm 清零
                                                                 0x5:对alarm进行清零
                                                                 0xa:不对alarm进行清零
                                                                 其它配置值非法 */
        unsigned int  reg_check_alarm_clr   : 4;  /* bit[16-19]: 寄存器合法性检查产生的alarm信号清零
                                                                 0x5:对alarm进行清零
                                                                 0xa:不对alarm进行清零
                                                                 其它配置值非法 */
        unsigned int  reg_access_alarm_clr  : 4;  /* bit[20-23]: LOCK后读写寄存器产生的alarm信号清零
                                                                 0x5:对alarm进行清零
                                                                 0xa:不对alarm进行清零
                                                                 其它配置值非法 */
        unsigned int  rx_response_alarm_clr : 4;  /* bit[24-27]: CTRL_RX模块response合法性检查产生的alarm信号清零
                                                                 0x5:对alarm进行清零
                                                                 0xa:不对alarm进行清零
                                                                 其它配置值非法 */
        unsigned int  tx_response_alarm_clr : 4;  /* bit[28-31]: CTRL_TX模块response合法性检查产生的alarm信号清零
                                                                 0x5:对alarm进行清零
                                                                 0xa:不对alarm进行清零
                                                                 其它配置值非法 */
    } reg;
} SOC_SCE_ALARM_CLR_UNION;
#endif
#define SOC_SCE_ALARM_CLR_aes_alaram_clr_START         (0)
#define SOC_SCE_ALARM_CLR_aes_alaram_clr_END           (3)
#define SOC_SCE_ALARM_CLR_sm4_alaram_clr_START         (4)
#define SOC_SCE_ALARM_CLR_sm4_alaram_clr_END           (7)
#define SOC_SCE_ALARM_CLR_des_alaram_clr_START         (8)
#define SOC_SCE_ALARM_CLR_des_alaram_clr_END           (11)
#define SOC_SCE_ALARM_CLR_alaram_clr_START             (12)
#define SOC_SCE_ALARM_CLR_alaram_clr_END               (15)
#define SOC_SCE_ALARM_CLR_reg_check_alarm_clr_START    (16)
#define SOC_SCE_ALARM_CLR_reg_check_alarm_clr_END      (19)
#define SOC_SCE_ALARM_CLR_reg_access_alarm_clr_START   (20)
#define SOC_SCE_ALARM_CLR_reg_access_alarm_clr_END     (23)
#define SOC_SCE_ALARM_CLR_rx_response_alarm_clr_START  (24)
#define SOC_SCE_ALARM_CLR_rx_response_alarm_clr_END    (27)
#define SOC_SCE_ALARM_CLR_tx_response_alarm_clr_START  (28)
#define SOC_SCE_ALARM_CLR_tx_response_alarm_clr_END    (31)


/*****************************************************************************
 结构名    : SOC_SCE_ALARM_MASK_UNION
 结构说明  : ALARM_MASK 寄存器结构定义。地址偏移量:0x0024，初值:0x00000000，宽度:32
 寄存器说明: 对称加解密引擎的alarm信号（屏蔽后）
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  aes_alaram_mask        : 4;  /* bit[0-3]  : aes_alarm
                                                                  任意bit为1:表示有alarm
                                                                  0:没有alarm */
        unsigned int  sm4_alaram_mask        : 4;  /* bit[4-7]  : sm4_alarm
                                                                  任意bit为1:表示有alarm
                                                                  0:没有alarm */
        unsigned int  des_alaram_mask        : 4;  /* bit[8-11] : des_alarm信号
                                                                  任意bit为1:表示有alarm
                                                                  0:没有alarm */
        unsigned int  sce_alarm_mask         : 1;  /* bit[12]   : sce顶层产生的alarm信号
                                                                  1:表示有alarm
                                                                  0:没有alarm */
        unsigned int  reg_check_alarm_mask   : 1;  /* bit[13]   : 寄存器合法性检查产生的alarm信号
                                                                  1:表示有alarm
                                                                  0:没有alarm */
        unsigned int  reg_access_alarm_mask  : 1;  /* bit[14]   : LOCK后读写寄存器产生的alarm信号
                                                                  1:表示有alarm
                                                                  0:没有alarm */
        unsigned int  rx_response_alarm_mask : 1;  /* bit[15]   : CTRL_RX模块response合法性检查产生的alarm信号
                                                                  1:表示有alarm
                                                                  0:没有alarm */
        unsigned int  tx_response_alarm_mask : 1;  /* bit[16]   : CTRL_TX模块response合法性检查产生的alarm信号
                                                                  1:表示有alarm
                                                                  0:没有alarm */
        unsigned int  reserved               : 15; /* bit[17-31]:  */
    } reg;
} SOC_SCE_ALARM_MASK_UNION;
#endif
#define SOC_SCE_ALARM_MASK_aes_alaram_mask_START         (0)
#define SOC_SCE_ALARM_MASK_aes_alaram_mask_END           (3)
#define SOC_SCE_ALARM_MASK_sm4_alaram_mask_START         (4)
#define SOC_SCE_ALARM_MASK_sm4_alaram_mask_END           (7)
#define SOC_SCE_ALARM_MASK_des_alaram_mask_START         (8)
#define SOC_SCE_ALARM_MASK_des_alaram_mask_END           (11)
#define SOC_SCE_ALARM_MASK_sce_alarm_mask_START          (12)
#define SOC_SCE_ALARM_MASK_sce_alarm_mask_END            (12)
#define SOC_SCE_ALARM_MASK_reg_check_alarm_mask_START    (13)
#define SOC_SCE_ALARM_MASK_reg_check_alarm_mask_END      (13)
#define SOC_SCE_ALARM_MASK_reg_access_alarm_mask_START   (14)
#define SOC_SCE_ALARM_MASK_reg_access_alarm_mask_END     (14)
#define SOC_SCE_ALARM_MASK_rx_response_alarm_mask_START  (15)
#define SOC_SCE_ALARM_MASK_rx_response_alarm_mask_END    (15)
#define SOC_SCE_ALARM_MASK_tx_response_alarm_mask_START  (16)
#define SOC_SCE_ALARM_MASK_tx_response_alarm_mask_END    (16)


/*****************************************************************************
 结构名    : SOC_SCE_TX_DAT_LEN_UNION
 结构说明  : TX_DAT_LEN 寄存器结构定义。地址偏移量:0x0030，初值:0x00000000，宽度:32
 寄存器说明: 引擎发送方向数据长度
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sce_tx_dat_len : 32; /* bit[0-31]: 引擎发送方向数据长度
                                                         以字节为单位，支持范围为1-10M字节 */
    } reg;
} SOC_SCE_TX_DAT_LEN_UNION;
#endif
#define SOC_SCE_TX_DAT_LEN_sce_tx_dat_len_START  (0)
#define SOC_SCE_TX_DAT_LEN_sce_tx_dat_len_END    (31)


/*****************************************************************************
 结构名    : SOC_SCE_REG_LOCK_UNION
 结构说明  : REG_LOCK 寄存器结构定义。地址偏移量:0x0034，初值:0x00000005，宽度:32
 寄存器说明: SCE寄存器锁定信号
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sce_reg_lock : 4;  /* bit[0-3] : 寄存器的读写锁定，默认为0x5
                                                       0x5：锁定，任何寄存器均不可读写
                                                       0xa：未锁定，寄存器可读写
                                                       其它配置值非法 */
        unsigned int  reserved     : 28; /* bit[4-31]:  */
    } reg;
} SOC_SCE_REG_LOCK_UNION;
#endif
#define SOC_SCE_REG_LOCK_sce_reg_lock_START  (0)
#define SOC_SCE_REG_LOCK_sce_reg_lock_END    (3)


/*****************************************************************************
 结构名    : SOC_SCE_DIN_UNION
 结构说明  : DIN 寄存器结构定义。地址偏移量:0x0040+(n)*4，初值:0x00000000，宽度:32
 寄存器说明: 引擎接收的一个数据分组
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sce_din : 32; /* bit[0-31]: 引擎接收的一个数据分组,n=0时，对应数据的高32位,n的范围0-15 */
    } reg;
} SOC_SCE_DIN_UNION;
#endif
#define SOC_SCE_DIN_sce_din_START  (0)
#define SOC_SCE_DIN_sce_din_END    (31)


/*****************************************************************************
 结构名    : SOC_SCE_IVIN_UNION
 结构说明  : IVIN 寄存器结构定义。地址偏移量:0x0080+(n)*4，初值:0x00000000，宽度:32
 寄存器说明: 引擎接收的IV IN
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sce_ivin : 32; /* bit[0-31]: 引擎接收的nV nN，n=0时，对应nV的高32位,n的范围0-15 */
    } reg;
} SOC_SCE_IVIN_UNION;
#endif
#define SOC_SCE_IVIN_sce_ivin_START  (0)
#define SOC_SCE_IVIN_sce_ivin_END    (31)


/*****************************************************************************
 结构名    : SOC_SCE_DOUT_UNION
 结构说明  : DOUT 寄存器结构定义。地址偏移量:0x00C0+(n)*4，初值:0x00000000，宽度:32
 寄存器说明: 引擎计算出的一个数据分组
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sce_dout : 32; /* bit[0-31]: 引擎计算出的一个数据分组，n=0时，对应数据的高32位,n的范围0-15 */
    } reg;
} SOC_SCE_DOUT_UNION;
#endif
#define SOC_SCE_DOUT_sce_dout_START  (0)
#define SOC_SCE_DOUT_sce_dout_END    (31)


/*****************************************************************************
 结构名    : SOC_SCE_IVOUT_UNION
 结构说明  : IVOUT 寄存器结构定义。地址偏移量:0x0100+(n)*4，初值:0x00000000，宽度:32
 寄存器说明: 引擎计算出的IV OUT
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sce_ivout : 32; /* bit[0-31]: 引擎计算出的nV OUT,n=0时，对应nV的高32位,n的范围0-15 */
    } reg;
} SOC_SCE_IVOUT_UNION;
#endif
#define SOC_SCE_IVOUT_sce_ivout_START  (0)
#define SOC_SCE_IVOUT_sce_ivout_END    (31)


/*****************************************************************************
 结构名    : SOC_SCE_POWER_DISTURB_EN_UNION
 结构说明  : POWER_DISTURB_EN 寄存器结构定义。地址偏移量:0x0140，初值:0x0000000A，宽度:32
 寄存器说明: 功耗加使能标志
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  power_disturb_en : 4;  /* bit[0-3] : 是否打开功耗加扰
                                                           0x5:默认使用MD5进行功耗加扰
                                                           0xa:不使用MD5进行功耗加扰
                                                           其它配置值非法 */
        unsigned int  reserved         : 28; /* bit[4-31]:  */
    } reg;
} SOC_SCE_POWER_DISTURB_EN_UNION;
#endif
#define SOC_SCE_POWER_DISTURB_EN_power_disturb_en_START  (0)
#define SOC_SCE_POWER_DISTURB_EN_power_disturb_en_END    (3)


/*****************************************************************************
 结构名    : SOC_SCE_POWER_DISTURB_RUN_UNION
 结构说明  : POWER_DISTURB_RUN 寄存器结构定义。地址偏移量:0x0144，初值:0x00000000，宽度:32
 寄存器说明: 功耗加扰启动标志
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  power_disturb_run : 1;  /* bit[0]   : 功耗加扰启动标志
                                                            1:启动功耗加扰
                                                            0:关闭功耗加扰功能 */
        unsigned int  reserved          : 31; /* bit[1-31]:  */
    } reg;
} SOC_SCE_POWER_DISTURB_RUN_UNION;
#endif
#define SOC_SCE_POWER_DISTURB_RUN_power_disturb_run_START  (0)
#define SOC_SCE_POWER_DISTURB_RUN_power_disturb_run_END    (0)


/*****************************************************************************
 结构名    : SOC_SCE_POWER_DISTURB_DIN_UNION
 结构说明  : POWER_DISTURB_DIN 寄存器结构定义。地址偏移量:0x0180+(n)*4，初值:0x00000000，宽度:32
 寄存器说明: 利用MD5进行功耗加扰时的初始数据值
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  power_disturb_din : 32; /* bit[0-31]: 利用MD5进行功耗加扰时的初始数据值,n=0时，对应dnn的高32位，n的范围0-15。按照MD5的PADDnNG方式，数据固定为小端输入，paddnng后的长度大端输入，且长度存放在倒数第二个word上。 */
    } reg;
} SOC_SCE_POWER_DISTURB_DIN_UNION;
#endif
#define SOC_SCE_POWER_DISTURB_DIN_power_disturb_din_START  (0)
#define SOC_SCE_POWER_DISTURB_DIN_power_disturb_din_END    (31)


/*****************************************************************************
 结构名    : SOC_SCE_REDROUND_EN_UNION
 结构说明  : REDROUND_EN 寄存器结构定义。地址偏移量:0x01C0，初值:0x0000000A，宽度:32
 寄存器说明: 伪round使能信号
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sce_redround_en : 4;  /* bit[0-3] : 伪round使能；默认不使能
                                                          0x5：使能伪round
                                                          0xa：不使能伪round
                                                          其它配置值非法 */
        unsigned int  reserved        : 28; /* bit[4-31]:  */
    } reg;
} SOC_SCE_REDROUND_EN_UNION;
#endif
#define SOC_SCE_REDROUND_EN_sce_redround_en_START  (0)
#define SOC_SCE_REDROUND_EN_sce_redround_en_END    (3)


/*****************************************************************************
 结构名    : SOC_SCE_REDROUND_NUM_UNION
 结构说明  : REDROUND_NUM 寄存器结构定义。地址偏移量:0x01C4，初值:0x00000007，宽度:32
 寄存器说明: 伪round轮数
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sce_redround_num : 3;  /* bit[0-2] : 伪round轮数：默认7轮
                                                           0x3:3轮
                                                           0x7:7轮
                                                           其它配置值非法。 */
        unsigned int  reserved         : 29; /* bit[3-31]:  */
    } reg;
} SOC_SCE_REDROUND_NUM_UNION;
#endif
#define SOC_SCE_REDROUND_NUM_sce_redround_num_START  (0)
#define SOC_SCE_REDROUND_NUM_sce_redround_num_END    (2)


/*****************************************************************************
 结构名    : SOC_SCE_RNG_ACTIVE_CHECK_EN_UNION
 结构说明  : RNG_ACTIVE_CHECK_EN 寄存器结构定义。地址偏移量:0x01C8，初值:0x0000000A，宽度:32
 寄存器说明: SM4掩码随机数是否变化检测使能
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  rng_active_check_en : 4;  /* bit[0-3] : SM4掩码是否变化检测信号，默认不使能
                                                              0x5:使能
                                                              0xa:不使能
                                                              其他配置值非法 */
        unsigned int  reserved            : 28; /* bit[4-31]:  */
    } reg;
} SOC_SCE_RNG_ACTIVE_CHECK_EN_UNION;
#endif
#define SOC_SCE_RNG_ACTIVE_CHECK_EN_rng_active_check_en_START  (0)
#define SOC_SCE_RNG_ACTIVE_CHECK_EN_rng_active_check_en_END    (3)


/*****************************************************************************
 结构名    : SOC_SCE_HASH_PADDING_EN_UNION
 结构说明  : HASH_PADDING_EN 寄存器结构定义。地址偏移量:0x01CC，初值:0x00000001，宽度:32
 寄存器说明: HASH分段时是否padding的标志
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  hash_padding_en : 1;  /* bit[0]   : HASH分段时是否padding的标志
                                                          0:NOT PADDING
                                                          1:PADDING */
        unsigned int  reserved        : 31; /* bit[1-31]:  */
    } reg;
} SOC_SCE_HASH_PADDING_EN_UNION;
#endif
#define SOC_SCE_HASH_PADDING_EN_hash_padding_en_START  (0)
#define SOC_SCE_HASH_PADDING_EN_hash_padding_en_END    (0)


/*****************************************************************************
 结构名    : SOC_SCE_EFUSEC_DBG_UNION
 结构说明  : EFUSEC_DBG 寄存器结构定义。地址偏移量:0x01D0，初值:0x00000AAA，宽度:32
 寄存器说明: EFUSEC输出至SCE的信号
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  debug_disable : 4;  /* bit[0-3]  : Debug disable
                                                         0xA:调试模式
                                                         0x5:非调试模式
                                                         其他值非法 */
        unsigned int  sm4_disable   : 4;  /* bit[4-7]  : SM4 disable
                                                         0xA:SM4不屏蔽
                                                         0x5:SM4屏蔽
                                                         其他值非法 */
        unsigned int  sm3_disable   : 4;  /* bit[8-11] : SM3 disable
                                                         0xA:SM3不屏蔽
                                                         0x5:SM3屏蔽
                                                         其他值非法 */
        unsigned int  reserved      : 20; /* bit[12-31]:  */
    } reg;
} SOC_SCE_EFUSEC_DBG_UNION;
#endif
#define SOC_SCE_EFUSEC_DBG_debug_disable_START  (0)
#define SOC_SCE_EFUSEC_DBG_debug_disable_END    (3)
#define SOC_SCE_EFUSEC_DBG_sm4_disable_START    (4)
#define SOC_SCE_EFUSEC_DBG_sm4_disable_END      (7)
#define SOC_SCE_EFUSEC_DBG_sm3_disable_START    (8)
#define SOC_SCE_EFUSEC_DBG_sm3_disable_END      (11)


/*****************************************************************************
 结构名    : SOC_SCE_IP_EN_UNION
 结构说明  : IP_EN 寄存器结构定义。地址偏移量:0x01D4，初值:0x00000AAA，宽度:32
 寄存器说明: 对称IP使能
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  aes_en   : 4;  /* bit[0-3]  : AES使能，运性期间必须保持0x5，不运行时保持0xA降低功耗
                                                    0xA:不使能
                                                    0x5:使能
                                                    其他值非法 */
        unsigned int  sm4_en   : 4;  /* bit[4-7]  : SM4使能，运性期间必须保持0x5，不运行时保持0xA降低功耗
                                                    0xA:不使能
                                                    0x5:使能
                                                    其他值非法 */
        unsigned int  des_en   : 4;  /* bit[8-11] : DES使能，运性期间必须保持0x5，不运行时保持0xA降低功耗
                                                    0xA:不使能
                                                    0x5:使能
                                                    其他值非法 */
        unsigned int  reserved : 20; /* bit[12-31]:  */
    } reg;
} SOC_SCE_IP_EN_UNION;
#endif
#define SOC_SCE_IP_EN_aes_en_START    (0)
#define SOC_SCE_IP_EN_aes_en_END      (3)
#define SOC_SCE_IP_EN_sm4_en_START    (4)
#define SOC_SCE_IP_EN_sm4_en_END      (7)
#define SOC_SCE_IP_EN_des_en_START    (8)
#define SOC_SCE_IP_EN_des_en_END      (11)


/*****************************************************************************
 结构名    : SOC_SCE_HASH_DATA_LENTH_ALL_UNION
 结构说明  : HASH_DATA_LENTH_ALL 寄存器结构定义。地址偏移量:0x0200，初值:0x00000000，宽度:32
 寄存器说明: 进行hash计算的总的数据长度
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  hash_data_lenth_all : 32; /* bit[0-31]: 进行hash计算的总的数据长度，单位为字节。长度范围1-10M BYTE */
    } reg;
} SOC_SCE_HASH_DATA_LENTH_ALL_UNION;
#endif
#define SOC_SCE_HASH_DATA_LENTH_ALL_hash_data_lenth_all_START  (0)
#define SOC_SCE_HASH_DATA_LENTH_ALL_hash_data_lenth_all_END    (31)


/*****************************************************************************
 结构名    : SOC_SCE_CNTIN_UNION
 结构说明  : CNTIN 寄存器结构定义。地址偏移量:0x0240+(n)*4，初值:0x00000000，宽度:32
 寄存器说明: CTR模式引擎接收的计数器的初值
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sce_cntin : 32; /* bit[0-31]: CTR模式时配置的cnt初始值,n=0时，对应数据的高32位,n的范围0-3 */
    } reg;
} SOC_SCE_CNTIN_UNION;
#endif
#define SOC_SCE_CNTIN_sce_cntin_START  (0)
#define SOC_SCE_CNTIN_sce_cntin_END    (31)


/*****************************************************************************
 结构名    : SOC_SCE_CNTOUT_UNION
 结构说明  : CNTOUT 寄存器结构定义。地址偏移量:0x0280+(n)*4，初值:0x00000000，宽度:32
 寄存器说明: CTR模式引擎输出的计数器的初值
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sce_cntout : 32; /* bit[0-31]: CTR模式时输出的cnt初始值,n=0时，对应数据的高32位,n的范围0-3 */
    } reg;
} SOC_SCE_CNTOUT_UNION;
#endif
#define SOC_SCE_CNTOUT_sce_cntout_START  (0)
#define SOC_SCE_CNTOUT_sce_cntout_END    (31)


/*****************************************************************************
 结构名    : SOC_SCE_SRC_ADDR_UNION
 结构说明  : SRC_ADDR 寄存器结构定义。地址偏移量:0x02C0，初值:0x00000000，宽度:32
 寄存器说明: 引擎取数据的源地址
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sce_src_addr_low : 32; /* bit[0-31]: 引擎取数据的源地址 */
    } reg;
} SOC_SCE_SRC_ADDR_UNION;
#endif
#define SOC_SCE_SRC_ADDR_sce_src_addr_low_START  (0)
#define SOC_SCE_SRC_ADDR_sce_src_addr_low_END    (31)


/*****************************************************************************
 结构名    : SOC_SCE_DES_ADDR_UNION
 结构说明  : DES_ADDR 寄存器结构定义。地址偏移量:0x02C4，初值:0x00000000，宽度:32
 寄存器说明: 引擎送数据的目的地址
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sce_des_addr_low : 32; /* bit[0-31]: 引擎送数据的目的地址 */
    } reg;
} SOC_SCE_DES_ADDR_UNION;
#endif
#define SOC_SCE_DES_ADDR_sce_des_addr_low_START  (0)
#define SOC_SCE_DES_ADDR_sce_des_addr_low_END    (31)


/*****************************************************************************
 结构名    : SOC_SCE_IV_BYPASS_UNION
 结构说明  : IV_BYPASS 寄存器结构定义。地址偏移量:0x02CC，初值:0x000000AA，宽度:32
 寄存器说明: 数据块指示信号
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  plaintext_en      : 4;  /* bit[0-3]  : 明密文指示信号
                                                             0xA:密文
                                                             0x5:明文 */
        unsigned int  iv_sel            : 4;  /* bit[4-7]  : 当前数据块的iv是选择软件配置的还是硬件原先生成的
                                                             0xA:使用软件配置的
                                                             0x5:硬件原先生成的 */
        unsigned int  sce_src_addr_high : 5;  /* bit[8-12] : 源地址的高位 */
        unsigned int  sce_des_addr_high : 5;  /* bit[13-17]: 目的地址的高位 */
        unsigned int  reserved          : 14; /* bit[18-31]:  */
    } reg;
} SOC_SCE_IV_BYPASS_UNION;
#endif
#define SOC_SCE_IV_BYPASS_plaintext_en_START       (0)
#define SOC_SCE_IV_BYPASS_plaintext_en_END         (3)
#define SOC_SCE_IV_BYPASS_iv_sel_START             (4)
#define SOC_SCE_IV_BYPASS_iv_sel_END               (7)
#define SOC_SCE_IV_BYPASS_sce_src_addr_high_START  (8)
#define SOC_SCE_IV_BYPASS_sce_src_addr_high_END    (12)
#define SOC_SCE_IV_BYPASS_sce_des_addr_high_START  (13)
#define SOC_SCE_IV_BYPASS_sce_des_addr_high_END    (17)


/*****************************************************************************
 结构名    : SOC_SCE_INT_SCE_MASK_EN_UNION
 结构说明  : INT_SCE_MASK_EN 寄存器结构定义。地址偏移量:0x02D0，初值:0x00000005，宽度:32
 寄存器说明: 中断屏蔽寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sce_int_mask_en : 4;  /* bit[0-3]  : 0x5：屏蔽该中断源
                                                           0xA：不屏蔽该中断源 */
        unsigned int  reserved_0      : 12; /* bit[4-15] : 保留 */
        unsigned int  reserved_1      : 16; /* bit[16-31]: 保留 */
    } reg;
} SOC_SCE_INT_SCE_MASK_EN_UNION;
#endif
#define SOC_SCE_INT_SCE_MASK_EN_sce_int_mask_en_START  (0)
#define SOC_SCE_INT_SCE_MASK_EN_sce_int_mask_en_END    (3)


/*****************************************************************************
 结构名    : SOC_SCE_INT_SCE_MASK_UNION
 结构说明  : INT_SCE_MASK 寄存器结构定义。地址偏移量:0x02D4，初值:0x0000000A，宽度:32
 寄存器说明: 中断状态寄存器(屏蔽后上报的状态)
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sce_int_mask : 4;  /* bit[0-3]  : mask后处理完成中断 状态寄存器
                                                        0x5：完成中断有效，表示处理完成
                                                        0xA：完成中断无效，可能是逻辑还在处理，也有可能是处理完成，但是中断被mask掉，或未启动操作 */
        unsigned int  reserved_0   : 12; /* bit[4-15] : 保留 */
        unsigned int  reserved_1   : 16; /* bit[16-31]: 保留 */
    } reg;
} SOC_SCE_INT_SCE_MASK_UNION;
#endif
#define SOC_SCE_INT_SCE_MASK_sce_int_mask_START  (0)
#define SOC_SCE_INT_SCE_MASK_sce_int_mask_END    (3)


/*****************************************************************************
 结构名    : SOC_SCE_INT_SCE_UNION
 结构说明  : INT_SCE 寄存器结构定义。地址偏移量:0x02D8，初值:0x0000000A，宽度:32
 寄存器说明: 中断屏蔽前状态寄存器(实际状态)
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sce_int  : 4;  /* bit[0-3]  : mask前(即按无屏蔽中断) 处理完成中断 状态寄存器
                                                    0x5：完成中断有效，表示处理完成
                                                    0xA：完成中断无效，逻辑还在处理或未启动操作 */
        unsigned int  reserved_0: 12; /* bit[4-15] : 保留 */
        unsigned int  reserved_1: 16; /* bit[16-31]: 保留 */
    } reg;
} SOC_SCE_INT_SCE_UNION;
#endif
#define SOC_SCE_INT_SCE_sce_int_START   (0)
#define SOC_SCE_INT_SCE_sce_int_END     (3)


/*****************************************************************************
 结构名    : SOC_SCE_INT_SCE_CLR_UNION
 结构说明  : INT_SCE_CLR 寄存器结构定义。地址偏移量:0x02DC，初值:0x0000000A，宽度:32
 寄存器说明: 中断清除寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sce_int_clr : 4;  /* bit[0-3]  : 说明：软件写0x5清除对应中断源，逻辑只在收到写0x5的时刻才对中断源进行清零。 */
        unsigned int  reserved_0  : 12; /* bit[4-15] : 保留 */
        unsigned int  reserved_1  : 16; /* bit[16-31]: 保留 */
    } reg;
} SOC_SCE_INT_SCE_CLR_UNION;
#endif
#define SOC_SCE_INT_SCE_CLR_sce_int_clr_START  (0)
#define SOC_SCE_INT_SCE_CLR_sce_int_clr_END    (3)


/*****************************************************************************
 结构名    : SOC_SCE_FIFO_RX_WDATA_UNION
 结构说明  : FIFO_RX_WDATA 寄存器结构定义。地址偏移量:0x02E0，初值:0x00000000，宽度:32
 寄存器说明: 收端fifo的写数据
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  fifo_rx_wdata : 32; /* bit[0-31]: 收端fifo的写数据 */
    } reg;
} SOC_SCE_FIFO_RX_WDATA_UNION;
#endif
#define SOC_SCE_FIFO_RX_WDATA_fifo_rx_wdata_START  (0)
#define SOC_SCE_FIFO_RX_WDATA_fifo_rx_wdata_END    (31)


/*****************************************************************************
 结构名    : SOC_SCE_FIFO_RX_RDATA_UNION
 结构说明  : FIFO_RX_RDATA 寄存器结构定义。地址偏移量:0x02E4，初值:0x00000000，宽度:32
 寄存器说明: 收端fifo的读数据
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  fifo_rx_rdata : 32; /* bit[0-31]: 收端fifo的读数据 */
    } reg;
} SOC_SCE_FIFO_RX_RDATA_UNION;
#endif
#define SOC_SCE_FIFO_RX_RDATA_fifo_rx_rdata_START  (0)
#define SOC_SCE_FIFO_RX_RDATA_fifo_rx_rdata_END    (31)


/*****************************************************************************
 结构名    : SOC_SCE_FIFO_TX_WDATA_UNION
 结构说明  : FIFO_TX_WDATA 寄存器结构定义。地址偏移量:0x02E8，初值:0x00000000，宽度:32
 寄存器说明: 发端fifo的写数据
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  fifo_tx_wdata : 32; /* bit[0-31]: 发端fifo的写数据 */
    } reg;
} SOC_SCE_FIFO_TX_WDATA_UNION;
#endif
#define SOC_SCE_FIFO_TX_WDATA_fifo_tx_wdata_START  (0)
#define SOC_SCE_FIFO_TX_WDATA_fifo_tx_wdata_END    (31)


/*****************************************************************************
 结构名    : SOC_SCE_FIFO_TX_RDATA_UNION
 结构说明  : FIFO_TX_RDATA 寄存器结构定义。地址偏移量:0x02EC，初值:0x00000000，宽度:32
 寄存器说明: 发端fifo的读数据
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  fifo_tx_rdata : 32; /* bit[0-31]: 发端fifo的读数据 */
    } reg;
} SOC_SCE_FIFO_TX_RDATA_UNION;
#endif
#define SOC_SCE_FIFO_TX_RDATA_fifo_tx_rdata_START  (0)
#define SOC_SCE_FIFO_TX_RDATA_fifo_tx_rdata_END    (31)


/*****************************************************************************
 结构名    : SOC_SCE_PROT_UNION
 结构说明  : PROT 寄存器结构定义。地址偏移量:0x02F0，初值:0x00000000，宽度:32
 寄存器说明: gm的控制信号
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  dw_axi_gm_prot : 6;  /* bit[0-5] : gm的prot信号，读为低3bit，写为高3bit，每个3bit的bit1使用sideband解析，不采用配置值 */
        unsigned int  reserved       : 26; /* bit[6-31]:  */
    } reg;
} SOC_SCE_PROT_UNION;
#endif
#define SOC_SCE_PROT_dw_axi_gm_prot_START  (0)
#define SOC_SCE_PROT_dw_axi_gm_prot_END    (5)


/*****************************************************************************
 结构名    : SOC_SCE_TP_MUX_UNION
 结构说明  : TP_MUX 寄存器结构定义。地址偏移量:0x02F4，初值:0x00000000，宽度:32
 寄存器说明: testpoint选择信号
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sce_tp_mux : 4;  /* bit[0-3] : testpoint选择信号 */
        unsigned int  reserved   : 28; /* bit[4-31]:  */
    } reg;
} SOC_SCE_TP_MUX_UNION;
#endif
#define SOC_SCE_TP_MUX_sce_tp_mux_START  (0)
#define SOC_SCE_TP_MUX_sce_tp_mux_END    (3)


/*****************************************************************************
 结构名    : SOC_SCE_CACHE_CTRL_UNION
 结构说明  : CACHE_CTRL 寄存器结构定义。地址偏移量:0x300，初值:0x00000000，宽度:32
 寄存器说明: SCE AXI读写通路是否支持cacheable操作的标志
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  mcache_wr : 4;  /* bit[0-3] : AXI写通道是否支持cache操作的标志
                                                    mcahce_wr[0]：Bufferable
                                                    mcahce_wr[1]：Cacheable
                                                    mcahce_wr[2]：Read Allocate
                                                    mcahce_wr[3]：Write Allocate
                                                    可配置的值为4'b0000和4'b0010 */
        unsigned int  mcache_rd : 4;  /* bit[4-7] : AXI读通道是否支持cache操作的标志
                                                    mcahce_rd[0]：Bufferable
                                                    mcahce_rd[1]：Cacheable
                                                    mcahce_rd[2]：Read Allocate
                                                    mcahce_rd[3]：Write Allocate
                                                    可配置的值为4'b0000和4'b0010 */
        unsigned int  reserved  : 24; /* bit[8-31]:  */
    } reg;
} SOC_SCE_CACHE_CTRL_UNION;
#endif
#define SOC_SCE_CACHE_CTRL_mcache_wr_START  (0)
#define SOC_SCE_CACHE_CTRL_mcache_wr_END    (3)
#define SOC_SCE_CACHE_CTRL_mcache_rd_START  (4)
#define SOC_SCE_CACHE_CTRL_mcache_rd_END    (7)


/*****************************************************************************
 结构名    : SOC_SCE_RX_RES_BURST_UNION
 结构说明  : RX_RES_BURST 寄存器结构定义。地址偏移量:0x304，初值:0x00000000，宽度:32
 寄存器说明: CTRL_RX已经接收到的burst个数
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  cnt_res_burst : 32; /* bit[0-31]: CTRL_RX已经接收到的burst个数 */
    } reg;
} SOC_SCE_RX_RES_BURST_UNION;
#endif
#define SOC_SCE_RX_RES_BURST_cnt_res_burst_START  (0)
#define SOC_SCE_RX_RES_BURST_cnt_res_burst_END    (31)


/*****************************************************************************
 结构名    : SOC_SCE_RX_RES_WORD_UNION
 结构说明  : RX_RES_WORD 寄存器结构定义。地址偏移量:0x308，初值:0x00000000，宽度:32
 寄存器说明: CTRL_RX已经接收到的word个数
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  cnt_res_word : 32; /* bit[0-31]: CTRL_RX已经接收到的word个数 */
    } reg;
} SOC_SCE_RX_RES_WORD_UNION;
#endif
#define SOC_SCE_RX_RES_WORD_cnt_res_word_START  (0)
#define SOC_SCE_RX_RES_WORD_cnt_res_word_END    (31)


/*****************************************************************************
 结构名    : SOC_SCE_TX_REMAIN_BURST_UNION
 结构说明  : TX_REMAIN_BURST 寄存器结构定义。地址偏移量:0x30C，初值:0x00000000，宽度:32
 寄存器说明: CTRL_TX还没有被接收的burst个数
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  cnt_remain_burst : 32; /* bit[0-31]: CTRL_TX还没有被接收的burst个数 */
    } reg;
} SOC_SCE_TX_REMAIN_BURST_UNION;
#endif
#define SOC_SCE_TX_REMAIN_BURST_cnt_remain_burst_START  (0)
#define SOC_SCE_TX_REMAIN_BURST_cnt_remain_burst_END    (31)


/*****************************************************************************
 结构名    : SOC_SCE_TX_REMAIN_WORD_UNION
 结构说明  : TX_REMAIN_WORD 寄存器结构定义。地址偏移量:0x310，初值:0x00000000，宽度:32
 寄存器说明: CTRL_TX还没有被接收的word个数
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  cnt_remain_word : 32; /* bit[0-31]: CTRL_TX还没有被接收的word个数 */
    } reg;
} SOC_SCE_TX_REMAIN_WORD_UNION;
#endif
#define SOC_SCE_TX_REMAIN_WORD_cnt_remain_word_START  (0)
#define SOC_SCE_TX_REMAIN_WORD_cnt_remain_word_END    (31)


/*****************************************************************************
 结构名    : SOC_SCE_AAD_LEN_UNION
 结构说明  : AAD_LEN 寄存器结构定义。地址偏移量:0x0314，初值:0x00000000，宽度:32
 寄存器说明: 相关数据长度
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  aad_lenth : 32; /* bit[0-31]: 相关数据长度
                                                    以字节为单位，支持范围为1-10M字节 */
    } reg;
} SOC_SCE_AAD_LEN_UNION;
#endif
#define SOC_SCE_AAD_LEN_aad_lenth_START  (0)
#define SOC_SCE_AAD_LEN_aad_lenth_END    (31)


/*****************************************************************************
 结构名    : SOC_SCE_T_Q_LENTH_UNION
 结构说明  : T_Q_LENTH 寄存器结构定义。地址偏移量:0x0318，初值:0x00000000，宽度:32
 寄存器说明: T_Q数据长度
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ccm_t_lenth : 5;  /* bit[0-4]  : ccm_t_lenth */
        unsigned int  reserved_0  : 3;  /* bit[5-7]  :  */
        unsigned int  ccm_q_lenth : 3;  /* bit[8-10] : ccm的q值 */
        unsigned int  reserved_1  : 1;  /* bit[11-11]:  */
        unsigned int  reserved_2  : 20; /* bit[12-31]:  */
    } reg;
} SOC_SCE_T_Q_LENTH_UNION;
#endif
#define SOC_SCE_T_Q_LENTH_ccm_t_lenth_START  (0)
#define SOC_SCE_T_Q_LENTH_ccm_t_lenth_END    (4)
#define SOC_SCE_T_Q_LENTH_ccm_q_lenth_START  (8)
#define SOC_SCE_T_Q_LENTH_ccm_q_lenth_END    (10)


/*****************************************************************************
 结构名    : SOC_SCE_CCM_VER_FAIL_UNION
 结构说明  : CCM_VER_FAIL 寄存器结构定义。地址偏移量:0x031c，初值:0x0000，宽度:32
 寄存器说明: CCM校验错误标志
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ccm_fail : 1;  /* bit[0]   : CCM校验错误标志，电平信号
                                                   0:校验成功
                                                   1:校验失败 */
        unsigned int  reserved : 31; /* bit[1-31]:  */
    } reg;
} SOC_SCE_CCM_VER_FAIL_UNION;
#endif
#define SOC_SCE_CCM_VER_FAIL_ccm_fail_START  (0)
#define SOC_SCE_CCM_VER_FAIL_ccm_fail_END    (0)


/*****************************************************************************
 结构名    : SOC_SCE_CCM_VER_FAIL_CLR_UNION
 结构说明  : CCM_VER_FAIL_CLR 寄存器结构定义。地址偏移量:0x0320，初值:0x0000，宽度:32
 寄存器说明: CCM校验错误标志位clr信号
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ccm_fail_clr : 1;  /* bit[0]   : CCM校验错误标志位clr信号
                                                       0:不clr
                                                       1:clr此信号位 */
        unsigned int  reserved     : 31; /* bit[1-31]:  */
    } reg;
} SOC_SCE_CCM_VER_FAIL_CLR_UNION;
#endif
#define SOC_SCE_CCM_VER_FAIL_CLR_ccm_fail_clr_START  (0)
#define SOC_SCE_CCM_VER_FAIL_CLR_ccm_fail_clr_END    (0)


/*****************************************************************************
 结构名    : SOC_SCE_AES_KEY_PARITY_UNION
 结构说明  : AES_KEY_PARITY 寄存器结构定义。地址偏移量:0x0324，初值:0x0000，宽度:32
 寄存器说明: XTS KEY1的密钥校验值寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  aes_key_parity : 32; /* bit[0-31]: XTS KEY1的密钥校验值寄存器 */
    } reg;
} SOC_SCE_AES_KEY_PARITY_UNION;
#endif
#define SOC_SCE_AES_KEY_PARITY_aes_key_parity_START  (0)
#define SOC_SCE_AES_KEY_PARITY_aes_key_parity_END    (31)


/*****************************************************************************
 结构名    : SOC_SCE_AES_KEY2_PARITY_UNION
 结构说明  : AES_KEY2_PARITY 寄存器结构定义。地址偏移量:0x0328，初值:0x0000，宽度:32
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
} SOC_SCE_AES_KEY2_PARITY_UNION;
#endif
#define SOC_SCE_AES_KEY2_PARITY_aes_key2_parity_START  (0)
#define SOC_SCE_AES_KEY2_PARITY_aes_key2_parity_END    (31)


/*****************************************************************************
 结构名    : SOC_SCE_KEY_REG_LOCK_UNION
 结构说明  : KEY_REG_LOCK 寄存器结构定义。地址偏移量:0x32c，初值:0x0005，宽度:32
 寄存器说明: KEY_REG_LOCK
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  key_reg_lock : 4;  /* bit[0-3] : key寄存器的读写锁定，默认为0x5
                                                       0x5：锁定，任何key寄存器均不可读写
                                                       0xa：未锁定，key寄存器可读写
                                                       其他值非法 */
        unsigned int  reserved     : 28; /* bit[4-31]:  */
    } reg;
} SOC_SCE_KEY_REG_LOCK_UNION;
#endif
#define SOC_SCE_KEY_REG_LOCK_key_reg_lock_START  (0)
#define SOC_SCE_KEY_REG_LOCK_key_reg_lock_END    (3)


/*****************************************************************************
 结构名    : SOC_SCE_gcm_counter0_UNION
 结构说明  : gcm_counter0 寄存器结构定义。地址偏移量:0x0340+(n)*4，初值:0x0000，宽度:32
 寄存器说明: GCM初始值
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  gcm_counter0 : 32; /* bit[0-31]: GCM counter初始值,n=0时，对应数据的高32位,n的范围0-3 */
    } reg;
} SOC_SCE_gcm_counter0_UNION;
#endif
#define SOC_SCE_gcm_counter0_gcm_counter0_START  (0)
#define SOC_SCE_gcm_counter0_gcm_counter0_END    (31)


/*****************************************************************************
 结构名    : SOC_SCE_ccm_q_UNION
 结构说明  : ccm_q 寄存器结构定义。地址偏移量:0x0380+(n)*4，初值:0x0000，宽度:32
 寄存器说明: ccm_q
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ccm_q : 32; /* bit[0-31]: ccm_q,Q值，n=0时，对应数据的高32位,n的范围0-1 */
    } reg;
} SOC_SCE_ccm_q_UNION;
#endif
#define SOC_SCE_ccm_q_ccm_q_START  (0)
#define SOC_SCE_ccm_q_ccm_q_END    (31)


/*****************************************************************************
 结构名    : SOC_SCE_ccm_nonce_UNION
 结构说明  : ccm_nonce 寄存器结构定义。地址偏移量:0x03c0+(n)*4，初值:0x0000，宽度:32
 寄存器说明: ccm_nonce
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ccm_nonce : 32; /* bit[0-31]: ccm_nonce,n=0时，对应数据的高32位,n的范围0-3 */
    } reg;
} SOC_SCE_ccm_nonce_UNION;
#endif
#define SOC_SCE_ccm_nonce_ccm_nonce_START  (0)
#define SOC_SCE_ccm_nonce_ccm_nonce_END    (31)


/*****************************************************************************
 结构名    : SOC_SCE_tweak_value_UNION
 结构说明  : tweak_value 寄存器结构定义。地址偏移量:0x0400+(n)*4，初值:0x0000，宽度:32
 寄存器说明: tweak_value初始值
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  tweak_value : 32; /* bit[0-31]: tweak_value初始值,n=0时，对应数据的高32位,n的范围0-3 */
    } reg;
} SOC_SCE_tweak_value_UNION;
#endif
#define SOC_SCE_tweak_value_tweak_value_START  (0)
#define SOC_SCE_tweak_value_tweak_value_END    (31)


/*****************************************************************************
 结构名    : SOC_SCE_xts_multi_data_UNION
 结构说明  : xts_multi_data 寄存器结构定义。地址偏移量:0x0440+(n)*4，初值:0x0000，宽度:32
 寄存器说明: tweak_value初始值
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  xts_multi_data : 32; /* bit[0-31]: xts_multi_data初始值,n=0时，对应数据的高32位,n的范围0-3 */
    } reg;
} SOC_SCE_xts_multi_data_UNION;
#endif
#define SOC_SCE_xts_multi_data_xts_multi_data_START  (0)
#define SOC_SCE_xts_multi_data_xts_multi_data_END    (31)


/*****************************************************************************
 结构名    : SOC_SCE_previous_ghash_digest_UNION
 结构说明  : previous_ghash_digest 寄存器结构定义。地址偏移量:0x0480+(n)*4，初值:0x0000，宽度:32
 寄存器说明: previous_ghash_digest
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  previous_ghash_digest : 32; /* bit[0-31]: previous_ghash_digest,n=0时，对应数据的高32位,n的范围0-3 */
    } reg;
} SOC_SCE_previous_ghash_digest_UNION;
#endif
#define SOC_SCE_previous_ghash_digest_previous_ghash_digest_START  (0)
#define SOC_SCE_previous_ghash_digest_previous_ghash_digest_END    (31)


/*****************************************************************************
 结构名    : SOC_SCE_aes_tag_out_UNION
 结构说明  : aes_tag_out 寄存器结构定义。地址偏移量:0x04c0+(n)*4，初值:0x0000，宽度:32
 寄存器说明: aes_tag_out
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  aes_tag_out : 32; /* bit[0-31]: aes_tag_out,n=0时，对应数据的高32位,n的范围0-3 */
    } reg;
} SOC_SCE_aes_tag_out_UNION;
#endif
#define SOC_SCE_aes_tag_out_aes_tag_out_START  (0)
#define SOC_SCE_aes_tag_out_aes_tag_out_END    (31)


/*****************************************************************************
 结构名    : SOC_SCE_ccm_tag_out_4ver_UNION
 结构说明  : ccm_tag_out_4ver 寄存器结构定义。地址偏移量:0x0500+(n)*4，初值:0x0000，宽度:32
 寄存器说明: ccm_tag_out_4ver
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ccm_tag_out_4ver : 32; /* bit[0-31]: ccm_tag_out_4ver,n=0时，对应数据的高32位,n的范围0-3 */
    } reg;
} SOC_SCE_ccm_tag_out_4ver_UNION;
#endif
#define SOC_SCE_ccm_tag_out_4ver_ccm_tag_out_4ver_START  (0)
#define SOC_SCE_ccm_tag_out_4ver_ccm_tag_out_4ver_END    (31)


/*****************************************************************************
 结构名    : SOC_SCE_AES_KEY1_UNION
 结构说明  : AES_KEY1 寄存器结构定义。地址偏移量:0x0540+(n)*4，初值:0x0000，宽度:32
 寄存器说明: AES_KEY1
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  AES_KEY1 : 32; /* bit[0-31]: AES_KEY1,n=0时，对应数据的高32位,n的范围0-7 */
    } reg;
} SOC_SCE_AES_KEY1_UNION;
#endif
#define SOC_SCE_AES_KEY1_AES_KEY1_START  (0)
#define SOC_SCE_AES_KEY1_AES_KEY1_END    (31)


/*****************************************************************************
 结构名    : SOC_SCE_AESKEY1_MASK_VALUE_UNION
 结构说明  : AESKEY1_MASK_VALUE 寄存器结构定义。地址偏移量:0x0580，初值:0x0000，宽度:32
 寄存器说明: XTS KEY1的密钥掩码寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  aes_key1_mask_value : 32; /* bit[0-31]: KEY1的密钥掩码寄存器 */
    } reg;
} SOC_SCE_AESKEY1_MASK_VALUE_UNION;
#endif
#define SOC_SCE_AESKEY1_MASK_VALUE_aes_key1_mask_value_START  (0)
#define SOC_SCE_AESKEY1_MASK_VALUE_aes_key1_mask_value_END    (31)


/*****************************************************************************
 结构名    : SOC_SCE_AES_KEY2_UNION
 结构说明  : AES_KEY2 寄存器结构定义。地址偏移量:0x05C0+(n)*4，初值:0x0000，宽度:32
 寄存器说明: AES_KEY2
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  AES_KEY2 : 32; /* bit[0-31]: AES_KEY2,n=0时，对应数据的高32位,n的范围0-7 */
    } reg;
} SOC_SCE_AES_KEY2_UNION;
#endif
#define SOC_SCE_AES_KEY2_AES_KEY2_START  (0)
#define SOC_SCE_AES_KEY2_AES_KEY2_END    (31)


/*****************************************************************************
 结构名    : SOC_SCE_AESKEY2_MASK_VALUE_UNION
 结构说明  : AESKEY2_MASK_VALUE 寄存器结构定义。地址偏移量:0x06a0，初值:0x0000，宽度:32
 寄存器说明: XTS KEY2的密钥掩码寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  aes_key2_mask_value : 32; /* bit[0-31]: KEY2的密钥掩码寄存器 */
    } reg;
} SOC_SCE_AESKEY2_MASK_VALUE_UNION;
#endif
#define SOC_SCE_AESKEY2_MASK_VALUE_aes_key2_mask_value_START  (0)
#define SOC_SCE_AESKEY2_MASK_VALUE_aes_key2_mask_value_END    (31)






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

#endif /* end of soc_sce_interface.h */
