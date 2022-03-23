/******************************************************************************

                 版权所有 (C), 2001-2019, 华为技术有限公司

 ******************************************************************************
  文 件 名   : soc_trng_interface.h
  版 本 号   : 初稿
  作    者   : Excel2Code
  生成日期   : 2019-10-26 10:53:30
  最近修改   :
  功能描述   : 接口头文件
  函数列表   :
  修改历史   :
  1.日    期   : 2019年10月26日
    作    者   : l00249396
    修改内容   : 从《HiEPS V200 nmanager寄存器手册_TRNG.xml》自动生成

******************************************************************************/

/*****************************************************************************
  1 其他头文件包含
*****************************************************************************/

#ifndef __SOC_TRNG_INTERFACE_H__
#define __SOC_TRNG_INTERFACE_H__

#ifdef __cplusplus
    #if __cplusplus
        extern "C" {
    #endif
#endif



/*****************************************************************************
  2 宏定义
*****************************************************************************/

/****************************************************************************
                     (1/2) NEW_TRNG
 ****************************************************************************/
/* 寄存器说明：新老TRNG选择
   位域定义UNION结构:  SOC_TRNG_REG_TRNG_SEL_UNION */
#define SOC_TRNG_REG_TRNG_SEL_ADDR(base)              ((base) + (0x0300))

/* 寄存器说明：TRNG控制信号
   位域定义UNION结构:  SOC_TRNG_OTP_TRNG_SEL_UNION */
#define SOC_TRNG_OTP_TRNG_SEL_ADDR(base)              ((base) + (0x0304))

/* 寄存器说明：OTP对新老TRNG的选择
   位域定义UNION结构:  SOC_TRNG_OTP_SW_FLAG_UNION */
#define SOC_TRNG_OTP_SW_FLAG_ADDR(base)               ((base) + (0x0308))

/* 寄存器说明：FRO_EN_0
   位域定义UNION结构:  SOC_TRNG_FRO_EN_0_UNION */
#define SOC_TRNG_FRO_EN_0_ADDR(base)                  ((base) + (0x030c))

/* 寄存器说明：FRO_EN_1
   位域定义UNION结构:  SOC_TRNG_FRO_EN_1_UNION */
#define SOC_TRNG_FRO_EN_1_ADDR(base)                  ((base) + (0x0310))

/* 寄存器说明：GARO_EN
   位域定义UNION结构:  SOC_TRNG_GARO_EN_UNION */
#define SOC_TRNG_GARO_EN_ADDR(base)                   ((base) + (0x0314))

/* 寄存器说明：MT_FRO_EN
   位域定义UNION结构:  SOC_TRNG_MT_FRO_EN_UNION */
#define SOC_TRNG_MT_FRO_EN_ADDR(base)                 ((base) + (0x0318))

/* 寄存器说明：MT_GARO_EN
   位域定义UNION结构:  SOC_TRNG_MT_GARO_EN_UNION */
#define SOC_TRNG_MT_GARO_EN_ADDR(base)                ((base) + (0x031c))

/* 寄存器说明：ENTROPY_SOURCE_ST
   位域定义UNION结构:  SOC_TRNG_ENTROPY_SOURCE_ST_UNION */
#define SOC_TRNG_ENTROPY_SOURCE_ST_ADDR(base)         ((base) + (0x320))

/* 寄存器说明：sample_clock_cfg
   位域定义UNION结构:  SOC_TRNG_SAMPLE_CLK_CFG_UNION */
#define SOC_TRNG_SAMPLE_CLK_CFG_ADDR(base)            ((base) + (0x324))

/* 寄存器说明：INT_CHI_ONLINE_CLR
   位域定义UNION结构:  SOC_TRNG_INT_CHI_ONLINE_CLR_UNION */
#define SOC_TRNG_INT_CHI_ONLINE_CLR_ADDR(base)        ((base) + (0x328))

/* 寄存器说明：RAW_BYPASS_EN
   位域定义UNION结构:  SOC_TRNG_RAW_BYPASS_EN_UNION */
#define SOC_TRNG_RAW_BYPASS_EN_ADDR(base)             ((base) + (0x32c))

/* 寄存器说明：THRE_CHI_PRE1
   位域定义UNION结构:  SOC_TRNG_THRE_CHI_PRE1_UNION */
#define SOC_TRNG_THRE_CHI_PRE1_ADDR(base)             ((base) + (0x0330))

/* 寄存器说明：THRE_CHI_PRE2
   位域定义UNION结构:  SOC_TRNG_THRE_CHI_PRE2_UNION */
#define SOC_TRNG_THRE_CHI_PRE2_ADDR(base)             ((base) + (0x334))

/* 寄存器说明：THRE_CHI_PRE3
   位域定义UNION结构:  SOC_TRNG_THRE_CHI_PRE3_UNION */
#define SOC_TRNG_THRE_CHI_PRE3_ADDR(base)             ((base) + (0x338))

/* 寄存器说明：THRE_CHI_ENTROPY
   位域定义UNION结构:  SOC_TRNG_THRE_CHI_ENTROPY_UNION */
#define SOC_TRNG_THRE_CHI_ENTROPY_ADDR(base)          ((base) + (0x33c))

/* 寄存器说明：THRE_LONG_RUN
   位域定义UNION结构:  SOC_TRNG_THRE_LONG_RUN_UNION */
#define SOC_TRNG_THRE_LONG_RUN_ADDR(base)             ((base) + (0x340))

/* 寄存器说明：THRE_POKER
   位域定义UNION结构:  SOC_TRNG_THRE_POKER_UNION */
#define SOC_TRNG_THRE_POKER_ADDR(base)                ((base) + (0x344))

/* 寄存器说明：TEST_WIN_RAW_TEST
   位域定义UNION结构:  SOC_TRNG_TEST_WIN_RAW_TEST_UNION */
#define SOC_TRNG_TEST_WIN_RAW_TEST_ADDR(base)         ((base) + (0x348))

/* 寄存器说明：THRE_FAIL_NUM
   位域定义UNION结构:  SOC_TRNG_THRE_FAIL_NUM_UNION */
#define SOC_TRNG_THRE_FAIL_NUM_ADDR(base)             ((base) + (0x34c))

/* 寄存器说明：RAW_TEST_CLEAR
   位域定义UNION结构:  SOC_TRNG_RAW_TEST_CLEAR_UNION */
#define SOC_TRNG_RAW_TEST_CLEAR_ADDR(base)            ((base) + (0x350))

/* 寄存器说明：RAW_FAIL_CNT
   位域定义UNION结构:  SOC_TRNG_RAW_FAIL_CNT_UNION */
#define SOC_TRNG_RAW_FAIL_CNT_ADDR(base)              ((base) + (0x354))

/* 寄存器说明：RAW_STATE
   位域定义UNION结构:  SOC_TRNG_RAW_STATE_UNION */
#define SOC_TRNG_RAW_STATE_ADDR(base)                 ((base) + (0x358))

/* 寄存器说明：XOR_COMP_CFG
   位域定义UNION结构:  SOC_TRNG_XOR_COMP_CFG_UNION */
#define SOC_TRNG_XOR_COMP_CFG_ADDR(base)              ((base) + (0x35c))

/* 寄存器说明：XOR_CHAIN_CFG
   位域定义UNION结构:  SOC_TRNG_XOR_CHAIN_CFG_UNION */
#define SOC_TRNG_XOR_CHAIN_CFG_ADDR(base)             ((base) + (0x360))

/* 寄存器说明：POST_PROCESS
   位域定义UNION结构:  SOC_TRNG_POST_PROCESS_UNION */
#define SOC_TRNG_POST_PROCESS_ADDR(base)              ((base) + (0x364))

/* 寄存器说明：RESEED_CNT_LIMIT
   位域定义UNION结构:  SOC_TRNG_RESEED_CNT_LIMIT_UNION */
#define SOC_TRNG_RESEED_CNT_LIMIT_ADDR(base)          ((base) + (0x368))

/* 寄存器说明：POST_TEST_BYP
   位域定义UNION结构:  SOC_TRNG_POST_TEST_BYP_UNION */
#define SOC_TRNG_POST_TEST_BYP_ADDR(base)             ((base) + (0x36c))

/* 寄存器说明：POST_TEST_ALARM_MSK
   位域定义UNION结构:  SOC_TRNG_POST_TEST_ALARM_MSK_UNION */
#define SOC_TRNG_POST_TEST_ALARM_MSK_ADDR(base)       ((base) + (0x370))

/* 寄存器说明：DISTRIBUTION
   位域定义UNION结构:  SOC_TRNG_DISTRIBUTION_UNION */
#define SOC_TRNG_DISTRIBUTION_ADDR(base)              ((base) + (0x378))

/* 寄存器说明：ALARM_STATE
   位域定义UNION结构:  SOC_TRNG_ALARM_STATE_UNION */
#define SOC_TRNG_ALARM_STATE_ADDR(base)               ((base) + (0x37c))

/* 寄存器说明：THRE_POST_POKER
   位域定义UNION结构:  SOC_TRNG_THRE_POST_POKER_UNION */
#define SOC_TRNG_THRE_POST_POKER_ADDR(base)           ((base) + (0x384))

/* 寄存器说明：POST_TEST_WIN_RAW_TEST
   位域定义UNION结构:  SOC_TRNG_POST_TEST_WIN_RAW_TEST_UNION */
#define SOC_TRNG_POST_TEST_WIN_RAW_TEST_ADDR(base)    ((base) + (0x388))

/* 寄存器说明：POST_TEST_WIN_RAW_TEST
   位域定义UNION结构:  SOC_TRNG_THRE_POST_FAIL_NUM_UNION */
#define SOC_TRNG_THRE_POST_FAIL_NUM_ADDR(base)        ((base) + (0x38c))

/* 寄存器说明：POST_TEST_WIN_RAW_TEST
   位域定义UNION结构:  SOC_TRNG_POST_TEST_CLEAR_UNION */
#define SOC_TRNG_POST_TEST_CLEAR_ADDR(base)           ((base) + (0x390))

/* 寄存器说明：POST_TEST_WIN_RAW_TEST
   位域定义UNION结构:  SOC_TRNG_POST_FAIL_CNT_UNION */
#define SOC_TRNG_POST_FAIL_CNT_ADDR(base)             ((base) + (0x394))

/* 寄存器说明：TRNG_DATA_0
   位域定义UNION结构:  SOC_TRNG_WAIT_FOR_USE_UNION */
#define SOC_TRNG_WAIT_FOR_USE_ADDR(base)              ((base) + (0x39c))

/* 寄存器说明：TIME_OUT_REGS
   位域定义UNION结构:  SOC_TRNG_RNG_TIME_OUT_UNION */
#define SOC_TRNG_RNG_TIME_OUT_ADDR(base)              ((base) + (0x3a0))

/* 寄存器说明：CHI_TEST_STATE
   位域定义UNION结构:  SOC_TRNG_CHI_TEST_STATE_UNION */
#define SOC_TRNG_CHI_TEST_STATE_ADDR(base)            ((base) + (0x3a4))

/* 寄存器说明：TRNG_CLK_EN
   位域定义UNION结构:  SOC_TRNG_CLK_EN_UNION */
#define SOC_TRNG_CLK_EN_ADDR(base)                    ((base) + (0x3a8))

/* 寄存器说明：TRNG_DONE
   位域定义UNION结构:  SOC_TRNG_DONE_UNION */
#define SOC_TRNG_DONE_ADDR(base)                      ((base) + (0x3ac))

/* 寄存器说明：TRNG_READY
   位域定义UNION结构:  SOC_TRNG_READY_UNION */
#define SOC_TRNG_READY_ADDR(base)                     ((base) + (0x3b0))

/* 寄存器说明：TRNG_READY_THRE
   位域定义UNION结构:  SOC_TRNG_READY_THRE_UNION */
#define SOC_TRNG_READY_THRE_ADDR(base)                ((base) + (0x3b4))

/* 寄存器说明：V
   位域定义UNION结构:  SOC_TRNG_FIFO_DATA_UNION */
#define SOC_TRNG_FIFO_DATA_ADDR(base)                 ((base) + (0x3b8))

/* 寄存器说明：PRT_LOCK
   位域定义UNION结构:  SOC_TRNG_PRT_LOCK_UNION */
#define SOC_TRNG_PRT_LOCK_ADDR(base)                  ((base) + (0x3bc))

/* 寄存器说明：ENTROPY_MERGE
   位域定义UNION结构:  SOC_TRNG_ENTROPY_MERGE_UNION */
#define SOC_TRNG_ENTROPY_MERGE_ADDR(base)             ((base) + (0x3c0))

/* 寄存器说明：KNOWN_ANSWER_TEST
   位域定义UNION结构:  SOC_TRNG_KNOWN_ANSWER_TEST_UNION */
#define SOC_TRNG_KNOWN_ANSWER_TEST_ADDR(base)         ((base) + (0x3c4))

/* 寄存器说明：信号保护的异常状态
   位域定义UNION结构:  SOC_TRNG_SIGNAL_ALARM_UNION */
#define SOC_TRNG_SIGNAL_ALARM_ADDR(base)              ((base) + (0x3c8))



/****************************************************************************
                     (2/2) reg_define 
 ****************************************************************************/
/* 寄存器说明：TRNG控制寄存器
   位域定义UNION结构:  SOC_TRNG_HISEC_COM_TRNG_CTRL_UNION */
#define SOC_TRNG_HISEC_COM_TRNG_CTRL_ADDR(base)       ((base) + (0x0000))

/* 寄存器说明：TRNG的FIFO数据寄存器
   位域定义UNION结构:  SOC_TRNG_HISEC_COM_TRNG_FIFO_DATA_UNION */
#define SOC_TRNG_HISEC_COM_TRNG_FIFO_DATA_ADDR(base)  ((base) + (0x0004))

/* 寄存器说明：TRNG的FIFO数据寄存器的状态
   位域定义UNION结构:  SOC_TRNG_HISEC_COM_TRNG_DATA_ST_UNION */
#define SOC_TRNG_HISEC_COM_TRNG_DATA_ST_ADDR(base)    ((base) + (0x0008))

/* 寄存器说明：熵源连续检测失败的次数统计（仅用于调试）
   位域定义UNION结构:  SOC_TRNG_HISEC_COM_TRNG_ENTROPY_MONO_CNT_UNION */
#define SOC_TRNG_HISEC_COM_TRNG_ENTROPY_MONO_CNT_ADDR(base) ((base) + (0x000C))

/* 寄存器说明：随机数连续检测失败次数统计（仅用于调试）
   位域定义UNION结构:  SOC_TRNG_HISEC_COM_TRNG_MONO_CNT_UNION */
#define SOC_TRNG_HISEC_COM_TRNG_MONO_CNT_ADDR(base)   ((base) + (0x0010))

/* 寄存器说明：告警源状态寄存器
   位域定义UNION结构:  SOC_TRNG_HISEC_COM_TRNG_ALARM_SRC_UNION */
#define SOC_TRNG_HISEC_COM_TRNG_ALARM_SRC_ADDR(base)  ((base) + (0x0014))

/* 寄存器说明：告警源屏蔽寄存器
   位域定义UNION结构:  SOC_TRNG_HISEC_COM_TRNG_ALARM_MASK_UNION */
#define SOC_TRNG_HISEC_COM_TRNG_ALARM_MASK_ADDR(base) ((base) + (0x0018))

/* 寄存器说明：屏蔽后的告警源状态寄存器
   位域定义UNION结构:  SOC_TRNG_HISEC_COM_TRNG_ALARM_SRC_POST_UNION */
#define SOC_TRNG_HISEC_COM_TRNG_ALARM_SRC_POST_ADDR(base) ((base) + (0x001C))

/* 寄存器说明：trng工作状态寄存器
   位域定义UNION结构:  SOC_TRNG_HISEC_COM_TRNG_FIFO_READY_UNION */
#define SOC_TRNG_HISEC_COM_TRNG_FIFO_READY_ADDR(base) ((base) + (0x0020))

/* 寄存器说明：4个模拟IP 核工作模式寄存器
   位域定义UNION结构:  SOC_TRNG_HISEC_COM_TRNG_OSC_TEST_SEL_UNION */
#define SOC_TRNG_HISEC_COM_TRNG_OSC_TEST_SEL_ADDR(base) ((base) + (0x0024))

/* 寄存器说明：随机数不产生超时时间配置寄存器
   位域定义UNION结构:  SOC_TRNG_HISEC_COM_TRNG_TIM_OUT_PERIOD_UNION */
#define SOC_TRNG_HISEC_COM_TRNG_TIM_OUT_PERIOD_ADDR(base) ((base) + (0x0028))

/* 寄存器说明：告警源和屏蔽后告警源清除寄存器
   位域定义UNION结构:  SOC_TRNG_HISEC_COM_TRNG_ALARM_CLR_UNION */
#define SOC_TRNG_HISEC_COM_TRNG_ALARM_CLR_ADDR(base)  ((base) + (0x002C))

/* 寄存器说明：熵源在线检查连续失败的阀值配置寄存器。
   位域定义UNION结构:  SOC_TRNG_HISEC_COM_TRNG_PRE_CK_CNT_UNION */
#define SOC_TRNG_HISEC_COM_TRNG_PRE_CK_CNT_ADDR(base) ((base) + (0x0030))

/* 寄存器说明：熵源在线检查的MONO检查阀值配置
   位域定义UNION结构:  SOC_TRNG_HISEC_COM_TRNG_PRE_MONO_CNT_UNION */
#define SOC_TRNG_HISEC_COM_TRNG_PRE_MONO_CNT_ADDR(base) ((base) + (0x0034))

/* 寄存器说明：熵源在线检查的LONG RUN检查阀值配置。
   位域定义UNION结构:  SOC_TRNG_HISEC_COM_TRNG_PRE_LONG_RUN_CNT_UNION */
#define SOC_TRNG_HISEC_COM_TRNG_PRE_LONG_RUN_CNT_ADDR(base) ((base) + (0x0038))

/* 寄存器说明：熵源在线检查的RUN检查阀值配置。
   位域定义UNION结构:  SOC_TRNG_HISEC_COM_TRNG_PRE_RUN_CNT_UNION */
#define SOC_TRNG_HISEC_COM_TRNG_PRE_RUN_CNT_ADDR(base) ((base) + (0x003C))

/* 寄存器说明：熵源在线检查的SERIAL检查阀值配置。
   位域定义UNION结构:  SOC_TRNG_HISEC_COM_TRNG_PRE_SERIAL_CNT_UNION */
#define SOC_TRNG_HISEC_COM_TRNG_PRE_SERIAL_CNT_ADDR(base) ((base) + (0x0040))

/* 寄存器说明：熵源在线检查的POKER检查阀值配置。
   位域定义UNION结构:  SOC_TRNG_HISEC_COM_TRNG_PRE_POKER_CNT_UNION */
#define SOC_TRNG_HISEC_COM_TRNG_PRE_POKER_CNT_ADDR(base) ((base) + (0x0044))

/* 寄存器说明：熵源在线检查的ATCR01检查阀值配置。
   位域定义UNION结构:  SOC_TRNG_HISEC_COM_TRNG_PRE_ATCR01_CNT_UNION */
#define SOC_TRNG_HISEC_COM_TRNG_PRE_ATCR01_CNT_ADDR(base) ((base) + (0x0048))

/* 寄存器说明：熵源在线检查的ATCR23检查阀值配置。
   位域定义UNION结构:  SOC_TRNG_HISEC_COM_TRNG_PRE_ATCR23_CNT_UNION */
#define SOC_TRNG_HISEC_COM_TRNG_PRE_ATCR23_CNT_ADDR(base) ((base) + (0x004C))

/* 寄存器说明：DRBG后随机数在线检查连续失败的阀值配置寄存器。
   位域定义UNION结构:  SOC_TRNG_HISEC_COM_TRNG_POS_CK_CNT_UNION */
#define SOC_TRNG_HISEC_COM_TRNG_POS_CK_CNT_ADDR(base) ((base) + (0x0050))

/* 寄存器说明：DRBG后随机数在线检查的MONO检查阀值配置
   位域定义UNION结构:  SOC_TRNG_HISEC_COM_TRNG_POS_MONO_CNT_UNION */
#define SOC_TRNG_HISEC_COM_TRNG_POS_MONO_CNT_ADDR(base) ((base) + (0x0054))

/* 寄存器说明：DRBG后随机数在线检查的LONG RUN检查阀值配置。
   位域定义UNION结构:  SOC_TRNG_HISEC_COM_TRNG_POS_LONG_RUN_CNT_UNION */
#define SOC_TRNG_HISEC_COM_TRNG_POS_LONG_RUN_CNT_ADDR(base) ((base) + (0x0058))

/* 寄存器说明：DRBG后随机数在线检查的RUN检查阀值配置。
   位域定义UNION结构:  SOC_TRNG_HISEC_COM_TRNG_POS_RUN_CNT_UNION */
#define SOC_TRNG_HISEC_COM_TRNG_POS_RUN_CNT_ADDR(base) ((base) + (0x005C))

/* 寄存器说明：DRBG后随机数在线检查的SERIAL检查阀值配置。
   位域定义UNION结构:  SOC_TRNG_HISEC_COM_TRNG_POS_SERIAL_CNT_UNION */
#define SOC_TRNG_HISEC_COM_TRNG_POS_SERIAL_CNT_ADDR(base) ((base) + (0x0060))

/* 寄存器说明：DRBG后随机数在线检查的POKER检查阀值配置。
   位域定义UNION结构:  SOC_TRNG_HISEC_COM_TRNG_POS_POKER_CNT_UNION */
#define SOC_TRNG_HISEC_COM_TRNG_POS_POKER_CNT_ADDR(base) ((base) + (0x0064))

/* 寄存器说明：DRBG后随机数在线检查的ATCR01检查阀值配置。
   位域定义UNION结构:  SOC_TRNG_HISEC_COM_TRNG_POS_ATCR01_CNT_UNION */
#define SOC_TRNG_HISEC_COM_TRNG_POS_ATCR01_CNT_ADDR(base) ((base) + (0x0068))

/* 寄存器说明：DRBG后随机数在线检查的ATCR23检查阀值配置。
   位域定义UNION结构:  SOC_TRNG_HISEC_COM_TRNG_POS_ATCR23_CNT_UNION */
#define SOC_TRNG_HISEC_COM_TRNG_POS_ATCR23_CNT_ADDR(base) ((base) + (0x006C))

/* 寄存器说明：熵源AIS31检查最大失败次数配置
   位域定义UNION结构:  SOC_TRNG_HISEC_COM_TRNG_AIS31_FAIL_CNT_UNION */
#define SOC_TRNG_HISEC_COM_TRNG_AIS31_FAIL_CNT_ADDR(base) ((base) + (0x0070))

/* 寄存器说明：熵源AIS31检查最大块次数配置
   位域定义UNION结构:  SOC_TRNG_HISEC_COM_TRNG_AIS31_BLOCK_CNT_UNION */
#define SOC_TRNG_HISEC_COM_TRNG_AIS31_BLOCK_CNT_ADDR(base) ((base) + (0x0074))

/* 寄存器说明：熵源AIS31 POKER检查的最低阈值
   位域定义UNION结构:  SOC_TRNG_HISEC_COM_TRNG_AIS31_POKER_LOW_UNION */
#define SOC_TRNG_HISEC_COM_TRNG_AIS31_POKER_LOW_ADDR(base) ((base) + (0x0078))

/* 寄存器说明：熵源AIS31 POKER检查的最高阈值
   位域定义UNION结构:  SOC_TRNG_HISEC_COM_TRNG_AIS31_POKER_HIG_UNION */
#define SOC_TRNG_HISEC_COM_TRNG_AIS31_POKER_HIG_ADDR(base) ((base) + (0x007C))

/* 寄存器说明：
   位域定义UNION结构:  SOC_TRNG_UNLOCK_UNION */
#define SOC_TRNG_UNLOCK_ADDR(base)                    ((base) + (0x0080))

/* 寄存器说明：PRE1阈值
   位域定义UNION结构:  SOC_TRNG_CTRL_CHI_TH_PRE1_UNION */
#define SOC_TRNG_CTRL_CHI_TH_PRE1_ADDR(base)          ((base) + (0x0084))

/* 寄存器说明：PRE2阈值
   位域定义UNION结构:  SOC_TRNG_CTRL_CHI_TH_PRE2_UNION */
#define SOC_TRNG_CTRL_CHI_TH_PRE2_ADDR(base)          ((base) + (0x0088))

/* 寄存器说明：PRE3阈值
   位域定义UNION结构:  SOC_TRNG_CTRL_CHI_TH_PRE3_UNION */
#define SOC_TRNG_CTRL_CHI_TH_PRE3_ADDR(base)          ((base) + (0x008C))

/* 寄存器说明：ENTROPY阈值
   位域定义UNION结构:  SOC_TRNG_CTRL_CHI_TH_ENTROPY_UNION */
#define SOC_TRNG_CTRL_CHI_TH_ENTROPY_ADDR(base)       ((base) + (0x0090))

/* 寄存器说明：TRNG中断状态清除寄存器
   位域定义UNION结构:  SOC_TRNG_INT_CLR_UNION */
#define SOC_TRNG_INT_CLR_ADDR(base)                   ((base) + (0x0094))

/* 寄存器说明：TRNG中断MASK控制寄存器
   位域定义UNION结构:  SOC_TRNG_INT_MASK_UNION */
#define SOC_TRNG_INT_MASK_ADDR(base)                  ((base) + (0x0098))

/* 寄存器说明：TRNG屏蔽前中断状态寄存器
   位域定义UNION结构:  SOC_TRNG_INT_SRC_STATUS_UNION */
#define SOC_TRNG_INT_SRC_STATUS_ADDR(base)            ((base) + (0x009C))

/* 寄存器说明：TRNG屏蔽后中断状态寄存器
   位域定义UNION结构:  SOC_TRNG_INT_STATUS_UNION */
#define SOC_TRNG_INT_STATUS_ADDR(base)                ((base) + (0x00A0))

/* 寄存器说明：TRNG的OTPC状态寄存器
   位域定义UNION结构:  SOC_TRNG_OTPC_STATUS_0_UNION */
#define SOC_TRNG_OTPC_STATUS_0_ADDR(base)             ((base) + (0x00A4))

/* 寄存器说明：TRNG的OTPC状态寄存器
   位域定义UNION结构:  SOC_TRNG_OTPC_STATUS_1_UNION */
#define SOC_TRNG_OTPC_STATUS_1_ADDR(base)             ((base) + (0x00A8))

/* 寄存器说明：OTPC_TRNG_TRIM寄存器
   位域定义UNION结构:  SOC_TRNG_OTPC_TRNG_TRIM_0_UNION */
#define SOC_TRNG_OTPC_TRNG_TRIM_0_ADDR(base)          ((base) + (0x00B0))

/* 寄存器说明：OTPC_TRNG_TRIM寄存器
   位域定义UNION结构:  SOC_TRNG_OTPC_TRNG_TRIM_1_UNION */
#define SOC_TRNG_OTPC_TRNG_TRIM_1_ADDR(base)          ((base) + (0x00B4))

/* 寄存器说明：OTPC_TRNG_TRIM寄存器
   位域定义UNION结构:  SOC_TRNG_OTPC_TRNG_TRIM_2_UNION */
#define SOC_TRNG_OTPC_TRNG_TRIM_2_ADDR(base)          ((base) + (0x00B8))

/* 寄存器说明：OTPC_TRNG_TRIM寄存器
   位域定义UNION结构:  SOC_TRNG_OTPC_TRNG_TRIM_3_UNION */
#define SOC_TRNG_OTPC_TRNG_TRIM_3_ADDR(base)          ((base) + (0x00Bc))

/* 寄存器说明：OTPC_TRNG_TRIM值的crc寄存器
   位域定义UNION结构:  SOC_TRNG_OTPC_TRNG_TRIM_CRC_UNION */
#define SOC_TRNG_OTPC_TRNG_TRIM_CRC_ADDR(base)        ((base) + (0x00c0))

/* 寄存器说明：超过此门限才允许软件读取TRNG随机数
   位域定义UNION结构:  SOC_TRNG_FIFO_RD_LINE_UNION */
#define SOC_TRNG_FIFO_RD_LINE_ADDR(base)              ((base) + (0x00c4))

/* 寄存器说明：DRBG非全种模式门限值
   位域定义UNION结构:  SOC_TRNG_DRBG_CYCLE_NUM_UNION */
#define SOC_TRNG_DRBG_CYCLE_NUM_ADDR(base)            ((base) + (0x00c8))





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
                     (1/2) NEW_TRNG
 ****************************************************************************/
/*****************************************************************************
 结构名    : SOC_TRNG_REG_TRNG_SEL_UNION
 结构说明  : REG_TRNG_SEL 寄存器结构定义。地址偏移量:0x0300，初值:0x00000005，宽度:32
 寄存器说明: 新老TRNG选择
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reg_trng_sel : 4;  /* bit[0-3] : 新老TRNG选择，“1010”表示选择新TRNG，“其他值”表示选择老TRNG；默认值“0101” */
        unsigned int  reserved     : 28; /* bit[4-31]:  */
    } reg;
} SOC_TRNG_REG_TRNG_SEL_UNION;
#endif
#define SOC_TRNG_REG_TRNG_SEL_reg_trng_sel_START  (0)
#define SOC_TRNG_REG_TRNG_SEL_reg_trng_sel_END    (3)


/*****************************************************************************
 结构名    : SOC_TRNG_OTP_TRNG_SEL_UNION
 结构说明  : OTP_TRNG_SEL 寄存器结构定义。地址偏移量:0x0304，初值:0x00000005，宽度:32
 寄存器说明: TRNG控制信号
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  otp_trng_sel : 4;  /* bit[0-3] : TRNG的控制信号，选择来自OTP还是寄存器配置,0xa表示选择寄存器配置,0x5表示otp配置,其他值无效，目前接死4'ha，表示由寄存器配置。 */
        unsigned int  reserved     : 28; /* bit[4-31]:  */
    } reg;
} SOC_TRNG_OTP_TRNG_SEL_UNION;
#endif
#define SOC_TRNG_OTP_TRNG_SEL_otp_trng_sel_START  (0)
#define SOC_TRNG_OTP_TRNG_SEL_otp_trng_sel_END    (3)


/*****************************************************************************
 结构名    : SOC_TRNG_OTP_SW_FLAG_UNION
 结构说明  : OTP_SW_FLAG 寄存器结构定义。地址偏移量:0x0308，初值:0x00000005，宽度:32
 寄存器说明: OTP对新老TRNG的选择
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  otp_sw_flag : 4;  /* bit[0-3] : otp对新老TRNG的选择,0xa表示选新trng,其他值表示选老TRNG; 目前接死由寄存器配置选择新老TRNG； */
        unsigned int  reserved    : 28; /* bit[4-31]:  */
    } reg;
} SOC_TRNG_OTP_SW_FLAG_UNION;
#endif
#define SOC_TRNG_OTP_SW_FLAG_otp_sw_flag_START  (0)
#define SOC_TRNG_OTP_SW_FLAG_otp_sw_flag_END    (3)


/*****************************************************************************
 结构名    : SOC_TRNG_FRO_EN_0_UNION
 结构说明  : FRO_EN_0 寄存器结构定义。地址偏移量:0x030c，初值:0x00000000，宽度:32
 寄存器说明: FRO_EN_0
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  fro_en_0 : 32; /* bit[0-31]: FRO的使能信号,1bit对应1个FRO */
    } reg;
} SOC_TRNG_FRO_EN_0_UNION;
#endif
#define SOC_TRNG_FRO_EN_0_fro_en_0_START  (0)
#define SOC_TRNG_FRO_EN_0_fro_en_0_END    (31)


/*****************************************************************************
 结构名    : SOC_TRNG_FRO_EN_1_UNION
 结构说明  : FRO_EN_1 寄存器结构定义。地址偏移量:0x0310，初值:0x00000000，宽度:32
 寄存器说明: FRO_EN_1
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  fro_en_1 : 18; /* bit[0-17] : FRO的使能信号,1bit对应1个FRO */
        unsigned int  reserved : 14; /* bit[18-31]:  */
    } reg;
} SOC_TRNG_FRO_EN_1_UNION;
#endif
#define SOC_TRNG_FRO_EN_1_fro_en_1_START  (0)
#define SOC_TRNG_FRO_EN_1_fro_en_1_END    (17)


/*****************************************************************************
 结构名    : SOC_TRNG_GARO_EN_UNION
 结构说明  : GARO_EN 寄存器结构定义。地址偏移量:0x0314，初值:0x00000000，宽度:32
 寄存器说明: GARO_EN
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  garo_en  : 16; /* bit[0-15] : FRO的使能信号,1bit对应1个FRO */
        unsigned int  reserved : 16; /* bit[16-31]:  */
    } reg;
} SOC_TRNG_GARO_EN_UNION;
#endif
#define SOC_TRNG_GARO_EN_garo_en_START   (0)
#define SOC_TRNG_GARO_EN_garo_en_END     (15)


/*****************************************************************************
 结构名    : SOC_TRNG_MT_FRO_EN_UNION
 结构说明  : MT_FRO_EN 寄存器结构定义。地址偏移量:0x0318，初值:0x0000000F，宽度:32
 寄存器说明: MT_FRO_EN
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  mt_fro_en : 8;  /* bit[0-7] : GARO的使能信号,1bit对应1个GARO */
        unsigned int  reserved  : 24; /* bit[8-31]:  */
    } reg;
} SOC_TRNG_MT_FRO_EN_UNION;
#endif
#define SOC_TRNG_MT_FRO_EN_mt_fro_en_START  (0)
#define SOC_TRNG_MT_FRO_EN_mt_fro_en_END    (7)


/*****************************************************************************
 结构名    : SOC_TRNG_MT_GARO_EN_UNION
 结构说明  : MT_GARO_EN 寄存器结构定义。地址偏移量:0x031c，初值:0x00000000，宽度:32
 寄存器说明: MT_GARO_EN
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  mt_garo_en : 4;  /* bit[0-3] : MTFRO的使能信号,1bit对应1个MTFRO */
        unsigned int  reserved   : 28; /* bit[4-31]:  */
    } reg;
} SOC_TRNG_MT_GARO_EN_UNION;
#endif
#define SOC_TRNG_MT_GARO_EN_mt_garo_en_START  (0)
#define SOC_TRNG_MT_GARO_EN_mt_garo_en_END    (3)


/*****************************************************************************
 结构名    : SOC_TRNG_ENTROPY_SOURCE_ST_UNION
 结构说明  : ENTROPY_SOURCE_ST 寄存器结构定义。地址偏移量:0x320，初值:0x00000000，宽度:32
 寄存器说明: ENTROPY_SOURCE_ST
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  src_afifo_empty : 4;  /* bit[0-3] : 4路随机源的异步fifo实时的空状态,高电平有效. */
        unsigned int  reserved        : 28; /* bit[4-31]:  */
    } reg;
} SOC_TRNG_ENTROPY_SOURCE_ST_UNION;
#endif
#define SOC_TRNG_ENTROPY_SOURCE_ST_src_afifo_empty_START  (0)
#define SOC_TRNG_ENTROPY_SOURCE_ST_src_afifo_empty_END    (3)


/*****************************************************************************
 结构名    : SOC_TRNG_SAMPLE_CLK_CFG_UNION
 结构说明  : SAMPLE_CLK_CFG 寄存器结构定义。地址偏移量:0x324，初值:0x0000001F，宽度:32
 寄存器说明: sample_clock_cfg
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sample_clk_cfg : 14; /* bit[0-13] : 
                                                          13:8 ro环分频配置；
                                                          7:6 预留;
                                                          5: 采样环震荡使能;
                                                          4：mt_garo的采样时钟选择； 1为选clk_sys
                                                          3：mt_fro的采样时钟选择； 1为选clk_sys
                                                          2:garo的采样时钟选择； 1为选clk_sys
                                                          1:fro的采样时钟选择； 1为选clk_sys
                                                          0:分频时钟选择; 1为选clk_sys */
        unsigned int  reserved       : 18; /* bit[14-31]:  */
    } reg;
} SOC_TRNG_SAMPLE_CLK_CFG_UNION;
#endif
#define SOC_TRNG_SAMPLE_CLK_CFG_sample_clk_cfg_START  (0)
#define SOC_TRNG_SAMPLE_CLK_CFG_sample_clk_cfg_END    (13)


/*****************************************************************************
 结构名    : SOC_TRNG_INT_CHI_ONLINE_CLR_UNION
 结构说明  : INT_CHI_ONLINE_CLR 寄存器结构定义。地址偏移量:0x328，初值:0x00000000，宽度:32
 寄存器说明: INT_CHI_ONLINE_CLR
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  int_chi_online_clr : 1;  /* bit[0-0] : chi_test的清状态信号,高脉冲有效 */
        unsigned int  reserved           : 31; /* bit[1-31]:  */
    } reg;
} SOC_TRNG_INT_CHI_ONLINE_CLR_UNION;
#endif
#define SOC_TRNG_INT_CHI_ONLINE_CLR_int_chi_online_clr_START  (0)
#define SOC_TRNG_INT_CHI_ONLINE_CLR_int_chi_online_clr_END    (0)


/*****************************************************************************
 结构名    : SOC_TRNG_RAW_BYPASS_EN_UNION
 结构说明  : RAW_BYPASS_EN 寄存器结构定义。地址偏移量:0x32c，初值:0x00000AAA，宽度:32
 寄存器说明: RAW_BYPASS_EN
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  bypass_en_poker : 4;  /* bit[0-3]  : poker_test的旁路使能,0x5有效,其他值无效;只允是0x5和0xa */
        unsigned int  bypass_en_chi   : 4;  /* bit[4-7]  : chi_test的旁路使能,0x5有效,其他值无效;只允是0x5和0xa */
        unsigned int  bypass_en_lrun  : 4;  /* bit[8-11] : long_run_test的旁路使能,0x5有效,其他值无效;只允是0x5和0xa */
        unsigned int  reserved        : 20; /* bit[12-31]:  */
    } reg;
} SOC_TRNG_RAW_BYPASS_EN_UNION;
#endif
#define SOC_TRNG_RAW_BYPASS_EN_bypass_en_poker_START  (0)
#define SOC_TRNG_RAW_BYPASS_EN_bypass_en_poker_END    (3)
#define SOC_TRNG_RAW_BYPASS_EN_bypass_en_chi_START    (4)
#define SOC_TRNG_RAW_BYPASS_EN_bypass_en_chi_END      (7)
#define SOC_TRNG_RAW_BYPASS_EN_bypass_en_lrun_START   (8)
#define SOC_TRNG_RAW_BYPASS_EN_bypass_en_lrun_END     (11)


/*****************************************************************************
 结构名    : SOC_TRNG_THRE_CHI_PRE1_UNION
 结构说明  : THRE_CHI_PRE1 寄存器结构定义。地址偏移量:0x0330，初值:0x000001C2，宽度:32
 寄存器说明: THRE_CHI_PRE1
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  thre_pre1 : 9;  /* bit[0-8] : Chi_test的阈值1 */
        unsigned int  reserved  : 23; /* bit[9-31]:  */
    } reg;
} SOC_TRNG_THRE_CHI_PRE1_UNION;
#endif
#define SOC_TRNG_THRE_CHI_PRE1_thre_pre1_START  (0)
#define SOC_TRNG_THRE_CHI_PRE1_thre_pre1_END    (8)


/*****************************************************************************
 结构名    : SOC_TRNG_THRE_CHI_PRE2_UNION
 结构说明  : THRE_CHI_PRE2 寄存器结构定义。地址偏移量:0x334，初值:0x00000000，宽度:32
 寄存器说明: THRE_CHI_PRE2
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  thre_pre2 : 9;  /* bit[0-8] : Chi_test的阈值2 */
        unsigned int  reserved  : 23; /* bit[9-31]:  */
    } reg;
} SOC_TRNG_THRE_CHI_PRE2_UNION;
#endif
#define SOC_TRNG_THRE_CHI_PRE2_thre_pre2_START  (0)
#define SOC_TRNG_THRE_CHI_PRE2_thre_pre2_END    (8)


/*****************************************************************************
 结构名    : SOC_TRNG_THRE_CHI_PRE3_UNION
 结构说明  : THRE_CHI_PRE3 寄存器结构定义。地址偏移量:0x338，初值:0x000001C2，宽度:32
 寄存器说明: THRE_CHI_PRE3
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  thre_pre3 : 9;  /* bit[0-8] : Chi_test的阈值3 */
        unsigned int  reserved  : 23; /* bit[9-31]:  */
    } reg;
} SOC_TRNG_THRE_CHI_PRE3_UNION;
#endif
#define SOC_TRNG_THRE_CHI_PRE3_thre_pre3_START  (0)
#define SOC_TRNG_THRE_CHI_PRE3_thre_pre3_END    (8)


/*****************************************************************************
 结构名    : SOC_TRNG_THRE_CHI_ENTROPY_UNION
 结构说明  : THRE_CHI_ENTROPY 寄存器结构定义。地址偏移量:0x33c，初值:0x000001C2，宽度:32
 寄存器说明: THRE_CHI_ENTROPY
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  thre_entropy : 9;  /* bit[0-8] : Chi_test的阈值4 */
        unsigned int  reserved     : 23; /* bit[9-31]:  */
    } reg;
} SOC_TRNG_THRE_CHI_ENTROPY_UNION;
#endif
#define SOC_TRNG_THRE_CHI_ENTROPY_thre_entropy_START  (0)
#define SOC_TRNG_THRE_CHI_ENTROPY_thre_entropy_END    (8)


/*****************************************************************************
 结构名    : SOC_TRNG_THRE_LONG_RUN_UNION
 结构说明  : THRE_LONG_RUN 寄存器结构定义。地址偏移量:0x340，初值:0x00000022，宽度:32
 寄存器说明: THRE_LONG_RUN
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  thre_long_run : 7;  /* bit[0-6] : long_run_test的阈值 */
        unsigned int  reserved      : 25; /* bit[7-31]:  */
    } reg;
} SOC_TRNG_THRE_LONG_RUN_UNION;
#endif
#define SOC_TRNG_THRE_LONG_RUN_thre_long_run_START  (0)
#define SOC_TRNG_THRE_LONG_RUN_thre_long_run_END    (6)


/*****************************************************************************
 结构名    : SOC_TRNG_THRE_POKER_UNION
 结构说明  : THRE_POKER 寄存器结构定义。地址偏移量:0x344，初值:0x00000FFF，宽度:32
 寄存器说明: THRE_POKER
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  poker_ck_hig : 16; /* bit[0-15] : poker_test的阈值 */
        unsigned int  reserved     : 16; /* bit[16-31]:  */
    } reg;
} SOC_TRNG_THRE_POKER_UNION;
#endif
#define SOC_TRNG_THRE_POKER_poker_ck_hig_START  (0)
#define SOC_TRNG_THRE_POKER_poker_ck_hig_END    (15)


/*****************************************************************************
 结构名    : SOC_TRNG_TEST_WIN_RAW_TEST_UNION
 结构说明  : TEST_WIN_RAW_TEST 寄存器结构定义。地址偏移量:0x348，初值:0x00666666，宽度:32
 寄存器说明: TEST_WIN_RAW_TEST
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  test_win_poker   : 8;  /* bit[0-7]  : poker_test的fail统计窗口 */
        unsigned int  test_win_chi     : 8;  /* bit[8-15] : chi_test的fail统计窗口 */
        unsigned int  test_win_longrun : 8;  /* bit[16-23]: long_run_test的fail统计窗口 */
        unsigned int  reserved         : 8;  /* bit[24-31]:  */
    } reg;
} SOC_TRNG_TEST_WIN_RAW_TEST_UNION;
#endif
#define SOC_TRNG_TEST_WIN_RAW_TEST_test_win_poker_START    (0)
#define SOC_TRNG_TEST_WIN_RAW_TEST_test_win_poker_END      (7)
#define SOC_TRNG_TEST_WIN_RAW_TEST_test_win_chi_START      (8)
#define SOC_TRNG_TEST_WIN_RAW_TEST_test_win_chi_END        (15)
#define SOC_TRNG_TEST_WIN_RAW_TEST_test_win_longrun_START  (16)
#define SOC_TRNG_TEST_WIN_RAW_TEST_test_win_longrun_END    (23)


/*****************************************************************************
 结构名    : SOC_TRNG_THRE_FAIL_NUM_UNION
 结构说明  : THRE_FAIL_NUM 寄存器结构定义。地址偏移量:0x34c，初值:0x00666666，宽度:32
 寄存器说明: THRE_FAIL_NUM
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  thre_fail_num_poker   : 8;  /* bit[0-7]  : poker_test在fail统计窗口内允许的fail上限,,超过该上限会触发中断 */
        unsigned int  thre_fail_num_chi     : 8;  /* bit[8-15] : chi_test在fail统计窗口内允许的fail上限,,超过该上限会触发中断 */
        unsigned int  thre_fail_num_longrun : 8;  /* bit[16-23]: long_run_test在fail统计窗口内允许的fail上限,超过该上限会触发中断 */
        unsigned int  reserved              : 8;  /* bit[24-31]:  */
    } reg;
} SOC_TRNG_THRE_FAIL_NUM_UNION;
#endif
#define SOC_TRNG_THRE_FAIL_NUM_thre_fail_num_poker_START    (0)
#define SOC_TRNG_THRE_FAIL_NUM_thre_fail_num_poker_END      (7)
#define SOC_TRNG_THRE_FAIL_NUM_thre_fail_num_chi_START      (8)
#define SOC_TRNG_THRE_FAIL_NUM_thre_fail_num_chi_END        (15)
#define SOC_TRNG_THRE_FAIL_NUM_thre_fail_num_longrun_START  (16)
#define SOC_TRNG_THRE_FAIL_NUM_thre_fail_num_longrun_END    (23)


/*****************************************************************************
 结构名    : SOC_TRNG_RAW_TEST_CLEAR_UNION
 结构说明  : RAW_TEST_CLEAR 寄存器结构定义。地址偏移量:0x350，初值:0x00000000，宽度:32
 寄存器说明: RAW_TEST_CLEAR
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  clear_poker   : 1;  /* bit[0-0] : long_run_test的fail统计结果清零 */
        unsigned int  clear_chi     : 1;  /* bit[1-1] : long_run_test的fail统计结果清零 */
        unsigned int  clear_longrun : 1;  /* bit[2-2] : long_run_test的fail统计结果清零 */
        unsigned int  reserved      : 29; /* bit[3-31]:  */
    } reg;
} SOC_TRNG_RAW_TEST_CLEAR_UNION;
#endif
#define SOC_TRNG_RAW_TEST_CLEAR_clear_poker_START    (0)
#define SOC_TRNG_RAW_TEST_CLEAR_clear_poker_END      (0)
#define SOC_TRNG_RAW_TEST_CLEAR_clear_chi_START      (1)
#define SOC_TRNG_RAW_TEST_CLEAR_clear_chi_END        (1)
#define SOC_TRNG_RAW_TEST_CLEAR_clear_longrun_START  (2)
#define SOC_TRNG_RAW_TEST_CLEAR_clear_longrun_END    (2)


/*****************************************************************************
 结构名    : SOC_TRNG_RAW_FAIL_CNT_UNION
 结构说明  : RAW_FAIL_CNT 寄存器结构定义。地址偏移量:0x354，初值:0x00000000，宽度:32
 寄存器说明: RAW_FAIL_CNT
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  fail_num_poker   : 8;  /* bit[0-7]  : 实时的long_run_test的fail次数,若该值大于test_win_**,则会触发中断 */
        unsigned int  fail_num_chi     : 8;  /* bit[8-15] : 实时的long_run_test的fail次数,若该值大于test_win_**,则会触发中断 */
        unsigned int  fail_num_longrun : 8;  /* bit[16-23]: 实时的long_run_test的fail次数,若该值大于test_win_**,则会触发中断 */
        unsigned int  reserved         : 8;  /* bit[24-31]:  */
    } reg;
} SOC_TRNG_RAW_FAIL_CNT_UNION;
#endif
#define SOC_TRNG_RAW_FAIL_CNT_fail_num_poker_START    (0)
#define SOC_TRNG_RAW_FAIL_CNT_fail_num_poker_END      (7)
#define SOC_TRNG_RAW_FAIL_CNT_fail_num_chi_START      (8)
#define SOC_TRNG_RAW_FAIL_CNT_fail_num_chi_END        (15)
#define SOC_TRNG_RAW_FAIL_CNT_fail_num_longrun_START  (16)
#define SOC_TRNG_RAW_FAIL_CNT_fail_num_longrun_END    (23)


/*****************************************************************************
 结构名    : SOC_TRNG_RAW_STATE_UNION
 结构说明  : RAW_STATE 寄存器结构定义。地址偏移量:0x358，初值:0x00000000，宽度:32
 寄存器说明: RAW_STATE
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  raw_state : 32; /* bit[0-31]: raw_test的状态 */
    } reg;
} SOC_TRNG_RAW_STATE_UNION;
#endif
#define SOC_TRNG_RAW_STATE_raw_state_START  (0)
#define SOC_TRNG_RAW_STATE_raw_state_END    (31)


/*****************************************************************************
 结构名    : SOC_TRNG_XOR_COMP_CFG_UNION
 结构说明  : XOR_COMP_CFG 寄存器结构定义。地址偏移量:0x35c，初值:0x00000000，宽度:32
 寄存器说明: XOR_COMP_CFG
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  xor_comp_rate : 5;  /* bit[0-4] : xor_compressing的压缩比,压缩比为该寄存器值+1; */
        unsigned int  reserved      : 27; /* bit[5-31]:  */
    } reg;
} SOC_TRNG_XOR_COMP_CFG_UNION;
#endif
#define SOC_TRNG_XOR_COMP_CFG_xor_comp_rate_START  (0)
#define SOC_TRNG_XOR_COMP_CFG_xor_comp_rate_END    (4)


/*****************************************************************************
 结构名    : SOC_TRNG_XOR_CHAIN_CFG_UNION
 结构说明  : XOR_CHAIN_CFG 寄存器结构定义。地址偏移量:0x360，初值:0x00000005，宽度:32
 寄存器说明: XOR_CHAIN_CFG
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  xor_chain_byp : 4;  /* bit[0-3] : xor_chain的旁路使能信号,0x5有效,其他值无效; */
        unsigned int  reserved      : 28; /* bit[4-31]:  */
    } reg;
} SOC_TRNG_XOR_CHAIN_CFG_UNION;
#endif
#define SOC_TRNG_XOR_CHAIN_CFG_xor_chain_byp_START  (0)
#define SOC_TRNG_XOR_CHAIN_CFG_xor_chain_byp_END    (3)


/*****************************************************************************
 结构名    : SOC_TRNG_POST_PROCESS_UNION
 结构说明  : POST_PROCESS 寄存器结构定义。地址偏移量:0x364，初值:0x0000000A，宽度:32
 寄存器说明: POST_PROCESS
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  byp_en_post_proc : 4;  /* bit[0-3] : post_processing的旁路使能,0xa无效,其他值有效; */
        unsigned int  reserved         : 28; /* bit[4-31]:  */
    } reg;
} SOC_TRNG_POST_PROCESS_UNION;
#endif
#define SOC_TRNG_POST_PROCESS_byp_en_post_proc_START  (0)
#define SOC_TRNG_POST_PROCESS_byp_en_post_proc_END    (3)


/*****************************************************************************
 结构名    : SOC_TRNG_RESEED_CNT_LIMIT_UNION
 结构说明  : RESEED_CNT_LIMIT 寄存器结构定义。地址偏移量:0x368，初值:0x00000002，宽度:32
 寄存器说明: RESEED_CNT_LIMIT
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reseed_cnt_limit : 32; /* bit[0-31]: HASH_DRBG一次reseed后生成随机数次数的限制,当该值为1时,为全种模式; */
    } reg;
} SOC_TRNG_RESEED_CNT_LIMIT_UNION;
#endif
#define SOC_TRNG_RESEED_CNT_LIMIT_reseed_cnt_limit_START  (0)
#define SOC_TRNG_RESEED_CNT_LIMIT_reseed_cnt_limit_END    (31)


/*****************************************************************************
 结构名    : SOC_TRNG_POST_TEST_BYP_UNION
 结构说明  : POST_TEST_BYP 寄存器结构定义。地址偏移量:0x36c，初值:0x00000AAA，宽度:32
 寄存器说明: POST_TEST_BYP
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  byp_en_poker   : 4;  /* bit[0-3]  : 后检测poker检测的旁路使能;0x5有效,其他值无效; */
        unsigned int  byp_en_256same : 4;  /* bit[4-7]  : 后检测相邻256bit相同的检测的旁路使能;0x5有效,其他值无效; */
        unsigned int  byp_en_32same  : 4;  /* bit[8-11] : 后检测相邻32bit相同的检测的旁路使能,0x5有效,其他值无效; */
        unsigned int  reserved       : 20; /* bit[12-31]:  */
    } reg;
} SOC_TRNG_POST_TEST_BYP_UNION;
#endif
#define SOC_TRNG_POST_TEST_BYP_byp_en_poker_START    (0)
#define SOC_TRNG_POST_TEST_BYP_byp_en_poker_END      (3)
#define SOC_TRNG_POST_TEST_BYP_byp_en_256same_START  (4)
#define SOC_TRNG_POST_TEST_BYP_byp_en_256same_END    (7)
#define SOC_TRNG_POST_TEST_BYP_byp_en_32same_START   (8)
#define SOC_TRNG_POST_TEST_BYP_byp_en_32same_END     (11)


/*****************************************************************************
 结构名    : SOC_TRNG_POST_TEST_ALARM_MSK_UNION
 结构说明  : POST_TEST_ALARM_MSK 寄存器结构定义。地址偏移量:0x370，初值:0x00AAAAAA，宽度:32
 寄存器说明: POST_TEST_ALARM_MSK
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  msk_alarm_poker    : 4;  /* bit[0-3]  : 后检测相邻poker检测fail屏蔽,0x5有效,其他值无效; */
        unsigned int  msk_alarm_256same  : 4;  /* bit[4-7]  : 后检测相邻256bit相同的检测fail屏蔽,0x5有效,其他值无效; */
        unsigned int  msk_alarm_32same   : 4;  /* bit[8-11] : 后检测相邻32bit相同的检测fail屏蔽,0x5有效,其他值无效; */
        unsigned int  msk_alarm_prepoker : 4;  /* bit[12-15]: 后检测相邻poker检测fail屏蔽,0x5有效,其他值无效; */
        unsigned int  msk_alarm_chi      : 4;  /* bit[16-19]: 后检测相邻256bit相同的检测fail屏蔽,0x5有效,其他值无效; */
        unsigned int  msk_alarm_longrun  : 4;  /* bit[20-23]: 后检测相邻32bit相同的检测fail屏蔽,0x5有效,其他值无效; */
        unsigned int  reserved           : 8;  /* bit[24-31]:  */
    } reg;
} SOC_TRNG_POST_TEST_ALARM_MSK_UNION;
#endif
#define SOC_TRNG_POST_TEST_ALARM_MSK_msk_alarm_poker_START     (0)
#define SOC_TRNG_POST_TEST_ALARM_MSK_msk_alarm_poker_END       (3)
#define SOC_TRNG_POST_TEST_ALARM_MSK_msk_alarm_256same_START   (4)
#define SOC_TRNG_POST_TEST_ALARM_MSK_msk_alarm_256same_END     (7)
#define SOC_TRNG_POST_TEST_ALARM_MSK_msk_alarm_32same_START    (8)
#define SOC_TRNG_POST_TEST_ALARM_MSK_msk_alarm_32same_END      (11)
#define SOC_TRNG_POST_TEST_ALARM_MSK_msk_alarm_prepoker_START  (12)
#define SOC_TRNG_POST_TEST_ALARM_MSK_msk_alarm_prepoker_END    (15)
#define SOC_TRNG_POST_TEST_ALARM_MSK_msk_alarm_chi_START       (16)
#define SOC_TRNG_POST_TEST_ALARM_MSK_msk_alarm_chi_END         (19)
#define SOC_TRNG_POST_TEST_ALARM_MSK_msk_alarm_longrun_START   (20)
#define SOC_TRNG_POST_TEST_ALARM_MSK_msk_alarm_longrun_END     (23)


/*****************************************************************************
 结构名    : SOC_TRNG_DISTRIBUTION_UNION
 结构说明  : DISTRIBUTION 寄存器结构定义。地址偏移量:0x378，初值:0x0000000A，宽度:32
 寄存器说明: DISTRIBUTION
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  full_dist_mode : 4;  /* bit[0-3] : distribution的全分发模式使能, */
        unsigned int  reserved       : 28; /* bit[4-31]:  */
    } reg;
} SOC_TRNG_DISTRIBUTION_UNION;
#endif
#define SOC_TRNG_DISTRIBUTION_full_dist_mode_START  (0)
#define SOC_TRNG_DISTRIBUTION_full_dist_mode_END    (3)


/*****************************************************************************
 结构名    : SOC_TRNG_ALARM_STATE_UNION
 结构说明  : ALARM_STATE 寄存器结构定义。地址偏移量:0x37c，初值:0x00000000，宽度:32
 寄存器说明: ALARM_STATE
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  alarm_pos_poker  : 1;  /* bit[0-0] : post_poker_test的faile状态,高有效 */
        unsigned int  alarm_same32     : 1;  /* bit[1-1] : 相邻32bit相同的faile状态,高有效 */
        unsigned int  alarm_same256    : 1;  /* bit[2-2] : 相邻256bit相同的faile状态,高有效 */
        unsigned int  alarm_pre_poker  : 1;  /* bit[3-3] : 前poker_test的faile状态,高有效 */
        unsigned int  alarm_chi_test   : 1;  /* bit[4-4] : chi_test的faile状态,高有效 */
        unsigned int  alarm_longrun    : 1;  /* bit[5-5] : long_run_test的faile状态,高有效 */
        unsigned int  alarm_otpc_check : 1;  /* bit[6-6] : otpc信号非法alarm,高有效 */
        unsigned int  signal_alarm     : 1;  /* bit[7-7] : reg_file信号保护alarm,高有效 */
        unsigned int  reserved         : 24; /* bit[8-31]:  */
    } reg;
} SOC_TRNG_ALARM_STATE_UNION;
#endif
#define SOC_TRNG_ALARM_STATE_alarm_pos_poker_START   (0)
#define SOC_TRNG_ALARM_STATE_alarm_pos_poker_END     (0)
#define SOC_TRNG_ALARM_STATE_alarm_same32_START      (1)
#define SOC_TRNG_ALARM_STATE_alarm_same32_END        (1)
#define SOC_TRNG_ALARM_STATE_alarm_same256_START     (2)
#define SOC_TRNG_ALARM_STATE_alarm_same256_END       (2)
#define SOC_TRNG_ALARM_STATE_alarm_pre_poker_START   (3)
#define SOC_TRNG_ALARM_STATE_alarm_pre_poker_END     (3)
#define SOC_TRNG_ALARM_STATE_alarm_chi_test_START    (4)
#define SOC_TRNG_ALARM_STATE_alarm_chi_test_END      (4)
#define SOC_TRNG_ALARM_STATE_alarm_longrun_START     (5)
#define SOC_TRNG_ALARM_STATE_alarm_longrun_END       (5)
#define SOC_TRNG_ALARM_STATE_alarm_otpc_check_START  (6)
#define SOC_TRNG_ALARM_STATE_alarm_otpc_check_END    (6)
#define SOC_TRNG_ALARM_STATE_signal_alarm_START      (7)
#define SOC_TRNG_ALARM_STATE_signal_alarm_END        (7)


/*****************************************************************************
 结构名    : SOC_TRNG_THRE_POST_POKER_UNION
 结构说明  : THRE_POST_POKER 寄存器结构定义。地址偏移量:0x384，初值:0x000001FE，宽度:32
 寄存器说明: THRE_POST_POKER
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  post_poker_ck_hig : 16; /* bit[0-15] : post_poker的阈值 */
        unsigned int  reserved          : 16; /* bit[16-31]:  */
    } reg;
} SOC_TRNG_THRE_POST_POKER_UNION;
#endif
#define SOC_TRNG_THRE_POST_POKER_post_poker_ck_hig_START  (0)
#define SOC_TRNG_THRE_POST_POKER_post_poker_ck_hig_END    (15)


/*****************************************************************************
 结构名    : SOC_TRNG_POST_TEST_WIN_RAW_TEST_UNION
 结构说明  : POST_TEST_WIN_RAW_TEST 寄存器结构定义。地址偏移量:0x388，初值:0x00666666，宽度:32
 寄存器说明: POST_TEST_WIN_RAW_TEST
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  test_win_post_poker : 8;  /* bit[0-7]  : post_poker_test的fail统计窗口 */
        unsigned int  test_win_same256    : 8;  /* bit[8-15] : same256的fail统计窗口 */
        unsigned int  test_win_same32     : 8;  /* bit[16-23]: same32的fail统计窗口 */
        unsigned int  reserved            : 8;  /* bit[24-31]:  */
    } reg;
} SOC_TRNG_POST_TEST_WIN_RAW_TEST_UNION;
#endif
#define SOC_TRNG_POST_TEST_WIN_RAW_TEST_test_win_post_poker_START  (0)
#define SOC_TRNG_POST_TEST_WIN_RAW_TEST_test_win_post_poker_END    (7)
#define SOC_TRNG_POST_TEST_WIN_RAW_TEST_test_win_same256_START     (8)
#define SOC_TRNG_POST_TEST_WIN_RAW_TEST_test_win_same256_END       (15)
#define SOC_TRNG_POST_TEST_WIN_RAW_TEST_test_win_same32_START      (16)
#define SOC_TRNG_POST_TEST_WIN_RAW_TEST_test_win_same32_END        (23)


/*****************************************************************************
 结构名    : SOC_TRNG_THRE_POST_FAIL_NUM_UNION
 结构说明  : THRE_POST_FAIL_NUM 寄存器结构定义。地址偏移量:0x38c，初值:0x00666666，宽度:32
 寄存器说明: POST_TEST_WIN_RAW_TEST
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  thre_fail_num_post_poker : 8;  /* bit[0-7]  : post_poker_test在fail统计窗口内允许的fail上限,,超过该上限会触发中断 */
        unsigned int  thre_fail_num_same256    : 8;  /* bit[8-15] : same256在fail统计窗口内允许的fail上限,,超过该上限会触发中断 */
        unsigned int  thre_fail_num_same32     : 8;  /* bit[16-23]: same32在fail统计窗口内允许的fail上限,超过该上限会触发中断 */
        unsigned int  reserved                 : 8;  /* bit[24-31]:  */
    } reg;
} SOC_TRNG_THRE_POST_FAIL_NUM_UNION;
#endif
#define SOC_TRNG_THRE_POST_FAIL_NUM_thre_fail_num_post_poker_START  (0)
#define SOC_TRNG_THRE_POST_FAIL_NUM_thre_fail_num_post_poker_END    (7)
#define SOC_TRNG_THRE_POST_FAIL_NUM_thre_fail_num_same256_START     (8)
#define SOC_TRNG_THRE_POST_FAIL_NUM_thre_fail_num_same256_END       (15)
#define SOC_TRNG_THRE_POST_FAIL_NUM_thre_fail_num_same32_START      (16)
#define SOC_TRNG_THRE_POST_FAIL_NUM_thre_fail_num_same32_END        (23)


/*****************************************************************************
 结构名    : SOC_TRNG_POST_TEST_CLEAR_UNION
 结构说明  : POST_TEST_CLEAR 寄存器结构定义。地址偏移量:0x390，初值:0x00000000，宽度:32
 寄存器说明: POST_TEST_WIN_RAW_TEST
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  clear_post_poker : 1;  /* bit[0-0] : post_poker的fail状态清信号,高有效 */
        unsigned int  clear_same256    : 1;  /* bit[1-1] : same256的fail状态清信号,高有效 */
        unsigned int  clear_same32     : 1;  /* bit[2-2] : same32的fail状态清信号,高有效 */
        unsigned int  reserved         : 29; /* bit[3-31]:  */
    } reg;
} SOC_TRNG_POST_TEST_CLEAR_UNION;
#endif
#define SOC_TRNG_POST_TEST_CLEAR_clear_post_poker_START  (0)
#define SOC_TRNG_POST_TEST_CLEAR_clear_post_poker_END    (0)
#define SOC_TRNG_POST_TEST_CLEAR_clear_same256_START     (1)
#define SOC_TRNG_POST_TEST_CLEAR_clear_same256_END       (1)
#define SOC_TRNG_POST_TEST_CLEAR_clear_same32_START      (2)
#define SOC_TRNG_POST_TEST_CLEAR_clear_same32_END        (2)


/*****************************************************************************
 结构名    : SOC_TRNG_POST_FAIL_CNT_UNION
 结构说明  : POST_FAIL_CNT 寄存器结构定义。地址偏移量:0x394，初值:0x00000000，宽度:32
 寄存器说明: POST_TEST_WIN_RAW_TEST
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  fail_num_post_poker : 8;  /* bit[0-7]  : post_poker在test_win中的实时fail次数 */
        unsigned int  fail_num_same256    : 8;  /* bit[8-15] : same256在test_win中的实时fail次数 */
        unsigned int  fail_num_same32     : 8;  /* bit[16-23]: same32在test_win中的实时fail次数 */
        unsigned int  reserved            : 8;  /* bit[24-31]:  */
    } reg;
} SOC_TRNG_POST_FAIL_CNT_UNION;
#endif
#define SOC_TRNG_POST_FAIL_CNT_fail_num_post_poker_START  (0)
#define SOC_TRNG_POST_FAIL_CNT_fail_num_post_poker_END    (7)
#define SOC_TRNG_POST_FAIL_CNT_fail_num_same256_START     (8)
#define SOC_TRNG_POST_FAIL_CNT_fail_num_same256_END       (15)
#define SOC_TRNG_POST_FAIL_CNT_fail_num_same32_START      (16)
#define SOC_TRNG_POST_FAIL_CNT_fail_num_same32_END        (23)


/*****************************************************************************
 结构名    : SOC_TRNG_WAIT_FOR_USE_UNION
 结构说明  : WAIT_FOR_USE 寄存器结构定义。地址偏移量:0x39c，初值:0x00000000，宽度:32
 寄存器说明: TRNG_DATA_0
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  wait_for_use : 32; /* bit[0-31]:  */
    } reg;
} SOC_TRNG_WAIT_FOR_USE_UNION;
#endif
#define SOC_TRNG_WAIT_FOR_USE_wait_for_use_START  (0)
#define SOC_TRNG_WAIT_FOR_USE_wait_for_use_END    (31)


/*****************************************************************************
 结构名    : SOC_TRNG_RNG_TIME_OUT_UNION
 结构说明  : RNG_TIME_OUT 寄存器结构定义。地址偏移量:0x3a0，初值:0xFFFFFF00，宽度:32
 寄存器说明: TIME_OUT_REGS
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  time_out_alarm     : 1;  /* bit[0-0] : 超时告警,高有效 */
        unsigned int  time_out_alarm_msk : 1;  /* bit[1-1] : 超时告警屏蔽,高有效 */
        unsigned int  time_out_clear     : 1;  /* bit[2-2] : 超时告警清楚,高有效 */
        unsigned int  reserved           : 5;  /* bit[3-7] :  */
        unsigned int  time_out_limit     : 24; /* bit[8-31]: 超时阈值 */
    } reg;
} SOC_TRNG_RNG_TIME_OUT_UNION;
#endif
#define SOC_TRNG_RNG_TIME_OUT_time_out_alarm_START      (0)
#define SOC_TRNG_RNG_TIME_OUT_time_out_alarm_END        (0)
#define SOC_TRNG_RNG_TIME_OUT_time_out_alarm_msk_START  (1)
#define SOC_TRNG_RNG_TIME_OUT_time_out_alarm_msk_END    (1)
#define SOC_TRNG_RNG_TIME_OUT_time_out_clear_START      (2)
#define SOC_TRNG_RNG_TIME_OUT_time_out_clear_END        (2)
#define SOC_TRNG_RNG_TIME_OUT_time_out_limit_START      (8)
#define SOC_TRNG_RNG_TIME_OUT_time_out_limit_END        (31)


/*****************************************************************************
 结构名    : SOC_TRNG_CHI_TEST_STATE_UNION
 结构说明  : CHI_TEST_STATE 寄存器结构定义。地址偏移量:0x3a4，初值:0x154，宽度:32
 寄存器说明: CHI_TEST_STATE
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  chi_fai        : 1;  /* bit[0-0] : chi_test的状态 */
        unsigned int  int_chi_online : 4;  /* bit[1-4] : chi_test的状态 */
        unsigned int  alarm_chi_tot  : 4;  /* bit[5-8] : chi_test的状态 */
        unsigned int  reserved       : 23; /* bit[9-31]:  */
    } reg;
} SOC_TRNG_CHI_TEST_STATE_UNION;
#endif
#define SOC_TRNG_CHI_TEST_STATE_chi_fai_START         (0)
#define SOC_TRNG_CHI_TEST_STATE_chi_fai_END           (0)
#define SOC_TRNG_CHI_TEST_STATE_int_chi_online_START  (1)
#define SOC_TRNG_CHI_TEST_STATE_int_chi_online_END    (4)
#define SOC_TRNG_CHI_TEST_STATE_alarm_chi_tot_START   (5)
#define SOC_TRNG_CHI_TEST_STATE_alarm_chi_tot_END     (8)


/*****************************************************************************
 结构名    : SOC_TRNG_CLK_EN_UNION
 结构说明  : CLK_EN 寄存器结构定义。地址偏移量:0x3a8，初值:0x0000000A，宽度:32
 寄存器说明: TRNG_CLK_EN
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  trng_clk_en : 4;  /* bit[0-3] : 新TRNG的随机时钟使能,高有效.该信号 */
        unsigned int  reserved    : 28; /* bit[4-31]:  */
    } reg;
} SOC_TRNG_CLK_EN_UNION;
#endif
#define SOC_TRNG_CLK_EN_trng_clk_en_START  (0)
#define SOC_TRNG_CLK_EN_trng_clk_en_END    (3)


/*****************************************************************************
 结构名    : SOC_TRNG_DONE_UNION
 结构说明  : DONE 寄存器结构定义。地址偏移量:0x3ac，初值:0x00000005，宽度:32
 寄存器说明: TRNG_DONE
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  trng_done : 4;  /* bit[0-3] : trng初始化完成表示,0x5有效,其他值无效 */
        unsigned int  reserved  : 28; /* bit[4-31]:  */
    } reg;
} SOC_TRNG_DONE_UNION;
#endif
#define SOC_TRNG_DONE_trng_done_START  (0)
#define SOC_TRNG_DONE_trng_done_END    (3)


/*****************************************************************************
 结构名    : SOC_TRNG_READY_UNION
 结构说明  : READY 寄存器结构定义。地址偏移量:0x3b0，初值:0x00000005，宽度:32
 寄存器说明: TRNG_READY
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  trng_ready : 4;  /* bit[0-3] : trng ready状态,0x5有效,其他值无效 */
        unsigned int  reserved   : 28; /* bit[4-31]:  */
    } reg;
} SOC_TRNG_READY_UNION;
#endif
#define SOC_TRNG_READY_trng_ready_START  (0)
#define SOC_TRNG_READY_trng_ready_END    (3)


/*****************************************************************************
 结构名    : SOC_TRNG_READY_THRE_UNION
 结构说明  : READY_THRE 寄存器结构定义。地址偏移量:0x3b4，初值:0x00000003，宽度:32
 寄存器说明: TRNG_READY_THRE
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  trng_ready_thre : 6;  /* bit[0-5] : trng_ready的阈值,该值是与TRNG_FIFO的cnt比较火的,当trng_rady_thre大于TRNG_FIFO cnt时,trng为ready有效 */
        unsigned int  reserved        : 26; /* bit[6-31]:  */
    } reg;
} SOC_TRNG_READY_THRE_UNION;
#endif
#define SOC_TRNG_READY_THRE_trng_ready_thre_START  (0)
#define SOC_TRNG_READY_THRE_trng_ready_thre_END    (5)


/*****************************************************************************
 结构名    : SOC_TRNG_FIFO_DATA_UNION
 结构说明  : FIFO_DATA 寄存器结构定义。地址偏移量:0x3b8，初值:0x00000000，宽度:32
 寄存器说明: V
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  trng_fifo_data : 32; /* bit[0-31]: trng随机数,供软件读取 */
    } reg;
} SOC_TRNG_FIFO_DATA_UNION;
#endif
#define SOC_TRNG_FIFO_DATA_trng_fifo_data_START  (0)
#define SOC_TRNG_FIFO_DATA_trng_fifo_data_END    (31)


/*****************************************************************************
 结构名    : SOC_TRNG_PRT_LOCK_UNION
 结构说明  : PRT_LOCK 寄存器结构定义。地址偏移量:0x3bc，初值:0x0000000A，宽度:32
 寄存器说明: PRT_LOCK
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  lock_reg : 4;  /* bit[0-3] : 寄存器锁,写任意值生效,生效后,所有RW_LOCK属性的寄存器不可被改写. */
        unsigned int  reserved : 28; /* bit[4-31]:  */
    } reg;
} SOC_TRNG_PRT_LOCK_UNION;
#endif
#define SOC_TRNG_PRT_LOCK_lock_reg_START  (0)
#define SOC_TRNG_PRT_LOCK_lock_reg_END    (3)


/*****************************************************************************
 结构名    : SOC_TRNG_ENTROPY_MERGE_UNION
 结构说明  : ENTROPY_MERGE 寄存器结构定义。地址偏移量:0x3c0，初值:0x00000000，宽度:32
 寄存器说明: ENTROPY_MERGE
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  src_merge_cfg : 4;  /* bit[0-3] : 配置新TRNG的随机源输出合并入老TRNG的熵源输出(MUX的输出位置)
                                                        0001: MUX输出follow老TRNG的data和vld;
                                                        0010: MUX输出follow新TRNG的data和vld;
                                                        0100: MUX输出的data为老TRNG的data异或新源的data;vld follow老TRNG的vld;
                                                        1000:MUX输出的data为老TRNG的data异或新源的data;vld follow新TRNG的vld;
                                                        其他值等价于"0001";
                                                        注意:当otpc_trng_pre_proc_en为0x5时,"0010"和"1000"这两项配置无效! */
        unsigned int  reserved      : 28; /* bit[4-31]:  */
    } reg;
} SOC_TRNG_ENTROPY_MERGE_UNION;
#endif
#define SOC_TRNG_ENTROPY_MERGE_src_merge_cfg_START  (0)
#define SOC_TRNG_ENTROPY_MERGE_src_merge_cfg_END    (3)


/*****************************************************************************
 结构名    : SOC_TRNG_KNOWN_ANSWER_TEST_UNION
 结构说明  : KNOWN_ANSWER_TEST 寄存器结构定义。地址偏移量:0x3c4，初值:0x00000002，宽度:32
 寄存器说明: KNOWN_ANSWER_TEST
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  answer_test_fail : 1;  /* bit[0-0] : known-answer test 失败指示信号,高有效;
                                                           系统解复位时自动触发known-answer test,软件在系统初始化时读该寄存器默认和法值为"1" */
        unsigned int  answer_test_done : 1;  /* bit[1-1] : known-answer test完成指示信号,高有效;
                                                           系统解复位时自动触发known-answer test,软件在系统初始化时读该寄存器默认和法值为"1" */
        unsigned int  answer_test_en   : 1;  /* bit[2-2] : 配置触发known-answer test,高有效 */
        unsigned int  reserved         : 29; /* bit[3-31]:  */
    } reg;
} SOC_TRNG_KNOWN_ANSWER_TEST_UNION;
#endif
#define SOC_TRNG_KNOWN_ANSWER_TEST_answer_test_fail_START  (0)
#define SOC_TRNG_KNOWN_ANSWER_TEST_answer_test_fail_END    (0)
#define SOC_TRNG_KNOWN_ANSWER_TEST_answer_test_done_START  (1)
#define SOC_TRNG_KNOWN_ANSWER_TEST_answer_test_done_END    (1)
#define SOC_TRNG_KNOWN_ANSWER_TEST_answer_test_en_START    (2)
#define SOC_TRNG_KNOWN_ANSWER_TEST_answer_test_en_END      (2)


/*****************************************************************************
 结构名    : SOC_TRNG_SIGNAL_ALARM_UNION
 结构说明  : SIGNAL_ALARM 寄存器结构定义。地址偏移量:0x3c8，初值:0x00000A0A，宽度:32
 寄存器说明: 信号保护的异常状态
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  all_signal_alarm     : 4;  /* bit[0-3]  : 信号保护alarm的只是信号,0xa表示无alarm,其他值表示有alarm */
        unsigned int  all_signal_alarm_clr : 1;  /* bit[4-4]  : 信号保护alarm电平信号的清除信号,写"1"有效 */
        unsigned int  reserved_0           : 3;  /* bit[5-7]  :  */
        unsigned int  msk_all_signal_alarm : 4;  /* bit[8-11] : 信号保护的alarm屏蔽信号,0x5表示不屏蔽,0xa表示屏蔽,其他值为非法值,会触发信号保护alarm */
        unsigned int  reserved_1           : 20; /* bit[12-31]:  */
    } reg;
} SOC_TRNG_SIGNAL_ALARM_UNION;
#endif
#define SOC_TRNG_SIGNAL_ALARM_all_signal_alarm_START      (0)
#define SOC_TRNG_SIGNAL_ALARM_all_signal_alarm_END        (3)
#define SOC_TRNG_SIGNAL_ALARM_all_signal_alarm_clr_START  (4)
#define SOC_TRNG_SIGNAL_ALARM_all_signal_alarm_clr_END    (4)
#define SOC_TRNG_SIGNAL_ALARM_msk_all_signal_alarm_START  (8)
#define SOC_TRNG_SIGNAL_ALARM_msk_all_signal_alarm_END    (11)




/****************************************************************************
                     (2/2) reg_define 
 ****************************************************************************/
/*****************************************************************************
 结构名    : SOC_TRNG_HISEC_COM_TRNG_CTRL_UNION
 结构说明  : HISEC_COM_TRNG_CTRL 寄存器结构定义。地址偏移量:0x0000，初值:0x0E483485，宽度:32
 寄存器说明: TRNG控制寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  drbg_enable     : 1;  /* bit[0]    : DRBG后处理使能。
                                                           0：不使能；
                                                           1：使能。 */
        unsigned int  fliter_enable   : 1;  /* bit[1]    : 随机数前处理使能，使用此功能后随机数产生速度降低4倍。
                                                           0：不使能；
                                                           1：使能。 */
        unsigned int  drop_enable     : 1;  /* bit[2]    : 丢掉不等概率数据使能，使用此功能后随机数产生速度降低3倍。
                                                           0：不使能；
                                                           1：使能。 */
        unsigned int  rng_sel         : 1;  /* bit[3]    : 测试模式下熵源TRNG输出选择：
                                                           0：选择所有随机源异或数据输出；
                                                           1：选择某一独立随机源数据输出； */
        unsigned int  ro_sel          : 4;  /* bit[4-7]  : 测试模式下GARO数字RO内部随机源选择，rng_sel为1时可配置：
                                                           0000：环路0
                                                           0001：环路1
                                                           0010：环路2
                                                           0011：环路3
                                                           0100：环路4
                                                           0101：环路5
                                                           0110：环路6
                                                           0111：环路7
                                                           other:8环路异或 */
        unsigned int  osc_sel         : 3;  /* bit[8-10] : 测试模式下模拟随机源选择，rng_sel为1时可配置。
                                                           000：使用随机源0；
                                                           001：使用随机源1；
                                                           010：使用随机源2；
                                                           011：使用随机源3;
                                                           other:4路异或 */
        unsigned int  testpoint_en    : 1;  /* bit[11]   : Testpoint使能信号：
                                                           0：不打开测试使能，Testpoint输出0；
                                                           1：打开测试使能，Testpoint输出源的数据。 */
        unsigned int  pre_test_enable : 1;  /* bit[12]   : PRE_SELF_TEST熵源随机数（随机源之后）在线自检使能。
                                                           0：不使能；
                                                           1：使能。 */
        unsigned int  pos_test_enable : 1;  /* bit[13]   : POS_SELF_TEST随机数（DRBG之后）在线自检使能。
                                                           0：不使能；
                                                           1：使能。 */
        unsigned int  rng_src_sel     : 2;  /* bit[14-15]: 三类源的选择，rng_sel为1时可配置：
                                                           00：三类源异或；
                                                           01：简单数字源；
                                                           10：GARO数字源；
                                                           11：模拟源。 */
        unsigned int  ro_hs_sel       : 3;  /* bit[16-18]: 测试模式下，简单数字源选择，当rng_sel为1时可配置：
                                                           000:4路异或输出；
                                                           100:第0路；
                                                           101：第1路；
                                                           110：第2路；
                                                           111：第3路；
                                                           其他：4路异或输出。 */
        unsigned int  digsrc_compen   : 1;  /* bit[19]   : 数字随机源压缩使能：
                                                           1：开启；
                                                           0：关闭。 */
        unsigned int  ro_hs_cfg       : 8;  /* bit[20-27]: 简单数字源配置，当src_cfg_en为1时可配置：
                                                           [27:26]:第3路配置；
                                                           [25:24]:第2路配置；
                                                           [23:22]:第1路配置；
                                                           [21:20]:第0路配置。 */
        unsigned int  src_cfg_en      : 1;  /* bit[28]   : 随机源源配置使能：
                                                           0：关闭；
                                                           1：开启。 */
        unsigned int  full_mode_en    : 1;  /* bit[29]   : 全种模式使能：
                                                           0：不使能；
                                                           1：使能。 */
        unsigned int  reserved        : 2;  /* bit[30-31]:  */
    } reg;
} SOC_TRNG_HISEC_COM_TRNG_CTRL_UNION;
#endif
#define SOC_TRNG_HISEC_COM_TRNG_CTRL_drbg_enable_START      (0)
#define SOC_TRNG_HISEC_COM_TRNG_CTRL_drbg_enable_END        (0)
#define SOC_TRNG_HISEC_COM_TRNG_CTRL_fliter_enable_START    (1)
#define SOC_TRNG_HISEC_COM_TRNG_CTRL_fliter_enable_END      (1)
#define SOC_TRNG_HISEC_COM_TRNG_CTRL_drop_enable_START      (2)
#define SOC_TRNG_HISEC_COM_TRNG_CTRL_drop_enable_END        (2)
#define SOC_TRNG_HISEC_COM_TRNG_CTRL_rng_sel_START          (3)
#define SOC_TRNG_HISEC_COM_TRNG_CTRL_rng_sel_END            (3)
#define SOC_TRNG_HISEC_COM_TRNG_CTRL_ro_sel_START           (4)
#define SOC_TRNG_HISEC_COM_TRNG_CTRL_ro_sel_END             (7)
#define SOC_TRNG_HISEC_COM_TRNG_CTRL_osc_sel_START          (8)
#define SOC_TRNG_HISEC_COM_TRNG_CTRL_osc_sel_END            (10)
#define SOC_TRNG_HISEC_COM_TRNG_CTRL_testpoint_en_START     (11)
#define SOC_TRNG_HISEC_COM_TRNG_CTRL_testpoint_en_END       (11)
#define SOC_TRNG_HISEC_COM_TRNG_CTRL_pre_test_enable_START  (12)
#define SOC_TRNG_HISEC_COM_TRNG_CTRL_pre_test_enable_END    (12)
#define SOC_TRNG_HISEC_COM_TRNG_CTRL_pos_test_enable_START  (13)
#define SOC_TRNG_HISEC_COM_TRNG_CTRL_pos_test_enable_END    (13)
#define SOC_TRNG_HISEC_COM_TRNG_CTRL_rng_src_sel_START      (14)
#define SOC_TRNG_HISEC_COM_TRNG_CTRL_rng_src_sel_END        (15)
#define SOC_TRNG_HISEC_COM_TRNG_CTRL_ro_hs_sel_START        (16)
#define SOC_TRNG_HISEC_COM_TRNG_CTRL_ro_hs_sel_END          (18)
#define SOC_TRNG_HISEC_COM_TRNG_CTRL_digsrc_compen_START    (19)
#define SOC_TRNG_HISEC_COM_TRNG_CTRL_digsrc_compen_END      (19)
#define SOC_TRNG_HISEC_COM_TRNG_CTRL_ro_hs_cfg_START        (20)
#define SOC_TRNG_HISEC_COM_TRNG_CTRL_ro_hs_cfg_END          (27)
#define SOC_TRNG_HISEC_COM_TRNG_CTRL_src_cfg_en_START       (28)
#define SOC_TRNG_HISEC_COM_TRNG_CTRL_src_cfg_en_END         (28)
#define SOC_TRNG_HISEC_COM_TRNG_CTRL_full_mode_en_START     (29)
#define SOC_TRNG_HISEC_COM_TRNG_CTRL_full_mode_en_END       (29)


/*****************************************************************************
 结构名    : SOC_TRNG_HISEC_COM_TRNG_FIFO_DATA_UNION
 结构说明  : HISEC_COM_TRNG_FIFO_DATA 寄存器结构定义。地址偏移量:0x0004，初值:0x00000000，宽度:32
 寄存器说明: TRNG的FIFO数据寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  trng_fifo_data : 32; /* bit[0-31]:  */
    } reg;
} SOC_TRNG_HISEC_COM_TRNG_FIFO_DATA_UNION;
#endif
#define SOC_TRNG_HISEC_COM_TRNG_FIFO_DATA_trng_fifo_data_START  (0)
#define SOC_TRNG_HISEC_COM_TRNG_FIFO_DATA_trng_fifo_data_END    (31)


/*****************************************************************************
 结构名    : SOC_TRNG_HISEC_COM_TRNG_DATA_ST_UNION
 结构说明  : HISEC_COM_TRNG_DATA_ST 寄存器结构定义。地址偏移量:0x0008，初值:0x00000000，宽度:32
 寄存器说明: TRNG的FIFO数据寄存器的状态
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  trng_fifo_data_cnt : 8;  /* bit[0-7] : fifo中随机数的个数。 */
        unsigned int  reserved           : 24; /* bit[8-31]:  */
    } reg;
} SOC_TRNG_HISEC_COM_TRNG_DATA_ST_UNION;
#endif
#define SOC_TRNG_HISEC_COM_TRNG_DATA_ST_trng_fifo_data_cnt_START  (0)
#define SOC_TRNG_HISEC_COM_TRNG_DATA_ST_trng_fifo_data_cnt_END    (7)


/*****************************************************************************
 结构名    : SOC_TRNG_HISEC_COM_TRNG_ENTROPY_MONO_CNT_UNION
 结构说明  : HISEC_COM_TRNG_ENTROPY_MONO_CNT 寄存器结构定义。地址偏移量:0x000C，初值:0x00000000，宽度:32
 寄存器说明: 熵源连续检测失败的次数统计（仅用于调试）
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  entropy_rng1_cnt : 3;  /* bit[0-2] : 保留。 */
        unsigned int  reserved         : 29; /* bit[3-31]:  */
    } reg;
} SOC_TRNG_HISEC_COM_TRNG_ENTROPY_MONO_CNT_UNION;
#endif
#define SOC_TRNG_HISEC_COM_TRNG_ENTROPY_MONO_CNT_entropy_rng1_cnt_START  (0)
#define SOC_TRNG_HISEC_COM_TRNG_ENTROPY_MONO_CNT_entropy_rng1_cnt_END    (2)


/*****************************************************************************
 结构名    : SOC_TRNG_HISEC_COM_TRNG_MONO_CNT_UNION
 结构说明  : HISEC_COM_TRNG_MONO_CNT 寄存器结构定义。地址偏移量:0x0010，初值:0x00000000，宽度:32
 寄存器说明: 随机数连续检测失败次数统计（仅用于调试）
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  self_alarm_cnt : 4;  /* bit[0-3] : 随机数连续检测失败次数统计 */
        unsigned int  reserved       : 28; /* bit[4-31]:  */
    } reg;
} SOC_TRNG_HISEC_COM_TRNG_MONO_CNT_UNION;
#endif
#define SOC_TRNG_HISEC_COM_TRNG_MONO_CNT_self_alarm_cnt_START  (0)
#define SOC_TRNG_HISEC_COM_TRNG_MONO_CNT_self_alarm_cnt_END    (3)


/*****************************************************************************
 结构名    : SOC_TRNG_HISEC_COM_TRNG_ALARM_SRC_UNION
 结构说明  : HISEC_COM_TRNG_ALARM_SRC 寄存器结构定义。地址偏移量:0x0014，初值:0x00000000，宽度:32
 寄存器说明: 告警源状态寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  pre_self_alarm_src    : 1;  /* bit[0]   : 熵源随机数在线检查告警，当在线检查连续出现n次失败（n为可配置的），则上报告警。 */
        unsigned int  pos_self_alarm_src    : 1;  /* bit[1]   : DRBG后的随机数在线检查告警，当在线检查连续出现n次失败（n为可配置的），则上报告警。 */
        unsigned int  rng_timeout_alarm_src : 1;  /* bit[2]   : 随机数长时间不能产生，超过一定时间，上报告警
                                                                0x1:告警；
                                                                0x0：无告警。 */
        unsigned int  pri_tim_out_alarm_src : 1;  /* bit[3]   : TRNG输出私有接口超时告警。
                                                                0x1：TRNG的私有接口长时间无输出，超时告警；
                                                                0x0：正常工作。 */
        unsigned int  prt_alarm_src         : 1;  /* bit[4]   : 关键信号保护告警。
                                                                0x1：TRNG的关键信号受到攻击告警；
                                                                0x0：正常工作。 */
        unsigned int  reserved              : 27; /* bit[5-31]:  */
    } reg;
} SOC_TRNG_HISEC_COM_TRNG_ALARM_SRC_UNION;
#endif
#define SOC_TRNG_HISEC_COM_TRNG_ALARM_SRC_pre_self_alarm_src_START     (0)
#define SOC_TRNG_HISEC_COM_TRNG_ALARM_SRC_pre_self_alarm_src_END       (0)
#define SOC_TRNG_HISEC_COM_TRNG_ALARM_SRC_pos_self_alarm_src_START     (1)
#define SOC_TRNG_HISEC_COM_TRNG_ALARM_SRC_pos_self_alarm_src_END       (1)
#define SOC_TRNG_HISEC_COM_TRNG_ALARM_SRC_rng_timeout_alarm_src_START  (2)
#define SOC_TRNG_HISEC_COM_TRNG_ALARM_SRC_rng_timeout_alarm_src_END    (2)
#define SOC_TRNG_HISEC_COM_TRNG_ALARM_SRC_pri_tim_out_alarm_src_START  (3)
#define SOC_TRNG_HISEC_COM_TRNG_ALARM_SRC_pri_tim_out_alarm_src_END    (3)
#define SOC_TRNG_HISEC_COM_TRNG_ALARM_SRC_prt_alarm_src_START          (4)
#define SOC_TRNG_HISEC_COM_TRNG_ALARM_SRC_prt_alarm_src_END            (4)


/*****************************************************************************
 结构名    : SOC_TRNG_HISEC_COM_TRNG_ALARM_MASK_UNION
 结构说明  : HISEC_COM_TRNG_ALARM_MASK 寄存器结构定义。地址偏移量:0x0018，初值:0x000AAAAA，宽度:32
 寄存器说明: 告警源屏蔽寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  pre_self_alarm_mask    : 4;  /* bit[0-3]  : TRNG模块内部告警的屏蔽信号；
                                                                  0x5为屏蔽有效，屏蔽TRNG告警信号；
                                                                  其他值表示屏蔽无效； */
        unsigned int  pos_self_alarm_mask    : 4;  /* bit[4-7]  : TRNG模块内部告警的屏蔽信号；
                                                                  0x5为屏蔽有效，屏蔽TRNG告警信号；
                                                                  其他值表示屏蔽无效； */
        unsigned int  rng_timeout_alarm_mask : 4;  /* bit[8-11] : TRNG模块内部告警的屏蔽信号；
                                                                  0x5为屏蔽有效，屏蔽TRNG告警信号；
                                                                  其他值表示屏蔽无效； */
        unsigned int  pri_tim_out_alarm_mask : 4;  /* bit[12-15]: TRNG模块内部告警的屏蔽信号；
                                                                  0x5为屏蔽有效，屏蔽TRNG告警信号；
                                                                  其他值表示屏蔽无效； */
        unsigned int  prt_alarm_mask         : 4;  /* bit[16-19]: TRNG模块关键信号攻击异常告警屏蔽；
                                                                  0x5为屏蔽有效，屏蔽关键信号攻击告警；
                                                                  其他值表示屏蔽无效； */
        unsigned int  reserved               : 12; /* bit[20-31]:  */
    } reg;
} SOC_TRNG_HISEC_COM_TRNG_ALARM_MASK_UNION;
#endif
#define SOC_TRNG_HISEC_COM_TRNG_ALARM_MASK_pre_self_alarm_mask_START     (0)
#define SOC_TRNG_HISEC_COM_TRNG_ALARM_MASK_pre_self_alarm_mask_END       (3)
#define SOC_TRNG_HISEC_COM_TRNG_ALARM_MASK_pos_self_alarm_mask_START     (4)
#define SOC_TRNG_HISEC_COM_TRNG_ALARM_MASK_pos_self_alarm_mask_END       (7)
#define SOC_TRNG_HISEC_COM_TRNG_ALARM_MASK_rng_timeout_alarm_mask_START  (8)
#define SOC_TRNG_HISEC_COM_TRNG_ALARM_MASK_rng_timeout_alarm_mask_END    (11)
#define SOC_TRNG_HISEC_COM_TRNG_ALARM_MASK_pri_tim_out_alarm_mask_START  (12)
#define SOC_TRNG_HISEC_COM_TRNG_ALARM_MASK_pri_tim_out_alarm_mask_END    (15)
#define SOC_TRNG_HISEC_COM_TRNG_ALARM_MASK_prt_alarm_mask_START          (16)
#define SOC_TRNG_HISEC_COM_TRNG_ALARM_MASK_prt_alarm_mask_END            (19)


/*****************************************************************************
 结构名    : SOC_TRNG_HISEC_COM_TRNG_ALARM_SRC_POST_UNION
 结构说明  : HISEC_COM_TRNG_ALARM_SRC_POST 寄存器结构定义。地址偏移量:0x001C，初值:0x00000000，宽度:32
 寄存器说明: 屏蔽后的告警源状态寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  pre_self_alarm_post    : 1;  /* bit[0]   : 熵源随机数在线检查告警，当在线检查连续出现n次失败（n为可配置的），则上报告警。 */
        unsigned int  pos_self_alarm_post    : 1;  /* bit[1]   : DRBG后的随机数在线检查告警，当在线检查连续出现n次失败（n为可配置的），则上报告警。 */
        unsigned int  rng_timeout_alarm_post : 1;  /* bit[2]   : 随机数长时间不能产生，超过一定时间，上报告警
                                                                 0x1:告警；
                                                                 0x0：无告警。 */
        unsigned int  pri_tim_out_alarm_post : 1;  /* bit[3]   : TRNG输出私有接口超时告警。
                                                                 0x1：TRNG的私有接口长时间无输出，超时告警；
                                                                 0x0：正常工作。 */
        unsigned int  prt_alarm_post         : 1;  /* bit[4]   : 关键信号保护告警。
                                                                 0x1：TRNG的关键信号受到攻击告警；
                                                                 0x0：正常工作。 */
        unsigned int  reserved               : 27; /* bit[5-31]:  */
    } reg;
} SOC_TRNG_HISEC_COM_TRNG_ALARM_SRC_POST_UNION;
#endif
#define SOC_TRNG_HISEC_COM_TRNG_ALARM_SRC_POST_pre_self_alarm_post_START     (0)
#define SOC_TRNG_HISEC_COM_TRNG_ALARM_SRC_POST_pre_self_alarm_post_END       (0)
#define SOC_TRNG_HISEC_COM_TRNG_ALARM_SRC_POST_pos_self_alarm_post_START     (1)
#define SOC_TRNG_HISEC_COM_TRNG_ALARM_SRC_POST_pos_self_alarm_post_END       (1)
#define SOC_TRNG_HISEC_COM_TRNG_ALARM_SRC_POST_rng_timeout_alarm_post_START  (2)
#define SOC_TRNG_HISEC_COM_TRNG_ALARM_SRC_POST_rng_timeout_alarm_post_END    (2)
#define SOC_TRNG_HISEC_COM_TRNG_ALARM_SRC_POST_pri_tim_out_alarm_post_START  (3)
#define SOC_TRNG_HISEC_COM_TRNG_ALARM_SRC_POST_pri_tim_out_alarm_post_END    (3)
#define SOC_TRNG_HISEC_COM_TRNG_ALARM_SRC_POST_prt_alarm_post_START          (4)
#define SOC_TRNG_HISEC_COM_TRNG_ALARM_SRC_POST_prt_alarm_post_END            (4)


/*****************************************************************************
 结构名    : SOC_TRNG_HISEC_COM_TRNG_FIFO_READY_UNION
 结构说明  : HISEC_COM_TRNG_FIFO_READY 寄存器结构定义。地址偏移量:0x0020，初值:0x000000AA，宽度:32
 寄存器说明: trng工作状态寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  trng_data_ready : 4;  /* bit[0-3] : trng_data_ready = 4'h5表示随机数据已准备好，可读取TRNG的数据寄存器 */
        unsigned int  trng_done       : 4;  /* bit[4-7] : trng_done=4'h5表示trng_top模块已经正常开始运行 */
        unsigned int  reserved        : 24; /* bit[8-31]:  */
    } reg;
} SOC_TRNG_HISEC_COM_TRNG_FIFO_READY_UNION;
#endif
#define SOC_TRNG_HISEC_COM_TRNG_FIFO_READY_trng_data_ready_START  (0)
#define SOC_TRNG_HISEC_COM_TRNG_FIFO_READY_trng_data_ready_END    (3)
#define SOC_TRNG_HISEC_COM_TRNG_FIFO_READY_trng_done_START        (4)
#define SOC_TRNG_HISEC_COM_TRNG_FIFO_READY_trng_done_END          (7)


/*****************************************************************************
 结构名    : SOC_TRNG_HISEC_COM_TRNG_OSC_TEST_SEL_UNION
 结构说明  : HISEC_COM_TRNG_OSC_TEST_SEL 寄存器结构定义。地址偏移量:0x0024，初值:0x000000FF，宽度:32
 寄存器说明: 4个模拟IP 核工作模式寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  osc_trng_sel : 8;  /* bit[0-7] : 4个模拟IP源的配置，默认8’h00，TRNG复位释放后，自动更新成8'hFF。当src_cfg_en为1时可配置，
                                                       [7:6]第3路TRNG配置；
                                                       [5:4]第2路TRNG配置；
                                                       [3:2]第1路TRNG配置；
                                                       [1:0]第0路TRNG配置；
                                                       
                                                       两bit的配置值：
                                                       00：disable RNG；
                                                       01：测试随机源环路1；
                                                       10：测试随机源环路2；
                                                       11：模拟源正常工作模式。 */
        unsigned int  reserved     : 24; /* bit[8-31]:  */
    } reg;
} SOC_TRNG_HISEC_COM_TRNG_OSC_TEST_SEL_UNION;
#endif
#define SOC_TRNG_HISEC_COM_TRNG_OSC_TEST_SEL_osc_trng_sel_START  (0)
#define SOC_TRNG_HISEC_COM_TRNG_OSC_TEST_SEL_osc_trng_sel_END    (7)


/*****************************************************************************
 结构名    : SOC_TRNG_HISEC_COM_TRNG_TIM_OUT_PERIOD_UNION
 结构说明  : HISEC_COM_TRNG_TIM_OUT_PERIOD 寄存器结构定义。地址偏移量:0x0028，初值:0xFFFFFFFF，宽度:32
 寄存器说明: 随机数不产生超时时间配置寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  garo_disable   : 1;  /* bit[0-0] : garo环的去使能信号,高有效 */
        unsigned int  tim_out_period : 31; /* bit[1-31]: 随机数不产生的超时时间,单位为时钟周期 */
    } reg;
} SOC_TRNG_HISEC_COM_TRNG_TIM_OUT_PERIOD_UNION;
#endif
#define SOC_TRNG_HISEC_COM_TRNG_TIM_OUT_PERIOD_garo_disable_START    (0)
#define SOC_TRNG_HISEC_COM_TRNG_TIM_OUT_PERIOD_garo_disable_END      (0)
#define SOC_TRNG_HISEC_COM_TRNG_TIM_OUT_PERIOD_tim_out_period_START  (1)
#define SOC_TRNG_HISEC_COM_TRNG_TIM_OUT_PERIOD_tim_out_period_END    (31)


/*****************************************************************************
 结构名    : SOC_TRNG_HISEC_COM_TRNG_ALARM_CLR_UNION
 结构说明  : HISEC_COM_TRNG_ALARM_CLR 寄存器结构定义。地址偏移量:0x002C，初值:0x00000000，宽度:32
 寄存器说明: 告警源和屏蔽后告警源清除寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  pre_self_alarm_clr    : 4;  /* bit[0-3]  : TRNG模块内部告警的清除信号；
                                                                 0x5为清除有效，清除TRNG告警信号；
                                                                 其他值表示清除无效； */
        unsigned int  pos_self_alarm_clr    : 4;  /* bit[4-7]  : TRNG模块内部告警的清除信号；
                                                                 0x5为清除有效，清除TRNG告警信号；
                                                                 其他值表示清除无效； */
        unsigned int  rng_timeout_alarm_clr : 4;  /* bit[8-11] : TRNG模块内部告警的清除信号；
                                                                 0x5为清除有效，清除TRNG告警信号；
                                                                 其他值表示清除无效； */
        unsigned int  pri_tim_out_alarm_clr : 4;  /* bit[12-15]: TRNG模块内部告警的清除信号；
                                                                 0x5为清除有效，清除TRNG告警信号；
                                                                 其他值表示清除无效； */
        unsigned int  prt_alarm_clr         : 4;  /* bit[16-19]: TRNG模块关键信号攻击异常告警清除；
                                                                 0x5为清除有效，清除关键信号攻击告警；
                                                                 其他值表示清除无效； */
        unsigned int  reserved              : 12; /* bit[20-31]:  */
    } reg;
} SOC_TRNG_HISEC_COM_TRNG_ALARM_CLR_UNION;
#endif
#define SOC_TRNG_HISEC_COM_TRNG_ALARM_CLR_pre_self_alarm_clr_START     (0)
#define SOC_TRNG_HISEC_COM_TRNG_ALARM_CLR_pre_self_alarm_clr_END       (3)
#define SOC_TRNG_HISEC_COM_TRNG_ALARM_CLR_pos_self_alarm_clr_START     (4)
#define SOC_TRNG_HISEC_COM_TRNG_ALARM_CLR_pos_self_alarm_clr_END       (7)
#define SOC_TRNG_HISEC_COM_TRNG_ALARM_CLR_rng_timeout_alarm_clr_START  (8)
#define SOC_TRNG_HISEC_COM_TRNG_ALARM_CLR_rng_timeout_alarm_clr_END    (11)
#define SOC_TRNG_HISEC_COM_TRNG_ALARM_CLR_pri_tim_out_alarm_clr_START  (12)
#define SOC_TRNG_HISEC_COM_TRNG_ALARM_CLR_pri_tim_out_alarm_clr_END    (15)
#define SOC_TRNG_HISEC_COM_TRNG_ALARM_CLR_prt_alarm_clr_START          (16)
#define SOC_TRNG_HISEC_COM_TRNG_ALARM_CLR_prt_alarm_clr_END            (19)


/*****************************************************************************
 结构名    : SOC_TRNG_HISEC_COM_TRNG_PRE_CK_CNT_UNION
 结构说明  : HISEC_COM_TRNG_PRE_CK_CNT 寄存器结构定义。地址偏移量:0x0030，初值:0x0000000F，宽度:32
 寄存器说明: 熵源在线检查连续失败的阀值配置寄存器。
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  pre_self_fail_cnt : 4;  /* bit[0-3] : 熵源在线检查连续失败的次数配置寄存器；
                                                            配置范围为3~15，当超出此范围则赋值为15. */
        unsigned int  reserved          : 28; /* bit[4-31]:  */
    } reg;
} SOC_TRNG_HISEC_COM_TRNG_PRE_CK_CNT_UNION;
#endif
#define SOC_TRNG_HISEC_COM_TRNG_PRE_CK_CNT_pre_self_fail_cnt_START  (0)
#define SOC_TRNG_HISEC_COM_TRNG_PRE_CK_CNT_pre_self_fail_cnt_END    (3)


/*****************************************************************************
 结构名    : SOC_TRNG_HISEC_COM_TRNG_PRE_MONO_CNT_UNION
 结构说明  : HISEC_COM_TRNG_PRE_MONO_CNT 寄存器结构定义。地址偏移量:0x0034，初值:0x0000FF00，宽度:32
 寄存器说明: 熵源在线检查的MONO检查阀值配置
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  pre_mono_ck_low : 8;  /* bit[0-7]  : MONO检查的最低阀值 */
        unsigned int  pre_mono_ck_hig : 8;  /* bit[8-15] : MONO检查的最高阀值 */
        unsigned int  reserved        : 16; /* bit[16-31]:  */
    } reg;
} SOC_TRNG_HISEC_COM_TRNG_PRE_MONO_CNT_UNION;
#endif
#define SOC_TRNG_HISEC_COM_TRNG_PRE_MONO_CNT_pre_mono_ck_low_START  (0)
#define SOC_TRNG_HISEC_COM_TRNG_PRE_MONO_CNT_pre_mono_ck_low_END    (7)
#define SOC_TRNG_HISEC_COM_TRNG_PRE_MONO_CNT_pre_mono_ck_hig_START  (8)
#define SOC_TRNG_HISEC_COM_TRNG_PRE_MONO_CNT_pre_mono_ck_hig_END    (15)


/*****************************************************************************
 结构名    : SOC_TRNG_HISEC_COM_TRNG_PRE_LONG_RUN_CNT_UNION
 结构说明  : HISEC_COM_TRNG_PRE_LONG_RUN_CNT 寄存器结构定义。地址偏移量:0x0038，初值:0x000000FF，宽度:32
 寄存器说明: 熵源在线检查的LONG RUN检查阀值配置。
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  pre_long_run_hig : 8;  /* bit[0-7] : LONG RUN检查的最高阀值 */
        unsigned int  reserved         : 24; /* bit[8-31]:  */
    } reg;
} SOC_TRNG_HISEC_COM_TRNG_PRE_LONG_RUN_CNT_UNION;
#endif
#define SOC_TRNG_HISEC_COM_TRNG_PRE_LONG_RUN_CNT_pre_long_run_hig_START  (0)
#define SOC_TRNG_HISEC_COM_TRNG_PRE_LONG_RUN_CNT_pre_long_run_hig_END    (7)


/*****************************************************************************
 结构名    : SOC_TRNG_HISEC_COM_TRNG_PRE_RUN_CNT_UNION
 结构说明  : HISEC_COM_TRNG_PRE_RUN_CNT 寄存器结构定义。地址偏移量:0x003C，初值:0x0000FFFF，宽度:32
 寄存器说明: 熵源在线检查的RUN检查阀值配置。
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  pre_run_test_hig : 16; /* bit[0-15] : RUN检查的最高阀值 */
        unsigned int  reserved         : 16; /* bit[16-31]:  */
    } reg;
} SOC_TRNG_HISEC_COM_TRNG_PRE_RUN_CNT_UNION;
#endif
#define SOC_TRNG_HISEC_COM_TRNG_PRE_RUN_CNT_pre_run_test_hig_START  (0)
#define SOC_TRNG_HISEC_COM_TRNG_PRE_RUN_CNT_pre_run_test_hig_END    (15)


/*****************************************************************************
 结构名    : SOC_TRNG_HISEC_COM_TRNG_PRE_SERIAL_CNT_UNION
 结构说明  : HISEC_COM_TRNG_PRE_SERIAL_CNT 寄存器结构定义。地址偏移量:0x0040，初值:0x0000FFFF，宽度:32
 寄存器说明: 熵源在线检查的SERIAL检查阀值配置。
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  pre_serial_ck_hig : 16; /* bit[0-15] : RUN检查的最高阀值 */
        unsigned int  reserved          : 16; /* bit[16-31]:  */
    } reg;
} SOC_TRNG_HISEC_COM_TRNG_PRE_SERIAL_CNT_UNION;
#endif
#define SOC_TRNG_HISEC_COM_TRNG_PRE_SERIAL_CNT_pre_serial_ck_hig_START  (0)
#define SOC_TRNG_HISEC_COM_TRNG_PRE_SERIAL_CNT_pre_serial_ck_hig_END    (15)


/*****************************************************************************
 结构名    : SOC_TRNG_HISEC_COM_TRNG_PRE_POKER_CNT_UNION
 结构说明  : HISEC_COM_TRNG_PRE_POKER_CNT 寄存器结构定义。地址偏移量:0x0044，初值:0x0000FFFF，宽度:32
 寄存器说明: 熵源在线检查的POKER检查阀值配置。
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  pre_poker_ck_hig : 16; /* bit[0-15] : POKER检查的最高阀值 */
        unsigned int  reserved         : 16; /* bit[16-31]:  */
    } reg;
} SOC_TRNG_HISEC_COM_TRNG_PRE_POKER_CNT_UNION;
#endif
#define SOC_TRNG_HISEC_COM_TRNG_PRE_POKER_CNT_pre_poker_ck_hig_START  (0)
#define SOC_TRNG_HISEC_COM_TRNG_PRE_POKER_CNT_pre_poker_ck_hig_END    (15)


/*****************************************************************************
 结构名    : SOC_TRNG_HISEC_COM_TRNG_PRE_ATCR01_CNT_UNION
 结构说明  : HISEC_COM_TRNG_PRE_ATCR01_CNT 寄存器结构定义。地址偏移量:0x0048，初值:0xFF00FF00，宽度:32
 寄存器说明: 熵源在线检查的ATCR01检查阀值配置。
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  pre_actr0_ck_low : 8;  /* bit[0-7]  : AUTOCORRELATION CNT0检查的最低阀值 */
        unsigned int  pre_actr0_ck_hig : 8;  /* bit[8-15] : AUTOCORRELATION CNT0检查的最高阀值 */
        unsigned int  pre_actr1_ck_low : 8;  /* bit[16-23]: AUTOCORRELATION CNT1检查的最低阀值 */
        unsigned int  pre_actr1_ck_hig : 8;  /* bit[24-31]: AUTOCORRELATION CNT1检查的最高阀值 */
    } reg;
} SOC_TRNG_HISEC_COM_TRNG_PRE_ATCR01_CNT_UNION;
#endif
#define SOC_TRNG_HISEC_COM_TRNG_PRE_ATCR01_CNT_pre_actr0_ck_low_START  (0)
#define SOC_TRNG_HISEC_COM_TRNG_PRE_ATCR01_CNT_pre_actr0_ck_low_END    (7)
#define SOC_TRNG_HISEC_COM_TRNG_PRE_ATCR01_CNT_pre_actr0_ck_hig_START  (8)
#define SOC_TRNG_HISEC_COM_TRNG_PRE_ATCR01_CNT_pre_actr0_ck_hig_END    (15)
#define SOC_TRNG_HISEC_COM_TRNG_PRE_ATCR01_CNT_pre_actr1_ck_low_START  (16)
#define SOC_TRNG_HISEC_COM_TRNG_PRE_ATCR01_CNT_pre_actr1_ck_low_END    (23)
#define SOC_TRNG_HISEC_COM_TRNG_PRE_ATCR01_CNT_pre_actr1_ck_hig_START  (24)
#define SOC_TRNG_HISEC_COM_TRNG_PRE_ATCR01_CNT_pre_actr1_ck_hig_END    (31)


/*****************************************************************************
 结构名    : SOC_TRNG_HISEC_COM_TRNG_PRE_ATCR23_CNT_UNION
 结构说明  : HISEC_COM_TRNG_PRE_ATCR23_CNT 寄存器结构定义。地址偏移量:0x004C，初值:0xFF00FF00，宽度:32
 寄存器说明: 熵源在线检查的ATCR23检查阀值配置。
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  pre_actr2_ck_low : 8;  /* bit[0-7]  : AUTOCORRELATION CNT2检查的最低阀值 */
        unsigned int  pre_actr2_ck_hig : 8;  /* bit[8-15] : AUTOCORRELATION CNT2检查的最高阀值 */
        unsigned int  pre_actr3_ck_low : 8;  /* bit[16-23]: AUTOCORRELATION CNT3检查的最低阀值 */
        unsigned int  pre_actr3_ck_hig : 8;  /* bit[24-31]: AUTOCORRELATION CNT3检查的最高阀值 */
    } reg;
} SOC_TRNG_HISEC_COM_TRNG_PRE_ATCR23_CNT_UNION;
#endif
#define SOC_TRNG_HISEC_COM_TRNG_PRE_ATCR23_CNT_pre_actr2_ck_low_START  (0)
#define SOC_TRNG_HISEC_COM_TRNG_PRE_ATCR23_CNT_pre_actr2_ck_low_END    (7)
#define SOC_TRNG_HISEC_COM_TRNG_PRE_ATCR23_CNT_pre_actr2_ck_hig_START  (8)
#define SOC_TRNG_HISEC_COM_TRNG_PRE_ATCR23_CNT_pre_actr2_ck_hig_END    (15)
#define SOC_TRNG_HISEC_COM_TRNG_PRE_ATCR23_CNT_pre_actr3_ck_low_START  (16)
#define SOC_TRNG_HISEC_COM_TRNG_PRE_ATCR23_CNT_pre_actr3_ck_low_END    (23)
#define SOC_TRNG_HISEC_COM_TRNG_PRE_ATCR23_CNT_pre_actr3_ck_hig_START  (24)
#define SOC_TRNG_HISEC_COM_TRNG_PRE_ATCR23_CNT_pre_actr3_ck_hig_END    (31)


/*****************************************************************************
 结构名    : SOC_TRNG_HISEC_COM_TRNG_POS_CK_CNT_UNION
 结构说明  : HISEC_COM_TRNG_POS_CK_CNT 寄存器结构定义。地址偏移量:0x0050，初值:0x00000008，宽度:32
 寄存器说明: DRBG后随机数在线检查连续失败的阀值配置寄存器。
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  pos_self_fail_cnt : 4;  /* bit[0-3] : 熵源在线检查连续失败的次数配置寄存器；
                                                            配置范围为3~8，当超出此范围则赋值为5. */
        unsigned int  reserved          : 28; /* bit[4-31]:  */
    } reg;
} SOC_TRNG_HISEC_COM_TRNG_POS_CK_CNT_UNION;
#endif
#define SOC_TRNG_HISEC_COM_TRNG_POS_CK_CNT_pos_self_fail_cnt_START  (0)
#define SOC_TRNG_HISEC_COM_TRNG_POS_CK_CNT_pos_self_fail_cnt_END    (3)


/*****************************************************************************
 结构名    : SOC_TRNG_HISEC_COM_TRNG_POS_MONO_CNT_UNION
 结构说明  : HISEC_COM_TRNG_POS_MONO_CNT 寄存器结构定义。地址偏移量:0x0054，初值:0x0000FF00，宽度:32
 寄存器说明: DRBG后随机数在线检查的MONO检查阀值配置
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  pos_mono_ck_low : 8;  /* bit[0-7]  : MONO检查的最低阀值 */
        unsigned int  pos_mono_ck_hig : 8;  /* bit[8-15] : MONO检查的最高阀值 */
        unsigned int  reserved        : 16; /* bit[16-31]:  */
    } reg;
} SOC_TRNG_HISEC_COM_TRNG_POS_MONO_CNT_UNION;
#endif
#define SOC_TRNG_HISEC_COM_TRNG_POS_MONO_CNT_pos_mono_ck_low_START  (0)
#define SOC_TRNG_HISEC_COM_TRNG_POS_MONO_CNT_pos_mono_ck_low_END    (7)
#define SOC_TRNG_HISEC_COM_TRNG_POS_MONO_CNT_pos_mono_ck_hig_START  (8)
#define SOC_TRNG_HISEC_COM_TRNG_POS_MONO_CNT_pos_mono_ck_hig_END    (15)


/*****************************************************************************
 结构名    : SOC_TRNG_HISEC_COM_TRNG_POS_LONG_RUN_CNT_UNION
 结构说明  : HISEC_COM_TRNG_POS_LONG_RUN_CNT 寄存器结构定义。地址偏移量:0x0058，初值:0x000000FF，宽度:32
 寄存器说明: DRBG后随机数在线检查的LONG RUN检查阀值配置。
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  pos_long_run_hig : 8;  /* bit[0-7] : LONG RUN检查的最高阀值 */
        unsigned int  reserved         : 24; /* bit[8-31]:  */
    } reg;
} SOC_TRNG_HISEC_COM_TRNG_POS_LONG_RUN_CNT_UNION;
#endif
#define SOC_TRNG_HISEC_COM_TRNG_POS_LONG_RUN_CNT_pos_long_run_hig_START  (0)
#define SOC_TRNG_HISEC_COM_TRNG_POS_LONG_RUN_CNT_pos_long_run_hig_END    (7)


/*****************************************************************************
 结构名    : SOC_TRNG_HISEC_COM_TRNG_POS_RUN_CNT_UNION
 结构说明  : HISEC_COM_TRNG_POS_RUN_CNT 寄存器结构定义。地址偏移量:0x005C，初值:0x0000FFFF，宽度:32
 寄存器说明: DRBG后随机数在线检查的RUN检查阀值配置。
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  pos_run_test_hig : 16; /* bit[0-15] : RUN检查的最高阀值 */
        unsigned int  reserved         : 16; /* bit[16-31]:  */
    } reg;
} SOC_TRNG_HISEC_COM_TRNG_POS_RUN_CNT_UNION;
#endif
#define SOC_TRNG_HISEC_COM_TRNG_POS_RUN_CNT_pos_run_test_hig_START  (0)
#define SOC_TRNG_HISEC_COM_TRNG_POS_RUN_CNT_pos_run_test_hig_END    (15)


/*****************************************************************************
 结构名    : SOC_TRNG_HISEC_COM_TRNG_POS_SERIAL_CNT_UNION
 结构说明  : HISEC_COM_TRNG_POS_SERIAL_CNT 寄存器结构定义。地址偏移量:0x0060，初值:0x0000FFFF，宽度:32
 寄存器说明: DRBG后随机数在线检查的SERIAL检查阀值配置。
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  pos_serial_ck_hig : 16; /* bit[0-15] : RUN检查的最高阀值 */
        unsigned int  reserved          : 16; /* bit[16-31]:  */
    } reg;
} SOC_TRNG_HISEC_COM_TRNG_POS_SERIAL_CNT_UNION;
#endif
#define SOC_TRNG_HISEC_COM_TRNG_POS_SERIAL_CNT_pos_serial_ck_hig_START  (0)
#define SOC_TRNG_HISEC_COM_TRNG_POS_SERIAL_CNT_pos_serial_ck_hig_END    (15)


/*****************************************************************************
 结构名    : SOC_TRNG_HISEC_COM_TRNG_POS_POKER_CNT_UNION
 结构说明  : HISEC_COM_TRNG_POS_POKER_CNT 寄存器结构定义。地址偏移量:0x0064，初值:0x0000FFFF，宽度:32
 寄存器说明: DRBG后随机数在线检查的POKER检查阀值配置。
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  pos_poker_ck_hig : 16; /* bit[0-15] : POKER检查的最高阀值 */
        unsigned int  reserved         : 16; /* bit[16-31]:  */
    } reg;
} SOC_TRNG_HISEC_COM_TRNG_POS_POKER_CNT_UNION;
#endif
#define SOC_TRNG_HISEC_COM_TRNG_POS_POKER_CNT_pos_poker_ck_hig_START  (0)
#define SOC_TRNG_HISEC_COM_TRNG_POS_POKER_CNT_pos_poker_ck_hig_END    (15)


/*****************************************************************************
 结构名    : SOC_TRNG_HISEC_COM_TRNG_POS_ATCR01_CNT_UNION
 结构说明  : HISEC_COM_TRNG_POS_ATCR01_CNT 寄存器结构定义。地址偏移量:0x0068，初值:0xFF00FF00，宽度:32
 寄存器说明: DRBG后随机数在线检查的ATCR01检查阀值配置。
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  pos_actr0_ck_low : 8;  /* bit[0-7]  : AUTOCORRELATION CNT0检查的最低阀值 */
        unsigned int  pos_actr0_ck_hig : 8;  /* bit[8-15] : AUTOCORRELATION CNT0检查的最高阀值 */
        unsigned int  pos_actr1_ck_low : 8;  /* bit[16-23]: AUTOCORRELATION CNT1检查的最低阀值 */
        unsigned int  pos_actr1_ck_hig : 8;  /* bit[24-31]: AUTOCORRELATION CNT1检查的最高阀值 */
    } reg;
} SOC_TRNG_HISEC_COM_TRNG_POS_ATCR01_CNT_UNION;
#endif
#define SOC_TRNG_HISEC_COM_TRNG_POS_ATCR01_CNT_pos_actr0_ck_low_START  (0)
#define SOC_TRNG_HISEC_COM_TRNG_POS_ATCR01_CNT_pos_actr0_ck_low_END    (7)
#define SOC_TRNG_HISEC_COM_TRNG_POS_ATCR01_CNT_pos_actr0_ck_hig_START  (8)
#define SOC_TRNG_HISEC_COM_TRNG_POS_ATCR01_CNT_pos_actr0_ck_hig_END    (15)
#define SOC_TRNG_HISEC_COM_TRNG_POS_ATCR01_CNT_pos_actr1_ck_low_START  (16)
#define SOC_TRNG_HISEC_COM_TRNG_POS_ATCR01_CNT_pos_actr1_ck_low_END    (23)
#define SOC_TRNG_HISEC_COM_TRNG_POS_ATCR01_CNT_pos_actr1_ck_hig_START  (24)
#define SOC_TRNG_HISEC_COM_TRNG_POS_ATCR01_CNT_pos_actr1_ck_hig_END    (31)


/*****************************************************************************
 结构名    : SOC_TRNG_HISEC_COM_TRNG_POS_ATCR23_CNT_UNION
 结构说明  : HISEC_COM_TRNG_POS_ATCR23_CNT 寄存器结构定义。地址偏移量:0x006C，初值:0xFF00FF00，宽度:32
 寄存器说明: DRBG后随机数在线检查的ATCR23检查阀值配置。
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  pos_actr2_ck_low : 8;  /* bit[0-7]  : AUTOCORRELATION CNT2检查的最低阀值 */
        unsigned int  pos_actr2_ck_hig : 8;  /* bit[8-15] : AUTOCORRELATION CNT2检查的最高阀值 */
        unsigned int  pos_actr3_ck_low : 8;  /* bit[16-23]: AUTOCORRELATION CNT3检查的最低阀值 */
        unsigned int  pos_actr3_ck_hig : 8;  /* bit[24-31]: AUTOCORRELATION CNT3检查的最高阀值 */
    } reg;
} SOC_TRNG_HISEC_COM_TRNG_POS_ATCR23_CNT_UNION;
#endif
#define SOC_TRNG_HISEC_COM_TRNG_POS_ATCR23_CNT_pos_actr2_ck_low_START  (0)
#define SOC_TRNG_HISEC_COM_TRNG_POS_ATCR23_CNT_pos_actr2_ck_low_END    (7)
#define SOC_TRNG_HISEC_COM_TRNG_POS_ATCR23_CNT_pos_actr2_ck_hig_START  (8)
#define SOC_TRNG_HISEC_COM_TRNG_POS_ATCR23_CNT_pos_actr2_ck_hig_END    (15)
#define SOC_TRNG_HISEC_COM_TRNG_POS_ATCR23_CNT_pos_actr3_ck_low_START  (16)
#define SOC_TRNG_HISEC_COM_TRNG_POS_ATCR23_CNT_pos_actr3_ck_low_END    (23)
#define SOC_TRNG_HISEC_COM_TRNG_POS_ATCR23_CNT_pos_actr3_ck_hig_START  (24)
#define SOC_TRNG_HISEC_COM_TRNG_POS_ATCR23_CNT_pos_actr3_ck_hig_END    (31)


/*****************************************************************************
 结构名    : SOC_TRNG_HISEC_COM_TRNG_AIS31_FAIL_CNT_UNION
 结构说明  : HISEC_COM_TRNG_AIS31_FAIL_CNT 寄存器结构定义。地址偏移量:0x0070，初值:0x000000FF，宽度:32
 寄存器说明: 熵源AIS31检查最大失败次数配置
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ais31_fail_cnt : 8;  /* bit[0-7] : 熵源AIS31检查最大失败次数配置阈值；
                                                         最小值为8'd3，默认值为8'd20； 如果配置值小于最小值，则逻辑默认为8'd20； */
        unsigned int  reserved       : 24; /* bit[8-31]:  */
    } reg;
} SOC_TRNG_HISEC_COM_TRNG_AIS31_FAIL_CNT_UNION;
#endif
#define SOC_TRNG_HISEC_COM_TRNG_AIS31_FAIL_CNT_ais31_fail_cnt_START  (0)
#define SOC_TRNG_HISEC_COM_TRNG_AIS31_FAIL_CNT_ais31_fail_cnt_END    (7)


/*****************************************************************************
 结构名    : SOC_TRNG_HISEC_COM_TRNG_AIS31_BLOCK_CNT_UNION
 结构说明  : HISEC_COM_TRNG_AIS31_BLOCK_CNT 寄存器结构定义。地址偏移量:0x0074，初值:0x00000200，宽度:32
 寄存器说明: 熵源AIS31检查最大块次数配置
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ais31_block_cnt : 10; /* bit[0-9]  : 熵源AIS31检查最大检查块配置阈值；
                                                           默认值为10'd512，即512次；当配置为0时，表示不进行AIS31检查； */
        unsigned int  reserved        : 22; /* bit[10-31]:  */
    } reg;
} SOC_TRNG_HISEC_COM_TRNG_AIS31_BLOCK_CNT_UNION;
#endif
#define SOC_TRNG_HISEC_COM_TRNG_AIS31_BLOCK_CNT_ais31_block_cnt_START  (0)
#define SOC_TRNG_HISEC_COM_TRNG_AIS31_BLOCK_CNT_ais31_block_cnt_END    (9)


/*****************************************************************************
 结构名    : SOC_TRNG_HISEC_COM_TRNG_AIS31_POKER_LOW_UNION
 结构说明  : HISEC_COM_TRNG_AIS31_POKER_LOW 寄存器结构定义。地址偏移量:0x0078，初值:0x00000000，宽度:32
 寄存器说明: 熵源AIS31 POKER检查的最低阈值
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ais31_poker_low : 8;  /* bit[0-7] : 熵源AIS31 POKER检查的最低阈值 */
        unsigned int  reserved        : 24; /* bit[8-31]:  */
    } reg;
} SOC_TRNG_HISEC_COM_TRNG_AIS31_POKER_LOW_UNION;
#endif
#define SOC_TRNG_HISEC_COM_TRNG_AIS31_POKER_LOW_ais31_poker_low_START  (0)
#define SOC_TRNG_HISEC_COM_TRNG_AIS31_POKER_LOW_ais31_poker_low_END    (7)


/*****************************************************************************
 结构名    : SOC_TRNG_HISEC_COM_TRNG_AIS31_POKER_HIG_UNION
 结构说明  : HISEC_COM_TRNG_AIS31_POKER_HIG 寄存器结构定义。地址偏移量:0x007C，初值:0x000000FF，宽度:32
 寄存器说明: 熵源AIS31 POKER检查的最高阈值
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ais31_poker_hig : 8;  /* bit[0-7] : 熵源AIS31 POKER检查的最高阈值 */
        unsigned int  reserved        : 24; /* bit[8-31]:  */
    } reg;
} SOC_TRNG_HISEC_COM_TRNG_AIS31_POKER_HIG_UNION;
#endif
#define SOC_TRNG_HISEC_COM_TRNG_AIS31_POKER_HIG_ais31_poker_hig_START  (0)
#define SOC_TRNG_HISEC_COM_TRNG_AIS31_POKER_HIG_ais31_poker_hig_END    (7)


/*****************************************************************************
 结构名    : SOC_TRNG_UNLOCK_UNION
 结构说明  : UNLOCK 寄存器结构定义。地址偏移量:0x0080，初值:0x0000000A，宽度:32
 寄存器说明: 
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  trng_unlock : 4;  /* bit[0-3] : 寄存器锁，写0xA时锁定不可配置，写0x5解锁可配，写入其他值产生alarm。 */
        unsigned int  reserved    : 28; /* bit[4-31]:  */
    } reg;
} SOC_TRNG_UNLOCK_UNION;
#endif
#define SOC_TRNG_UNLOCK_trng_unlock_START  (0)
#define SOC_TRNG_UNLOCK_trng_unlock_END    (3)


/*****************************************************************************
 结构名    : SOC_TRNG_CTRL_CHI_TH_PRE1_UNION
 结构说明  : CTRL_CHI_TH_PRE1 寄存器结构定义。地址偏移量:0x0084，初值:0x000001C2，宽度:32
 寄存器说明: PRE1阈值
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  thre_pre1 : 9;  /* bit[0-8] : 在线测试的阈值信号，PRE1阈值。 */
        unsigned int  reserved  : 23; /* bit[9-31]:  */
    } reg;
} SOC_TRNG_CTRL_CHI_TH_PRE1_UNION;
#endif
#define SOC_TRNG_CTRL_CHI_TH_PRE1_thre_pre1_START  (0)
#define SOC_TRNG_CTRL_CHI_TH_PRE1_thre_pre1_END    (8)


/*****************************************************************************
 结构名    : SOC_TRNG_CTRL_CHI_TH_PRE2_UNION
 结构说明  : CTRL_CHI_TH_PRE2 寄存器结构定义。地址偏移量:0x0088，初值:0x00000000，宽度:32
 寄存器说明: PRE2阈值
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  thre_pre2 : 9;  /* bit[0-8] : 在线测试的阈值信号，PRE2阈值。 */
        unsigned int  reserved  : 23; /* bit[9-31]:  */
    } reg;
} SOC_TRNG_CTRL_CHI_TH_PRE2_UNION;
#endif
#define SOC_TRNG_CTRL_CHI_TH_PRE2_thre_pre2_START  (0)
#define SOC_TRNG_CTRL_CHI_TH_PRE2_thre_pre2_END    (8)


/*****************************************************************************
 结构名    : SOC_TRNG_CTRL_CHI_TH_PRE3_UNION
 结构说明  : CTRL_CHI_TH_PRE3 寄存器结构定义。地址偏移量:0x008C，初值:0x000001C2，宽度:32
 寄存器说明: PRE3阈值
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  thre_pre3 : 9;  /* bit[0-8] : 在线测试的阈值信号，PRE3阈值。 */
        unsigned int  reserved  : 23; /* bit[9-31]:  */
    } reg;
} SOC_TRNG_CTRL_CHI_TH_PRE3_UNION;
#endif
#define SOC_TRNG_CTRL_CHI_TH_PRE3_thre_pre3_START  (0)
#define SOC_TRNG_CTRL_CHI_TH_PRE3_thre_pre3_END    (8)


/*****************************************************************************
 结构名    : SOC_TRNG_CTRL_CHI_TH_ENTROPY_UNION
 结构说明  : CTRL_CHI_TH_ENTROPY 寄存器结构定义。地址偏移量:0x0090，初值:0x000001C2，宽度:32
 寄存器说明: ENTROPY阈值
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  thre_entropy : 9;  /* bit[0-8] : 在线测试的阈值信号，entropy阈值。 */
        unsigned int  reserved     : 23; /* bit[9-31]:  */
    } reg;
} SOC_TRNG_CTRL_CHI_TH_ENTROPY_UNION;
#endif
#define SOC_TRNG_CTRL_CHI_TH_ENTROPY_thre_entropy_START  (0)
#define SOC_TRNG_CTRL_CHI_TH_ENTROPY_thre_entropy_END    (8)


/*****************************************************************************
 结构名    : SOC_TRNG_INT_CLR_UNION
 结构说明  : INT_CLR 寄存器结构定义。地址偏移量:0x0094，初值:0x00000000，宽度:32
 寄存器说明: TRNG中断状态清除寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  chi_online_int_clr : 4;  /* bit[0-3] : CHI_TEST模块online 中断清除使能信号，写清。
                                                             0x5清除TRNG的告警。
                                                             其它，不清除TRNG的告警。 */
        unsigned int  reserved           : 28; /* bit[4-31]:  */
    } reg;
} SOC_TRNG_INT_CLR_UNION;
#endif
#define SOC_TRNG_INT_CLR_chi_online_int_clr_START  (0)
#define SOC_TRNG_INT_CLR_chi_online_int_clr_END    (3)


/*****************************************************************************
 结构名    : SOC_TRNG_INT_MASK_UNION
 结构说明  : INT_MASK 寄存器结构定义。地址偏移量:0x0098，初值:0x00000005，宽度:32
 寄存器说明: TRNG中断MASK控制寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  chi_online_int_mask : 4;  /* bit[0-3] : CHI ONLINE 中断屏蔽寄存器:
                                                              0x5:屏蔽，0xA：不屏蔽
                                                              其他值:产生alarm。 */
        unsigned int  reserved            : 28; /* bit[4-31]:  */
    } reg;
} SOC_TRNG_INT_MASK_UNION;
#endif
#define SOC_TRNG_INT_MASK_chi_online_int_mask_START  (0)
#define SOC_TRNG_INT_MASK_chi_online_int_mask_END    (3)


/*****************************************************************************
 结构名    : SOC_TRNG_INT_SRC_STATUS_UNION
 结构说明  : INT_SRC_STATUS 寄存器结构定义。地址偏移量:0x009C，初值:0x00000000，宽度:32
 寄存器说明: TRNG屏蔽前中断状态寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  int_chi_online_src : 1;  /* bit[0]   : CHI online原始中断状态：
                                                             1'b0:无中断。
                                                             1'b1:有中断。 */
        unsigned int  reserved           : 31; /* bit[1-31]:  */
    } reg;
} SOC_TRNG_INT_SRC_STATUS_UNION;
#endif
#define SOC_TRNG_INT_SRC_STATUS_int_chi_online_src_START  (0)
#define SOC_TRNG_INT_SRC_STATUS_int_chi_online_src_END    (0)


/*****************************************************************************
 结构名    : SOC_TRNG_INT_STATUS_UNION
 结构说明  : INT_STATUS 寄存器结构定义。地址偏移量:0x00A0，初值:0x00000000，宽度:32
 寄存器说明: TRNG屏蔽后中断状态寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  int_chi_online : 1;  /* bit[0]   : CHI online屏蔽后的中断状态：
                                                         1'b0:无中断。
                                                         1'b1:有中断。 */
        unsigned int  reserved       : 31; /* bit[1-31]:  */
    } reg;
} SOC_TRNG_INT_STATUS_UNION;
#endif
#define SOC_TRNG_INT_STATUS_int_chi_online_START  (0)
#define SOC_TRNG_INT_STATUS_int_chi_online_END    (0)


/*****************************************************************************
 结构名    : SOC_TRNG_OTPC_STATUS_0_UNION
 结构说明  : OTPC_STATUS_0 寄存器结构定义。地址偏移量:0x00A4，初值:0x55555555，宽度:32
 寄存器说明: TRNG的OTPC状态寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  otpc_trng_ctrl_sel      : 4;  /* bit[0-3]  : OTPC控制选择，5为OTPC，a为CPU。 */
        unsigned int  otpc_trng_tp_disable    : 4;  /* bit[4-7]  : Testpoint关闭，5为关闭,a为不关闭。 */
        unsigned int  otpc_trng_digsrc_compen : 4;  /* bit[8-11] : 数字随机源压缩使能，5为使能,a为不使能。 */
        unsigned int  otpc_trng_scrfilter_en  : 4;  /* bit[12-15]: 随机源整体压缩使能，5为使能,a为不使能。 */
        unsigned int  otpc_trng_discard_en    : 4;  /* bit[16-19]: 随机丢弃使能，5为使能,a为不使能。 */
        unsigned int  otpc_trng_pre_proc_en   : 4;  /* bit[20-23]: 前处理使能，5为使能,a为不使能。 */
        unsigned int  otpc_trng_post_proc_en  : 4;  /* bit[24-27]: 后处理使能，5为使能,a为不使能。 */
        unsigned int  otpc_trng_post_test_en  : 4;  /* bit[28-31]: 后处理后在线检测使能，5为使能,a为不使能。 */
    } reg;
} SOC_TRNG_OTPC_STATUS_0_UNION;
#endif
#define SOC_TRNG_OTPC_STATUS_0_otpc_trng_ctrl_sel_START       (0)
#define SOC_TRNG_OTPC_STATUS_0_otpc_trng_ctrl_sel_END         (3)
#define SOC_TRNG_OTPC_STATUS_0_otpc_trng_tp_disable_START     (4)
#define SOC_TRNG_OTPC_STATUS_0_otpc_trng_tp_disable_END       (7)
#define SOC_TRNG_OTPC_STATUS_0_otpc_trng_digsrc_compen_START  (8)
#define SOC_TRNG_OTPC_STATUS_0_otpc_trng_digsrc_compen_END    (11)
#define SOC_TRNG_OTPC_STATUS_0_otpc_trng_scrfilter_en_START   (12)
#define SOC_TRNG_OTPC_STATUS_0_otpc_trng_scrfilter_en_END     (15)
#define SOC_TRNG_OTPC_STATUS_0_otpc_trng_discard_en_START     (16)
#define SOC_TRNG_OTPC_STATUS_0_otpc_trng_discard_en_END       (19)
#define SOC_TRNG_OTPC_STATUS_0_otpc_trng_pre_proc_en_START    (20)
#define SOC_TRNG_OTPC_STATUS_0_otpc_trng_pre_proc_en_END      (23)
#define SOC_TRNG_OTPC_STATUS_0_otpc_trng_post_proc_en_START   (24)
#define SOC_TRNG_OTPC_STATUS_0_otpc_trng_post_proc_en_END     (27)
#define SOC_TRNG_OTPC_STATUS_0_otpc_trng_post_test_en_START   (28)
#define SOC_TRNG_OTPC_STATUS_0_otpc_trng_post_test_en_END     (31)


/*****************************************************************************
 结构名    : SOC_TRNG_OTPC_STATUS_1_UNION
 结构说明  : OTPC_STATUS_1 寄存器结构定义。地址偏移量:0x00A8，初值:0x00055E45，宽度:32
 寄存器说明: TRNG的OTPC状态寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  otpc_trng_pre_test_en : 4;  /* bit[0-3]  : 随机源在线检测使能，1为使能。 */
        unsigned int  otpc_trng_hs_src_cfg  : 8;  /* bit[4-11] : 海思随机源环路配置。 */
        unsigned int  otpc_trng_full_dis    : 4;  /* bit[12-15]: 全种模式关闭，1为关闭。 */
        unsigned int  otpc_hw_rd_finish     : 4;  /* bit[16-19]: otpc读完成标记，5表示完成，a未完成 */
        unsigned int  reserved              : 12; /* bit[20-31]:  */
    } reg;
} SOC_TRNG_OTPC_STATUS_1_UNION;
#endif
#define SOC_TRNG_OTPC_STATUS_1_otpc_trng_pre_test_en_START  (0)
#define SOC_TRNG_OTPC_STATUS_1_otpc_trng_pre_test_en_END    (3)
#define SOC_TRNG_OTPC_STATUS_1_otpc_trng_hs_src_cfg_START   (4)
#define SOC_TRNG_OTPC_STATUS_1_otpc_trng_hs_src_cfg_END     (11)
#define SOC_TRNG_OTPC_STATUS_1_otpc_trng_full_dis_START     (12)
#define SOC_TRNG_OTPC_STATUS_1_otpc_trng_full_dis_END       (15)
#define SOC_TRNG_OTPC_STATUS_1_otpc_hw_rd_finish_START      (16)
#define SOC_TRNG_OTPC_STATUS_1_otpc_hw_rd_finish_END        (19)


/*****************************************************************************
 结构名    : SOC_TRNG_OTPC_TRNG_TRIM_0_UNION
 结构说明  : OTPC_TRNG_TRIM_0 寄存器结构定义。地址偏移量:0x00B0，初值:0x00000000，宽度:32
 寄存器说明: OTPC_TRNG_TRIM寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved : 32; /* bit[0-31]: OTPC_TRNG_TRIM[31：0]寄存器 */
    } reg;
} SOC_TRNG_OTPC_TRNG_TRIM_0_UNION;
#endif


/*****************************************************************************
 结构名    : SOC_TRNG_OTPC_TRNG_TRIM_1_UNION
 结构说明  : OTPC_TRNG_TRIM_1 寄存器结构定义。地址偏移量:0x00B4，初值:0x00000000，宽度:32
 寄存器说明: OTPC_TRNG_TRIM寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved : 32; /* bit[0-31]: OTPC_TRNG_TRIM[63：32]寄存器 */
    } reg;
} SOC_TRNG_OTPC_TRNG_TRIM_1_UNION;
#endif


/*****************************************************************************
 结构名    : SOC_TRNG_OTPC_TRNG_TRIM_2_UNION
 结构说明  : OTPC_TRNG_TRIM_2 寄存器结构定义。地址偏移量:0x00B8，初值:0x00000000，宽度:32
 寄存器说明: OTPC_TRNG_TRIM寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved : 32; /* bit[0-31]: OTPC_TRNG_TRIM[95：64]寄存器 */
    } reg;
} SOC_TRNG_OTPC_TRNG_TRIM_2_UNION;
#endif


/*****************************************************************************
 结构名    : SOC_TRNG_OTPC_TRNG_TRIM_3_UNION
 结构说明  : OTPC_TRNG_TRIM_3 寄存器结构定义。地址偏移量:0x00Bc，初值:0x00000000，宽度:32
 寄存器说明: OTPC_TRNG_TRIM寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved : 32; /* bit[0-31]: OTPC_TRNG_TRIM[127：96]寄存器 */
    } reg;
} SOC_TRNG_OTPC_TRNG_TRIM_3_UNION;
#endif


/*****************************************************************************
 结构名    : SOC_TRNG_OTPC_TRNG_TRIM_CRC_UNION
 结构说明  : OTPC_TRNG_TRIM_CRC 寄存器结构定义。地址偏移量:0x00c0，初值:0x00006666，宽度:32
 寄存器说明: OTPC_TRNG_TRIM值的crc寄存器
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  OTPC_TRNG_TRIM_CRC : 16; /* bit[0-15] : OTPC_TRNG_TRIM值的crc4寄存器
                                                              crc寄存器[3:0]~[15:12]对应tri值的[31:0]~[127:96] */
        unsigned int  reserved           : 16; /* bit[16-31]:  */
    } reg;
} SOC_TRNG_OTPC_TRNG_TRIM_CRC_UNION;
#endif
#define SOC_TRNG_OTPC_TRNG_TRIM_CRC_OTPC_TRNG_TRIM_CRC_START  (0)
#define SOC_TRNG_OTPC_TRNG_TRIM_CRC_OTPC_TRNG_TRIM_CRC_END    (15)


/*****************************************************************************
 结构名    : SOC_TRNG_FIFO_RD_LINE_UNION
 结构说明  : FIFO_RD_LINE 寄存器结构定义。地址偏移量:0x00c4，初值:0x00000000，宽度:32
 寄存器说明: 超过此门限才允许软件读取TRNG随机数
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  fifo_rd_line : 32; /* bit[0-31]:  */
    } reg;
} SOC_TRNG_FIFO_RD_LINE_UNION;
#endif
#define SOC_TRNG_FIFO_RD_LINE_fifo_rd_line_START  (0)
#define SOC_TRNG_FIFO_RD_LINE_fifo_rd_line_END    (31)


/*****************************************************************************
 结构名    : SOC_TRNG_DRBG_CYCLE_NUM_UNION
 结构说明  : DRBG_CYCLE_NUM 寄存器结构定义。地址偏移量:0x00c8，初值:0x00000405，宽度:32
 寄存器说明: DRBG非全种模式门限值
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reseed_num_max : 8;  /* bit[0-7]  : reseed_num_max */
        unsigned int  rand_gen_max   : 8;  /* bit[8-15] : rand_gen_max */
        unsigned int  reserved       : 16; /* bit[16-31]:  */
    } reg;
} SOC_TRNG_DRBG_CYCLE_NUM_UNION;
#endif
#define SOC_TRNG_DRBG_CYCLE_NUM_reseed_num_max_START  (0)
#define SOC_TRNG_DRBG_CYCLE_NUM_reseed_num_max_END    (7)
#define SOC_TRNG_DRBG_CYCLE_NUM_rand_gen_max_START    (8)
#define SOC_TRNG_DRBG_CYCLE_NUM_rand_gen_max_END      (15)






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

#endif /* end of soc_trng_interface.h */
