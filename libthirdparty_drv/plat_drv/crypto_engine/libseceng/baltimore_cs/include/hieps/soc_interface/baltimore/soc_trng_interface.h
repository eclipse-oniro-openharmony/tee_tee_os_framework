/******************************************************************************

                 ��Ȩ���� (C), 2001-2019, ��Ϊ�������޹�˾

 ******************************************************************************
  �� �� ��   : soc_trng_interface.h
  �� �� ��   : ����
  ��    ��   : Excel2Code
  ��������   : 2019-10-26 10:53:30
  ����޸�   :
  ��������   : �ӿ�ͷ�ļ�
  �����б�   :
  �޸���ʷ   :
  1.��    ��   : 2019��10��26��
    ��    ��   : l00249396
    �޸�����   : �ӡ�HiEPS V200 nmanager�Ĵ����ֲ�_TRNG.xml���Զ�����

******************************************************************************/

/*****************************************************************************
  1 ����ͷ�ļ�����
*****************************************************************************/

#ifndef __SOC_TRNG_INTERFACE_H__
#define __SOC_TRNG_INTERFACE_H__

#ifdef __cplusplus
    #if __cplusplus
        extern "C" {
    #endif
#endif



/*****************************************************************************
  2 �궨��
*****************************************************************************/

/****************************************************************************
                     (1/2) NEW_TRNG
 ****************************************************************************/
/* �Ĵ���˵��������TRNGѡ��
   λ����UNION�ṹ:  SOC_TRNG_REG_TRNG_SEL_UNION */
#define SOC_TRNG_REG_TRNG_SEL_ADDR(base)              ((base) + (0x0300))

/* �Ĵ���˵����TRNG�����ź�
   λ����UNION�ṹ:  SOC_TRNG_OTP_TRNG_SEL_UNION */
#define SOC_TRNG_OTP_TRNG_SEL_ADDR(base)              ((base) + (0x0304))

/* �Ĵ���˵����OTP������TRNG��ѡ��
   λ����UNION�ṹ:  SOC_TRNG_OTP_SW_FLAG_UNION */
#define SOC_TRNG_OTP_SW_FLAG_ADDR(base)               ((base) + (0x0308))

/* �Ĵ���˵����FRO_EN_0
   λ����UNION�ṹ:  SOC_TRNG_FRO_EN_0_UNION */
#define SOC_TRNG_FRO_EN_0_ADDR(base)                  ((base) + (0x030c))

/* �Ĵ���˵����FRO_EN_1
   λ����UNION�ṹ:  SOC_TRNG_FRO_EN_1_UNION */
#define SOC_TRNG_FRO_EN_1_ADDR(base)                  ((base) + (0x0310))

/* �Ĵ���˵����GARO_EN
   λ����UNION�ṹ:  SOC_TRNG_GARO_EN_UNION */
#define SOC_TRNG_GARO_EN_ADDR(base)                   ((base) + (0x0314))

/* �Ĵ���˵����MT_FRO_EN
   λ����UNION�ṹ:  SOC_TRNG_MT_FRO_EN_UNION */
#define SOC_TRNG_MT_FRO_EN_ADDR(base)                 ((base) + (0x0318))

/* �Ĵ���˵����MT_GARO_EN
   λ����UNION�ṹ:  SOC_TRNG_MT_GARO_EN_UNION */
#define SOC_TRNG_MT_GARO_EN_ADDR(base)                ((base) + (0x031c))

/* �Ĵ���˵����ENTROPY_SOURCE_ST
   λ����UNION�ṹ:  SOC_TRNG_ENTROPY_SOURCE_ST_UNION */
#define SOC_TRNG_ENTROPY_SOURCE_ST_ADDR(base)         ((base) + (0x320))

/* �Ĵ���˵����sample_clock_cfg
   λ����UNION�ṹ:  SOC_TRNG_SAMPLE_CLK_CFG_UNION */
#define SOC_TRNG_SAMPLE_CLK_CFG_ADDR(base)            ((base) + (0x324))

/* �Ĵ���˵����INT_CHI_ONLINE_CLR
   λ����UNION�ṹ:  SOC_TRNG_INT_CHI_ONLINE_CLR_UNION */
#define SOC_TRNG_INT_CHI_ONLINE_CLR_ADDR(base)        ((base) + (0x328))

/* �Ĵ���˵����RAW_BYPASS_EN
   λ����UNION�ṹ:  SOC_TRNG_RAW_BYPASS_EN_UNION */
#define SOC_TRNG_RAW_BYPASS_EN_ADDR(base)             ((base) + (0x32c))

/* �Ĵ���˵����THRE_CHI_PRE1
   λ����UNION�ṹ:  SOC_TRNG_THRE_CHI_PRE1_UNION */
#define SOC_TRNG_THRE_CHI_PRE1_ADDR(base)             ((base) + (0x0330))

/* �Ĵ���˵����THRE_CHI_PRE2
   λ����UNION�ṹ:  SOC_TRNG_THRE_CHI_PRE2_UNION */
#define SOC_TRNG_THRE_CHI_PRE2_ADDR(base)             ((base) + (0x334))

/* �Ĵ���˵����THRE_CHI_PRE3
   λ����UNION�ṹ:  SOC_TRNG_THRE_CHI_PRE3_UNION */
#define SOC_TRNG_THRE_CHI_PRE3_ADDR(base)             ((base) + (0x338))

/* �Ĵ���˵����THRE_CHI_ENTROPY
   λ����UNION�ṹ:  SOC_TRNG_THRE_CHI_ENTROPY_UNION */
#define SOC_TRNG_THRE_CHI_ENTROPY_ADDR(base)          ((base) + (0x33c))

/* �Ĵ���˵����THRE_LONG_RUN
   λ����UNION�ṹ:  SOC_TRNG_THRE_LONG_RUN_UNION */
#define SOC_TRNG_THRE_LONG_RUN_ADDR(base)             ((base) + (0x340))

/* �Ĵ���˵����THRE_POKER
   λ����UNION�ṹ:  SOC_TRNG_THRE_POKER_UNION */
#define SOC_TRNG_THRE_POKER_ADDR(base)                ((base) + (0x344))

/* �Ĵ���˵����TEST_WIN_RAW_TEST
   λ����UNION�ṹ:  SOC_TRNG_TEST_WIN_RAW_TEST_UNION */
#define SOC_TRNG_TEST_WIN_RAW_TEST_ADDR(base)         ((base) + (0x348))

/* �Ĵ���˵����THRE_FAIL_NUM
   λ����UNION�ṹ:  SOC_TRNG_THRE_FAIL_NUM_UNION */
#define SOC_TRNG_THRE_FAIL_NUM_ADDR(base)             ((base) + (0x34c))

/* �Ĵ���˵����RAW_TEST_CLEAR
   λ����UNION�ṹ:  SOC_TRNG_RAW_TEST_CLEAR_UNION */
#define SOC_TRNG_RAW_TEST_CLEAR_ADDR(base)            ((base) + (0x350))

/* �Ĵ���˵����RAW_FAIL_CNT
   λ����UNION�ṹ:  SOC_TRNG_RAW_FAIL_CNT_UNION */
#define SOC_TRNG_RAW_FAIL_CNT_ADDR(base)              ((base) + (0x354))

/* �Ĵ���˵����RAW_STATE
   λ����UNION�ṹ:  SOC_TRNG_RAW_STATE_UNION */
#define SOC_TRNG_RAW_STATE_ADDR(base)                 ((base) + (0x358))

/* �Ĵ���˵����XOR_COMP_CFG
   λ����UNION�ṹ:  SOC_TRNG_XOR_COMP_CFG_UNION */
#define SOC_TRNG_XOR_COMP_CFG_ADDR(base)              ((base) + (0x35c))

/* �Ĵ���˵����XOR_CHAIN_CFG
   λ����UNION�ṹ:  SOC_TRNG_XOR_CHAIN_CFG_UNION */
#define SOC_TRNG_XOR_CHAIN_CFG_ADDR(base)             ((base) + (0x360))

/* �Ĵ���˵����POST_PROCESS
   λ����UNION�ṹ:  SOC_TRNG_POST_PROCESS_UNION */
#define SOC_TRNG_POST_PROCESS_ADDR(base)              ((base) + (0x364))

/* �Ĵ���˵����RESEED_CNT_LIMIT
   λ����UNION�ṹ:  SOC_TRNG_RESEED_CNT_LIMIT_UNION */
#define SOC_TRNG_RESEED_CNT_LIMIT_ADDR(base)          ((base) + (0x368))

/* �Ĵ���˵����POST_TEST_BYP
   λ����UNION�ṹ:  SOC_TRNG_POST_TEST_BYP_UNION */
#define SOC_TRNG_POST_TEST_BYP_ADDR(base)             ((base) + (0x36c))

/* �Ĵ���˵����POST_TEST_ALARM_MSK
   λ����UNION�ṹ:  SOC_TRNG_POST_TEST_ALARM_MSK_UNION */
#define SOC_TRNG_POST_TEST_ALARM_MSK_ADDR(base)       ((base) + (0x370))

/* �Ĵ���˵����DISTRIBUTION
   λ����UNION�ṹ:  SOC_TRNG_DISTRIBUTION_UNION */
#define SOC_TRNG_DISTRIBUTION_ADDR(base)              ((base) + (0x378))

/* �Ĵ���˵����ALARM_STATE
   λ����UNION�ṹ:  SOC_TRNG_ALARM_STATE_UNION */
#define SOC_TRNG_ALARM_STATE_ADDR(base)               ((base) + (0x37c))

/* �Ĵ���˵����THRE_POST_POKER
   λ����UNION�ṹ:  SOC_TRNG_THRE_POST_POKER_UNION */
#define SOC_TRNG_THRE_POST_POKER_ADDR(base)           ((base) + (0x384))

/* �Ĵ���˵����POST_TEST_WIN_RAW_TEST
   λ����UNION�ṹ:  SOC_TRNG_POST_TEST_WIN_RAW_TEST_UNION */
#define SOC_TRNG_POST_TEST_WIN_RAW_TEST_ADDR(base)    ((base) + (0x388))

/* �Ĵ���˵����POST_TEST_WIN_RAW_TEST
   λ����UNION�ṹ:  SOC_TRNG_THRE_POST_FAIL_NUM_UNION */
#define SOC_TRNG_THRE_POST_FAIL_NUM_ADDR(base)        ((base) + (0x38c))

/* �Ĵ���˵����POST_TEST_WIN_RAW_TEST
   λ����UNION�ṹ:  SOC_TRNG_POST_TEST_CLEAR_UNION */
#define SOC_TRNG_POST_TEST_CLEAR_ADDR(base)           ((base) + (0x390))

/* �Ĵ���˵����POST_TEST_WIN_RAW_TEST
   λ����UNION�ṹ:  SOC_TRNG_POST_FAIL_CNT_UNION */
#define SOC_TRNG_POST_FAIL_CNT_ADDR(base)             ((base) + (0x394))

/* �Ĵ���˵����TRNG_DATA_0
   λ����UNION�ṹ:  SOC_TRNG_WAIT_FOR_USE_UNION */
#define SOC_TRNG_WAIT_FOR_USE_ADDR(base)              ((base) + (0x39c))

/* �Ĵ���˵����TIME_OUT_REGS
   λ����UNION�ṹ:  SOC_TRNG_RNG_TIME_OUT_UNION */
#define SOC_TRNG_RNG_TIME_OUT_ADDR(base)              ((base) + (0x3a0))

/* �Ĵ���˵����CHI_TEST_STATE
   λ����UNION�ṹ:  SOC_TRNG_CHI_TEST_STATE_UNION */
#define SOC_TRNG_CHI_TEST_STATE_ADDR(base)            ((base) + (0x3a4))

/* �Ĵ���˵����TRNG_CLK_EN
   λ����UNION�ṹ:  SOC_TRNG_CLK_EN_UNION */
#define SOC_TRNG_CLK_EN_ADDR(base)                    ((base) + (0x3a8))

/* �Ĵ���˵����TRNG_DONE
   λ����UNION�ṹ:  SOC_TRNG_DONE_UNION */
#define SOC_TRNG_DONE_ADDR(base)                      ((base) + (0x3ac))

/* �Ĵ���˵����TRNG_READY
   λ����UNION�ṹ:  SOC_TRNG_READY_UNION */
#define SOC_TRNG_READY_ADDR(base)                     ((base) + (0x3b0))

/* �Ĵ���˵����TRNG_READY_THRE
   λ����UNION�ṹ:  SOC_TRNG_READY_THRE_UNION */
#define SOC_TRNG_READY_THRE_ADDR(base)                ((base) + (0x3b4))

/* �Ĵ���˵����V
   λ����UNION�ṹ:  SOC_TRNG_FIFO_DATA_UNION */
#define SOC_TRNG_FIFO_DATA_ADDR(base)                 ((base) + (0x3b8))

/* �Ĵ���˵����PRT_LOCK
   λ����UNION�ṹ:  SOC_TRNG_PRT_LOCK_UNION */
#define SOC_TRNG_PRT_LOCK_ADDR(base)                  ((base) + (0x3bc))

/* �Ĵ���˵����ENTROPY_MERGE
   λ����UNION�ṹ:  SOC_TRNG_ENTROPY_MERGE_UNION */
#define SOC_TRNG_ENTROPY_MERGE_ADDR(base)             ((base) + (0x3c0))

/* �Ĵ���˵����KNOWN_ANSWER_TEST
   λ����UNION�ṹ:  SOC_TRNG_KNOWN_ANSWER_TEST_UNION */
#define SOC_TRNG_KNOWN_ANSWER_TEST_ADDR(base)         ((base) + (0x3c4))

/* �Ĵ���˵�����źű������쳣״̬
   λ����UNION�ṹ:  SOC_TRNG_SIGNAL_ALARM_UNION */
#define SOC_TRNG_SIGNAL_ALARM_ADDR(base)              ((base) + (0x3c8))



/****************************************************************************
                     (2/2) reg_define 
 ****************************************************************************/
/* �Ĵ���˵����TRNG���ƼĴ���
   λ����UNION�ṹ:  SOC_TRNG_HISEC_COM_TRNG_CTRL_UNION */
#define SOC_TRNG_HISEC_COM_TRNG_CTRL_ADDR(base)       ((base) + (0x0000))

/* �Ĵ���˵����TRNG��FIFO���ݼĴ���
   λ����UNION�ṹ:  SOC_TRNG_HISEC_COM_TRNG_FIFO_DATA_UNION */
#define SOC_TRNG_HISEC_COM_TRNG_FIFO_DATA_ADDR(base)  ((base) + (0x0004))

/* �Ĵ���˵����TRNG��FIFO���ݼĴ�����״̬
   λ����UNION�ṹ:  SOC_TRNG_HISEC_COM_TRNG_DATA_ST_UNION */
#define SOC_TRNG_HISEC_COM_TRNG_DATA_ST_ADDR(base)    ((base) + (0x0008))

/* �Ĵ���˵������Դ�������ʧ�ܵĴ���ͳ�ƣ������ڵ��ԣ�
   λ����UNION�ṹ:  SOC_TRNG_HISEC_COM_TRNG_ENTROPY_MONO_CNT_UNION */
#define SOC_TRNG_HISEC_COM_TRNG_ENTROPY_MONO_CNT_ADDR(base) ((base) + (0x000C))

/* �Ĵ���˵����������������ʧ�ܴ���ͳ�ƣ������ڵ��ԣ�
   λ����UNION�ṹ:  SOC_TRNG_HISEC_COM_TRNG_MONO_CNT_UNION */
#define SOC_TRNG_HISEC_COM_TRNG_MONO_CNT_ADDR(base)   ((base) + (0x0010))

/* �Ĵ���˵�����澯Դ״̬�Ĵ���
   λ����UNION�ṹ:  SOC_TRNG_HISEC_COM_TRNG_ALARM_SRC_UNION */
#define SOC_TRNG_HISEC_COM_TRNG_ALARM_SRC_ADDR(base)  ((base) + (0x0014))

/* �Ĵ���˵�����澯Դ���μĴ���
   λ����UNION�ṹ:  SOC_TRNG_HISEC_COM_TRNG_ALARM_MASK_UNION */
#define SOC_TRNG_HISEC_COM_TRNG_ALARM_MASK_ADDR(base) ((base) + (0x0018))

/* �Ĵ���˵�������κ�ĸ澯Դ״̬�Ĵ���
   λ����UNION�ṹ:  SOC_TRNG_HISEC_COM_TRNG_ALARM_SRC_POST_UNION */
#define SOC_TRNG_HISEC_COM_TRNG_ALARM_SRC_POST_ADDR(base) ((base) + (0x001C))

/* �Ĵ���˵����trng����״̬�Ĵ���
   λ����UNION�ṹ:  SOC_TRNG_HISEC_COM_TRNG_FIFO_READY_UNION */
#define SOC_TRNG_HISEC_COM_TRNG_FIFO_READY_ADDR(base) ((base) + (0x0020))

/* �Ĵ���˵����4��ģ��IP �˹���ģʽ�Ĵ���
   λ����UNION�ṹ:  SOC_TRNG_HISEC_COM_TRNG_OSC_TEST_SEL_UNION */
#define SOC_TRNG_HISEC_COM_TRNG_OSC_TEST_SEL_ADDR(base) ((base) + (0x0024))

/* �Ĵ���˵�����������������ʱʱ�����üĴ���
   λ����UNION�ṹ:  SOC_TRNG_HISEC_COM_TRNG_TIM_OUT_PERIOD_UNION */
#define SOC_TRNG_HISEC_COM_TRNG_TIM_OUT_PERIOD_ADDR(base) ((base) + (0x0028))

/* �Ĵ���˵�����澯Դ�����κ�澯Դ����Ĵ���
   λ����UNION�ṹ:  SOC_TRNG_HISEC_COM_TRNG_ALARM_CLR_UNION */
#define SOC_TRNG_HISEC_COM_TRNG_ALARM_CLR_ADDR(base)  ((base) + (0x002C))

/* �Ĵ���˵������Դ���߼������ʧ�ܵķ�ֵ���üĴ�����
   λ����UNION�ṹ:  SOC_TRNG_HISEC_COM_TRNG_PRE_CK_CNT_UNION */
#define SOC_TRNG_HISEC_COM_TRNG_PRE_CK_CNT_ADDR(base) ((base) + (0x0030))

/* �Ĵ���˵������Դ���߼���MONO��鷧ֵ����
   λ����UNION�ṹ:  SOC_TRNG_HISEC_COM_TRNG_PRE_MONO_CNT_UNION */
#define SOC_TRNG_HISEC_COM_TRNG_PRE_MONO_CNT_ADDR(base) ((base) + (0x0034))

/* �Ĵ���˵������Դ���߼���LONG RUN��鷧ֵ���á�
   λ����UNION�ṹ:  SOC_TRNG_HISEC_COM_TRNG_PRE_LONG_RUN_CNT_UNION */
#define SOC_TRNG_HISEC_COM_TRNG_PRE_LONG_RUN_CNT_ADDR(base) ((base) + (0x0038))

/* �Ĵ���˵������Դ���߼���RUN��鷧ֵ���á�
   λ����UNION�ṹ:  SOC_TRNG_HISEC_COM_TRNG_PRE_RUN_CNT_UNION */
#define SOC_TRNG_HISEC_COM_TRNG_PRE_RUN_CNT_ADDR(base) ((base) + (0x003C))

/* �Ĵ���˵������Դ���߼���SERIAL��鷧ֵ���á�
   λ����UNION�ṹ:  SOC_TRNG_HISEC_COM_TRNG_PRE_SERIAL_CNT_UNION */
#define SOC_TRNG_HISEC_COM_TRNG_PRE_SERIAL_CNT_ADDR(base) ((base) + (0x0040))

/* �Ĵ���˵������Դ���߼���POKER��鷧ֵ���á�
   λ����UNION�ṹ:  SOC_TRNG_HISEC_COM_TRNG_PRE_POKER_CNT_UNION */
#define SOC_TRNG_HISEC_COM_TRNG_PRE_POKER_CNT_ADDR(base) ((base) + (0x0044))

/* �Ĵ���˵������Դ���߼���ATCR01��鷧ֵ���á�
   λ����UNION�ṹ:  SOC_TRNG_HISEC_COM_TRNG_PRE_ATCR01_CNT_UNION */
#define SOC_TRNG_HISEC_COM_TRNG_PRE_ATCR01_CNT_ADDR(base) ((base) + (0x0048))

/* �Ĵ���˵������Դ���߼���ATCR23��鷧ֵ���á�
   λ����UNION�ṹ:  SOC_TRNG_HISEC_COM_TRNG_PRE_ATCR23_CNT_UNION */
#define SOC_TRNG_HISEC_COM_TRNG_PRE_ATCR23_CNT_ADDR(base) ((base) + (0x004C))

/* �Ĵ���˵����DRBG����������߼������ʧ�ܵķ�ֵ���üĴ�����
   λ����UNION�ṹ:  SOC_TRNG_HISEC_COM_TRNG_POS_CK_CNT_UNION */
#define SOC_TRNG_HISEC_COM_TRNG_POS_CK_CNT_ADDR(base) ((base) + (0x0050))

/* �Ĵ���˵����DRBG����������߼���MONO��鷧ֵ����
   λ����UNION�ṹ:  SOC_TRNG_HISEC_COM_TRNG_POS_MONO_CNT_UNION */
#define SOC_TRNG_HISEC_COM_TRNG_POS_MONO_CNT_ADDR(base) ((base) + (0x0054))

/* �Ĵ���˵����DRBG����������߼���LONG RUN��鷧ֵ���á�
   λ����UNION�ṹ:  SOC_TRNG_HISEC_COM_TRNG_POS_LONG_RUN_CNT_UNION */
#define SOC_TRNG_HISEC_COM_TRNG_POS_LONG_RUN_CNT_ADDR(base) ((base) + (0x0058))

/* �Ĵ���˵����DRBG����������߼���RUN��鷧ֵ���á�
   λ����UNION�ṹ:  SOC_TRNG_HISEC_COM_TRNG_POS_RUN_CNT_UNION */
#define SOC_TRNG_HISEC_COM_TRNG_POS_RUN_CNT_ADDR(base) ((base) + (0x005C))

/* �Ĵ���˵����DRBG����������߼���SERIAL��鷧ֵ���á�
   λ����UNION�ṹ:  SOC_TRNG_HISEC_COM_TRNG_POS_SERIAL_CNT_UNION */
#define SOC_TRNG_HISEC_COM_TRNG_POS_SERIAL_CNT_ADDR(base) ((base) + (0x0060))

/* �Ĵ���˵����DRBG����������߼���POKER��鷧ֵ���á�
   λ����UNION�ṹ:  SOC_TRNG_HISEC_COM_TRNG_POS_POKER_CNT_UNION */
#define SOC_TRNG_HISEC_COM_TRNG_POS_POKER_CNT_ADDR(base) ((base) + (0x0064))

/* �Ĵ���˵����DRBG����������߼���ATCR01��鷧ֵ���á�
   λ����UNION�ṹ:  SOC_TRNG_HISEC_COM_TRNG_POS_ATCR01_CNT_UNION */
#define SOC_TRNG_HISEC_COM_TRNG_POS_ATCR01_CNT_ADDR(base) ((base) + (0x0068))

/* �Ĵ���˵����DRBG����������߼���ATCR23��鷧ֵ���á�
   λ����UNION�ṹ:  SOC_TRNG_HISEC_COM_TRNG_POS_ATCR23_CNT_UNION */
#define SOC_TRNG_HISEC_COM_TRNG_POS_ATCR23_CNT_ADDR(base) ((base) + (0x006C))

/* �Ĵ���˵������ԴAIS31������ʧ�ܴ�������
   λ����UNION�ṹ:  SOC_TRNG_HISEC_COM_TRNG_AIS31_FAIL_CNT_UNION */
#define SOC_TRNG_HISEC_COM_TRNG_AIS31_FAIL_CNT_ADDR(base) ((base) + (0x0070))

/* �Ĵ���˵������ԴAIS31��������������
   λ����UNION�ṹ:  SOC_TRNG_HISEC_COM_TRNG_AIS31_BLOCK_CNT_UNION */
#define SOC_TRNG_HISEC_COM_TRNG_AIS31_BLOCK_CNT_ADDR(base) ((base) + (0x0074))

/* �Ĵ���˵������ԴAIS31 POKER���������ֵ
   λ����UNION�ṹ:  SOC_TRNG_HISEC_COM_TRNG_AIS31_POKER_LOW_UNION */
#define SOC_TRNG_HISEC_COM_TRNG_AIS31_POKER_LOW_ADDR(base) ((base) + (0x0078))

/* �Ĵ���˵������ԴAIS31 POKER���������ֵ
   λ����UNION�ṹ:  SOC_TRNG_HISEC_COM_TRNG_AIS31_POKER_HIG_UNION */
#define SOC_TRNG_HISEC_COM_TRNG_AIS31_POKER_HIG_ADDR(base) ((base) + (0x007C))

/* �Ĵ���˵����
   λ����UNION�ṹ:  SOC_TRNG_UNLOCK_UNION */
#define SOC_TRNG_UNLOCK_ADDR(base)                    ((base) + (0x0080))

/* �Ĵ���˵����PRE1��ֵ
   λ����UNION�ṹ:  SOC_TRNG_CTRL_CHI_TH_PRE1_UNION */
#define SOC_TRNG_CTRL_CHI_TH_PRE1_ADDR(base)          ((base) + (0x0084))

/* �Ĵ���˵����PRE2��ֵ
   λ����UNION�ṹ:  SOC_TRNG_CTRL_CHI_TH_PRE2_UNION */
#define SOC_TRNG_CTRL_CHI_TH_PRE2_ADDR(base)          ((base) + (0x0088))

/* �Ĵ���˵����PRE3��ֵ
   λ����UNION�ṹ:  SOC_TRNG_CTRL_CHI_TH_PRE3_UNION */
#define SOC_TRNG_CTRL_CHI_TH_PRE3_ADDR(base)          ((base) + (0x008C))

/* �Ĵ���˵����ENTROPY��ֵ
   λ����UNION�ṹ:  SOC_TRNG_CTRL_CHI_TH_ENTROPY_UNION */
#define SOC_TRNG_CTRL_CHI_TH_ENTROPY_ADDR(base)       ((base) + (0x0090))

/* �Ĵ���˵����TRNG�ж�״̬����Ĵ���
   λ����UNION�ṹ:  SOC_TRNG_INT_CLR_UNION */
#define SOC_TRNG_INT_CLR_ADDR(base)                   ((base) + (0x0094))

/* �Ĵ���˵����TRNG�ж�MASK���ƼĴ���
   λ����UNION�ṹ:  SOC_TRNG_INT_MASK_UNION */
#define SOC_TRNG_INT_MASK_ADDR(base)                  ((base) + (0x0098))

/* �Ĵ���˵����TRNG����ǰ�ж�״̬�Ĵ���
   λ����UNION�ṹ:  SOC_TRNG_INT_SRC_STATUS_UNION */
#define SOC_TRNG_INT_SRC_STATUS_ADDR(base)            ((base) + (0x009C))

/* �Ĵ���˵����TRNG���κ��ж�״̬�Ĵ���
   λ����UNION�ṹ:  SOC_TRNG_INT_STATUS_UNION */
#define SOC_TRNG_INT_STATUS_ADDR(base)                ((base) + (0x00A0))

/* �Ĵ���˵����TRNG��OTPC״̬�Ĵ���
   λ����UNION�ṹ:  SOC_TRNG_OTPC_STATUS_0_UNION */
#define SOC_TRNG_OTPC_STATUS_0_ADDR(base)             ((base) + (0x00A4))

/* �Ĵ���˵����TRNG��OTPC״̬�Ĵ���
   λ����UNION�ṹ:  SOC_TRNG_OTPC_STATUS_1_UNION */
#define SOC_TRNG_OTPC_STATUS_1_ADDR(base)             ((base) + (0x00A8))

/* �Ĵ���˵����OTPC_TRNG_TRIM�Ĵ���
   λ����UNION�ṹ:  SOC_TRNG_OTPC_TRNG_TRIM_0_UNION */
#define SOC_TRNG_OTPC_TRNG_TRIM_0_ADDR(base)          ((base) + (0x00B0))

/* �Ĵ���˵����OTPC_TRNG_TRIM�Ĵ���
   λ����UNION�ṹ:  SOC_TRNG_OTPC_TRNG_TRIM_1_UNION */
#define SOC_TRNG_OTPC_TRNG_TRIM_1_ADDR(base)          ((base) + (0x00B4))

/* �Ĵ���˵����OTPC_TRNG_TRIM�Ĵ���
   λ����UNION�ṹ:  SOC_TRNG_OTPC_TRNG_TRIM_2_UNION */
#define SOC_TRNG_OTPC_TRNG_TRIM_2_ADDR(base)          ((base) + (0x00B8))

/* �Ĵ���˵����OTPC_TRNG_TRIM�Ĵ���
   λ����UNION�ṹ:  SOC_TRNG_OTPC_TRNG_TRIM_3_UNION */
#define SOC_TRNG_OTPC_TRNG_TRIM_3_ADDR(base)          ((base) + (0x00Bc))

/* �Ĵ���˵����OTPC_TRNG_TRIMֵ��crc�Ĵ���
   λ����UNION�ṹ:  SOC_TRNG_OTPC_TRNG_TRIM_CRC_UNION */
#define SOC_TRNG_OTPC_TRNG_TRIM_CRC_ADDR(base)        ((base) + (0x00c0))

/* �Ĵ���˵�������������޲����������ȡTRNG�����
   λ����UNION�ṹ:  SOC_TRNG_FIFO_RD_LINE_UNION */
#define SOC_TRNG_FIFO_RD_LINE_ADDR(base)              ((base) + (0x00c4))

/* �Ĵ���˵����DRBG��ȫ��ģʽ����ֵ
   λ����UNION�ṹ:  SOC_TRNG_DRBG_CYCLE_NUM_UNION */
#define SOC_TRNG_DRBG_CYCLE_NUM_ADDR(base)            ((base) + (0x00c8))





/*****************************************************************************
  3 ö�ٶ���
*****************************************************************************/



/*****************************************************************************
  4 ��Ϣͷ����
*****************************************************************************/


/*****************************************************************************
  5 ��Ϣ����
*****************************************************************************/



/*****************************************************************************
  6 STRUCT����
*****************************************************************************/



/*****************************************************************************
  7 UNION����
*****************************************************************************/

/****************************************************************************
                     (1/2) NEW_TRNG
 ****************************************************************************/
/*****************************************************************************
 �ṹ��    : SOC_TRNG_REG_TRNG_SEL_UNION
 �ṹ˵��  : REG_TRNG_SEL �Ĵ����ṹ���塣��ַƫ����:0x0300����ֵ:0x00000005�����:32
 �Ĵ���˵��: ����TRNGѡ��
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reg_trng_sel : 4;  /* bit[0-3] : ����TRNGѡ�񣬡�1010����ʾѡ����TRNG��������ֵ����ʾѡ����TRNG��Ĭ��ֵ��0101�� */
        unsigned int  reserved     : 28; /* bit[4-31]:  */
    } reg;
} SOC_TRNG_REG_TRNG_SEL_UNION;
#endif
#define SOC_TRNG_REG_TRNG_SEL_reg_trng_sel_START  (0)
#define SOC_TRNG_REG_TRNG_SEL_reg_trng_sel_END    (3)


/*****************************************************************************
 �ṹ��    : SOC_TRNG_OTP_TRNG_SEL_UNION
 �ṹ˵��  : OTP_TRNG_SEL �Ĵ����ṹ���塣��ַƫ����:0x0304����ֵ:0x00000005�����:32
 �Ĵ���˵��: TRNG�����ź�
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  otp_trng_sel : 4;  /* bit[0-3] : TRNG�Ŀ����źţ�ѡ������OTP���ǼĴ�������,0xa��ʾѡ��Ĵ�������,0x5��ʾotp����,����ֵ��Ч��Ŀǰ����4'ha����ʾ�ɼĴ������á� */
        unsigned int  reserved     : 28; /* bit[4-31]:  */
    } reg;
} SOC_TRNG_OTP_TRNG_SEL_UNION;
#endif
#define SOC_TRNG_OTP_TRNG_SEL_otp_trng_sel_START  (0)
#define SOC_TRNG_OTP_TRNG_SEL_otp_trng_sel_END    (3)


/*****************************************************************************
 �ṹ��    : SOC_TRNG_OTP_SW_FLAG_UNION
 �ṹ˵��  : OTP_SW_FLAG �Ĵ����ṹ���塣��ַƫ����:0x0308����ֵ:0x00000005�����:32
 �Ĵ���˵��: OTP������TRNG��ѡ��
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  otp_sw_flag : 4;  /* bit[0-3] : otp������TRNG��ѡ��,0xa��ʾѡ��trng,����ֵ��ʾѡ��TRNG; Ŀǰ�����ɼĴ�������ѡ������TRNG�� */
        unsigned int  reserved    : 28; /* bit[4-31]:  */
    } reg;
} SOC_TRNG_OTP_SW_FLAG_UNION;
#endif
#define SOC_TRNG_OTP_SW_FLAG_otp_sw_flag_START  (0)
#define SOC_TRNG_OTP_SW_FLAG_otp_sw_flag_END    (3)


/*****************************************************************************
 �ṹ��    : SOC_TRNG_FRO_EN_0_UNION
 �ṹ˵��  : FRO_EN_0 �Ĵ����ṹ���塣��ַƫ����:0x030c����ֵ:0x00000000�����:32
 �Ĵ���˵��: FRO_EN_0
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  fro_en_0 : 32; /* bit[0-31]: FRO��ʹ���ź�,1bit��Ӧ1��FRO */
    } reg;
} SOC_TRNG_FRO_EN_0_UNION;
#endif
#define SOC_TRNG_FRO_EN_0_fro_en_0_START  (0)
#define SOC_TRNG_FRO_EN_0_fro_en_0_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_TRNG_FRO_EN_1_UNION
 �ṹ˵��  : FRO_EN_1 �Ĵ����ṹ���塣��ַƫ����:0x0310����ֵ:0x00000000�����:32
 �Ĵ���˵��: FRO_EN_1
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  fro_en_1 : 18; /* bit[0-17] : FRO��ʹ���ź�,1bit��Ӧ1��FRO */
        unsigned int  reserved : 14; /* bit[18-31]:  */
    } reg;
} SOC_TRNG_FRO_EN_1_UNION;
#endif
#define SOC_TRNG_FRO_EN_1_fro_en_1_START  (0)
#define SOC_TRNG_FRO_EN_1_fro_en_1_END    (17)


/*****************************************************************************
 �ṹ��    : SOC_TRNG_GARO_EN_UNION
 �ṹ˵��  : GARO_EN �Ĵ����ṹ���塣��ַƫ����:0x0314����ֵ:0x00000000�����:32
 �Ĵ���˵��: GARO_EN
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  garo_en  : 16; /* bit[0-15] : FRO��ʹ���ź�,1bit��Ӧ1��FRO */
        unsigned int  reserved : 16; /* bit[16-31]:  */
    } reg;
} SOC_TRNG_GARO_EN_UNION;
#endif
#define SOC_TRNG_GARO_EN_garo_en_START   (0)
#define SOC_TRNG_GARO_EN_garo_en_END     (15)


/*****************************************************************************
 �ṹ��    : SOC_TRNG_MT_FRO_EN_UNION
 �ṹ˵��  : MT_FRO_EN �Ĵ����ṹ���塣��ַƫ����:0x0318����ֵ:0x0000000F�����:32
 �Ĵ���˵��: MT_FRO_EN
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  mt_fro_en : 8;  /* bit[0-7] : GARO��ʹ���ź�,1bit��Ӧ1��GARO */
        unsigned int  reserved  : 24; /* bit[8-31]:  */
    } reg;
} SOC_TRNG_MT_FRO_EN_UNION;
#endif
#define SOC_TRNG_MT_FRO_EN_mt_fro_en_START  (0)
#define SOC_TRNG_MT_FRO_EN_mt_fro_en_END    (7)


/*****************************************************************************
 �ṹ��    : SOC_TRNG_MT_GARO_EN_UNION
 �ṹ˵��  : MT_GARO_EN �Ĵ����ṹ���塣��ַƫ����:0x031c����ֵ:0x00000000�����:32
 �Ĵ���˵��: MT_GARO_EN
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  mt_garo_en : 4;  /* bit[0-3] : MTFRO��ʹ���ź�,1bit��Ӧ1��MTFRO */
        unsigned int  reserved   : 28; /* bit[4-31]:  */
    } reg;
} SOC_TRNG_MT_GARO_EN_UNION;
#endif
#define SOC_TRNG_MT_GARO_EN_mt_garo_en_START  (0)
#define SOC_TRNG_MT_GARO_EN_mt_garo_en_END    (3)


/*****************************************************************************
 �ṹ��    : SOC_TRNG_ENTROPY_SOURCE_ST_UNION
 �ṹ˵��  : ENTROPY_SOURCE_ST �Ĵ����ṹ���塣��ַƫ����:0x320����ֵ:0x00000000�����:32
 �Ĵ���˵��: ENTROPY_SOURCE_ST
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  src_afifo_empty : 4;  /* bit[0-3] : 4·���Դ���첽fifoʵʱ�Ŀ�״̬,�ߵ�ƽ��Ч. */
        unsigned int  reserved        : 28; /* bit[4-31]:  */
    } reg;
} SOC_TRNG_ENTROPY_SOURCE_ST_UNION;
#endif
#define SOC_TRNG_ENTROPY_SOURCE_ST_src_afifo_empty_START  (0)
#define SOC_TRNG_ENTROPY_SOURCE_ST_src_afifo_empty_END    (3)


/*****************************************************************************
 �ṹ��    : SOC_TRNG_SAMPLE_CLK_CFG_UNION
 �ṹ˵��  : SAMPLE_CLK_CFG �Ĵ����ṹ���塣��ַƫ����:0x324����ֵ:0x0000001F�����:32
 �Ĵ���˵��: sample_clock_cfg
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sample_clk_cfg : 14; /* bit[0-13] : 
                                                          13:8 ro����Ƶ���ã�
                                                          7:6 Ԥ��;
                                                          5: ��������ʹ��;
                                                          4��mt_garo�Ĳ���ʱ��ѡ�� 1Ϊѡclk_sys
                                                          3��mt_fro�Ĳ���ʱ��ѡ�� 1Ϊѡclk_sys
                                                          2:garo�Ĳ���ʱ��ѡ�� 1Ϊѡclk_sys
                                                          1:fro�Ĳ���ʱ��ѡ�� 1Ϊѡclk_sys
                                                          0:��Ƶʱ��ѡ��; 1Ϊѡclk_sys */
        unsigned int  reserved       : 18; /* bit[14-31]:  */
    } reg;
} SOC_TRNG_SAMPLE_CLK_CFG_UNION;
#endif
#define SOC_TRNG_SAMPLE_CLK_CFG_sample_clk_cfg_START  (0)
#define SOC_TRNG_SAMPLE_CLK_CFG_sample_clk_cfg_END    (13)


/*****************************************************************************
 �ṹ��    : SOC_TRNG_INT_CHI_ONLINE_CLR_UNION
 �ṹ˵��  : INT_CHI_ONLINE_CLR �Ĵ����ṹ���塣��ַƫ����:0x328����ֵ:0x00000000�����:32
 �Ĵ���˵��: INT_CHI_ONLINE_CLR
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  int_chi_online_clr : 1;  /* bit[0-0] : chi_test����״̬�ź�,��������Ч */
        unsigned int  reserved           : 31; /* bit[1-31]:  */
    } reg;
} SOC_TRNG_INT_CHI_ONLINE_CLR_UNION;
#endif
#define SOC_TRNG_INT_CHI_ONLINE_CLR_int_chi_online_clr_START  (0)
#define SOC_TRNG_INT_CHI_ONLINE_CLR_int_chi_online_clr_END    (0)


/*****************************************************************************
 �ṹ��    : SOC_TRNG_RAW_BYPASS_EN_UNION
 �ṹ˵��  : RAW_BYPASS_EN �Ĵ����ṹ���塣��ַƫ����:0x32c����ֵ:0x00000AAA�����:32
 �Ĵ���˵��: RAW_BYPASS_EN
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  bypass_en_poker : 4;  /* bit[0-3]  : poker_test����·ʹ��,0x5��Ч,����ֵ��Ч;ֻ����0x5��0xa */
        unsigned int  bypass_en_chi   : 4;  /* bit[4-7]  : chi_test����·ʹ��,0x5��Ч,����ֵ��Ч;ֻ����0x5��0xa */
        unsigned int  bypass_en_lrun  : 4;  /* bit[8-11] : long_run_test����·ʹ��,0x5��Ч,����ֵ��Ч;ֻ����0x5��0xa */
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
 �ṹ��    : SOC_TRNG_THRE_CHI_PRE1_UNION
 �ṹ˵��  : THRE_CHI_PRE1 �Ĵ����ṹ���塣��ַƫ����:0x0330����ֵ:0x000001C2�����:32
 �Ĵ���˵��: THRE_CHI_PRE1
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  thre_pre1 : 9;  /* bit[0-8] : Chi_test����ֵ1 */
        unsigned int  reserved  : 23; /* bit[9-31]:  */
    } reg;
} SOC_TRNG_THRE_CHI_PRE1_UNION;
#endif
#define SOC_TRNG_THRE_CHI_PRE1_thre_pre1_START  (0)
#define SOC_TRNG_THRE_CHI_PRE1_thre_pre1_END    (8)


/*****************************************************************************
 �ṹ��    : SOC_TRNG_THRE_CHI_PRE2_UNION
 �ṹ˵��  : THRE_CHI_PRE2 �Ĵ����ṹ���塣��ַƫ����:0x334����ֵ:0x00000000�����:32
 �Ĵ���˵��: THRE_CHI_PRE2
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  thre_pre2 : 9;  /* bit[0-8] : Chi_test����ֵ2 */
        unsigned int  reserved  : 23; /* bit[9-31]:  */
    } reg;
} SOC_TRNG_THRE_CHI_PRE2_UNION;
#endif
#define SOC_TRNG_THRE_CHI_PRE2_thre_pre2_START  (0)
#define SOC_TRNG_THRE_CHI_PRE2_thre_pre2_END    (8)


/*****************************************************************************
 �ṹ��    : SOC_TRNG_THRE_CHI_PRE3_UNION
 �ṹ˵��  : THRE_CHI_PRE3 �Ĵ����ṹ���塣��ַƫ����:0x338����ֵ:0x000001C2�����:32
 �Ĵ���˵��: THRE_CHI_PRE3
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  thre_pre3 : 9;  /* bit[0-8] : Chi_test����ֵ3 */
        unsigned int  reserved  : 23; /* bit[9-31]:  */
    } reg;
} SOC_TRNG_THRE_CHI_PRE3_UNION;
#endif
#define SOC_TRNG_THRE_CHI_PRE3_thre_pre3_START  (0)
#define SOC_TRNG_THRE_CHI_PRE3_thre_pre3_END    (8)


/*****************************************************************************
 �ṹ��    : SOC_TRNG_THRE_CHI_ENTROPY_UNION
 �ṹ˵��  : THRE_CHI_ENTROPY �Ĵ����ṹ���塣��ַƫ����:0x33c����ֵ:0x000001C2�����:32
 �Ĵ���˵��: THRE_CHI_ENTROPY
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  thre_entropy : 9;  /* bit[0-8] : Chi_test����ֵ4 */
        unsigned int  reserved     : 23; /* bit[9-31]:  */
    } reg;
} SOC_TRNG_THRE_CHI_ENTROPY_UNION;
#endif
#define SOC_TRNG_THRE_CHI_ENTROPY_thre_entropy_START  (0)
#define SOC_TRNG_THRE_CHI_ENTROPY_thre_entropy_END    (8)


/*****************************************************************************
 �ṹ��    : SOC_TRNG_THRE_LONG_RUN_UNION
 �ṹ˵��  : THRE_LONG_RUN �Ĵ����ṹ���塣��ַƫ����:0x340����ֵ:0x00000022�����:32
 �Ĵ���˵��: THRE_LONG_RUN
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  thre_long_run : 7;  /* bit[0-6] : long_run_test����ֵ */
        unsigned int  reserved      : 25; /* bit[7-31]:  */
    } reg;
} SOC_TRNG_THRE_LONG_RUN_UNION;
#endif
#define SOC_TRNG_THRE_LONG_RUN_thre_long_run_START  (0)
#define SOC_TRNG_THRE_LONG_RUN_thre_long_run_END    (6)


/*****************************************************************************
 �ṹ��    : SOC_TRNG_THRE_POKER_UNION
 �ṹ˵��  : THRE_POKER �Ĵ����ṹ���塣��ַƫ����:0x344����ֵ:0x00000FFF�����:32
 �Ĵ���˵��: THRE_POKER
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  poker_ck_hig : 16; /* bit[0-15] : poker_test����ֵ */
        unsigned int  reserved     : 16; /* bit[16-31]:  */
    } reg;
} SOC_TRNG_THRE_POKER_UNION;
#endif
#define SOC_TRNG_THRE_POKER_poker_ck_hig_START  (0)
#define SOC_TRNG_THRE_POKER_poker_ck_hig_END    (15)


/*****************************************************************************
 �ṹ��    : SOC_TRNG_TEST_WIN_RAW_TEST_UNION
 �ṹ˵��  : TEST_WIN_RAW_TEST �Ĵ����ṹ���塣��ַƫ����:0x348����ֵ:0x00666666�����:32
 �Ĵ���˵��: TEST_WIN_RAW_TEST
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  test_win_poker   : 8;  /* bit[0-7]  : poker_test��failͳ�ƴ��� */
        unsigned int  test_win_chi     : 8;  /* bit[8-15] : chi_test��failͳ�ƴ��� */
        unsigned int  test_win_longrun : 8;  /* bit[16-23]: long_run_test��failͳ�ƴ��� */
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
 �ṹ��    : SOC_TRNG_THRE_FAIL_NUM_UNION
 �ṹ˵��  : THRE_FAIL_NUM �Ĵ����ṹ���塣��ַƫ����:0x34c����ֵ:0x00666666�����:32
 �Ĵ���˵��: THRE_FAIL_NUM
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  thre_fail_num_poker   : 8;  /* bit[0-7]  : poker_test��failͳ�ƴ����������fail����,,���������޻ᴥ���ж� */
        unsigned int  thre_fail_num_chi     : 8;  /* bit[8-15] : chi_test��failͳ�ƴ����������fail����,,���������޻ᴥ���ж� */
        unsigned int  thre_fail_num_longrun : 8;  /* bit[16-23]: long_run_test��failͳ�ƴ����������fail����,���������޻ᴥ���ж� */
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
 �ṹ��    : SOC_TRNG_RAW_TEST_CLEAR_UNION
 �ṹ˵��  : RAW_TEST_CLEAR �Ĵ����ṹ���塣��ַƫ����:0x350����ֵ:0x00000000�����:32
 �Ĵ���˵��: RAW_TEST_CLEAR
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  clear_poker   : 1;  /* bit[0-0] : long_run_test��failͳ�ƽ������ */
        unsigned int  clear_chi     : 1;  /* bit[1-1] : long_run_test��failͳ�ƽ������ */
        unsigned int  clear_longrun : 1;  /* bit[2-2] : long_run_test��failͳ�ƽ������ */
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
 �ṹ��    : SOC_TRNG_RAW_FAIL_CNT_UNION
 �ṹ˵��  : RAW_FAIL_CNT �Ĵ����ṹ���塣��ַƫ����:0x354����ֵ:0x00000000�����:32
 �Ĵ���˵��: RAW_FAIL_CNT
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  fail_num_poker   : 8;  /* bit[0-7]  : ʵʱ��long_run_test��fail����,����ֵ����test_win_**,��ᴥ���ж� */
        unsigned int  fail_num_chi     : 8;  /* bit[8-15] : ʵʱ��long_run_test��fail����,����ֵ����test_win_**,��ᴥ���ж� */
        unsigned int  fail_num_longrun : 8;  /* bit[16-23]: ʵʱ��long_run_test��fail����,����ֵ����test_win_**,��ᴥ���ж� */
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
 �ṹ��    : SOC_TRNG_RAW_STATE_UNION
 �ṹ˵��  : RAW_STATE �Ĵ����ṹ���塣��ַƫ����:0x358����ֵ:0x00000000�����:32
 �Ĵ���˵��: RAW_STATE
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  raw_state : 32; /* bit[0-31]: raw_test��״̬ */
    } reg;
} SOC_TRNG_RAW_STATE_UNION;
#endif
#define SOC_TRNG_RAW_STATE_raw_state_START  (0)
#define SOC_TRNG_RAW_STATE_raw_state_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_TRNG_XOR_COMP_CFG_UNION
 �ṹ˵��  : XOR_COMP_CFG �Ĵ����ṹ���塣��ַƫ����:0x35c����ֵ:0x00000000�����:32
 �Ĵ���˵��: XOR_COMP_CFG
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  xor_comp_rate : 5;  /* bit[0-4] : xor_compressing��ѹ����,ѹ����Ϊ�üĴ���ֵ+1; */
        unsigned int  reserved      : 27; /* bit[5-31]:  */
    } reg;
} SOC_TRNG_XOR_COMP_CFG_UNION;
#endif
#define SOC_TRNG_XOR_COMP_CFG_xor_comp_rate_START  (0)
#define SOC_TRNG_XOR_COMP_CFG_xor_comp_rate_END    (4)


/*****************************************************************************
 �ṹ��    : SOC_TRNG_XOR_CHAIN_CFG_UNION
 �ṹ˵��  : XOR_CHAIN_CFG �Ĵ����ṹ���塣��ַƫ����:0x360����ֵ:0x00000005�����:32
 �Ĵ���˵��: XOR_CHAIN_CFG
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  xor_chain_byp : 4;  /* bit[0-3] : xor_chain����·ʹ���ź�,0x5��Ч,����ֵ��Ч; */
        unsigned int  reserved      : 28; /* bit[4-31]:  */
    } reg;
} SOC_TRNG_XOR_CHAIN_CFG_UNION;
#endif
#define SOC_TRNG_XOR_CHAIN_CFG_xor_chain_byp_START  (0)
#define SOC_TRNG_XOR_CHAIN_CFG_xor_chain_byp_END    (3)


/*****************************************************************************
 �ṹ��    : SOC_TRNG_POST_PROCESS_UNION
 �ṹ˵��  : POST_PROCESS �Ĵ����ṹ���塣��ַƫ����:0x364����ֵ:0x0000000A�����:32
 �Ĵ���˵��: POST_PROCESS
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  byp_en_post_proc : 4;  /* bit[0-3] : post_processing����·ʹ��,0xa��Ч,����ֵ��Ч; */
        unsigned int  reserved         : 28; /* bit[4-31]:  */
    } reg;
} SOC_TRNG_POST_PROCESS_UNION;
#endif
#define SOC_TRNG_POST_PROCESS_byp_en_post_proc_START  (0)
#define SOC_TRNG_POST_PROCESS_byp_en_post_proc_END    (3)


/*****************************************************************************
 �ṹ��    : SOC_TRNG_RESEED_CNT_LIMIT_UNION
 �ṹ˵��  : RESEED_CNT_LIMIT �Ĵ����ṹ���塣��ַƫ����:0x368����ֵ:0x00000002�����:32
 �Ĵ���˵��: RESEED_CNT_LIMIT
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reseed_cnt_limit : 32; /* bit[0-31]: HASH_DRBGһ��reseed���������������������,����ֵΪ1ʱ,Ϊȫ��ģʽ; */
    } reg;
} SOC_TRNG_RESEED_CNT_LIMIT_UNION;
#endif
#define SOC_TRNG_RESEED_CNT_LIMIT_reseed_cnt_limit_START  (0)
#define SOC_TRNG_RESEED_CNT_LIMIT_reseed_cnt_limit_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_TRNG_POST_TEST_BYP_UNION
 �ṹ˵��  : POST_TEST_BYP �Ĵ����ṹ���塣��ַƫ����:0x36c����ֵ:0x00000AAA�����:32
 �Ĵ���˵��: POST_TEST_BYP
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  byp_en_poker   : 4;  /* bit[0-3]  : ����poker������·ʹ��;0x5��Ч,����ֵ��Ч; */
        unsigned int  byp_en_256same : 4;  /* bit[4-7]  : ��������256bit��ͬ�ļ�����·ʹ��;0x5��Ч,����ֵ��Ч; */
        unsigned int  byp_en_32same  : 4;  /* bit[8-11] : ��������32bit��ͬ�ļ�����·ʹ��,0x5��Ч,����ֵ��Ч; */
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
 �ṹ��    : SOC_TRNG_POST_TEST_ALARM_MSK_UNION
 �ṹ˵��  : POST_TEST_ALARM_MSK �Ĵ����ṹ���塣��ַƫ����:0x370����ֵ:0x00AAAAAA�����:32
 �Ĵ���˵��: POST_TEST_ALARM_MSK
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  msk_alarm_poker    : 4;  /* bit[0-3]  : ��������poker���fail����,0x5��Ч,����ֵ��Ч; */
        unsigned int  msk_alarm_256same  : 4;  /* bit[4-7]  : ��������256bit��ͬ�ļ��fail����,0x5��Ч,����ֵ��Ч; */
        unsigned int  msk_alarm_32same   : 4;  /* bit[8-11] : ��������32bit��ͬ�ļ��fail����,0x5��Ч,����ֵ��Ч; */
        unsigned int  msk_alarm_prepoker : 4;  /* bit[12-15]: ��������poker���fail����,0x5��Ч,����ֵ��Ч; */
        unsigned int  msk_alarm_chi      : 4;  /* bit[16-19]: ��������256bit��ͬ�ļ��fail����,0x5��Ч,����ֵ��Ч; */
        unsigned int  msk_alarm_longrun  : 4;  /* bit[20-23]: ��������32bit��ͬ�ļ��fail����,0x5��Ч,����ֵ��Ч; */
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
 �ṹ��    : SOC_TRNG_DISTRIBUTION_UNION
 �ṹ˵��  : DISTRIBUTION �Ĵ����ṹ���塣��ַƫ����:0x378����ֵ:0x0000000A�����:32
 �Ĵ���˵��: DISTRIBUTION
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  full_dist_mode : 4;  /* bit[0-3] : distribution��ȫ�ַ�ģʽʹ��, */
        unsigned int  reserved       : 28; /* bit[4-31]:  */
    } reg;
} SOC_TRNG_DISTRIBUTION_UNION;
#endif
#define SOC_TRNG_DISTRIBUTION_full_dist_mode_START  (0)
#define SOC_TRNG_DISTRIBUTION_full_dist_mode_END    (3)


/*****************************************************************************
 �ṹ��    : SOC_TRNG_ALARM_STATE_UNION
 �ṹ˵��  : ALARM_STATE �Ĵ����ṹ���塣��ַƫ����:0x37c����ֵ:0x00000000�����:32
 �Ĵ���˵��: ALARM_STATE
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  alarm_pos_poker  : 1;  /* bit[0-0] : post_poker_test��faile״̬,����Ч */
        unsigned int  alarm_same32     : 1;  /* bit[1-1] : ����32bit��ͬ��faile״̬,����Ч */
        unsigned int  alarm_same256    : 1;  /* bit[2-2] : ����256bit��ͬ��faile״̬,����Ч */
        unsigned int  alarm_pre_poker  : 1;  /* bit[3-3] : ǰpoker_test��faile״̬,����Ч */
        unsigned int  alarm_chi_test   : 1;  /* bit[4-4] : chi_test��faile״̬,����Ч */
        unsigned int  alarm_longrun    : 1;  /* bit[5-5] : long_run_test��faile״̬,����Ч */
        unsigned int  alarm_otpc_check : 1;  /* bit[6-6] : otpc�źŷǷ�alarm,����Ч */
        unsigned int  signal_alarm     : 1;  /* bit[7-7] : reg_file�źű���alarm,����Ч */
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
 �ṹ��    : SOC_TRNG_THRE_POST_POKER_UNION
 �ṹ˵��  : THRE_POST_POKER �Ĵ����ṹ���塣��ַƫ����:0x384����ֵ:0x000001FE�����:32
 �Ĵ���˵��: THRE_POST_POKER
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  post_poker_ck_hig : 16; /* bit[0-15] : post_poker����ֵ */
        unsigned int  reserved          : 16; /* bit[16-31]:  */
    } reg;
} SOC_TRNG_THRE_POST_POKER_UNION;
#endif
#define SOC_TRNG_THRE_POST_POKER_post_poker_ck_hig_START  (0)
#define SOC_TRNG_THRE_POST_POKER_post_poker_ck_hig_END    (15)


/*****************************************************************************
 �ṹ��    : SOC_TRNG_POST_TEST_WIN_RAW_TEST_UNION
 �ṹ˵��  : POST_TEST_WIN_RAW_TEST �Ĵ����ṹ���塣��ַƫ����:0x388����ֵ:0x00666666�����:32
 �Ĵ���˵��: POST_TEST_WIN_RAW_TEST
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  test_win_post_poker : 8;  /* bit[0-7]  : post_poker_test��failͳ�ƴ��� */
        unsigned int  test_win_same256    : 8;  /* bit[8-15] : same256��failͳ�ƴ��� */
        unsigned int  test_win_same32     : 8;  /* bit[16-23]: same32��failͳ�ƴ��� */
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
 �ṹ��    : SOC_TRNG_THRE_POST_FAIL_NUM_UNION
 �ṹ˵��  : THRE_POST_FAIL_NUM �Ĵ����ṹ���塣��ַƫ����:0x38c����ֵ:0x00666666�����:32
 �Ĵ���˵��: POST_TEST_WIN_RAW_TEST
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  thre_fail_num_post_poker : 8;  /* bit[0-7]  : post_poker_test��failͳ�ƴ����������fail����,,���������޻ᴥ���ж� */
        unsigned int  thre_fail_num_same256    : 8;  /* bit[8-15] : same256��failͳ�ƴ����������fail����,,���������޻ᴥ���ж� */
        unsigned int  thre_fail_num_same32     : 8;  /* bit[16-23]: same32��failͳ�ƴ����������fail����,���������޻ᴥ���ж� */
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
 �ṹ��    : SOC_TRNG_POST_TEST_CLEAR_UNION
 �ṹ˵��  : POST_TEST_CLEAR �Ĵ����ṹ���塣��ַƫ����:0x390����ֵ:0x00000000�����:32
 �Ĵ���˵��: POST_TEST_WIN_RAW_TEST
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  clear_post_poker : 1;  /* bit[0-0] : post_poker��fail״̬���ź�,����Ч */
        unsigned int  clear_same256    : 1;  /* bit[1-1] : same256��fail״̬���ź�,����Ч */
        unsigned int  clear_same32     : 1;  /* bit[2-2] : same32��fail״̬���ź�,����Ч */
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
 �ṹ��    : SOC_TRNG_POST_FAIL_CNT_UNION
 �ṹ˵��  : POST_FAIL_CNT �Ĵ����ṹ���塣��ַƫ����:0x394����ֵ:0x00000000�����:32
 �Ĵ���˵��: POST_TEST_WIN_RAW_TEST
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  fail_num_post_poker : 8;  /* bit[0-7]  : post_poker��test_win�е�ʵʱfail���� */
        unsigned int  fail_num_same256    : 8;  /* bit[8-15] : same256��test_win�е�ʵʱfail���� */
        unsigned int  fail_num_same32     : 8;  /* bit[16-23]: same32��test_win�е�ʵʱfail���� */
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
 �ṹ��    : SOC_TRNG_WAIT_FOR_USE_UNION
 �ṹ˵��  : WAIT_FOR_USE �Ĵ����ṹ���塣��ַƫ����:0x39c����ֵ:0x00000000�����:32
 �Ĵ���˵��: TRNG_DATA_0
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
 �ṹ��    : SOC_TRNG_RNG_TIME_OUT_UNION
 �ṹ˵��  : RNG_TIME_OUT �Ĵ����ṹ���塣��ַƫ����:0x3a0����ֵ:0xFFFFFF00�����:32
 �Ĵ���˵��: TIME_OUT_REGS
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  time_out_alarm     : 1;  /* bit[0-0] : ��ʱ�澯,����Ч */
        unsigned int  time_out_alarm_msk : 1;  /* bit[1-1] : ��ʱ�澯����,����Ч */
        unsigned int  time_out_clear     : 1;  /* bit[2-2] : ��ʱ�澯���,����Ч */
        unsigned int  reserved           : 5;  /* bit[3-7] :  */
        unsigned int  time_out_limit     : 24; /* bit[8-31]: ��ʱ��ֵ */
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
 �ṹ��    : SOC_TRNG_CHI_TEST_STATE_UNION
 �ṹ˵��  : CHI_TEST_STATE �Ĵ����ṹ���塣��ַƫ����:0x3a4����ֵ:0x154�����:32
 �Ĵ���˵��: CHI_TEST_STATE
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  chi_fai        : 1;  /* bit[0-0] : chi_test��״̬ */
        unsigned int  int_chi_online : 4;  /* bit[1-4] : chi_test��״̬ */
        unsigned int  alarm_chi_tot  : 4;  /* bit[5-8] : chi_test��״̬ */
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
 �ṹ��    : SOC_TRNG_CLK_EN_UNION
 �ṹ˵��  : CLK_EN �Ĵ����ṹ���塣��ַƫ����:0x3a8����ֵ:0x0000000A�����:32
 �Ĵ���˵��: TRNG_CLK_EN
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  trng_clk_en : 4;  /* bit[0-3] : ��TRNG�����ʱ��ʹ��,����Ч.���ź� */
        unsigned int  reserved    : 28; /* bit[4-31]:  */
    } reg;
} SOC_TRNG_CLK_EN_UNION;
#endif
#define SOC_TRNG_CLK_EN_trng_clk_en_START  (0)
#define SOC_TRNG_CLK_EN_trng_clk_en_END    (3)


/*****************************************************************************
 �ṹ��    : SOC_TRNG_DONE_UNION
 �ṹ˵��  : DONE �Ĵ����ṹ���塣��ַƫ����:0x3ac����ֵ:0x00000005�����:32
 �Ĵ���˵��: TRNG_DONE
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  trng_done : 4;  /* bit[0-3] : trng��ʼ����ɱ�ʾ,0x5��Ч,����ֵ��Ч */
        unsigned int  reserved  : 28; /* bit[4-31]:  */
    } reg;
} SOC_TRNG_DONE_UNION;
#endif
#define SOC_TRNG_DONE_trng_done_START  (0)
#define SOC_TRNG_DONE_trng_done_END    (3)


/*****************************************************************************
 �ṹ��    : SOC_TRNG_READY_UNION
 �ṹ˵��  : READY �Ĵ����ṹ���塣��ַƫ����:0x3b0����ֵ:0x00000005�����:32
 �Ĵ���˵��: TRNG_READY
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  trng_ready : 4;  /* bit[0-3] : trng ready״̬,0x5��Ч,����ֵ��Ч */
        unsigned int  reserved   : 28; /* bit[4-31]:  */
    } reg;
} SOC_TRNG_READY_UNION;
#endif
#define SOC_TRNG_READY_trng_ready_START  (0)
#define SOC_TRNG_READY_trng_ready_END    (3)


/*****************************************************************************
 �ṹ��    : SOC_TRNG_READY_THRE_UNION
 �ṹ˵��  : READY_THRE �Ĵ����ṹ���塣��ַƫ����:0x3b4����ֵ:0x00000003�����:32
 �Ĵ���˵��: TRNG_READY_THRE
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  trng_ready_thre : 6;  /* bit[0-5] : trng_ready����ֵ,��ֵ����TRNG_FIFO��cnt�Ƚϻ��,��trng_rady_thre����TRNG_FIFO cntʱ,trngΪready��Ч */
        unsigned int  reserved        : 26; /* bit[6-31]:  */
    } reg;
} SOC_TRNG_READY_THRE_UNION;
#endif
#define SOC_TRNG_READY_THRE_trng_ready_thre_START  (0)
#define SOC_TRNG_READY_THRE_trng_ready_thre_END    (5)


/*****************************************************************************
 �ṹ��    : SOC_TRNG_FIFO_DATA_UNION
 �ṹ˵��  : FIFO_DATA �Ĵ����ṹ���塣��ַƫ����:0x3b8����ֵ:0x00000000�����:32
 �Ĵ���˵��: V
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  trng_fifo_data : 32; /* bit[0-31]: trng�����,�������ȡ */
    } reg;
} SOC_TRNG_FIFO_DATA_UNION;
#endif
#define SOC_TRNG_FIFO_DATA_trng_fifo_data_START  (0)
#define SOC_TRNG_FIFO_DATA_trng_fifo_data_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_TRNG_PRT_LOCK_UNION
 �ṹ˵��  : PRT_LOCK �Ĵ����ṹ���塣��ַƫ����:0x3bc����ֵ:0x0000000A�����:32
 �Ĵ���˵��: PRT_LOCK
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  lock_reg : 4;  /* bit[0-3] : �Ĵ�����,д����ֵ��Ч,��Ч��,����RW_LOCK���ԵļĴ������ɱ���д. */
        unsigned int  reserved : 28; /* bit[4-31]:  */
    } reg;
} SOC_TRNG_PRT_LOCK_UNION;
#endif
#define SOC_TRNG_PRT_LOCK_lock_reg_START  (0)
#define SOC_TRNG_PRT_LOCK_lock_reg_END    (3)


/*****************************************************************************
 �ṹ��    : SOC_TRNG_ENTROPY_MERGE_UNION
 �ṹ˵��  : ENTROPY_MERGE �Ĵ����ṹ���塣��ַƫ����:0x3c0����ֵ:0x00000000�����:32
 �Ĵ���˵��: ENTROPY_MERGE
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  src_merge_cfg : 4;  /* bit[0-3] : ������TRNG�����Դ����ϲ�����TRNG����Դ���(MUX�����λ��)
                                                        0001: MUX���follow��TRNG��data��vld;
                                                        0010: MUX���follow��TRNG��data��vld;
                                                        0100: MUX�����dataΪ��TRNG��data�����Դ��data;vld follow��TRNG��vld;
                                                        1000:MUX�����dataΪ��TRNG��data�����Դ��data;vld follow��TRNG��vld;
                                                        ����ֵ�ȼ���"0001";
                                                        ע��:��otpc_trng_pre_proc_enΪ0x5ʱ,"0010"��"1000"������������Ч! */
        unsigned int  reserved      : 28; /* bit[4-31]:  */
    } reg;
} SOC_TRNG_ENTROPY_MERGE_UNION;
#endif
#define SOC_TRNG_ENTROPY_MERGE_src_merge_cfg_START  (0)
#define SOC_TRNG_ENTROPY_MERGE_src_merge_cfg_END    (3)


/*****************************************************************************
 �ṹ��    : SOC_TRNG_KNOWN_ANSWER_TEST_UNION
 �ṹ˵��  : KNOWN_ANSWER_TEST �Ĵ����ṹ���塣��ַƫ����:0x3c4����ֵ:0x00000002�����:32
 �Ĵ���˵��: KNOWN_ANSWER_TEST
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  answer_test_fail : 1;  /* bit[0-0] : known-answer test ʧ��ָʾ�ź�,����Ч;
                                                           ϵͳ�⸴λʱ�Զ�����known-answer test,�����ϵͳ��ʼ��ʱ���üĴ���Ĭ�Ϻͷ�ֵΪ"1" */
        unsigned int  answer_test_done : 1;  /* bit[1-1] : known-answer test���ָʾ�ź�,����Ч;
                                                           ϵͳ�⸴λʱ�Զ�����known-answer test,�����ϵͳ��ʼ��ʱ���üĴ���Ĭ�Ϻͷ�ֵΪ"1" */
        unsigned int  answer_test_en   : 1;  /* bit[2-2] : ���ô���known-answer test,����Ч */
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
 �ṹ��    : SOC_TRNG_SIGNAL_ALARM_UNION
 �ṹ˵��  : SIGNAL_ALARM �Ĵ����ṹ���塣��ַƫ����:0x3c8����ֵ:0x00000A0A�����:32
 �Ĵ���˵��: �źű������쳣״̬
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  all_signal_alarm     : 4;  /* bit[0-3]  : �źű���alarm��ֻ���ź�,0xa��ʾ��alarm,����ֵ��ʾ��alarm */
        unsigned int  all_signal_alarm_clr : 1;  /* bit[4-4]  : �źű���alarm��ƽ�źŵ�����ź�,д"1"��Ч */
        unsigned int  reserved_0           : 3;  /* bit[5-7]  :  */
        unsigned int  msk_all_signal_alarm : 4;  /* bit[8-11] : �źű�����alarm�����ź�,0x5��ʾ������,0xa��ʾ����,����ֵΪ�Ƿ�ֵ,�ᴥ���źű���alarm */
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
 �ṹ��    : SOC_TRNG_HISEC_COM_TRNG_CTRL_UNION
 �ṹ˵��  : HISEC_COM_TRNG_CTRL �Ĵ����ṹ���塣��ַƫ����:0x0000����ֵ:0x0E483485�����:32
 �Ĵ���˵��: TRNG���ƼĴ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  drbg_enable     : 1;  /* bit[0]    : DRBG����ʹ�ܡ�
                                                           0����ʹ�ܣ�
                                                           1��ʹ�ܡ� */
        unsigned int  fliter_enable   : 1;  /* bit[1]    : �����ǰ����ʹ�ܣ�ʹ�ô˹��ܺ�����������ٶȽ���4����
                                                           0����ʹ�ܣ�
                                                           1��ʹ�ܡ� */
        unsigned int  drop_enable     : 1;  /* bit[2]    : �������ȸ�������ʹ�ܣ�ʹ�ô˹��ܺ�����������ٶȽ���3����
                                                           0����ʹ�ܣ�
                                                           1��ʹ�ܡ� */
        unsigned int  rng_sel         : 1;  /* bit[3]    : ����ģʽ����ԴTRNG���ѡ��
                                                           0��ѡ���������Դ������������
                                                           1��ѡ��ĳһ�������Դ��������� */
        unsigned int  ro_sel          : 4;  /* bit[4-7]  : ����ģʽ��GARO����RO�ڲ����Դѡ��rng_selΪ1ʱ�����ã�
                                                           0000����·0
                                                           0001����·1
                                                           0010����·2
                                                           0011����·3
                                                           0100����·4
                                                           0101����·5
                                                           0110����·6
                                                           0111����·7
                                                           other:8��·��� */
        unsigned int  osc_sel         : 3;  /* bit[8-10] : ����ģʽ��ģ�����Դѡ��rng_selΪ1ʱ�����á�
                                                           000��ʹ�����Դ0��
                                                           001��ʹ�����Դ1��
                                                           010��ʹ�����Դ2��
                                                           011��ʹ�����Դ3;
                                                           other:4·��� */
        unsigned int  testpoint_en    : 1;  /* bit[11]   : Testpointʹ���źţ�
                                                           0�����򿪲���ʹ�ܣ�Testpoint���0��
                                                           1���򿪲���ʹ�ܣ�Testpoint���Դ�����ݡ� */
        unsigned int  pre_test_enable : 1;  /* bit[12]   : PRE_SELF_TEST��Դ����������Դ֮�������Լ�ʹ�ܡ�
                                                           0����ʹ�ܣ�
                                                           1��ʹ�ܡ� */
        unsigned int  pos_test_enable : 1;  /* bit[13]   : POS_SELF_TEST�������DRBG֮�������Լ�ʹ�ܡ�
                                                           0����ʹ�ܣ�
                                                           1��ʹ�ܡ� */
        unsigned int  rng_src_sel     : 2;  /* bit[14-15]: ����Դ��ѡ��rng_selΪ1ʱ�����ã�
                                                           00������Դ���
                                                           01��������Դ��
                                                           10��GARO����Դ��
                                                           11��ģ��Դ�� */
        unsigned int  ro_hs_sel       : 3;  /* bit[16-18]: ����ģʽ�£�������Դѡ�񣬵�rng_selΪ1ʱ�����ã�
                                                           000:4·��������
                                                           100:��0·��
                                                           101����1·��
                                                           110����2·��
                                                           111����3·��
                                                           ������4·�������� */
        unsigned int  digsrc_compen   : 1;  /* bit[19]   : �������Դѹ��ʹ�ܣ�
                                                           1��������
                                                           0���رա� */
        unsigned int  ro_hs_cfg       : 8;  /* bit[20-27]: ������Դ���ã���src_cfg_enΪ1ʱ�����ã�
                                                           [27:26]:��3·���ã�
                                                           [25:24]:��2·���ã�
                                                           [23:22]:��1·���ã�
                                                           [21:20]:��0·���á� */
        unsigned int  src_cfg_en      : 1;  /* bit[28]   : ���ԴԴ����ʹ�ܣ�
                                                           0���رգ�
                                                           1�������� */
        unsigned int  full_mode_en    : 1;  /* bit[29]   : ȫ��ģʽʹ�ܣ�
                                                           0����ʹ�ܣ�
                                                           1��ʹ�ܡ� */
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
 �ṹ��    : SOC_TRNG_HISEC_COM_TRNG_FIFO_DATA_UNION
 �ṹ˵��  : HISEC_COM_TRNG_FIFO_DATA �Ĵ����ṹ���塣��ַƫ����:0x0004����ֵ:0x00000000�����:32
 �Ĵ���˵��: TRNG��FIFO���ݼĴ���
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
 �ṹ��    : SOC_TRNG_HISEC_COM_TRNG_DATA_ST_UNION
 �ṹ˵��  : HISEC_COM_TRNG_DATA_ST �Ĵ����ṹ���塣��ַƫ����:0x0008����ֵ:0x00000000�����:32
 �Ĵ���˵��: TRNG��FIFO���ݼĴ�����״̬
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  trng_fifo_data_cnt : 8;  /* bit[0-7] : fifo��������ĸ����� */
        unsigned int  reserved           : 24; /* bit[8-31]:  */
    } reg;
} SOC_TRNG_HISEC_COM_TRNG_DATA_ST_UNION;
#endif
#define SOC_TRNG_HISEC_COM_TRNG_DATA_ST_trng_fifo_data_cnt_START  (0)
#define SOC_TRNG_HISEC_COM_TRNG_DATA_ST_trng_fifo_data_cnt_END    (7)


/*****************************************************************************
 �ṹ��    : SOC_TRNG_HISEC_COM_TRNG_ENTROPY_MONO_CNT_UNION
 �ṹ˵��  : HISEC_COM_TRNG_ENTROPY_MONO_CNT �Ĵ����ṹ���塣��ַƫ����:0x000C����ֵ:0x00000000�����:32
 �Ĵ���˵��: ��Դ�������ʧ�ܵĴ���ͳ�ƣ������ڵ��ԣ�
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  entropy_rng1_cnt : 3;  /* bit[0-2] : ������ */
        unsigned int  reserved         : 29; /* bit[3-31]:  */
    } reg;
} SOC_TRNG_HISEC_COM_TRNG_ENTROPY_MONO_CNT_UNION;
#endif
#define SOC_TRNG_HISEC_COM_TRNG_ENTROPY_MONO_CNT_entropy_rng1_cnt_START  (0)
#define SOC_TRNG_HISEC_COM_TRNG_ENTROPY_MONO_CNT_entropy_rng1_cnt_END    (2)


/*****************************************************************************
 �ṹ��    : SOC_TRNG_HISEC_COM_TRNG_MONO_CNT_UNION
 �ṹ˵��  : HISEC_COM_TRNG_MONO_CNT �Ĵ����ṹ���塣��ַƫ����:0x0010����ֵ:0x00000000�����:32
 �Ĵ���˵��: ������������ʧ�ܴ���ͳ�ƣ������ڵ��ԣ�
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  self_alarm_cnt : 4;  /* bit[0-3] : ������������ʧ�ܴ���ͳ�� */
        unsigned int  reserved       : 28; /* bit[4-31]:  */
    } reg;
} SOC_TRNG_HISEC_COM_TRNG_MONO_CNT_UNION;
#endif
#define SOC_TRNG_HISEC_COM_TRNG_MONO_CNT_self_alarm_cnt_START  (0)
#define SOC_TRNG_HISEC_COM_TRNG_MONO_CNT_self_alarm_cnt_END    (3)


/*****************************************************************************
 �ṹ��    : SOC_TRNG_HISEC_COM_TRNG_ALARM_SRC_UNION
 �ṹ˵��  : HISEC_COM_TRNG_ALARM_SRC �Ĵ����ṹ���塣��ַƫ����:0x0014����ֵ:0x00000000�����:32
 �Ĵ���˵��: �澯Դ״̬�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  pre_self_alarm_src    : 1;  /* bit[0]   : ��Դ��������߼��澯�������߼����������n��ʧ�ܣ�nΪ�����õģ������ϱ��澯�� */
        unsigned int  pos_self_alarm_src    : 1;  /* bit[1]   : DRBG�����������߼��澯�������߼����������n��ʧ�ܣ�nΪ�����õģ������ϱ��澯�� */
        unsigned int  rng_timeout_alarm_src : 1;  /* bit[2]   : �������ʱ�䲻�ܲ���������һ��ʱ�䣬�ϱ��澯
                                                                0x1:�澯��
                                                                0x0���޸澯�� */
        unsigned int  pri_tim_out_alarm_src : 1;  /* bit[3]   : TRNG���˽�нӿڳ�ʱ�澯��
                                                                0x1��TRNG��˽�нӿڳ�ʱ�����������ʱ�澯��
                                                                0x0������������ */
        unsigned int  prt_alarm_src         : 1;  /* bit[4]   : �ؼ��źű����澯��
                                                                0x1��TRNG�Ĺؼ��ź��ܵ������澯��
                                                                0x0������������ */
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
 �ṹ��    : SOC_TRNG_HISEC_COM_TRNG_ALARM_MASK_UNION
 �ṹ˵��  : HISEC_COM_TRNG_ALARM_MASK �Ĵ����ṹ���塣��ַƫ����:0x0018����ֵ:0x000AAAAA�����:32
 �Ĵ���˵��: �澯Դ���μĴ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  pre_self_alarm_mask    : 4;  /* bit[0-3]  : TRNGģ���ڲ��澯�������źţ�
                                                                  0x5Ϊ������Ч������TRNG�澯�źţ�
                                                                  ����ֵ��ʾ������Ч�� */
        unsigned int  pos_self_alarm_mask    : 4;  /* bit[4-7]  : TRNGģ���ڲ��澯�������źţ�
                                                                  0x5Ϊ������Ч������TRNG�澯�źţ�
                                                                  ����ֵ��ʾ������Ч�� */
        unsigned int  rng_timeout_alarm_mask : 4;  /* bit[8-11] : TRNGģ���ڲ��澯�������źţ�
                                                                  0x5Ϊ������Ч������TRNG�澯�źţ�
                                                                  ����ֵ��ʾ������Ч�� */
        unsigned int  pri_tim_out_alarm_mask : 4;  /* bit[12-15]: TRNGģ���ڲ��澯�������źţ�
                                                                  0x5Ϊ������Ч������TRNG�澯�źţ�
                                                                  ����ֵ��ʾ������Ч�� */
        unsigned int  prt_alarm_mask         : 4;  /* bit[16-19]: TRNGģ��ؼ��źŹ����쳣�澯���Σ�
                                                                  0x5Ϊ������Ч�����ιؼ��źŹ����澯��
                                                                  ����ֵ��ʾ������Ч�� */
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
 �ṹ��    : SOC_TRNG_HISEC_COM_TRNG_ALARM_SRC_POST_UNION
 �ṹ˵��  : HISEC_COM_TRNG_ALARM_SRC_POST �Ĵ����ṹ���塣��ַƫ����:0x001C����ֵ:0x00000000�����:32
 �Ĵ���˵��: ���κ�ĸ澯Դ״̬�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  pre_self_alarm_post    : 1;  /* bit[0]   : ��Դ��������߼��澯�������߼����������n��ʧ�ܣ�nΪ�����õģ������ϱ��澯�� */
        unsigned int  pos_self_alarm_post    : 1;  /* bit[1]   : DRBG�����������߼��澯�������߼����������n��ʧ�ܣ�nΪ�����õģ������ϱ��澯�� */
        unsigned int  rng_timeout_alarm_post : 1;  /* bit[2]   : �������ʱ�䲻�ܲ���������һ��ʱ�䣬�ϱ��澯
                                                                 0x1:�澯��
                                                                 0x0���޸澯�� */
        unsigned int  pri_tim_out_alarm_post : 1;  /* bit[3]   : TRNG���˽�нӿڳ�ʱ�澯��
                                                                 0x1��TRNG��˽�нӿڳ�ʱ�����������ʱ�澯��
                                                                 0x0������������ */
        unsigned int  prt_alarm_post         : 1;  /* bit[4]   : �ؼ��źű����澯��
                                                                 0x1��TRNG�Ĺؼ��ź��ܵ������澯��
                                                                 0x0������������ */
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
 �ṹ��    : SOC_TRNG_HISEC_COM_TRNG_FIFO_READY_UNION
 �ṹ˵��  : HISEC_COM_TRNG_FIFO_READY �Ĵ����ṹ���塣��ַƫ����:0x0020����ֵ:0x000000AA�����:32
 �Ĵ���˵��: trng����״̬�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  trng_data_ready : 4;  /* bit[0-3] : trng_data_ready = 4'h5��ʾ���������׼���ã��ɶ�ȡTRNG�����ݼĴ��� */
        unsigned int  trng_done       : 4;  /* bit[4-7] : trng_done=4'h5��ʾtrng_topģ���Ѿ�������ʼ���� */
        unsigned int  reserved        : 24; /* bit[8-31]:  */
    } reg;
} SOC_TRNG_HISEC_COM_TRNG_FIFO_READY_UNION;
#endif
#define SOC_TRNG_HISEC_COM_TRNG_FIFO_READY_trng_data_ready_START  (0)
#define SOC_TRNG_HISEC_COM_TRNG_FIFO_READY_trng_data_ready_END    (3)
#define SOC_TRNG_HISEC_COM_TRNG_FIFO_READY_trng_done_START        (4)
#define SOC_TRNG_HISEC_COM_TRNG_FIFO_READY_trng_done_END          (7)


/*****************************************************************************
 �ṹ��    : SOC_TRNG_HISEC_COM_TRNG_OSC_TEST_SEL_UNION
 �ṹ˵��  : HISEC_COM_TRNG_OSC_TEST_SEL �Ĵ����ṹ���塣��ַƫ����:0x0024����ֵ:0x000000FF�����:32
 �Ĵ���˵��: 4��ģ��IP �˹���ģʽ�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  osc_trng_sel : 8;  /* bit[0-7] : 4��ģ��IPԴ�����ã�Ĭ��8��h00��TRNG��λ�ͷź��Զ����³�8'hFF����src_cfg_enΪ1ʱ�����ã�
                                                       [7:6]��3·TRNG���ã�
                                                       [5:4]��2·TRNG���ã�
                                                       [3:2]��1·TRNG���ã�
                                                       [1:0]��0·TRNG���ã�
                                                       
                                                       ��bit������ֵ��
                                                       00��disable RNG��
                                                       01���������Դ��·1��
                                                       10���������Դ��·2��
                                                       11��ģ��Դ��������ģʽ�� */
        unsigned int  reserved     : 24; /* bit[8-31]:  */
    } reg;
} SOC_TRNG_HISEC_COM_TRNG_OSC_TEST_SEL_UNION;
#endif
#define SOC_TRNG_HISEC_COM_TRNG_OSC_TEST_SEL_osc_trng_sel_START  (0)
#define SOC_TRNG_HISEC_COM_TRNG_OSC_TEST_SEL_osc_trng_sel_END    (7)


/*****************************************************************************
 �ṹ��    : SOC_TRNG_HISEC_COM_TRNG_TIM_OUT_PERIOD_UNION
 �ṹ˵��  : HISEC_COM_TRNG_TIM_OUT_PERIOD �Ĵ����ṹ���塣��ַƫ����:0x0028����ֵ:0xFFFFFFFF�����:32
 �Ĵ���˵��: �������������ʱʱ�����üĴ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  garo_disable   : 1;  /* bit[0-0] : garo����ȥʹ���ź�,����Ч */
        unsigned int  tim_out_period : 31; /* bit[1-31]: ������������ĳ�ʱʱ��,��λΪʱ������ */
    } reg;
} SOC_TRNG_HISEC_COM_TRNG_TIM_OUT_PERIOD_UNION;
#endif
#define SOC_TRNG_HISEC_COM_TRNG_TIM_OUT_PERIOD_garo_disable_START    (0)
#define SOC_TRNG_HISEC_COM_TRNG_TIM_OUT_PERIOD_garo_disable_END      (0)
#define SOC_TRNG_HISEC_COM_TRNG_TIM_OUT_PERIOD_tim_out_period_START  (1)
#define SOC_TRNG_HISEC_COM_TRNG_TIM_OUT_PERIOD_tim_out_period_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_TRNG_HISEC_COM_TRNG_ALARM_CLR_UNION
 �ṹ˵��  : HISEC_COM_TRNG_ALARM_CLR �Ĵ����ṹ���塣��ַƫ����:0x002C����ֵ:0x00000000�����:32
 �Ĵ���˵��: �澯Դ�����κ�澯Դ����Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  pre_self_alarm_clr    : 4;  /* bit[0-3]  : TRNGģ���ڲ��澯������źţ�
                                                                 0x5Ϊ�����Ч�����TRNG�澯�źţ�
                                                                 ����ֵ��ʾ�����Ч�� */
        unsigned int  pos_self_alarm_clr    : 4;  /* bit[4-7]  : TRNGģ���ڲ��澯������źţ�
                                                                 0x5Ϊ�����Ч�����TRNG�澯�źţ�
                                                                 ����ֵ��ʾ�����Ч�� */
        unsigned int  rng_timeout_alarm_clr : 4;  /* bit[8-11] : TRNGģ���ڲ��澯������źţ�
                                                                 0x5Ϊ�����Ч�����TRNG�澯�źţ�
                                                                 ����ֵ��ʾ�����Ч�� */
        unsigned int  pri_tim_out_alarm_clr : 4;  /* bit[12-15]: TRNGģ���ڲ��澯������źţ�
                                                                 0x5Ϊ�����Ч�����TRNG�澯�źţ�
                                                                 ����ֵ��ʾ�����Ч�� */
        unsigned int  prt_alarm_clr         : 4;  /* bit[16-19]: TRNGģ��ؼ��źŹ����쳣�澯�����
                                                                 0x5Ϊ�����Ч������ؼ��źŹ����澯��
                                                                 ����ֵ��ʾ�����Ч�� */
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
 �ṹ��    : SOC_TRNG_HISEC_COM_TRNG_PRE_CK_CNT_UNION
 �ṹ˵��  : HISEC_COM_TRNG_PRE_CK_CNT �Ĵ����ṹ���塣��ַƫ����:0x0030����ֵ:0x0000000F�����:32
 �Ĵ���˵��: ��Դ���߼������ʧ�ܵķ�ֵ���üĴ�����
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  pre_self_fail_cnt : 4;  /* bit[0-3] : ��Դ���߼������ʧ�ܵĴ������üĴ�����
                                                            ���÷�ΧΪ3~15���������˷�Χ��ֵΪ15. */
        unsigned int  reserved          : 28; /* bit[4-31]:  */
    } reg;
} SOC_TRNG_HISEC_COM_TRNG_PRE_CK_CNT_UNION;
#endif
#define SOC_TRNG_HISEC_COM_TRNG_PRE_CK_CNT_pre_self_fail_cnt_START  (0)
#define SOC_TRNG_HISEC_COM_TRNG_PRE_CK_CNT_pre_self_fail_cnt_END    (3)


/*****************************************************************************
 �ṹ��    : SOC_TRNG_HISEC_COM_TRNG_PRE_MONO_CNT_UNION
 �ṹ˵��  : HISEC_COM_TRNG_PRE_MONO_CNT �Ĵ����ṹ���塣��ַƫ����:0x0034����ֵ:0x0000FF00�����:32
 �Ĵ���˵��: ��Դ���߼���MONO��鷧ֵ����
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  pre_mono_ck_low : 8;  /* bit[0-7]  : MONO������ͷ�ֵ */
        unsigned int  pre_mono_ck_hig : 8;  /* bit[8-15] : MONO������߷�ֵ */
        unsigned int  reserved        : 16; /* bit[16-31]:  */
    } reg;
} SOC_TRNG_HISEC_COM_TRNG_PRE_MONO_CNT_UNION;
#endif
#define SOC_TRNG_HISEC_COM_TRNG_PRE_MONO_CNT_pre_mono_ck_low_START  (0)
#define SOC_TRNG_HISEC_COM_TRNG_PRE_MONO_CNT_pre_mono_ck_low_END    (7)
#define SOC_TRNG_HISEC_COM_TRNG_PRE_MONO_CNT_pre_mono_ck_hig_START  (8)
#define SOC_TRNG_HISEC_COM_TRNG_PRE_MONO_CNT_pre_mono_ck_hig_END    (15)


/*****************************************************************************
 �ṹ��    : SOC_TRNG_HISEC_COM_TRNG_PRE_LONG_RUN_CNT_UNION
 �ṹ˵��  : HISEC_COM_TRNG_PRE_LONG_RUN_CNT �Ĵ����ṹ���塣��ַƫ����:0x0038����ֵ:0x000000FF�����:32
 �Ĵ���˵��: ��Դ���߼���LONG RUN��鷧ֵ���á�
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  pre_long_run_hig : 8;  /* bit[0-7] : LONG RUN������߷�ֵ */
        unsigned int  reserved         : 24; /* bit[8-31]:  */
    } reg;
} SOC_TRNG_HISEC_COM_TRNG_PRE_LONG_RUN_CNT_UNION;
#endif
#define SOC_TRNG_HISEC_COM_TRNG_PRE_LONG_RUN_CNT_pre_long_run_hig_START  (0)
#define SOC_TRNG_HISEC_COM_TRNG_PRE_LONG_RUN_CNT_pre_long_run_hig_END    (7)


/*****************************************************************************
 �ṹ��    : SOC_TRNG_HISEC_COM_TRNG_PRE_RUN_CNT_UNION
 �ṹ˵��  : HISEC_COM_TRNG_PRE_RUN_CNT �Ĵ����ṹ���塣��ַƫ����:0x003C����ֵ:0x0000FFFF�����:32
 �Ĵ���˵��: ��Դ���߼���RUN��鷧ֵ���á�
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  pre_run_test_hig : 16; /* bit[0-15] : RUN������߷�ֵ */
        unsigned int  reserved         : 16; /* bit[16-31]:  */
    } reg;
} SOC_TRNG_HISEC_COM_TRNG_PRE_RUN_CNT_UNION;
#endif
#define SOC_TRNG_HISEC_COM_TRNG_PRE_RUN_CNT_pre_run_test_hig_START  (0)
#define SOC_TRNG_HISEC_COM_TRNG_PRE_RUN_CNT_pre_run_test_hig_END    (15)


/*****************************************************************************
 �ṹ��    : SOC_TRNG_HISEC_COM_TRNG_PRE_SERIAL_CNT_UNION
 �ṹ˵��  : HISEC_COM_TRNG_PRE_SERIAL_CNT �Ĵ����ṹ���塣��ַƫ����:0x0040����ֵ:0x0000FFFF�����:32
 �Ĵ���˵��: ��Դ���߼���SERIAL��鷧ֵ���á�
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  pre_serial_ck_hig : 16; /* bit[0-15] : RUN������߷�ֵ */
        unsigned int  reserved          : 16; /* bit[16-31]:  */
    } reg;
} SOC_TRNG_HISEC_COM_TRNG_PRE_SERIAL_CNT_UNION;
#endif
#define SOC_TRNG_HISEC_COM_TRNG_PRE_SERIAL_CNT_pre_serial_ck_hig_START  (0)
#define SOC_TRNG_HISEC_COM_TRNG_PRE_SERIAL_CNT_pre_serial_ck_hig_END    (15)


/*****************************************************************************
 �ṹ��    : SOC_TRNG_HISEC_COM_TRNG_PRE_POKER_CNT_UNION
 �ṹ˵��  : HISEC_COM_TRNG_PRE_POKER_CNT �Ĵ����ṹ���塣��ַƫ����:0x0044����ֵ:0x0000FFFF�����:32
 �Ĵ���˵��: ��Դ���߼���POKER��鷧ֵ���á�
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  pre_poker_ck_hig : 16; /* bit[0-15] : POKER������߷�ֵ */
        unsigned int  reserved         : 16; /* bit[16-31]:  */
    } reg;
} SOC_TRNG_HISEC_COM_TRNG_PRE_POKER_CNT_UNION;
#endif
#define SOC_TRNG_HISEC_COM_TRNG_PRE_POKER_CNT_pre_poker_ck_hig_START  (0)
#define SOC_TRNG_HISEC_COM_TRNG_PRE_POKER_CNT_pre_poker_ck_hig_END    (15)


/*****************************************************************************
 �ṹ��    : SOC_TRNG_HISEC_COM_TRNG_PRE_ATCR01_CNT_UNION
 �ṹ˵��  : HISEC_COM_TRNG_PRE_ATCR01_CNT �Ĵ����ṹ���塣��ַƫ����:0x0048����ֵ:0xFF00FF00�����:32
 �Ĵ���˵��: ��Դ���߼���ATCR01��鷧ֵ���á�
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  pre_actr0_ck_low : 8;  /* bit[0-7]  : AUTOCORRELATION CNT0������ͷ�ֵ */
        unsigned int  pre_actr0_ck_hig : 8;  /* bit[8-15] : AUTOCORRELATION CNT0������߷�ֵ */
        unsigned int  pre_actr1_ck_low : 8;  /* bit[16-23]: AUTOCORRELATION CNT1������ͷ�ֵ */
        unsigned int  pre_actr1_ck_hig : 8;  /* bit[24-31]: AUTOCORRELATION CNT1������߷�ֵ */
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
 �ṹ��    : SOC_TRNG_HISEC_COM_TRNG_PRE_ATCR23_CNT_UNION
 �ṹ˵��  : HISEC_COM_TRNG_PRE_ATCR23_CNT �Ĵ����ṹ���塣��ַƫ����:0x004C����ֵ:0xFF00FF00�����:32
 �Ĵ���˵��: ��Դ���߼���ATCR23��鷧ֵ���á�
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  pre_actr2_ck_low : 8;  /* bit[0-7]  : AUTOCORRELATION CNT2������ͷ�ֵ */
        unsigned int  pre_actr2_ck_hig : 8;  /* bit[8-15] : AUTOCORRELATION CNT2������߷�ֵ */
        unsigned int  pre_actr3_ck_low : 8;  /* bit[16-23]: AUTOCORRELATION CNT3������ͷ�ֵ */
        unsigned int  pre_actr3_ck_hig : 8;  /* bit[24-31]: AUTOCORRELATION CNT3������߷�ֵ */
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
 �ṹ��    : SOC_TRNG_HISEC_COM_TRNG_POS_CK_CNT_UNION
 �ṹ˵��  : HISEC_COM_TRNG_POS_CK_CNT �Ĵ����ṹ���塣��ַƫ����:0x0050����ֵ:0x00000008�����:32
 �Ĵ���˵��: DRBG����������߼������ʧ�ܵķ�ֵ���üĴ�����
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  pos_self_fail_cnt : 4;  /* bit[0-3] : ��Դ���߼������ʧ�ܵĴ������üĴ�����
                                                            ���÷�ΧΪ3~8���������˷�Χ��ֵΪ5. */
        unsigned int  reserved          : 28; /* bit[4-31]:  */
    } reg;
} SOC_TRNG_HISEC_COM_TRNG_POS_CK_CNT_UNION;
#endif
#define SOC_TRNG_HISEC_COM_TRNG_POS_CK_CNT_pos_self_fail_cnt_START  (0)
#define SOC_TRNG_HISEC_COM_TRNG_POS_CK_CNT_pos_self_fail_cnt_END    (3)


/*****************************************************************************
 �ṹ��    : SOC_TRNG_HISEC_COM_TRNG_POS_MONO_CNT_UNION
 �ṹ˵��  : HISEC_COM_TRNG_POS_MONO_CNT �Ĵ����ṹ���塣��ַƫ����:0x0054����ֵ:0x0000FF00�����:32
 �Ĵ���˵��: DRBG����������߼���MONO��鷧ֵ����
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  pos_mono_ck_low : 8;  /* bit[0-7]  : MONO������ͷ�ֵ */
        unsigned int  pos_mono_ck_hig : 8;  /* bit[8-15] : MONO������߷�ֵ */
        unsigned int  reserved        : 16; /* bit[16-31]:  */
    } reg;
} SOC_TRNG_HISEC_COM_TRNG_POS_MONO_CNT_UNION;
#endif
#define SOC_TRNG_HISEC_COM_TRNG_POS_MONO_CNT_pos_mono_ck_low_START  (0)
#define SOC_TRNG_HISEC_COM_TRNG_POS_MONO_CNT_pos_mono_ck_low_END    (7)
#define SOC_TRNG_HISEC_COM_TRNG_POS_MONO_CNT_pos_mono_ck_hig_START  (8)
#define SOC_TRNG_HISEC_COM_TRNG_POS_MONO_CNT_pos_mono_ck_hig_END    (15)


/*****************************************************************************
 �ṹ��    : SOC_TRNG_HISEC_COM_TRNG_POS_LONG_RUN_CNT_UNION
 �ṹ˵��  : HISEC_COM_TRNG_POS_LONG_RUN_CNT �Ĵ����ṹ���塣��ַƫ����:0x0058����ֵ:0x000000FF�����:32
 �Ĵ���˵��: DRBG����������߼���LONG RUN��鷧ֵ���á�
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  pos_long_run_hig : 8;  /* bit[0-7] : LONG RUN������߷�ֵ */
        unsigned int  reserved         : 24; /* bit[8-31]:  */
    } reg;
} SOC_TRNG_HISEC_COM_TRNG_POS_LONG_RUN_CNT_UNION;
#endif
#define SOC_TRNG_HISEC_COM_TRNG_POS_LONG_RUN_CNT_pos_long_run_hig_START  (0)
#define SOC_TRNG_HISEC_COM_TRNG_POS_LONG_RUN_CNT_pos_long_run_hig_END    (7)


/*****************************************************************************
 �ṹ��    : SOC_TRNG_HISEC_COM_TRNG_POS_RUN_CNT_UNION
 �ṹ˵��  : HISEC_COM_TRNG_POS_RUN_CNT �Ĵ����ṹ���塣��ַƫ����:0x005C����ֵ:0x0000FFFF�����:32
 �Ĵ���˵��: DRBG����������߼���RUN��鷧ֵ���á�
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  pos_run_test_hig : 16; /* bit[0-15] : RUN������߷�ֵ */
        unsigned int  reserved         : 16; /* bit[16-31]:  */
    } reg;
} SOC_TRNG_HISEC_COM_TRNG_POS_RUN_CNT_UNION;
#endif
#define SOC_TRNG_HISEC_COM_TRNG_POS_RUN_CNT_pos_run_test_hig_START  (0)
#define SOC_TRNG_HISEC_COM_TRNG_POS_RUN_CNT_pos_run_test_hig_END    (15)


/*****************************************************************************
 �ṹ��    : SOC_TRNG_HISEC_COM_TRNG_POS_SERIAL_CNT_UNION
 �ṹ˵��  : HISEC_COM_TRNG_POS_SERIAL_CNT �Ĵ����ṹ���塣��ַƫ����:0x0060����ֵ:0x0000FFFF�����:32
 �Ĵ���˵��: DRBG����������߼���SERIAL��鷧ֵ���á�
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  pos_serial_ck_hig : 16; /* bit[0-15] : RUN������߷�ֵ */
        unsigned int  reserved          : 16; /* bit[16-31]:  */
    } reg;
} SOC_TRNG_HISEC_COM_TRNG_POS_SERIAL_CNT_UNION;
#endif
#define SOC_TRNG_HISEC_COM_TRNG_POS_SERIAL_CNT_pos_serial_ck_hig_START  (0)
#define SOC_TRNG_HISEC_COM_TRNG_POS_SERIAL_CNT_pos_serial_ck_hig_END    (15)


/*****************************************************************************
 �ṹ��    : SOC_TRNG_HISEC_COM_TRNG_POS_POKER_CNT_UNION
 �ṹ˵��  : HISEC_COM_TRNG_POS_POKER_CNT �Ĵ����ṹ���塣��ַƫ����:0x0064����ֵ:0x0000FFFF�����:32
 �Ĵ���˵��: DRBG����������߼���POKER��鷧ֵ���á�
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  pos_poker_ck_hig : 16; /* bit[0-15] : POKER������߷�ֵ */
        unsigned int  reserved         : 16; /* bit[16-31]:  */
    } reg;
} SOC_TRNG_HISEC_COM_TRNG_POS_POKER_CNT_UNION;
#endif
#define SOC_TRNG_HISEC_COM_TRNG_POS_POKER_CNT_pos_poker_ck_hig_START  (0)
#define SOC_TRNG_HISEC_COM_TRNG_POS_POKER_CNT_pos_poker_ck_hig_END    (15)


/*****************************************************************************
 �ṹ��    : SOC_TRNG_HISEC_COM_TRNG_POS_ATCR01_CNT_UNION
 �ṹ˵��  : HISEC_COM_TRNG_POS_ATCR01_CNT �Ĵ����ṹ���塣��ַƫ����:0x0068����ֵ:0xFF00FF00�����:32
 �Ĵ���˵��: DRBG����������߼���ATCR01��鷧ֵ���á�
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  pos_actr0_ck_low : 8;  /* bit[0-7]  : AUTOCORRELATION CNT0������ͷ�ֵ */
        unsigned int  pos_actr0_ck_hig : 8;  /* bit[8-15] : AUTOCORRELATION CNT0������߷�ֵ */
        unsigned int  pos_actr1_ck_low : 8;  /* bit[16-23]: AUTOCORRELATION CNT1������ͷ�ֵ */
        unsigned int  pos_actr1_ck_hig : 8;  /* bit[24-31]: AUTOCORRELATION CNT1������߷�ֵ */
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
 �ṹ��    : SOC_TRNG_HISEC_COM_TRNG_POS_ATCR23_CNT_UNION
 �ṹ˵��  : HISEC_COM_TRNG_POS_ATCR23_CNT �Ĵ����ṹ���塣��ַƫ����:0x006C����ֵ:0xFF00FF00�����:32
 �Ĵ���˵��: DRBG����������߼���ATCR23��鷧ֵ���á�
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  pos_actr2_ck_low : 8;  /* bit[0-7]  : AUTOCORRELATION CNT2������ͷ�ֵ */
        unsigned int  pos_actr2_ck_hig : 8;  /* bit[8-15] : AUTOCORRELATION CNT2������߷�ֵ */
        unsigned int  pos_actr3_ck_low : 8;  /* bit[16-23]: AUTOCORRELATION CNT3������ͷ�ֵ */
        unsigned int  pos_actr3_ck_hig : 8;  /* bit[24-31]: AUTOCORRELATION CNT3������߷�ֵ */
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
 �ṹ��    : SOC_TRNG_HISEC_COM_TRNG_AIS31_FAIL_CNT_UNION
 �ṹ˵��  : HISEC_COM_TRNG_AIS31_FAIL_CNT �Ĵ����ṹ���塣��ַƫ����:0x0070����ֵ:0x000000FF�����:32
 �Ĵ���˵��: ��ԴAIS31������ʧ�ܴ�������
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ais31_fail_cnt : 8;  /* bit[0-7] : ��ԴAIS31������ʧ�ܴ���������ֵ��
                                                         ��СֵΪ8'd3��Ĭ��ֵΪ8'd20�� �������ֵС����Сֵ�����߼�Ĭ��Ϊ8'd20�� */
        unsigned int  reserved       : 24; /* bit[8-31]:  */
    } reg;
} SOC_TRNG_HISEC_COM_TRNG_AIS31_FAIL_CNT_UNION;
#endif
#define SOC_TRNG_HISEC_COM_TRNG_AIS31_FAIL_CNT_ais31_fail_cnt_START  (0)
#define SOC_TRNG_HISEC_COM_TRNG_AIS31_FAIL_CNT_ais31_fail_cnt_END    (7)


/*****************************************************************************
 �ṹ��    : SOC_TRNG_HISEC_COM_TRNG_AIS31_BLOCK_CNT_UNION
 �ṹ˵��  : HISEC_COM_TRNG_AIS31_BLOCK_CNT �Ĵ����ṹ���塣��ַƫ����:0x0074����ֵ:0x00000200�����:32
 �Ĵ���˵��: ��ԴAIS31��������������
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ais31_block_cnt : 10; /* bit[0-9]  : ��ԴAIS31���������������ֵ��
                                                           Ĭ��ֵΪ10'd512����512�Σ�������Ϊ0ʱ����ʾ������AIS31��飻 */
        unsigned int  reserved        : 22; /* bit[10-31]:  */
    } reg;
} SOC_TRNG_HISEC_COM_TRNG_AIS31_BLOCK_CNT_UNION;
#endif
#define SOC_TRNG_HISEC_COM_TRNG_AIS31_BLOCK_CNT_ais31_block_cnt_START  (0)
#define SOC_TRNG_HISEC_COM_TRNG_AIS31_BLOCK_CNT_ais31_block_cnt_END    (9)


/*****************************************************************************
 �ṹ��    : SOC_TRNG_HISEC_COM_TRNG_AIS31_POKER_LOW_UNION
 �ṹ˵��  : HISEC_COM_TRNG_AIS31_POKER_LOW �Ĵ����ṹ���塣��ַƫ����:0x0078����ֵ:0x00000000�����:32
 �Ĵ���˵��: ��ԴAIS31 POKER���������ֵ
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ais31_poker_low : 8;  /* bit[0-7] : ��ԴAIS31 POKER���������ֵ */
        unsigned int  reserved        : 24; /* bit[8-31]:  */
    } reg;
} SOC_TRNG_HISEC_COM_TRNG_AIS31_POKER_LOW_UNION;
#endif
#define SOC_TRNG_HISEC_COM_TRNG_AIS31_POKER_LOW_ais31_poker_low_START  (0)
#define SOC_TRNG_HISEC_COM_TRNG_AIS31_POKER_LOW_ais31_poker_low_END    (7)


/*****************************************************************************
 �ṹ��    : SOC_TRNG_HISEC_COM_TRNG_AIS31_POKER_HIG_UNION
 �ṹ˵��  : HISEC_COM_TRNG_AIS31_POKER_HIG �Ĵ����ṹ���塣��ַƫ����:0x007C����ֵ:0x000000FF�����:32
 �Ĵ���˵��: ��ԴAIS31 POKER���������ֵ
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ais31_poker_hig : 8;  /* bit[0-7] : ��ԴAIS31 POKER���������ֵ */
        unsigned int  reserved        : 24; /* bit[8-31]:  */
    } reg;
} SOC_TRNG_HISEC_COM_TRNG_AIS31_POKER_HIG_UNION;
#endif
#define SOC_TRNG_HISEC_COM_TRNG_AIS31_POKER_HIG_ais31_poker_hig_START  (0)
#define SOC_TRNG_HISEC_COM_TRNG_AIS31_POKER_HIG_ais31_poker_hig_END    (7)


/*****************************************************************************
 �ṹ��    : SOC_TRNG_UNLOCK_UNION
 �ṹ˵��  : UNLOCK �Ĵ����ṹ���塣��ַƫ����:0x0080����ֵ:0x0000000A�����:32
 �Ĵ���˵��: 
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  trng_unlock : 4;  /* bit[0-3] : �Ĵ�������д0xAʱ�����������ã�д0x5�������䣬д������ֵ����alarm�� */
        unsigned int  reserved    : 28; /* bit[4-31]:  */
    } reg;
} SOC_TRNG_UNLOCK_UNION;
#endif
#define SOC_TRNG_UNLOCK_trng_unlock_START  (0)
#define SOC_TRNG_UNLOCK_trng_unlock_END    (3)


/*****************************************************************************
 �ṹ��    : SOC_TRNG_CTRL_CHI_TH_PRE1_UNION
 �ṹ˵��  : CTRL_CHI_TH_PRE1 �Ĵ����ṹ���塣��ַƫ����:0x0084����ֵ:0x000001C2�����:32
 �Ĵ���˵��: PRE1��ֵ
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  thre_pre1 : 9;  /* bit[0-8] : ���߲��Ե���ֵ�źţ�PRE1��ֵ�� */
        unsigned int  reserved  : 23; /* bit[9-31]:  */
    } reg;
} SOC_TRNG_CTRL_CHI_TH_PRE1_UNION;
#endif
#define SOC_TRNG_CTRL_CHI_TH_PRE1_thre_pre1_START  (0)
#define SOC_TRNG_CTRL_CHI_TH_PRE1_thre_pre1_END    (8)


/*****************************************************************************
 �ṹ��    : SOC_TRNG_CTRL_CHI_TH_PRE2_UNION
 �ṹ˵��  : CTRL_CHI_TH_PRE2 �Ĵ����ṹ���塣��ַƫ����:0x0088����ֵ:0x00000000�����:32
 �Ĵ���˵��: PRE2��ֵ
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  thre_pre2 : 9;  /* bit[0-8] : ���߲��Ե���ֵ�źţ�PRE2��ֵ�� */
        unsigned int  reserved  : 23; /* bit[9-31]:  */
    } reg;
} SOC_TRNG_CTRL_CHI_TH_PRE2_UNION;
#endif
#define SOC_TRNG_CTRL_CHI_TH_PRE2_thre_pre2_START  (0)
#define SOC_TRNG_CTRL_CHI_TH_PRE2_thre_pre2_END    (8)


/*****************************************************************************
 �ṹ��    : SOC_TRNG_CTRL_CHI_TH_PRE3_UNION
 �ṹ˵��  : CTRL_CHI_TH_PRE3 �Ĵ����ṹ���塣��ַƫ����:0x008C����ֵ:0x000001C2�����:32
 �Ĵ���˵��: PRE3��ֵ
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  thre_pre3 : 9;  /* bit[0-8] : ���߲��Ե���ֵ�źţ�PRE3��ֵ�� */
        unsigned int  reserved  : 23; /* bit[9-31]:  */
    } reg;
} SOC_TRNG_CTRL_CHI_TH_PRE3_UNION;
#endif
#define SOC_TRNG_CTRL_CHI_TH_PRE3_thre_pre3_START  (0)
#define SOC_TRNG_CTRL_CHI_TH_PRE3_thre_pre3_END    (8)


/*****************************************************************************
 �ṹ��    : SOC_TRNG_CTRL_CHI_TH_ENTROPY_UNION
 �ṹ˵��  : CTRL_CHI_TH_ENTROPY �Ĵ����ṹ���塣��ַƫ����:0x0090����ֵ:0x000001C2�����:32
 �Ĵ���˵��: ENTROPY��ֵ
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  thre_entropy : 9;  /* bit[0-8] : ���߲��Ե���ֵ�źţ�entropy��ֵ�� */
        unsigned int  reserved     : 23; /* bit[9-31]:  */
    } reg;
} SOC_TRNG_CTRL_CHI_TH_ENTROPY_UNION;
#endif
#define SOC_TRNG_CTRL_CHI_TH_ENTROPY_thre_entropy_START  (0)
#define SOC_TRNG_CTRL_CHI_TH_ENTROPY_thre_entropy_END    (8)


/*****************************************************************************
 �ṹ��    : SOC_TRNG_INT_CLR_UNION
 �ṹ˵��  : INT_CLR �Ĵ����ṹ���塣��ַƫ����:0x0094����ֵ:0x00000000�����:32
 �Ĵ���˵��: TRNG�ж�״̬����Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  chi_online_int_clr : 4;  /* bit[0-3] : CHI_TESTģ��online �ж����ʹ���źţ�д�塣
                                                             0x5���TRNG�ĸ澯��
                                                             �����������TRNG�ĸ澯�� */
        unsigned int  reserved           : 28; /* bit[4-31]:  */
    } reg;
} SOC_TRNG_INT_CLR_UNION;
#endif
#define SOC_TRNG_INT_CLR_chi_online_int_clr_START  (0)
#define SOC_TRNG_INT_CLR_chi_online_int_clr_END    (3)


/*****************************************************************************
 �ṹ��    : SOC_TRNG_INT_MASK_UNION
 �ṹ˵��  : INT_MASK �Ĵ����ṹ���塣��ַƫ����:0x0098����ֵ:0x00000005�����:32
 �Ĵ���˵��: TRNG�ж�MASK���ƼĴ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  chi_online_int_mask : 4;  /* bit[0-3] : CHI ONLINE �ж����μĴ���:
                                                              0x5:���Σ�0xA��������
                                                              ����ֵ:����alarm�� */
        unsigned int  reserved            : 28; /* bit[4-31]:  */
    } reg;
} SOC_TRNG_INT_MASK_UNION;
#endif
#define SOC_TRNG_INT_MASK_chi_online_int_mask_START  (0)
#define SOC_TRNG_INT_MASK_chi_online_int_mask_END    (3)


/*****************************************************************************
 �ṹ��    : SOC_TRNG_INT_SRC_STATUS_UNION
 �ṹ˵��  : INT_SRC_STATUS �Ĵ����ṹ���塣��ַƫ����:0x009C����ֵ:0x00000000�����:32
 �Ĵ���˵��: TRNG����ǰ�ж�״̬�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  int_chi_online_src : 1;  /* bit[0]   : CHI onlineԭʼ�ж�״̬��
                                                             1'b0:���жϡ�
                                                             1'b1:���жϡ� */
        unsigned int  reserved           : 31; /* bit[1-31]:  */
    } reg;
} SOC_TRNG_INT_SRC_STATUS_UNION;
#endif
#define SOC_TRNG_INT_SRC_STATUS_int_chi_online_src_START  (0)
#define SOC_TRNG_INT_SRC_STATUS_int_chi_online_src_END    (0)


/*****************************************************************************
 �ṹ��    : SOC_TRNG_INT_STATUS_UNION
 �ṹ˵��  : INT_STATUS �Ĵ����ṹ���塣��ַƫ����:0x00A0����ֵ:0x00000000�����:32
 �Ĵ���˵��: TRNG���κ��ж�״̬�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  int_chi_online : 1;  /* bit[0]   : CHI online���κ���ж�״̬��
                                                         1'b0:���жϡ�
                                                         1'b1:���жϡ� */
        unsigned int  reserved       : 31; /* bit[1-31]:  */
    } reg;
} SOC_TRNG_INT_STATUS_UNION;
#endif
#define SOC_TRNG_INT_STATUS_int_chi_online_START  (0)
#define SOC_TRNG_INT_STATUS_int_chi_online_END    (0)


/*****************************************************************************
 �ṹ��    : SOC_TRNG_OTPC_STATUS_0_UNION
 �ṹ˵��  : OTPC_STATUS_0 �Ĵ����ṹ���塣��ַƫ����:0x00A4����ֵ:0x55555555�����:32
 �Ĵ���˵��: TRNG��OTPC״̬�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  otpc_trng_ctrl_sel      : 4;  /* bit[0-3]  : OTPC����ѡ��5ΪOTPC��aΪCPU�� */
        unsigned int  otpc_trng_tp_disable    : 4;  /* bit[4-7]  : Testpoint�رգ�5Ϊ�ر�,aΪ���رա� */
        unsigned int  otpc_trng_digsrc_compen : 4;  /* bit[8-11] : �������Դѹ��ʹ�ܣ�5Ϊʹ��,aΪ��ʹ�ܡ� */
        unsigned int  otpc_trng_scrfilter_en  : 4;  /* bit[12-15]: ���Դ����ѹ��ʹ�ܣ�5Ϊʹ��,aΪ��ʹ�ܡ� */
        unsigned int  otpc_trng_discard_en    : 4;  /* bit[16-19]: �������ʹ�ܣ�5Ϊʹ��,aΪ��ʹ�ܡ� */
        unsigned int  otpc_trng_pre_proc_en   : 4;  /* bit[20-23]: ǰ����ʹ�ܣ�5Ϊʹ��,aΪ��ʹ�ܡ� */
        unsigned int  otpc_trng_post_proc_en  : 4;  /* bit[24-27]: ����ʹ�ܣ�5Ϊʹ��,aΪ��ʹ�ܡ� */
        unsigned int  otpc_trng_post_test_en  : 4;  /* bit[28-31]: ��������߼��ʹ�ܣ�5Ϊʹ��,aΪ��ʹ�ܡ� */
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
 �ṹ��    : SOC_TRNG_OTPC_STATUS_1_UNION
 �ṹ˵��  : OTPC_STATUS_1 �Ĵ����ṹ���塣��ַƫ����:0x00A8����ֵ:0x00055E45�����:32
 �Ĵ���˵��: TRNG��OTPC״̬�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  otpc_trng_pre_test_en : 4;  /* bit[0-3]  : ���Դ���߼��ʹ�ܣ�1Ϊʹ�ܡ� */
        unsigned int  otpc_trng_hs_src_cfg  : 8;  /* bit[4-11] : ��˼���Դ��·���á� */
        unsigned int  otpc_trng_full_dis    : 4;  /* bit[12-15]: ȫ��ģʽ�رգ�1Ϊ�رա� */
        unsigned int  otpc_hw_rd_finish     : 4;  /* bit[16-19]: otpc����ɱ�ǣ�5��ʾ��ɣ�aδ��� */
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
 �ṹ��    : SOC_TRNG_OTPC_TRNG_TRIM_0_UNION
 �ṹ˵��  : OTPC_TRNG_TRIM_0 �Ĵ����ṹ���塣��ַƫ����:0x00B0����ֵ:0x00000000�����:32
 �Ĵ���˵��: OTPC_TRNG_TRIM�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved : 32; /* bit[0-31]: OTPC_TRNG_TRIM[31��0]�Ĵ��� */
    } reg;
} SOC_TRNG_OTPC_TRNG_TRIM_0_UNION;
#endif


/*****************************************************************************
 �ṹ��    : SOC_TRNG_OTPC_TRNG_TRIM_1_UNION
 �ṹ˵��  : OTPC_TRNG_TRIM_1 �Ĵ����ṹ���塣��ַƫ����:0x00B4����ֵ:0x00000000�����:32
 �Ĵ���˵��: OTPC_TRNG_TRIM�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved : 32; /* bit[0-31]: OTPC_TRNG_TRIM[63��32]�Ĵ��� */
    } reg;
} SOC_TRNG_OTPC_TRNG_TRIM_1_UNION;
#endif


/*****************************************************************************
 �ṹ��    : SOC_TRNG_OTPC_TRNG_TRIM_2_UNION
 �ṹ˵��  : OTPC_TRNG_TRIM_2 �Ĵ����ṹ���塣��ַƫ����:0x00B8����ֵ:0x00000000�����:32
 �Ĵ���˵��: OTPC_TRNG_TRIM�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved : 32; /* bit[0-31]: OTPC_TRNG_TRIM[95��64]�Ĵ��� */
    } reg;
} SOC_TRNG_OTPC_TRNG_TRIM_2_UNION;
#endif


/*****************************************************************************
 �ṹ��    : SOC_TRNG_OTPC_TRNG_TRIM_3_UNION
 �ṹ˵��  : OTPC_TRNG_TRIM_3 �Ĵ����ṹ���塣��ַƫ����:0x00Bc����ֵ:0x00000000�����:32
 �Ĵ���˵��: OTPC_TRNG_TRIM�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved : 32; /* bit[0-31]: OTPC_TRNG_TRIM[127��96]�Ĵ��� */
    } reg;
} SOC_TRNG_OTPC_TRNG_TRIM_3_UNION;
#endif


/*****************************************************************************
 �ṹ��    : SOC_TRNG_OTPC_TRNG_TRIM_CRC_UNION
 �ṹ˵��  : OTPC_TRNG_TRIM_CRC �Ĵ����ṹ���塣��ַƫ����:0x00c0����ֵ:0x00006666�����:32
 �Ĵ���˵��: OTPC_TRNG_TRIMֵ��crc�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  OTPC_TRNG_TRIM_CRC : 16; /* bit[0-15] : OTPC_TRNG_TRIMֵ��crc4�Ĵ���
                                                              crc�Ĵ���[3:0]~[15:12]��Ӧtriֵ��[31:0]~[127:96] */
        unsigned int  reserved           : 16; /* bit[16-31]:  */
    } reg;
} SOC_TRNG_OTPC_TRNG_TRIM_CRC_UNION;
#endif
#define SOC_TRNG_OTPC_TRNG_TRIM_CRC_OTPC_TRNG_TRIM_CRC_START  (0)
#define SOC_TRNG_OTPC_TRNG_TRIM_CRC_OTPC_TRNG_TRIM_CRC_END    (15)


/*****************************************************************************
 �ṹ��    : SOC_TRNG_FIFO_RD_LINE_UNION
 �ṹ˵��  : FIFO_RD_LINE �Ĵ����ṹ���塣��ַƫ����:0x00c4����ֵ:0x00000000�����:32
 �Ĵ���˵��: ���������޲����������ȡTRNG�����
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
 �ṹ��    : SOC_TRNG_DRBG_CYCLE_NUM_UNION
 �ṹ˵��  : DRBG_CYCLE_NUM �Ĵ����ṹ���塣��ַƫ����:0x00c8����ֵ:0x00000405�����:32
 �Ĵ���˵��: DRBG��ȫ��ģʽ����ֵ
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
  8 OTHERS����
*****************************************************************************/



/*****************************************************************************
  9 ȫ�ֱ�������
*****************************************************************************/


/*****************************************************************************
  10 ��������
*****************************************************************************/


#ifdef __cplusplus
    #if __cplusplus
        }
    #endif
#endif

#endif /* end of soc_trng_interface.h */
