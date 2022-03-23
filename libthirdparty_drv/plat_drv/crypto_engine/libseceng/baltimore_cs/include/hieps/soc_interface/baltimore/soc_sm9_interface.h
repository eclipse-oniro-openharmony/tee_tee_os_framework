/******************************************************************************

                 ��Ȩ���� (C), 2001-2019, ��Ϊ�������޹�˾

 ******************************************************************************
  �� �� ��   : soc_sm9_interface.h
  �� �� ��   : ����
  ��    ��   : Excel2Code
  ��������   : 2019-10-26 10:53:29
  ����޸�   :
  ��������   : �ӿ�ͷ�ļ�
  �����б�   :
  �޸���ʷ   :
  1.��    ��   : 2019��10��26��
    ��    ��   : l00249396
    �޸�����   : �ӡ�HiEPS V200 nmanager�Ĵ����ֲ�_SM9.xml���Զ�����

******************************************************************************/

/*****************************************************************************
  1 ����ͷ�ļ�����
*****************************************************************************/

#ifndef __SOC_SM9_INTERFACE_H__
#define __SOC_SM9_INTERFACE_H__

#ifdef __cplusplus
    #if __cplusplus
        extern "C" {
    #endif
#endif



/*****************************************************************************
  2 �궨��
*****************************************************************************/

/****************************************************************************
                     (1/1) reg_define
 ****************************************************************************/
/* �Ĵ���˵����æ״̬�Ĵ���
   λ����UNION�ṹ:  SOC_SM9_BUSY_UNION */
#define SOC_SM9_BUSY_ADDR(base)                       ((base) + (0x0000))

/* �Ĵ���˵�������������Ĵ���
   λ����UNION�ṹ:  SOC_SM9_START_UNION */
#define SOC_SM9_START_ADDR(base)                      ((base) + (0x0004))

/* �Ĵ���˵�����ж����μĴ���
   λ����UNION�ṹ:  SOC_SM9_INT_MASK_UNION */
#define SOC_SM9_INT_MASK_ADDR(base)                   ((base) + (0x0008))

/* �Ĵ���˵�����ж�״̬�Ĵ���(���κ��ϱ���״̬)
   λ����UNION�ṹ:  SOC_SM9_INT_STATUS_UNION */
#define SOC_SM9_INT_STATUS_ADDR(base)                 ((base) + (0x000C))

/* �Ĵ���˵�����ж�����ǰ״̬�Ĵ���(ʵ��״̬)
   λ����UNION�ṹ:  SOC_SM9_INT_NOMASK_STATUS_UNION */
#define SOC_SM9_INT_NOMASK_STATUS_ADDR(base)          ((base) + (0x0010))

/* �Ĵ���˵�����ж�����Ĵ���
   λ����UNION�ṹ:  SOC_SM9_INT_CLR_UNION */
#define SOC_SM9_INT_CLR_ADDR(base)                    ((base) + (0x0014))

/* �Ĵ���˵����ALARM���μĴ���
   λ����UNION�ṹ:  SOC_SM9_ALARM_MASK_UNION */
#define SOC_SM9_ALARM_MASK_ADDR(base)                 ((base) + (0x0018))

/* �Ĵ���˵����ALARM״̬�Ĵ���(���κ��ϱ���״̬)
   λ����UNION�ṹ:  SOC_SM9_ALARM_STATUS_UNION */
#define SOC_SM9_ALARM_STATUS_ADDR(base)               ((base) + (0x001C))

/* �Ĵ���˵����ALARM����ǰ״̬�Ĵ���(ʵ��״̬)
   λ����UNION�ṹ:  SOC_SM9_ALARM_NOMASK_STATUS_UNION */
#define SOC_SM9_ALARM_NOMASK_STATUS_ADDR(base)        ((base) + (0x0020))

/* �Ĵ���˵����ALARM����Ĵ���
   λ����UNION�ṹ:  SOC_SM9_ALARM_CLR_UNION */
#define SOC_SM9_ALARM_CLR_ADDR(base)                  ((base) + (0x0024))

/* �Ĵ���˵����SM9�����־�Ĵ���
   λ����UNION�ṹ:  SOC_SM9_RESULT_FLAG_UNION */
#define SOC_SM9_RESULT_FLAG_ADDR(base)                ((base) + (0x0028))

/* �Ĵ���˵����SM9���ʧ�ܱ�־�Ĵ���
   λ����UNION�ṹ:  SOC_SM9_FAILURE_FLAG_UNION */
#define SOC_SM9_FAILURE_FLAG_ADDR(base)               ((base) + (0x002C))

/* �Ĵ���˵����IRAM�߽��ַ�Ĵ���
   λ����UNION�ṹ:  SOC_SM9_IRAM_BOUNDRY_UNION */
#define SOC_SM9_IRAM_BOUNDRY_ADDR(base)               ((base) + (0x0030))

/* �Ĵ���˵����MOD_ADDѡ��Ĵ���
   λ����UNION�ṹ:  SOC_SM9_ADD_SEL_UNION */
#define SOC_SM9_ADD_SEL_ADDR(base)                    ((base) + (0x0034))

/* �Ĵ���˵����IRAM0ָ��Ĵ���
   λ����UNION�ṹ:  SOC_SM9_PC_CNT_IRAM0_UNION */
#define SOC_SM9_PC_CNT_IRAM0_ADDR(base)               ((base) + (0x0038))

/* �Ĵ���˵����IRAM1ָ��Ĵ���
   λ����UNION�ṹ:  SOC_SM9_PC_CNT_IRAM1_UNION */
#define SOC_SM9_PC_CNT_IRAM1_ADDR(base)               ((base) + (0x003C))

/* �Ĵ���˵����IRAM0��DEBUGʱ��ʹ�ܼĴ���
   λ����UNION�ṹ:  SOC_SM9_PC_DEBUG_IRAM0_EN_UNION */
#define SOC_SM9_PC_DEBUG_IRAM0_EN_ADDR(base)          ((base) + (0x0040))

/* �Ĵ���˵����IRAM0��DEBUGʱ�ĵ�ַ�Ĵ���
   λ����UNION�ṹ:  SOC_SM9_PC_DEBUG_IRAM0_UNION */
#define SOC_SM9_PC_DEBUG_IRAM0_ADDR(base)             ((base) + (0x0044))

/* �Ĵ���˵����ģ��P
   λ����UNION�ṹ:  SOC_SM9_MODULUS_P_UNION */
#define SOC_SM9_MODULUS_P_ADDR(base, n)               ((base) + (0x0400+(n)*4))

/* �Ĵ���˵����ģ��N
   λ����UNION�ṹ:  SOC_SM9_MODULUS_N_UNION */
#define SOC_SM9_MODULUS_N_ADDR(base, n)               ((base) + (0x0420+(n)*4))

/* �Ĵ���˵����IRAM(4096*64bit)��д�Ĵ���
   λ����UNION�ṹ:  SOC_SM9_IRAM_UNION */
#define SOC_SM9_IRAM_ADDR(base, m)                    ((base) + (0x0800+(m)*4))

/* �Ĵ���˵����DRAM(3520*256bit)��д�Ĵ���
   λ����UNION�ṹ:  SOC_SM9_DRAM_UNION */
#define SOC_SM9_DRAM_ADDR(base, k)                    ((base) + (0x8800+(k)*4))





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
                     (1/1) reg_define
 ****************************************************************************/
/*****************************************************************************
 �ṹ��    : SOC_SM9_BUSY_UNION
 �ṹ˵��  : BUSY �Ĵ����ṹ���塣��ַƫ����:0x0000����ֵ:0x00000000�����:32
 �Ĵ���˵��: æ״̬�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sm9_busy : 1;  /* bit[0]   : SM9ģ���æ״̬��־
                                                    0x1��ʾģ�鴦��æ״̬
                                                    0x0��ʾģ�鴦�ڿ���״̬
                                                   ˵����CPU����ִ�в���ǰ��ѯ��ֵ��Ϊ0ʱ��������ִ��ĳ������Ӳ����ʼִ�в����ڼ䱣��Ϊæ״̬����ɺ��Ϊ��״̬��CPU�ɶ�ȡ������� */
        unsigned int  reserved : 31; /* bit[1-31]: ���� */
    } reg;
} SOC_SM9_BUSY_UNION;
#endif
#define SOC_SM9_BUSY_sm9_busy_START  (0)
#define SOC_SM9_BUSY_sm9_busy_END    (0)


/*****************************************************************************
 �ṹ��    : SOC_SM9_START_UNION
 �ṹ˵��  : START �Ĵ����ṹ���塣��ַƫ����:0x0004����ֵ:0x00000000�����:32
 �Ĵ���˵��: ���������Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sm9_start : 1;  /* bit[0]   : CPU��������
                                                    0x1 ������ִ�в�����
                                                    0x0��������ִ�С�
                                                    ˵����CPU����������Ӳ����ʼִ����Ӧ�Ĳ�����SM9ִ�в����ڼ�CPU�������øüĴ��� */
        unsigned int  reserved  : 31; /* bit[1-31]: ���� */
    } reg;
} SOC_SM9_START_UNION;
#endif
#define SOC_SM9_START_sm9_start_START  (0)
#define SOC_SM9_START_sm9_start_END    (0)


/*****************************************************************************
 �ṹ��    : SOC_SM9_INT_MASK_UNION
 �ṹ˵��  : INT_MASK �Ĵ����ṹ���塣��ַƫ����:0x0008����ֵ:0x00000001�����:32
 �Ĵ���˵��: �ж����μĴ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sm9_int_mask : 1;  /* bit[0]   : 1�����θ��ж�Դ
                                                       0�������θ��ж�Դ */
        unsigned int  reserved     : 31; /* bit[1-31]: ���� */
    } reg;
} SOC_SM9_INT_MASK_UNION;
#endif
#define SOC_SM9_INT_MASK_sm9_int_mask_START  (0)
#define SOC_SM9_INT_MASK_sm9_int_mask_END    (0)


/*****************************************************************************
 �ṹ��    : SOC_SM9_INT_STATUS_UNION
 �ṹ˵��  : INT_STATUS �Ĵ����ṹ���塣��ַƫ����:0x000C����ֵ:0x00000000�����:32
 �Ĵ���˵��: �ж�״̬�Ĵ���(���κ��ϱ���״̬)
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sm9_int_status : 1;  /* bit[0]   : mask��������ж� ״̬�Ĵ���
                                                         1������ж���Ч����ʾ�������
                                                         0������ж���Ч���������߼����ڴ���Ҳ�п����Ǵ�����ɣ������жϱ�mask������δ�������� */
        unsigned int  reserved       : 31; /* bit[1-31]: ���� */
    } reg;
} SOC_SM9_INT_STATUS_UNION;
#endif
#define SOC_SM9_INT_STATUS_sm9_int_status_START  (0)
#define SOC_SM9_INT_STATUS_sm9_int_status_END    (0)


/*****************************************************************************
 �ṹ��    : SOC_SM9_INT_NOMASK_STATUS_UNION
 �ṹ˵��  : INT_NOMASK_STATUS �Ĵ����ṹ���塣��ַƫ����:0x0010����ֵ:0x00000000�����:32
 �Ĵ���˵��: �ж�����ǰ״̬�Ĵ���(ʵ��״̬)
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sm9_int_nomsk_status : 1;  /* bit[0]   : maskǰ(�����������ж�) ��������ж� ״̬�Ĵ���
                                                               1������ж���Ч����ʾ�������
                                                               0������ж���Ч���߼����ڴ����δ�������� */
        unsigned int  reserved             : 31; /* bit[1-31]: ���� */
    } reg;
} SOC_SM9_INT_NOMASK_STATUS_UNION;
#endif
#define SOC_SM9_INT_NOMASK_STATUS_sm9_int_nomsk_status_START  (0)
#define SOC_SM9_INT_NOMASK_STATUS_sm9_int_nomsk_status_END    (0)


/*****************************************************************************
 �ṹ��    : SOC_SM9_INT_CLR_UNION
 �ṹ˵��  : INT_CLR �Ĵ����ṹ���塣��ַƫ����:0x0014����ֵ:0x00000000�����:32
 �Ĵ���˵��: �ж�����Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sm9_int_clr : 1;  /* bit[0]   : ˵�������д0x1�����Ӧ�ж�Դ���߼�ֻ���յ�д0x1��ʱ�̲Ŷ��ж�Դ�������㡣 */
        unsigned int  reserved    : 31; /* bit[1-31]: ���� */
    } reg;
} SOC_SM9_INT_CLR_UNION;
#endif
#define SOC_SM9_INT_CLR_sm9_int_clr_START  (0)
#define SOC_SM9_INT_CLR_sm9_int_clr_END    (0)


/*****************************************************************************
 �ṹ��    : SOC_SM9_ALARM_MASK_UNION
 �ṹ˵��  : ALARM_MASK �Ĵ����ṹ���塣��ַƫ����:0x0018����ֵ:0x00000001�����:32
 �Ĵ���˵��: ALARM���μĴ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sm9_alarm_mask : 1;  /* bit[0]   : SM9 ALARM����
                                                         0x1�����Σ������ALARM
                                                         0x0�������� */
        unsigned int  reserved       : 31; /* bit[1-31]: ���� */
    } reg;
} SOC_SM9_ALARM_MASK_UNION;
#endif
#define SOC_SM9_ALARM_MASK_sm9_alarm_mask_START  (0)
#define SOC_SM9_ALARM_MASK_sm9_alarm_mask_END    (0)


/*****************************************************************************
 �ṹ��    : SOC_SM9_ALARM_STATUS_UNION
 �ṹ˵��  : ALARM_STATUS �Ĵ����ṹ���塣��ַƫ����:0x001C����ֵ:0x00000000�����:32
 �Ĵ���˵��: ALARM״̬�Ĵ���(���κ��ϱ���״̬)
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sm9_alarm_status : 1;  /* bit[0]   : SM9���κ� ALARM ״̬
                                                           1����⵽alarm
                                                           0��δ���alarm */
        unsigned int  reserved         : 31; /* bit[1-31]: ���� */
    } reg;
} SOC_SM9_ALARM_STATUS_UNION;
#endif
#define SOC_SM9_ALARM_STATUS_sm9_alarm_status_START  (0)
#define SOC_SM9_ALARM_STATUS_sm9_alarm_status_END    (0)


/*****************************************************************************
 �ṹ��    : SOC_SM9_ALARM_NOMASK_STATUS_UNION
 �ṹ˵��  : ALARM_NOMASK_STATUS �Ĵ����ṹ���塣��ַƫ����:0x0020����ֵ:0x00000000�����:32
 �Ĵ���˵��: ALARM����ǰ״̬�Ĵ���(ʵ��״̬)
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sm9_alarm_nomask_status : 1;  /* bit[0]   : SM9ԭʼALARM ״̬
                                                                  1����⵽ԭʼalarm
                                                                  0��δ��⵽ԭʼalarm */
        unsigned int  reserved                : 31; /* bit[1-31]: ���� */
    } reg;
} SOC_SM9_ALARM_NOMASK_STATUS_UNION;
#endif
#define SOC_SM9_ALARM_NOMASK_STATUS_sm9_alarm_nomask_status_START  (0)
#define SOC_SM9_ALARM_NOMASK_STATUS_sm9_alarm_nomask_status_END    (0)


/*****************************************************************************
 �ṹ��    : SOC_SM9_ALARM_CLR_UNION
 �ṹ˵��  : ALARM_CLR �Ĵ����ṹ���塣��ַƫ����:0x0024����ֵ:0x00000000�����:32
 �Ĵ���˵��: ALARM����Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sm9_alarm_clr : 1;  /* bit[0]   : ˵�������д0x1���ALARMԴ������ֵ��Ч���߼�ֻ���յ�д0x1��ʱ�̲Ŷ�ALRAM�������㡣 */
        unsigned int  reserved      : 31; /* bit[1-31]: ���� */
    } reg;
} SOC_SM9_ALARM_CLR_UNION;
#endif
#define SOC_SM9_ALARM_CLR_sm9_alarm_clr_START  (0)
#define SOC_SM9_ALARM_CLR_sm9_alarm_clr_END    (0)


/*****************************************************************************
 �ṹ��    : SOC_SM9_RESULT_FLAG_UNION
 �ṹ˵��  : RESULT_FLAG �Ĵ����ṹ���塣��ַƫ����:0x0028����ֵ:0x00000000�����:32
 �Ĵ���˵��: SM9�����־�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sm9_result_flag : 4;  /* bit[0-3] : �����־
                                                          0x00����ʼ������״̬���޽��
                                                          0x05������ɹ�����RAM����ʱRAM������Ч����������RAM���н�����ݡ�
                                                          0x0a������ʧ�ܣ��޽�����ݡ�(ʧ��ԭ����Ĵ���SM9_FAILURE_FLAG)
                                                          ������������
                                                          ˵��������SM9_START������������SM9_BUSY��æ��Ϊ��æʱ�ٶ��Ĵ����� */
        unsigned int  reserved        : 28; /* bit[4-31]: ������ */
    } reg;
} SOC_SM9_RESULT_FLAG_UNION;
#endif
#define SOC_SM9_RESULT_FLAG_sm9_result_flag_START  (0)
#define SOC_SM9_RESULT_FLAG_sm9_result_flag_END    (3)


/*****************************************************************************
 �ṹ��    : SOC_SM9_FAILURE_FLAG_UNION
 �ṹ˵��  : FAILURE_FLAG �Ĵ����ṹ���塣��ַƫ����:0x002C����ֵ:0x00000000�����:32
 �Ĵ���˵��: SM9���ʧ�ܱ�־�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sm9_failure_flag : 3;  /* bit[0-2] : ���ʧ��ԭ��Ĵ���
                                                           0x0����ʼ������״̬���޽��
                                                           0x1: ģ���޽��
                                                           0x4:��˻��ӽ��Ϊ����Զ��
                                                           ������������ */
        unsigned int  reserved         : 29; /* bit[3-31]: ������ */
    } reg;
} SOC_SM9_FAILURE_FLAG_UNION;
#endif
#define SOC_SM9_FAILURE_FLAG_sm9_failure_flag_START  (0)
#define SOC_SM9_FAILURE_FLAG_sm9_failure_flag_END    (2)


/*****************************************************************************
 �ṹ��    : SOC_SM9_IRAM_BOUNDRY_UNION
 �ṹ˵��  : IRAM_BOUNDRY �Ĵ����ṹ���塣��ַƫ����:0x0030����ֵ:0x00000800�����:32
 �Ĵ���˵��: IRAM�߽��ַ�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sm9_iram_boundry : 12; /* bit[0-11] : IRAM0/IRAM1���߼��߽磬�ײ�����ָ������￪ʼ���� */
        unsigned int  reserved         : 20; /* bit[12-31]: ������ */
    } reg;
} SOC_SM9_IRAM_BOUNDRY_UNION;
#endif
#define SOC_SM9_IRAM_BOUNDRY_sm9_iram_boundry_START  (0)
#define SOC_SM9_IRAM_BOUNDRY_sm9_iram_boundry_END    (11)


/*****************************************************************************
 �ṹ��    : SOC_SM9_ADD_SEL_UNION
 �ṹ˵��  : ADD_SEL �Ĵ����ṹ���塣��ַƫ����:0x0034����ֵ:0x00000000�����:32
 �Ĵ���˵��: MOD_ADDѡ��Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sm9_add_sel : 1;  /* bit[0]   : ģ��ģ��ѡ���źţ�
                                                      0x0��ʹ�ø�����ģ��ģ�飻
                                                      0x1��ʹ��RSA��ģ��ģ�顣 */
        unsigned int  reserved    : 31; /* bit[1-31]: ������ */
    } reg;
} SOC_SM9_ADD_SEL_UNION;
#endif
#define SOC_SM9_ADD_SEL_sm9_add_sel_START  (0)
#define SOC_SM9_ADD_SEL_sm9_add_sel_END    (0)


/*****************************************************************************
 �ṹ��    : SOC_SM9_PC_CNT_IRAM0_UNION
 �ṹ˵��  : PC_CNT_IRAM0 �Ĵ����ṹ���塣��ַƫ����:0x0038����ֵ:0x00000000�����:32
 �Ĵ���˵��: IRAM0ָ��Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  pc_cnt_iram0 : 12; /* bit[0-11] : IRAM0��תָ������� */
        unsigned int  reserved     : 20; /* bit[12-31]: ������ */
    } reg;
} SOC_SM9_PC_CNT_IRAM0_UNION;
#endif
#define SOC_SM9_PC_CNT_IRAM0_pc_cnt_iram0_START  (0)
#define SOC_SM9_PC_CNT_IRAM0_pc_cnt_iram0_END    (11)


/*****************************************************************************
 �ṹ��    : SOC_SM9_PC_CNT_IRAM1_UNION
 �ṹ˵��  : PC_CNT_IRAM1 �Ĵ����ṹ���塣��ַƫ����:0x003C����ֵ:0x00000000�����:32
 �Ĵ���˵��: IRAM1ָ��Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  pc_cnt_iram1 : 12; /* bit[0-11] : IRAM1��תָ������� */
        unsigned int  reserved     : 20; /* bit[12-31]: ������ */
    } reg;
} SOC_SM9_PC_CNT_IRAM1_UNION;
#endif
#define SOC_SM9_PC_CNT_IRAM1_pc_cnt_iram1_START  (0)
#define SOC_SM9_PC_CNT_IRAM1_pc_cnt_iram1_END    (11)


/*****************************************************************************
 �ṹ��    : SOC_SM9_PC_DEBUG_IRAM0_EN_UNION
 �ṹ˵��  : PC_DEBUG_IRAM0_EN �Ĵ����ṹ���塣��ַƫ����:0x0040����ֵ:0x00000000�����:32
 �Ĵ���˵��: IRAM0��DEBUGʱ��ʹ�ܼĴ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  pc_debug_iram0_en : 1;  /* bit[0]   : SM9 IRAM0 DEBUG��ʹ���ź�
                                                            0x0:��ʹ��IRAM0��DEBUG����
                                                            0x1:ʹ��IRAM0��DEBUG���� */
        unsigned int  reserved          : 31; /* bit[1-31]: ������ */
    } reg;
} SOC_SM9_PC_DEBUG_IRAM0_EN_UNION;
#endif
#define SOC_SM9_PC_DEBUG_IRAM0_EN_pc_debug_iram0_en_START  (0)
#define SOC_SM9_PC_DEBUG_IRAM0_EN_pc_debug_iram0_en_END    (0)


/*****************************************************************************
 �ṹ��    : SOC_SM9_PC_DEBUG_IRAM0_UNION
 �ṹ˵��  : PC_DEBUG_IRAM0 �Ĵ����ṹ���塣��ַƫ����:0x0044����ֵ:0x00000000�����:32
 �Ĵ���˵��: IRAM0��DEBUGʱ�ĵ�ַ�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  pc_debug_iram0 : 12; /* bit[0-11] : SM9 IRAM0 DEBUG�ĵ�ַ�ź�
                                                          ��IRAM0�е�ָ��ִ�е��üĴ������õĵ�ַʱ��ֹͣ���㣨�õ�ַ�����ָ�������ִ�У� */
        unsigned int  reserved       : 20; /* bit[12-31]: ������ */
    } reg;
} SOC_SM9_PC_DEBUG_IRAM0_UNION;
#endif
#define SOC_SM9_PC_DEBUG_IRAM0_pc_debug_iram0_START  (0)
#define SOC_SM9_PC_DEBUG_IRAM0_pc_debug_iram0_END    (11)


/*****************************************************************************
 �ṹ��    : SOC_SM9_MODULUS_P_UNION
 �ṹ˵��  : MODULUS_P �Ĵ����ṹ���塣��ַƫ����:0x0400+(n)*4����ֵ:0x00000000�����:32
 �Ĵ���˵��: ģ��P
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  modulus_p : 32; /* bit[0-31]: CPU����ģ��P���ݼĴ�������������8��32bit���ݣ�P�ĸ�bit�����ڸߵ�ַ�С�д��˳��Ϊ�����32bit��ʼд�����32bit���д��
                                                    ��ַ���n��Χ[0,7] */
    } reg;
} SOC_SM9_MODULUS_P_UNION;
#endif
#define SOC_SM9_MODULUS_P_modulus_p_START  (0)
#define SOC_SM9_MODULUS_P_modulus_p_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_SM9_MODULUS_N_UNION
 �ṹ˵��  : MODULUS_N �Ĵ����ṹ���塣��ַƫ����:0x0420+(n)*4����ֵ:0x00000000�����:32
 �Ĵ���˵��: ģ��N
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  modulus_n : 32; /* bit[0-31]: CPU����ģ��N���ݼĴ�������������8��32bit���ݣ�P�ĸ�bit�����ڸߵ�ַ�С�д��˳��Ϊ�����32bit��ʼд�����32bit���д��
                                                    ��ַ���n��Χ[0,7] */
    } reg;
} SOC_SM9_MODULUS_N_UNION;
#endif
#define SOC_SM9_MODULUS_N_modulus_n_START  (0)
#define SOC_SM9_MODULUS_N_modulus_n_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_SM9_IRAM_UNION
 �ṹ˵��  : IRAM �Ĵ����ṹ���塣��ַƫ����:0x0800+(m)*4����ֵ:0x00000000�����:32
 �Ĵ���˵��: IRAM(4096*64bit)��д�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  iram : 32; /* bit[0-31]: CPU����IRAM���ݼĴ�����оƬ�ڲ�RAMΪ48bitλ�������64bitΪ��λ��д����(n��ż����ʼ)����ʼֵ��IRAM��ĳ�ʼֵ����һ����0��
                                               ��ַ���m��Χ[0,8191]��64λ���������64bit��ʹ��С��ģʽ */
    } reg;
} SOC_SM9_IRAM_UNION;
#endif
#define SOC_SM9_IRAM_iram_START  (0)
#define SOC_SM9_IRAM_iram_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_SM9_DRAM_UNION
 �ṹ˵��  : DRAM �Ĵ����ṹ���塣��ַƫ����:0x8800+(k)*4����ֵ:0x00000000�����:32
 �Ĵ���˵��: DRAM(3520*256bit)��д�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  dram : 32; /* bit[0-31]: CPU����DRAM���ݼĴ�����оƬ�ڲ�RAMΪ256bitλ�������256bitΪ��λ��д����(n��8����������ʼ)����ʼֵ��DRAM��ĳ�ʼֵ����һ����0��
                                               ��ַ���k��Χ[0,28159]��256λ���������256bit��ʹ��С��ģʽ */
    } reg;
} SOC_SM9_DRAM_UNION;
#endif
#define SOC_SM9_DRAM_dram_START  (0)
#define SOC_SM9_DRAM_dram_END    (31)






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

#endif /* end of soc_sm9_interface.h */
