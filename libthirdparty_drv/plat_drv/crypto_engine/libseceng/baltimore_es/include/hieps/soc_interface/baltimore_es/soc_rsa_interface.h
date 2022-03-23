/******************************************************************************

                 ��Ȩ���� (C), 2001-2019, ��Ϊ�������޹�˾

 ******************************************************************************
  �� �� ��   : soc_rsa_interface.h
  �� �� ��   : ����
  ��    ��   : Excel2Code
  ��������   : 2019-10-26 10:53:24
  ����޸�   :
  ��������   : �ӿ�ͷ�ļ�
  �����б�   :
  �޸���ʷ   :
  1.��    ��   : 2019��10��26��
    ��    ��   : l00249396
    �޸�����   : �ӡ�HiEPS V200 nmanager�Ĵ����ֲ�_RSA.xml���Զ�����

******************************************************************************/

/*****************************************************************************
  1 ����ͷ�ļ�����
*****************************************************************************/

#ifndef __SOC_RSA_INTERFACE_H__
#define __SOC_RSA_INTERFACE_H__

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
   λ����UNION�ṹ:  SOC_RSA_BUSY_UNION */
#define SOC_RSA_BUSY_ADDR(base)                       ((base) + (0x0000))

/* �Ĵ���˵��������ģʽ�Ĵ���
   λ����UNION�ṹ:  SOC_RSA_WORK_MODE_UNION */
#define SOC_RSA_WORK_MODE_ADDR(base)                  ((base) + (0x0004))

/* �Ĵ���˵�������������Ĵ���
   λ����UNION�ṹ:  SOC_RSA_START_UNION */
#define SOC_RSA_START_ADDR(base)                      ((base) + (0x0008))

/* �Ĵ���˵��������ʹ�ܼĴ���(�ڲ�������)
   λ����UNION�ṹ:  SOC_RSA_DEBUG_EN_UNION */
#define SOC_RSA_DEBUG_EN_ADDR(base)                   ((base) + (0x0010))

/* �Ĵ���˵����RSA_RNG_OPT���üĴ���(testchip�ڲ�ʹ��)
   λ����UNION�ṹ:  SOC_RSA_RNG_OPTION_UNION */
#define SOC_RSA_RNG_OPTION_ADDR(base)                 ((base) + (0x0014))

/* �Ĵ���˵����NEW ALARM���μĴ���
   λ����UNION�ṹ:  SOC_RSA_NEW_ALARM_MASK_UNION */
#define SOC_RSA_NEW_ALARM_MASK_ADDR(base)             ((base) + (0x0018))

/* �Ĵ���˵�����ж����μĴ���
   λ����UNION�ṹ:  SOC_RSA_INT_MASK_UNION */
#define SOC_RSA_INT_MASK_ADDR(base)                   ((base) + (0x0020))

/* �Ĵ���˵�����ж�״̬�Ĵ���(���κ��ϱ���״̬)
   λ����UNION�ṹ:  SOC_RSA_INT_STATUS_UNION */
#define SOC_RSA_INT_STATUS_ADDR(base)                 ((base) + (0x0024))

/* �Ĵ���˵�����ж�����ǰ״̬�Ĵ���(ʵ��״̬)
   λ����UNION�ṹ:  SOC_RSA_INT_NOMASK_STATUS_UNION */
#define SOC_RSA_INT_NOMASK_STATUS_ADDR(base)          ((base) + (0x0028))

/* �Ĵ���˵�����ж�����Ĵ���
   λ����UNION�ṹ:  SOC_RSA_INT_CLR_UNION */
#define SOC_RSA_INT_CLR_ADDR(base)                    ((base) + (0x002C))

/* �Ĵ���˵����ALARM���μĴ���
   λ����UNION�ṹ:  SOC_RSA_ALARM_MASK_UNION */
#define SOC_RSA_ALARM_MASK_ADDR(base)                 ((base) + (0x0030))

/* �Ĵ���˵����ALARM״̬�Ĵ���(���κ��ϱ���״̬)
   λ����UNION�ṹ:  SOC_RSA_ALARM_STATUS_UNION */
#define SOC_RSA_ALARM_STATUS_ADDR(base)               ((base) + (0x0034))

/* �Ĵ���˵����ALARM����ǰ״̬�Ĵ���(ʵ��״̬)
   λ����UNION�ṹ:  SOC_RSA_ALARM_NOMASK_STATUS_UNION */
#define SOC_RSA_ALARM_NOMASK_STATUS_ADDR(base)        ((base) + (0x0038))

/* �Ĵ���˵����ALARM����Ĵ���
   λ����UNION�ṹ:  SOC_RSA_ALARM_CLR_UNION */
#define SOC_RSA_ALARM_CLR_ADDR(base)                  ((base) + (0x003C))

/* �Ĵ���˵����RSA�����־�Ĵ���
   λ����UNION�ṹ:  SOC_RSA_RESULT_FLAG_UNION */
#define SOC_RSA_RESULT_FLAG_ADDR(base)                ((base) + (0x0040))

/* �Ĵ���˵����RSA���ʧ�ܱ�־�Ĵ���
   λ����UNION�ṹ:  SOC_RSA_FAILURE_FLAG_UNION */
#define SOC_RSA_FAILURE_FLAG_ADDR(base)               ((base) + (0x0044))

/* �Ĵ���˵����ͳ������Ĵ���
   λ����UNION�ṹ:  SOC_RSA_STAT_CLR_UNION */
#define SOC_RSA_STAT_CLR_ADDR(base)                   ((base) + (0x0050))

/* �Ĵ���˵����RSA����Կ����Ĵ���
   λ����UNION�ṹ:  SOC_RSA_KEY_MSK_UNION */
#define SOC_RSA_KEY_MSK_ADDR(base)                    ((base) + (0x0054))

/* �Ĵ���˵����RSA����Կ���ݼĴ���
   λ����UNION�ṹ:  SOC_RSA_KEY_BACKUP_UNION */
#define SOC_RSA_KEY_BACKUP_ADDR(base)                 ((base) + (0x0058))

/* �Ĵ���˵����RSA�ļĴ���lock�Ĵ���
   λ����UNION�ṹ:  SOC_RSA_LOCK_UNION */
#define SOC_RSA_LOCK_ADDR(base)                       ((base) + (0x005C))

/* �Ĵ���˵����RSA����Կlock�Ĵ���
   λ����UNION�ṹ:  SOC_RSA_KEY_LOCK_UNION */
#define SOC_RSA_KEY_LOCK_ADDR(base)                   ((base) + (0x0060))

/* �Ĵ���˵����RSA�İ汾�Ĵ���
   λ����UNION�ṹ:  SOC_RSA_VERSION_ID_UNION */
#define SOC_RSA_VERSION_ID_ADDR(base)                 ((base) + (0x007C))

/* �Ĵ���˵����RSAģ�������λΪ1�Ĵ���
   λ����UNION�ṹ:  SOC_RSA_LSB_N_EQUAL_ONE_UNION */
#define SOC_RSA_LSB_N_EQUAL_ONE_ADDR(base)            ((base) + (0x0080))

/* �Ĵ���˵����MRAM(4096bit)��д�Ĵ���
   λ����UNION�ṹ:  SOC_RSA_MRAM_UNION */
#define SOC_RSA_MRAM_ADDR(base, n)                    ((base) + (0x0200+(n)*4))

/* �Ĵ���˵����NRAM(4096bit)��д�Ĵ���
   λ����UNION�ṹ:  SOC_RSA_NRAM_UNION */
#define SOC_RSA_NRAM_ADDR(base, n)                    ((base) + (0x0600+(n)*4))

/* �Ĵ���˵����KRAM(4096bit)��д�Ĵ���
   λ����UNION�ṹ:  SOC_RSA_KRAM_UNION */
#define SOC_RSA_KRAM_ADDR(base, n)                    ((base) + (0x0A00+(n)*4))

/* �Ĵ���˵����RRAM(4096bit)��д�Ĵ���
   λ����UNION�ṹ:  SOC_RSA_RRAM_UNION */
#define SOC_RSA_RRAM_ADDR(base, n)                    ((base) + (0x0E00+(n)*4))





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
 �ṹ��    : SOC_RSA_BUSY_UNION
 �ṹ˵��  : BUSY �Ĵ����ṹ���塣��ַƫ����:0x0000����ֵ:0x00000000�����:32
 �Ĵ���˵��: æ״̬�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  rsa_busy : 1;  /* bit[0]   : RSAģ���æ״̬��־
                                                    0x1��ʾģ�鴦��æ״̬
                                                    0x0��ʾģ�鴦�ڿ���״̬
                                                   ˵����CPU����ִ�в���ǰ��ѯ��ֵ��Ϊ0ʱ��������ִ��ĳ������Ӳ����ʼִ�в����ڼ䱣��Ϊæ״̬����ɺ��Ϊ��״̬��CPU�ɶ�ȡ������� */
        unsigned int  reserved : 31; /* bit[1-31]: ���� */
    } reg;
} SOC_RSA_BUSY_UNION;
#endif
#define SOC_RSA_BUSY_rsa_busy_START  (0)
#define SOC_RSA_BUSY_rsa_busy_END    (0)


/*****************************************************************************
 �ṹ��    : SOC_RSA_WORK_MODE_UNION
 �ṹ˵��  : WORK_MODE �Ĵ����ṹ���塣��ַƫ����:0x0004����ֵ:0x00000400�����:32
 �Ĵ���˵��: ����ģʽ�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  opcode   : 4;  /* bit[0-3]  : RSAִ�в����ڼ�CPU�������øüĴ���
                                                    BIT[3:0]������ģʽ
                                                    4'0��RSAģ��
                                                    4'1��RSA��Կ���� (����Կ����)
                                                    4'2��RSA��Կ���� (������Կ����)
                                                    4'd3���ɸ�����ģ�ӣ�
                                                    4'd4����Ԫ��ת����
                                                    4'd5���ɸ�����ģ����
                                                    4'd6���ɸ�����ģ�ˣ�
                                                    4'd7��ģ�棻 
                                                    4'd8����ģ�� 
                                                    4'd9�������˷���
                                                    4'd10��PQ����
                                                    4'd12����ˣ� 
                                                    4'd13����ӣ�
                                                    4'd15����RAM������0���� (���������Ҫȷ���Ƿ���Ҫ��0����)
                                                    ����ֵ��Ϊ�Ƿ����ã��߼������alarm�澯�� */
        unsigned int  reserved_0: 4;  /* bit[4-7]  : ���� */
        unsigned int  mode     : 8;  /* bit[8-15] : RSAִ�в����ڼ�CPU�������øüĴ���
                                                    ģʽ(������Ӧ����Կ���ȵ�ģʽ������RAM��ģʽ)
                                                    RSAģ��ʱ��������Կλ���Ӧ����ֵ���£�
                                                     8: 512
                                                    16: 1024
                                                    18: 1152
                                                    31: 1984
                                                    32: 2048
                                                    48: 3072
                                                    64: 4096
                                                    ��ע����Ч���÷�ΧΪ8~64��������������λΪ64bit������Ϊ�Ƿ����á�
                                                    RSA��Կ����ʱ������ֵ��Ӧ��Կ���£�
                                                     8: 512
                                                    16: 1024
                                                    18: 1152
                                                    31: 1984
                                                    32: 2048
                                                    48: 3072
                                                    64: 4096
                                                    ��ע����Ч���÷�ΧΪ8~64��������������λΪ64bit������Ϊ�Ƿ����á�
                                                    ��ˣ�������Կλ���Ӧ����ֵ���£�
                                                     4: 256 (���<=256bitʱ��256bit��˲��������õ�����Ҳ��256bit,����ĸ�λ��0����160/192/224λ��ĵ��)
                                                     6: 384
                                                     9: 576 (���λ��Ϊ513~576bitʱ ��576bit��˲��������õ�����Ҳ��576bit,����ĸ�λ��0)
                                                    ��ע���㷨δ˵��������λ��֧�֣��ޱ�׼�������ݽ�����֤����
                                                    ��RAM������0����ʱ RAM����ģʽ��bit��������
                                                     mode[0](��Ӧ�Ĵ���bit8 ) Ϊ1ʱ����MRAM
                                                     mode[1](��Ӧ�Ĵ���bit9 ) Ϊ1ʱ����KRAM
                                                     mode[2](��Ӧ�Ĵ���bit10) Ϊ1ʱ����NRAM
                                                     mode[3](��Ӧ�Ĵ���bit11) Ϊ1ʱ����RRAM
                                                     mode[4](��Ӧ�Ĵ���bit12) Ϊ1ʱ����PKAֻ�ڲ�ʹ�õ�RAM(������MRAM/KRAM/NRAM/RRAM)
                                                     mode[7:5](��Ӧ�Ĵ���bit13~15) ������
                                                    ��ģ������ģ a mod b ���õĳ��ȿ��Ե�128��a����Ч����������128��
                                                     ����b�������Ч���������64������64�ĵĿռ��貹�㣩��
                                                     ͬʱ�������Ҳ��64�� */
        unsigned int  reserved_1: 16; /* bit[16-31]: ���� */
    } reg;
} SOC_RSA_WORK_MODE_UNION;
#endif
#define SOC_RSA_WORK_MODE_opcode_START    (0)
#define SOC_RSA_WORK_MODE_opcode_END      (3)
#define SOC_RSA_WORK_MODE_mode_START      (8)
#define SOC_RSA_WORK_MODE_mode_END        (15)


/*****************************************************************************
 �ṹ��    : SOC_RSA_START_UNION
 �ṹ˵��  : START �Ĵ����ṹ���塣��ַƫ����:0x0008����ֵ:0x00000000�����:32
 �Ĵ���˵��: ���������Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  rsa_start : 4;  /* bit[0-3] : CPU��������
                                                    0xA ������ִ�в�����
                                                    ������������ִ�С�
                                                    ˵����CPU����������Ӳ����ʼִ����Ӧ�Ĳ�����RSAִ�в����ڼ�CPU�������øüĴ��� */
        unsigned int  reserved  : 28; /* bit[4-31]: ���� */
    } reg;
} SOC_RSA_START_UNION;
#endif
#define SOC_RSA_START_rsa_start_START  (0)
#define SOC_RSA_START_rsa_start_END    (3)


/*****************************************************************************
 �ṹ��    : SOC_RSA_DEBUG_EN_UNION
 �ṹ˵��  : DEBUG_EN �Ĵ����ṹ���塣��ַƫ����:0x0010����ֵ:0x0000000A�����:32
 �Ĵ���˵��: ����ʹ�ܼĴ���(�ڲ�������)
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  rsa_debug_en : 4;  /* bit[0-3] : CPU���õ���ʹ�ܣ���OTP RSA����ʹ��ʱ�üĴ�����Ч������̶�Ϊ���Խ�ֹ
                                                       0x5������ʹ�ܣ�δ��������ʱKRAM�������ܶ�ȡ��
                                                       0xa�����Խ�ֹ, KRAM�����ݲ��ܶ�ȡ�� */
        unsigned int  reserved     : 28; /* bit[4-31]: ���� */
    } reg;
} SOC_RSA_DEBUG_EN_UNION;
#endif
#define SOC_RSA_DEBUG_EN_rsa_debug_en_START  (0)
#define SOC_RSA_DEBUG_EN_rsa_debug_en_END    (3)


/*****************************************************************************
 �ṹ��    : SOC_RSA_RNG_OPTION_UNION
 �ṹ˵��  : RNG_OPTION �Ĵ����ṹ���塣��ַƫ����:0x0014����ֵ:0x00000001�����:32
 �Ĵ���˵��: RSA_RNG_OPT���üĴ���(testchip�ڲ�ʹ��)
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  rsa_rng_option : 2;  /* bit[0-1] : ����RSA��ECC��������ѡ������ڲ������á�
                                                         0��ѡ��16bit�����
                                                         1��ѡ��32bit�����
                                                         2��ѡ��48bit�����
                                                         3��ѡ��64bit����� */
        unsigned int  reserved       : 30; /* bit[2-31]: ���� */
    } reg;
} SOC_RSA_RNG_OPTION_UNION;
#endif
#define SOC_RSA_RNG_OPTION_rsa_rng_option_START  (0)
#define SOC_RSA_RNG_OPTION_rsa_rng_option_END    (1)


/*****************************************************************************
 �ṹ��    : SOC_RSA_NEW_ALARM_MASK_UNION
 �ṹ˵��  : NEW_ALARM_MASK �Ĵ����ṹ���塣��ַƫ����:0x0018����ֵ:0x00000005�����:32
 �Ĵ���˵��: NEW ALARM���μĴ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  rsa_new_alarm_mask : 4;  /* bit[0-3] : ������ALARMԴ����
                                                             0x5�����Σ������ALARM
                                                             ������������ */
        unsigned int  reserved           : 28; /* bit[4-31]: ���� */
    } reg;
} SOC_RSA_NEW_ALARM_MASK_UNION;
#endif
#define SOC_RSA_NEW_ALARM_MASK_rsa_new_alarm_mask_START  (0)
#define SOC_RSA_NEW_ALARM_MASK_rsa_new_alarm_mask_END    (3)


/*****************************************************************************
 �ṹ��    : SOC_RSA_INT_MASK_UNION
 �ṹ˵��  : INT_MASK �Ĵ����ṹ���塣��ַƫ����:0x0020����ֵ:0x00000001�����:32
 �Ĵ���˵��: �ж����μĴ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  finish_int_mask : 1;  /* bit[0]    : 1�����θ��ж�Դ
                                                           0�������θ��ж�Դ */
        unsigned int  reserved_0      : 15; /* bit[1-15] : ���� */
        unsigned int  reserved_1      : 16; /* bit[16-31]: ���� */
    } reg;
} SOC_RSA_INT_MASK_UNION;
#endif
#define SOC_RSA_INT_MASK_finish_int_mask_START  (0)
#define SOC_RSA_INT_MASK_finish_int_mask_END    (0)


/*****************************************************************************
 �ṹ��    : SOC_RSA_INT_STATUS_UNION
 �ṹ˵��  : INT_STATUS �Ĵ����ṹ���塣��ַƫ����:0x0024����ֵ:0x00000000�����:32
 �Ĵ���˵��: �ж�״̬�Ĵ���(���κ��ϱ���״̬)
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  finish_int_status : 1;  /* bit[0]    : mask��������ж� ״̬�Ĵ���
                                                             1������ж���Ч����ʾ�������
                                                             0������ж���Ч���������߼����ڴ���Ҳ�п����Ǵ�����ɣ������жϱ�mask������δ�������� */
        unsigned int  reserved_0        : 15; /* bit[1-15] : ���� */
        unsigned int  reserved_1        : 16; /* bit[16-31]: ���� */
    } reg;
} SOC_RSA_INT_STATUS_UNION;
#endif
#define SOC_RSA_INT_STATUS_finish_int_status_START  (0)
#define SOC_RSA_INT_STATUS_finish_int_status_END    (0)


/*****************************************************************************
 �ṹ��    : SOC_RSA_INT_NOMASK_STATUS_UNION
 �ṹ˵��  : INT_NOMASK_STATUS �Ĵ����ṹ���塣��ַƫ����:0x0028����ֵ:0x00000000�����:32
 �Ĵ���˵��: �ж�����ǰ״̬�Ĵ���(ʵ��״̬)
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  finish_int_nomsk_status : 1;  /* bit[0]   : maskǰ(�����������ж�) ��������ж� ״̬�Ĵ���
                                                                  1������ж���Ч����ʾ�������
                                                                  0������ж���Ч���߼����ڴ����δ�������� */
        unsigned int  reserved                : 31; /* bit[1-31]: ���� */
    } reg;
} SOC_RSA_INT_NOMASK_STATUS_UNION;
#endif
#define SOC_RSA_INT_NOMASK_STATUS_finish_int_nomsk_status_START  (0)
#define SOC_RSA_INT_NOMASK_STATUS_finish_int_nomsk_status_END    (0)


/*****************************************************************************
 �ṹ��    : SOC_RSA_INT_CLR_UNION
 �ṹ˵��  : INT_CLR �Ĵ����ṹ���塣��ַƫ����:0x002C����ֵ:0x00000000�����:32
 �Ĵ���˵��: �ж�����Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  finish_int_clr : 1;  /* bit[0]   : ˵�������д0x1�����Ӧ�ж�Դ���߼�ֻ���յ�д0x1��ʱ�̲Ŷ��ж�Դ�������㡣���������0x1����ڸüĴ����У�Ϊ�˲�Ӱ����Խ���ԸüĴ���д0x0�ָ�Ĭ��ֵ�� */
        unsigned int  reserved_0     : 7;  /* bit[1-7] : ���� */
        unsigned int  reserved_1     : 24; /* bit[8-31]: ���� */
    } reg;
} SOC_RSA_INT_CLR_UNION;
#endif
#define SOC_RSA_INT_CLR_finish_int_clr_START  (0)
#define SOC_RSA_INT_CLR_finish_int_clr_END    (0)


/*****************************************************************************
 �ṹ��    : SOC_RSA_ALARM_MASK_UNION
 �ṹ˵��  : ALARM_MASK �Ĵ����ṹ���塣��ַƫ����:0x0030����ֵ:0x00000005�����:32
 �Ĵ���˵��: ALARM���μĴ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  rsa_dfa_alarm_mask : 4;  /* bit[0-3] : DFA ALARM����
                                                             0x5�����Σ������ALARM
                                                             ������������ */
        unsigned int  reserved           : 28; /* bit[4-31]: ���� */
    } reg;
} SOC_RSA_ALARM_MASK_UNION;
#endif
#define SOC_RSA_ALARM_MASK_rsa_dfa_alarm_mask_START  (0)
#define SOC_RSA_ALARM_MASK_rsa_dfa_alarm_mask_END    (3)


/*****************************************************************************
 �ṹ��    : SOC_RSA_ALARM_STATUS_UNION
 �ṹ˵��  : ALARM_STATUS �Ĵ����ṹ���塣��ַƫ����:0x0034����ֵ:0x00000000�����:32
 �Ĵ���˵��: ALARM״̬�Ĵ���(���κ��ϱ���״̬)
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  rsa_dfa_alarm_status    : 1;  /* bit[0]   : DFA ALARM ״̬
                                                                  1����⵽DFA�������
                                                                  0��δ��⵽DFA���� */
        unsigned int  rsa_attack_alarm_status : 1;  /* bit[1]   : �ؼ��źű�������ALARM״̬
                                                                  1����⵽�ؼ��źű�����
                                                                  0��δ��⵽�ؼ��źű����� */
        unsigned int  reserved_0              : 6;  /* bit[2-7] : ���� */
        unsigned int  reserved_1              : 24; /* bit[8-31]: ���� */
    } reg;
} SOC_RSA_ALARM_STATUS_UNION;
#endif
#define SOC_RSA_ALARM_STATUS_rsa_dfa_alarm_status_START     (0)
#define SOC_RSA_ALARM_STATUS_rsa_dfa_alarm_status_END       (0)
#define SOC_RSA_ALARM_STATUS_rsa_attack_alarm_status_START  (1)
#define SOC_RSA_ALARM_STATUS_rsa_attack_alarm_status_END    (1)


/*****************************************************************************
 �ṹ��    : SOC_RSA_ALARM_NOMASK_STATUS_UNION
 �ṹ˵��  : ALARM_NOMASK_STATUS �Ĵ����ṹ���塣��ַƫ����:0x0038����ֵ:0x00000000�����:32
 �Ĵ���˵��: ALARM����ǰ״̬�Ĵ���(ʵ��״̬)
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  rsa_dfa_alarm_nomask_status    : 1;  /* bit[0]   : DFA ALARM ״̬
                                                                         1����⵽DFA�������
                                                                         0��δ��⵽DFA���� */
        unsigned int  rsa_attack_alarm_nomask_status : 1;  /* bit[1]   : �ؼ��źű�������ALARM״̬
                                                                         1����⵽�ؼ��źű�����
                                                                         0��δ��⵽�ؼ��źű����� */
        unsigned int  reserved_0                     : 6;  /* bit[2-7] : ���� */
        unsigned int  reserved_1                     : 24; /* bit[8-31]: ���� */
    } reg;
} SOC_RSA_ALARM_NOMASK_STATUS_UNION;
#endif
#define SOC_RSA_ALARM_NOMASK_STATUS_rsa_dfa_alarm_nomask_status_START     (0)
#define SOC_RSA_ALARM_NOMASK_STATUS_rsa_dfa_alarm_nomask_status_END       (0)
#define SOC_RSA_ALARM_NOMASK_STATUS_rsa_attack_alarm_nomask_status_START  (1)
#define SOC_RSA_ALARM_NOMASK_STATUS_rsa_attack_alarm_nomask_status_END    (1)


/*****************************************************************************
 �ṹ��    : SOC_RSA_ALARM_CLR_UNION
 �ṹ˵��  : ALARM_CLR �Ĵ����ṹ���塣��ַƫ����:0x003C����ֵ:0x00000000�����:32
 �Ĵ���˵��: ALARM����Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  rsa_dfa_alarm_clr    : 4;  /* bit[0-3] : ˵�������д0x5���DFA ALARMԴ������ֵ��Ч���߼�ֻ���յ�д0x5��ʱ�̲Ŷ�DFA ALRAM�������㡣 */
        unsigned int  rsa_attack_alarm_clr : 4;  /* bit[4-7] : ˵�������д0x5����ؼ��źű���ALARMԴ������ֵ��Ч���߼�ֻ���յ�д0x5��ʱ�̲Ŷ�ALRAM�������㡣 */
        unsigned int  reserved             : 24; /* bit[8-31]: ���� */
    } reg;
} SOC_RSA_ALARM_CLR_UNION;
#endif
#define SOC_RSA_ALARM_CLR_rsa_dfa_alarm_clr_START     (0)
#define SOC_RSA_ALARM_CLR_rsa_dfa_alarm_clr_END       (3)
#define SOC_RSA_ALARM_CLR_rsa_attack_alarm_clr_START  (4)
#define SOC_RSA_ALARM_CLR_rsa_attack_alarm_clr_END    (7)


/*****************************************************************************
 �ṹ��    : SOC_RSA_RESULT_FLAG_UNION
 �ṹ˵��  : RESULT_FLAG �Ĵ����ṹ���塣��ַƫ����:0x0040����ֵ:0x00000000�����:32
 �Ĵ���˵��: RSA�����־�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  rsa_result_flag : 4;  /* bit[0-3] : �����־
                                                          0x00����ʼ������״̬���޽��
                                                          0x05������ɹ�����RAM����ʱRAM������Ч����������RAM���н�����ݡ�
                                                          0x0a������ʧ�ܣ��޽�����ݡ�(ʧ��ԭ����Ĵ���RSA_FAILURE_FLAG)
                                                          ������������
                                                          ˵��������RSA_START������������RSA_BUSY��æ��Ϊ��æʱ�ٶ��Ĵ����� */
        unsigned int  reserved        : 28; /* bit[4-31]: ������ */
    } reg;
} SOC_RSA_RESULT_FLAG_UNION;
#endif
#define SOC_RSA_RESULT_FLAG_rsa_result_flag_START  (0)
#define SOC_RSA_RESULT_FLAG_rsa_result_flag_END    (3)


/*****************************************************************************
 �ṹ��    : SOC_RSA_FAILURE_FLAG_UNION
 �ṹ˵��  : FAILURE_FLAG �Ĵ����ṹ���塣��ַƫ����:0x0044����ֵ:0x00000000�����:32
 �Ĵ���˵��: RSA���ʧ�ܱ�־�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  rsa_failure_flag : 3;  /* bit[0-2] : ���ʧ��ԭ��Ĵ���
                                                           0x0����ʼ������״̬���޽��
                                                           0x1: ģ���޽��
                                                           0x2: ���������ʧ��
                                                           0x3: ��DFA����ʧ��
                                                           0x4:��˻��ӽ��Ϊ����Զ��
                                                           ������������ */
        unsigned int  reserved         : 29; /* bit[3-31]: ������ */
    } reg;
} SOC_RSA_FAILURE_FLAG_UNION;
#endif
#define SOC_RSA_FAILURE_FLAG_rsa_failure_flag_START  (0)
#define SOC_RSA_FAILURE_FLAG_rsa_failure_flag_END    (2)


/*****************************************************************************
 �ṹ��    : SOC_RSA_STAT_CLR_UNION
 �ṹ˵��  : STAT_CLR �Ĵ����ṹ���塣��ַƫ����:0x0050����ֵ:0x00000000�����:32
 �Ĵ���˵��: ͳ������Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  rsa_stat_clr : 1;  /* bit[0]   : ͳ�ƼĴ�������Ĵ�����
                                                       ˵�����üĴ����ǵ�ƽ�źţ����д1��ͳ�ƼĴ������㴦�����ͨ��д0��ֹͣ���㹦�ܡ� */
        unsigned int  reserved     : 31; /* bit[1-31]: ���� */
    } reg;
} SOC_RSA_STAT_CLR_UNION;
#endif
#define SOC_RSA_STAT_CLR_rsa_stat_clr_START  (0)
#define SOC_RSA_STAT_CLR_rsa_stat_clr_END    (0)


/*****************************************************************************
 �ṹ��    : SOC_RSA_KEY_MSK_UNION
 �ṹ˵��  : KEY_MSK �Ĵ����ṹ���塣��ַƫ����:0x0054����ֵ:0x00000000�����:32
 �Ĵ���˵��: RSA����Կ����Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  rsa_key_msk : 32; /* bit[0-31]: RSA�ڶ�д��Կ����������Կ���ɵĽ����ʱ����Կ���μĴ�������Ҫ�ڶ�дǰ�������ã�����ֵΪ�����ȡ��һ��������� */
    } reg;
} SOC_RSA_KEY_MSK_UNION;
#endif
#define SOC_RSA_KEY_MSK_rsa_key_msk_START  (0)
#define SOC_RSA_KEY_MSK_rsa_key_msk_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_RSA_KEY_BACKUP_UNION
 �ṹ˵��  : KEY_BACKUP �Ĵ����ṹ���塣��ַƫ����:0x0058����ֵ:0xDEADBEEF�����:32
 �Ĵ���˵��: RSA����Կ���ݼĴ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  rsa_key_backup : 32; /* bit[0-31]: RSA�ڶ�д��Կ����������Կ���ɵĽ����ʱ����Կ���ݼĴ�����д��Կ��ʱ����Ҫ��д֮ǰ���ã�����ʱ����Ҫ�ڶ�֮���ȡ�� */
    } reg;
} SOC_RSA_KEY_BACKUP_UNION;
#endif
#define SOC_RSA_KEY_BACKUP_rsa_key_backup_START  (0)
#define SOC_RSA_KEY_BACKUP_rsa_key_backup_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_RSA_LOCK_UNION
 �ṹ˵��  : LOCK �Ĵ����ṹ���塣��ַƫ����:0x005C����ֵ:0x00000005�����:32
 �Ĵ���˵��: RSA�ļĴ���lock�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  rsa_lock : 4;  /* bit[0-3] : RSA�������Ĵ�����lock�Ĵ�����
                                                   0x5��lockʹ�ܣ�
                                                   0xA��lock��ʹ�ܣ�
                                                   ����ֵ���Ƿ��������alarm��
                                                   ���������Ĵ���ǰҪ����lock�Ĵ���Ϊ��ʹ��״̬�� */
        unsigned int  reserved : 28; /* bit[4-31]: ���� */
    } reg;
} SOC_RSA_LOCK_UNION;
#endif
#define SOC_RSA_LOCK_rsa_lock_START  (0)
#define SOC_RSA_LOCK_rsa_lock_END    (3)


/*****************************************************************************
 �ṹ��    : SOC_RSA_KEY_LOCK_UNION
 �ṹ˵��  : KEY_LOCK �Ĵ����ṹ���塣��ַƫ����:0x0060����ֵ:0x00000005�����:32
 �Ĵ���˵��: RSA����Կlock�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  rsa_key_lock : 4;  /* bit[0-3] : RSA����Կ�Ĵ�����lock�Ĵ�����
                                                       0x5��lockʹ�ܣ�
                                                       0xA��lock��ʹ�ܣ�
                                                       ����ֵ���Ƿ��������alarm��
                                                       ������Կ�Ĵ�������Կ���ݼĴ���ǰҪ����lock�Ĵ���Ϊ��ʹ��״̬��
                                                       ����Ҫdebug��Կ�Ĵ�������Կ���ݼĴ���ʱ����Ҫ�����Ĵ�������Ϊ��ʹ��״̬�� */
        unsigned int  reserved     : 28; /* bit[4-31]: ���� */
    } reg;
} SOC_RSA_KEY_LOCK_UNION;
#endif
#define SOC_RSA_KEY_LOCK_rsa_key_lock_START  (0)
#define SOC_RSA_KEY_LOCK_rsa_key_lock_END    (3)


/*****************************************************************************
 �ṹ��    : SOC_RSA_VERSION_ID_UNION
 �ṹ˵��  : VERSION_ID �Ĵ����ṹ���塣��ַƫ����:0x007C����ֵ:0x20160720�����:32
 �Ĵ���˵��: RSA�İ汾�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  rs_version_id : 32; /* bit[0-31]: ��ͬ�İ汾�ĳ�ʼֵ��һ�� */
    } reg;
} SOC_RSA_VERSION_ID_UNION;
#endif
#define SOC_RSA_VERSION_ID_rs_version_id_START  (0)
#define SOC_RSA_VERSION_ID_rs_version_id_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_RSA_LSB_N_EQUAL_ONE_UNION
 �ṹ˵��  : LSB_N_EQUAL_ONE �Ĵ����ṹ���塣��ַƫ����:0x0080����ֵ:0x0000000A�����:32
 �Ĵ���˵��: RSAģ�������λΪ1�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved : 32; /* bit[0-31]: RSA��Կ����ʱ��N�ĸ�λ�Ƿ�ǿ��Ϊ1��Ĭ��Ϊ4'ha
                                                   4'ha:���ɵ�ģ��N�ĸ�λ��ǿ��Ϊ1
                                                   4'h5:���ɵ�ģ��N�ĸ�λ����Ϊ1
                                                   ����ֵ�Ƿ� */
    } reg;
} SOC_RSA_LSB_N_EQUAL_ONE_UNION;
#endif


/*****************************************************************************
 �ṹ��    : SOC_RSA_MRAM_UNION
 �ṹ˵��  : MRAM �Ĵ����ṹ���塣��ַƫ����:0x0200+(n)*4����ֵ:0x00000000�����:32
 �Ĵ���˵��: MRAM(4096bit)��д�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  mram : 32; /* bit[0-31]: CPU����MRAM���ݼĴ�����оƬ�ڲ�RAMΪ64bitλ�������64bitΪ��λ��д����(n��ż����ʼ)����ͬ�������õ����ݵ�ַ�ռ�����û��ֲ�����
                                               ˵�������й����в��ܶ�д����ʼֵ��MRAM��ĳ�ʼֵ����һ����0��
                                               ��ַ���n��Χ[0,127] */
    } reg;
} SOC_RSA_MRAM_UNION;
#endif
#define SOC_RSA_MRAM_mram_START  (0)
#define SOC_RSA_MRAM_mram_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_RSA_NRAM_UNION
 �ṹ˵��  : NRAM �Ĵ����ṹ���塣��ַƫ����:0x0600+(n)*4����ֵ:0x00000000�����:32
 �Ĵ���˵��: NRAM(4096bit)��д�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  nram : 32; /* bit[0-31]: CPU����NRAM���ݼĴ�����оƬ�ڲ�RAMΪ64bitλ�������64bitΪ��λ��д����(n��ż����ʼ)����ͬ�������õ����ݵ�ַ�ռ�����û��ֲ�����
                                               ˵�������й����в��ܶ�д����ʼֵ��NRAM��ĳ�ʼֵ����һ����0��
                                               ��ַ���n��Χ[0,127] */
    } reg;
} SOC_RSA_NRAM_UNION;
#endif
#define SOC_RSA_NRAM_nram_START  (0)
#define SOC_RSA_NRAM_nram_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_RSA_KRAM_UNION
 �ṹ˵��  : KRAM �Ĵ����ṹ���塣��ַƫ����:0x0A00+(n)*4����ֵ:0x00000000�����:32
 �Ĵ���˵��: KRAM(4096bit)��д�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  kram : 32; /* bit[0-31]: CPU����KRAM���ݼĴ�����оƬ�ڲ�RAMΪ64bitλ�������64bitΪ��λ��д����(n��ż����ʼ)����ͬ�������õ����ݵ�ַ�ռ�����û��ֲ�����
                                               ˵�������й����в��ܶ�д������ģʽ�� �����й����пɶ�д����ʼֵ��KRAM��ĳ�ʼֵ����һ����0��
                                               ��ַ���n��Χ[0,127] */
    } reg;
} SOC_RSA_KRAM_UNION;
#endif
#define SOC_RSA_KRAM_kram_START  (0)
#define SOC_RSA_KRAM_kram_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_RSA_RRAM_UNION
 �ṹ˵��  : RRAM �Ĵ����ṹ���塣��ַƫ����:0x0E00+(n)*4����ֵ:0x00000000�����:32
 �Ĵ���˵��: RRAM(4096bit)��д�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  rram : 32; /* bit[0-31]: CPU����RRAM���ݼĴ�����оƬ�ڲ�RAMΪ64bitλ�������64bitΪ��λ��д����(n��ż����ʼ)����ͬ�������õ����ݵ�ַ�ռ�����û��ֲ�����
                                               ˵�������й����в��ܶ�д����ʼֵ��RRAM��ĳ�ʼֵ����һ����0��
                                               ��ַ���n��Χ[0,127] */
    } reg;
} SOC_RSA_RRAM_UNION;
#endif
#define SOC_RSA_RRAM_rram_START  (0)
#define SOC_RSA_RRAM_rram_END    (31)






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

#endif /* end of soc_rsa_interface.h */
