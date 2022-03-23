/******************************************************************************

                 ��Ȩ���� (C), 2001-2019, ��Ϊ�������޹�˾

 ******************************************************************************
  �� �� ��   : soc_ecc_interface.h
  �� �� ��   : ����
  ��    ��   : Excel2Code
  ��������   : 2019-10-26 10:53:22
  ����޸�   :
  ��������   : �ӿ�ͷ�ļ�
  �����б�   :
  �޸���ʷ   :
  1.��    ��   : 2019��10��26��
    ��    ��   : l00249396
    �޸�����   : �ӡ�HiEPS V200 nmanager�Ĵ����ֲ�_ECC.xml���Զ�����

******************************************************************************/

/*****************************************************************************
  1 ����ͷ�ļ�����
*****************************************************************************/

#ifndef __SOC_ECC_INTERFACE_H__
#define __SOC_ECC_INTERFACE_H__

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
/* �Ĵ���˵����ECC����æµ״ָ̬ʾ�Ĵ���
   λ����UNION�ṹ:  SOC_ECC_BUSY_UNION */
#define SOC_ECC_BUSY_ADDR(base)                       ((base) + (0x0000))

/* �Ĵ���˵��������ģʽѡ��Ĵ���
   λ����UNION�ṹ:  SOC_ECC_MODE_UNION */
#define SOC_ECC_MODE_ADDR(base)                       ((base) + (0x0004))

/* �Ĵ���˵����ECC_�����Ĵ���
   λ����UNION�ṹ:  SOC_ECC_START_UNION */
#define SOC_ECC_START_ADDR(base)                      ((base) + (0x0008))

/* �Ĵ���˵����RAM�������ʹ�ܼĴ���
   λ����UNION�ṹ:  SOC_ECC_RAM_CLR_EN_UNION */
#define SOC_ECC_RAM_CLR_EN_ADDR(base)                 ((base) + (0x000C))

/* �Ĵ���˵����RAM���������ɼĴ���
   λ����UNION�ṹ:  SOC_ECC_RAM_CLR_DONE_UNION */
#define SOC_ECC_RAM_CLR_DONE_ADDR(base)               ((base) + (0x0010))

/* �Ĵ���˵����ECC�������ԭʼ�жϼĴ���
   λ����UNION�ṹ:  SOC_ECC_ORI_INT_UNION */
#define SOC_ECC_ORI_INT_ADDR(base)                    ((base) + (0x0014))

/* �Ĵ���˵����ECC����������μĴ���
   λ����UNION�ṹ:  SOC_ECC_INT_MSK_UNION */
#define SOC_ECC_INT_MSK_ADDR(base)                    ((base) + (0x0018))

/* �Ĵ���˵����ECC����������κ�Ĵ���
   λ����UNION�ṹ:  SOC_ECC_INT_ECC_UNION */
#define SOC_ECC_INT_ECC_ADDR(base)                    ((base) + (0x001C))

/* �Ĵ���˵����ECC����ж�����Ĵ���
   λ����UNION�ṹ:  SOC_ECC_INT_CLR_UNION */
#define SOC_ECC_INT_CLR_ADDR(base)                    ((base) + (0x0020))

/* �Ĵ���˵����ECC DFAԭʼ�澯�Ĵ���
   λ����UNION�ṹ:  SOC_ECC_ALARM_DFA_ORI_UNION */
#define SOC_ECC_ALARM_DFA_ORI_ADDR(base)              ((base) + (0x0024))

/* �Ĵ���˵����ECC DFA�澯���μĴ���
   λ����UNION�ṹ:  SOC_ECC_ALARM_DFA_MSK_UNION */
#define SOC_ECC_ALARM_DFA_MSK_ADDR(base)              ((base) + (0x0028))

/* �Ĵ���˵����ECC DFA���κ�澯
   λ����UNION�ṹ:  SOC_ECC_ALARM_DFA_UNION */
#define SOC_ECC_ALARM_DFA_ADDR(base)                  ((base) + (0x002C))

/* �Ĵ���˵����ECC DFA�澯����Ĵ���
   λ����UNION�ṹ:  SOC_ECC_ALARM_DFA_CLR_UNION */
#define SOC_ECC_ALARM_DFA_CLR_ADDR(base)              ((base) + (0x0030))

/* �Ĵ���˵����ECC �źű���ԭʼ�澯�Ĵ���
   λ����UNION�ṹ:  SOC_ECC_ALARM_PRT_ORI_UNION */
#define SOC_ECC_ALARM_PRT_ORI_ADDR(base)              ((base) + (0x0034))

/* �Ĵ���˵����ECC �źű����澯���μĴ���
   λ����UNION�ṹ:  SOC_ECC_ALARM_PRT_MSK_UNION */
#define SOC_ECC_ALARM_PRT_MSK_ADDR(base)              ((base) + (0x0038))

/* �Ĵ���˵����ECC �źű������κ�澯
   λ����UNION�ṹ:  SOC_ECC_ALARM_PRT_UNION */
#define SOC_ECC_ALARM_PRT_ADDR(base)                  ((base) + (0x003C))

/* �Ĵ���˵����ECC �źű����澯����Ĵ���
   λ����UNION�ṹ:  SOC_ECC_ALARM_PRT_CLR_UNION */
#define SOC_ECC_ALARM_PRT_CLR_ADDR(base)              ((base) + (0x0040))

/* �Ĵ���˵������������Ϊ����Զ��ָʾ�Ĵ���
   λ����UNION�ṹ:  SOC_ECC_POINT_RESULT_INFI_UNION */
#define SOC_ECC_POINT_RESULT_INFI_ADDR(base)          ((base) + (0x0044))

/* �Ĵ���˵����ECC��Կ����Ĵ���
   λ����UNION�ṹ:  SOC_ECC_KEY_MSK_UNION */
#define SOC_ECC_KEY_MSK_ADDR(base)                    ((base) + (0x0048))

/* �Ĵ���˵����ECC��Կ���ݼĴ���
   λ����UNION�ṹ:  SOC_ECC_KEY_BACKUP_UNION */
#define SOC_ECC_KEY_BACKUP_ADDR(base)                 ((base) + (0x004C))

/* �Ĵ���˵����ECC���ļ���ʹ�ܼĴ���
   λ����UNION�ṹ:  SOC_ECC_SCRAMB_EN_UNION */
#define SOC_ECC_SCRAMB_EN_ADDR(base)                  ((base) + (0x0050))

/* �Ĵ���˵����ECC lock�Ĵ���
   λ����UNION�ṹ:  SOC_ECC_LOCK_UNION */
#define SOC_ECC_LOCK_ADDR(base)                       ((base) + (0x0054))

/* �Ĵ���˵����ECC ��Կlock�Ĵ���
   λ����UNION�ṹ:  SOC_ECC_KEY_LOCK_UNION */
#define SOC_ECC_KEY_LOCK_ADDR(base)                   ((base) + (0x0058))

/* �Ĵ���˵����ECC debug�׶�ȥ�ڼĴ���
   λ����UNION�ṹ:  SOC_ECC_DEBUG_UNMASK_UNION */
#define SOC_ECC_DEBUG_UNMASK_ADDR(base)               ((base) + (0x005C))

/* �Ĵ���˵����������1�Ĵ���
   λ����UNION�ṹ:  SOC_ECC_EC_PX1_UNION */
#define SOC_ECC_EC_PX1_ADDR(base, n)                  ((base) + (0x0100+4*(n)))

/* �Ĵ���˵����������2�Ĵ���
   λ����UNION�ṹ:  SOC_ECC_EC_PY1_UNION */
#define SOC_ECC_EC_PY1_ADDR(base, n)                  ((base) + (0x0148+4*(n)))

/* �Ĵ���˵����������3�Ĵ���
   λ����UNION�ṹ:  SOC_ECC_EC_PX2_UNION */
#define SOC_ECC_EC_PX2_ADDR(base, n)                  ((base) + (0x0190+4*(n)))

/* �Ĵ���˵����������4�Ĵ���
   λ����UNION�ṹ:  SOC_ECC_EC_PY2_UNION */
#define SOC_ECC_EC_PY2_ADDR(base, n)                  ((base) + (0x01D8+4*(n)))

/* �Ĵ���˵����ģ���Ĵ���
   λ����UNION�ṹ:  SOC_ECC_OPRAND_N_UNION */
#define SOC_ECC_OPRAND_N_ADDR(base, n)                ((base) + (0x0220+4*(n)))

/* �Ĵ���˵����Ԥ����ֵ�Ĵ���
   λ����UNION�ṹ:  SOC_ECC_OPRAND_C_UNION */
#define SOC_ECC_OPRAND_C_ADDR(base, n)                ((base) + (0x0268+4*(n)))

/* �Ĵ���˵�������1�Ĵ���
   λ����UNION�ṹ:  SOC_ECC_RESULT_X_UNION */
#define SOC_ECC_RESULT_X_ADDR(base, n)                ((base) + (0x02B0+4*(n)))

/* �Ĵ���˵�������2�Ĵ���
   λ����UNION�ṹ:  SOC_ECC_RESULT_Y_UNION */
#define SOC_ECC_RESULT_Y_ADDR(base, n)                ((base) + (0x02F8+4*(n)))

/* �Ĵ���˵������˳����Ĵ���
   λ����UNION�ṹ:  SOC_ECC_MUL_K_UNION */
#define SOC_ECC_MUL_K_ADDR(base, n)                   ((base) + (0x0340+4*(n)))

/* �Ĵ���˵������Բ���߲�����P�Ĵ���
   λ����UNION�ṹ:  SOC_ECC_EC_PARA_P_UNION */
#define SOC_ECC_EC_PARA_P_ADDR(base, n)               ((base) + (0x0388+4*(n)))

/* �Ĵ���˵������Բ���߲�����A�Ĵ���
   λ����UNION�ṹ:  SOC_ECC_EC_PARA_A_UNION */
#define SOC_ECC_EC_PARA_A_ADDR(base, n)               ((base) + (0x03D0+4*(n)))

/* �Ĵ���˵������Բ���߲�����B�Ĵ���
   λ����UNION�ṹ:  SOC_ECC_EC_PARA_B_UNION */
#define SOC_ECC_EC_PARA_B_ADDR(base, n)               ((base) + (0x0418+4*(n)))

/* �Ĵ���˵������Բ���߲�����N�Ĵ���
   λ����UNION�ṹ:  SOC_ECC_EC_PARA_N_UNION */
#define SOC_ECC_EC_PARA_N_ADDR(base, n)               ((base) + (0x0460+4*(n)))

/* �Ĵ���˵������Բ���߲����л���G��X����Ĵ���
   λ����UNION�ṹ:  SOC_ECC_EC_PARA_GX_UNION */
#define SOC_ECC_EC_PARA_GX_ADDR(base, n)              ((base) + (0x04A8+4*(n)))

/* �Ĵ���˵������Բ���߲����л���G��Y����Ĵ���
   λ����UNION�ṹ:  SOC_ECC_EC_PARA_GY_UNION */
#define SOC_ECC_EC_PARA_GY_ADDR(base, n)              ((base) + (0x04F0+4*(n)))





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
 �ṹ��    : SOC_ECC_BUSY_UNION
 �ṹ˵��  : BUSY �Ĵ����ṹ���塣��ַƫ����:0x0000����ֵ:0x0000000A�����:32
 �Ĵ���˵��: ECC����æµ״ָ̬ʾ�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ecc_busy : 4;  /* bit[0-3] : ECC����״ָ̬ʾ�Ĵ���
                                                   A��ECC����û�н��л��Ѿ�������
                                                   5��ECC�������ڽ��С� */
        unsigned int  reverved : 28; /* bit[4-31]:  */
    } reg;
} SOC_ECC_BUSY_UNION;
#endif
#define SOC_ECC_BUSY_ecc_busy_START  (0)
#define SOC_ECC_BUSY_ecc_busy_END    (3)
#define SOC_ECC_BUSY_reverved_START  (4)
#define SOC_ECC_BUSY_reverved_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_ECC_MODE_UNION
 �ṹ˵��  : MODE �Ĵ����ṹ���塣��ַƫ����:0x0004����ֵ:0x00000040�����:32
 �Ĵ���˵��: ����ģʽѡ��Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  mode     : 4;  /* bit[0-3] : ECCģʽѡ��Ĵ�����
                                                   000��������㣻
                                                   001��������㣻
                                                   010��ģ�����㣻
                                                   011��ģ�����㣻
                                                   100��ģ�����㣻
                                                   101��ģ�����㣻
                                                   ����ֵ���Ƿ�ֵ�����ϱ�alarm�� */
        unsigned int  length   : 4;  /* bit[4-7] : ECC���㳤�ȼĴ�����
                                                   2��128 bits
                                                   3��192 bits
                                                   4��256 bits
                                                   ����ֵ���Ƿ����ϱ�alarm */
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
 �ṹ��    : SOC_ECC_START_UNION
 �ṹ˵��  : START �Ĵ����ṹ���塣��ַƫ����:0x0008����ֵ:0x0000000A�����:32
 �Ĵ���˵��: ECC_�����Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ecc_start : 4;  /* bit[0-3] : ECC���������ź�
                                                    5��������
                                                    A��δ������ */
        unsigned int  reverved  : 28; /* bit[4-31]:  */
    } reg;
} SOC_ECC_START_UNION;
#endif
#define SOC_ECC_START_ecc_start_START  (0)
#define SOC_ECC_START_ecc_start_END    (3)
#define SOC_ECC_START_reverved_START   (4)
#define SOC_ECC_START_reverved_END     (31)


/*****************************************************************************
 �ṹ��    : SOC_ECC_RAM_CLR_EN_UNION
 �ṹ˵��  : RAM_CLR_EN �Ĵ����ṹ���塣��ַƫ����:0x000C����ֵ:0x0000000A�����:32
 �Ĵ���˵��: RAM�������ʹ�ܼĴ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ecc_ram_clr_en : 4;  /* bit[0-3] : RAM����Ĵ�����
                                                         5��ʹ�����㹦�ܣ�
                                                         A����ʹ�����㹦�ܡ� */
        unsigned int  reverved       : 28; /* bit[4-31]:  */
    } reg;
} SOC_ECC_RAM_CLR_EN_UNION;
#endif
#define SOC_ECC_RAM_CLR_EN_ecc_ram_clr_en_START  (0)
#define SOC_ECC_RAM_CLR_EN_ecc_ram_clr_en_END    (3)
#define SOC_ECC_RAM_CLR_EN_reverved_START        (4)
#define SOC_ECC_RAM_CLR_EN_reverved_END          (31)


/*****************************************************************************
 �ṹ��    : SOC_ECC_RAM_CLR_DONE_UNION
 �ṹ˵��  : RAM_CLR_DONE �Ĵ����ṹ���塣��ַƫ����:0x0010����ֵ:0x0000000A�����:32
 �Ĵ���˵��: RAM���������ɼĴ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ecc_ram_clr_done : 4;  /* bit[0-3] : RAM�������ָʾ�Ĵ�����
                                                           5��RAMʹ�������Ѿ���ɣ�
                                                           A��RAMʹ�����㹦��δ��ɡ� */
        unsigned int  reverved         : 28; /* bit[4-31]:  */
    } reg;
} SOC_ECC_RAM_CLR_DONE_UNION;
#endif
#define SOC_ECC_RAM_CLR_DONE_ecc_ram_clr_done_START  (0)
#define SOC_ECC_RAM_CLR_DONE_ecc_ram_clr_done_END    (3)
#define SOC_ECC_RAM_CLR_DONE_reverved_START          (4)
#define SOC_ECC_RAM_CLR_DONE_reverved_END            (31)


/*****************************************************************************
 �ṹ��    : SOC_ECC_ORI_INT_UNION
 �ṹ˵��  : ORI_INT �Ĵ����ṹ���塣��ַƫ����:0x0014����ֵ:0x0000000A�����:32
 �Ĵ���˵��: ECC�������ԭʼ�жϼĴ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ecc_ori_int : 4;  /* bit[0-3] : ԭʼ�ж�״̬�Ĵ�����
                                                      A��ECC��������ж�û�в��������㻹û�п�ʼ��
                                                      5��ECC��������жϲ����� */
        unsigned int  reverved    : 28; /* bit[4-31]:  */
    } reg;
} SOC_ECC_ORI_INT_UNION;
#endif
#define SOC_ECC_ORI_INT_ecc_ori_int_START  (0)
#define SOC_ECC_ORI_INT_ecc_ori_int_END    (3)
#define SOC_ECC_ORI_INT_reverved_START     (4)
#define SOC_ECC_ORI_INT_reverved_END       (31)


/*****************************************************************************
 �ṹ��    : SOC_ECC_INT_MSK_UNION
 �ṹ˵��  : INT_MSK �Ĵ����ṹ���塣��ַƫ����:0x0018����ֵ:0x00000005�����:32
 �Ĵ���˵��: ECC����������μĴ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ecc_int_msk : 4;  /* bit[0-3] : �ж����μĴ�����
                                                      4'hA��������ԭʼ�жϣ�
                                                      4'h5������ԭʼ�жϣ�
                                                      �������Ƿ��������alarm�� */
        unsigned int  reverved    : 28; /* bit[4-31]:  */
    } reg;
} SOC_ECC_INT_MSK_UNION;
#endif
#define SOC_ECC_INT_MSK_ecc_int_msk_START  (0)
#define SOC_ECC_INT_MSK_ecc_int_msk_END    (3)
#define SOC_ECC_INT_MSK_reverved_START     (4)
#define SOC_ECC_INT_MSK_reverved_END       (31)


/*****************************************************************************
 �ṹ��    : SOC_ECC_INT_ECC_UNION
 �ṹ˵��  : INT_ECC �Ĵ����ṹ���塣��ַƫ����:0x001C����ֵ:0x0000000A�����:32
 �Ĵ���˵��: ECC����������κ�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  int_ecc  : 4;  /* bit[0-3] : ���κ��жϣ�
                                                   A�����κ��ж���Ч��
                                                   5�����κ��ж���Ч�� */
        unsigned int  reverved : 28; /* bit[4-31]:  */
    } reg;
} SOC_ECC_INT_ECC_UNION;
#endif
#define SOC_ECC_INT_ECC_int_ecc_START   (0)
#define SOC_ECC_INT_ECC_int_ecc_END     (3)
#define SOC_ECC_INT_ECC_reverved_START  (4)
#define SOC_ECC_INT_ECC_reverved_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_ECC_INT_CLR_UNION
 �ṹ˵��  : INT_CLR �Ĵ����ṹ���塣��ַƫ����:0x0020����ֵ:0x0000000A�����:32
 �Ĵ���˵��: ECC����ж�����Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ecc_int_clr : 4;  /* bit[0-3] : �ж�����Ĵ�����
                                                      0xA�������ԭʼ�жϺ����κ��жϣ�
                                                      0x5�����ԭʼ�жϺ����κ��жϡ�
                                                      �������Ƿ��������alarm�� */
        unsigned int  reverved    : 28; /* bit[4-31]:  */
    } reg;
} SOC_ECC_INT_CLR_UNION;
#endif
#define SOC_ECC_INT_CLR_ecc_int_clr_START  (0)
#define SOC_ECC_INT_CLR_ecc_int_clr_END    (3)
#define SOC_ECC_INT_CLR_reverved_START     (4)
#define SOC_ECC_INT_CLR_reverved_END       (31)


/*****************************************************************************
 �ṹ��    : SOC_ECC_ALARM_DFA_ORI_UNION
 �ṹ˵��  : ALARM_DFA_ORI �Ĵ����ṹ���塣��ַƫ����:0x0024����ֵ:0x0000000A�����:32
 �Ĵ���˵��: ECC DFAԭʼ�澯�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  alarm_dfa_ori : 4;  /* bit[0-3] : ԭʼDFA�澯״̬�Ĵ�����
                                                        A��ECC DFA�澯û�в��������㻹û�п�ʼ��
                                                        5��ECC DFA�澯������ */
        unsigned int  reverved      : 28; /* bit[4-31]:  */
    } reg;
} SOC_ECC_ALARM_DFA_ORI_UNION;
#endif
#define SOC_ECC_ALARM_DFA_ORI_alarm_dfa_ori_START  (0)
#define SOC_ECC_ALARM_DFA_ORI_alarm_dfa_ori_END    (3)
#define SOC_ECC_ALARM_DFA_ORI_reverved_START       (4)
#define SOC_ECC_ALARM_DFA_ORI_reverved_END         (31)


/*****************************************************************************
 �ṹ��    : SOC_ECC_ALARM_DFA_MSK_UNION
 �ṹ˵��  : ALARM_DFA_MSK �Ĵ����ṹ���塣��ַƫ����:0x0028����ֵ:0x0000000A�����:32
 �Ĵ���˵��: ECC DFA�澯���μĴ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  alarm_dfa_msk : 4;  /* bit[0-3] : �澯���μĴ�����
                                                        4'hA��������ԭʼ�澯��
                                                        4'h5������ԭʼ�澯��
                                                        �������Ƿ��������alarm�� */
        unsigned int  reverved      : 28; /* bit[4-31]:  */
    } reg;
} SOC_ECC_ALARM_DFA_MSK_UNION;
#endif
#define SOC_ECC_ALARM_DFA_MSK_alarm_dfa_msk_START  (0)
#define SOC_ECC_ALARM_DFA_MSK_alarm_dfa_msk_END    (3)
#define SOC_ECC_ALARM_DFA_MSK_reverved_START       (4)
#define SOC_ECC_ALARM_DFA_MSK_reverved_END         (31)


/*****************************************************************************
 �ṹ��    : SOC_ECC_ALARM_DFA_UNION
 �ṹ˵��  : ALARM_DFA �Ĵ����ṹ���塣��ַƫ����:0x002C����ֵ:0x0000000A�����:32
 �Ĵ���˵��: ECC DFA���κ�澯
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  alarm_dfa : 4;  /* bit[0-3] : ���κ�澯��
                                                    A��ECC DFA�澯û�в��������㻹û�п�ʼ��
                                                    5��ECC DFA�澯������ */
        unsigned int  reverved  : 28; /* bit[4-31]:  */
    } reg;
} SOC_ECC_ALARM_DFA_UNION;
#endif
#define SOC_ECC_ALARM_DFA_alarm_dfa_START  (0)
#define SOC_ECC_ALARM_DFA_alarm_dfa_END    (3)
#define SOC_ECC_ALARM_DFA_reverved_START   (4)
#define SOC_ECC_ALARM_DFA_reverved_END     (31)


/*****************************************************************************
 �ṹ��    : SOC_ECC_ALARM_DFA_CLR_UNION
 �ṹ˵��  : ALARM_DFA_CLR �Ĵ����ṹ���塣��ַƫ����:0x0030����ֵ:0x0000000A�����:32
 �Ĵ���˵��: ECC DFA�澯����Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  alarm_dfa_clr : 4;  /* bit[0-3] : �澯����Ĵ�����
                                                        4'hA��������澯��
                                                        4'h5������澯��
                                                        �������Ƿ��������alarm�� */
        unsigned int  reverved      : 28; /* bit[4-31]:  */
    } reg;
} SOC_ECC_ALARM_DFA_CLR_UNION;
#endif
#define SOC_ECC_ALARM_DFA_CLR_alarm_dfa_clr_START  (0)
#define SOC_ECC_ALARM_DFA_CLR_alarm_dfa_clr_END    (3)
#define SOC_ECC_ALARM_DFA_CLR_reverved_START       (4)
#define SOC_ECC_ALARM_DFA_CLR_reverved_END         (31)


/*****************************************************************************
 �ṹ��    : SOC_ECC_ALARM_PRT_ORI_UNION
 �ṹ˵��  : ALARM_PRT_ORI �Ĵ����ṹ���塣��ַƫ����:0x0034����ֵ:0x0000000A�����:32
 �Ĵ���˵��: ECC �źű���ԭʼ�澯�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  alarm_prt_ori : 4;  /* bit[0-3] : ԭʼPRT�澯״̬�Ĵ�����
                                                        A��ECC PRT�澯û�в��������㻹û�п�ʼ��
                                                        5��ECC PRT�澯������ */
        unsigned int  reverved      : 28; /* bit[4-31]:  */
    } reg;
} SOC_ECC_ALARM_PRT_ORI_UNION;
#endif
#define SOC_ECC_ALARM_PRT_ORI_alarm_prt_ori_START  (0)
#define SOC_ECC_ALARM_PRT_ORI_alarm_prt_ori_END    (3)
#define SOC_ECC_ALARM_PRT_ORI_reverved_START       (4)
#define SOC_ECC_ALARM_PRT_ORI_reverved_END         (31)


/*****************************************************************************
 �ṹ��    : SOC_ECC_ALARM_PRT_MSK_UNION
 �ṹ˵��  : ALARM_PRT_MSK �Ĵ����ṹ���塣��ַƫ����:0x0038����ֵ:0x0000000A�����:32
 �Ĵ���˵��: ECC �źű����澯���μĴ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  alarm_prt_msk : 4;  /* bit[0-3] : �澯���μĴ�����
                                                        4'hA��������ԭʼ�澯��
                                                        4'h5������ԭʼ�澯��
                                                        �������Ƿ��������alarm�� */
        unsigned int  reverved      : 28; /* bit[4-31]:  */
    } reg;
} SOC_ECC_ALARM_PRT_MSK_UNION;
#endif
#define SOC_ECC_ALARM_PRT_MSK_alarm_prt_msk_START  (0)
#define SOC_ECC_ALARM_PRT_MSK_alarm_prt_msk_END    (3)
#define SOC_ECC_ALARM_PRT_MSK_reverved_START       (4)
#define SOC_ECC_ALARM_PRT_MSK_reverved_END         (31)


/*****************************************************************************
 �ṹ��    : SOC_ECC_ALARM_PRT_UNION
 �ṹ˵��  : ALARM_PRT �Ĵ����ṹ���塣��ַƫ����:0x003C����ֵ:0x0000000A�����:32
 �Ĵ���˵��: ECC �źű������κ�澯
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  alarm_prt : 4;  /* bit[0-3] : ���κ�澯��
                                                    A��ECC PRT�澯û�в��������㻹û�п�ʼ��
                                                    5��ECC PRT�澯������ */
        unsigned int  reverved  : 28; /* bit[4-31]:  */
    } reg;
} SOC_ECC_ALARM_PRT_UNION;
#endif
#define SOC_ECC_ALARM_PRT_alarm_prt_START  (0)
#define SOC_ECC_ALARM_PRT_alarm_prt_END    (3)
#define SOC_ECC_ALARM_PRT_reverved_START   (4)
#define SOC_ECC_ALARM_PRT_reverved_END     (31)


/*****************************************************************************
 �ṹ��    : SOC_ECC_ALARM_PRT_CLR_UNION
 �ṹ˵��  : ALARM_PRT_CLR �Ĵ����ṹ���塣��ַƫ����:0x0040����ֵ:0x0000000A�����:32
 �Ĵ���˵��: ECC �źű����澯����Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  alarm_prt_clr : 4;  /* bit[0-3] : �澯����Ĵ�����
                                                        4'hA��������澯��
                                                        4'h5������澯��
                                                        �������Ƿ��������alarm�� */
        unsigned int  reverved      : 28; /* bit[4-31]:  */
    } reg;
} SOC_ECC_ALARM_PRT_CLR_UNION;
#endif
#define SOC_ECC_ALARM_PRT_CLR_alarm_prt_clr_START  (0)
#define SOC_ECC_ALARM_PRT_CLR_alarm_prt_clr_END    (3)
#define SOC_ECC_ALARM_PRT_CLR_reverved_START       (4)
#define SOC_ECC_ALARM_PRT_CLR_reverved_END         (31)


/*****************************************************************************
 �ṹ��    : SOC_ECC_POINT_RESULT_INFI_UNION
 �ṹ˵��  : POINT_RESULT_INFI �Ĵ����ṹ���塣��ַƫ����:0x0044����ֵ:0x0000000A�����:32
 �Ĵ���˵��: ��������Ϊ����Զ��ָʾ�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  point_result_infi : 4;  /* bit[0-3] : ��������Ϊ����Զ��ָʾ�Ĵ�����
                                                            5����������Ϊ����Զ�㣻
                                                            A������������������Զ�㡣 */
        unsigned int  reverved          : 28; /* bit[4-31]:  */
    } reg;
} SOC_ECC_POINT_RESULT_INFI_UNION;
#endif
#define SOC_ECC_POINT_RESULT_INFI_point_result_infi_START  (0)
#define SOC_ECC_POINT_RESULT_INFI_point_result_infi_END    (3)
#define SOC_ECC_POINT_RESULT_INFI_reverved_START           (4)
#define SOC_ECC_POINT_RESULT_INFI_reverved_END             (31)


/*****************************************************************************
 �ṹ��    : SOC_ECC_KEY_MSK_UNION
 �ṹ˵��  : KEY_MSK �Ĵ����ṹ���塣��ַƫ����:0x0048����ֵ:0x00000000�����:32
 �Ĵ���˵��: ECC��Կ����Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ecc_key_msk : 32; /* bit[0-31]: ECCģ���д��Կʱ������Ĵ������üĴ�����Ҫ�ڶ�д��Կǰ�������á� */
    } reg;
} SOC_ECC_KEY_MSK_UNION;
#endif
#define SOC_ECC_KEY_MSK_ecc_key_msk_START  (0)
#define SOC_ECC_KEY_MSK_ecc_key_msk_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_ECC_KEY_BACKUP_UNION
 �ṹ˵��  : KEY_BACKUP �Ĵ����ṹ���塣��ַƫ����:0x004C����ֵ:0x00000000�����:32
 �Ĵ���˵��: ECC��Կ���ݼĴ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ecc_key_backup : 32; /* bit[0-31]: ECCģ���д��Կʱ����Կ���ݼĴ������üĴ����ڽ��ж�дÿ32bit��Կǰ�������á� */
    } reg;
} SOC_ECC_KEY_BACKUP_UNION;
#endif
#define SOC_ECC_KEY_BACKUP_ecc_key_backup_START  (0)
#define SOC_ECC_KEY_BACKUP_ecc_key_backup_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_ECC_SCRAMB_EN_UNION
 �ṹ˵��  : SCRAMB_EN �Ĵ����ṹ���塣��ַƫ����:0x0050����ֵ:0x0000000A�����:32
 �Ĵ���˵��: ECC���ļ���ʹ�ܼĴ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ecc_scramb_en : 4;  /* bit[0-3] : ECC���ļ���ʹ�ܼĴ�����
                                                        0x5�����ļ���ʹ�ܣ�
                                                        0xA�����ļ��Ų�ʹ�ܣ�
                                                        ����ֵ���Ƿ�ֵ�����ϱ�alarm��
                                                        ECC���ļ��ŵ�����Ϊ��ӵ����ã����ļ�����ɺ󲻲����жϡ� */
        unsigned int  reverved      : 28; /* bit[4-31]:  */
    } reg;
} SOC_ECC_SCRAMB_EN_UNION;
#endif
#define SOC_ECC_SCRAMB_EN_ecc_scramb_en_START  (0)
#define SOC_ECC_SCRAMB_EN_ecc_scramb_en_END    (3)
#define SOC_ECC_SCRAMB_EN_reverved_START       (4)
#define SOC_ECC_SCRAMB_EN_reverved_END         (31)


/*****************************************************************************
 �ṹ��    : SOC_ECC_LOCK_UNION
 �ṹ˵��  : LOCK �Ĵ����ṹ���塣��ַƫ����:0x0054����ֵ:0x00000005�����:32
 �Ĵ���˵��: ECC lock�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ecc_lock : 4;  /* bit[0-3] : ECC�������Ĵ�����lock�Ĵ�����
                                                   0x5��lockʹ�ܣ�
                                                   0xA��lock��ʹ�ܣ�
                                                   ����ֵ���Ƿ�ֵ�����ϱ�alarm��
                                                   ���������Ĵ���ǰҪ����lock�Ĵ���Ϊ��ʹ��״̬�� */
        unsigned int  reverved : 28; /* bit[4-31]:  */
    } reg;
} SOC_ECC_LOCK_UNION;
#endif
#define SOC_ECC_LOCK_ecc_lock_START  (0)
#define SOC_ECC_LOCK_ecc_lock_END    (3)
#define SOC_ECC_LOCK_reverved_START  (4)
#define SOC_ECC_LOCK_reverved_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_ECC_KEY_LOCK_UNION
 �ṹ˵��  : KEY_LOCK �Ĵ����ṹ���塣��ַƫ����:0x0058����ֵ:0x00000005�����:32
 �Ĵ���˵��: ECC ��Կlock�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ecc_key_lock : 4;  /* bit[0-3] : ECC����Կ�Ĵ�������Կ���ݼĴ�����lock�Ĵ�����
                                                       0x5��lockʹ�ܣ�
                                                       0xA��lock��ʹ�ܣ�
                                                       ����ֵ���Ƿ�ֵ�����ϱ�alarm��
                                                       ������Կ�Ĵ�������Կ���ݼĴ���ǰҪ����lock�Ĵ���Ϊ��ʹ��״̬��
                                                       ����Ҫdebug��Կ�Ĵ�������Կ���ݼĴ���ʱ����Ҫ�����Ĵ�������Ϊ��ʹ��״̬�� */
        unsigned int  reverved     : 28; /* bit[4-31]:  */
    } reg;
} SOC_ECC_KEY_LOCK_UNION;
#endif
#define SOC_ECC_KEY_LOCK_ecc_key_lock_START  (0)
#define SOC_ECC_KEY_LOCK_ecc_key_lock_END    (3)
#define SOC_ECC_KEY_LOCK_reverved_START      (4)
#define SOC_ECC_KEY_LOCK_reverved_END        (31)


/*****************************************************************************
 �ṹ��    : SOC_ECC_DEBUG_UNMASK_UNION
 �ṹ˵��  : DEBUG_UNMASK �Ĵ����ṹ���塣��ַƫ����:0x005C����ֵ:0x0000000A�����:32
 �Ĵ���˵��: ECC debug�׶�ȥ�ڼĴ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ecc_debug_unmask : 4;  /* bit[0-3] : ECC��debug�׶ν��ڲ�����ȥ���ļĴ�����
                                                           0x5��ȥ��ʹ�ܣ�
                                                           0xA��ȥ�ڲ�ʹ�ܣ�
                                                           ����ֵ���Ƿ�ֵ�����ϱ�alarm��
                                                           �üĴ���ֻ����debug״̬����Ч����otp�͹�����debug_disable�źŹ�ͬ�����ڲ������ȥ�ڣ���debug״̬�¿ɶ���д�����������á� */
        unsigned int  reverved         : 28; /* bit[4-31]:  */
    } reg;
} SOC_ECC_DEBUG_UNMASK_UNION;
#endif
#define SOC_ECC_DEBUG_UNMASK_ecc_debug_unmask_START  (0)
#define SOC_ECC_DEBUG_UNMASK_ecc_debug_unmask_END    (3)
#define SOC_ECC_DEBUG_UNMASK_reverved_START          (4)
#define SOC_ECC_DEBUG_UNMASK_reverved_END            (31)


/*****************************************************************************
 �ṹ��    : SOC_ECC_EC_PX1_UNION
 �ṹ˵��  : EC_PX1 �Ĵ����ṹ���塣��ַƫ����:0x0100+4*(n)����ֵ:0x00000000�����:32
 �Ĵ���˵��: ������1�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ec_px1 : 32; /* bit[0-31]: CPU�������ݼĴ�����оƬ�ڲ�RAMΪ64bitλ�������64bitΪ��λ��д����(n��ż����ʼ)����ͬ�������õ����ݵ�ַ�ռ�����û��ֲ�����
                                                 ˵�������й����в��ܶ�д����ʼֵ��RAM��ĳ�ʼֵ����һ����0��
                                                 ��ַ���n��Χ[0,7]��
                                                 ����ecc_mode[2:0]���ж��üĴ����ĺ��壺
                                                 ecc_mode[2:0]=000(���)�������������Բ���ߵ��x���ꣻ
                                                 ecc_mode[2:0]=001(���)����������е�һ����Բ���ߵ��x���ꣻ
                                                 ecc_mode[2:0]=010(ģ��)��ģ�������е�һ����������
                                                 ecc_mode[2:0]=011(ģ��)��ģ�������е�һ����������
                                                 ecc_mode[2:0]=100(ģ��)��ģ�������е�һ����������
                                                 ecc_mode[2:0]=101(ģ��)��ģ�������еĲ�������
                                                 ecc_mode[2:0]=�����������������塣 */
    } reg;
} SOC_ECC_EC_PX1_UNION;
#endif
#define SOC_ECC_EC_PX1_ec_px1_START  (0)
#define SOC_ECC_EC_PX1_ec_px1_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_ECC_EC_PY1_UNION
 �ṹ˵��  : EC_PY1 �Ĵ����ṹ���塣��ַƫ����:0x0148+4*(n)����ֵ:0x00000000�����:32
 �Ĵ���˵��: ������2�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ec_py1 : 32; /* bit[0-31]: ���÷�ʽͬec_px1��
                                                 ����ecc_mode[2:0]���ж������ݵĺ��壺
                                                 ecc_mode[2:0]=000(���)�������������Բ���ߵ��y���ꣻ
                                                 ecc_mode[2:0]=001(���)����������е�һ����Բ���ߵ��y���ꣻ
                                                 ecc_mode[2:0]=010(ģ��)��ģ�������еڶ�����������
                                                 ecc_mode[2:0]=011(ģ��)��ģ�������еڶ�����������
                                                 ecc_mode[2:0]=100(ģ��)��ģ�������еڶ�����������
                                                 ecc_mode[2:0]=�����������������塣 */
    } reg;
} SOC_ECC_EC_PY1_UNION;
#endif
#define SOC_ECC_EC_PY1_ec_py1_START  (0)
#define SOC_ECC_EC_PY1_ec_py1_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_ECC_EC_PX2_UNION
 �ṹ˵��  : EC_PX2 �Ĵ����ṹ���塣��ַƫ����:0x0190+4*(n)����ֵ:0x00000000�����:32
 �Ĵ���˵��: ������3�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ec_px2 : 32; /* bit[0-31]: ���÷�ʽͬec_px1��
                                                 ����ecc_mode[2:0]���ж������ݵĺ��壺
                                                 ecc_mode[2:0]=001(���)����������еڶ�����Բ���ߵ��x���ꣻ
                                                 ecc_mode[2:0]=�����������������塣 */
    } reg;
} SOC_ECC_EC_PX2_UNION;
#endif
#define SOC_ECC_EC_PX2_ec_px2_START  (0)
#define SOC_ECC_EC_PX2_ec_px2_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_ECC_EC_PY2_UNION
 �ṹ˵��  : EC_PY2 �Ĵ����ṹ���塣��ַƫ����:0x01D8+4*(n)����ֵ:0x00000000�����:32
 �Ĵ���˵��: ������4�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ec_py2 : 32; /* bit[0-31]: ���÷�ʽͬec_px1��
                                                 ����ecc_mode[2:0]���ж������ݵĺ��壺
                                                 ecc_mode[2:0]=001(���)����������еڶ�����Բ���ߵ��y���ꣻ
                                                 ecc_mode[2:0]=�����������������塣 */
    } reg;
} SOC_ECC_EC_PY2_UNION;
#endif
#define SOC_ECC_EC_PY2_ec_py2_START  (0)
#define SOC_ECC_EC_PY2_ec_py2_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_ECC_OPRAND_N_UNION
 �ṹ˵��  : OPRAND_N �Ĵ����ṹ���塣��ַƫ����:0x0220+4*(n)����ֵ:0x00000000�����:32
 �Ĵ���˵��: ģ���Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  oprand_n : 32; /* bit[0-31]: ���÷�ʽͬec_px1��
                                                   ģ���㴦���е�ģ����ģ����ֵ�����������
                                                   ��1�� ���ecc_mode[2:0]=000����ecc_mode[2:0]=001�������е��������Բ�����ϵĵ�˻��ߵ�����㣬�˴���operand_n [255:0]����Բ���߲���p[255:0]��
                                                   ��2�� ������еĲ�����Բ�����ϵĵ�ӻ��ߵ�ˣ����е���ģ����������˴���operand_n [255:0]��256bit��ģ���� */
    } reg;
} SOC_ECC_OPRAND_N_UNION;
#endif
#define SOC_ECC_OPRAND_N_oprand_n_START  (0)
#define SOC_ECC_OPRAND_N_oprand_n_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_ECC_OPRAND_C_UNION
 �ṹ˵��  : OPRAND_C �Ĵ����ṹ���塣��ַƫ����:0x0268+4*(n)����ֵ:0x00000000�����:32
 �Ĵ���˵��: Ԥ����ֵ�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  oprand_c : 32; /* bit[0-31]: ���÷�ʽͬec_px1��
                                                   Ԥ����ֵC = 2 (2*64*��len+1��) mod operand_n [255:0] ��ֵ�����Ԥ�����֮��ͨ��д�üĴ���������Ƭ��RAM��,�����operand_n [255:0]Ϊģ����operand_n [255:0]��ֵ���������������������ο�operand_n [255:0]�Ĵ��������� */
    } reg;
} SOC_ECC_OPRAND_C_UNION;
#endif
#define SOC_ECC_OPRAND_C_oprand_c_START  (0)
#define SOC_ECC_OPRAND_C_oprand_c_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_ECC_RESULT_X_UNION
 �ṹ˵��  : RESULT_X �Ĵ����ṹ���塣��ַƫ����:0x02B0+4*(n)����ֵ:0x00000000�����:32
 �Ĵ���˵��: ���1�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  result_x : 32; /* bit[0-31]: ���÷�ʽͬec_px1��
                                                   ����ecc_mode[2:0]���ж������ݵĺ��壺
                                                   ecc_mode[2:0]=000(���)���������������Բ���ߵ��x���ꣻ
                                                   ecc_mode[2:0]=001(���)���������������Բ���ߵ��x���ꣻ
                                                   ecc_mode[2:0]=010(ģ��)��ģ����������
                                                   ecc_mode[2:0]=011(ģ��)��ģ����������
                                                   ecc_mode[2:0]=100(ģ��)��ģ����������
                                                   ecc_mode[2:0]=101(ģ��)��ģ����������
                                                   ecc_mode[2:0]=�����������������塣 */
    } reg;
} SOC_ECC_RESULT_X_UNION;
#endif
#define SOC_ECC_RESULT_X_result_x_START  (0)
#define SOC_ECC_RESULT_X_result_x_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_ECC_RESULT_Y_UNION
 �ṹ˵��  : RESULT_Y �Ĵ����ṹ���塣��ַƫ����:0x02F8+4*(n)����ֵ:0x00000000�����:32
 �Ĵ���˵��: ���2�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  result_y : 32; /* bit[0-31]: ���÷�ʽͬec_px1��
                                                   ����ecc_mode[2:0]���ж������ݵĺ��壺
                                                   ecc_mode[2:0]=000(���)���������������Բ���ߵ��y���ꣻ
                                                   ecc_mode[2:0]=001(���)���������������Բ���ߵ��y���ꣻ
                                                   ecc_mode[2:0]=�����������������塣 */
    } reg;
} SOC_ECC_RESULT_Y_UNION;
#endif
#define SOC_ECC_RESULT_Y_result_y_START  (0)
#define SOC_ECC_RESULT_Y_result_y_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_ECC_MUL_K_UNION
 �ṹ˵��  : MUL_K �Ĵ����ṹ���塣��ַƫ����:0x0340+4*(n)����ֵ:0x00000000�����:32
 �Ĵ���˵��: ��˳����Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  mul_k : 32; /* bit[0-31]: ���÷�ʽͬec_px1��
                                                ����㷨��256bit�������� */
    } reg;
} SOC_ECC_MUL_K_UNION;
#endif
#define SOC_ECC_MUL_K_mul_k_START  (0)
#define SOC_ECC_MUL_K_mul_k_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_ECC_EC_PARA_P_UNION
 �ṹ˵��  : EC_PARA_P �Ĵ����ṹ���塣��ַƫ����:0x0388+4*(n)����ֵ:0x00000000�����:32
 �Ĵ���˵��: ��Բ���߲�����P�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ec_para_p : 32; /* bit[0-31]: ���÷�ʽͬec_px1��
                                                    ��Բ���߲�����256bit������p�� */
    } reg;
} SOC_ECC_EC_PARA_P_UNION;
#endif
#define SOC_ECC_EC_PARA_P_ec_para_p_START  (0)
#define SOC_ECC_EC_PARA_P_ec_para_p_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_ECC_EC_PARA_A_UNION
 �ṹ˵��  : EC_PARA_A �Ĵ����ṹ���塣��ַƫ����:0x03D0+4*(n)����ֵ:0x00000000�����:32
 �Ĵ���˵��: ��Բ���߲�����A�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ec_para_a : 32; /* bit[0-31]: ���÷�ʽͬec_px1��
                                                    ��Բ���߲�����256bit������a�� */
    } reg;
} SOC_ECC_EC_PARA_A_UNION;
#endif
#define SOC_ECC_EC_PARA_A_ec_para_a_START  (0)
#define SOC_ECC_EC_PARA_A_ec_para_a_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_ECC_EC_PARA_B_UNION
 �ṹ˵��  : EC_PARA_B �Ĵ����ṹ���塣��ַƫ����:0x0418+4*(n)����ֵ:0x00000000�����:32
 �Ĵ���˵��: ��Բ���߲�����B�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ec_para_b : 32; /* bit[0-31]: ���÷�ʽͬec_px1��
                                                    ��Բ���߲�����256bit������b�� */
    } reg;
} SOC_ECC_EC_PARA_B_UNION;
#endif
#define SOC_ECC_EC_PARA_B_ec_para_b_START  (0)
#define SOC_ECC_EC_PARA_B_ec_para_b_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_ECC_EC_PARA_N_UNION
 �ṹ˵��  : EC_PARA_N �Ĵ����ṹ���塣��ַƫ����:0x0460+4*(n)����ֵ:0x00000000�����:32
 �Ĵ���˵��: ��Բ���߲�����N�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ec_para_n : 32; /* bit[0-31]: ���÷�ʽͬec_px1��
                                                    ��Բ���߲�����256bit������n�� */
    } reg;
} SOC_ECC_EC_PARA_N_UNION;
#endif
#define SOC_ECC_EC_PARA_N_ec_para_n_START  (0)
#define SOC_ECC_EC_PARA_N_ec_para_n_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_ECC_EC_PARA_GX_UNION
 �ṹ˵��  : EC_PARA_GX �Ĵ����ṹ���塣��ַƫ����:0x04A8+4*(n)����ֵ:0x00000000�����:32
 �Ĵ���˵��: ��Բ���߲����л���G��X����Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ec_para_gx : 32; /* bit[0-31]: ���÷�ʽͬec_px1��
                                                     ��Բ���߲�����256bit������Gx�� */
    } reg;
} SOC_ECC_EC_PARA_GX_UNION;
#endif
#define SOC_ECC_EC_PARA_GX_ec_para_gx_START  (0)
#define SOC_ECC_EC_PARA_GX_ec_para_gx_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_ECC_EC_PARA_GY_UNION
 �ṹ˵��  : EC_PARA_GY �Ĵ����ṹ���塣��ַƫ����:0x04F0+4*(n)����ֵ:0x00000000�����:32
 �Ĵ���˵��: ��Բ���߲����л���G��Y����Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ec_para_gy : 32; /* bit[0-31]: ���÷�ʽͬec_px1��
                                                     ��Բ���߲�����256bit������Gy�� */
    } reg;
} SOC_ECC_EC_PARA_GY_UNION;
#endif
#define SOC_ECC_EC_PARA_GY_ec_para_gy_START  (0)
#define SOC_ECC_EC_PARA_GY_ec_para_gy_END    (31)






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

#endif /* end of soc_ecc_interface.h */
