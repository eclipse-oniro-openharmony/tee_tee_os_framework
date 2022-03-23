/******************************************************************************

                 ��Ȩ���� (C), 2001-2019, ��Ϊ�������޹�˾

 ******************************************************************************
  �� �� ��   : soc_etzpc_interface.h
  �� �� ��   : ����
  ��    ��   : Excel2Code
  ��������   : 2019-10-26 11:03:09
  ����޸�   :
  ��������   : �ӿ�ͷ�ļ�
  �����б�   :
  �޸���ʷ   :
  1.��    ��   : 2019��10��26��
    ��    ��   : l00249396
    �޸�����   : �ӡ�HiEPS V210 �Ĵ����ֲ�_ETZPC.xml���Զ�����

******************************************************************************/

/*****************************************************************************
  1 ����ͷ�ļ�����
*****************************************************************************/

#ifndef __SOC_ETZPC_INTERFACE_H__
#define __SOC_ETZPC_INTERFACE_H__

#ifdef __cplusplus
    #if __cplusplus
        extern "C" {
    #endif
#endif



/*****************************************************************************
  2 �궨��
*****************************************************************************/

/****************************************************************************
                     (1/1) ETZPC
 ****************************************************************************/
/* �Ĵ���˵�������ڿ��ư�ȫ�����������С
            �Ӳ�TZMA���ж�secram�Ŀ��ƣ���4KBΪ��λ
            0x00000000 = no secure region
            0x00000001 = 4KB secure region
            0x00000002 = 8KB secure region
            ��
            0x000001FF = 2044KB secure region
            0x00000200 �����ϵ����ý�������secram�ռ����ɰ�ȫ�ռ䡣
   λ����UNION�ṹ:  SOC_ETZPC_R0SIZE_UNION */
#define SOC_ETZPC_R0SIZE_ADDR(base)                   ((base) + (0x000))

/* �Ĵ���˵����IP��ȫ����״̬�Ĵ���0��
   λ����UNION�ṹ:  SOC_ETZPC_DECPROT0STAT_UNION */
#define SOC_ETZPC_DECPROT0STAT_ADDR(base)             ((base) + (0x800))

/* �Ĵ���˵����IP��ȫ������λ�Ĵ���0��
   λ����UNION�ṹ:  SOC_ETZPC_DECPROT0SET_UNION */
#define SOC_ETZPC_DECPROT0SET_ADDR(base)              ((base) + (0x804))

/* �Ĵ���˵����IP��ȫ��������Ĵ���0��
   λ����UNION�ṹ:  SOC_ETZPC_DECPROT0CLR_UNION */
#define SOC_ETZPC_DECPROT0CLR_ADDR(base)              ((base) + (0x808))

/* �Ĵ���˵����IP��ȫ����״̬�Ĵ���1��
   λ����UNION�ṹ:  SOC_ETZPC_DECPROT1STAT_UNION */
#define SOC_ETZPC_DECPROT1STAT_ADDR(base)             ((base) + (0x80C))

/* �Ĵ���˵����IP��ȫ������λ�Ĵ���1��
   λ����UNION�ṹ:  SOC_ETZPC_DECPROT1SET_UNION */
#define SOC_ETZPC_DECPROT1SET_ADDR(base)              ((base) + (0x810))

/* �Ĵ���˵����IP��ȫ��������Ĵ���1��
   λ����UNION�ṹ:  SOC_ETZPC_DECPROT1CLR_UNION */
#define SOC_ETZPC_DECPROT1CLR_ADDR(base)              ((base) + (0x814))

/* �Ĵ���˵����IP��ȫ����״̬�Ĵ���2��
   λ����UNION�ṹ:  SOC_ETZPC_DECPROT2STAT_UNION */
#define SOC_ETZPC_DECPROT2STAT_ADDR(base)             ((base) + (0x818))

/* �Ĵ���˵����IP��ȫ������λ�Ĵ���2��
   λ����UNION�ṹ:  SOC_ETZPC_DECPROT2SET_UNION */
#define SOC_ETZPC_DECPROT2SET_ADDR(base)              ((base) + (0x81C))

/* �Ĵ���˵����IP��ȫ��������Ĵ���2��
   λ����UNION�ṹ:  SOC_ETZPC_DECPROT2CLR_UNION */
#define SOC_ETZPC_DECPROT2CLR_ADDR(base)              ((base) + (0x820))

/* �Ĵ���˵����IP��ȫ����״̬�Ĵ���3��
   λ����UNION�ṹ:  SOC_ETZPC_DECPROT3STAT_UNION */
#define SOC_ETZPC_DECPROT3STAT_ADDR(base)             ((base) + (0x824))

/* �Ĵ���˵����IP��ȫ������λ�Ĵ���3��
   λ����UNION�ṹ:  SOC_ETZPC_DECPROT3SET_UNION */
#define SOC_ETZPC_DECPROT3SET_ADDR(base)              ((base) + (0x828))

/* �Ĵ���˵����IP��ȫ��������Ĵ���3��
   λ����UNION�ṹ:  SOC_ETZPC_DECPROT3CLR_UNION */
#define SOC_ETZPC_DECPROT3CLR_ADDR(base)              ((base) + (0x82C))

/* �Ĵ���˵����IP��ȫ����״̬�Ĵ���4��
   λ����UNION�ṹ:  SOC_ETZPC_DECPROT4STAT_UNION */
#define SOC_ETZPC_DECPROT4STAT_ADDR(base)             ((base) + (0x830))

/* �Ĵ���˵����IP��ȫ������λ�Ĵ���4��
   λ����UNION�ṹ:  SOC_ETZPC_DECPROT4SET_UNION */
#define SOC_ETZPC_DECPROT4SET_ADDR(base)              ((base) + (0x834))

/* �Ĵ���˵����IP��ȫ��������Ĵ���4��
   λ����UNION�ṹ:  SOC_ETZPC_DECPROT4CLR_UNION */
#define SOC_ETZPC_DECPROT4CLR_ADDR(base)              ((base) + (0x838))

/* �Ĵ���˵����IP��ȫ����״̬�Ĵ���5��
   λ����UNION�ṹ:  SOC_ETZPC_DECPROT5STAT_UNION */
#define SOC_ETZPC_DECPROT5STAT_ADDR(base)             ((base) + (0x83C))

/* �Ĵ���˵����IP��ȫ������λ�Ĵ���5��
   λ����UNION�ṹ:  SOC_ETZPC_DECPROT5SET_UNION */
#define SOC_ETZPC_DECPROT5SET_ADDR(base)              ((base) + (0x840))

/* �Ĵ���˵����IP��ȫ��������Ĵ���5��
   λ����UNION�ṹ:  SOC_ETZPC_DECPROT5CLR_UNION */
#define SOC_ETZPC_DECPROT5CLR_ADDR(base)              ((base) + (0x844))

/* �Ĵ���˵����IP��ȫ����״̬�Ĵ���6��
   λ����UNION�ṹ:  SOC_ETZPC_DECPROT6STAT_UNION */
#define SOC_ETZPC_DECPROT6STAT_ADDR(base)             ((base) + (0x848))

/* �Ĵ���˵����IP��ȫ������λ�Ĵ���6��
   λ����UNION�ṹ:  SOC_ETZPC_DECPROT6SET_UNION */
#define SOC_ETZPC_DECPROT6SET_ADDR(base)              ((base) + (0x84C))

/* �Ĵ���˵����IP��ȫ��������Ĵ���6��
   λ����UNION�ṹ:  SOC_ETZPC_DECPROT6CLR_UNION */
#define SOC_ETZPC_DECPROT6CLR_ADDR(base)              ((base) + (0x850))

/* �Ĵ���˵����IP��ȫ����״̬�Ĵ���7��
   λ����UNION�ṹ:  SOC_ETZPC_DECPROT7STAT_UNION */
#define SOC_ETZPC_DECPROT7STAT_ADDR(base)             ((base) + (0x854))

/* �Ĵ���˵����IP��ȫ������λ�Ĵ���7��
   λ����UNION�ṹ:  SOC_ETZPC_DECPROT7SET_UNION */
#define SOC_ETZPC_DECPROT7SET_ADDR(base)              ((base) + (0x858))

/* �Ĵ���˵����IP��ȫ��������Ĵ���7��
   λ����UNION�ṹ:  SOC_ETZPC_DECPROT7CLR_UNION */
#define SOC_ETZPC_DECPROT7CLR_ADDR(base)              ((base) + (0x85C))

/* �Ĵ���˵����IP��ȫ����״̬�Ĵ���8��
   λ����UNION�ṹ:  SOC_ETZPC_DECPROT8STAT_UNION */
#define SOC_ETZPC_DECPROT8STAT_ADDR(base)             ((base) + (0x860))

/* �Ĵ���˵����IP��ȫ������λ�Ĵ���8��
   λ����UNION�ṹ:  SOC_ETZPC_DECPROT8SET_UNION */
#define SOC_ETZPC_DECPROT8SET_ADDR(base)              ((base) + (0x864))

/* �Ĵ���˵����IP��ȫ��������Ĵ���8��
   λ����UNION�ṹ:  SOC_ETZPC_DECPROT8CLR_UNION */
#define SOC_ETZPC_DECPROT8CLR_ADDR(base)              ((base) + (0x868))

/* �Ĵ���˵��������reg0�Ĵ�������Ϣ��
   λ����UNION�ṹ:  SOC_ETZPC_REG0_STAT_UNION */
#define SOC_ETZPC_REG0_STAT_ADDR(base)                ((base) + (0x86C))

/* �Ĵ���˵��������reg1�Ĵ�������Ϣ��
   λ����UNION�ṹ:  SOC_ETZPC_REG1_STAT_UNION */
#define SOC_ETZPC_REG1_STAT_ADDR(base)                ((base) + (0x870))

/* �Ĵ���˵�����Ĵ�PATCHУ����Ϣ�ļĴ���0
   λ����UNION�ṹ:  SOC_ETZPC_EFUSEC2HIEPS_PATCH0_SEC_UNION */
#define SOC_ETZPC_EFUSEC2HIEPS_PATCH0_SEC_ADDR(base)  ((base) + (0x874))

/* �Ĵ���˵�����Ĵ�PATCHУ����Ϣ�ļĴ���1
   λ����UNION�ṹ:  SOC_ETZPC_EFUSEC2HIEPS_PATCH1_SEC_UNION */
#define SOC_ETZPC_EFUSEC2HIEPS_PATCH1_SEC_ADDR(base)  ((base) + (0x878))

/* �Ĵ���˵�����Ĵ�PATCHУ����Ϣ�ļĴ���2
   λ����UNION�ṹ:  SOC_ETZPC_EFUSEC2HIEPS_PATCH2_SEC_UNION */
#define SOC_ETZPC_EFUSEC2HIEPS_PATCH2_SEC_ADDR(base)  ((base) + (0x87C))

/* �Ĵ���˵�����Ĵ�PATCHУ����Ϣ�ļĴ���3
   λ����UNION�ṹ:  SOC_ETZPC_EFUSEC2HIEPS_PATCH3_SEC_UNION */
#define SOC_ETZPC_EFUSEC2HIEPS_PATCH3_SEC_ADDR(base)  ((base) + (0x880))

/* �Ĵ���˵�����Ĵ�PATCHУ����Ϣ�ļĴ���4
   λ����UNION�ṹ:  SOC_ETZPC_EFUSEC2HIEPS_PATCH4_SEC_UNION */
#define SOC_ETZPC_EFUSEC2HIEPS_PATCH4_SEC_ADDR(base)  ((base) + (0x884))

/* �Ĵ���˵�����Ĵ�PATCHУ����Ϣ�ļĴ���5
   λ����UNION�ṹ:  SOC_ETZPC_EFUSEC2HIEPS_PATCH5_SEC_UNION */
#define SOC_ETZPC_EFUSEC2HIEPS_PATCH5_SEC_ADDR(base)  ((base) + (0x888))

/* �Ĵ���˵�����Ĵ�PATCHУ����Ϣ�ļĴ���6
   λ����UNION�ṹ:  SOC_ETZPC_EFUSEC2HIEPS_PATCH6_SEC_UNION */
#define SOC_ETZPC_EFUSEC2HIEPS_PATCH6_SEC_ADDR(base)  ((base) + (0x88C))

/* �Ĵ���˵�����Ĵ�PATCHУ����Ϣ�ļĴ���7
   λ����UNION�ṹ:  SOC_ETZPC_EFUSEC2HIEPS_PATCH7_SEC_UNION */
#define SOC_ETZPC_EFUSEC2HIEPS_PATCH7_SEC_ADDR(base)  ((base) + (0x890))





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
                     (1/1) ETZPC
 ****************************************************************************/
/*****************************************************************************
 �ṹ��    : SOC_ETZPC_R0SIZE_UNION
 �ṹ˵��  : R0SIZE �Ĵ����ṹ���塣��ַƫ����:0x000����ֵ:0x000003FF�����:32
 �Ĵ���˵��: ���ڿ��ư�ȫ�����������С
            �Ӳ�TZMA���ж�secram�Ŀ��ƣ���4KBΪ��λ
            0x00000000 = no secure region
            0x00000001 = 4KB secure region
            0x00000002 = 8KB secure region
            ��
            0x000001FF = 2044KB secure region
            0x00000200 �����ϵ����ý�������secram�ռ����ɰ�ȫ�ռ䡣
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved_0: 10; /* bit[0-9]  : ������ */
        unsigned int  reserved_1: 22; /* bit[10-31]: ������HiEPSδʹ�á� */
    } reg;
} SOC_ETZPC_R0SIZE_UNION;
#endif


/*****************************************************************************
 �ṹ��    : SOC_ETZPC_DECPROT0STAT_UNION
 �ṹ˵��  : DECPROT0STAT �Ĵ����ṹ���塣��ַƫ����:0x800����ֵ:0x00000000�����:32
 �Ĵ���˵��: IP��ȫ����״̬�Ĵ���0��
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved_0       : 1;  /* bit[0] : ������HIEPSδʹ�á� */
        unsigned int  reserved_1       : 1;  /* bit[1] : ������HIEPSδʹ�á� */
        unsigned int  reserved_2       : 1;  /* bit[2] : ������HIEPSδʹ�á� */
        unsigned int  reserved_3       : 1;  /* bit[3] : ������HIEPSδʹ�á� */
        unsigned int  tz_secure_km_0   : 1;  /* bit[4] : KM ��״̬�Ĵ� */
        unsigned int  tz_secure_km_1   : 1;  /* bit[5] : KM ��״̬�Ĵ� */
        unsigned int  tz_secure_km_2   : 1;  /* bit[6] : KM ��״̬�Ĵ� */
        unsigned int  tz_secure_km_3   : 1;  /* bit[7] : KM ��״̬�Ĵ� */
        unsigned int  tz_secure_sce_0  : 1;  /* bit[8] : SCE ��״̬�Ĵ� */
        unsigned int  tz_secure_sce_1  : 1;  /* bit[9] : SCE ��״̬�Ĵ� */
        unsigned int  tz_secure_sce_2  : 1;  /* bit[10]: SCE ��״̬�Ĵ� */
        unsigned int  tz_secure_sce_3  : 1;  /* bit[11]: SCE ��״̬�Ĵ� */
        unsigned int  tz_secure_pke_0  : 1;  /* bit[12]: PKE ��״̬�Ĵ� */
        unsigned int  tz_secure_pke_1  : 1;  /* bit[13]: PKE ��״̬�Ĵ� */
        unsigned int  tz_secure_pke_2  : 1;  /* bit[14]: PKE ��״̬�Ĵ� */
        unsigned int  tz_secure_pke_3  : 1;  /* bit[15]: PKE ��״̬�Ĵ� */
        unsigned int  reserved_4       : 1;  /* bit[16]: ������HIEPSδʹ�á� */
        unsigned int  reserved_5       : 1;  /* bit[17]: ������HIEPSδʹ�á� */
        unsigned int  reserved_6       : 1;  /* bit[18]: ������HIEPSδʹ�á� */
        unsigned int  reserved_7       : 1;  /* bit[19]: ������HIEPSδʹ�á� */
        unsigned int  tz_secure_sce2_0 : 1;  /* bit[20]: SCE2 ��״̬�Ĵ� */
        unsigned int  tz_secure_sce2_1 : 1;  /* bit[21]: SCE2 ��״̬�Ĵ� */
        unsigned int  tz_secure_sce2_2 : 1;  /* bit[22]: SCE2 ��״̬�Ĵ� */
        unsigned int  tz_secure_sce2_3 : 1;  /* bit[23]: SCE2 ��״̬�Ĵ� */
        unsigned int  tz_secure_pke2_0 : 1;  /* bit[24]: PKE2 ��״̬�Ĵ� */
        unsigned int  tz_secure_pke2_1 : 1;  /* bit[25]: PKE2 ��״̬�Ĵ� */
        unsigned int  tz_secure_pke2_2 : 1;  /* bit[26]: PKE2 ��״̬�Ĵ� */
        unsigned int  tz_secure_pke2_3 : 1;  /* bit[27]: PKE2 ��״̬�Ĵ� */
        unsigned int  reserved_8       : 1;  /* bit[28]: ������HIEPSδʹ�á� */
        unsigned int  reserved_9       : 1;  /* bit[29]: ������HIEPSδʹ�á� */
        unsigned int  reserved_10      : 1;  /* bit[30]: ������HIEPSδʹ�á� */
        unsigned int  reserved_11      : 1;  /* bit[31]: ������HiEPSδʹ�á� */
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
 �ṹ��    : SOC_ETZPC_DECPROT0SET_UNION
 �ṹ˵��  : DECPROT0SET �Ĵ����ṹ���塣��ַƫ����:0x804����ֵ:0x00000000�����:32
 �Ĵ���˵��: IP��ȫ������λ�Ĵ���0��
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved_0 : 1;  /* bit[0] : ������HIEPSδʹ�á� */
        unsigned int  reserved_1 : 1;  /* bit[1] : ������HIEPSδʹ�á� */
        unsigned int  reserved_2 : 1;  /* bit[2] : ������HIEPSδʹ�á� */
        unsigned int  reserved_3 : 1;  /* bit[3] : ������HIEPSδʹ�á� */
        unsigned int  km_set_0   : 1;  /* bit[4] : KM �İ�ȫ��λ�Ĵ��� */
        unsigned int  km_set_1   : 1;  /* bit[5] : KM �İ�ȫ��λ�Ĵ��� */
        unsigned int  km_set_2   : 1;  /* bit[6] : KM �İ�ȫ��λ�Ĵ��� */
        unsigned int  km_set_3   : 1;  /* bit[7] : KM �İ�ȫ��λ�Ĵ��� */
        unsigned int  sce_set_0  : 1;  /* bit[8] : SCE �İ�ȫ��λ�Ĵ��� */
        unsigned int  sce_set_1  : 1;  /* bit[9] : SCE �İ�ȫ��λ�Ĵ��� */
        unsigned int  sce_set_2  : 1;  /* bit[10]: SCE �İ�ȫ��λ�Ĵ��� */
        unsigned int  sce_set_3  : 1;  /* bit[11]: SCE �İ�ȫ��λ�Ĵ��� */
        unsigned int  pke_set_0  : 1;  /* bit[12]: PKE �İ�ȫ��λ�Ĵ��� */
        unsigned int  pke_set_1  : 1;  /* bit[13]: PKE �İ�ȫ��λ�Ĵ��� */
        unsigned int  pke_set_2  : 1;  /* bit[14]: PKE �İ�ȫ��λ�Ĵ��� */
        unsigned int  pke_set_3  : 1;  /* bit[15]: PKE �İ�ȫ��λ�Ĵ��� */
        unsigned int  reserved_4 : 1;  /* bit[16]: ������HIEPSδʹ�á� */
        unsigned int  reserved_5 : 1;  /* bit[17]: ������HIEPSδʹ�á� */
        unsigned int  reserved_6 : 1;  /* bit[18]: ������HIEPSδʹ�á� */
        unsigned int  reserved_7 : 1;  /* bit[19]: ������HIEPSδʹ�á� */
        unsigned int  sce2_set_0 : 1;  /* bit[20]: SCE2 �İ�ȫ��λ�Ĵ��� */
        unsigned int  sce2_set_1 : 1;  /* bit[21]: SCE2 �İ�ȫ��λ�Ĵ��� */
        unsigned int  sce2_set_2 : 1;  /* bit[22]: SCE2 �İ�ȫ��λ�Ĵ��� */
        unsigned int  sce2_set_3 : 1;  /* bit[23]: SCE2 �İ�ȫ��λ�Ĵ��� */
        unsigned int  pke2_set_0 : 1;  /* bit[24]: PKE2 �İ�ȫ��λ�Ĵ��� */
        unsigned int  pke2_set_1 : 1;  /* bit[25]: PKE2 �İ�ȫ��λ�Ĵ��� */
        unsigned int  pke2_set_2 : 1;  /* bit[26]: PKE2 �İ�ȫ��λ�Ĵ��� */
        unsigned int  pke2_set_3 : 1;  /* bit[27]: PKE2 �İ�ȫ��λ�Ĵ��� */
        unsigned int  reserved_8 : 1;  /* bit[28]: ������HIEPSδʹ�á� */
        unsigned int  reserved_9 : 1;  /* bit[29]: ������HIEPSδʹ�á� */
        unsigned int  reserved_10: 1;  /* bit[30]: ������HIEPSδʹ�á� */
        unsigned int  reserved_11: 1;  /* bit[31]: ������HIEPSδʹ�á� */
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
 �ṹ��    : SOC_ETZPC_DECPROT0CLR_UNION
 �ṹ˵��  : DECPROT0CLR �Ĵ����ṹ���塣��ַƫ����:0x808����ֵ:0x00000000�����:32
 �Ĵ���˵��: IP��ȫ��������Ĵ���0��
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved_0 : 1;  /* bit[0] : ������HIEPSδʹ�á� */
        unsigned int  reserved_1 : 1;  /* bit[1] : ������HIEPSδʹ�á� */
        unsigned int  reserved_2 : 1;  /* bit[2] : ������HIEPSδʹ�á� */
        unsigned int  reserved_3 : 1;  /* bit[3] : ������HIEPSδʹ�á� */
        unsigned int  km_clr_0   : 1;  /* bit[4] : KM �İ�ȫ����Ĵ��� */
        unsigned int  km_clr_1   : 1;  /* bit[5] : KM �İ�ȫ����Ĵ��� */
        unsigned int  km_clr_2   : 1;  /* bit[6] : KM �İ�ȫ����Ĵ��� */
        unsigned int  km_clr_3   : 1;  /* bit[7] : KM �İ�ȫ����Ĵ��� */
        unsigned int  sce_clr_0  : 1;  /* bit[8] : SCE �İ�ȫ����Ĵ��� */
        unsigned int  sce_clr_1  : 1;  /* bit[9] : SCE �İ�ȫ����Ĵ��� */
        unsigned int  sce_clr_2  : 1;  /* bit[10]: SCE �İ�ȫ����Ĵ��� */
        unsigned int  sce_clr_3  : 1;  /* bit[11]: SCE �İ�ȫ����Ĵ��� */
        unsigned int  pke_clr_0  : 1;  /* bit[12]: PKE �İ�ȫ����Ĵ��� */
        unsigned int  pke_clr_1  : 1;  /* bit[13]: PKE �İ�ȫ����Ĵ��� */
        unsigned int  pke_clr_2  : 1;  /* bit[14]: PKE �İ�ȫ����Ĵ��� */
        unsigned int  pke_clr_3  : 1;  /* bit[15]: PKE �İ�ȫ����Ĵ��� */
        unsigned int  reserved_4 : 1;  /* bit[16]: ������HIEPSδʹ�á� */
        unsigned int  reserved_5 : 1;  /* bit[17]: ������HIEPSδʹ�á� */
        unsigned int  reserved_6 : 1;  /* bit[18]: ������HIEPSδʹ�á� */
        unsigned int  reserved_7 : 1;  /* bit[19]: ������HIEPSδʹ�á� */
        unsigned int  sce2_clr_0 : 1;  /* bit[20]: SCE2 �İ�ȫ����Ĵ��� */
        unsigned int  sce2_clr_1 : 1;  /* bit[21]: SCE2 �İ�ȫ����Ĵ��� */
        unsigned int  sce2_clr_2 : 1;  /* bit[22]: SCE2 �İ�ȫ����Ĵ��� */
        unsigned int  sce2_clr_3 : 1;  /* bit[23]: SCE2 �İ�ȫ����Ĵ��� */
        unsigned int  pke2_clr_0 : 1;  /* bit[24]: PKE2 �İ�ȫ����Ĵ��� */
        unsigned int  pke2_clr_1 : 1;  /* bit[25]: PKE2 �İ�ȫ����Ĵ��� */
        unsigned int  pke2_clr_2 : 1;  /* bit[26]: PKE2 �İ�ȫ����Ĵ��� */
        unsigned int  pke2_clr_3 : 1;  /* bit[27]: PKE2 �İ�ȫ����Ĵ��� */
        unsigned int  reserved_8 : 1;  /* bit[28]: ������HIEPSδʹ�á� */
        unsigned int  reserved_9 : 1;  /* bit[29]: ������HIEPSδʹ�á� */
        unsigned int  reserved_10: 1;  /* bit[30]: ������HIEPSδʹ�á� */
        unsigned int  reserved_11: 1;  /* bit[31]: ������HIEPSδʹ�á� */
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
 �ṹ��    : SOC_ETZPC_DECPROT1STAT_UNION
 �ṹ˵��  : DECPROT1STAT �Ĵ����ṹ���塣��ַƫ����:0x80C����ֵ:0x00000000�����:32
 �Ĵ���˵��: IP��ȫ����״̬�Ĵ���1��
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  config_state_0  : 1;  /* bit[0] : CONFIG�İ�ȫ״̬�Ĵ��� */
        unsigned int  config_state_1  : 1;  /* bit[1] : CONFIG�İ�ȫ״̬�Ĵ��� */
        unsigned int  config_state_2  : 1;  /* bit[2] : CONFIG�İ�ȫ״̬�Ĵ��� */
        unsigned int  config_state_3  : 1;  /* bit[3] : CONFIG�İ�ȫ״̬�Ĵ��� */
        unsigned int  reserved_0      : 1;  /* bit[4] : ������HIEPSδʹ�á� */
        unsigned int  reserved_1      : 1;  /* bit[5] : ������HIEPSδʹ�á� */
        unsigned int  reserved_2      : 1;  /* bit[6] : ������HIEPSδʹ�á� */
        unsigned int  reserved_3      : 1;  /* bit[7] : ������HIEPSδʹ�á� */
        unsigned int  trng_state_0    : 1;  /* bit[8] : TRNG�İ�ȫ״̬�Ĵ��� */
        unsigned int  trng_state_1    : 1;  /* bit[9] : TRNG�İ�ȫ״̬�Ĵ��� */
        unsigned int  trng_state_2    : 1;  /* bit[10]: TRNG�İ�ȫ״̬�Ĵ��� */
        unsigned int  trng_state_3    : 1;  /* bit[11]: TRNG�İ�ȫ״̬�Ĵ��� */
        unsigned int  timer_state_0   : 1;  /* bit[12]: TIMER�İ�ȫ״̬�Ĵ��� */
        unsigned int  timer_state_1   : 1;  /* bit[13]: TIMER�İ�ȫ״̬�Ĵ��� */
        unsigned int  timer_state_2   : 1;  /* bit[14]: TIMER�İ�ȫ״̬�Ĵ��� */
        unsigned int  timer_state_3   : 1;  /* bit[15]: TIMER�İ�ȫ״̬�Ĵ��� */
        unsigned int  tz_secure_mmu_0 : 1;  /* bit[16]: MMU ��״̬�Ĵ� */
        unsigned int  tz_secure_mmu_1 : 1;  /* bit[17]: MMU ��״̬�Ĵ� */
        unsigned int  tz_secure_mmu_2 : 1;  /* bit[18]: MMU ��״̬�Ĵ� */
        unsigned int  tz_secure_mmu_3 : 1;  /* bit[19]: MMU ��״̬�Ĵ� */
        unsigned int  reserved_4      : 1;  /* bit[20]: ������HIEPSδʹ�á� */
        unsigned int  reserved_5      : 1;  /* bit[21]: ������HIEPSδʹ�á� */
        unsigned int  reserved_6      : 1;  /* bit[22]: ������HIEPSδʹ�á� */
        unsigned int  reserved_7      : 1;  /* bit[23]: ������HIEPSδʹ�á� */
        unsigned int  reserved_8      : 1;  /* bit[24]: ������HIEPSδʹ�á� */
        unsigned int  reserved_9      : 1;  /* bit[25]: ������HIEPSδʹ�á� */
        unsigned int  reserved_10     : 1;  /* bit[26]: ������HIEPSδʹ�á� */
        unsigned int  reserved_11     : 1;  /* bit[27]: ������HIEPSδʹ�á� */
        unsigned int  reserved_12     : 1;  /* bit[28]: ������HIEPSδʹ�á� */
        unsigned int  reserved_13     : 1;  /* bit[29]: ������HIEPSδʹ�á� */
        unsigned int  reserved_14     : 1;  /* bit[30]: ������HIEPSδʹ�á� */
        unsigned int  reserved_15     : 1;  /* bit[31]: ������HIEPSδʹ�� */
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
 �ṹ��    : SOC_ETZPC_DECPROT1SET_UNION
 �ṹ˵��  : DECPROT1SET �Ĵ����ṹ���塣��ַƫ����:0x810����ֵ:0x00000000�����:32
 �Ĵ���˵��: IP��ȫ������λ�Ĵ���1��
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  config_set_0 : 1;  /* bit[0] : CONFIG�İ�ȫ������λ�Ĵ��� */
        unsigned int  config_set_1 : 1;  /* bit[1] : CONFIG�İ�ȫ������λ�Ĵ��� */
        unsigned int  config_set_2 : 1;  /* bit[2] : CONFIG�İ�ȫ������λ�Ĵ��� */
        unsigned int  config_set_3 : 1;  /* bit[3] : CONFIG�İ�ȫ������λ�Ĵ��� */
        unsigned int  reserved_0   : 1;  /* bit[4] : ������HIEPSδʹ�á� */
        unsigned int  reserved_1   : 1;  /* bit[5] : ������HIEPSδʹ�á� */
        unsigned int  reserved_2   : 1;  /* bit[6] : ������HIEPSδʹ�á� */
        unsigned int  reserved_3   : 1;  /* bit[7] : ������HIEPSδʹ�á� */
        unsigned int  trng_set_0   : 1;  /* bit[8] : TRNG�İ�ȫ������λ�Ĵ��� */
        unsigned int  trng_set_1   : 1;  /* bit[9] : TRNG�İ�ȫ������λ�Ĵ��� */
        unsigned int  trng_set_2   : 1;  /* bit[10]: TRNG�İ�ȫ������λ�Ĵ��� */
        unsigned int  trng_set_3   : 1;  /* bit[11]: TRNG�İ�ȫ������λ�Ĵ��� */
        unsigned int  timer_set_0  : 1;  /* bit[12]: TIMER�İ�ȫ������λ�Ĵ��� */
        unsigned int  timer_set_1  : 1;  /* bit[13]: TIMER�İ�ȫ������λ�Ĵ��� */
        unsigned int  timer_set_2  : 1;  /* bit[14]: TIMER�İ�ȫ������λ�Ĵ��� */
        unsigned int  timer_set_3  : 1;  /* bit[15]: TIMER�İ�ȫ������λ�Ĵ��� */
        unsigned int  mmu_set_0    : 1;  /* bit[16]: MMU �İ�ȫ������λ�Ĵ��� */
        unsigned int  mmu_set_1    : 1;  /* bit[17]: MMU �İ�ȫ������λ�Ĵ��� */
        unsigned int  mmu_set_2    : 1;  /* bit[18]: MMU �İ�ȫ������λ�Ĵ��� */
        unsigned int  mmu_set_3    : 1;  /* bit[19]: MMU �İ�ȫ������λ�Ĵ��� */
        unsigned int  reserved_4   : 1;  /* bit[20]: ������HIEPSδʹ�á� */
        unsigned int  reserved_5   : 1;  /* bit[21]: ������HIEPSδʹ�á� */
        unsigned int  reserved_6   : 1;  /* bit[22]: ������HIEPSδʹ�á� */
        unsigned int  reserved_7   : 1;  /* bit[23]: ������HIEPSδʹ�á� */
        unsigned int  reserved_8   : 1;  /* bit[24]: ������HIEPSδʹ�á� */
        unsigned int  reserved_9   : 1;  /* bit[25]: ������HIEPSδʹ�á� */
        unsigned int  reserved_10  : 1;  /* bit[26]: ������HIEPSδʹ�á� */
        unsigned int  reserved_11  : 1;  /* bit[27]: ������HIEPSδʹ�á� */
        unsigned int  reserved_12  : 1;  /* bit[28]: ������HIEPSδʹ�á� */
        unsigned int  reserved_13  : 1;  /* bit[29]: ������HIEPSδʹ�á� */
        unsigned int  reserved_14  : 1;  /* bit[30]: ������HIEPSδʹ�á� */
        unsigned int  reserved_15  : 1;  /* bit[31]: ������HIEPSδʹ�á� */
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
 �ṹ��    : SOC_ETZPC_DECPROT1CLR_UNION
 �ṹ˵��  : DECPROT1CLR �Ĵ����ṹ���塣��ַƫ����:0x814����ֵ:0x00000000�����:32
 �Ĵ���˵��: IP��ȫ��������Ĵ���1��
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  config_clr_0 : 1;  /* bit[0] : CONFIG�İ�ȫ��������Ĵ��� */
        unsigned int  config_clr_1 : 1;  /* bit[1] : CONFIG�İ�ȫ��������Ĵ��� */
        unsigned int  config_clr_2 : 1;  /* bit[2] : CONFIG�İ�ȫ��������Ĵ��� */
        unsigned int  config_clr_3 : 1;  /* bit[3] : CONFIG�İ�ȫ��������Ĵ��� */
        unsigned int  reserved_0   : 1;  /* bit[4] : ������HIEPSδʹ�á� */
        unsigned int  reserved_1   : 1;  /* bit[5] : ������HIEPSδʹ�á� */
        unsigned int  reserved_2   : 1;  /* bit[6] : ������HIEPSδʹ�á� */
        unsigned int  reserved_3   : 1;  /* bit[7] : ������HIEPSδʹ�á� */
        unsigned int  trng_clr_0   : 1;  /* bit[8] : TRNG�İ�ȫ��������Ĵ��� */
        unsigned int  trng_clr_1   : 1;  /* bit[9] : TRNG�İ�ȫ��������Ĵ��� */
        unsigned int  trng_clr_2   : 1;  /* bit[10]: TRNG�İ�ȫ��������Ĵ��� */
        unsigned int  trng_clr_3   : 1;  /* bit[11]: TRNG�İ�ȫ��������Ĵ��� */
        unsigned int  timer_clr_0  : 1;  /* bit[12]: TIMER�İ�ȫ��������Ĵ��� */
        unsigned int  timer_clr_1  : 1;  /* bit[13]: TIMER�İ�ȫ��������Ĵ��� */
        unsigned int  timer_clr_2  : 1;  /* bit[14]: TIMER�İ�ȫ��������Ĵ��� */
        unsigned int  timer_clr_3  : 1;  /* bit[15]: TIMER�İ�ȫ��������Ĵ��� */
        unsigned int  mmu_clr_0    : 1;  /* bit[16]: MMU �İ�ȫ����Ĵ��� */
        unsigned int  mmu_clr_1    : 1;  /* bit[17]: MMU �İ�ȫ����Ĵ��� */
        unsigned int  mmu_clr_2    : 1;  /* bit[18]: MMU �İ�ȫ����Ĵ��� */
        unsigned int  mmu_clr_3    : 1;  /* bit[19]: MMU �İ�ȫ����Ĵ��� */
        unsigned int  reserved_4   : 1;  /* bit[20]: ������HIEPSδʹ�á� */
        unsigned int  reserved_5   : 1;  /* bit[21]: ������HIEPSδʹ�á� */
        unsigned int  reserved_6   : 1;  /* bit[22]: ������HIEPSδʹ�á� */
        unsigned int  reserved_7   : 1;  /* bit[23]: ������HIEPSδʹ�á� */
        unsigned int  reserved_8   : 1;  /* bit[24]: ������HIEPSδʹ�á� */
        unsigned int  reserved_9   : 1;  /* bit[25]: ������HIEPSδʹ�á� */
        unsigned int  reserved_10  : 1;  /* bit[26]: ������HIEPSδʹ�á� */
        unsigned int  reserved_11  : 1;  /* bit[27]: ������HIEPSδʹ�á� */
        unsigned int  reserved_12  : 1;  /* bit[28]: ������HIEPSδʹ�á� */
        unsigned int  reserved_13  : 1;  /* bit[29]: ������HIEPSδʹ�á� */
        unsigned int  reserved_14  : 1;  /* bit[30]: ������HIEPSδʹ�á� */
        unsigned int  reserved_15  : 1;  /* bit[31]: ������HIEPSδʹ�á� */
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
 �ṹ��    : SOC_ETZPC_DECPROT2STAT_UNION
 �ṹ˵��  : DECPROT2STAT �Ĵ����ṹ���塣��ַƫ����:0x818����ֵ:0x00000000�����:32
 �Ĵ���˵��: IP��ȫ����״̬�Ĵ���2��
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved_0: 1;  /* bit[0] : ������HIEPSδʹ�á� */
        unsigned int  reserved_1: 1;  /* bit[1] : ������HIEPSδʹ�á� */
        unsigned int  reserved_2: 1;  /* bit[2] : ������HIEPSδʹ�á� */
        unsigned int  reserved_3: 1;  /* bit[3] : ������HIEPSδʹ�á� */
        unsigned int  reserved_4: 1;  /* bit[4] : ������HIEPSδʹ�á� */
        unsigned int  reserved_5: 1;  /* bit[5] : ������HIEPSδʹ�á� */
        unsigned int  reserved_6: 1;  /* bit[6] : ������HIEPSδʹ�á� */
        unsigned int  reserved_7: 1;  /* bit[7] : ������HIEPSδʹ�á� */
        unsigned int  reserved_8: 1;  /* bit[8] : ������HIEPSδʹ�á� */
        unsigned int  reserved_9: 1;  /* bit[9] : ������HIEPSδʹ�á� */
        unsigned int  reserved_10: 1;  /* bit[10]: ������HIEPSδʹ�á� */
        unsigned int  reserved_11: 1;  /* bit[11]: ������HIEPSδʹ�á� */
        unsigned int  reserved_12: 1;  /* bit[12]: ������HIEPSδʹ�á� */
        unsigned int  reserved_13: 1;  /* bit[13]: ������HIEPSδʹ�á� */
        unsigned int  reserved_14: 1;  /* bit[14]: ������HIEPSδʹ�á� */
        unsigned int  reserved_15: 1;  /* bit[15]: ������HIEPSδʹ�á� */
        unsigned int  reserved_16: 1;  /* bit[16]: ������HIEPSδʹ�á� */
        unsigned int  reserved_17: 1;  /* bit[17]: ������HIEPSδʹ�á� */
        unsigned int  reserved_18: 1;  /* bit[18]: ������HIEPSδʹ�á� */
        unsigned int  reserved_19: 1;  /* bit[19]: ������HIEPSδʹ�á� */
        unsigned int  reserved_20: 1;  /* bit[20]: ������HIEPSδʹ�á� */
        unsigned int  reserved_21: 1;  /* bit[21]: ������HIEPSδʹ�á� */
        unsigned int  reserved_22: 1;  /* bit[22]: ������HIEPSδʹ�á� */
        unsigned int  reserved_23: 1;  /* bit[23]: ������HIEPSδʹ�á� */
        unsigned int  reserved_24: 1;  /* bit[24]: ������HIEPSδʹ�á� */
        unsigned int  reserved_25: 1;  /* bit[25]: ������HIEPSδʹ�á� */
        unsigned int  reserved_26: 1;  /* bit[26]: ������HIEPSδʹ�á� */
        unsigned int  reserved_27: 1;  /* bit[27]: ������HIEPSδʹ�á� */
        unsigned int  reserved_28: 1;  /* bit[28]: ������HIEPSδʹ�á� */
        unsigned int  reserved_29: 1;  /* bit[29]: ������HIEPSδʹ�á� */
        unsigned int  reserved_30: 1;  /* bit[30]: ������HIEPSδʹ�á� */
        unsigned int  reserved_31: 1;  /* bit[31]: ������HIEPSδʹ�á� */
    } reg;
} SOC_ETZPC_DECPROT2STAT_UNION;
#endif


/*****************************************************************************
 �ṹ��    : SOC_ETZPC_DECPROT2SET_UNION
 �ṹ˵��  : DECPROT2SET �Ĵ����ṹ���塣��ַƫ����:0x81C����ֵ:0x00000000�����:32
 �Ĵ���˵��: IP��ȫ������λ�Ĵ���2��
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved_0: 1;  /* bit[0] : ������HIEPSδʹ�á� */
        unsigned int  reserved_1: 1;  /* bit[1] : ������HIEPSδʹ�á� */
        unsigned int  reserved_2: 1;  /* bit[2] : ������HIEPSδʹ�á� */
        unsigned int  reserved_3: 1;  /* bit[3] : ������HIEPSδʹ�á� */
        unsigned int  reserved_4: 1;  /* bit[4] : ������HIEPSδʹ�á� */
        unsigned int  reserved_5: 1;  /* bit[5] : ������HIEPSδʹ�á� */
        unsigned int  reserved_6: 1;  /* bit[6] : ������HIEPSδʹ�á� */
        unsigned int  reserved_7: 1;  /* bit[7] : ������HIEPSδʹ�á� */
        unsigned int  reserved_8: 1;  /* bit[8] : ������HIEPSδʹ�á� */
        unsigned int  reserved_9: 1;  /* bit[9] : ������HIEPSδʹ�á� */
        unsigned int  reserved_10: 1;  /* bit[10]: ������HIEPSδʹ�á� */
        unsigned int  reserved_11: 1;  /* bit[11]: ������HIEPSδʹ�á� */
        unsigned int  reserved_12: 1;  /* bit[12]: ������HIEPSδʹ�á� */
        unsigned int  reserved_13: 1;  /* bit[13]: ������HIEPSδʹ�á� */
        unsigned int  reserved_14: 1;  /* bit[14]: ������HIEPSδʹ�á� */
        unsigned int  reserved_15: 1;  /* bit[15]: ������HIEPSδʹ�á� */
        unsigned int  reserved_16: 1;  /* bit[16]: ������HIEPSδʹ�á� */
        unsigned int  reserved_17: 1;  /* bit[17]: ������HIEPSδʹ�á� */
        unsigned int  reserved_18: 1;  /* bit[18]: ������HIEPSδʹ�á� */
        unsigned int  reserved_19: 1;  /* bit[19]: ������HIEPSδʹ�á� */
        unsigned int  reserved_20: 1;  /* bit[20]: ������HIEPSδʹ�á� */
        unsigned int  reserved_21: 1;  /* bit[21]: ������HIEPSδʹ�á� */
        unsigned int  reserved_22: 1;  /* bit[22]: ������HIEPSδʹ�á� */
        unsigned int  reserved_23: 1;  /* bit[23]: ������HIEPSδʹ�á� */
        unsigned int  reserved_24: 1;  /* bit[24]: ������HIEPSδʹ�á� */
        unsigned int  reserved_25: 1;  /* bit[25]: ������HIEPSδʹ�á� */
        unsigned int  reserved_26: 1;  /* bit[26]: ������HIEPSδʹ�á� */
        unsigned int  reserved_27: 1;  /* bit[27]: ������HIEPSδʹ�á� */
        unsigned int  reserved_28: 1;  /* bit[28]: ������HIEPSδʹ�á� */
        unsigned int  reserved_29: 1;  /* bit[29]: ������HIEPSδʹ�á� */
        unsigned int  reserved_30: 1;  /* bit[30]: ������HIEPSδʹ�á� */
        unsigned int  reserved_31: 1;  /* bit[31]: ������HIEPSδʹ�á� */
    } reg;
} SOC_ETZPC_DECPROT2SET_UNION;
#endif


/*****************************************************************************
 �ṹ��    : SOC_ETZPC_DECPROT2CLR_UNION
 �ṹ˵��  : DECPROT2CLR �Ĵ����ṹ���塣��ַƫ����:0x820����ֵ:0x00000000�����:32
 �Ĵ���˵��: IP��ȫ��������Ĵ���2��
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved_0: 1;  /* bit[0] : ������HIEPSδʹ�á� */
        unsigned int  reserved_1: 1;  /* bit[1] : ������HIEPSδʹ�á� */
        unsigned int  reserved_2: 1;  /* bit[2] : ������HIEPSδʹ�á� */
        unsigned int  reserved_3: 1;  /* bit[3] : ������HIEPSδʹ�á� */
        unsigned int  reserved_4: 1;  /* bit[4] : ������HIEPSδʹ�á� */
        unsigned int  reserved_5: 1;  /* bit[5] : ������HIEPSδʹ�á� */
        unsigned int  reserved_6: 1;  /* bit[6] : ������HIEPSδʹ�á� */
        unsigned int  reserved_7: 1;  /* bit[7] : ������HIEPSδʹ�á� */
        unsigned int  reserved_8: 1;  /* bit[8] : ������HIEPSδʹ�á� */
        unsigned int  reserved_9: 1;  /* bit[9] : ������HIEPSδʹ�á� */
        unsigned int  reserved_10: 1;  /* bit[10]: ������HIEPSδʹ�á� */
        unsigned int  reserved_11: 1;  /* bit[11]: ������HIEPSδʹ�á� */
        unsigned int  reserved_12: 1;  /* bit[12]: ������HIEPSδʹ�á� */
        unsigned int  reserved_13: 1;  /* bit[13]: ������HIEPSδʹ�á� */
        unsigned int  reserved_14: 1;  /* bit[14]: ������HIEPSδʹ�á� */
        unsigned int  reserved_15: 1;  /* bit[15]: ������HIEPSδʹ�á� */
        unsigned int  reserved_16: 1;  /* bit[16]: ������HIEPSδʹ�á� */
        unsigned int  reserved_17: 1;  /* bit[17]: ������HIEPSδʹ�á� */
        unsigned int  reserved_18: 1;  /* bit[18]: ������HIEPSδʹ�á� */
        unsigned int  reserved_19: 1;  /* bit[19]: ������HIEPSδʹ�á� */
        unsigned int  reserved_20: 1;  /* bit[20]: ������HIEPSδʹ�á� */
        unsigned int  reserved_21: 1;  /* bit[21]: ������HIEPSδʹ�á� */
        unsigned int  reserved_22: 1;  /* bit[22]: ������HIEPSδʹ�á� */
        unsigned int  reserved_23: 1;  /* bit[23]: ������HIEPSδʹ�á� */
        unsigned int  reserved_24: 1;  /* bit[24]: ������HIEPSδʹ�á� */
        unsigned int  reserved_25: 1;  /* bit[25]: ������HIEPSδʹ�á� */
        unsigned int  reserved_26: 1;  /* bit[26]: ������HIEPSδʹ�á� */
        unsigned int  reserved_27: 1;  /* bit[27]: ������HIEPSδʹ�á� */
        unsigned int  reserved_28: 1;  /* bit[28]: ������HIEPSδʹ�á� */
        unsigned int  reserved_29: 1;  /* bit[29]: ������HIEPSδʹ�á� */
        unsigned int  reserved_30: 1;  /* bit[30]: ������HIEPSδʹ�á� */
        unsigned int  reserved_31: 1;  /* bit[31]: ������HIEPSδʹ�á� */
    } reg;
} SOC_ETZPC_DECPROT2CLR_UNION;
#endif


/*****************************************************************************
 �ṹ��    : SOC_ETZPC_DECPROT3STAT_UNION
 �ṹ˵��  : DECPROT3STAT �Ĵ����ṹ���塣��ַƫ����:0x824����ֵ:0x00000000�����:32
 �Ĵ���˵��: IP��ȫ����״̬�Ĵ���3��
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved_0: 1;  /* bit[0] : ������HIEPSδʹ�á� */
        unsigned int  reserved_1: 1;  /* bit[1] : ������HIEPSδʹ�á� */
        unsigned int  reserved_2: 1;  /* bit[2] : ������HIEPSδʹ�á� */
        unsigned int  reserved_3: 1;  /* bit[3] : ������HIEPSδʹ�á� */
        unsigned int  reserved_4: 1;  /* bit[4] : ������HIEPSδʹ�á� */
        unsigned int  reserved_5: 1;  /* bit[5] : ������HIEPSδʹ�á� */
        unsigned int  reserved_6: 1;  /* bit[6] : ������HIEPSδʹ�á� */
        unsigned int  reserved_7: 1;  /* bit[7] : ������HIEPSδʹ�á� */
        unsigned int  reserved_8: 1;  /* bit[8] : ������HIEPSδʹ�á� */
        unsigned int  reserved_9: 1;  /* bit[9] : ������HIEPSδʹ�á� */
        unsigned int  reserved_10: 1;  /* bit[10]: ������HIEPSδʹ�á� */
        unsigned int  reserved_11: 1;  /* bit[11]: ������HIEPSδʹ�á� */
        unsigned int  reserved_12: 1;  /* bit[12]: ������HIEPSδʹ�á� */
        unsigned int  reserved_13: 1;  /* bit[13]: ������HIEPSδʹ�á� */
        unsigned int  reserved_14: 1;  /* bit[14]: ������HIEPSδʹ�á� */
        unsigned int  reserved_15: 1;  /* bit[15]: ������HIEPSδʹ�á� */
        unsigned int  reserved_16: 1;  /* bit[16]: ������HIEPSδʹ�á� */
        unsigned int  reserved_17: 1;  /* bit[17]: ������HIEPSδʹ�á� */
        unsigned int  reserved_18: 1;  /* bit[18]: ������HIEPSδʹ�á� */
        unsigned int  reserved_19: 1;  /* bit[19]: ������HIEPSδʹ�á� */
        unsigned int  reserved_20: 1;  /* bit[20]: ������HIEPSδʹ�á� */
        unsigned int  reserved_21: 1;  /* bit[21]: ������HIEPSδʹ�á� */
        unsigned int  reserved_22: 1;  /* bit[22]: ������HIEPSδʹ�á� */
        unsigned int  reserved_23: 1;  /* bit[23]: ������HIEPSδʹ�á� */
        unsigned int  reserved_24: 1;  /* bit[24]: ������HIEPSδʹ�á� */
        unsigned int  reserved_25: 1;  /* bit[25]: ������HIEPSδʹ�á� */
        unsigned int  reserved_26: 1;  /* bit[26]: ������HIEPSδʹ�á� */
        unsigned int  reserved_27: 1;  /* bit[27]: ������HIEPSδʹ�á� */
        unsigned int  reserved_28: 1;  /* bit[28]: ������HIEPSδʹ�á� */
        unsigned int  reserved_29: 1;  /* bit[29]: ������HIEPSδʹ�á� */
        unsigned int  reserved_30: 1;  /* bit[30]: ������HIEPSδʹ�á� */
        unsigned int  reserved_31: 1;  /* bit[31]: ������HIEPSδʹ�á� */
    } reg;
} SOC_ETZPC_DECPROT3STAT_UNION;
#endif


/*****************************************************************************
 �ṹ��    : SOC_ETZPC_DECPROT3SET_UNION
 �ṹ˵��  : DECPROT3SET �Ĵ����ṹ���塣��ַƫ����:0x828����ֵ:0x00000000�����:32
 �Ĵ���˵��: IP��ȫ������λ�Ĵ���3��
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved_0: 1;  /* bit[0] : ������HIEPSδʹ�á� */
        unsigned int  reserved_1: 1;  /* bit[1] : ������HIEPSδʹ�á� */
        unsigned int  reserved_2: 1;  /* bit[2] : ������HIEPSδʹ�á� */
        unsigned int  reserved_3: 1;  /* bit[3] : ������HIEPSδʹ�á� */
        unsigned int  reserved_4: 1;  /* bit[4] : ������HIEPSδʹ�á� */
        unsigned int  reserved_5: 1;  /* bit[5] : ������HIEPSδʹ�á� */
        unsigned int  reserved_6: 1;  /* bit[6] : ������HIEPSδʹ�á� */
        unsigned int  reserved_7: 1;  /* bit[7] : ������HIEPSδʹ�á� */
        unsigned int  reserved_8: 1;  /* bit[8] : ������HIEPSδʹ�á� */
        unsigned int  reserved_9: 1;  /* bit[9] : ������HIEPSδʹ�á� */
        unsigned int  reserved_10: 1;  /* bit[10]: ������HIEPSδʹ�á� */
        unsigned int  reserved_11: 1;  /* bit[11]: ������HIEPSδʹ�á� */
        unsigned int  reserved_12: 1;  /* bit[12]: ������HIEPSδʹ�á� */
        unsigned int  reserved_13: 1;  /* bit[13]: ������HIEPSδʹ�á� */
        unsigned int  reserved_14: 1;  /* bit[14]: ������HIEPSδʹ�á� */
        unsigned int  reserved_15: 1;  /* bit[15]: ������HIEPSδʹ�á� */
        unsigned int  reserved_16: 1;  /* bit[16]: ������HIEPSδʹ�á� */
        unsigned int  reserved_17: 1;  /* bit[17]: ������HIEPSδʹ�á� */
        unsigned int  reserved_18: 1;  /* bit[18]: ������HIEPSδʹ�á� */
        unsigned int  reserved_19: 1;  /* bit[19]: ������HIEPSδʹ�á� */
        unsigned int  reserved_20: 1;  /* bit[20]: ������HIEPSδʹ�á� */
        unsigned int  reserved_21: 1;  /* bit[21]: ������HIEPSδʹ�á� */
        unsigned int  reserved_22: 1;  /* bit[22]: ������HIEPSδʹ�á� */
        unsigned int  reserved_23: 1;  /* bit[23]: ������HIEPSδʹ�á� */
        unsigned int  reserved_24: 1;  /* bit[24]: ������HIEPSδʹ�á� */
        unsigned int  reserved_25: 1;  /* bit[25]: ������HIEPSδʹ�á� */
        unsigned int  reserved_26: 1;  /* bit[26]: ������HIEPSδʹ�á� */
        unsigned int  reserved_27: 1;  /* bit[27]: ������HIEPSδʹ�á� */
        unsigned int  reserved_28: 1;  /* bit[28]: ������HIEPSδʹ�á� */
        unsigned int  reserved_29: 1;  /* bit[29]: ������HIEPSδʹ�á� */
        unsigned int  reserved_30: 1;  /* bit[30]: ������HIEPSδʹ�á� */
        unsigned int  reserved_31: 1;  /* bit[31]: ������HIEPSδʹ�á� */
    } reg;
} SOC_ETZPC_DECPROT3SET_UNION;
#endif


/*****************************************************************************
 �ṹ��    : SOC_ETZPC_DECPROT3CLR_UNION
 �ṹ˵��  : DECPROT3CLR �Ĵ����ṹ���塣��ַƫ����:0x82C����ֵ:0x00000000�����:32
 �Ĵ���˵��: IP��ȫ��������Ĵ���3��
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved_0: 1;  /* bit[0] : ������HIEPSδʹ�á� */
        unsigned int  reserved_1: 1;  /* bit[1] : ������HIEPSδʹ�á� */
        unsigned int  reserved_2: 1;  /* bit[2] : ������HIEPSδʹ�á� */
        unsigned int  reserved_3: 1;  /* bit[3] : ������HIEPSδʹ�á� */
        unsigned int  reserved_4: 1;  /* bit[4] : ������HIEPSδʹ�á� */
        unsigned int  reserved_5: 1;  /* bit[5] : ������HIEPSδʹ�á� */
        unsigned int  reserved_6: 1;  /* bit[6] : ������HIEPSδʹ�á� */
        unsigned int  reserved_7: 1;  /* bit[7] : ������HIEPSδʹ�á� */
        unsigned int  reserved_8: 1;  /* bit[8] : ������HIEPSδʹ�á� */
        unsigned int  reserved_9: 1;  /* bit[9] : ������HIEPSδʹ�á� */
        unsigned int  reserved_10: 1;  /* bit[10]: ������HIEPSδʹ�á� */
        unsigned int  reserved_11: 1;  /* bit[11]: ������HIEPSδʹ�á� */
        unsigned int  reserved_12: 1;  /* bit[12]: ������HIEPSδʹ�á� */
        unsigned int  reserved_13: 1;  /* bit[13]: ������HIEPSδʹ�á� */
        unsigned int  reserved_14: 1;  /* bit[14]: ������HIEPSδʹ�á� */
        unsigned int  reserved_15: 1;  /* bit[15]: ������HIEPSδʹ�á� */
        unsigned int  reserved_16: 1;  /* bit[16]: ������HIEPSδʹ�á� */
        unsigned int  reserved_17: 1;  /* bit[17]: ������HIEPSδʹ�á� */
        unsigned int  reserved_18: 1;  /* bit[18]: ������HIEPSδʹ�á� */
        unsigned int  reserved_19: 1;  /* bit[19]: ������HIEPSδʹ�á� */
        unsigned int  reserved_20: 1;  /* bit[20]: ������HIEPSδʹ�á� */
        unsigned int  reserved_21: 1;  /* bit[21]: ������HIEPSδʹ�á� */
        unsigned int  reserved_22: 1;  /* bit[22]: ������HIEPSδʹ�á� */
        unsigned int  reserved_23: 1;  /* bit[23]: ������HIEPSδʹ�á� */
        unsigned int  reserved_24: 1;  /* bit[24]: ������HIEPSδʹ�á� */
        unsigned int  reserved_25: 1;  /* bit[25]: ������HIEPSδʹ�á� */
        unsigned int  reserved_26: 1;  /* bit[26]: ������HIEPSδʹ�á� */
        unsigned int  reserved_27: 1;  /* bit[27]: ������HIEPSδʹ�á� */
        unsigned int  reserved_28: 1;  /* bit[28]: ������HIEPSδʹ�á� */
        unsigned int  reserved_29: 1;  /* bit[29]: ������HIEPSδʹ�á� */
        unsigned int  reserved_30: 1;  /* bit[30]: ������HIEPSδʹ�á� */
        unsigned int  reserved_31: 1;  /* bit[31]: ������HIEPSδʹ�á� */
    } reg;
} SOC_ETZPC_DECPROT3CLR_UNION;
#endif


/*****************************************************************************
 �ṹ��    : SOC_ETZPC_DECPROT4STAT_UNION
 �ṹ˵��  : DECPROT4STAT �Ĵ����ṹ���塣��ַƫ����:0x830����ֵ:0x00000000�����:32
 �Ĵ���˵��: IP��ȫ����״̬�Ĵ���4��
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  tz_sce_axi_mst_wr_stat_0  : 1;  /* bit[0] : SCE AXI master�Ķ�����Ȩ��:
                                                                  ? 3��b000:trusted stream secure world 
                                                                  ? 3��b001:non-trusted stream non-secure world
                                                                  ? 3��b010:protected stream non-secure world 
                                                                  ? 3��b100:trusted stream secure world
                                                                  ����ֵ��non-trusted stream */
        unsigned int  tz_sce_axi_mst_wr_stat_1  : 1;  /* bit[1] : SCE AXI master�Ķ�����Ȩ��:
                                                                  ? 3��b000:trusted stream secure world 
                                                                  ? 3��b001:non-trusted stream non-secure world
                                                                  ? 3��b010:protected stream non-secure world 
                                                                  ? 3��b100:trusted stream secure world
                                                                  ����ֵ��non-trusted stream */
        unsigned int  tz_sce_axi_mst_wr_stat_2  : 1;  /* bit[2] : SCE AXI master�Ķ�����Ȩ��:
                                                                  ? 3��b000:trusted stream secure world 
                                                                  ? 3��b001:non-trusted stream non-secure world
                                                                  ? 3��b010:protected stream non-secure world 
                                                                  ? 3��b100:trusted stream secure world
                                                                  ����ֵ��non-trusted stream */
        unsigned int  tz_sce_axi_mst_rd_stat_0  : 1;  /* bit[3] : SCE AXI master�Ķ�����Ȩ��:
                                                                  ? 3��b000:trusted stream secure world 
                                                                  ? 3��b001:non-trusted stream non-secure world
                                                                  ? 3��b010:protected stream non-secure world 
                                                                  ? 3��b100:trusted stream secure world
                                                                  ����ֵ��non-trusted stream */
        unsigned int  tz_sce_axi_mst_rd_stat_1  : 1;  /* bit[4] : SCE AXI master�Ķ�����Ȩ��:
                                                                  ? 3��b000:trusted stream secure world 
                                                                  ? 3��b001:non-trusted stream non-secure world
                                                                  ? 3��b010:protected stream non-secure world 
                                                                  ? 3��b100:trusted stream secure world
                                                                  ����ֵ��non-trusted stream */
        unsigned int  tz_sce_axi_mst_rd_stat_2  : 1;  /* bit[5] : SCE AXI master�Ķ�����Ȩ��:
                                                                  ? 3��b000:trusted stream secure world 
                                                                  ? 3��b001:non-trusted stream non-secure world
                                                                  ? 3��b010:protected stream non-secure world 
                                                                  ? 3��b100:trusted stream secure world
                                                                  ����ֵ��non-trusted stream */
        unsigned int  tz_sce2_axi_mst_wr_stat_0 : 1;  /* bit[6] : SCE2 AXI master�Ķ�����Ȩ��:
                                                                  ? 3��b000:trusted stream secure world 
                                                                  ? 3��b001:non-trusted stream non-secure world
                                                                  ? 3��b010:protected stream non-secure world 
                                                                  ? 3��b100:trusted stream secure world
                                                                  ����ֵ��non-trusted stream */
        unsigned int  tz_sce2_axi_mst_wr_stat_1 : 1;  /* bit[7] : SCE2 AXI master�Ķ�����Ȩ��:
                                                                  ? 3��b000:trusted stream secure world 
                                                                  ? 3��b001:non-trusted stream non-secure world
                                                                  ? 3��b010:protected stream non-secure world 
                                                                  ? 3��b100:trusted stream secure world
                                                                  ����ֵ��non-trusted stream */
        unsigned int  tz_sce2_axi_mst_wr_stat_2 : 1;  /* bit[8] : SCE2 AXI master�Ķ�����Ȩ��:
                                                                  ? 3��b000:trusted stream secure world 
                                                                  ? 3��b001:non-trusted stream non-secure world
                                                                  ? 3��b010:protected stream non-secure world 
                                                                  ? 3��b100:trusted stream secure world
                                                                  ����ֵ��non-trusted stream */
        unsigned int  tz_sce2_axi_mst_rd_stat_0 : 1;  /* bit[9] : SCE2 AXI master�Ķ�����Ȩ��:
                                                                  ? 3��b000:trusted stream secure world 
                                                                  ? 3��b001:non-trusted stream non-secure world
                                                                  ? 3��b010:protected stream non-secure world 
                                                                  ? 3��b100:trusted stream secure world
                                                                  ����ֵ��non-trusted stream */
        unsigned int  tz_sce2_axi_mst_rd_stat_1 : 1;  /* bit[10]: SCE2 AXI master�Ķ�����Ȩ��:
                                                                  ? 3��b000:trusted stream secure world 
                                                                  ? 3��b001:non-trusted stream non-secure world
                                                                  ? 3��b010:protected stream non-secure world 
                                                                  ? 3��b100:trusted stream secure world
                                                                  ����ֵ��non-trusted stream */
        unsigned int  tz_sce2_axi_mst_rd_stat_2 : 1;  /* bit[11]: SCE2 AXI master�Ķ�����Ȩ��:
                                                                  ? 3��b000:trusted stream secure world 
                                                                  ? 3��b001:non-trusted stream non-secure world
                                                                  ? 3��b010:protected stream non-secure world 
                                                                  ? 3��b100:trusted stream secure world
                                                                  ����ֵ��non-trusted stream */
        unsigned int  reserved_0                : 1;  /* bit[12]: ������HIEPSδʹ�á� */
        unsigned int  reserved_1                : 1;  /* bit[13]: ������HIEPSδʹ�á� */
        unsigned int  reserved_2                : 1;  /* bit[14]: ������HIEPSδʹ�á� */
        unsigned int  reserved_3                : 1;  /* bit[15]: ������HIEPSδʹ�á� */
        unsigned int  reserved_4                : 1;  /* bit[16]: ������HIEPSδʹ�á� */
        unsigned int  reserved_5                : 1;  /* bit[17]: ������HIEPSδʹ�á� */
        unsigned int  reserved_6                : 1;  /* bit[18]: ������HIEPSδʹ�á� */
        unsigned int  reserved_7                : 1;  /* bit[19]: ������HIEPSδʹ�á� */
        unsigned int  reserved_8                : 1;  /* bit[20]: ������HIEPSδʹ�á� */
        unsigned int  reserved_9                : 1;  /* bit[21]: ������HIEPSδʹ�á� */
        unsigned int  reserved_10               : 1;  /* bit[22]: ������HIEPSδʹ�á� */
        unsigned int  reserved_11               : 1;  /* bit[23]: ������HIEPSδʹ�á� */
        unsigned int  reserved_12               : 1;  /* bit[24]: ������HIEPSδʹ�á� */
        unsigned int  reserved_13               : 1;  /* bit[25]: ������HIEPSδʹ�á� */
        unsigned int  reserved_14               : 1;  /* bit[26]: ������HIEPSδʹ�á� */
        unsigned int  reserved_15               : 1;  /* bit[27]: ������HIEPSδʹ�á� */
        unsigned int  reserved_16               : 1;  /* bit[28]: ������HIEPSδʹ�á� */
        unsigned int  reserved_17               : 1;  /* bit[29]: ������HIEPSδʹ�á� */
        unsigned int  reserved_18               : 1;  /* bit[30]: ������HIEPSδʹ�á� */
        unsigned int  reserved_19               : 1;  /* bit[31]: ������HIEPSδʹ�á� */
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
 �ṹ��    : SOC_ETZPC_DECPROT4SET_UNION
 �ṹ˵��  : DECPROT4SET �Ĵ����ṹ���塣��ַƫ����:0x834����ֵ:0x00000000�����:32
 �Ĵ���˵��: IP��ȫ������λ�Ĵ���4��
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  tz_sce_axi_mst_wr_set_0  : 1;  /* bit[0] : SCE AXI MST д������Ȩ����λ�Ĵ��� */
        unsigned int  tz_sce_axi_mst_wr_set_1  : 1;  /* bit[1] : SCE AXI MST д������Ȩ����λ�Ĵ��� */
        unsigned int  tz_sce_axi_mst_wr_set_2  : 1;  /* bit[2] : SCE AXI MST д������Ȩ����λ�Ĵ��� */
        unsigned int  tz_sce_axi_mst_rd_set_0  : 1;  /* bit[3] : SCE AXI MST ��������Ȩ����λ�Ĵ��� */
        unsigned int  tz_sce_axi_mst_rd_set_1  : 1;  /* bit[4] : SCE AXI MST ��������Ȩ����λ�Ĵ��� */
        unsigned int  tz_sce_axi_mst_rd_set_2  : 1;  /* bit[5] : SCE AXI MST ��������Ȩ����λ�Ĵ��� */
        unsigned int  tz_sce2_axi_mst_wr_set_0 : 1;  /* bit[6] : SCE2 AXI MST д������Ȩ����λ�Ĵ��� */
        unsigned int  tz_sce2_axi_mst_wr_set_1 : 1;  /* bit[7] : SCE2 AXI MST д������Ȩ����λ�Ĵ��� */
        unsigned int  tz_sce2_axi_mst_wr_set_2 : 1;  /* bit[8] : SCE2 AXI MST д������Ȩ����λ�Ĵ��� */
        unsigned int  tz_sce2_axi_mst_rd_set_0 : 1;  /* bit[9] : SCE2 AXI MST ��������Ȩ����λ�Ĵ��� */
        unsigned int  tz_sce2_axi_mst_rd_set_1 : 1;  /* bit[10]: SCE2 AXI MST ��������Ȩ����λ�Ĵ��� */
        unsigned int  tz_sce2_axi_mst_rd_set_2 : 1;  /* bit[11]: SCE2 AXI MST ��������Ȩ����λ�Ĵ��� */
        unsigned int  reserved_0               : 1;  /* bit[12]: ������HIEPSδʹ�á� */
        unsigned int  reserved_1               : 1;  /* bit[13]: ������HIEPSδʹ�á� */
        unsigned int  reserved_2               : 1;  /* bit[14]: ������HIEPSδʹ�á� */
        unsigned int  reserved_3               : 1;  /* bit[15]: ������HIEPSδʹ�á� */
        unsigned int  reserved_4               : 1;  /* bit[16]: ������HIEPSδʹ�á� */
        unsigned int  reserved_5               : 1;  /* bit[17]: ������HIEPSδʹ�á� */
        unsigned int  reserved_6               : 1;  /* bit[18]: ������HIEPSδʹ�á� */
        unsigned int  reserved_7               : 1;  /* bit[19]: ������HIEPSδʹ�á� */
        unsigned int  reserved_8               : 1;  /* bit[20]: ������HIEPSδʹ�á� */
        unsigned int  reserved_9               : 1;  /* bit[21]: ������HIEPSδʹ�á� */
        unsigned int  reserved_10              : 1;  /* bit[22]: ������HIEPSδʹ�á� */
        unsigned int  reserved_11              : 1;  /* bit[23]: ������HIEPSδʹ�á� */
        unsigned int  reserved_12              : 1;  /* bit[24]: ������HIEPSδʹ�á� */
        unsigned int  reserved_13              : 1;  /* bit[25]: ������HIEPSδʹ�á� */
        unsigned int  reserved_14              : 1;  /* bit[26]: ������HIEPSδʹ�á� */
        unsigned int  reserved_15              : 1;  /* bit[27]: ������HIEPSδʹ�á� */
        unsigned int  reserved_16              : 1;  /* bit[28]: ������HIEPSδʹ�á� */
        unsigned int  reserved_17              : 1;  /* bit[29]: ������HIEPSδʹ�á� */
        unsigned int  reserved_18              : 1;  /* bit[30]: ������HIEPSδʹ�á� */
        unsigned int  reserved_19              : 1;  /* bit[31]: ������HIEPSδʹ�á� */
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
 �ṹ��    : SOC_ETZPC_DECPROT4CLR_UNION
 �ṹ˵��  : DECPROT4CLR �Ĵ����ṹ���塣��ַƫ����:0x838����ֵ:0x00000000�����:32
 �Ĵ���˵��: IP��ȫ��������Ĵ���4��
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  tz_sce_axi_mst_wr_clr_0  : 1;  /* bit[0] : SCE AXI MST д������Ȩ������Ĵ��� */
        unsigned int  tz_sce_axi_mst_wr_clr_1  : 1;  /* bit[1] : SCE AXI MST д������Ȩ������Ĵ��� */
        unsigned int  tz_sce_axi_mst_wr_clr_2  : 1;  /* bit[2] : SCE AXI MST д������Ȩ������Ĵ��� */
        unsigned int  tz_sce_axi_mst_rd_clr_0  : 1;  /* bit[3] : SCE AXI MST ��������Ȩ������Ĵ��� */
        unsigned int  tz_sce_axi_mst_rd_clr_1  : 1;  /* bit[4] : SCE AXI MST ��������Ȩ������Ĵ��� */
        unsigned int  tz_sce_axi_mst_rd_clr_2  : 1;  /* bit[5] : SCE AXI MST ��������Ȩ������Ĵ��� */
        unsigned int  tz_sce2_axi_mst_wr_clr_0 : 1;  /* bit[6] : SCE2 AXI MST д������Ȩ������Ĵ��� */
        unsigned int  tz_sce2_axi_mst_wr_clr_1 : 1;  /* bit[7] : SCE2 AXI MST д������Ȩ������Ĵ��� */
        unsigned int  tz_sce2_axi_mst_wr_clr_2 : 1;  /* bit[8] : SCE2 AXI MST д������Ȩ������Ĵ��� */
        unsigned int  tz_sce2_axi_mst_rd_clr_0 : 1;  /* bit[9] : SCE2 AXI MST ��������Ȩ������Ĵ��� */
        unsigned int  tz_sce2_axi_mst_rd_clr_1 : 1;  /* bit[10]: SCE2 AXI MST ��������Ȩ������Ĵ��� */
        unsigned int  tz_sce2_axi_mst_rd_clr_2 : 1;  /* bit[11]: SCE2 AXI MST ��������Ȩ������Ĵ��� */
        unsigned int  reserved_0               : 1;  /* bit[12]: ������HIEPSδʹ�á� */
        unsigned int  reserved_1               : 1;  /* bit[13]: ������HIEPSδʹ�á� */
        unsigned int  reserved_2               : 1;  /* bit[14]: ������HIEPSδʹ�á� */
        unsigned int  reserved_3               : 1;  /* bit[15]: ������HIEPSδʹ�á� */
        unsigned int  reserved_4               : 1;  /* bit[16]: ������HIEPSδʹ�á� */
        unsigned int  reserved_5               : 1;  /* bit[17]: ������HIEPSδʹ�á� */
        unsigned int  reserved_6               : 1;  /* bit[18]: ������HIEPSδʹ�á� */
        unsigned int  reserved_7               : 1;  /* bit[19]: ������HIEPSδʹ�á� */
        unsigned int  reserved_8               : 1;  /* bit[20]: ������HIEPSδʹ�á� */
        unsigned int  reserved_9               : 1;  /* bit[21]: ������HIEPSδʹ�á� */
        unsigned int  reserved_10              : 1;  /* bit[22]: ������HIEPSδʹ�á� */
        unsigned int  reserved_11              : 1;  /* bit[23]: ������HIEPSδʹ�á� */
        unsigned int  reserved_12              : 1;  /* bit[24]: ������HIEPSδʹ�á� */
        unsigned int  reserved_13              : 1;  /* bit[25]: ������HIEPSδʹ�á� */
        unsigned int  reserved_14              : 1;  /* bit[26]: ������HIEPSδʹ�á� */
        unsigned int  reserved_15              : 1;  /* bit[27]: ������HIEPSδʹ�á� */
        unsigned int  reserved_16              : 1;  /* bit[28]: ������HIEPSδʹ�á� */
        unsigned int  reserved_17              : 1;  /* bit[29]: ������HIEPSδʹ�á� */
        unsigned int  reserved_18              : 1;  /* bit[30]: ������HIEPSδʹ�á� */
        unsigned int  reserved_19              : 1;  /* bit[31]: ������HIEPSδʹ�á� */
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
 �ṹ��    : SOC_ETZPC_DECPROT5STAT_UNION
 �ṹ˵��  : DECPROT5STAT �Ĵ����ṹ���塣��ַƫ����:0x83C����ֵ:0x00300000�����:32
 �Ĵ���˵��: IP��ȫ����״̬�Ĵ���5��
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved_0: 1;  /* bit[0] : ������HIEPSδʹ�á� */
        unsigned int  reserved_1: 1;  /* bit[1] : ������HIEPSδʹ�á� */
        unsigned int  reserved_2: 1;  /* bit[2] : ������HIEPSδʹ�á� */
        unsigned int  reserved_3: 1;  /* bit[3] : ������HIEPSδʹ�á� */
        unsigned int  reserved_4: 1;  /* bit[4] : ������HIEPSδʹ�á� */
        unsigned int  reserved_5: 1;  /* bit[5] : ������HIEPSδʹ�á� */
        unsigned int  reserved_6: 1;  /* bit[6] : ������HIEPSδʹ�á� */
        unsigned int  reserved_7: 1;  /* bit[7] : ������HIEPSδʹ�á� */
        unsigned int  reserved_8: 1;  /* bit[8] : ������HIEPSδʹ�á� */
        unsigned int  reserved_9: 1;  /* bit[9] : ������HIEPSδʹ�á� */
        unsigned int  reserved_10: 1;  /* bit[10]: ������HIEPSδʹ�á� */
        unsigned int  reserved_11: 1;  /* bit[11]: ������HIEPSδʹ�á� */
        unsigned int  reserved_12: 1;  /* bit[12]: ������HIEPSδʹ�á� */
        unsigned int  reserved_13: 1;  /* bit[13]: ������HIEPSδʹ�á� */
        unsigned int  reserved_14: 1;  /* bit[14]: ������HIEPSδʹ�á� */
        unsigned int  reserved_15: 1;  /* bit[15]: ������HIEPSδʹ�á� */
        unsigned int  reserved_16: 1;  /* bit[16]: ������HIEPSδʹ�á� */
        unsigned int  reserved_17: 1;  /* bit[17]: ������HIEPSδʹ�á� */
        unsigned int  reserved_18: 1;  /* bit[18]: ������HIEPSδʹ�á� */
        unsigned int  reserved_19: 1;  /* bit[19]: ������HIEPSδʹ�á� */
        unsigned int  reserved_20: 1;  /* bit[20]: ������HIEPSδʹ�á� */
        unsigned int  reserved_21: 1;  /* bit[21]: ������HIEPSδʹ�á� */
        unsigned int  reserved_22: 1;  /* bit[22]: ������HIEPSδʹ�á� */
        unsigned int  reserved_23: 1;  /* bit[23]: ������HIEPSδʹ�á� */
        unsigned int  reserved_24: 1;  /* bit[24]: ������HIEPSδʹ�á� */
        unsigned int  reserved_25: 1;  /* bit[25]: ������HIEPSδʹ�á� */
        unsigned int  reserved_26: 1;  /* bit[26]: ������HIEPSδʹ�á� */
        unsigned int  reserved_27: 1;  /* bit[27]: ������HIEPSδʹ�á� */
        unsigned int  reserved_28: 1;  /* bit[28]: ������HIEPSδʹ�á� */
        unsigned int  reserved_29: 1;  /* bit[29]: ������HIEPSδʹ�á� */
        unsigned int  reserved_30: 1;  /* bit[30]: ������HIEPSδʹ�á� */
        unsigned int  reserved_31: 1;  /* bit[31]: ������HIEPSδʹ�á� */
    } reg;
} SOC_ETZPC_DECPROT5STAT_UNION;
#endif


/*****************************************************************************
 �ṹ��    : SOC_ETZPC_DECPROT5SET_UNION
 �ṹ˵��  : DECPROT5SET �Ĵ����ṹ���塣��ַƫ����:0x840����ֵ:0x00000000�����:32
 �Ĵ���˵��: IP��ȫ������λ�Ĵ���5��
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved_0: 1;  /* bit[0] : ������HIEPSδʹ�á� */
        unsigned int  reserved_1: 1;  /* bit[1] : ������HIEPSδʹ�á� */
        unsigned int  reserved_2: 1;  /* bit[2] : ������HIEPSδʹ�á� */
        unsigned int  reserved_3: 1;  /* bit[3] : ������HIEPSδʹ�á� */
        unsigned int  reserved_4: 1;  /* bit[4] : ������HIEPSδʹ�á� */
        unsigned int  reserved_5: 1;  /* bit[5] : ������HIEPSδʹ�á� */
        unsigned int  reserved_6: 1;  /* bit[6] : ������HIEPSδʹ�á� */
        unsigned int  reserved_7: 1;  /* bit[7] : ������HIEPSδʹ�á� */
        unsigned int  reserved_8: 1;  /* bit[8] : ������HIEPSδʹ�á� */
        unsigned int  reserved_9: 1;  /* bit[9] : ������HIEPSδʹ�á� */
        unsigned int  reserved_10: 1;  /* bit[10]: ������HIEPSδʹ�á� */
        unsigned int  reserved_11: 1;  /* bit[11]: ������HIEPSδʹ�á� */
        unsigned int  reserved_12: 1;  /* bit[12]: ������HIEPSδʹ�á� */
        unsigned int  reserved_13: 1;  /* bit[13]: ������HIEPSδʹ�á� */
        unsigned int  reserved_14: 1;  /* bit[14]: ������HIEPSδʹ�á� */
        unsigned int  reserved_15: 1;  /* bit[15]: ������HIEPSδʹ�á� */
        unsigned int  reserved_16: 1;  /* bit[16]: ������HIEPSδʹ�á� */
        unsigned int  reserved_17: 1;  /* bit[17]: ������HIEPSδʹ�á� */
        unsigned int  reserved_18: 1;  /* bit[18]: ������HIEPSδʹ�á� */
        unsigned int  reserved_19: 1;  /* bit[19]: ������HIEPSδʹ�á� */
        unsigned int  reserved_20: 1;  /* bit[20]: ������HIEPSδʹ�á� */
        unsigned int  reserved_21: 1;  /* bit[21]: ������HIEPSδʹ�á� */
        unsigned int  reserved_22: 1;  /* bit[22]: ������HIEPSδʹ�á� */
        unsigned int  reserved_23: 1;  /* bit[23]: ������HIEPSδʹ�á� */
        unsigned int  reserved_24: 1;  /* bit[24]: ������HIEPSδʹ�á� */
        unsigned int  reserved_25: 1;  /* bit[25]: ������HIEPSδʹ�á� */
        unsigned int  reserved_26: 1;  /* bit[26]: ������HIEPSδʹ�á� */
        unsigned int  reserved_27: 1;  /* bit[27]: ������HIEPSδʹ�á� */
        unsigned int  reserved_28: 1;  /* bit[28]: ������HIEPSδʹ�á� */
        unsigned int  reserved_29: 1;  /* bit[29]: ������HIEPSδʹ�á� */
        unsigned int  reserved_30: 1;  /* bit[30]: ������HIEPSδʹ�á� */
        unsigned int  reserved_31: 1;  /* bit[31]: ������HIEPSδʹ�á� */
    } reg;
} SOC_ETZPC_DECPROT5SET_UNION;
#endif


/*****************************************************************************
 �ṹ��    : SOC_ETZPC_DECPROT5CLR_UNION
 �ṹ˵��  : DECPROT5CLR �Ĵ����ṹ���塣��ַƫ����:0x844����ֵ:0x00000000�����:32
 �Ĵ���˵��: IP��ȫ��������Ĵ���5��
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved_0: 1;  /* bit[0] : ������HIEPSδʹ�á� */
        unsigned int  reserved_1: 1;  /* bit[1] : ������HIEPSδʹ�á� */
        unsigned int  reserved_2: 1;  /* bit[2] : ������HIEPSδʹ�á� */
        unsigned int  reserved_3: 1;  /* bit[3] : ������HIEPSδʹ�á� */
        unsigned int  reserved_4: 1;  /* bit[4] : ������HIEPSδʹ�á� */
        unsigned int  reserved_5: 1;  /* bit[5] : ������HIEPSδʹ�á� */
        unsigned int  reserved_6: 1;  /* bit[6] : ������HIEPSδʹ�á� */
        unsigned int  reserved_7: 1;  /* bit[7] : ������HIEPSδʹ�á� */
        unsigned int  reserved_8: 1;  /* bit[8] : ������HIEPSδʹ�á� */
        unsigned int  reserved_9: 1;  /* bit[9] : ������HIEPSδʹ�á� */
        unsigned int  reserved_10: 1;  /* bit[10]: ������HIEPSδʹ�á� */
        unsigned int  reserved_11: 1;  /* bit[11]: ������HIEPSδʹ�á� */
        unsigned int  reserved_12: 1;  /* bit[12]: ������HIEPSδʹ�á� */
        unsigned int  reserved_13: 1;  /* bit[13]: ������HIEPSδʹ�á� */
        unsigned int  reserved_14: 1;  /* bit[14]: ������HIEPSδʹ�á� */
        unsigned int  reserved_15: 1;  /* bit[15]: ������HIEPSδʹ�á� */
        unsigned int  reserved_16: 1;  /* bit[16]: ������HIEPSδʹ�á� */
        unsigned int  reserved_17: 1;  /* bit[17]: ������HIEPSδʹ�á� */
        unsigned int  reserved_18: 1;  /* bit[18]: ������HIEPSδʹ�á� */
        unsigned int  reserved_19: 1;  /* bit[19]: ������HIEPSδʹ�á� */
        unsigned int  reserved_20: 1;  /* bit[20]: ������HIEPSδʹ�á� */
        unsigned int  reserved_21: 1;  /* bit[21]: ������HIEPSδʹ�á� */
        unsigned int  reserved_22: 1;  /* bit[22]: ������HIEPSδʹ�á� */
        unsigned int  reserved_23: 1;  /* bit[23]: ������HIEPSδʹ�á� */
        unsigned int  reserved_24: 1;  /* bit[24]: ������HIEPSδʹ�á� */
        unsigned int  reserved_25: 1;  /* bit[25]: ������HIEPSδʹ�á� */
        unsigned int  reserved_26: 1;  /* bit[26]: ������HIEPSδʹ�á� */
        unsigned int  reserved_27: 1;  /* bit[27]: ������HIEPSδʹ�á� */
        unsigned int  reserved_28: 1;  /* bit[28]: ������HIEPSδʹ�á� */
        unsigned int  reserved_29: 1;  /* bit[29]: ������HIEPSδʹ�á� */
        unsigned int  reserved_30: 1;  /* bit[30]: ������HIEPSδʹ�á� */
        unsigned int  reserved_31: 1;  /* bit[31]: ������HIEPSδʹ�á� */
    } reg;
} SOC_ETZPC_DECPROT5CLR_UNION;
#endif


/*****************************************************************************
 �ṹ��    : SOC_ETZPC_DECPROT6STAT_UNION
 �ṹ˵��  : DECPROT6STAT �Ĵ����ṹ���塣��ַƫ����:0x848����ֵ:0x0007FEE0�����:32
 �Ĵ���˵��: IP��ȫ����״̬�Ĵ���6��
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved_0: 1;  /* bit[0] : ������HIEPSδʹ�á� */
        unsigned int  reserved_1: 1;  /* bit[1] : ������HIEPSδʹ�á� */
        unsigned int  reserved_2: 1;  /* bit[2] : ������HIEPSδʹ�á� */
        unsigned int  reserved_3: 1;  /* bit[3] : ������HIEPSδʹ�á� */
        unsigned int  reserved_4: 1;  /* bit[4] : ������HIEPSδʹ�á� */
        unsigned int  reserved_5: 1;  /* bit[5] : ������HIEPSδʹ�á� */
        unsigned int  reserved_6: 1;  /* bit[6] : ������HIEPSδʹ�á� */
        unsigned int  reserved_7: 1;  /* bit[7] : ������HIEPSδʹ�á� */
        unsigned int  reserved_8: 1;  /* bit[8] : ������HIEPSδʹ�á� */
        unsigned int  reserved_9: 1;  /* bit[9] : ������HIEPSδʹ�á� */
        unsigned int  reserved_10: 1;  /* bit[10]: ������HIEPSδʹ�á� */
        unsigned int  reserved_11: 1;  /* bit[11]: ������HIEPSδʹ�á� */
        unsigned int  reserved_12: 1;  /* bit[12]: ������HIEPSδʹ�á� */
        unsigned int  reserved_13: 1;  /* bit[13]: ������HIEPSδʹ�á� */
        unsigned int  reserved_14: 1;  /* bit[14]: ������HIEPSδʹ�á� */
        unsigned int  reserved_15: 1;  /* bit[15]: ������HIEPSδʹ�á� */
        unsigned int  reserved_16: 1;  /* bit[16]: ������HIEPSδʹ�á� */
        unsigned int  reserved_17: 1;  /* bit[17]: ������HIEPSδʹ�á� */
        unsigned int  reserved_18: 1;  /* bit[18]: ������HIEPSδʹ�á� */
        unsigned int  reserved_19: 1;  /* bit[19]: ������HIEPSδʹ�á� */
        unsigned int  reserved_20: 1;  /* bit[20]: ������HIEPSδʹ�á� */
        unsigned int  reserved_21: 1;  /* bit[21]: ������HIEPSδʹ�á� */
        unsigned int  reserved_22: 1;  /* bit[22]: ������HIEPSδʹ�á� */
        unsigned int  reserved_23: 1;  /* bit[23]: ������HIEPSδʹ�á� */
        unsigned int  reserved_24: 1;  /* bit[24]: ������HIEPSδʹ�á� */
        unsigned int  reserved_25: 1;  /* bit[25]: ������HIEPSδʹ�á� */
        unsigned int  reserved_26: 1;  /* bit[26]: ������HIEPSδʹ�á� */
        unsigned int  reserved_27: 1;  /* bit[27]: ������HIEPSδʹ�á� */
        unsigned int  reserved_28: 1;  /* bit[28]: ������HIEPSδʹ�á� */
        unsigned int  reserved_29: 1;  /* bit[29]: ������HIEPSδʹ�á� */
        unsigned int  reserved_30: 1;  /* bit[30]: ������HIEPSδʹ�á� */
        unsigned int  reserved_31: 1;  /* bit[31]: ������HIEPSδʹ�á� */
    } reg;
} SOC_ETZPC_DECPROT6STAT_UNION;
#endif


/*****************************************************************************
 �ṹ��    : SOC_ETZPC_DECPROT6SET_UNION
 �ṹ˵��  : DECPROT6SET �Ĵ����ṹ���塣��ַƫ����:0x84C����ֵ:0x00000000�����:32
 �Ĵ���˵��: IP��ȫ������λ�Ĵ���6��
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved_0: 1;  /* bit[0] : ������HIEPSδʹ�á� */
        unsigned int  reserved_1: 1;  /* bit[1] : ������HIEPSδʹ�á� */
        unsigned int  reserved_2: 1;  /* bit[2] : ������HIEPSδʹ�á� */
        unsigned int  reserved_3: 1;  /* bit[3] : ������HIEPSδʹ�á� */
        unsigned int  reserved_4: 1;  /* bit[4] : ������HIEPSδʹ�á� */
        unsigned int  reserved_5: 1;  /* bit[5] : ������HIEPSδʹ�á� */
        unsigned int  reserved_6: 1;  /* bit[6] : ������HIEPSδʹ�á� */
        unsigned int  reserved_7: 1;  /* bit[7] : ������HIEPSδʹ�á� */
        unsigned int  reserved_8: 1;  /* bit[8] : ������HIEPSδʹ�á� */
        unsigned int  reserved_9: 1;  /* bit[9] : ������HIEPSδʹ�á� */
        unsigned int  reserved_10: 1;  /* bit[10]: ������HIEPSδʹ�á� */
        unsigned int  reserved_11: 1;  /* bit[11]: ������HIEPSδʹ�á� */
        unsigned int  reserved_12: 1;  /* bit[12]: ������HIEPSδʹ�á� */
        unsigned int  reserved_13: 1;  /* bit[13]: ������HIEPSδʹ�á� */
        unsigned int  reserved_14: 1;  /* bit[14]: ������HIEPSδʹ�á� */
        unsigned int  reserved_15: 1;  /* bit[15]: ������HIEPSδʹ�á� */
        unsigned int  reserved_16: 1;  /* bit[16]: ������HIEPSδʹ�á� */
        unsigned int  reserved_17: 1;  /* bit[17]: ������HIEPSδʹ�á� */
        unsigned int  reserved_18: 1;  /* bit[18]: ������HIEPSδʹ�á� */
        unsigned int  reserved_19: 1;  /* bit[19]: ������HIEPSδʹ�á� */
        unsigned int  reserved_20: 1;  /* bit[20]: ������HIEPSδʹ�á� */
        unsigned int  reserved_21: 1;  /* bit[21]: ������HIEPSδʹ�á� */
        unsigned int  reserved_22: 1;  /* bit[22]: ������HIEPSδʹ�á� */
        unsigned int  reserved_23: 1;  /* bit[23]: ������HIEPSδʹ�á� */
        unsigned int  reserved_24: 1;  /* bit[24]: ������HIEPSδʹ�á� */
        unsigned int  reserved_25: 1;  /* bit[25]: ������HIEPSδʹ�á� */
        unsigned int  reserved_26: 1;  /* bit[26]: ������HIEPSδʹ�á� */
        unsigned int  reserved_27: 1;  /* bit[27]: ������HIEPSδʹ�á� */
        unsigned int  reserved_28: 1;  /* bit[28]: ������HIEPSδʹ�á� */
        unsigned int  reserved_29: 1;  /* bit[29]: ������HIEPSδʹ�á� */
        unsigned int  reserved_30: 1;  /* bit[30]: ������HIEPSδʹ�á� */
        unsigned int  reserved_31: 1;  /* bit[31]: ������HIEPSδʹ�á� */
    } reg;
} SOC_ETZPC_DECPROT6SET_UNION;
#endif


/*****************************************************************************
 �ṹ��    : SOC_ETZPC_DECPROT6CLR_UNION
 �ṹ˵��  : DECPROT6CLR �Ĵ����ṹ���塣��ַƫ����:0x850����ֵ:0x00000000�����:32
 �Ĵ���˵��: IP��ȫ��������Ĵ���6��
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved_0: 1;  /* bit[0] : ������HIEPSδʹ�á� */
        unsigned int  reserved_1: 1;  /* bit[1] : ������HIEPSδʹ�á� */
        unsigned int  reserved_2: 1;  /* bit[2] : ������HIEPSδʹ�á� */
        unsigned int  reserved_3: 1;  /* bit[3] : ������HIEPSδʹ�á� */
        unsigned int  reserved_4: 1;  /* bit[4] : ������HIEPSδʹ�á� */
        unsigned int  reserved_5: 1;  /* bit[5] : ������HIEPSδʹ�á� */
        unsigned int  reserved_6: 1;  /* bit[6] : ������HIEPSδʹ�á� */
        unsigned int  reserved_7: 1;  /* bit[7] : ������HIEPSδʹ�á� */
        unsigned int  reserved_8: 1;  /* bit[8] : ������HIEPSδʹ�á� */
        unsigned int  reserved_9: 1;  /* bit[9] : ������HIEPSδʹ�á� */
        unsigned int  reserved_10: 1;  /* bit[10]: ������HIEPSδʹ�á� */
        unsigned int  reserved_11: 1;  /* bit[11]: ������HIEPSδʹ�á� */
        unsigned int  reserved_12: 1;  /* bit[12]: ������HIEPSδʹ�á� */
        unsigned int  reserved_13: 1;  /* bit[13]: ������HIEPSδʹ�á� */
        unsigned int  reserved_14: 1;  /* bit[14]: ������HIEPSδʹ�á� */
        unsigned int  reserved_15: 1;  /* bit[15]: ������HIEPSδʹ�á� */
        unsigned int  reserved_16: 1;  /* bit[16]: ������HIEPSδʹ�á� */
        unsigned int  reserved_17: 1;  /* bit[17]: ������HIEPSδʹ�á� */
        unsigned int  reserved_18: 1;  /* bit[18]: ������HIEPSδʹ�á� */
        unsigned int  reserved_19: 1;  /* bit[19]: ������HIEPSδʹ�á� */
        unsigned int  reserved_20: 1;  /* bit[20]: ������HIEPSδʹ�á� */
        unsigned int  reserved_21: 1;  /* bit[21]: ������HIEPSδʹ�á� */
        unsigned int  reserved_22: 1;  /* bit[22]: ������HIEPSδʹ�á� */
        unsigned int  reserved_23: 1;  /* bit[23]: ������HIEPSδʹ�á� */
        unsigned int  reserved_24: 1;  /* bit[24]: ������HIEPSδʹ�á� */
        unsigned int  reserved_25: 1;  /* bit[25]: ������HIEPSδʹ�á� */
        unsigned int  reserved_26: 1;  /* bit[26]: ������HIEPSδʹ�á� */
        unsigned int  reserved_27: 1;  /* bit[27]: ������HIEPSδʹ�á� */
        unsigned int  reserved_28: 1;  /* bit[28]: ������HIEPSδʹ�á� */
        unsigned int  reserved_29: 1;  /* bit[29]: ������HIEPSδʹ�á� */
        unsigned int  reserved_30: 1;  /* bit[30]: ������HIEPSδʹ�á� */
        unsigned int  reserved_31: 1;  /* bit[31]: ������HIEPSδʹ�á� */
    } reg;
} SOC_ETZPC_DECPROT6CLR_UNION;
#endif


/*****************************************************************************
 �ṹ��    : SOC_ETZPC_DECPROT7STAT_UNION
 �ṹ˵��  : DECPROT7STAT �Ĵ����ṹ���塣��ַƫ����:0x854����ֵ:0x00000000�����:32
 �Ĵ���˵��: IP��ȫ����״̬�Ĵ���7��
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved_0: 1;  /* bit[0]   : ������HIEPSδʹ�á� */
        unsigned int  reserved_1: 1;  /* bit[1]   : ������HIEPSδʹ�á� */
        unsigned int  reserved_2: 1;  /* bit[2]   : ������HIEPSδʹ�á� */
        unsigned int  reserved_3: 1;  /* bit[3]   : ������HIEPSδʹ�á� */
        unsigned int  reserved_4: 28; /* bit[4-31]: ������HIEPSδʹ�á� */
    } reg;
} SOC_ETZPC_DECPROT7STAT_UNION;
#endif


/*****************************************************************************
 �ṹ��    : SOC_ETZPC_DECPROT7SET_UNION
 �ṹ˵��  : DECPROT7SET �Ĵ����ṹ���塣��ַƫ����:0x858����ֵ:0x00000000�����:32
 �Ĵ���˵��: IP��ȫ������λ�Ĵ���7��
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved_0: 1;  /* bit[0]   : ������HIEPSδʹ�á� */
        unsigned int  reserved_1: 1;  /* bit[1]   : ������HIEPSδʹ�á� */
        unsigned int  reserved_2: 1;  /* bit[2]   : ������HIEPSδʹ�á� */
        unsigned int  reserved_3: 1;  /* bit[3]   : ������HIEPSδʹ�á� */
        unsigned int  reserved_4: 28; /* bit[4-31]: ������HIEPSδʹ�á� */
    } reg;
} SOC_ETZPC_DECPROT7SET_UNION;
#endif


/*****************************************************************************
 �ṹ��    : SOC_ETZPC_DECPROT7CLR_UNION
 �ṹ˵��  : DECPROT7CLR �Ĵ����ṹ���塣��ַƫ����:0x85C����ֵ:0x00000000�����:32
 �Ĵ���˵��: IP��ȫ��������Ĵ���7��
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved_0: 1;  /* bit[0]   : ������HIEPSδʹ�á� */
        unsigned int  reserved_1: 1;  /* bit[1]   : ������HIEPSδʹ�á� */
        unsigned int  reserved_2: 1;  /* bit[2]   : ������HIEPSδʹ�á� */
        unsigned int  reserved_3: 1;  /* bit[3]   : ������HIEPSδʹ�á� */
        unsigned int  reserved_4: 28; /* bit[4-31]: ������HIEPSδʹ�á� */
    } reg;
} SOC_ETZPC_DECPROT7CLR_UNION;
#endif


/*****************************************************************************
 �ṹ��    : SOC_ETZPC_DECPROT8STAT_UNION
 �ṹ˵��  : DECPROT8STAT �Ĵ����ṹ���塣��ַƫ����:0x860����ֵ:0x00000007�����:32
 �Ĵ���˵��: IP��ȫ����״̬�Ĵ���8��
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved_0: 8;  /* bit[0-7] : ������HIEPSδʹ�á� */
        unsigned int  reserved_1: 23; /* bit[8-30]: ������HIEPSδʹ�á� */
        unsigned int  reserved_2: 1;  /* bit[31]  : ������HIEPSδʹ�á� */
    } reg;
} SOC_ETZPC_DECPROT8STAT_UNION;
#endif


/*****************************************************************************
 �ṹ��    : SOC_ETZPC_DECPROT8SET_UNION
 �ṹ˵��  : DECPROT8SET �Ĵ����ṹ���塣��ַƫ����:0x864����ֵ:0x00000000�����:32
 �Ĵ���˵��: IP��ȫ������λ�Ĵ���8��
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved_0: 8;  /* bit[0-7] : ������HIEPSδʹ�á� */
        unsigned int  reserved_1: 23; /* bit[8-30]: ������HIEPSδʹ�á� */
        unsigned int  reserved_2: 1;  /* bit[31]  : ������HIEPSδʹ�á� */
    } reg;
} SOC_ETZPC_DECPROT8SET_UNION;
#endif


/*****************************************************************************
 �ṹ��    : SOC_ETZPC_DECPROT8CLR_UNION
 �ṹ˵��  : DECPROT8CLR �Ĵ����ṹ���塣��ַƫ����:0x868����ֵ:0x00000000�����:32
 �Ĵ���˵��: IP��ȫ��������Ĵ���8��
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved_0: 8;  /* bit[0-7] : ������HIEPSδʹ�á� */
        unsigned int  reserved_1: 23; /* bit[8-30]: ������HIEPSδʹ�á� */
        unsigned int  reserved_2: 1;  /* bit[31]  : ������HIEPSδʹ�á� */
    } reg;
} SOC_ETZPC_DECPROT8CLR_UNION;
#endif


/*****************************************************************************
 �ṹ��    : SOC_ETZPC_REG0_STAT_UNION
 �ṹ˵��  : REG0_STAT �Ĵ����ṹ���塣��ַƫ����:0x86C����ֵ:0x00000000�����:32
 �Ĵ���˵��: ����reg0�Ĵ�������Ϣ��
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved : 32; /* bit[0-31]: ������ */
    } reg;
} SOC_ETZPC_REG0_STAT_UNION;
#endif


/*****************************************************************************
 �ṹ��    : SOC_ETZPC_REG1_STAT_UNION
 �ṹ˵��  : REG1_STAT �Ĵ����ṹ���塣��ַƫ����:0x870����ֵ:0x00000000�����:32
 �Ĵ���˵��: ����reg1�Ĵ�������Ϣ��
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved : 32; /* bit[0-31]: ������ */
    } reg;
} SOC_ETZPC_REG1_STAT_UNION;
#endif


/*****************************************************************************
 �ṹ��    : SOC_ETZPC_EFUSEC2HIEPS_PATCH0_SEC_UNION
 �ṹ˵��  : EFUSEC2HIEPS_PATCH0_SEC �Ĵ����ṹ���塣��ַƫ����:0x874����ֵ:0x00000000�����:32
 �Ĵ���˵��: �Ĵ�PATCHУ����Ϣ�ļĴ���0
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  efusec2hieps_patch0_sec : 32; /* bit[0-31]: ��������Ȼ����ʹ�ã�����Ӳ���߼����ֲ��� */
    } reg;
} SOC_ETZPC_EFUSEC2HIEPS_PATCH0_SEC_UNION;
#endif
#define SOC_ETZPC_EFUSEC2HIEPS_PATCH0_SEC_efusec2hieps_patch0_sec_START  (0)
#define SOC_ETZPC_EFUSEC2HIEPS_PATCH0_SEC_efusec2hieps_patch0_sec_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_ETZPC_EFUSEC2HIEPS_PATCH1_SEC_UNION
 �ṹ˵��  : EFUSEC2HIEPS_PATCH1_SEC �Ĵ����ṹ���塣��ַƫ����:0x878����ֵ:0x00000000�����:32
 �Ĵ���˵��: �Ĵ�PATCHУ����Ϣ�ļĴ���1
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  efusec2hieps_patch1_sec : 32; /* bit[0-31]: ��������Ȼ����ʹ�ã�����Ӳ���߼����ֲ��� */
    } reg;
} SOC_ETZPC_EFUSEC2HIEPS_PATCH1_SEC_UNION;
#endif
#define SOC_ETZPC_EFUSEC2HIEPS_PATCH1_SEC_efusec2hieps_patch1_sec_START  (0)
#define SOC_ETZPC_EFUSEC2HIEPS_PATCH1_SEC_efusec2hieps_patch1_sec_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_ETZPC_EFUSEC2HIEPS_PATCH2_SEC_UNION
 �ṹ˵��  : EFUSEC2HIEPS_PATCH2_SEC �Ĵ����ṹ���塣��ַƫ����:0x87C����ֵ:0x00000000�����:32
 �Ĵ���˵��: �Ĵ�PATCHУ����Ϣ�ļĴ���2
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  efusec2hieps_patch2_sec : 32; /* bit[0-31]: ��������Ȼ����ʹ�ã�����Ӳ���߼����ֲ��� */
    } reg;
} SOC_ETZPC_EFUSEC2HIEPS_PATCH2_SEC_UNION;
#endif
#define SOC_ETZPC_EFUSEC2HIEPS_PATCH2_SEC_efusec2hieps_patch2_sec_START  (0)
#define SOC_ETZPC_EFUSEC2HIEPS_PATCH2_SEC_efusec2hieps_patch2_sec_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_ETZPC_EFUSEC2HIEPS_PATCH3_SEC_UNION
 �ṹ˵��  : EFUSEC2HIEPS_PATCH3_SEC �Ĵ����ṹ���塣��ַƫ����:0x880����ֵ:0x00000000�����:32
 �Ĵ���˵��: �Ĵ�PATCHУ����Ϣ�ļĴ���3
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  efusec2hieps_patch3_sec : 32; /* bit[0-31]: ��������Ȼ����ʹ�ã�����Ӳ���߼����ֲ��� */
    } reg;
} SOC_ETZPC_EFUSEC2HIEPS_PATCH3_SEC_UNION;
#endif
#define SOC_ETZPC_EFUSEC2HIEPS_PATCH3_SEC_efusec2hieps_patch3_sec_START  (0)
#define SOC_ETZPC_EFUSEC2HIEPS_PATCH3_SEC_efusec2hieps_patch3_sec_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_ETZPC_EFUSEC2HIEPS_PATCH4_SEC_UNION
 �ṹ˵��  : EFUSEC2HIEPS_PATCH4_SEC �Ĵ����ṹ���塣��ַƫ����:0x884����ֵ:0x00000000�����:32
 �Ĵ���˵��: �Ĵ�PATCHУ����Ϣ�ļĴ���4
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  efusec2hieps_patch4_sec : 32; /* bit[0-31]: ��������Ȼ����ʹ�ã�����Ӳ���߼����ֲ��� */
    } reg;
} SOC_ETZPC_EFUSEC2HIEPS_PATCH4_SEC_UNION;
#endif
#define SOC_ETZPC_EFUSEC2HIEPS_PATCH4_SEC_efusec2hieps_patch4_sec_START  (0)
#define SOC_ETZPC_EFUSEC2HIEPS_PATCH4_SEC_efusec2hieps_patch4_sec_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_ETZPC_EFUSEC2HIEPS_PATCH5_SEC_UNION
 �ṹ˵��  : EFUSEC2HIEPS_PATCH5_SEC �Ĵ����ṹ���塣��ַƫ����:0x888����ֵ:0x00000000�����:32
 �Ĵ���˵��: �Ĵ�PATCHУ����Ϣ�ļĴ���5
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  efusec2hieps_patch5_sec : 32; /* bit[0-31]: ��������Ȼ����ʹ�ã�����Ӳ���߼����ֲ��� */
    } reg;
} SOC_ETZPC_EFUSEC2HIEPS_PATCH5_SEC_UNION;
#endif
#define SOC_ETZPC_EFUSEC2HIEPS_PATCH5_SEC_efusec2hieps_patch5_sec_START  (0)
#define SOC_ETZPC_EFUSEC2HIEPS_PATCH5_SEC_efusec2hieps_patch5_sec_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_ETZPC_EFUSEC2HIEPS_PATCH6_SEC_UNION
 �ṹ˵��  : EFUSEC2HIEPS_PATCH6_SEC �Ĵ����ṹ���塣��ַƫ����:0x88C����ֵ:0x00000000�����:32
 �Ĵ���˵��: �Ĵ�PATCHУ����Ϣ�ļĴ���6
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  efusec2hieps_patch6_sec : 32; /* bit[0-31]: ��������Ȼ����ʹ�ã�����Ӳ���߼����ֲ��� */
    } reg;
} SOC_ETZPC_EFUSEC2HIEPS_PATCH6_SEC_UNION;
#endif
#define SOC_ETZPC_EFUSEC2HIEPS_PATCH6_SEC_efusec2hieps_patch6_sec_START  (0)
#define SOC_ETZPC_EFUSEC2HIEPS_PATCH6_SEC_efusec2hieps_patch6_sec_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_ETZPC_EFUSEC2HIEPS_PATCH7_SEC_UNION
 �ṹ˵��  : EFUSEC2HIEPS_PATCH7_SEC �Ĵ����ṹ���塣��ַƫ����:0x890����ֵ:0x00000000�����:32
 �Ĵ���˵��: �Ĵ�PATCHУ����Ϣ�ļĴ���7
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  efusec2hieps_patch7_sec : 32; /* bit[0-31]: ��������Ȼ����ʹ�ã�����Ӳ���߼����ֲ��� */
    } reg;
} SOC_ETZPC_EFUSEC2HIEPS_PATCH7_SEC_UNION;
#endif
#define SOC_ETZPC_EFUSEC2HIEPS_PATCH7_SEC_efusec2hieps_patch7_sec_START  (0)
#define SOC_ETZPC_EFUSEC2HIEPS_PATCH7_SEC_efusec2hieps_patch7_sec_END    (31)






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

#endif /* end of soc_etzpc_interface.h */
