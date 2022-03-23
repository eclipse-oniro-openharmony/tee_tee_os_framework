/******************************************************************************

                 ��Ȩ���� (C), 2001-2019, ��Ϊ�������޹�˾

 ******************************************************************************
  �� �� ��   : soc_km_interface.h
  �� �� ��   : ����
  ��    ��   : Excel2Code
  ��������   : 2019-10-26 10:53:23
  ����޸�   :
  ��������   : �ӿ�ͷ�ļ�
  �����б�   :
  �޸���ʷ   :
  1.��    ��   : 2019��10��26��
    ��    ��   : l00249396
    �޸�����   : �ӡ�HiEPS V200 nManager�Ĵ����ֲ�_KM.xml���Զ�����

******************************************************************************/

/*****************************************************************************
  1 ����ͷ�ļ�����
*****************************************************************************/

#ifndef __SOC_KM_INTERFACE_H__
#define __SOC_KM_INTERFACE_H__

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
/* �Ĵ���˵����KM STR�Ĵ���
   λ����UNION�ṹ:  SOC_KM_STR_UNION */
#define SOC_KM_STR_ADDR(base)                         ((base) + (0x0000))

/* �Ĵ���˵������Կ·�ɼĴ���
   λ����UNION�ṹ:  SOC_KM_MODE_UNION */
#define SOC_KM_MODE_ADDR(base)                        ((base) + (0x0004))

/* �Ĵ���˵����������Կ�����ź�
   λ����UNION�ṹ:  SOC_KM_DERIVE_KEY_CLR_UNION */
#define SOC_KM_DERIVE_KEY_CLR_ADDR(base)              ((base) + (0x0008))

/* �Ĵ���˵������Կ������ɱ�־
   λ����UNION�ṹ:  SOC_KM_KEY_DECRY_DONE_UNION */
#define SOC_KM_KEY_DECRY_DONE_ADDR(base)              ((base) + (0x000C))

/* �Ĵ���˵������Կ������ɱ�־
   λ����UNION�ṹ:  SOC_KM_KEY_DERIVE_DONE_UNION */
#define SOC_KM_KEY_DERIVE_DONE_ADDR(base)             ((base) + (0x0010))

/* �Ĵ���˵������Կ��������ź�����
   λ����UNION�ṹ:  SOC_KM_KEY_DERIVE_DONE_CLR_UNION */
#define SOC_KM_KEY_DERIVE_DONE_CLR_ADDR(base)         ((base) + (0x0014))

/* �Ĵ���˵����KM�Ĳ����ź�
   λ����UNION�ṹ:  SOC_KM_DFX_UNION */
#define SOC_KM_DFX_ADDR(base)                         ((base) + (0x0018))

/* �Ĵ���˵����KM�Ĵ��������ź�
   λ����UNION�ṹ:  SOC_KM_REG_LOCK_UNION */
#define SOC_KM_REG_LOCK_ADDR(base)                    ((base) + (0x001C))

/* �Ĵ���˵����CPU���õ�AES KEY
   λ����UNION�ṹ:  SOC_KM_AES_KEY_UNION */
#define SOC_KM_AES_KEY_ADDR(base, n)                  ((base) + (0x0020+(n)*4))

/* �Ĵ���˵����CPU���õ�DES KEY
   λ����UNION�ṹ:  SOC_KM_DES_KEY_UNION */
#define SOC_KM_DES_KEY_ADDR(base, n)                  ((base) + (0x0040+(n)*4))

/* �Ĵ���˵����CPU���õ�SM4 KEY
   λ����UNION�ṹ:  SOC_KM_SM4_KEY_UNION */
#define SOC_KM_SM4_KEY_ADDR(base, n)                  ((base) + (0x0060+(n)*4))

/* �Ĵ���˵��������ǰ��kdr
   λ����UNION�ṹ:  SOC_KM_KDR_IN_UNION */
#define SOC_KM_KDR_IN_ADDR(base, n)                   ((base) + (0x0080+(n)*4))

/* �Ĵ���˵�������ܺ��kdr
   λ����UNION�ṹ:  SOC_KM_KDR_OUT_UNION */
#define SOC_KM_KDR_OUT_ADDR(base, n)                  ((base) + (0x00A0+(n)*4))

/* �Ĵ���˵�������ĵ�cek
   λ����UNION�ṹ:  SOC_KM_CEK_IN_UNION */
#define SOC_KM_CEK_IN_ADDR(base, n)                   ((base) + (0x00C0+(n)*4))

/* �Ĵ���˵��������KEY
   λ����UNION�ṹ:  SOC_KM_DERIVE_KEY_UNION */
#define SOC_KM_DERIVE_KEY_ADDR(base, n)               ((base) + (0x0120+(n)*4))

/* �Ĵ���˵��������ǰ��gid
   λ����UNION�ṹ:  SOC_KM_GID_IN_UNION */
#define SOC_KM_GID_IN_ADDR(base, n)                   ((base) + (0x0140+(n)*4))

/* �Ĵ���˵�������ܺ��gid
   λ����UNION�ṹ:  SOC_KM_GID_OUT_UNION */
#define SOC_KM_GID_OUT_ADDR(base, n)                  ((base) + (0x0160+(n)*4))

/* �Ĵ���˵��������ǰ��pos
   λ����UNION�ṹ:  SOC_KM_POS_IN_UNION */
#define SOC_KM_POS_IN_ADDR(base, n)                   ((base) + (0x0180+(n)*4))

/* �Ĵ���˵�������ܺ��pos
   λ����UNION�ṹ:  SOC_KM_POS_OUT_UNION */
#define SOC_KM_POS_OUT_ADDR(base, n)                  ((base) + (0x01A0+(n)*4))

/* �Ĵ���˵����EPS_GJ_ROTPK������
   λ����UNION�ṹ:  SOC_KM_ROTPK_GJ_UNION */
#define SOC_KM_ROTPK_GJ_ADDR(base, n)                 ((base) + (0x01C0+(n)*4))

/* �Ĵ���˵����EPS_GM_ROTPK������
   λ����UNION�ṹ:  SOC_KM_ROTPK_GM_UNION */
#define SOC_KM_ROTPK_GM_ADDR(base, n)                 ((base) + (0x01E0+(n)*4))

/* �Ĵ���˵�����澯�����ź�
   λ����UNION�ṹ:  SOC_KM_ALARM_CLR_UNION */
#define SOC_KM_ALARM_CLR_ADDR(base)                   ((base) + (0x0200))

/* �Ĵ���˵�����澯�����ź�
   λ����UNION�ṹ:  SOC_KM_ALARM_MASK_EN_UNION */
#define SOC_KM_ALARM_MASK_EN_ADDR(base)               ((base) + (0x0204))

/* �Ĵ���˵����alarm�źţ�����ǰ��
   λ����UNION�ṹ:  SOC_KM_ALARM_UNION */
#define SOC_KM_ALARM_ADDR(base)                       ((base) + (0x0208))

/* �Ĵ���˵����alarm�źţ����κ�
   λ����UNION�ṹ:  SOC_KM_ALARM_MASK_UNION */
#define SOC_KM_ALARM_MASK_ADDR(base)                  ((base) + (0x020C))

/* �Ĵ���˵������Կ�����Ĵ���
   λ����UNION�ṹ:  SOC_KM_KEY_REG_LOCK_UNION */
#define SOC_KM_KEY_REG_LOCK_ADDR(base)                ((base) + (0x0210))

/* �Ĵ���˵����AES��Կ����Ĵ���
   λ����UNION�ṹ:  SOC_KM_AESKEY_MASK_VALUE_UNION */
#define SOC_KM_AESKEY_MASK_VALUE_ADDR(base)           ((base) + (0x0214))

/* �Ĵ���˵����DES��Կ����Ĵ���
   λ����UNION�ṹ:  SOC_KM_DESKEY_MASK_VALUE_UNION */
#define SOC_KM_DESKEY_MASK_VALUE_ADDR(base)           ((base) + (0x0218))

/* �Ĵ���˵����SM4��Կ����Ĵ���
   λ����UNION�ṹ:  SOC_KM_SM4KEY_MASK_VALUE_UNION */
#define SOC_KM_SM4KEY_MASK_VALUE_ADDR(base)           ((base) + (0x021C))

/* �Ĵ���˵����AES��ԿУ��ֵ�Ĵ���
   λ����UNION�ṹ:  SOC_KM_AES_KEY_PARITY_UNION */
#define SOC_KM_AES_KEY_PARITY_ADDR(base)              ((base) + (0x0220))

/* �Ĵ���˵����DES��ԿУ��ֵ�Ĵ���
   λ����UNION�ṹ:  SOC_KM_DES_KEY_PARITY_UNION */
#define SOC_KM_DES_KEY_PARITY_ADDR(base)              ((base) + (0x0224))

/* �Ĵ���˵����SM4��ԿУ��ֵ�Ĵ���
   λ����UNION�ṹ:  SOC_KM_SM4_KEY_PARITY_UNION */
#define SOC_KM_SM4_KEY_PARITY_ADDR(base)              ((base) + (0x0228))

/* �Ĵ���˵��������KDR��ԿУ��ֵ�Ĵ���
   λ����UNION�ṹ:  SOC_KM_KDR_IN_PARITY_UNION */
#define SOC_KM_KDR_IN_PARITY_ADDR(base)               ((base) + (0x022C))

/* �Ĵ���˵��������KDR��ԿУ��ֵ�Ĵ���
   λ����UNION�ṹ:  SOC_KM_KDR_OUT_PARITY_UNION */
#define SOC_KM_KDR_OUT_PARITY_ADDR(base)              ((base) + (0x0230))

/* �Ĵ���˵��������CEK��ԿУ��ֵ�Ĵ���
   λ����UNION�ṹ:  SOC_KM_CEK_IN_PARITY_UNION */
#define SOC_KM_CEK_IN_PARITY_ADDR(base)               ((base) + (0x0234))

/* �Ĵ���˵��������KEY��ԿУ��ֵ�Ĵ���
   λ����UNION�ṹ:  SOC_KM_DERIVE_KEY_PARITY_UNION */
#define SOC_KM_DERIVE_KEY_PARITY_ADDR(base)           ((base) + (0x0238))

/* �Ĵ���˵����CEK��Կ����Ĵ���
   λ����UNION�ṹ:  SOC_KM_CEK_MASK_VALUE_UNION */
#define SOC_KM_CEK_MASK_VALUE_ADDR(base)              ((base) + (0x0248))

/* �Ĵ���˵������Կ����Ĵ���
   λ����UNION�ṹ:  SOC_KM_KEY_MASK_VALUE_UNION */
#define SOC_KM_KEY_MASK_VALUE_ADDR(base)              ((base) + (0x024C))

/* �Ĵ���˵��������GID��ԿУ��ֵ�Ĵ���
   λ����UNION�ṹ:  SOC_KM_GID_IN_PARITY_UNION */
#define SOC_KM_GID_IN_PARITY_ADDR(base)               ((base) + (0x0254))

/* �Ĵ���˵��������GID��ԿУ��ֵ�Ĵ���
   λ����UNION�ṹ:  SOC_KM_GID_OUT_PARITY_UNION */
#define SOC_KM_GID_OUT_PARITY_ADDR(base)              ((base) + (0x0258))

/* �Ĵ���˵��������POS��ԿУ��ֵ�Ĵ���
   λ����UNION�ṹ:  SOC_KM_POS_IN_PARITY_UNION */
#define SOC_KM_POS_IN_PARITY_ADDR(base)               ((base) + (0x025C))

/* �Ĵ���˵��������POS��ԿУ��ֵ�Ĵ���
   λ����UNION�ṹ:  SOC_KM_POS_OUT_PARITY_UNION */
#define SOC_KM_POS_OUT_PARITY_ADDR(base)              ((base) + (0x0260))

/* �Ĵ���˵����EPS_GJ_ROTPKУ��ֵ�Ĵ���
   λ����UNION�ṹ:  SOC_KM_ROTPK_GJ_PARITY_UNION */
#define SOC_KM_ROTPK_GJ_PARITY_ADDR(base)             ((base) + (0x0264))

/* �Ĵ���˵����EPS_GM_ROTPKУ��ֵ�Ĵ���
   λ����UNION�ṹ:  SOC_KM_ROTPK_GM_PARITY_UNION */
#define SOC_KM_ROTPK_GM_PARITY_ADDR(base)             ((base) + (0x0268))

/* �Ĵ���˵����DDR������Կ
   λ����UNION�ṹ:  SOC_KM_DDRENC_KEY_UNION */
#define SOC_KM_DDRENC_KEY_ADDR(base, n)               ((base) + (0x026C+(n)*4))

/* �Ĵ���˵�������õ�XTS KEY2
   λ����UNION�ṹ:  SOC_KM_AES_KEY2_UNION */
#define SOC_KM_AES_KEY2_ADDR(base, n)                 ((base) + (0x0280+(n)*4))

/* �Ĵ���˵����XTS KEY2����Կ����Ĵ���
   λ����UNION�ṹ:  SOC_KM_AESKEY2_MASK_VALUE_UNION */
#define SOC_KM_AESKEY2_MASK_VALUE_ADDR(base)          ((base) + (0x02A0))

/* �Ĵ���˵����XTS KEY2����ԿУ��ֵ�Ĵ���
   λ����UNION�ṹ:  SOC_KM_AES_KEY2_PARITY_UNION */
#define SOC_KM_AES_KEY2_PARITY_ADDR(base)             ((base) + (0x02A4))

/* �Ĵ���˵����
   λ����UNION�ṹ:  SOC_KM_DEBUG_SD_UNION */
#define SOC_KM_DEBUG_SD_ADDR(base)                    ((base) + (0x02A8))

/* �Ĵ���˵�����������ɶ�key
   λ����UNION�ṹ:  SOC_KM_DERIVE_KEY_SEC_UNION */
#define SOC_KM_DERIVE_KEY_SEC_ADDR(base, n)           ((base) + (0x02C0+(n)*4))

/* �Ĵ���˵�����������ɶ�key������
   λ����UNION�ṹ:  SOC_KM_DERIVE_KEY_SEC_M_UNION */
#define SOC_KM_DERIVE_KEY_SEC_M_ADDR(base, n)         ((base) + (0x0300+(n)*4))





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
 �ṹ��    : SOC_KM_STR_UNION
 �ṹ˵��  : STR �Ĵ����ṹ���塣��ַƫ����:0x0000����ֵ:0x00000000�����:32
 �Ĵ���˵��: KM STR�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  km_str   : 1;  /* bit[0]   : ��Կ���ܿ�ʼ������־
                                                   1Ϊ��ʼ */
        unsigned int  reserved : 31; /* bit[1-31]:  */
    } reg;
} SOC_KM_STR_UNION;
#endif
#define SOC_KM_STR_km_str_START    (0)
#define SOC_KM_STR_km_str_END      (0)


/*****************************************************************************
 �ṹ��    : SOC_KM_MODE_UNION
 �ṹ˵��  : MODE �Ĵ����ṹ���塣��ַƫ����:0x0004����ֵ:0x00000000�����:32
 �Ĵ���˵��: ��Կ·�ɼĴ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  des_key_sel       : 1;  /* bit[0]    : DES_KEYѡ��
                                                             0:ѡ��CPU���õ�����KEY��Ϊ��Կ
                                                             1:ѡ������������KEY��Ϊ��Կ */
        unsigned int  reserved_0        : 3;  /* bit[1-3]  :  */
        unsigned int  aes_key_sel       : 3;  /* bit[4-6]  : AES_KEYѡ��
                                                             0: ѡ������CEK��Ϊ��Կ
                                                             1: ѡ����ܺ��kdr��Ϊ��Կ������������key
                                                             2: ѡ��GID��������Կ������������key����ֱ�Ӽӽ���
                                                             3: ѡ���߼�KEY��Ϊ��Կ
                                                             4: ѡ��cpu���õ�����key��Ϊ��Կ
                                                             5: ѡ������������key��Ϊ��Կ
                                                             6: ѡ��POS��������Կ������������key����ֱ�Ӽӽ���
                                                             ��������ֵ�Ƿ� */
        unsigned int  reserved_1        : 1;  /* bit[7]    :  */
        unsigned int  sm4_key_sel       : 3;  /* bit[8-10] : SM4_KEYѡ��
                                                             0:ѡ������CEK��Ϊ��Կ
                                                             1:ѡ��cpu���õ�����key��Ϊ��Կ
                                                             2:ѡ������������KEY��Ϊ��Կ
                                                             3:ѡ��GID��������Կ�����������ӽ���
                                                             4:ѡ��POS��������Կ�����������ӽ���
                                                             ��������ֵ�Ƿ� */
        unsigned int  reserved_2        : 1;  /* bit[11]   :  */
        unsigned int  km_mode           : 2;  /* bit[12-13]: ��Կ�����ģʽ
                                                             0: �����ӽ���
                                                             1: ��Կ����
                                                             2: ��Կ����
                                                             3: RTL KEYֱ�Ӽ���
                                                             ��������ֵ�Ƿ� */
        unsigned int  ddrenc_key_derive : 1;  /* bit[14]   : ָʾ��ǰ����Կ�����Ƿ�ΪDDR����KEY������
                                                             0: ��DDR����KEY������
                                                             1: DDR����KEY������ */
        unsigned int  kdr_inv           : 1;  /* bit[15]   : ָʾʹ��kdr����ʱ���Ƿ���Ҫ��kdrȡ����ȡ��ʱ����������ɶ���
                                                             0: ����kdrȡ��
                                                             1: ��kdrȡ�� */
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
 �ṹ��    : SOC_KM_DERIVE_KEY_CLR_UNION
 �ṹ˵��  : DERIVE_KEY_CLR �Ĵ����ṹ���塣��ַƫ����:0x0008����ֵ:0x00000000�����:32
 �Ĵ���˵��: ������Կ�����ź�
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  derive_key_clr     : 1;  /* bit[0]   : ������������Կ���㣨������Կ�ɶ�ʱ��
                                                             ֻҪ���øüĴ����ͻ����� */
        unsigned int  derive_key_sec_clr : 1;  /* bit[1]   : ������������Կ���㣨������Կ���ɶ�ʱ��
                                                             ֻҪ���øüĴ����ͻ����� */
        unsigned int  reserved           : 30; /* bit[2-31]:  */
    } reg;
} SOC_KM_DERIVE_KEY_CLR_UNION;
#endif
#define SOC_KM_DERIVE_KEY_CLR_derive_key_clr_START      (0)
#define SOC_KM_DERIVE_KEY_CLR_derive_key_clr_END        (0)
#define SOC_KM_DERIVE_KEY_CLR_derive_key_sec_clr_START  (1)
#define SOC_KM_DERIVE_KEY_CLR_derive_key_sec_clr_END    (1)


/*****************************************************************************
 �ṹ��    : SOC_KM_KEY_DECRY_DONE_UNION
 �ṹ˵��  : KEY_DECRY_DONE �Ĵ����ṹ���塣��ַƫ����:0x000C����ֵ:0x00000000�����:32
 �Ĵ���˵��: ��Կ������ɱ�־
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  key_decry_done : 1;  /* bit[0]   : ��Կ������ɱ�־
                                                         0:��Կ����δ���
                                                         1:��Կ������� */
        unsigned int  reserved       : 31; /* bit[1-31]:  */
    } reg;
} SOC_KM_KEY_DECRY_DONE_UNION;
#endif
#define SOC_KM_KEY_DECRY_DONE_key_decry_done_START  (0)
#define SOC_KM_KEY_DECRY_DONE_key_decry_done_END    (0)


/*****************************************************************************
 �ṹ��    : SOC_KM_KEY_DERIVE_DONE_UNION
 �ṹ˵��  : KEY_DERIVE_DONE �Ĵ����ṹ���塣��ַƫ����:0x0010����ֵ:0x00000000�����:32
 �Ĵ���˵��: ��Կ������ɱ�־
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  key_derive_done : 1;  /* bit[0]   : ��Կ������ɱ�־
                                                          0:��Կ����δ���
                                                          1:��Կ������� */
        unsigned int  reserved        : 31; /* bit[1-31]:  */
    } reg;
} SOC_KM_KEY_DERIVE_DONE_UNION;
#endif
#define SOC_KM_KEY_DERIVE_DONE_key_derive_done_START  (0)
#define SOC_KM_KEY_DERIVE_DONE_key_derive_done_END    (0)


/*****************************************************************************
 �ṹ��    : SOC_KM_KEY_DERIVE_DONE_CLR_UNION
 �ṹ˵��  : KEY_DERIVE_DONE_CLR �Ĵ����ṹ���塣��ַƫ����:0x0014����ֵ:0x00000000�����:32
 �Ĵ���˵��: ��Կ��������ź�����
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  key_derive_done_clr : 1;  /* bit[0]   : ������������Կ����źŽ�������
                                                              ֻҪ���øüĴ����ͻ����� */
        unsigned int  reserved            : 31; /* bit[1-31]:  */
    } reg;
} SOC_KM_KEY_DERIVE_DONE_CLR_UNION;
#endif
#define SOC_KM_KEY_DERIVE_DONE_CLR_key_derive_done_clr_START  (0)
#define SOC_KM_KEY_DERIVE_DONE_CLR_key_derive_done_clr_END    (0)


/*****************************************************************************
 �ṹ��    : SOC_KM_DFX_UNION
 �ṹ˵��  : DFX �Ĵ����ṹ���塣��ַƫ����:0x0018����ֵ:0x00000001�����:32
 �Ĵ���˵��: KM�Ĳ����ź�
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  key_decry_state : 16; /* bit[0-15] : ��Կ���ܵ�״̬�������ĸ�״̬�����ڵ��Զ�λ����
                                                           0x0001:KEY_DECRY_IDLE
                                                           0x0002:KEY_DECRY_STR
                                                           0x0004:KDR_RD
                                                           0x0080:KEY_DECRY
                                                           0x0100:DECRY_STORE
                                                           0x0200:DECRY_ALARM */
        unsigned int  keyid_cnt       : 1;  /* bit[16]   : �̶�Ϊ0 */
        unsigned int  reserved_0      : 3;  /* bit[17-19]:  */
        unsigned int  key_lenth_cnt   : 2;  /* bit[20-21]: key_lenth_cnt�����ڵ��Զ�λ */
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
 �ṹ��    : SOC_KM_REG_LOCK_UNION
 �ṹ˵��  : REG_LOCK �Ĵ����ṹ���塣��ַƫ����:0x001C����ֵ:0x00000005�����:32
 �Ĵ���˵��: KM�Ĵ��������ź�
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  km_reg_lock : 4;  /* bit[0-3] : �Ĵ����Ķ�д������Ĭ��Ϊ0x5
                                                      0x5���������κμĴ���������д
                                                      0xa��δ�������Ĵ�����д
                                                      ����ֵ�Ƿ� */
        unsigned int  reserved    : 28; /* bit[4-31]:  */
    } reg;
} SOC_KM_REG_LOCK_UNION;
#endif
#define SOC_KM_REG_LOCK_km_reg_lock_START  (0)
#define SOC_KM_REG_LOCK_km_reg_lock_END    (3)


/*****************************************************************************
 �ṹ��    : SOC_KM_AES_KEY_UNION
 �ṹ˵��  : AES_KEY �Ĵ����ṹ���塣��ַƫ����:0x0020+(n)*4����ֵ:0x00000000�����:32
 �Ĵ���˵��: CPU���õ�AES KEY
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  aes_key : 32; /* bit[0-31]: n=0ʱ����Ӧkey�ĸ�32λ,n�ķ�Χ0-7������keyΪС�˷�ʽ������ģʽ�ɶ� */
    } reg;
} SOC_KM_AES_KEY_UNION;
#endif
#define SOC_KM_AES_KEY_aes_key_START  (0)
#define SOC_KM_AES_KEY_aes_key_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_KM_DES_KEY_UNION
 �ṹ˵��  : DES_KEY �Ĵ����ṹ���塣��ַƫ����:0x0040+(n)*4����ֵ:0x00000000�����:32
 �Ĵ���˵��: CPU���õ�DES KEY
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  aes_key : 32; /* bit[0-31]: n=0,2,4ʱ����Ӧdes_key_x�ĸ�32λ,n�ķ�Χ0-5������keyΪС�˷�ʽ
                                                  n=0,1,��Ӧdes_key1
                                                  n=2,3,��Ӧdes_key2
                                                  n=4,5,��Ӧdes_key3
                                                  ������ģʽ�ɶ� */
    } reg;
} SOC_KM_DES_KEY_UNION;
#endif
#define SOC_KM_DES_KEY_aes_key_START  (0)
#define SOC_KM_DES_KEY_aes_key_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_KM_SM4_KEY_UNION
 �ṹ˵��  : SM4_KEY �Ĵ����ṹ���塣��ַƫ����:0x0060+(n)*4����ֵ:0x00000000�����:32
 �Ĵ���˵��: CPU���õ�SM4 KEY
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  aes_key : 32; /* bit[0-31]: n=0ʱ����Ӧkey�ĸ�32λ,n�ķ�Χ0-3������keyΪС�˷�ʽ������ģʽ�ɶ� */
    } reg;
} SOC_KM_SM4_KEY_UNION;
#endif
#define SOC_KM_SM4_KEY_aes_key_START  (0)
#define SOC_KM_SM4_KEY_aes_key_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_KM_KDR_IN_UNION
 �ṹ˵��  : KDR_IN �Ĵ����ṹ���塣��ַƫ����:0x0080+(n)*4����ֵ:0x00000000�����:32
 �Ĵ���˵��: ����ǰ��kdr
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  kdr_in : 32; /* bit[0-31]: n=0ʱ����Ӧkey�ĸ�32λ,n�ķ�Χ0-7,����ǰ��kdr������keyΪС�˷�ʽ */
    } reg;
} SOC_KM_KDR_IN_UNION;
#endif
#define SOC_KM_KDR_IN_kdr_in_START  (0)
#define SOC_KM_KDR_IN_kdr_in_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_KM_KDR_OUT_UNION
 �ṹ˵��  : KDR_OUT �Ĵ����ṹ���塣��ַƫ����:0x00A0+(n)*4����ֵ:0x00000000�����:32
 �Ĵ���˵��: ���ܺ��kdr
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  kdr_out : 32; /* bit[0-31]: n=0ʱ����Ӧkey�ĸ�32λ,n�ķ�Χ0-7,����kdr��Կ���ܺ�����ֵ������keyΪС�˷�ʽ */
    } reg;
} SOC_KM_KDR_OUT_UNION;
#endif
#define SOC_KM_KDR_OUT_kdr_out_START  (0)
#define SOC_KM_KDR_OUT_kdr_out_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_KM_CEK_IN_UNION
 �ṹ˵��  : CEK_IN �Ĵ����ṹ���塣��ַƫ����:0x00C0+(n)*4����ֵ:0x00000000�����:32
 �Ĵ���˵��: ���ĵ�cek
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  cek_in : 32; /* bit[0-31]: n=0ʱ����Ӧkey�ĸ�32λ,n�ķ�Χ0-3,����keyΪС�˷�ʽ��������ģʽ�ɶ� */
    } reg;
} SOC_KM_CEK_IN_UNION;
#endif
#define SOC_KM_CEK_IN_cek_in_START  (0)
#define SOC_KM_CEK_IN_cek_in_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_KM_DERIVE_KEY_UNION
 �ṹ˵��  : DERIVE_KEY �Ĵ����ṹ���塣��ַƫ����:0x0120+(n)*4����ֵ:0x00000000�����:32
 �Ĵ���˵��: ����KEY
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  derive_key : 32; /* bit[0-31]: n=0ʱ����Ӧkey�ĸ�32λ,n�ķ�Χ0-3������keyΪС�˷�ʽ�� */
    } reg;
} SOC_KM_DERIVE_KEY_UNION;
#endif
#define SOC_KM_DERIVE_KEY_derive_key_START  (0)
#define SOC_KM_DERIVE_KEY_derive_key_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_KM_GID_IN_UNION
 �ṹ˵��  : GID_IN �Ĵ����ṹ���塣��ַƫ����:0x0140+(n)*4����ֵ:0x00000000�����:32
 �Ĵ���˵��: ����ǰ��gid
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  gid_in : 32; /* bit[0-31]: n=0ʱ����Ӧkey�ĸ�32λ,n�ķ�Χ0-3,����ǰ��gid������keyΪС�˷�ʽ */
    } reg;
} SOC_KM_GID_IN_UNION;
#endif
#define SOC_KM_GID_IN_gid_in_START  (0)
#define SOC_KM_GID_IN_gid_in_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_KM_GID_OUT_UNION
 �ṹ˵��  : GID_OUT �Ĵ����ṹ���塣��ַƫ����:0x0160+(n)*4����ֵ:0x00000000�����:32
 �Ĵ���˵��: ���ܺ��gid
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  gid_out : 32; /* bit[0-31]: n=0ʱ����Ӧkey�ĸ�32λ,n�ķ�Χ0-3,����gid��Կ���ܺ�����ֵ������keyΪС�˷�ʽ */
    } reg;
} SOC_KM_GID_OUT_UNION;
#endif
#define SOC_KM_GID_OUT_gid_out_START  (0)
#define SOC_KM_GID_OUT_gid_out_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_KM_POS_IN_UNION
 �ṹ˵��  : POS_IN �Ĵ����ṹ���塣��ַƫ����:0x0180+(n)*4����ֵ:0x00000000�����:32
 �Ĵ���˵��: ����ǰ��pos
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  pos_in : 32; /* bit[0-31]: n=0ʱ����Ӧkey�ĸ�32λ,n�ķ�Χ0-3,����ǰ��pos������keyΪС�˷�ʽ */
    } reg;
} SOC_KM_POS_IN_UNION;
#endif
#define SOC_KM_POS_IN_pos_in_START  (0)
#define SOC_KM_POS_IN_pos_in_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_KM_POS_OUT_UNION
 �ṹ˵��  : POS_OUT �Ĵ����ṹ���塣��ַƫ����:0x01A0+(n)*4����ֵ:0x00000000�����:32
 �Ĵ���˵��: ���ܺ��pos
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  pos_out : 32; /* bit[0-31]: n=0ʱ����Ӧkey�ĸ�32λ,n�ķ�Χ0-3,����pos��Կ���ܺ�����ֵ������keyΪС�˷�ʽ */
    } reg;
} SOC_KM_POS_OUT_UNION;
#endif
#define SOC_KM_POS_OUT_pos_out_START  (0)
#define SOC_KM_POS_OUT_pos_out_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_KM_ROTPK_GJ_UNION
 �ṹ˵��  : ROTPK_GJ �Ĵ����ṹ���塣��ַƫ����:0x01C0+(n)*4����ֵ:0x00000000�����:32
 �Ĵ���˵��: EPS_GJ_ROTPK������
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  rotpk_gj_out : 32; /* bit[0-31]: n=0ʱ����Ӧkey�ĸ�32λ,n�ķ�Χ0-7,EPS_GJ_ROTPK�����ֵ������keyΪС�˷�ʽ */
    } reg;
} SOC_KM_ROTPK_GJ_UNION;
#endif
#define SOC_KM_ROTPK_GJ_rotpk_gj_out_START  (0)
#define SOC_KM_ROTPK_GJ_rotpk_gj_out_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_KM_ROTPK_GM_UNION
 �ṹ˵��  : ROTPK_GM �Ĵ����ṹ���塣��ַƫ����:0x01E0+(n)*4����ֵ:0x00000000�����:32
 �Ĵ���˵��: EPS_GM_ROTPK������
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  rotpk_gm_out : 32; /* bit[0-31]: n=0ʱ����Ӧkey�ĸ�32λ,n�ķ�Χ0-7,EPS_GM_ROTPK�����ֵ������keyΪС�˷�ʽ */
    } reg;
} SOC_KM_ROTPK_GM_UNION;
#endif
#define SOC_KM_ROTPK_GM_rotpk_gm_out_START  (0)
#define SOC_KM_ROTPK_GM_rotpk_gm_out_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_KM_ALARM_CLR_UNION
 �ṹ˵��  : ALARM_CLR �Ĵ����ṹ���塣��ַƫ����:0x0200����ֵ:0x0000AAAA�����:32
 �Ĵ���˵��: �澯�����ź�
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  alarm_critical_clr   : 4;  /* bit[0-3]  : ��km����ģ�������alarm�ź�����
                                                                4'h5:�Ը澯�ź�����
                                                                4'ha:���Ը澯�ź�����
                                                                ����ֵ�Ƿ� */
        unsigned int  alarm_reg_check_clr  : 4;  /* bit[4-7]  : �ԼĴ����Ϸ��Լ�������alarm�ź�����
                                                                4'h5:�Ը澯�ź�����
                                                                4'ha:���Ը澯�ź�����
                                                                ����ֵ�Ƿ� */
        unsigned int  alarm_reg_access_clr : 4;  /* bit[8-11] : ��LOCK���д�Ĵ���������alarm�ź��ź�����
                                                                4'h5:�Ը澯�ź�����
                                                                4'ha:���Ը澯�ź�����
                                                                ����ֵ�Ƿ� */
        unsigned int  alarm_key_check_clr  : 4;  /* bit[12-15]: ��KEY ��������alarm�ź��ź�����
                                                                4'h5:�Ը澯�ź�����
                                                                4'ha:���Ը澯�ź�����
                                                                ����ֵ�Ƿ� */
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
 �ṹ��    : SOC_KM_ALARM_MASK_EN_UNION
 �ṹ˵��  : ALARM_MASK_EN �Ĵ����ṹ���塣��ַƫ����:0x0204����ֵ:0x00005555�����:32
 �Ĵ���˵��: �澯�����ź�
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  alarm_critical_mask_en   : 4;  /* bit[0-3]  : ��km����ģ�������alarm�ź�����,Ĭ������
                                                                    4'h5:�Ը澯�ź�����
                                                                    4'ha:���Ը澯�źŲ�����,
                                                                    ����ֵ�Ƿ� */
        unsigned int  alarm_reg_check_mask_en  : 4;  /* bit[4-7]  : �ԼĴ����Ϸ��Լ�������alarm�ź�����,Ĭ������
                                                                    4'h5:�Ը澯�ź�����
                                                                    4'ha:���Ը澯�źŲ�����,
                                                                    ����ֵ�Ƿ� */
        unsigned int  alarm_reg_access_mask_en : 4;  /* bit[8-11] : ��LOCK���д�Ĵ���������alarm�ź��ź����Σ�Ĭ������
                                                                    4'h5:�Ը澯�ź�����
                                                                    4'ha:���Ը澯�źŲ�����,
                                                                    ����ֵ�Ƿ� */
        unsigned int  alarm_key_check_mask_en  : 4;  /* bit[12-15]: KEY��������alarm�ź��ź����Σ�Ĭ������
                                                                    4'h5:�Ը澯�ź�����
                                                                    4'ha:���Ը澯�źŲ�����,
                                                                    ����ֵ�Ƿ� */
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
 �ṹ��    : SOC_KM_ALARM_UNION
 �ṹ˵��  : ALARM �Ĵ����ṹ���塣��ַƫ����:0x0208����ֵ:0x00000000�����:32
 �Ĵ���˵��: alarm�źţ�����ǰ��
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  alarm_critical   : 1;  /* bit[0]   : km����ģ�������alarm�ź�
                                                           1:��ʾ��alarm
                                                           0:û��alarm */
        unsigned int  alarm_reg_check  : 1;  /* bit[1]   : �Ĵ����Ϸ��Լ�������alarm�ź�
                                                           1:��ʾ��alarm
                                                           0:û��alarm */
        unsigned int  alarm_reg_access : 1;  /* bit[2]   : LOCK���д�Ĵ���������alarm�ź�
                                                           1:��ʾ��alarm
                                                           0:û��alarm */
        unsigned int  alarm_key_check  : 1;  /* bit[3]   : KEY��������alarm�ź�
                                                           1:��ʾ��alarm
                                                           0:û��alarm */
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
 �ṹ��    : SOC_KM_ALARM_MASK_UNION
 �ṹ˵��  : ALARM_MASK �Ĵ����ṹ���塣��ַƫ����:0x020C����ֵ:0x00000000�����:32
 �Ĵ���˵��: alarm�źţ����κ�
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  alarm_critical_mask   : 1;  /* bit[0]   : km����ģ�������alarm�ź�
                                                                1:��ʾ��alarm
                                                                0:û��alarm */
        unsigned int  alarm_reg_check_mask  : 1;  /* bit[1]   : �Ĵ����Ϸ��Լ�������alarm�ź�
                                                                1:��ʾ��alarm
                                                                0:û��alarm */
        unsigned int  alarm_reg_access_mask : 1;  /* bit[2]   : LOCK���д�Ĵ���������alarm�ź�
                                                                1:��ʾ��alarm
                                                                0:û��alarm */
        unsigned int  alarm_key_check       : 1;  /* bit[3]   : KEY��������alarm�ź�
                                                                1:��ʾ��alarm
                                                                0:û��alarm */
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
 �ṹ��    : SOC_KM_KEY_REG_LOCK_UNION
 �ṹ˵��  : KEY_REG_LOCK �Ĵ����ṹ���塣��ַƫ����:0x0210����ֵ:0x00000005�����:32
 �Ĵ���˵��: ��Կ�����Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  key_lock : 4;  /* bit[0-3] : key�Ĵ����Ķ�д������Ĭ��Ϊ0x5
                                                   0x5���������κ�key�Ĵ��������ɶ�д
                                                   0xa��δ������key�Ĵ����ɶ�д
                                                   ����ֵ�Ƿ� */
        unsigned int  reserved : 28; /* bit[4-31]:  */
    } reg;
} SOC_KM_KEY_REG_LOCK_UNION;
#endif
#define SOC_KM_KEY_REG_LOCK_key_lock_START  (0)
#define SOC_KM_KEY_REG_LOCK_key_lock_END    (3)


/*****************************************************************************
 �ṹ��    : SOC_KM_AESKEY_MASK_VALUE_UNION
 �ṹ˵��  : AESKEY_MASK_VALUE �Ĵ����ṹ���塣��ַƫ����:0x0214����ֵ:0x00000000�����:32
 �Ĵ���˵��: AES��Կ����Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  aeskey_mask_value : 32; /* bit[0-31]: key������ֵ */
    } reg;
} SOC_KM_AESKEY_MASK_VALUE_UNION;
#endif
#define SOC_KM_AESKEY_MASK_VALUE_aeskey_mask_value_START  (0)
#define SOC_KM_AESKEY_MASK_VALUE_aeskey_mask_value_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_KM_DESKEY_MASK_VALUE_UNION
 �ṹ˵��  : DESKEY_MASK_VALUE �Ĵ����ṹ���塣��ַƫ����:0x0218����ֵ:0x00000000�����:32
 �Ĵ���˵��: DES��Կ����Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  deskey_mask_value : 32; /* bit[0-31]: key������ֵ */
    } reg;
} SOC_KM_DESKEY_MASK_VALUE_UNION;
#endif
#define SOC_KM_DESKEY_MASK_VALUE_deskey_mask_value_START  (0)
#define SOC_KM_DESKEY_MASK_VALUE_deskey_mask_value_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_KM_SM4KEY_MASK_VALUE_UNION
 �ṹ˵��  : SM4KEY_MASK_VALUE �Ĵ����ṹ���塣��ַƫ����:0x021C����ֵ:0x00000000�����:32
 �Ĵ���˵��: SM4��Կ����Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sm4key_mask_value : 32; /* bit[0-31]: key������ֵ */
    } reg;
} SOC_KM_SM4KEY_MASK_VALUE_UNION;
#endif
#define SOC_KM_SM4KEY_MASK_VALUE_sm4key_mask_value_START  (0)
#define SOC_KM_SM4KEY_MASK_VALUE_sm4key_mask_value_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_KM_AES_KEY_PARITY_UNION
 �ṹ˵��  : AES_KEY_PARITY �Ĵ����ṹ���塣��ַƫ����:0x0220����ֵ:0x00000000�����:32
 �Ĵ���˵��: AES��ԿУ��ֵ�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  aes_key_parity : 32; /* bit[0-31]: AES��ԿУ��ֵ�Ĵ��� */
    } reg;
} SOC_KM_AES_KEY_PARITY_UNION;
#endif
#define SOC_KM_AES_KEY_PARITY_aes_key_parity_START  (0)
#define SOC_KM_AES_KEY_PARITY_aes_key_parity_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_KM_DES_KEY_PARITY_UNION
 �ṹ˵��  : DES_KEY_PARITY �Ĵ����ṹ���塣��ַƫ����:0x0224����ֵ:0x00000000�����:32
 �Ĵ���˵��: DES��ԿУ��ֵ�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  des_key_parity : 32; /* bit[0-31]: DES��ԿУ��ֵ�Ĵ��� */
    } reg;
} SOC_KM_DES_KEY_PARITY_UNION;
#endif
#define SOC_KM_DES_KEY_PARITY_des_key_parity_START  (0)
#define SOC_KM_DES_KEY_PARITY_des_key_parity_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_KM_SM4_KEY_PARITY_UNION
 �ṹ˵��  : SM4_KEY_PARITY �Ĵ����ṹ���塣��ַƫ����:0x0228����ֵ:0x00000000�����:32
 �Ĵ���˵��: SM4��ԿУ��ֵ�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sm4_key_parity : 32; /* bit[0-31]: SM4��ԿУ��ֵ�Ĵ��� */
    } reg;
} SOC_KM_SM4_KEY_PARITY_UNION;
#endif
#define SOC_KM_SM4_KEY_PARITY_sm4_key_parity_START  (0)
#define SOC_KM_SM4_KEY_PARITY_sm4_key_parity_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_KM_KDR_IN_PARITY_UNION
 �ṹ˵��  : KDR_IN_PARITY �Ĵ����ṹ���塣��ַƫ����:0x022C����ֵ:0x00000000�����:32
 �Ĵ���˵��: ����KDR��ԿУ��ֵ�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  kdr_in_parity : 32; /* bit[0-31]: ����KDR��ԿУ��ֵ�Ĵ��� */
    } reg;
} SOC_KM_KDR_IN_PARITY_UNION;
#endif
#define SOC_KM_KDR_IN_PARITY_kdr_in_parity_START  (0)
#define SOC_KM_KDR_IN_PARITY_kdr_in_parity_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_KM_KDR_OUT_PARITY_UNION
 �ṹ˵��  : KDR_OUT_PARITY �Ĵ����ṹ���塣��ַƫ����:0x0230����ֵ:0x00000000�����:32
 �Ĵ���˵��: ����KDR��ԿУ��ֵ�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  kdr_out_parity : 32; /* bit[0-31]: ����KDR��ԿУ��ֵ�Ĵ��� */
    } reg;
} SOC_KM_KDR_OUT_PARITY_UNION;
#endif
#define SOC_KM_KDR_OUT_PARITY_kdr_out_parity_START  (0)
#define SOC_KM_KDR_OUT_PARITY_kdr_out_parity_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_KM_CEK_IN_PARITY_UNION
 �ṹ˵��  : CEK_IN_PARITY �Ĵ����ṹ���塣��ַƫ����:0x0234����ֵ:0x00000000�����:32
 �Ĵ���˵��: ����CEK��ԿУ��ֵ�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  cek_in_parity : 32; /* bit[0-31]: ����CEK��ԿУ��ֵ�Ĵ��� */
    } reg;
} SOC_KM_CEK_IN_PARITY_UNION;
#endif
#define SOC_KM_CEK_IN_PARITY_cek_in_parity_START  (0)
#define SOC_KM_CEK_IN_PARITY_cek_in_parity_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_KM_DERIVE_KEY_PARITY_UNION
 �ṹ˵��  : DERIVE_KEY_PARITY �Ĵ����ṹ���塣��ַƫ����:0x0238����ֵ:0x00000000�����:32
 �Ĵ���˵��: ����KEY��ԿУ��ֵ�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  derive_key_parity : 32; /* bit[0-31]: ����������key����ԿУ��ֵ�Ĵ��� */
    } reg;
} SOC_KM_DERIVE_KEY_PARITY_UNION;
#endif
#define SOC_KM_DERIVE_KEY_PARITY_derive_key_parity_START  (0)
#define SOC_KM_DERIVE_KEY_PARITY_derive_key_parity_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_KM_CEK_MASK_VALUE_UNION
 �ṹ˵��  : CEK_MASK_VALUE �Ĵ����ṹ���塣��ַƫ����:0x0248����ֵ:0x00000000�����:32
 �Ĵ���˵��: CEK��Կ����Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  cek_mask_value : 32; /* bit[0-31]: ���õ�cek������ֵ */
    } reg;
} SOC_KM_CEK_MASK_VALUE_UNION;
#endif
#define SOC_KM_CEK_MASK_VALUE_cek_mask_value_START  (0)
#define SOC_KM_CEK_MASK_VALUE_cek_mask_value_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_KM_KEY_MASK_VALUE_UNION
 �ṹ˵��  : KEY_MASK_VALUE �Ĵ����ṹ���塣��ַƫ����:0x024C����ֵ:0x00000000�����:32
 �Ĵ���˵��: ��Կ����Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  key_mask_value : 32; /* bit[0-31]: �ϱ���key������ֵ */
    } reg;
} SOC_KM_KEY_MASK_VALUE_UNION;
#endif
#define SOC_KM_KEY_MASK_VALUE_key_mask_value_START  (0)
#define SOC_KM_KEY_MASK_VALUE_key_mask_value_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_KM_GID_IN_PARITY_UNION
 �ṹ˵��  : GID_IN_PARITY �Ĵ����ṹ���塣��ַƫ����:0x0254����ֵ:0x00000000�����:32
 �Ĵ���˵��: ����GID��ԿУ��ֵ�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  gid_in_parity : 32; /* bit[0-31]: ����GID��ԿУ��ֵ�Ĵ��� */
    } reg;
} SOC_KM_GID_IN_PARITY_UNION;
#endif
#define SOC_KM_GID_IN_PARITY_gid_in_parity_START  (0)
#define SOC_KM_GID_IN_PARITY_gid_in_parity_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_KM_GID_OUT_PARITY_UNION
 �ṹ˵��  : GID_OUT_PARITY �Ĵ����ṹ���塣��ַƫ����:0x0258����ֵ:0x00000000�����:32
 �Ĵ���˵��: ����GID��ԿУ��ֵ�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  gid_out_parity : 32; /* bit[0-31]: ����GID��ԿУ��ֵ�Ĵ��� */
    } reg;
} SOC_KM_GID_OUT_PARITY_UNION;
#endif
#define SOC_KM_GID_OUT_PARITY_gid_out_parity_START  (0)
#define SOC_KM_GID_OUT_PARITY_gid_out_parity_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_KM_POS_IN_PARITY_UNION
 �ṹ˵��  : POS_IN_PARITY �Ĵ����ṹ���塣��ַƫ����:0x025C����ֵ:0x00000000�����:32
 �Ĵ���˵��: ����POS��ԿУ��ֵ�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  pos_in_parity : 32; /* bit[0-31]: ����POS��ԿУ��ֵ�Ĵ��� */
    } reg;
} SOC_KM_POS_IN_PARITY_UNION;
#endif
#define SOC_KM_POS_IN_PARITY_pos_in_parity_START  (0)
#define SOC_KM_POS_IN_PARITY_pos_in_parity_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_KM_POS_OUT_PARITY_UNION
 �ṹ˵��  : POS_OUT_PARITY �Ĵ����ṹ���塣��ַƫ����:0x0260����ֵ:0x00000000�����:32
 �Ĵ���˵��: ����POS��ԿУ��ֵ�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  pos_out_parity : 32; /* bit[0-31]: ����POS��ԿУ��ֵ�Ĵ��� */
    } reg;
} SOC_KM_POS_OUT_PARITY_UNION;
#endif
#define SOC_KM_POS_OUT_PARITY_pos_out_parity_START  (0)
#define SOC_KM_POS_OUT_PARITY_pos_out_parity_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_KM_ROTPK_GJ_PARITY_UNION
 �ṹ˵��  : ROTPK_GJ_PARITY �Ĵ����ṹ���塣��ַƫ����:0x0264����ֵ:0x00000000�����:32
 �Ĵ���˵��: EPS_GJ_ROTPKУ��ֵ�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  rotpk_gj_parity : 32; /* bit[0-31]: EPS_GJ_ROTPKУ��ֵ�Ĵ��� */
    } reg;
} SOC_KM_ROTPK_GJ_PARITY_UNION;
#endif
#define SOC_KM_ROTPK_GJ_PARITY_rotpk_gj_parity_START  (0)
#define SOC_KM_ROTPK_GJ_PARITY_rotpk_gj_parity_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_KM_ROTPK_GM_PARITY_UNION
 �ṹ˵��  : ROTPK_GM_PARITY �Ĵ����ṹ���塣��ַƫ����:0x0268����ֵ:0x00000000�����:32
 �Ĵ���˵��: EPS_GM_ROTPKУ��ֵ�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  rotpk_gm_parity : 32; /* bit[0-31]: EPS_GM_ROTPKУ��ֵ�Ĵ��� */
    } reg;
} SOC_KM_ROTPK_GM_PARITY_UNION;
#endif
#define SOC_KM_ROTPK_GM_PARITY_rotpk_gm_parity_START  (0)
#define SOC_KM_ROTPK_GM_PARITY_rotpk_gm_parity_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_KM_DDRENC_KEY_UNION
 �ṹ˵��  : DDRENC_KEY �Ĵ����ṹ���塣��ַƫ����:0x026C+(n)*4����ֵ:0x00000000�����:32
 �Ĵ���˵��: DDR������Կ
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ddrenc_key : 32; /* bit[0-31]: n=0ʱ����Ӧkey�ĸ�32λ,n�ķ�Χ0-3,DDR����ʹ�õ���Կ������keyΪС�˷�ʽ */
    } reg;
} SOC_KM_DDRENC_KEY_UNION;
#endif
#define SOC_KM_DDRENC_KEY_ddrenc_key_START  (0)
#define SOC_KM_DDRENC_KEY_ddrenc_key_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_KM_AES_KEY2_UNION
 �ṹ˵��  : AES_KEY2 �Ĵ����ṹ���塣��ַƫ����:0x0280+(n)*4����ֵ:0x0000�����:32
 �Ĵ���˵��: ���õ�XTS KEY2
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  aes_key2 : 32; /* bit[0-31]: n=0ʱ����Ӧkey�ĸ�32λ,n�ķ�Χ0-7������keyΪС�˷�ʽ������ģʽ�ɶ� */
    } reg;
} SOC_KM_AES_KEY2_UNION;
#endif
#define SOC_KM_AES_KEY2_aes_key2_START  (0)
#define SOC_KM_AES_KEY2_aes_key2_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_KM_AESKEY2_MASK_VALUE_UNION
 �ṹ˵��  : AESKEY2_MASK_VALUE �Ĵ����ṹ���塣��ַƫ����:0x02A0����ֵ:0x0000�����:32
 �Ĵ���˵��: XTS KEY2����Կ����Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  aes_key2_mask_value : 32; /* bit[0-31]: XTS KEY2����Կ����Ĵ��� */
    } reg;
} SOC_KM_AESKEY2_MASK_VALUE_UNION;
#endif
#define SOC_KM_AESKEY2_MASK_VALUE_aes_key2_mask_value_START  (0)
#define SOC_KM_AESKEY2_MASK_VALUE_aes_key2_mask_value_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_KM_AES_KEY2_PARITY_UNION
 �ṹ˵��  : AES_KEY2_PARITY �Ĵ����ṹ���塣��ַƫ����:0x02A4����ֵ:0x0000�����:32
 �Ĵ���˵��: XTS KEY2����ԿУ��ֵ�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  aes_key2_parity : 32; /* bit[0-31]: XTS KEY2����ԿУ��ֵ�Ĵ��� */
    } reg;
} SOC_KM_AES_KEY2_PARITY_UNION;
#endif
#define SOC_KM_AES_KEY2_PARITY_aes_key2_parity_START  (0)
#define SOC_KM_AES_KEY2_PARITY_aes_key2_parity_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_KM_DEBUG_SD_UNION
 �ṹ˵��  : DEBUG_SD �Ĵ����ṹ���塣��ַƫ����:0x02A8����ֵ:0x00000000�����:32
 �Ĵ���˵��: 
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  DEBUG_SD : 1;  /* bit[0]   : ��ʱSD״̬��ѯ�Ĵ�����
                                                   0����SD
                                                   1��SD */
        unsigned int  reserved : 31; /* bit[1-31]:  */
    } reg;
} SOC_KM_DEBUG_SD_UNION;
#endif
#define SOC_KM_DEBUG_SD_DEBUG_SD_START  (0)
#define SOC_KM_DEBUG_SD_DEBUG_SD_END    (0)


/*****************************************************************************
 �ṹ��    : SOC_KM_DERIVE_KEY_SEC_UNION
 �ṹ˵��  : DERIVE_KEY_SEC �Ĵ����ṹ���塣��ַƫ����:0x02C0+(n)*4����ֵ:0x0000�����:32
 �Ĵ���˵��: �������ɶ�key
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  derive_key_sec : 32; /* bit[0-31]: n=0ʱ����Ӧkey�ĸ�32λ,n�ķ�Χ0-15������keyΪС�˷�ʽ�� */
    } reg;
} SOC_KM_DERIVE_KEY_SEC_UNION;
#endif
#define SOC_KM_DERIVE_KEY_SEC_derive_key_sec_START  (0)
#define SOC_KM_DERIVE_KEY_SEC_derive_key_sec_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_KM_DERIVE_KEY_SEC_M_UNION
 �ṹ˵��  : DERIVE_KEY_SEC_M �Ĵ����ṹ���塣��ַƫ����:0x0300+(n)*4����ֵ:0x0000�����:32
 �Ĵ���˵��: �������ɶ�key������
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  derive_key_sec_m : 32; /* bit[0-31]: n=0ʱ����Ӧkey�ĸ�32λ,n�ķ�Χ0-15������keyΪС�˷�ʽ�� */
    } reg;
} SOC_KM_DERIVE_KEY_SEC_M_UNION;
#endif
#define SOC_KM_DERIVE_KEY_SEC_M_derive_key_sec_m_START  (0)
#define SOC_KM_DERIVE_KEY_SEC_M_derive_key_sec_m_END    (31)






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

#endif /* end of soc_km_interface.h */
