/******************************************************************************

                 ��Ȩ���� (C), 2001-2019, ��Ϊ�������޹�˾

 ******************************************************************************
  �� �� ��   : soc_config_interface.h
  �� �� ��   : ����
  ��    ��   : Excel2Code
  ��������   : 2019-10-26 11:03:14
  ����޸�   :
  ��������   : �ӿ�ͷ�ļ�
  �����б�   :
  �޸���ʷ   :
  1.��    ��   : 2019��10��26��
    ��    ��   : l00249396
    �޸�����   : �ӡ�HiEPS V210 �Ĵ����ֲ�_CONFIG.xml���Զ�����

******************************************************************************/

/*****************************************************************************
  1 ����ͷ�ļ�����
*****************************************************************************/

#ifndef __SOC_CONFIG_INTERFACE_H__
#define __SOC_CONFIG_INTERFACE_H__

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
/* �Ĵ���˵����DDRENC���ƼĴ���
   λ����UNION�ṹ:  SOC_CONFIG_DDRENC_CTRL_UNION */
#define SOC_CONFIG_DDRENC_CTRL_ADDR(base)             ((base) + (0x00))

/* �Ĵ���˵�����Ĵ�efuse����ؿ�����Ϣ
   λ����UNION�ṹ:  SOC_CONFIG_EFUSEC2HIEPS_CTRL_UNION */
#define SOC_CONFIG_EFUSEC2HIEPS_CTRL_ADDR(base)       ((base) + (0x04))

/* �Ĵ���˵����
   λ����UNION�ṹ:  SOC_CONFIG_REG_RESERVED1_UNION */
#define SOC_CONFIG_REG_RESERVED1_ADDR(base)           ((base) + (0x08))

/* �Ĵ���˵����
   λ����UNION�ṹ:  SOC_CONFIG_REG_RESERVED2_UNION */
#define SOC_CONFIG_REG_RESERVED2_ADDR(base)           ((base) + (0x0C))

/* �Ĵ���˵����
   λ����UNION�ṹ:  SOC_CONFIG_REG_RESERVED3_UNION */
#define SOC_CONFIG_REG_RESERVED3_ADDR(base)           ((base) + (0x10))

/* �Ĵ���˵����QIC ����źŵĿ��ƼĴ�����
   λ����UNION�ṹ:  SOC_CONFIG_QIC_CTRL_UNION */
#define SOC_CONFIG_QIC_CTRL_ADDR(base)                ((base) + (0x14))

/* �Ĵ���˵����
   λ����UNION�ṹ:  SOC_CONFIG_REG_RESERVED4_UNION */
#define SOC_CONFIG_REG_RESERVED4_ADDR(base)           ((base) + (0x18))

/* �Ĵ���˵����
   λ����UNION�ṹ:  SOC_CONFIG_REG_RESERVED5_UNION */
#define SOC_CONFIG_REG_RESERVED5_ADDR(base)           ((base) + (0x1C))

/* �Ĵ���˵����
   λ����UNION�ṹ:  SOC_CONFIG_REG_RESERVED6_UNION */
#define SOC_CONFIG_REG_RESERVED6_ADDR(base)           ((base) + (0x20))

/* �Ĵ���˵��������ת��ƽ���ж�����Ĵ���
   λ����UNION�ṹ:  SOC_CONFIG_ALARM_CLR_UNION */
#define SOC_CONFIG_ALARM_CLR_ADDR(base)               ((base) + (0x24))

/* �Ĵ���˵����
   λ����UNION�ṹ:  SOC_CONFIG_REG_RESERVED7_UNION */
#define SOC_CONFIG_REG_RESERVED7_ADDR(base)           ((base) + (0x28))

/* �Ĵ���˵����
   λ����UNION�ṹ:  SOC_CONFIG_REG_RESERVED8_UNION */
#define SOC_CONFIG_REG_RESERVED8_ADDR(base)           ((base) + (0x2C))

/* �Ĵ���˵����
   λ����UNION�ṹ:  SOC_CONFIG_REG_RESERVED9_UNION */
#define SOC_CONFIG_REG_RESERVED9_ADDR(base)           ((base) + (0x30))

/* �Ĵ���˵��������ʱ��ʹ�ܼĴ���0��
   λ����UNION�ṹ:  SOC_CONFIG_HIEPS_PEREN0_UNION */
#define SOC_CONFIG_HIEPS_PEREN0_ADDR(base)            ((base) + (0x100))

/* �Ĵ���˵��������ʱ�ӽ�ֹ�Ĵ���0��
   λ����UNION�ṹ:  SOC_CONFIG_HIEPS_PERDIS0_UNION */
#define SOC_CONFIG_HIEPS_PERDIS0_ADDR(base)           ((base) + (0x104))

/* �Ĵ���˵��������ʱ��ʹ��״̬�Ĵ���0��
   λ����UNION�ṹ:  SOC_CONFIG_HIEPS_PERCLKEN0_UNION */
#define SOC_CONFIG_HIEPS_PERCLKEN0_ADDR(base)         ((base) + (0x108))

/* �Ĵ���˵����'����ʱ������״̬�Ĵ���0��
   λ����UNION�ṹ:  SOC_CONFIG_HIEPS_PERSTAT0_UNION */
#define SOC_CONFIG_HIEPS_PERSTAT0_ADDR(base)          ((base) + (0x10C))

/* �Ĵ���˵����������λʹ�ܼĴ���0��
   λ����UNION�ṹ:  SOC_CONFIG_PERRSTEN0_UNION */
#define SOC_CONFIG_PERRSTEN0_ADDR(base)               ((base) + (0x110))

/* �Ĵ���˵����������λ����Ĵ���0��
   λ����UNION�ṹ:  SOC_CONFIG_HIEPS_PERRSTDIS0_UNION */
#define SOC_CONFIG_HIEPS_PERRSTDIS0_ADDR(base)        ((base) + (0x114))

/* �Ĵ���˵����������λ״̬�Ĵ���0��
   λ����UNION�ṹ:  SOC_CONFIG_HIEPS_PERRSTSTAT0_UNION */
#define SOC_CONFIG_HIEPS_PERRSTSTAT0_ADDR(base)       ((base) + (0x118))

/* �Ĵ���˵����ʱ�ӷ�Ƶ�ȿ��ƼĴ���0��
   λ����UNION�ṹ:  SOC_CONFIG_HIEPS_DIV0_UNION */
#define SOC_CONFIG_HIEPS_DIV0_ADDR(base)              ((base) + (0x11C))

/* �Ĵ���˵����CRG���ƼĴ���0��
   λ����UNION�ṹ:  SOC_CONFIG_HIEPS_COMMON_CTRL0_UNION */
#define SOC_CONFIG_HIEPS_COMMON_CTRL0_ADDR(base)      ((base) + (0x120))

/* �Ĵ���˵����CRG���ƼĴ���1��
   λ����UNION�ṹ:  SOC_CONFIG_HIEPS_COMMON_CTRL1_UNION */
#define SOC_CONFIG_HIEPS_COMMON_CTRL1_ADDR(base)      ((base) + (0x124))

/* �Ĵ���˵����CRG���������ƼĴ�����
   λ����UNION�ṹ:  SOC_CONFIG_HIEPS_IPCLKRST_BYPASS0_UNION */
#define SOC_CONFIG_HIEPS_IPCLKRST_BYPASS0_ADDR(base)  ((base) + (0x128))

/* �Ĵ���˵����
   λ����UNION�ṹ:  SOC_CONFIG_HIEPS_MEM_CTRL_ROM_UNION */
#define SOC_CONFIG_HIEPS_MEM_CTRL_ROM_ADDR(base)      ((base) + (0x200))

/* �Ĵ���˵����
   λ����UNION�ṹ:  SOC_CONFIG_HIEPS_MEM_CTRL_SPRAM_UNION */
#define SOC_CONFIG_HIEPS_MEM_CTRL_SPRAM_ADDR(base)    ((base) + (0x204))

/* �Ĵ���˵����
   λ����UNION�ṹ:  SOC_CONFIG_HIEPS_MEM_CTRL_HD_UNION */
#define SOC_CONFIG_HIEPS_MEM_CTRL_HD_ADDR(base)       ((base) + (0x208))

/* �Ĵ���˵����
   λ����UNION�ṹ:  SOC_CONFIG_HIEPS_MEM_CTRL_DPRAM_UNION */
#define SOC_CONFIG_HIEPS_MEM_CTRL_DPRAM_ADDR(base)    ((base) + (0x20C))

/* �Ĵ���˵����
   λ����UNION�ṹ:  SOC_CONFIG_HIEPS_MEM_CTRL_BPRAM_UNION */
#define SOC_CONFIG_HIEPS_MEM_CTRL_BPRAM_ADDR(base)    ((base) + (0x210))

/* �Ĵ���˵�����ж�MASK
   λ����UNION�ṹ:  SOC_CONFIG_HIEPS_INTR_MASK_UNION */
#define SOC_CONFIG_HIEPS_INTR_MASK_ADDR(base)         ((base) + (0x214))

/* �Ĵ���˵����
   λ����UNION�ṹ:  SOC_CONFIG_HIEPS_SEC_CTRL_UNION */
#define SOC_CONFIG_HIEPS_SEC_CTRL_ADDR(base)          ((base) + (0x218))

/* �Ĵ���˵��������ͨ��QIC���ƼĴ���
   λ����UNION�ṹ:  SOC_CONFIG_HIEPS_QIC_ENC_CTRL_UNION */
#define SOC_CONFIG_HIEPS_QIC_ENC_CTRL_ADDR(base)      ((base) + (0x21C))

/* �Ĵ���˵����ALARM��״̬�Ĵ�Ĵ���
   λ����UNION�ṹ:  SOC_CONFIG_HIEPS_ALARM_STAT_UNION */
#define SOC_CONFIG_HIEPS_ALARM_STAT_ADDR(base)        ((base) + (0x220))

/* �Ĵ���˵����HIEPSϵͳ״̬
   λ����UNION�ṹ:  SOC_CONFIG_HIEPS_STAT_UNION */
#define SOC_CONFIG_HIEPS_STAT_ADDR(base)              ((base) + (0x224))

/* �Ĵ���˵����efuse����״̬
   λ����UNION�ṹ:  SOC_CONFIG_HIEPS_EFUSE_CTRL_STAT_UNION */
#define SOC_CONFIG_HIEPS_EFUSE_CTRL_STAT_ADDR(base)   ((base) + (0x228))

/* �Ĵ���˵����SCE1дͨ����ID����
   λ����UNION�ṹ:  SOC_CONFIG_HIEPS_MMU_WID_UNION */
#define SOC_CONFIG_HIEPS_MMU_WID_ADDR(base)           ((base) + (0x300))

/* �Ĵ���˵����SCE1��ͨ����ID����
   λ����UNION�ṹ:  SOC_CONFIG_HIEPS_MMU_RID_UNION */
#define SOC_CONFIG_HIEPS_MMU_RID_ADDR(base)           ((base) + (0x304))

/* �Ĵ���˵����SCE1Ԥȡ����ID
   λ����UNION�ṹ:  SOC_CONFIG_HIEPS_MMU_PREID_UNION */
#define SOC_CONFIG_HIEPS_MMU_PREID_ADDR(base)         ((base) + (0x308))

/* �Ĵ���˵����SCE2дͨ����ID����
   λ����UNION�ṹ:  SOC_CONFIG_HIEPS_MMU2_WID_UNION */
#define SOC_CONFIG_HIEPS_MMU2_WID_ADDR(base)          ((base) + (0x30C))

/* �Ĵ���˵����SCE2��ͨ����ID����
   λ����UNION�ṹ:  SOC_CONFIG_HIEPS_MMU2_RID_UNION */
#define SOC_CONFIG_HIEPS_MMU2_RID_ADDR(base)          ((base) + (0x310))

/* �Ĵ���˵����SCE2Ԥȡ����ID
   λ����UNION�ṹ:  SOC_CONFIG_HIEPS_MMU2_PREID_UNION */
#define SOC_CONFIG_HIEPS_MMU2_PREID_ADDR(base)        ((base) + (0x314))

/* �Ĵ���˵�������������ȼ����üĴ���
   λ����UNION�ṹ:  SOC_CONFIG_SCE_MST_PRIORITY_UNION */
#define SOC_CONFIG_SCE_MST_PRIORITY_ADDR(base)        ((base) + (0x400))

/* �Ĵ���˵����hint�ź�����
   λ����UNION�ṹ:  SOC_CONFIG_HIEPS_HINT_UNION */
#define SOC_CONFIG_HIEPS_HINT_ADDR(base)              ((base) + (0x404))

/* �Ĵ���˵����
   λ����UNION�ṹ:  SOC_CONFIG_REG_RESERVED10_UNION */
#define SOC_CONFIG_REG_RESERVED10_ADDR(base)          ((base) + (0x420))

/* �Ĵ���˵����
   λ����UNION�ṹ:  SOC_CONFIG_REG_RESERVED11_UNION */
#define SOC_CONFIG_REG_RESERVED11_ADDR(base)          ((base) + (0x424))

/* �Ĵ���˵����ѹ��״̬�Ĵ���
   λ����UNION�ṹ:  SOC_CONFIG_HIEPS_RCV_STATE_UNION */
#define SOC_CONFIG_HIEPS_RCV_STATE_ADDR(base)         ((base) + (0x500))

/* �Ĵ���˵���������Ĵ���
   λ����UNION�ṹ:  SOC_CONFIG_REG_RW_RES1_UNION */
#define SOC_CONFIG_REG_RW_RES1_ADDR(base)             ((base) + (0x800))

/* �Ĵ���˵���������Ĵ���
   λ����UNION�ṹ:  SOC_CONFIG_REG_RW_RES2_UNION */
#define SOC_CONFIG_REG_RW_RES2_ADDR(base)             ((base) + (0x804))

/* �Ĵ���˵���������Ĵ���
   λ����UNION�ṹ:  SOC_CONFIG_REG_RO_RES1_UNION */
#define SOC_CONFIG_REG_RO_RES1_ADDR(base)             ((base) + (0x808))





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
 �ṹ��    : SOC_CONFIG_DDRENC_CTRL_UNION
 �ṹ˵��  : DDRENC_CTRL �Ĵ����ṹ���塣��ַƫ����:0x00����ֵ:0x0000000A�����:32
 �Ĵ���˵��: DDRENC���ƼĴ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  bypass_ddrenc : 4;  /* bit[0-3] : bypass_ddrenc:DDR����ģ���bypass enable�ź�
                                                        4'b0101:bypass��
                                                        4'b1010:���ܣ�
                                                        ���ó�����ֵ���ռ��ܴ��� */
        unsigned int  reserved      : 28; /* bit[4-31]:  */
    } reg;
} SOC_CONFIG_DDRENC_CTRL_UNION;
#endif
#define SOC_CONFIG_DDRENC_CTRL_bypass_ddrenc_START  (0)
#define SOC_CONFIG_DDRENC_CTRL_bypass_ddrenc_END    (3)


/*****************************************************************************
 �ṹ��    : SOC_CONFIG_EFUSEC2HIEPS_CTRL_UNION
 �ṹ˵��  : EFUSEC2HIEPS_CTRL �Ĵ����ṹ���塣��ַƫ����:0x04����ֵ:0x00000000�����:32
 �Ĵ���˵��: �Ĵ�efuse����ؿ�����Ϣ
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  efusec2hieps_ctrl : 32; /* bit[0-31]: bit��31����ʾ������alarm����ʹ�ܣ�1��ʾ����alarm��0��ʾ������--reserved
                                                            bit��30:29����ʾpatch����ʹ��--reserved��
                                                            bit��28:27����ʾdcu_en��ѡ��dx����Ļ���eps����ģ�2��b01��ʾѡ��eps������ֵΪdx
                                                            bit��26��25����ʾarc����edcʱ���Ƿ��Զ�����halt����ʹarc����halt״̬--reserved
                                                            bit��24��Ϊ0��ʾ����д����mbist���ԣ���дΪ1���������ܽ��мĴ����ϱ��������������������߼�
                                                            bit��23:16����ʾhieps_patch��0bit����--reserved
                                                            bit��15����ʾdebug_rst��sercure_diasble������ش����enable�źţ�Ϊ0��ʾ�����и�λ��ǯλ����Ϊ1��ʾ���и�λ��ǯλ����
                                                            bit��14����Ϊ0��ʾ��trng��Ϊ1��ʾ��trng
                                                            bit��13����Ϊ0��ʾ��sdm�²��ص�spi��i2c��ʱ�ӣ�Ϊ1��ʾ�ص�spi��i2c��ʱ��--reserved
                                                            bit��12����Ϊ0��ʾbypass ddrenc���ܣ�Ϊ1��ʾ��bypass ddrenc����
                                                            ����reseverd */
    } reg;
} SOC_CONFIG_EFUSEC2HIEPS_CTRL_UNION;
#endif
#define SOC_CONFIG_EFUSEC2HIEPS_CTRL_efusec2hieps_ctrl_START  (0)
#define SOC_CONFIG_EFUSEC2HIEPS_CTRL_efusec2hieps_ctrl_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_CONFIG_REG_RESERVED1_UNION
 �ṹ˵��  : REG_RESERVED1 �Ĵ����ṹ���塣��ַƫ����:0x08����ֵ:0x00000000�����:32
 �Ĵ���˵��: 
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved : 32; /* bit[0-31]:  */
    } reg;
} SOC_CONFIG_REG_RESERVED1_UNION;
#endif


/*****************************************************************************
 �ṹ��    : SOC_CONFIG_REG_RESERVED2_UNION
 �ṹ˵��  : REG_RESERVED2 �Ĵ����ṹ���塣��ַƫ����:0x0C����ֵ:0x00000000�����:32
 �Ĵ���˵��: 
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved : 32; /* bit[0-31]:  */
    } reg;
} SOC_CONFIG_REG_RESERVED2_UNION;
#endif


/*****************************************************************************
 �ṹ��    : SOC_CONFIG_REG_RESERVED3_UNION
 �ṹ˵��  : REG_RESERVED3 �Ĵ����ṹ���塣��ַƫ����:0x10����ֵ:0x00000000�����:32
 �Ĵ���˵��: 
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved : 32; /* bit[0-31]: reserved */
    } reg;
} SOC_CONFIG_REG_RESERVED3_UNION;
#endif


/*****************************************************************************
 �ṹ��    : SOC_CONFIG_QIC_CTRL_UNION
 �ṹ˵��  : QIC_CTRL �Ĵ����ṹ���塣��ַƫ����:0x14����ֵ:0x00000000�����:32
 �Ĵ���˵��: QIC ����źŵĿ��ƼĴ�����
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  hieps2qic_unenc_awMainPress : 2;  /* bit[0-1]  : ��̬���ã�Ĭ��ֵΪ0������HIEPS QIC�ķǼ���дͨ����mainPress���ƣ�����QIC bufferˮ�ߵ���ֵ��λ����QOS��������ʱ��QIC�Ѿ���ѹEPSʱ�������ã������Կ�������mainPress�� */
        unsigned int  axi_unenc_awqos             : 4;  /* bit[2-5]  : ��̬���ã�HIEPS��QIC�ԽӵķǼ���дͨ����AXI master�ڵ�QOSֵ */
        unsigned int  axi_unenc_region            : 4;  /* bit[6-9]  : ��̬���ã�HIEPS��QIC�Խӵ�AXI master�ڵ�regionֵ���Ǽ���ͨ�� */
        unsigned int  reserved_0                  : 6;  /* bit[10-15]: reserved */
        unsigned int  reserved_1                  : 6;  /* bit[16-21]: reserved */
        unsigned int  reserved_2                  : 1;  /* bit[22]   : reserved */
        unsigned int  system_cache_hint_mux       : 1;  /* bit[23]   : ֻ����̬���ã�Ĭ��ֵΪ0
                                                                       0�����ض˿��ϵ�system cache hintΪ0������system cache��
                                                                       1��͸��MMU�����system cache hint�źŵ��˿��ϡ� */
        unsigned int  reserved_3                  : 1;  /* bit[24]   : reserved */
        unsigned int  hieps2qic_unenc_arMainPress : 2;  /* bit[25-26]: ��̬���ã�Ĭ��ֵΪ0������HIEPS QIC�ķǼ��ܶ�ͨ����mainPress���ƣ�����QIC bufferˮ�ߵ���ֵ��λ����QOS��������ʱ��QIC�Ѿ���ѹEPSʱ�������ã������Կ�������mainPress�� */
        unsigned int  axi_unenc_arqos             : 4;  /* bit[27-30]: ��̬���ã�HIEPS��QIC�ԽӵķǼ��ܶ�ͨ����AXI master�ڵ�QOSֵ */
        unsigned int  reserved_4                  : 1;  /* bit[31]   :  */
    } reg;
} SOC_CONFIG_QIC_CTRL_UNION;
#endif
#define SOC_CONFIG_QIC_CTRL_hieps2qic_unenc_awMainPress_START  (0)
#define SOC_CONFIG_QIC_CTRL_hieps2qic_unenc_awMainPress_END    (1)
#define SOC_CONFIG_QIC_CTRL_axi_unenc_awqos_START              (2)
#define SOC_CONFIG_QIC_CTRL_axi_unenc_awqos_END                (5)
#define SOC_CONFIG_QIC_CTRL_axi_unenc_region_START             (6)
#define SOC_CONFIG_QIC_CTRL_axi_unenc_region_END               (9)
#define SOC_CONFIG_QIC_CTRL_system_cache_hint_mux_START        (23)
#define SOC_CONFIG_QIC_CTRL_system_cache_hint_mux_END          (23)
#define SOC_CONFIG_QIC_CTRL_hieps2qic_unenc_arMainPress_START  (25)
#define SOC_CONFIG_QIC_CTRL_hieps2qic_unenc_arMainPress_END    (26)
#define SOC_CONFIG_QIC_CTRL_axi_unenc_arqos_START              (27)
#define SOC_CONFIG_QIC_CTRL_axi_unenc_arqos_END                (30)


/*****************************************************************************
 �ṹ��    : SOC_CONFIG_REG_RESERVED4_UNION
 �ṹ˵��  : REG_RESERVED4 �Ĵ����ṹ���塣��ַƫ����:0x18����ֵ:0x00000000�����:32
 �Ĵ���˵��: 
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved : 32; /* bit[0-31]: reserved */
    } reg;
} SOC_CONFIG_REG_RESERVED4_UNION;
#endif


/*****************************************************************************
 �ṹ��    : SOC_CONFIG_REG_RESERVED5_UNION
 �ṹ˵��  : REG_RESERVED5 �Ĵ����ṹ���塣��ַƫ����:0x1C����ֵ:0x00000000�����:32
 �Ĵ���˵��: 
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved : 32; /* bit[0-31]: reserved */
    } reg;
} SOC_CONFIG_REG_RESERVED5_UNION;
#endif


/*****************************************************************************
 �ṹ��    : SOC_CONFIG_REG_RESERVED6_UNION
 �ṹ˵��  : REG_RESERVED6 �Ĵ����ṹ���塣��ַƫ����:0x20����ֵ:0x00000000�����:32
 �Ĵ���˵��: 
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved : 32; /* bit[0-31]: reserved */
    } reg;
} SOC_CONFIG_REG_RESERVED6_UNION;
#endif


/*****************************************************************************
 �ṹ��    : SOC_CONFIG_ALARM_CLR_UNION
 �ṹ˵��  : ALARM_CLR �Ĵ����ṹ���塣��ַƫ����:0x24����ֵ:0x00000000�����:32
 �Ĵ���˵��: ����ת��ƽ���ж�����Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  clr_ddrenc_alarm_pulse : 1;  /* bit[0]   : 1�����alarm�ж�
                                                                 0��û��Ч�� */
        unsigned int  reserved               : 31; /* bit[1-31]: reserved */
    } reg;
} SOC_CONFIG_ALARM_CLR_UNION;
#endif
#define SOC_CONFIG_ALARM_CLR_clr_ddrenc_alarm_pulse_START  (0)
#define SOC_CONFIG_ALARM_CLR_clr_ddrenc_alarm_pulse_END    (0)


/*****************************************************************************
 �ṹ��    : SOC_CONFIG_REG_RESERVED7_UNION
 �ṹ˵��  : REG_RESERVED7 �Ĵ����ṹ���塣��ַƫ����:0x28����ֵ:0x00000000�����:32
 �Ĵ���˵��: 
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved : 32; /* bit[0-31]: reserved */
    } reg;
} SOC_CONFIG_REG_RESERVED7_UNION;
#endif


/*****************************************************************************
 �ṹ��    : SOC_CONFIG_REG_RESERVED8_UNION
 �ṹ˵��  : REG_RESERVED8 �Ĵ����ṹ���塣��ַƫ����:0x2C����ֵ:0x00000000�����:32
 �Ĵ���˵��: 
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved : 32; /* bit[0-31]: reserved */
    } reg;
} SOC_CONFIG_REG_RESERVED8_UNION;
#endif


/*****************************************************************************
 �ṹ��    : SOC_CONFIG_REG_RESERVED9_UNION
 �ṹ˵��  : REG_RESERVED9 �Ĵ����ṹ���塣��ַƫ����:0x30����ֵ:0x00000000�����:32
 �Ĵ���˵��: 
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved : 32; /* bit[0-31]: reserved */
    } reg;
} SOC_CONFIG_REG_RESERVED9_UNION;
#endif


/*****************************************************************************
 �ṹ��    : SOC_CONFIG_HIEPS_PEREN0_UNION
 �ṹ˵��  : HIEPS_PEREN0 �Ĵ����ṹ���塣��ַƫ����:0x100����ֵ:0x00000000�����:32
 �Ĵ���˵��: ����ʱ��ʹ�ܼĴ���0��
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  gt_pclk_hieps_timer : 1;  /* bit[0]    : TIMERʱ�ӵ����ſ� */
        unsigned int  gt_pclk_hieps_trng  : 1;  /* bit[1]    : TRNGʱ�ӵ����ſ� */
        unsigned int  gt_clk_hieps_sce_km : 1;  /* bit[2]    : SCE��KMʱ�ӵ����ſ� */
        unsigned int  gt_clk_hieps_pke    : 1;  /* bit[3]    : PKEʱ�ӵ����ſ� */
        unsigned int  gt_clk_hieps_mmu    : 1;  /* bit[4]    : MMU�����ſ� */
        unsigned int  gt_clk_ddr_crpt     : 1;  /* bit[5]    : DDR����ʱ�ӵ����ſ� */
        unsigned int  gt_clk_hieps_cmp    : 1;  /* bit[6]    : ѹ��ģ��ʱ�ӵ����ſ� */
        unsigned int  gt_clk_hieps_pke2   : 1;  /* bit[7]    : PKE2ʱ�ӵ����ſ� */
        unsigned int  gt_clk_hieps_sce2   : 1;  /* bit[8]    : SCE2ʱ�ӵ����ſ� */
        unsigned int  gt_aclk_hieps_qic   : 1;  /* bit[9]    : qicʱ�ӵ����ſ� */
        unsigned int  reserved            : 22; /* bit[10-31]: ����ʱ��ʹ�ܿ��ƣ�
                                                               0��д0��Ч����
                                                               1��ʹ��IPʱ�ӡ� */
    } reg;
} SOC_CONFIG_HIEPS_PEREN0_UNION;
#endif
#define SOC_CONFIG_HIEPS_PEREN0_gt_pclk_hieps_timer_START  (0)
#define SOC_CONFIG_HIEPS_PEREN0_gt_pclk_hieps_timer_END    (0)
#define SOC_CONFIG_HIEPS_PEREN0_gt_pclk_hieps_trng_START   (1)
#define SOC_CONFIG_HIEPS_PEREN0_gt_pclk_hieps_trng_END     (1)
#define SOC_CONFIG_HIEPS_PEREN0_gt_clk_hieps_sce_km_START  (2)
#define SOC_CONFIG_HIEPS_PEREN0_gt_clk_hieps_sce_km_END    (2)
#define SOC_CONFIG_HIEPS_PEREN0_gt_clk_hieps_pke_START     (3)
#define SOC_CONFIG_HIEPS_PEREN0_gt_clk_hieps_pke_END       (3)
#define SOC_CONFIG_HIEPS_PEREN0_gt_clk_hieps_mmu_START     (4)
#define SOC_CONFIG_HIEPS_PEREN0_gt_clk_hieps_mmu_END       (4)
#define SOC_CONFIG_HIEPS_PEREN0_gt_clk_ddr_crpt_START      (5)
#define SOC_CONFIG_HIEPS_PEREN0_gt_clk_ddr_crpt_END        (5)
#define SOC_CONFIG_HIEPS_PEREN0_gt_clk_hieps_cmp_START     (6)
#define SOC_CONFIG_HIEPS_PEREN0_gt_clk_hieps_cmp_END       (6)
#define SOC_CONFIG_HIEPS_PEREN0_gt_clk_hieps_pke2_START    (7)
#define SOC_CONFIG_HIEPS_PEREN0_gt_clk_hieps_pke2_END      (7)
#define SOC_CONFIG_HIEPS_PEREN0_gt_clk_hieps_sce2_START    (8)
#define SOC_CONFIG_HIEPS_PEREN0_gt_clk_hieps_sce2_END      (8)
#define SOC_CONFIG_HIEPS_PEREN0_gt_aclk_hieps_qic_START    (9)
#define SOC_CONFIG_HIEPS_PEREN0_gt_aclk_hieps_qic_END      (9)


/*****************************************************************************
 �ṹ��    : SOC_CONFIG_HIEPS_PERDIS0_UNION
 �ṹ˵��  : HIEPS_PERDIS0 �Ĵ����ṹ���塣��ַƫ����:0x104����ֵ:0x00000000�����:32
 �Ĵ���˵��: ����ʱ�ӽ�ֹ�Ĵ���0��
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  gt_pclk_hieps_timer : 1;  /* bit[0]    : TIMERʱ�ӵĽ�ֹ���� */
        unsigned int  gt_pclk_hieps_trng  : 1;  /* bit[1]    : TRNGʱ�ӵĽ�ֹ���� */
        unsigned int  gt_clk_hieps_sce_km : 1;  /* bit[2]    : SCE��KMʱ�ӵĽ�ֹ���� */
        unsigned int  gt_clk_hieps_pke    : 1;  /* bit[3]    : PKEʱ�ӵĽ�ֹ���� */
        unsigned int  gt_clk_hieps_mmu    : 1;  /* bit[4]    : MMU��ʱ�ӽ�ֹ���� */
        unsigned int  gt_clk_ddr_crpt     : 1;  /* bit[5]    : DDR����ʱ�ӵĽ�ֹ���� */
        unsigned int  gt_clk_hieps_cmp    : 1;  /* bit[6]    : ѹ��ģ��ʱ�ӵĽ�ֹ���� */
        unsigned int  gt_clk_hieps_pke2   : 1;  /* bit[7]    : PKE2ʱ�ӵĽ�ֹ���� */
        unsigned int  gt_clk_hieps_sce2   : 1;  /* bit[8]    : SCE2ʱ�ӵĽ�ֹ���� */
        unsigned int  gt_aclk_hieps_qic   : 1;  /* bit[9]    : qicʱ�ӵĽ�ֹ���� */
        unsigned int  reserved            : 22; /* bit[10-31]: ����ʱ�ӽ�ֹ���ƣ�
                                                               0��д0��Ч����
                                                               1����ֹIPʱ�ӡ� */
    } reg;
} SOC_CONFIG_HIEPS_PERDIS0_UNION;
#endif
#define SOC_CONFIG_HIEPS_PERDIS0_gt_pclk_hieps_timer_START  (0)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_pclk_hieps_timer_END    (0)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_pclk_hieps_trng_START   (1)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_pclk_hieps_trng_END     (1)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_clk_hieps_sce_km_START  (2)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_clk_hieps_sce_km_END    (2)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_clk_hieps_pke_START     (3)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_clk_hieps_pke_END       (3)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_clk_hieps_mmu_START     (4)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_clk_hieps_mmu_END       (4)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_clk_ddr_crpt_START      (5)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_clk_ddr_crpt_END        (5)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_clk_hieps_cmp_START     (6)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_clk_hieps_cmp_END       (6)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_clk_hieps_pke2_START    (7)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_clk_hieps_pke2_END      (7)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_clk_hieps_sce2_START    (8)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_clk_hieps_sce2_END      (8)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_aclk_hieps_qic_START    (9)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_aclk_hieps_qic_END      (9)


/*****************************************************************************
 �ṹ��    : SOC_CONFIG_HIEPS_PERCLKEN0_UNION
 �ṹ˵��  : HIEPS_PERCLKEN0 �Ĵ����ṹ���塣��ַƫ����:0x108����ֵ:0x000003FF�����:32
 �Ĵ���˵��: ����ʱ��ʹ��״̬�Ĵ���0��
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  gt_pclk_hieps_timer : 1;  /* bit[0]    : TIMERʱ��ʹ��״̬ */
        unsigned int  gt_pclk_hieps_trng  : 1;  /* bit[1]    : TRNGʱ��ʹ��״̬ */
        unsigned int  gt_clk_hieps_sce_km : 1;  /* bit[2]    : SCE��KMʱ��ʹ��״̬ */
        unsigned int  gt_clk_hieps_pke    : 1;  /* bit[3]    : PKEʱ��ʹ��״̬ */
        unsigned int  gt_clk_hieps_mmu    : 1;  /* bit[4]    : MMU��ʱ��ʹ��״̬��ͬʱ����bclk��cclk */
        unsigned int  gt_clk_ddr_crpt     : 1;  /* bit[5]    : DDR����ʱ�ӵ�ʹ��״̬ */
        unsigned int  gt_clk_hieps_cmp    : 1;  /* bit[6]    : ѹ��ģ��ʱ�ӵ�ʹ��״̬ */
        unsigned int  gt_clk_hieps_pke2   : 1;  /* bit[7]    : PKE2ʱ�ӵ�ʹ��״̬ */
        unsigned int  gt_clk_hieps_sce2   : 1;  /* bit[8]    : SCE2ʱ�ӵ�ʹ��״̬ */
        unsigned int  gt_aclk_hieps_qic   : 1;  /* bit[9]    : qicʱ�ӵ�ʹ��״̬ */
        unsigned int  reserved            : 22; /* bit[10-31]: ����ʱ��ʹ��״̬��
                                                               0��IPʱ��ʹ�ܳ���״̬��
                                                               1��IPʱ��ʹ��״̬�� */
    } reg;
} SOC_CONFIG_HIEPS_PERCLKEN0_UNION;
#endif
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_pclk_hieps_timer_START  (0)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_pclk_hieps_timer_END    (0)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_pclk_hieps_trng_START   (1)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_pclk_hieps_trng_END     (1)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_clk_hieps_sce_km_START  (2)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_clk_hieps_sce_km_END    (2)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_clk_hieps_pke_START     (3)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_clk_hieps_pke_END       (3)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_clk_hieps_mmu_START     (4)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_clk_hieps_mmu_END       (4)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_clk_ddr_crpt_START      (5)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_clk_ddr_crpt_END        (5)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_clk_hieps_cmp_START     (6)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_clk_hieps_cmp_END       (6)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_clk_hieps_pke2_START    (7)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_clk_hieps_pke2_END      (7)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_clk_hieps_sce2_START    (8)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_clk_hieps_sce2_END      (8)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_aclk_hieps_qic_START    (9)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_aclk_hieps_qic_END      (9)


/*****************************************************************************
 �ṹ��    : SOC_CONFIG_HIEPS_PERSTAT0_UNION
 �ṹ˵��  : HIEPS_PERSTAT0 �Ĵ����ṹ���塣��ַƫ����:0x10C����ֵ:0x000003FF�����:32
 �Ĵ���˵��: '����ʱ������״̬�Ĵ���0��
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  st_pclk_hieps_timer   : 1;  /* bit[0]    : TIMER��ʱ��״̬ */
        unsigned int  st_pclk_hieps_trng    : 1;  /* bit[1]    : TRNG��ʱ��״̬ */
        unsigned int  st_clk_hieps_sce_km   : 1;  /* bit[2]    : SCE��KM��ʱ��״̬ */
        unsigned int  st_clk_hieps_pke      : 1;  /* bit[3]    : PKE��ʱ��״̬ */
        unsigned int  st_clk_hieps_mmu_bclk : 1;  /* bit[4]    : �Զ�gating��mmu bclk��״̬��mmu_bclk��״̬�������Զ��ſ� */
        unsigned int  st_clk_ddr_crpt       : 1;  /* bit[5]    : DDR���ܵ�ʱ��״̬ */
        unsigned int  st_clk_hieps_cmp      : 1;  /* bit[6]    : ѹ��ģ���ʱ��״̬ */
        unsigned int  st_clk_hieps_pke2     : 1;  /* bit[7]    : PKE2��ʱ��״̬ */
        unsigned int  st_clk_hieps_sce2     : 1;  /* bit[8]    : SCE2��ʱ��״̬ */
        unsigned int  st_aclk_hieps_qic     : 1;  /* bit[9]    : qic��ʱ��״̬ */
        unsigned int  reserved              : 22; /* bit[10-31]: ����ʱ������״̬��
                                                                 0��IPʱ�ӽ�ֹ״̬��
                                                                 1��IPʱ��ʹ��״̬�� */
    } reg;
} SOC_CONFIG_HIEPS_PERSTAT0_UNION;
#endif
#define SOC_CONFIG_HIEPS_PERSTAT0_st_pclk_hieps_timer_START    (0)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_pclk_hieps_timer_END      (0)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_pclk_hieps_trng_START     (1)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_pclk_hieps_trng_END       (1)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_clk_hieps_sce_km_START    (2)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_clk_hieps_sce_km_END      (2)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_clk_hieps_pke_START       (3)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_clk_hieps_pke_END         (3)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_clk_hieps_mmu_bclk_START  (4)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_clk_hieps_mmu_bclk_END    (4)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_clk_ddr_crpt_START        (5)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_clk_ddr_crpt_END          (5)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_clk_hieps_cmp_START       (6)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_clk_hieps_cmp_END         (6)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_clk_hieps_pke2_START      (7)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_clk_hieps_pke2_END        (7)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_clk_hieps_sce2_START      (8)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_clk_hieps_sce2_END        (8)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_aclk_hieps_qic_START      (9)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_aclk_hieps_qic_END        (9)


/*****************************************************************************
 �ṹ��    : SOC_CONFIG_PERRSTEN0_UNION
 �ṹ˵��  : PERRSTEN0 �Ĵ����ṹ���塣��ַƫ����:0x110����ֵ:0x00000000�����:32
 �Ĵ���˵��: ������λʹ�ܼĴ���0��
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ip_prst_hieps_timer : 1;  /* bit[0]   : IP��λʹ�ܣ�
                                                              0��IP��λʹ��״̬���䣻
                                                              1��IP��λʹ�ܡ� */
        unsigned int  ip_prst_hieps_trng  : 1;  /* bit[1]   : ͬbit0 */
        unsigned int  ip_rst_hieps_sce_km : 1;  /* bit[2]   : ͬbit0 */
        unsigned int  ip_rst_hieps_pke    : 1;  /* bit[3]   : ͬbit0 */
        unsigned int  ip_rst_hieps_mmu    : 1;  /* bit[4]   : ͬbit0 */
        unsigned int  ip_rst_ddr_crpt     : 1;  /* bit[5]   : ͬbit0 */
        unsigned int  ip_rst_hieps_cmp    : 1;  /* bit[6]   : ͬbit0 */
        unsigned int  ip_rst_hieps_sce2   : 1;  /* bit[7]   : ͬbit0 */
        unsigned int  ip_rst_hieps_pke2   : 1;  /* bit[8]   : ͬbit0 */
        unsigned int  reserved            : 23; /* bit[9-31]: IP��λʹ�ܣ�
                                                              0��IP��λʹ��״̬���䣻
                                                              1��IP��λʹ�ܡ� */
    } reg;
} SOC_CONFIG_PERRSTEN0_UNION;
#endif
#define SOC_CONFIG_PERRSTEN0_ip_prst_hieps_timer_START  (0)
#define SOC_CONFIG_PERRSTEN0_ip_prst_hieps_timer_END    (0)
#define SOC_CONFIG_PERRSTEN0_ip_prst_hieps_trng_START   (1)
#define SOC_CONFIG_PERRSTEN0_ip_prst_hieps_trng_END     (1)
#define SOC_CONFIG_PERRSTEN0_ip_rst_hieps_sce_km_START  (2)
#define SOC_CONFIG_PERRSTEN0_ip_rst_hieps_sce_km_END    (2)
#define SOC_CONFIG_PERRSTEN0_ip_rst_hieps_pke_START     (3)
#define SOC_CONFIG_PERRSTEN0_ip_rst_hieps_pke_END       (3)
#define SOC_CONFIG_PERRSTEN0_ip_rst_hieps_mmu_START     (4)
#define SOC_CONFIG_PERRSTEN0_ip_rst_hieps_mmu_END       (4)
#define SOC_CONFIG_PERRSTEN0_ip_rst_ddr_crpt_START      (5)
#define SOC_CONFIG_PERRSTEN0_ip_rst_ddr_crpt_END        (5)
#define SOC_CONFIG_PERRSTEN0_ip_rst_hieps_cmp_START     (6)
#define SOC_CONFIG_PERRSTEN0_ip_rst_hieps_cmp_END       (6)
#define SOC_CONFIG_PERRSTEN0_ip_rst_hieps_sce2_START    (7)
#define SOC_CONFIG_PERRSTEN0_ip_rst_hieps_sce2_END      (7)
#define SOC_CONFIG_PERRSTEN0_ip_rst_hieps_pke2_START    (8)
#define SOC_CONFIG_PERRSTEN0_ip_rst_hieps_pke2_END      (8)


/*****************************************************************************
 �ṹ��    : SOC_CONFIG_HIEPS_PERRSTDIS0_UNION
 �ṹ˵��  : HIEPS_PERRSTDIS0 �Ĵ����ṹ���塣��ַƫ����:0x114����ֵ:0x00000000�����:32
 �Ĵ���˵��: ������λ����Ĵ���0��
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ip_prst_hieps_timer : 1;  /* bit[0]   : IP��λ���룺
                                                              0��IP��λʹ��״̬���䣻
                                                              1��IP��λ���롣 */
        unsigned int  ip_prst_hieps_trng  : 1;  /* bit[1]   : ͬbit0 */
        unsigned int  ip_rst_hieps_sce_km : 1;  /* bit[2]   : ͬbit0 */
        unsigned int  ip_rst_hieps_pke    : 1;  /* bit[3]   : ͬbit0 */
        unsigned int  ip_rst_hieps_mmu    : 1;  /* bit[4]   : ͬbit0 */
        unsigned int  ip_rst_ddr_crpt     : 1;  /* bit[5]   : ͬbit0 */
        unsigned int  ip_rst_hieps_cmp    : 1;  /* bit[6]   : ͬbit0 */
        unsigned int  ip_rst_hieps_sce2   : 1;  /* bit[7]   : ͬbit0 */
        unsigned int  ip_rst_hieps_pke2   : 1;  /* bit[8]   : ͬbit0 */
        unsigned int  reserved            : 23; /* bit[9-31]: IP��λ���룺
                                                              0��IP��λʹ��״̬���䣻
                                                              1��IP��λ���롣 */
    } reg;
} SOC_CONFIG_HIEPS_PERRSTDIS0_UNION;
#endif
#define SOC_CONFIG_HIEPS_PERRSTDIS0_ip_prst_hieps_timer_START  (0)
#define SOC_CONFIG_HIEPS_PERRSTDIS0_ip_prst_hieps_timer_END    (0)
#define SOC_CONFIG_HIEPS_PERRSTDIS0_ip_prst_hieps_trng_START   (1)
#define SOC_CONFIG_HIEPS_PERRSTDIS0_ip_prst_hieps_trng_END     (1)
#define SOC_CONFIG_HIEPS_PERRSTDIS0_ip_rst_hieps_sce_km_START  (2)
#define SOC_CONFIG_HIEPS_PERRSTDIS0_ip_rst_hieps_sce_km_END    (2)
#define SOC_CONFIG_HIEPS_PERRSTDIS0_ip_rst_hieps_pke_START     (3)
#define SOC_CONFIG_HIEPS_PERRSTDIS0_ip_rst_hieps_pke_END       (3)
#define SOC_CONFIG_HIEPS_PERRSTDIS0_ip_rst_hieps_mmu_START     (4)
#define SOC_CONFIG_HIEPS_PERRSTDIS0_ip_rst_hieps_mmu_END       (4)
#define SOC_CONFIG_HIEPS_PERRSTDIS0_ip_rst_ddr_crpt_START      (5)
#define SOC_CONFIG_HIEPS_PERRSTDIS0_ip_rst_ddr_crpt_END        (5)
#define SOC_CONFIG_HIEPS_PERRSTDIS0_ip_rst_hieps_cmp_START     (6)
#define SOC_CONFIG_HIEPS_PERRSTDIS0_ip_rst_hieps_cmp_END       (6)
#define SOC_CONFIG_HIEPS_PERRSTDIS0_ip_rst_hieps_sce2_START    (7)
#define SOC_CONFIG_HIEPS_PERRSTDIS0_ip_rst_hieps_sce2_END      (7)
#define SOC_CONFIG_HIEPS_PERRSTDIS0_ip_rst_hieps_pke2_START    (8)
#define SOC_CONFIG_HIEPS_PERRSTDIS0_ip_rst_hieps_pke2_END      (8)


/*****************************************************************************
 �ṹ��    : SOC_CONFIG_HIEPS_PERRSTSTAT0_UNION
 �ṹ˵��  : HIEPS_PERRSTSTAT0 �Ĵ����ṹ���塣��ַƫ����:0x118����ֵ:0x00000000�����:32
 �Ĵ���˵��: ������λ״̬�Ĵ���0��
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ip_prst_hieps_timer : 1;  /* bit[0]   : Ĭ�Ͻ⸴λ */
        unsigned int  ip_prst_hieps_trng  : 1;  /* bit[1]   : Ĭ�Ͻ⸴λ */
        unsigned int  ip_rst_hieps_sce_km : 1;  /* bit[2]   : Ĭ�Ͻ⸴λ */
        unsigned int  ip_rst_hieps_pke    : 1;  /* bit[3]   : Ĭ�Ͻ⸴λ */
        unsigned int  ip_rst_hieps_mmu    : 1;  /* bit[4]   : Ĭ�Ͻ⸴λ */
        unsigned int  ip_rst_ddr_crpt     : 1;  /* bit[5]   : Ĭ�Ͻ⸴λ */
        unsigned int  ip_rst_hieps_cmp    : 1;  /* bit[6]   : Ĭ�Ͻ⸴λ */
        unsigned int  ip_rst_hieps_sce2   : 1;  /* bit[7]   : Ĭ�Ͻ⸴λ */
        unsigned int  ip_rst_hieps_pke2   : 1;  /* bit[8]   : Ĭ�Ͻ⸴λ */
        unsigned int  reserved            : 23; /* bit[9-31]: IP��λʹ��״̬��
                                                              0��IP���ڸ�λ����״̬��
                                                              1��IP������λʹ��״̬�� */
    } reg;
} SOC_CONFIG_HIEPS_PERRSTSTAT0_UNION;
#endif
#define SOC_CONFIG_HIEPS_PERRSTSTAT0_ip_prst_hieps_timer_START  (0)
#define SOC_CONFIG_HIEPS_PERRSTSTAT0_ip_prst_hieps_timer_END    (0)
#define SOC_CONFIG_HIEPS_PERRSTSTAT0_ip_prst_hieps_trng_START   (1)
#define SOC_CONFIG_HIEPS_PERRSTSTAT0_ip_prst_hieps_trng_END     (1)
#define SOC_CONFIG_HIEPS_PERRSTSTAT0_ip_rst_hieps_sce_km_START  (2)
#define SOC_CONFIG_HIEPS_PERRSTSTAT0_ip_rst_hieps_sce_km_END    (2)
#define SOC_CONFIG_HIEPS_PERRSTSTAT0_ip_rst_hieps_pke_START     (3)
#define SOC_CONFIG_HIEPS_PERRSTSTAT0_ip_rst_hieps_pke_END       (3)
#define SOC_CONFIG_HIEPS_PERRSTSTAT0_ip_rst_hieps_mmu_START     (4)
#define SOC_CONFIG_HIEPS_PERRSTSTAT0_ip_rst_hieps_mmu_END       (4)
#define SOC_CONFIG_HIEPS_PERRSTSTAT0_ip_rst_ddr_crpt_START      (5)
#define SOC_CONFIG_HIEPS_PERRSTSTAT0_ip_rst_ddr_crpt_END        (5)
#define SOC_CONFIG_HIEPS_PERRSTSTAT0_ip_rst_hieps_cmp_START     (6)
#define SOC_CONFIG_HIEPS_PERRSTSTAT0_ip_rst_hieps_cmp_END       (6)
#define SOC_CONFIG_HIEPS_PERRSTSTAT0_ip_rst_hieps_sce2_START    (7)
#define SOC_CONFIG_HIEPS_PERRSTSTAT0_ip_rst_hieps_sce2_END      (7)
#define SOC_CONFIG_HIEPS_PERRSTSTAT0_ip_rst_hieps_pke2_START    (8)
#define SOC_CONFIG_HIEPS_PERRSTSTAT0_ip_rst_hieps_pke2_END      (8)


/*****************************************************************************
 �ṹ��    : SOC_CONFIG_HIEPS_DIV0_UNION
 �ṹ˵��  : HIEPS_DIV0 �Ĵ����ṹ���塣��ַƫ����:0x11C����ֵ:0x00000007�����:32
 �Ĵ���˵��: ʱ�ӷ�Ƶ�ȿ��ƼĴ���0��
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  div_hieps_ahb_bus_tp    : 2;  /* bit[0-1]  : Ĭ��Ϊ3������4��Ƶ */
        unsigned int  div_hieps_timer         : 2;  /* bit[2-3]  : Ĭ��Ϊ1������19.2Mhz��2��Ƶ9.6MHz�� */
        unsigned int  sc_gt_clk_hieps_ahb_bus : 1;  /* bit[4]    : ahbʱ���ſؿ��ƣ����������testpoint�ϵ�ahb��Ƶʱ�� */
        unsigned int  reserved_0              : 11; /* bit[5-15] : ������ */
        unsigned int  reserved_1              : 16; /* bit[16-31]: bitmasken:ÿ������λ��ʹ��λ,
                                                                   ֻ�е�bitmasken��Ӧ�ı���λΪ1'b1����Ӧ�ı���λ�������á�bitmasken[0]����[0]��maskʹ��λ��д1��Ч�� */
    } reg;
} SOC_CONFIG_HIEPS_DIV0_UNION;
#endif
#define SOC_CONFIG_HIEPS_DIV0_div_hieps_ahb_bus_tp_START     (0)
#define SOC_CONFIG_HIEPS_DIV0_div_hieps_ahb_bus_tp_END       (1)
#define SOC_CONFIG_HIEPS_DIV0_div_hieps_timer_START          (2)
#define SOC_CONFIG_HIEPS_DIV0_div_hieps_timer_END            (3)
#define SOC_CONFIG_HIEPS_DIV0_sc_gt_clk_hieps_ahb_bus_START  (4)
#define SOC_CONFIG_HIEPS_DIV0_sc_gt_clk_hieps_ahb_bus_END    (4)


/*****************************************************************************
 �ṹ��    : SOC_CONFIG_HIEPS_COMMON_CTRL0_UNION
 �ṹ˵��  : HIEPS_COMMON_CTRL0 �Ĵ����ṹ���塣��ַƫ����:0x120����ֵ:0x0000000C�����:32
 �Ĵ���˵��: CRG���ƼĴ���0��
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  timer0_soft_en      : 1;  /* bit[0]    : timer1����ʹ�ܵ�������أ�Ĭ�Ϲرա� */
        unsigned int  timer1_soft_en      : 1;  /* bit[1]    : timer0����ʹ�ܵ�������أ�Ĭ�Ϲرա� */
        unsigned int  hieps_timer0_en_sel : 1;  /* bit[2]    : 32k����19.2Mhz��Ƶʱ�ӣ�
                                                               Ĭ��timer�ļ���ʹ��ʱ��Ϊ9.6Mhz
                                                               0��32K����ʹ��
                                                               1��ѡ��19.2M�ķ�Ƶʱ�� */
        unsigned int  hieps_timer1_en_sel : 1;  /* bit[3]    : 32k����19.2Mhz��Ƶʱ�ӣ�
                                                               Ĭ��timer�ļ���ʹ��ʱ��Ϊ9.6Mhz
                                                               0��32K����ʹ��
                                                               1��ѡ��19.2M�ķ�Ƶʱ�� */
        unsigned int  reserved_0          : 12; /* bit[4-15] : ������ */
        unsigned int  reserved_1          : 16; /* bit[16-31]: bitmasken:ÿ������λ��ʹ��λ,
                                                               ֻ�е�bitmasken��Ӧ�ı���λΪ1'b1����Ӧ�ı���λ�������á�bitmasken[0]����[0]��maskʹ��λ��д1��Ч�� */
    } reg;
} SOC_CONFIG_HIEPS_COMMON_CTRL0_UNION;
#endif
#define SOC_CONFIG_HIEPS_COMMON_CTRL0_timer0_soft_en_START       (0)
#define SOC_CONFIG_HIEPS_COMMON_CTRL0_timer0_soft_en_END         (0)
#define SOC_CONFIG_HIEPS_COMMON_CTRL0_timer1_soft_en_START       (1)
#define SOC_CONFIG_HIEPS_COMMON_CTRL0_timer1_soft_en_END         (1)
#define SOC_CONFIG_HIEPS_COMMON_CTRL0_hieps_timer0_en_sel_START  (2)
#define SOC_CONFIG_HIEPS_COMMON_CTRL0_hieps_timer0_en_sel_END    (2)
#define SOC_CONFIG_HIEPS_COMMON_CTRL0_hieps_timer1_en_sel_START  (3)
#define SOC_CONFIG_HIEPS_COMMON_CTRL0_hieps_timer1_en_sel_END    (3)


/*****************************************************************************
 �ṹ��    : SOC_CONFIG_HIEPS_COMMON_CTRL1_UNION
 �ṹ˵��  : HIEPS_COMMON_CTRL1 �Ĵ����ṹ���塣��ַƫ����:0x124����ֵ:0x00000000�����:32
 �Ĵ���˵��: CRG���ƼĴ���1��
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved_0: 16; /* bit[0-15] : ������ */
        unsigned int  reserved_1: 16; /* bit[16-31]: bitmasken:ÿ������λ��ʹ��λ,
                                                     ֻ�е�bitmasken��Ӧ�ı���λΪ1'b1����Ӧ�ı���λ�������á�bitmasken[0]����[0]��maskʹ��λ��д1��Ч�� */
    } reg;
} SOC_CONFIG_HIEPS_COMMON_CTRL1_UNION;
#endif


/*****************************************************************************
 �ṹ��    : SOC_CONFIG_HIEPS_IPCLKRST_BYPASS0_UNION
 �ṹ˵��  : HIEPS_IPCLKRST_BYPASS0 �Ĵ����ṹ���塣��ַƫ����:0x128����ֵ:0x00000000�����:32
 �Ĵ���˵��: CRG���������ƼĴ�����
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  hieps_timer_clkrst_bypass  : 1;  /* bit[0]   : ������ָʾ�Ƿ�bypass
                                                                     1��������flag�øߣ�����slave���������߼���bypass
                                                                     0���������߼���Ч */
        unsigned int  hieps_trng_clkrst_bypass   : 1;  /* bit[1]   : ͬbit0 */
        unsigned int  hieps_sce_km_clkrst_bypass : 1;  /* bit[2]   : ͬbit0 */
        unsigned int  hieps_pke_clkrst_bypass    : 1;  /* bit[3]   : ͬbit0 */
        unsigned int  hieps_mmu_clkrst_bypass    : 1;  /* bit[4]   : ͬbit0 */
        unsigned int  hieps_sce2_clkrst_bypass   : 1;  /* bit[5]   : ͬbit0 */
        unsigned int  hieps_pke2_clkrst_bypass   : 1;  /* bit[6]   : ͬbit0 */
        unsigned int  reserved                   : 25; /* bit[7-31]:  */
    } reg;
} SOC_CONFIG_HIEPS_IPCLKRST_BYPASS0_UNION;
#endif
#define SOC_CONFIG_HIEPS_IPCLKRST_BYPASS0_hieps_timer_clkrst_bypass_START   (0)
#define SOC_CONFIG_HIEPS_IPCLKRST_BYPASS0_hieps_timer_clkrst_bypass_END     (0)
#define SOC_CONFIG_HIEPS_IPCLKRST_BYPASS0_hieps_trng_clkrst_bypass_START    (1)
#define SOC_CONFIG_HIEPS_IPCLKRST_BYPASS0_hieps_trng_clkrst_bypass_END      (1)
#define SOC_CONFIG_HIEPS_IPCLKRST_BYPASS0_hieps_sce_km_clkrst_bypass_START  (2)
#define SOC_CONFIG_HIEPS_IPCLKRST_BYPASS0_hieps_sce_km_clkrst_bypass_END    (2)
#define SOC_CONFIG_HIEPS_IPCLKRST_BYPASS0_hieps_pke_clkrst_bypass_START     (3)
#define SOC_CONFIG_HIEPS_IPCLKRST_BYPASS0_hieps_pke_clkrst_bypass_END       (3)
#define SOC_CONFIG_HIEPS_IPCLKRST_BYPASS0_hieps_mmu_clkrst_bypass_START     (4)
#define SOC_CONFIG_HIEPS_IPCLKRST_BYPASS0_hieps_mmu_clkrst_bypass_END       (4)
#define SOC_CONFIG_HIEPS_IPCLKRST_BYPASS0_hieps_sce2_clkrst_bypass_START    (5)
#define SOC_CONFIG_HIEPS_IPCLKRST_BYPASS0_hieps_sce2_clkrst_bypass_END      (5)
#define SOC_CONFIG_HIEPS_IPCLKRST_BYPASS0_hieps_pke2_clkrst_bypass_START    (6)
#define SOC_CONFIG_HIEPS_IPCLKRST_BYPASS0_hieps_pke2_clkrst_bypass_END      (6)


/*****************************************************************************
 �ṹ��    : SOC_CONFIG_HIEPS_MEM_CTRL_ROM_UNION
 �ṹ˵��  : HIEPS_MEM_CTRL_ROM �Ĵ����ṹ���塣��ַƫ����:0x200����ֵ:0x00000000�����:32
 �Ĵ���˵��: 
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  hieps_rom_ctrl_ckhe : 1;  /* bit[0]   : ROM ���ƣ�
                                                              bit[5]����CKHE��Ĭ��Ϊ0 */
        unsigned int  hieps_rom_ctrl_ckle : 1;  /* bit[1]   : ROM ����
                                                              bit[4]����CKLE��Ĭ��Ϊ0�� */
        unsigned int  hieps_rom_ctrl_skp  : 2;  /* bit[2-3] : ROM ����
                                                              bit[3:2]����SKP��Ĭ��Ϊ00�� */
        unsigned int  hieps_rom_ctrl_dt   : 2;  /* bit[4-5] : ROM ����
                                                              bit[1:0]����DT��Ĭ��Ϊ00 */
        unsigned int  reserved            : 26; /* bit[6-31]: ��ʹ�� */
    } reg;
} SOC_CONFIG_HIEPS_MEM_CTRL_ROM_UNION;
#endif
#define SOC_CONFIG_HIEPS_MEM_CTRL_ROM_hieps_rom_ctrl_ckhe_START  (0)
#define SOC_CONFIG_HIEPS_MEM_CTRL_ROM_hieps_rom_ctrl_ckhe_END    (0)
#define SOC_CONFIG_HIEPS_MEM_CTRL_ROM_hieps_rom_ctrl_ckle_START  (1)
#define SOC_CONFIG_HIEPS_MEM_CTRL_ROM_hieps_rom_ctrl_ckle_END    (1)
#define SOC_CONFIG_HIEPS_MEM_CTRL_ROM_hieps_rom_ctrl_skp_START   (2)
#define SOC_CONFIG_HIEPS_MEM_CTRL_ROM_hieps_rom_ctrl_skp_END     (3)
#define SOC_CONFIG_HIEPS_MEM_CTRL_ROM_hieps_rom_ctrl_dt_START    (4)
#define SOC_CONFIG_HIEPS_MEM_CTRL_ROM_hieps_rom_ctrl_dt_END      (5)


/*****************************************************************************
 �ṹ��    : SOC_CONFIG_HIEPS_MEM_CTRL_SPRAM_UNION
 �ṹ˵��  : HIEPS_MEM_CTRL_SPRAM �Ĵ����ṹ���塣��ַƫ����:0x204����ֵ:0x00015858�����:32
 �Ĵ���˵��: 
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  hieps_spram_mem_ctrl : 26; /* bit[0-25] : memory����
                                                                bit[0]����SLP��
                                                                0����Ч
                                                                1������sleepģʽ
                                                                bit[1]����DSLP��
                                                                0����Ч
                                                                1������deep sleepģʽ
                                                                bit[2]����SD��
                                                                0����Ч
                                                                1������shut downģʽ
                                                                bit[5:3]����TSELR�����ڶ���Ĭ��ֵ011��
                                                                bit[7:6]����TSELW������д��Ĭ��ֵ01��
                                                                bit[10:8]����TEST������pin��Ĭ��ֵ000��
                                                                bit[13:11]����TSELR�����ڶ���Ĭ��ֵ011��
                                                                bit[15:14]����TSELW������д��Ĭ��ֵ01��
                                                                bit[17��16]����TRA����assist�������DR����mem��Ĭ��ֵ01��
                                                                ����bitδʹ�� */
        unsigned int  reserved             : 6;  /* bit[26-31]: ����RSA/SM9 SPRAM
                                                                SPS����ʹ��bit[5:3][7:6]
                                                                SPA����ʹ��bit[13:11][15:14] */
    } reg;
} SOC_CONFIG_HIEPS_MEM_CTRL_SPRAM_UNION;
#endif
#define SOC_CONFIG_HIEPS_MEM_CTRL_SPRAM_hieps_spram_mem_ctrl_START  (0)
#define SOC_CONFIG_HIEPS_MEM_CTRL_SPRAM_hieps_spram_mem_ctrl_END    (25)


/*****************************************************************************
 �ṹ��    : SOC_CONFIG_HIEPS_MEM_CTRL_HD_UNION
 �ṹ˵��  : HIEPS_MEM_CTRL_HD �Ĵ����ṹ���塣��ַƫ����:0x208����ֵ:0x00015858�����:32
 �Ĵ���˵��: 
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  hieps_hd_mem_ctrl : 26; /* bit[0-25] : memory����
                                                             bit[0]����SLP��
                                                             0����Ч
                                                             1������sleepģʽ
                                                             bit[1]����DSLP��
                                                             0����Ч
                                                             1������deep sleepģʽ
                                                             bit[2]����SD��
                                                             0����Ч
                                                             1������shut downģʽ
                                                             bit[5:3]����TSELR�����ڶ���Ĭ��ֵ011��
                                                             bit[7:6]����TSELW������д��Ĭ��ֵ01��
                                                             bit[10:8]����TEST������pin��Ĭ��ֵ000��
                                                             bit[13:11]����TSELR�����ڶ���Ĭ��ֵ011��
                                                             bit[15:14]����TSELW������д��Ĭ��ֵ01��
                                                             bit[17��16]����TRA����assist�������DR����mem��Ĭ��ֵ01��
                                                             ����bitδʹ�� */
        unsigned int  reserved          : 6;  /* bit[26-31]: ����ARC HD���͵�RAM
                                                             SPS����ʹ��bit[5:3][7:6]
                                                             SPA����ʹ��bit[13:11][15:14]
                                                             ��ʹ�� */
    } reg;
} SOC_CONFIG_HIEPS_MEM_CTRL_HD_UNION;
#endif
#define SOC_CONFIG_HIEPS_MEM_CTRL_HD_hieps_hd_mem_ctrl_START  (0)
#define SOC_CONFIG_HIEPS_MEM_CTRL_HD_hieps_hd_mem_ctrl_END    (25)


/*****************************************************************************
 �ṹ��    : SOC_CONFIG_HIEPS_MEM_CTRL_DPRAM_UNION
 �ṹ˵��  : HIEPS_MEM_CTRL_DPRAM �Ĵ����ṹ���塣��ַƫ����:0x20C����ֵ:0x00000850�����:32
 �Ĵ���˵��: 
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  hieps_dpram_mem_ctrl : 16; /* bit[0-15] : memory����
                                                                bit[0]����LS��
                                                                0����Ч
                                                                1������sleepģʽ
                                                                bit[1]����DSLP��
                                                                0����Ч
                                                                1������deep sleepģʽ
                                                                bit[2]����SD��
                                                                0����Ч
                                                                1������shut downģʽ
                                                                bit[5:4]����TSELR�����ڶ���Ĭ��ֵ01��
                                                                bit[7:6]����TSELW������д��Ĭ��ֵ01��
                                                                bit[10:8]����TEST������pin��Ĭ��ֵ000��
                                                                bit[12:11]������TRA����assist�������DR����mem��Ĭ��ֵ01
                                                                ����bitδʹ�á� */
        unsigned int  reserved             : 16; /* bit[16-31]: ����RSA/ECC/SM9 TPRAM */
    } reg;
} SOC_CONFIG_HIEPS_MEM_CTRL_DPRAM_UNION;
#endif
#define SOC_CONFIG_HIEPS_MEM_CTRL_DPRAM_hieps_dpram_mem_ctrl_START  (0)
#define SOC_CONFIG_HIEPS_MEM_CTRL_DPRAM_hieps_dpram_mem_ctrl_END    (15)


/*****************************************************************************
 �ṹ��    : SOC_CONFIG_HIEPS_MEM_CTRL_BPRAM_UNION
 �ṹ˵��  : HIEPS_MEM_CTRL_BPRAM �Ĵ����ṹ���塣��ַƫ����:0x210����ֵ:0x00004858�����:32
 �Ĵ���˵��: 
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  hieps_bpram_mem_ctrl : 16; /* bit[0-15] : memory����
                                                                bit[0]����LS��
                                                                0����Ч
                                                                1������sleepģʽ
                                                                bit[1]����DSLP��
                                                                0����Ч
                                                                1������deep sleepģʽ
                                                                bit[2]����SD��
                                                                0����Ч
                                                                1������shut downģʽ
                                                                bit[5:3]����TSELR�����ڶ���Ĭ��ֵ011��
                                                                bit[7:6]����TSELW������д��Ĭ��ֵ01��
                                                                bit[10:8]����TEST������pin��Ĭ��ֵ000��
                                                                bit[12:11]������TRA����assist�������DR����mem��Ĭ��ֵ01
                                                                bit[15:14]��TSELM��Ĭ��ֵ01
                                                                ����bitδʹ�á� */
        unsigned int  reserved             : 16; /* bit[16-31]: ����SM9 BPRAM */
    } reg;
} SOC_CONFIG_HIEPS_MEM_CTRL_BPRAM_UNION;
#endif
#define SOC_CONFIG_HIEPS_MEM_CTRL_BPRAM_hieps_bpram_mem_ctrl_START  (0)
#define SOC_CONFIG_HIEPS_MEM_CTRL_BPRAM_hieps_bpram_mem_ctrl_END    (15)


/*****************************************************************************
 �ṹ��    : SOC_CONFIG_HIEPS_INTR_MASK_UNION
 �ṹ˵��  : HIEPS_INTR_MASK �Ĵ����ṹ���塣��ַƫ����:0x214����ֵ:0x00001F7E�����:32
 �Ĵ���˵��: �ж�MASK
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved_0            : 1;  /* bit[0]    : reserved */
        unsigned int  cfg_alarm_km_mask     : 1;  /* bit[1]    : 1��:���Σ����͸��ⲿ�жϣ�Ĭ������
                                                                 0�������� */
        unsigned int  cfg_alarm_sce_mask    : 1;  /* bit[2]    : Ĭ������ */
        unsigned int  cfg_alarm_rsa_mask    : 1;  /* bit[3]    : Ĭ������ */
        unsigned int  cfg_alarm_ecc_mask    : 1;  /* bit[4]    : Ĭ������ */
        unsigned int  cfg_alarm_trng_mask   : 1;  /* bit[5]    : Ĭ������ */
        unsigned int  cfg_int_trng_mask     : 1;  /* bit[6]    : Ĭ������ */
        unsigned int  reserved_1            : 1;  /* bit[7]    : reserved */
        unsigned int  cfg_alarm_sm9_mask    : 1;  /* bit[8]    : Ĭ������ */
        unsigned int  cfg_alarm_ddrenc_mask : 1;  /* bit[9]    : Ĭ������ */
        unsigned int  cfg_alarm_sce2_mask   : 1;  /* bit[10]   : Ĭ������ */
        unsigned int  cfg_alarm_rsa3_mask   : 1;  /* bit[11]   : Ĭ������ */
        unsigned int  cfg_alarm_rsa2_mask   : 1;  /* bit[12]   : Ĭ������ */
        unsigned int  reserved_2            : 1;  /* bit[13]   : reserved */
        unsigned int  reserved_3            : 1;  /* bit[14]   : reserved */
        unsigned int  reserved_4            : 1;  /* bit[15]   : reserved */
        unsigned int  reserved_5            : 1;  /* bit[16]   : reserved */
        unsigned int  reserved_6            : 15; /* bit[17-31]: ���������ALARM�ź�Ϊ�͸�AP��ALARM */
    } reg;
} SOC_CONFIG_HIEPS_INTR_MASK_UNION;
#endif
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_alarm_km_mask_START      (1)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_alarm_km_mask_END        (1)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_alarm_sce_mask_START     (2)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_alarm_sce_mask_END       (2)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_alarm_rsa_mask_START     (3)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_alarm_rsa_mask_END       (3)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_alarm_ecc_mask_START     (4)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_alarm_ecc_mask_END       (4)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_alarm_trng_mask_START    (5)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_alarm_trng_mask_END      (5)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_int_trng_mask_START      (6)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_int_trng_mask_END        (6)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_alarm_sm9_mask_START     (8)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_alarm_sm9_mask_END       (8)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_alarm_ddrenc_mask_START  (9)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_alarm_ddrenc_mask_END    (9)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_alarm_sce2_mask_START    (10)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_alarm_sce2_mask_END      (10)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_alarm_rsa3_mask_START    (11)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_alarm_rsa3_mask_END      (11)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_alarm_rsa2_mask_START    (12)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_alarm_rsa2_mask_END      (12)


/*****************************************************************************
 �ṹ��    : SOC_CONFIG_HIEPS_SEC_CTRL_UNION
 �ṹ˵��  : HIEPS_SEC_CTRL �Ĵ����ṹ���塣��ַƫ����:0x218����ֵ:0x00000028�����:32
 �Ĵ���˵��: 
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  hieps2lm_busy        : 3;  /* bit[0-2] : ÿbit������ʾ��������������ĸ�ģ��Ĺ���״̬��
                                                               1��������load_monitor��״̬Ϊbusy��
                                                               0��������load_monitor��״̬Ϊidle�� */
        unsigned int  hieps_perf_stat_en   : 1;  /* bit[3]   : ֻ�ܾ�̬���á�
                                                               Ĭ�Ͽ����Ǽ���ͨ��
                                                               1������perf_stat���EPS AXI���߲�����
                                                               0��������perf_stat���EPS AXI���߲��� */
        unsigned int  hieps2qic_disable    : 1;  /* bit[4]   : ֻ�ܾ�̬���á�
                                                               �رպ��޷���ѯHiEPS QIC�Ƿ��в�����pending trans����
                                                               1���رգ����ɲ�ѯ��
                                                               0��Ĭ��Ϊ0 ���ɲ�ѯ */
        unsigned int  hieps_perf_stat_en_1 : 1;  /* bit[5]   : ֻ�ܾ�̬���á�
                                                               Ĭ�Ͽ�������ͨ��
                                                               1������perf_stat���EPS AXI���߲�����
                                                               0��������perf_stat���EPS AXI���߲��� */
        unsigned int  cfg_trust2prot_en    : 1;  /* bit[6]   : ����MMU���ڴ��Ĳ���Ȩ�ޣ�
                                                               1��MMU���ڵ�Ȩ��Ϊprotected��
                                                               0��MMU���ڵ�Ȩ��ΪNon-trusted�� */
        unsigned int  eps_debug_rma_en     : 1;  /* bit[7]   : RMA ģʽ�µĵ���Ȩ�޿����ź�
                                                               0������
                                                               1�������� */
        unsigned int  hieps2dmss_sec_lock  : 1;  /* bit[8]   : bus monitor�Ƿ�����debug��ʹ�ܿ��ƣ�
                                                               0������bus monitor ���EPS��MEDIA2
                                                               1��������bus monitor ���EPS��MEDIA2 */
        unsigned int  reserved             : 23; /* bit[9-31]:  */
    } reg;
} SOC_CONFIG_HIEPS_SEC_CTRL_UNION;
#endif
#define SOC_CONFIG_HIEPS_SEC_CTRL_hieps2lm_busy_START         (0)
#define SOC_CONFIG_HIEPS_SEC_CTRL_hieps2lm_busy_END           (2)
#define SOC_CONFIG_HIEPS_SEC_CTRL_hieps_perf_stat_en_START    (3)
#define SOC_CONFIG_HIEPS_SEC_CTRL_hieps_perf_stat_en_END      (3)
#define SOC_CONFIG_HIEPS_SEC_CTRL_hieps2qic_disable_START     (4)
#define SOC_CONFIG_HIEPS_SEC_CTRL_hieps2qic_disable_END       (4)
#define SOC_CONFIG_HIEPS_SEC_CTRL_hieps_perf_stat_en_1_START  (5)
#define SOC_CONFIG_HIEPS_SEC_CTRL_hieps_perf_stat_en_1_END    (5)
#define SOC_CONFIG_HIEPS_SEC_CTRL_cfg_trust2prot_en_START     (6)
#define SOC_CONFIG_HIEPS_SEC_CTRL_cfg_trust2prot_en_END       (6)
#define SOC_CONFIG_HIEPS_SEC_CTRL_eps_debug_rma_en_START      (7)
#define SOC_CONFIG_HIEPS_SEC_CTRL_eps_debug_rma_en_END        (7)
#define SOC_CONFIG_HIEPS_SEC_CTRL_hieps2dmss_sec_lock_START   (8)
#define SOC_CONFIG_HIEPS_SEC_CTRL_hieps2dmss_sec_lock_END     (8)


/*****************************************************************************
 �ṹ��    : SOC_CONFIG_HIEPS_QIC_ENC_CTRL_UNION
 �ṹ˵��  : HIEPS_QIC_ENC_CTRL �Ĵ����ṹ���塣��ַƫ����:0x21C����ֵ:0x00000000�����:32
 �Ĵ���˵��: ����ͨ��QIC���ƼĴ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  hieps2qic_enc_awMainPress : 2;  /* bit[0-1]  : ��̬���ã�Ĭ��ֵΪ0��ARC����HIEPS QIC�ļ���дͨ����mainPress���ƣ�����QIC bufferˮ�ߵ���ֵ��λ����QOS��������ʱ��QIC�Ѿ���ѹEPSʱ�������ã������Կ�������mainPress�� */
        unsigned int  axi_enc_awqos             : 4;  /* bit[2-5]  : ��̬���ã�HIEPS��QIC�Խӵļ���дͨ����AXI master�ڵ�QOSֵ */
        unsigned int  axi_enc_region            : 4;  /* bit[6-9]  : ��̬���ã�HIEPS��QIC�Խӵ�AXI master�ڵ�regionֵ������ͨ�� */
        unsigned int  hieps2qic_enc_arMainPress : 2;  /* bit[10-11]: ��̬���ã�Ĭ��ֵΪ0��ARC����HIEPS QIC�ļ��ܶ�ͨ����mainPress���ƣ�����QIC bufferˮ�ߵ���ֵ��λ����QOS��������ʱ��QIC�Ѿ���ѹEPSʱ�������ã������Կ�������mainPress�� */
        unsigned int  axi_enc_arqos             : 4;  /* bit[12-15]: ��̬���ã�HIEPS��QIC�Խӵļ��ܶ�ͨ����AXI master�ڵ�QOSֵ */
        unsigned int  reserved                  : 16; /* bit[16-31]:  */
    } reg;
} SOC_CONFIG_HIEPS_QIC_ENC_CTRL_UNION;
#endif
#define SOC_CONFIG_HIEPS_QIC_ENC_CTRL_hieps2qic_enc_awMainPress_START  (0)
#define SOC_CONFIG_HIEPS_QIC_ENC_CTRL_hieps2qic_enc_awMainPress_END    (1)
#define SOC_CONFIG_HIEPS_QIC_ENC_CTRL_axi_enc_awqos_START              (2)
#define SOC_CONFIG_HIEPS_QIC_ENC_CTRL_axi_enc_awqos_END                (5)
#define SOC_CONFIG_HIEPS_QIC_ENC_CTRL_axi_enc_region_START             (6)
#define SOC_CONFIG_HIEPS_QIC_ENC_CTRL_axi_enc_region_END               (9)
#define SOC_CONFIG_HIEPS_QIC_ENC_CTRL_hieps2qic_enc_arMainPress_START  (10)
#define SOC_CONFIG_HIEPS_QIC_ENC_CTRL_hieps2qic_enc_arMainPress_END    (11)
#define SOC_CONFIG_HIEPS_QIC_ENC_CTRL_axi_enc_arqos_START              (12)
#define SOC_CONFIG_HIEPS_QIC_ENC_CTRL_axi_enc_arqos_END                (15)


/*****************************************************************************
 �ṹ��    : SOC_CONFIG_HIEPS_ALARM_STAT_UNION
 �ṹ˵��  : HIEPS_ALARM_STAT �Ĵ����ṹ���塣��ַƫ����:0x220����ֵ:0x00000000�����:32
 �Ĵ���˵��: ALARM��״̬�Ĵ�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  alarm_km_stat     : 1;  /* bit[0]    : alarm��״̬��
                                                             1����alarm
                                                             0:��alarm */
        unsigned int  alarm_sce_stat    : 1;  /* bit[1]    : ͬbit0 */
        unsigned int  alarm_rsa_stat    : 1;  /* bit[2]    : ͬbit0 */
        unsigned int  alarm_ecc_stat    : 1;  /* bit[3]    : ͬbit0 */
        unsigned int  alarm_trng_stat   : 1;  /* bit[4]    : ͬbit0 */
        unsigned int  int_trng_stat     : 1;  /* bit[5]    : ͬbit0 */
        unsigned int  alarm_sm9_stat    : 1;  /* bit[6]    : ͬbit0 */
        unsigned int  alarm_ddrenc_stat : 1;  /* bit[7]    : ͬbit0 */
        unsigned int  alarm_sce2_stat   : 1;  /* bit[8]    : ͬbit0 */
        unsigned int  alarm_rsa3_stat   : 1;  /* bit[9]    : ͬbit0 */
        unsigned int  alarm_rsa2_stat   : 1;  /* bit[10]   : ͬbit0 */
        unsigned int  reserved          : 21; /* bit[11-31]: ����Ĵ����ϱ���ALARM�ź�Ϊmask֮���ALARM */
    } reg;
} SOC_CONFIG_HIEPS_ALARM_STAT_UNION;
#endif
#define SOC_CONFIG_HIEPS_ALARM_STAT_alarm_km_stat_START      (0)
#define SOC_CONFIG_HIEPS_ALARM_STAT_alarm_km_stat_END        (0)
#define SOC_CONFIG_HIEPS_ALARM_STAT_alarm_sce_stat_START     (1)
#define SOC_CONFIG_HIEPS_ALARM_STAT_alarm_sce_stat_END       (1)
#define SOC_CONFIG_HIEPS_ALARM_STAT_alarm_rsa_stat_START     (2)
#define SOC_CONFIG_HIEPS_ALARM_STAT_alarm_rsa_stat_END       (2)
#define SOC_CONFIG_HIEPS_ALARM_STAT_alarm_ecc_stat_START     (3)
#define SOC_CONFIG_HIEPS_ALARM_STAT_alarm_ecc_stat_END       (3)
#define SOC_CONFIG_HIEPS_ALARM_STAT_alarm_trng_stat_START    (4)
#define SOC_CONFIG_HIEPS_ALARM_STAT_alarm_trng_stat_END      (4)
#define SOC_CONFIG_HIEPS_ALARM_STAT_int_trng_stat_START      (5)
#define SOC_CONFIG_HIEPS_ALARM_STAT_int_trng_stat_END        (5)
#define SOC_CONFIG_HIEPS_ALARM_STAT_alarm_sm9_stat_START     (6)
#define SOC_CONFIG_HIEPS_ALARM_STAT_alarm_sm9_stat_END       (6)
#define SOC_CONFIG_HIEPS_ALARM_STAT_alarm_ddrenc_stat_START  (7)
#define SOC_CONFIG_HIEPS_ALARM_STAT_alarm_ddrenc_stat_END    (7)
#define SOC_CONFIG_HIEPS_ALARM_STAT_alarm_sce2_stat_START    (8)
#define SOC_CONFIG_HIEPS_ALARM_STAT_alarm_sce2_stat_END      (8)
#define SOC_CONFIG_HIEPS_ALARM_STAT_alarm_rsa3_stat_START    (9)
#define SOC_CONFIG_HIEPS_ALARM_STAT_alarm_rsa3_stat_END      (9)
#define SOC_CONFIG_HIEPS_ALARM_STAT_alarm_rsa2_stat_START    (10)
#define SOC_CONFIG_HIEPS_ALARM_STAT_alarm_rsa2_stat_END      (10)


/*****************************************************************************
 �ṹ��    : SOC_CONFIG_HIEPS_STAT_UNION
 �ṹ˵��  : HIEPS_STAT �Ĵ����ṹ���塣��ַƫ����:0x224����ֵ:0x00000000�����:32
 �Ĵ���˵��: HIEPSϵͳ״̬
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  hieps_lcs_4bit : 4;  /* bit[0-3] : HIEPS����������״̬��
                                                         4'b0000:ICCT
                                                         4'b0001:ICDT
                                                         4'b0011:UM
                                                         4'b0111:��lcs_rmaΪ1ʱ,0111��ʾRMA����lcs_rmaΪ0,0111��ʾSDMRM
                                                         others:SDM */
        unsigned int  hw_rd_finish   : 1;  /* bit[4]   : efuse�͸�eps���ź��Ƿ���Ч
                                                         1����Ч */
        unsigned int  lcs_rma        : 1;  /* bit[5]   : Lcs_ram�����������жϣ�
                                                         1��RMA��������
                                                         0�������������� */
        unsigned int  reserved       : 26; /* bit[6-31]:  */
    } reg;
} SOC_CONFIG_HIEPS_STAT_UNION;
#endif
#define SOC_CONFIG_HIEPS_STAT_hieps_lcs_4bit_START  (0)
#define SOC_CONFIG_HIEPS_STAT_hieps_lcs_4bit_END    (3)
#define SOC_CONFIG_HIEPS_STAT_hw_rd_finish_START    (4)
#define SOC_CONFIG_HIEPS_STAT_hw_rd_finish_END      (4)
#define SOC_CONFIG_HIEPS_STAT_lcs_rma_START         (5)
#define SOC_CONFIG_HIEPS_STAT_lcs_rma_END           (5)


/*****************************************************************************
 �ṹ��    : SOC_CONFIG_HIEPS_EFUSE_CTRL_STAT_UNION
 �ṹ˵��  : HIEPS_EFUSE_CTRL_STAT �Ĵ����ṹ���塣��ַƫ����:0x228����ֵ:0x00000A00�����:32
 �Ĵ���˵��: efuse����״̬
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  eps_debug_disable       : 4;  /* bit[0-3]  : EPS UMģʽ�µĵ��Կ����źţ�
                                                                   4'h0:������ԣ�
                                                                   ����ֵ��������ԡ� */
        unsigned int  km_debug_disable        : 4;  /* bit[4-7]  : KM��key�ļĴ����ϱ������źţ�
                                                                   0�����ϱ�
                                                                   ����ֵ���ϱ� */
        unsigned int  misc2crypto_smx_disable : 4;  /* bit[8-11] : �������������ʹ�ܣ�
                                                                   4'h5:�����㷨����ʹ��
                                                                   4'ha:�����㷨����ʹ�� */
        unsigned int  reserved                : 20; /* bit[12-31]:  */
    } reg;
} SOC_CONFIG_HIEPS_EFUSE_CTRL_STAT_UNION;
#endif
#define SOC_CONFIG_HIEPS_EFUSE_CTRL_STAT_eps_debug_disable_START        (0)
#define SOC_CONFIG_HIEPS_EFUSE_CTRL_STAT_eps_debug_disable_END          (3)
#define SOC_CONFIG_HIEPS_EFUSE_CTRL_STAT_km_debug_disable_START         (4)
#define SOC_CONFIG_HIEPS_EFUSE_CTRL_STAT_km_debug_disable_END           (7)
#define SOC_CONFIG_HIEPS_EFUSE_CTRL_STAT_misc2crypto_smx_disable_START  (8)
#define SOC_CONFIG_HIEPS_EFUSE_CTRL_STAT_misc2crypto_smx_disable_END    (11)


/*****************************************************************************
 �ṹ��    : SOC_CONFIG_HIEPS_MMU_WID_UNION
 �ṹ˵��  : HIEPS_MMU_WID �Ĵ����ṹ���塣��ַƫ����:0x300����ֵ:0x00010000�����:32
 �Ĵ���˵��: SCE1дͨ����ID����
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  awmmusid_s0    : 8;  /* bit[0-7]  : SCE1дͨ��Stream ID��
                                                          Media2��SMMU��masterͳһ���䡣 */
        unsigned int  awmmussid_s0   : 8;  /* bit[8-15] : SCE1дͨ��Sub Stream ID */
        unsigned int  awmmusecsid_s0 : 1;  /* bit[16]   : SCE1дͨ��Stream ID Secure flag�źš�
                                                          0: ��ǰҳ�������non-secure�ġ�
                                                          1: ��ǰҳ�������secure�ġ� */
        unsigned int  awmmussidv_s0  : 1;  /* bit[17]   : SCE1дͨ��Sub Stream ID validָʾ�źš�
                                                          0: SSID��Ч����ʹ��SSID���ж�̬ҳ���л���
                                                          1: SSID��Ч��ʹ��SSID���ж�̬ҳ���л��� */
        unsigned int  reserved       : 14; /* bit[18-31]: reserved */
    } reg;
} SOC_CONFIG_HIEPS_MMU_WID_UNION;
#endif
#define SOC_CONFIG_HIEPS_MMU_WID_awmmusid_s0_START     (0)
#define SOC_CONFIG_HIEPS_MMU_WID_awmmusid_s0_END       (7)
#define SOC_CONFIG_HIEPS_MMU_WID_awmmussid_s0_START    (8)
#define SOC_CONFIG_HIEPS_MMU_WID_awmmussid_s0_END      (15)
#define SOC_CONFIG_HIEPS_MMU_WID_awmmusecsid_s0_START  (16)
#define SOC_CONFIG_HIEPS_MMU_WID_awmmusecsid_s0_END    (16)
#define SOC_CONFIG_HIEPS_MMU_WID_awmmussidv_s0_START   (17)
#define SOC_CONFIG_HIEPS_MMU_WID_awmmussidv_s0_END     (17)


/*****************************************************************************
 �ṹ��    : SOC_CONFIG_HIEPS_MMU_RID_UNION
 �ṹ˵��  : HIEPS_MMU_RID �Ĵ����ṹ���塣��ַƫ����:0x304����ֵ:0x00010000�����:32
 �Ĵ���˵��: SCE1��ͨ����ID����
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  armmusid_s0    : 8;  /* bit[0-7]  : SCE1��ͨ��Stream ID��
                                                          Media2��SMMU��masterͳһ���䡣 */
        unsigned int  armmussid_s0   : 8;  /* bit[8-15] : SCE1��ͨ��Sub Stream ID */
        unsigned int  armmusecsid_s0 : 1;  /* bit[16]   : SCE1��ͨ��Stream ID Secure flag�źš�
                                                          0: ��ǰҳ�������non-secure�ġ�
                                                          1: ��ǰҳ�������secure�ġ� */
        unsigned int  armmussidv_s0  : 1;  /* bit[17]   : SCE1��ͨ��Sub Stream ID validָʾ�źš�
                                                          0: SSID��Ч����ʹ��SSID���ж�̬ҳ���л���
                                                          1: SSID��Ч��ʹ��SSID���ж�̬ҳ���л��� */
        unsigned int  reserved       : 14; /* bit[18-31]: reserved */
    } reg;
} SOC_CONFIG_HIEPS_MMU_RID_UNION;
#endif
#define SOC_CONFIG_HIEPS_MMU_RID_armmusid_s0_START     (0)
#define SOC_CONFIG_HIEPS_MMU_RID_armmusid_s0_END       (7)
#define SOC_CONFIG_HIEPS_MMU_RID_armmussid_s0_START    (8)
#define SOC_CONFIG_HIEPS_MMU_RID_armmussid_s0_END      (15)
#define SOC_CONFIG_HIEPS_MMU_RID_armmusecsid_s0_START  (16)
#define SOC_CONFIG_HIEPS_MMU_RID_armmusecsid_s0_END    (16)
#define SOC_CONFIG_HIEPS_MMU_RID_armmussidv_s0_START   (17)
#define SOC_CONFIG_HIEPS_MMU_RID_armmussidv_s0_END     (17)


/*****************************************************************************
 �ṹ��    : SOC_CONFIG_HIEPS_MMU_PREID_UNION
 �ṹ˵��  : HIEPS_MMU_PREID �Ĵ����ṹ���塣��ַƫ����:0x308����ֵ:0x00000001�����:32
 �Ĵ���˵��: SCE1Ԥȡ����ID
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  armmuswid_s0 : 8;  /* bit[0-7]  : SCE1��ͨ��Ԥȡ����ID */
        unsigned int  awmmuswid_s0 : 8;  /* bit[8-15] : SCE1дͨ��Ԥȡ����ID */
        unsigned int  reserved     : 16; /* bit[16-31]: reserved */
    } reg;
} SOC_CONFIG_HIEPS_MMU_PREID_UNION;
#endif
#define SOC_CONFIG_HIEPS_MMU_PREID_armmuswid_s0_START  (0)
#define SOC_CONFIG_HIEPS_MMU_PREID_armmuswid_s0_END    (7)
#define SOC_CONFIG_HIEPS_MMU_PREID_awmmuswid_s0_START  (8)
#define SOC_CONFIG_HIEPS_MMU_PREID_awmmuswid_s0_END    (15)


/*****************************************************************************
 �ṹ��    : SOC_CONFIG_HIEPS_MMU2_WID_UNION
 �ṹ˵��  : HIEPS_MMU2_WID �Ĵ����ṹ���塣��ַƫ����:0x30C����ֵ:0x00010000�����:32
 �Ĵ���˵��: SCE2дͨ����ID����
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  awmmusid_s1    : 8;  /* bit[0-7]  : SCE2дͨ��Stream ID��
                                                          Media2��SMMU��masterͳһ���䡣 */
        unsigned int  awmmussid_s1   : 8;  /* bit[8-15] : SCE2дͨ��Sub Stream ID */
        unsigned int  awmmusecsid_s1 : 1;  /* bit[16]   : SCE2дͨ��Stream ID Secure flag�źš�
                                                          0: ��ǰҳ�������non-secure�ġ�
                                                          1: ��ǰҳ�������secure�ġ� */
        unsigned int  awmmussidv_s1  : 1;  /* bit[17]   : SCE2дͨ��Sub Stream ID validָʾ�źš�
                                                          0: SSID��Ч����ʹ��SSID���ж�̬ҳ���л���
                                                          1: SSID��Ч��ʹ��SSID���ж�̬ҳ���л��� */
        unsigned int  reserved       : 14; /* bit[18-31]: reserved */
    } reg;
} SOC_CONFIG_HIEPS_MMU2_WID_UNION;
#endif
#define SOC_CONFIG_HIEPS_MMU2_WID_awmmusid_s1_START     (0)
#define SOC_CONFIG_HIEPS_MMU2_WID_awmmusid_s1_END       (7)
#define SOC_CONFIG_HIEPS_MMU2_WID_awmmussid_s1_START    (8)
#define SOC_CONFIG_HIEPS_MMU2_WID_awmmussid_s1_END      (15)
#define SOC_CONFIG_HIEPS_MMU2_WID_awmmusecsid_s1_START  (16)
#define SOC_CONFIG_HIEPS_MMU2_WID_awmmusecsid_s1_END    (16)
#define SOC_CONFIG_HIEPS_MMU2_WID_awmmussidv_s1_START   (17)
#define SOC_CONFIG_HIEPS_MMU2_WID_awmmussidv_s1_END     (17)


/*****************************************************************************
 �ṹ��    : SOC_CONFIG_HIEPS_MMU2_RID_UNION
 �ṹ˵��  : HIEPS_MMU2_RID �Ĵ����ṹ���塣��ַƫ����:0x310����ֵ:0x00010000�����:32
 �Ĵ���˵��: SCE2��ͨ����ID����
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  armmusid_s1    : 8;  /* bit[0-7]  : SCE2��ͨ��Stream ID��
                                                          Media2��SMMU��masterͳһ���䡣 */
        unsigned int  armmussid_s1   : 8;  /* bit[8-15] : SCE2��ͨ��Sub Stream ID */
        unsigned int  armmusecsid_s1 : 1;  /* bit[16]   : SCE2��ͨ��Stream ID Secure flag�źš�
                                                          0: ��ǰҳ�������non-secure�ġ�
                                                          1: ��ǰҳ�������secure�ġ� */
        unsigned int  armmussidv_s1  : 1;  /* bit[17]   : SCE2��ͨ��Sub Stream ID validָʾ�źš�
                                                          0: SSID��Ч����ʹ��SSID���ж�̬ҳ���л���
                                                          1: SSID��Ч��ʹ��SSID���ж�̬ҳ���л��� */
        unsigned int  reserved       : 14; /* bit[18-31]: reserved */
    } reg;
} SOC_CONFIG_HIEPS_MMU2_RID_UNION;
#endif
#define SOC_CONFIG_HIEPS_MMU2_RID_armmusid_s1_START     (0)
#define SOC_CONFIG_HIEPS_MMU2_RID_armmusid_s1_END       (7)
#define SOC_CONFIG_HIEPS_MMU2_RID_armmussid_s1_START    (8)
#define SOC_CONFIG_HIEPS_MMU2_RID_armmussid_s1_END      (15)
#define SOC_CONFIG_HIEPS_MMU2_RID_armmusecsid_s1_START  (16)
#define SOC_CONFIG_HIEPS_MMU2_RID_armmusecsid_s1_END    (16)
#define SOC_CONFIG_HIEPS_MMU2_RID_armmussidv_s1_START   (17)
#define SOC_CONFIG_HIEPS_MMU2_RID_armmussidv_s1_END     (17)


/*****************************************************************************
 �ṹ��    : SOC_CONFIG_HIEPS_MMU2_PREID_UNION
 �ṹ˵��  : HIEPS_MMU2_PREID �Ĵ����ṹ���塣��ַƫ����:0x314����ֵ:0x00000203�����:32
 �Ĵ���˵��: SCE2Ԥȡ����ID
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  armmuswid_s1 : 8;  /* bit[0-7]  : SCE2��ͨ��Ԥȡ����ID */
        unsigned int  awmmuswid_s1 : 8;  /* bit[8-15] : SCE2дͨ��Ԥȡ����ID */
        unsigned int  reserved     : 16; /* bit[16-31]: reserved */
    } reg;
} SOC_CONFIG_HIEPS_MMU2_PREID_UNION;
#endif
#define SOC_CONFIG_HIEPS_MMU2_PREID_armmuswid_s1_START  (0)
#define SOC_CONFIG_HIEPS_MMU2_PREID_armmuswid_s1_END    (7)
#define SOC_CONFIG_HIEPS_MMU2_PREID_awmmuswid_s1_START  (8)
#define SOC_CONFIG_HIEPS_MMU2_PREID_awmmuswid_s1_END    (15)


/*****************************************************************************
 �ṹ��    : SOC_CONFIG_SCE_MST_PRIORITY_UNION
 �ṹ˵��  : SCE_MST_PRIORITY �Ĵ����ṹ���塣��ַƫ����:0x400����ֵ:0x00000001�����:32
 �Ĵ���˵��: ���������ȼ����üĴ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  sce_mst_priority_sce2to2  : 1;  /* bit[0]   : AXI 2to2��SCE���ȼ����� bit[0]��bit[1]���ʹ�ã�����Ϊ1�����ȼ���������Ϊ0�����ȼ�������������������ȼ���ͬ����SCE1���ȼ��� */
        unsigned int  sce2_mst_priority_sce2to2 : 1;  /* bit[1]   : AXI 2to2��SCE2���ȼ����� bit[0]��bit[1]���ʹ�ã�����Ϊ1�����ȼ���������Ϊ0�����ȼ�������������������ȼ���ͬ����SCE1���ȼ��� */
        unsigned int  reserved                  : 30; /* bit[2-31]: reserved */
    } reg;
} SOC_CONFIG_SCE_MST_PRIORITY_UNION;
#endif
#define SOC_CONFIG_SCE_MST_PRIORITY_sce_mst_priority_sce2to2_START   (0)
#define SOC_CONFIG_SCE_MST_PRIORITY_sce_mst_priority_sce2to2_END     (0)
#define SOC_CONFIG_SCE_MST_PRIORITY_sce2_mst_priority_sce2to2_START  (1)
#define SOC_CONFIG_SCE_MST_PRIORITY_sce2_mst_priority_sce2to2_END    (1)


/*****************************************************************************
 �ṹ��    : SOC_CONFIG_HIEPS_HINT_UNION
 �ṹ˵��  : HIEPS_HINT �Ĵ����ṹ���塣��ַƫ����:0x404����ֵ:0x00000000�����:32
 �Ĵ���˵��: hint�ź�����
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved_0  : 4;  /* bit[0-3]  : Arc��ͨ����hint�ź�����: ��axcacheΪnon_cacheable������£�4��h0��ʾ������system cache������ֵ�ɷ��ʵ�system cache */
        unsigned int  reserved_1  : 4;  /* bit[4-7]  : Arcдͨ����hint�ź�����: ��axcacheΪnon_cacheable������£�4��h0��ʾ������system cache������ֵ�ɷ��ʵ�system cache */
        unsigned int  sce_arhint  : 4;  /* bit[8-11] : Sce��ͨ����hint�ź�����: ��axcacheΪnon_cacheable������£�4��h0��ʾ������system cache������ֵ�ɷ��ʵ�system cache */
        unsigned int  sce_awhint  : 4;  /* bit[12-15]: Sceдͨ����hint�ź�����: ��axcacheΪnon_cacheable������£�4��h0��ʾ������system cache������ֵ�ɷ��ʵ�system cache */
        unsigned int  sce2_arhint : 4;  /* bit[16-19]: Sce2��ͨ����hint�ź�����: ��axcacheΪnon_cacheable������£�4��h0��ʾ������system cache������ֵ�ɷ��ʵ�system cache */
        unsigned int  sce2_awhint : 4;  /* bit[20-23]: Sce2дͨ����hint�ź�����: ��axcacheΪnon_cacheable������£�4��h0��ʾ������system cache������ֵ�ɷ��ʵ�system cache */
        unsigned int  reserved_2  : 8;  /* bit[24-31]: reserved */
    } reg;
} SOC_CONFIG_HIEPS_HINT_UNION;
#endif
#define SOC_CONFIG_HIEPS_HINT_sce_arhint_START   (8)
#define SOC_CONFIG_HIEPS_HINT_sce_arhint_END     (11)
#define SOC_CONFIG_HIEPS_HINT_sce_awhint_START   (12)
#define SOC_CONFIG_HIEPS_HINT_sce_awhint_END     (15)
#define SOC_CONFIG_HIEPS_HINT_sce2_arhint_START  (16)
#define SOC_CONFIG_HIEPS_HINT_sce2_arhint_END    (19)
#define SOC_CONFIG_HIEPS_HINT_sce2_awhint_START  (20)
#define SOC_CONFIG_HIEPS_HINT_sce2_awhint_END    (23)


/*****************************************************************************
 �ṹ��    : SOC_CONFIG_REG_RESERVED10_UNION
 �ṹ˵��  : REG_RESERVED10 �Ĵ����ṹ���塣��ַƫ����:0x420����ֵ:0x00000000�����:32
 �Ĵ���˵��: 
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved : 32; /* bit[0-31]: reserved */
    } reg;
} SOC_CONFIG_REG_RESERVED10_UNION;
#endif


/*****************************************************************************
 �ṹ��    : SOC_CONFIG_REG_RESERVED11_UNION
 �ṹ˵��  : REG_RESERVED11 �Ĵ����ṹ���塣��ַƫ����:0x424����ֵ:0x00000000�����:32
 �Ĵ���˵��: 
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reserved : 32; /* bit[0-31]: reserved */
    } reg;
} SOC_CONFIG_REG_RESERVED11_UNION;
#endif


/*****************************************************************************
 �ṹ��    : SOC_CONFIG_HIEPS_RCV_STATE_UNION
 �ṹ˵��  : HIEPS_RCV_STATE �Ĵ����ṹ���塣��ַƫ����:0x500����ֵ:0x00000000�����:32
 �Ĵ���˵��: ѹ��״̬�Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  hieps_rcv_state : 32; /* bit[0-31]: bit0:hieps_kdr_rcv_state kdr��ѹ�����״ָ̬ʾ
                                                          bit1:hieps_gid_rcv_state gid��ѹ�����״ָ̬ʾ
                                                          bit2:hieps_gm_posk_rcv_stategm posk��ѹ�����״ָ̬ʾ
                                                          bit3:hieps_gm_rotpk_rcv_stategm rotpk��ѹ�����״ָ̬ʾ
                                                          bit4:hieps_gj_rotpk_rcv_stategj rotpk��ѹ�����״ָ̬ʾ
                                                          bit5:hieps_patch_rcv_state patch��ѹ�����״ָ̬ʾ
                                                          bit6-31:reserved */
    } reg;
} SOC_CONFIG_HIEPS_RCV_STATE_UNION;
#endif
#define SOC_CONFIG_HIEPS_RCV_STATE_hieps_rcv_state_START  (0)
#define SOC_CONFIG_HIEPS_RCV_STATE_hieps_rcv_state_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_CONFIG_REG_RW_RES1_UNION
 �ṹ˵��  : REG_RW_RES1 �Ĵ����ṹ���塣��ַƫ����:0x800����ֵ:0x00000000�����:32
 �Ĵ���˵��: �����Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reg_rw_res1 : 32; /* bit[0-31]: ���� */
    } reg;
} SOC_CONFIG_REG_RW_RES1_UNION;
#endif
#define SOC_CONFIG_REG_RW_RES1_reg_rw_res1_START  (0)
#define SOC_CONFIG_REG_RW_RES1_reg_rw_res1_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_CONFIG_REG_RW_RES2_UNION
 �ṹ˵��  : REG_RW_RES2 �Ĵ����ṹ���塣��ַƫ����:0x804����ֵ:0x00000000�����:32
 �Ĵ���˵��: �����Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reg_rw_res2 : 32; /* bit[0-31]: ���� */
    } reg;
} SOC_CONFIG_REG_RW_RES2_UNION;
#endif
#define SOC_CONFIG_REG_RW_RES2_reg_rw_res2_START  (0)
#define SOC_CONFIG_REG_RW_RES2_reg_rw_res2_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_CONFIG_REG_RO_RES1_UNION
 �ṹ˵��  : REG_RO_RES1 �Ĵ����ṹ���塣��ַƫ����:0x808����ֵ:0x00000000�����:32
 �Ĵ���˵��: �����Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  reg_ro_res1 : 32; /* bit[0-31]: ���� */
    } reg;
} SOC_CONFIG_REG_RO_RES1_UNION;
#endif
#define SOC_CONFIG_REG_RO_RES1_reg_ro_res1_START  (0)
#define SOC_CONFIG_REG_RO_RES1_reg_ro_res1_END    (31)






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

#endif /* end of soc_config_interface.h */
