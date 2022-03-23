/******************************************************************************

                 ��Ȩ���� (C), 2001-2019, ��Ϊ�������޹�˾

 ******************************************************************************
  �� �� ��   : soc_config_interface.h
  �� �� ��   : ����
  ��    ��   : Excel2Code
  ��������   : 2019-10-26 10:53:31
  ����޸�   :
  ��������   : �ӿ�ͷ�ļ�
  �����б�   :
  �޸���ʷ   :
  1.��    ��   : 2019��10��26��
    ��    ��   : l00249396
    �޸�����   : �ӡ�HiEPS V200 �Ĵ����ֲ�_CONFIG.xml���Զ�����

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
/* �Ĵ���˵����ARC ctrl register&#13;
   λ����UNION�ṹ:  SOC_CONFIG_ARC_CTRL0_UNION */
#define SOC_CONFIG_ARC_CTRL0_ADDR(base)               ((base) + (0x00))

/* �Ĵ���˵����arc���ƼĴ���
   λ����UNION�ṹ:  SOC_CONFIG_ARC_CTRL1_UNION */
#define SOC_CONFIG_ARC_CTRL1_ADDR(base)               ((base) + (0x04))

/* �Ĵ���˵����arc״̬�ض��Ĵ���
   λ����UNION�ṹ:  SOC_CONFIG_ARC_STATE_UNION */
#define SOC_CONFIG_ARC_STATE_ADDR(base)               ((base) + (0x08))

/* �Ĵ���˵����arc CTI��״̬
   λ����UNION�ṹ:  SOC_CONFIG_ARC_CTI_STATE_UNION */
#define SOC_CONFIG_ARC_CTI_STATE_ADDR(base)           ((base) + (0x0C))

/* �Ĵ���˵����ARC����DDR�Ļ����������üĴ�����
   λ����UNION�ṹ:  SOC_CONFIG_DDR_ACCESS_WINDOW_UNION */
#define SOC_CONFIG_DDR_ACCESS_WINDOW_ADDR(base)       ((base) + (0x10))

/* �Ĵ���˵����QIC ����źŵĿ��ƼĴ�����
   λ����UNION�ṹ:  SOC_CONFIG_QIC_CTRL_UNION */
#define SOC_CONFIG_QIC_CTRL_ADDR(base)                ((base) + (0x14))

/* �Ĵ���˵����ARC actionpoint�Ŀ�������Ĵ���
   λ����UNION�ṹ:  SOC_CONFIG_ARC_ACTIONPT_CMD_UNION */
#define SOC_CONFIG_ARC_ACTIONPT_CMD_ADDR(base)        ((base) + (0x18))

/* �Ĵ���˵����ARC��
   λ����UNION�ṹ:  SOC_CONFIG_ARC_AP_PARAM0_UNION */
#define SOC_CONFIG_ARC_AP_PARAM0_ADDR(base)           ((base) + (0x1C))

/* �Ĵ���˵����ARC��
   λ����UNION�ṹ:  SOC_CONFIG_ARC_AP_PARAM1_UNION */
#define SOC_CONFIG_ARC_AP_PARAM1_ADDR(base)           ((base) + (0x20))

/* �Ĵ���˵��������ת��ƽ���ж�����Ĵ���
   λ����UNION�ṹ:  SOC_CONFIG_ALARM_CLR_UNION */
#define SOC_CONFIG_ALARM_CLR_ADDR(base)               ((base) + (0x24))

/* �Ĵ���˵����enhance DDR����ʼ��ַ
   λ����UNION�ṹ:  SOC_CONFIG_ENHANCE_DDR_START_UNION */
#define SOC_CONFIG_ENHANCE_DDR_START_ADDR(base)       ((base) + (0x28))

/* �Ĵ���˵����enhance DDR�Ľ�����ַ
   λ����UNION�ṹ:  SOC_CONFIG_ENHANCE_DDR_END_UNION */
#define SOC_CONFIG_ENHANCE_DDR_END_ADDR(base)         ((base) + (0x2C))

/* �Ĵ���˵����ROM�������ƼĴ���
   λ����UNION�ṹ:  SOC_CONFIG_ROM_LOCK_EN_UNION */
#define SOC_CONFIG_ROM_LOCK_EN_ADDR(base)             ((base) + (0x30))

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

/* �Ĵ���˵����CRG���ƼĴ���0��
   λ����UNION�ṹ:  SOC_CONFIG_HIEPS_COMMON_CTRL1_UNION */
#define SOC_CONFIG_HIEPS_COMMON_CTRL1_ADDR(base)      ((base) + (0x124))

/* �Ĵ���˵����CRG���ƼĴ���0��
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

/* �Ĵ���˵����SPI/I2C���ÿ�������
   λ����UNION�ṹ:  SOC_CONFIG_HIEPS_SPI_I2C_CTRL_UNION */
#define SOC_CONFIG_HIEPS_SPI_I2C_CTRL_ADDR(base)      ((base) + (0x420))

/* �Ĵ���˵����SPI/I2C����״̬��ѯ
   λ����UNION�ṹ:  SOC_CONFIG_HIEPS_SPI_I2C_ACK_UNION */
#define SOC_CONFIG_HIEPS_SPI_I2C_ACK_ADDR(base)       ((base) + (0x424))

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
 �ṹ��    : SOC_CONFIG_ARC_CTRL0_UNION
 �ṹ˵��  : ARC_CTRL0 �Ĵ����ṹ���塣��ַƫ����:0x00����ֵ:0x000000F0�����:32
 �Ĵ���˵��: ARC ctrl register&#13;
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  arc_nmi                   : 1;  /* bit[0]    : NMI �жϣ�1��Ч�� */
        unsigned int  arc_nmi_ack_synced        : 1;  /* bit[1]    : arc ���յ�nmi�ж�ʱ�����ص�ack�źżĴ档 */
        unsigned int  eps_event_config          : 1;  /* bit[2]    : arc ͨ�����øüĴ�������event�������� */
        unsigned int  intr_as_event_en          : 1;  /* bit[3]    : EPS�ڲ����ж��Ƿ���ΪARC event����Դ��
                                                                     0���жϲ���ΪeventԴ��Ĭ�ϣ���
                                                                     1���ж���ΪeventԴ */
        unsigned int  event_i_extend_cycle      : 4;  /* bit[4-7]  : EPS �����event�¼�չ�����������AHBʱ�ӣ���Ĭ��15�ġ� */
        unsigned int  arc_dbg_cache_rst_disable : 1;  /* bit[8]    : ARC reset���Ƿ�cache�����ݽ�ֹ����Ŀ���
                                                                     0�����
                                                                     1����ֹ��� */
        unsigned int  cfg_arc_arcache           : 4;  /* bit[9-12] : ARC axi�ӿڶ�DDR��arcache�ź�����ֵ��arc2qic_axcache_muxΪ1ʱ��������Ч��Ϊ1ʱ��������Ч */
        unsigned int  cfg_arc_awcache           : 4;  /* bit[13-16]: ARC axi�ӿ�дDDR��awcache�ź�����ֵ��arc2qic_axcache_muxΪ1ʱ��������Ч��Ϊ0ʱ��������Ч */
        unsigned int  reserved                  : 15; /* bit[17-31]:  */
    } reg;
} SOC_CONFIG_ARC_CTRL0_UNION;
#endif
#define SOC_CONFIG_ARC_CTRL0_arc_nmi_START                    (0)
#define SOC_CONFIG_ARC_CTRL0_arc_nmi_END                      (0)
#define SOC_CONFIG_ARC_CTRL0_arc_nmi_ack_synced_START         (1)
#define SOC_CONFIG_ARC_CTRL0_arc_nmi_ack_synced_END           (1)
#define SOC_CONFIG_ARC_CTRL0_eps_event_config_START           (2)
#define SOC_CONFIG_ARC_CTRL0_eps_event_config_END             (2)
#define SOC_CONFIG_ARC_CTRL0_intr_as_event_en_START           (3)
#define SOC_CONFIG_ARC_CTRL0_intr_as_event_en_END             (3)
#define SOC_CONFIG_ARC_CTRL0_event_i_extend_cycle_START       (4)
#define SOC_CONFIG_ARC_CTRL0_event_i_extend_cycle_END         (7)
#define SOC_CONFIG_ARC_CTRL0_arc_dbg_cache_rst_disable_START  (8)
#define SOC_CONFIG_ARC_CTRL0_arc_dbg_cache_rst_disable_END    (8)
#define SOC_CONFIG_ARC_CTRL0_cfg_arc_arcache_START            (9)
#define SOC_CONFIG_ARC_CTRL0_cfg_arc_arcache_END              (12)
#define SOC_CONFIG_ARC_CTRL0_cfg_arc_awcache_START            (13)
#define SOC_CONFIG_ARC_CTRL0_cfg_arc_awcache_END              (16)


/*****************************************************************************
 �ṹ��    : SOC_CONFIG_ARC_CTRL1_UNION
 �ṹ˵��  : ARC_CTRL1 �Ĵ����ṹ���塣��ַƫ����:0x04����ֵ:0x00000201�����:32
 �Ĵ���˵��: arc���ƼĴ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  arcnum         : 8;  /* bit[0-7]  : arc core����Ŀ��Ĭ��ֵΪ1��Ŀǰarc���ˣ���������Ч�� */
        unsigned int  arc_clusternum : 8;  /* bit[8-15] : arc�˵�clusternum ��Ĭ��ֵΪ2��Ŀǰarc���ˣ���������Ч�� */
        unsigned int  reserved       : 16; /* bit[16-31]:  */
    } reg;
} SOC_CONFIG_ARC_CTRL1_UNION;
#endif
#define SOC_CONFIG_ARC_CTRL1_arcnum_START          (0)
#define SOC_CONFIG_ARC_CTRL1_arcnum_END            (7)
#define SOC_CONFIG_ARC_CTRL1_arc_clusternum_START  (8)
#define SOC_CONFIG_ARC_CTRL1_arc_clusternum_END    (15)


/*****************************************************************************
 �ṹ��    : SOC_CONFIG_ARC_STATE_UNION
 �ṹ˵��  : ARC_STATE �Ĵ����ṹ���塣��ַƫ����:0x08����ֵ:0x00000000�����:32
 �Ĵ���˵��: arc״̬�ض��Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  cti_rtt_filters_synced   : 26; /* bit[0-25] : cti�ض��źţ�trace �����ݲ�������Ŀǰδʹ�� */
        unsigned int  arc_run_ack_synced       : 1;  /* bit[26]   : �˷����յ�run���󷵻ص�arc_run_ack�źżĴ��� */
        unsigned int  arc_halt_ack_synced      : 1;  /* bit[27]   : �˷����յ�halt���󷵻ص�arc_halt_ack�źżĴ��� */
        unsigned int  arc_core_stalled_synced  : 1;  /* bit[28]   : ARC core ��ǰִ�е�ָ��δ��ɵ�ִ���źš� */
        unsigned int  arc_sys_tf_halt_r_synced : 1;  /* bit[29]   : ARC core����triple fault exception��״ָ̬ʾ�Ĵ� */
        unsigned int  reserved                 : 2;  /* bit[30-31]:  */
    } reg;
} SOC_CONFIG_ARC_STATE_UNION;
#endif
#define SOC_CONFIG_ARC_STATE_cti_rtt_filters_synced_START    (0)
#define SOC_CONFIG_ARC_STATE_cti_rtt_filters_synced_END      (25)
#define SOC_CONFIG_ARC_STATE_arc_run_ack_synced_START        (26)
#define SOC_CONFIG_ARC_STATE_arc_run_ack_synced_END          (26)
#define SOC_CONFIG_ARC_STATE_arc_halt_ack_synced_START       (27)
#define SOC_CONFIG_ARC_STATE_arc_halt_ack_synced_END         (27)
#define SOC_CONFIG_ARC_STATE_arc_core_stalled_synced_START   (28)
#define SOC_CONFIG_ARC_STATE_arc_core_stalled_synced_END     (28)
#define SOC_CONFIG_ARC_STATE_arc_sys_tf_halt_r_synced_START  (29)
#define SOC_CONFIG_ARC_STATE_arc_sys_tf_halt_r_synced_END    (29)


/*****************************************************************************
 �ṹ��    : SOC_CONFIG_ARC_CTI_STATE_UNION
 �ṹ˵��  : ARC_CTI_STATE �Ĵ����ṹ���塣��ַƫ����:0x0C����ֵ:0x00000000�����:32
 �Ĵ���˵��: arc CTI��״̬
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  arc_cti_ap_status_synced : 8;  /* bit[0-7] : ARC ��CTI״̬��trace �����ݲ�������Ŀǰδʹ�� */
        unsigned int  reserved                 : 24; /* bit[8-31]:  */
    } reg;
} SOC_CONFIG_ARC_CTI_STATE_UNION;
#endif
#define SOC_CONFIG_ARC_CTI_STATE_arc_cti_ap_status_synced_START  (0)
#define SOC_CONFIG_ARC_CTI_STATE_arc_cti_ap_status_synced_END    (7)


/*****************************************************************************
 �ṹ��    : SOC_CONFIG_DDR_ACCESS_WINDOW_UNION
 �ṹ˵��  : DDR_ACCESS_WINDOW �Ĵ����ṹ���塣��ַƫ����:0x10����ֵ:0x00000000�����:32
 �Ĵ���˵��: ARC����DDR�Ļ����������üĴ�����
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ddr_access_window : 32; /* bit[0-31]: ARC axi����ddr�ĵ�ַ�����Ĵ�����v200֧������Ϊ0����512M�� */
    } reg;
} SOC_CONFIG_DDR_ACCESS_WINDOW_UNION;
#endif
#define SOC_CONFIG_DDR_ACCESS_WINDOW_ddr_access_window_START  (0)
#define SOC_CONFIG_DDR_ACCESS_WINDOW_ddr_access_window_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_CONFIG_QIC_CTRL_UNION
 �ṹ˵��  : QIC_CTRL �Ĵ����ṹ���塣��ַƫ����:0x14����ֵ:0x013EFC00�����:32
 �Ĵ���˵��: QIC ����źŵĿ��ƼĴ�����
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  hieps2qic_unenc_awMainPress : 2;  /* bit[0-1]  : ��̬���ã�Ĭ��ֵΪ0��ARC����HIEPS QIC�ķǼ���дͨ����mainPress���ƣ�����QIC bufferˮ�ߵ���ֵ��λ����QOS��������ʱ��QIC�Ѿ���ѹEPSʱ�������ã������Կ�������mainPress�� */
        unsigned int  axi_unenc_awqos             : 4;  /* bit[2-5]  : ��̬���ã�HIEPS��QIC�ԽӵķǼ���дͨ����AXI master�ڵ�QOSֵ */
        unsigned int  axi_unenc_region            : 4;  /* bit[6-9]  : ��̬���ã�HIEPS��QIC�Խӵ�AXI master�ڵ�regionֵ���Ǽ���ͨ�� */
        unsigned int  sce_mst_mid                 : 6;  /* bit[10-15]: SCEͳһ�����Master ID�� */
        unsigned int  arc_mst_mid                 : 6;  /* bit[16-21]: ARCͳһ�����Master ID�� */
        unsigned int  qic2hieps_resp_mux          : 1;  /* bit[22]   : EPS����H2X��ʱ��H�˷��ص�response�Ƿ�ǿ��ת����okay response��mux���ơ�
                                                                       0��H�˷��ص�response��Ĭ�ϣ�����EBTʱ��H�� ����error response��
                                                                       1��ǿ��okay response */
        unsigned int  system_cache_hint_mux       : 1;  /* bit[23]   : ֻ����̬���ã�Ĭ��ֵΪ0
                                                                       0�����ض˿��ϵ�system cache hintΪ0������system cache��
                                                                       1��͸��MMU�����system cache hint�źŵ��˿��ϡ� */
        unsigned int  arc2qic_axcache_mux         : 1;  /* bit[24]   : ֻ����̬���á�Ĭ��ѡ��Ĵ������Ƶ�cacheable���ơ�
                                                                       ARC����DDR�Ĳ����Ƿ�ѡ������ɿص�cacheable�Ŀ��ƣ�
                                                                       0��ARC������axcache�ź�ָ����ʱaxcache[3��2]�̶�Ϊ0����2bit͸����
                                                                       1��ѡ��������Ƶ�axcache�ź�
                                                                       ��ARC����DDRʱ�������������Ϊcacheable�����������L3 cache������������й¶�ķ��գ� */
        unsigned int  hieps2qic_unenc_arMainPress : 2;  /* bit[25-26]: ��̬���ã�Ĭ��ֵΪ0��ARC����HIEPS QIC�ķǼ��ܶ�ͨ����mainPress���ƣ�����QIC bufferˮ�ߵ���ֵ��λ����QOS��������ʱ��QIC�Ѿ���ѹEPSʱ�������ã������Կ�������mainPress�� */
        unsigned int  axi_unenc_arqos             : 4;  /* bit[27-30]: ��̬���ã�HIEPS��QIC�ԽӵķǼ��ܶ�ͨ����AXI master�ڵ�QOSֵ */
        unsigned int  reserved                    : 1;  /* bit[31]   :  */
    } reg;
} SOC_CONFIG_QIC_CTRL_UNION;
#endif
#define SOC_CONFIG_QIC_CTRL_hieps2qic_unenc_awMainPress_START  (0)
#define SOC_CONFIG_QIC_CTRL_hieps2qic_unenc_awMainPress_END    (1)
#define SOC_CONFIG_QIC_CTRL_axi_unenc_awqos_START              (2)
#define SOC_CONFIG_QIC_CTRL_axi_unenc_awqos_END                (5)
#define SOC_CONFIG_QIC_CTRL_axi_unenc_region_START             (6)
#define SOC_CONFIG_QIC_CTRL_axi_unenc_region_END               (9)
#define SOC_CONFIG_QIC_CTRL_sce_mst_mid_START                  (10)
#define SOC_CONFIG_QIC_CTRL_sce_mst_mid_END                    (15)
#define SOC_CONFIG_QIC_CTRL_arc_mst_mid_START                  (16)
#define SOC_CONFIG_QIC_CTRL_arc_mst_mid_END                    (21)
#define SOC_CONFIG_QIC_CTRL_qic2hieps_resp_mux_START           (22)
#define SOC_CONFIG_QIC_CTRL_qic2hieps_resp_mux_END             (22)
#define SOC_CONFIG_QIC_CTRL_system_cache_hint_mux_START        (23)
#define SOC_CONFIG_QIC_CTRL_system_cache_hint_mux_END          (23)
#define SOC_CONFIG_QIC_CTRL_arc2qic_axcache_mux_START          (24)
#define SOC_CONFIG_QIC_CTRL_arc2qic_axcache_mux_END            (24)
#define SOC_CONFIG_QIC_CTRL_hieps2qic_unenc_arMainPress_START  (25)
#define SOC_CONFIG_QIC_CTRL_hieps2qic_unenc_arMainPress_END    (26)
#define SOC_CONFIG_QIC_CTRL_axi_unenc_arqos_START              (27)
#define SOC_CONFIG_QIC_CTRL_axi_unenc_arqos_END                (30)


/*****************************************************************************
 �ṹ��    : SOC_CONFIG_ARC_ACTIONPT_CMD_UNION
 �ṹ˵��  : ARC_ACTIONPT_CMD �Ĵ����ṹ���塣��ַƫ����:0x18����ֵ:0x00000000�����:32
 �Ĵ���˵��: ARC actionpoint�Ŀ�������Ĵ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  arc_ap_param0_read  : 1;  /* bit[0]   : Enable write actionpoints 
                                                              1��ʹ�ܣ�����ƥ��ֵ��ͬ�Ķ�����ʱ����action point
                                                              0����ʹ�� */
        unsigned int  arc_ap_param1_read  : 1;  /* bit[1]   : Enable write actionpoints 
                                                              1��ʹ�ܣ�����ƥ��ֵ��ͬ�Ķ�����ʱ����action point
                                                              0����ʹ�� */
        unsigned int  arc_ap_param0_write : 1;  /* bit[2]   : Enable write actionpoints 
                                                              1��ʹ�ܣ�����ƥ��ֵ��ͬ��д����ʱ����action point
                                                              0����ʹ�� */
        unsigned int  arc_ap_param1_write : 1;  /* bit[3]   : Enable write actionpoints 
                                                              1��ʹ�ܣ�����ƥ��ֵ��ͬ��д����ʱ����action point
                                                              0����ʹ�� */
        unsigned int  reserved            : 28; /* bit[4-31]: ARC ��չ��actionpoint�������ã���ARC��Ҳ����ͨ�����øüĴ���ͬ������ARC�ڲ���actionpoint */
    } reg;
} SOC_CONFIG_ARC_ACTIONPT_CMD_UNION;
#endif
#define SOC_CONFIG_ARC_ACTIONPT_CMD_arc_ap_param0_read_START   (0)
#define SOC_CONFIG_ARC_ACTIONPT_CMD_arc_ap_param0_read_END     (0)
#define SOC_CONFIG_ARC_ACTIONPT_CMD_arc_ap_param1_read_START   (1)
#define SOC_CONFIG_ARC_ACTIONPT_CMD_arc_ap_param1_read_END     (1)
#define SOC_CONFIG_ARC_ACTIONPT_CMD_arc_ap_param0_write_START  (2)
#define SOC_CONFIG_ARC_ACTIONPT_CMD_arc_ap_param0_write_END    (2)
#define SOC_CONFIG_ARC_ACTIONPT_CMD_arc_ap_param1_write_START  (3)
#define SOC_CONFIG_ARC_ACTIONPT_CMD_arc_ap_param1_write_END    (3)


/*****************************************************************************
 �ṹ��    : SOC_CONFIG_ARC_AP_PARAM0_UNION
 �ṹ˵��  : ARC_AP_PARAM0 �Ĵ����ṹ���塣��ַƫ����:0x1C����ֵ:0x00000000�����:32
 �Ĵ���˵��: ARC��
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  arc_ap_param0 : 32; /* bit[0-31]: ARC ��չ��actionpoint�������ã���ARC��Ҳ����ͨ�����øüĴ���ͬ������ARC�ڲ���actionpoint����һ��ƥ��ֵ */
    } reg;
} SOC_CONFIG_ARC_AP_PARAM0_UNION;
#endif
#define SOC_CONFIG_ARC_AP_PARAM0_arc_ap_param0_START  (0)
#define SOC_CONFIG_ARC_AP_PARAM0_arc_ap_param0_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_CONFIG_ARC_AP_PARAM1_UNION
 �ṹ˵��  : ARC_AP_PARAM1 �Ĵ����ṹ���塣��ַƫ����:0x20����ֵ:0x00000000�����:32
 �Ĵ���˵��: ARC��
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  arc_ap_param1 : 32; /* bit[0-31]: ARC ��չ��actionpoint�������ã���ARC��Ҳ����ͨ�����øüĴ���ͬ������ARC�ڲ���actionpoint���ڶ���ƥ��ֵ */
    } reg;
} SOC_CONFIG_ARC_AP_PARAM1_UNION;
#endif
#define SOC_CONFIG_ARC_AP_PARAM1_arc_ap_param1_START  (0)
#define SOC_CONFIG_ARC_AP_PARAM1_arc_ap_param1_END    (31)


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
        unsigned int  clr_npu_iso_posedge    : 1;  /* bit[0]   : NPUǶλʹ���ź��������жϵ������
                                                                 1�����
                                                                 0��û��Ч�� */
        unsigned int  clr_npu_rst_posedge    : 1;  /* bit[1]   : NPU��λ�ź��������жϵ������
                                                                 1�����
                                                                 0��û��Ч�� */
        unsigned int  clr_ddrenc_alarm_pulse : 1;  /* bit[2]   : 1�����alarm�ж�
                                                                 0��û��Ч�� */
        unsigned int  clr_npu_iso_negedge    : 1;  /* bit[3]   : NPUǶλʹ���ź��½����жϵ������
                                                                 1�����
                                                                 0��û��Ч�� */
        unsigned int  clr_npu_rst_negedge    : 1;  /* bit[4]   : NPU��λ�ź��½����жϵ������
                                                                 1�����
                                                                 0��û��Ч�� */
        unsigned int  reserved               : 27; /* bit[5-31]: 1�����alarm�ж�
                                                                 0��û��Ч�� */
    } reg;
} SOC_CONFIG_ALARM_CLR_UNION;
#endif
#define SOC_CONFIG_ALARM_CLR_clr_npu_iso_posedge_START     (0)
#define SOC_CONFIG_ALARM_CLR_clr_npu_iso_posedge_END       (0)
#define SOC_CONFIG_ALARM_CLR_clr_npu_rst_posedge_START     (1)
#define SOC_CONFIG_ALARM_CLR_clr_npu_rst_posedge_END       (1)
#define SOC_CONFIG_ALARM_CLR_clr_ddrenc_alarm_pulse_START  (2)
#define SOC_CONFIG_ALARM_CLR_clr_ddrenc_alarm_pulse_END    (2)
#define SOC_CONFIG_ALARM_CLR_clr_npu_iso_negedge_START     (3)
#define SOC_CONFIG_ALARM_CLR_clr_npu_iso_negedge_END       (3)
#define SOC_CONFIG_ALARM_CLR_clr_npu_rst_negedge_START     (4)
#define SOC_CONFIG_ALARM_CLR_clr_npu_rst_negedge_END       (4)


/*****************************************************************************
 �ṹ��    : SOC_CONFIG_ENHANCE_DDR_START_UNION
 �ṹ˵��  : ENHANCE_DDR_START �Ĵ����ṹ���塣��ַƫ����:0x28����ֵ:0x002CC000�����:32
 �Ĵ���˵��: enhance DDR����ʼ��ַ
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  enhance_ddr_start : 32; /* bit[0-31]: DDR�����EPS��enhance�������ʼ��ַ����ַ�����������ʼ��ַ */
    } reg;
} SOC_CONFIG_ENHANCE_DDR_START_UNION;
#endif
#define SOC_CONFIG_ENHANCE_DDR_START_enhance_ddr_start_START  (0)
#define SOC_CONFIG_ENHANCE_DDR_START_enhance_ddr_start_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_CONFIG_ENHANCE_DDR_END_UNION
 �ṹ˵��  : ENHANCE_DDR_END �Ĵ����ṹ���塣��ַƫ����:0x2C����ֵ:0x002CD000�����:32
 �Ĵ���˵��: enhance DDR�Ľ�����ַ
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  enhance_ddr_end : 32; /* bit[0-31]: DDR�����EPS��enhance����Ľ�����ַ����ַ���䲻�����ý�����ַ */
    } reg;
} SOC_CONFIG_ENHANCE_DDR_END_UNION;
#endif
#define SOC_CONFIG_ENHANCE_DDR_END_enhance_ddr_end_START  (0)
#define SOC_CONFIG_ENHANCE_DDR_END_enhance_ddr_end_END    (31)


/*****************************************************************************
 �ṹ��    : SOC_CONFIG_ROM_LOCK_EN_UNION
 �ṹ˵��  : ROM_LOCK_EN �Ĵ����ṹ���塣��ַƫ����:0x30����ֵ:0x0000000A�����:32
 �Ĵ���˵��: ROM�������ƼĴ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  prt_lock : 4;  /* bit[0-3] : ����üĴ���д���κ�ֵ��Ӳ���Զ�����Ϊ5��ROM����,���ܶ�ȡROM������ */
        unsigned int  reserved : 28; /* bit[4-31]: ���� */
    } reg;
} SOC_CONFIG_ROM_LOCK_EN_UNION;
#endif
#define SOC_CONFIG_ROM_LOCK_EN_prt_lock_START  (0)
#define SOC_CONFIG_ROM_LOCK_EN_prt_lock_END    (3)


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
        unsigned int  gt_pclk_hieps_ipc    : 1;  /* bit[0]    : IPCʱ�ӵ����ſ� */
        unsigned int  gt_pclk_hieps_wdog   : 1;  /* bit[1]    : WDOGʱ�ӵ����ſ� */
        unsigned int  gt_pclk_hieps_timer  : 1;  /* bit[2]    : TIMERʱ�ӵ����ſ� */
        unsigned int  gt_pclk_hieps_uart   : 1;  /* bit[3]    : UARTʱ�ӵ����ſ� */
        unsigned int  gt_pclk_hieps_trng   : 1;  /* bit[4]    : TRNGʱ�ӵ����ſ� */
        unsigned int  gt_clk_hieps_sce_km  : 1;  /* bit[5]    : SCE��KMʱ�ӵ����ſ� */
        unsigned int  gt_clk_hieps_pke     : 1;  /* bit[6]    : PKEʱ�ӵ����ſ� */
        unsigned int  gt_aclk_hieps_qic    : 1;  /* bit[7]    : ɾ��gt_clk_hieps_mmu_autogt������gt_aclk_hieps_qic */
        unsigned int  gt_clk_hieps_arc     : 1;  /* bit[8]    : ARC ��ʱ�ӵ����ſ� */
        unsigned int  gt_clk_hieps_arc_rtt : 1;  /* bit[9]    : ARC RTT�ӿڿ������ʱ�ӵ����ſ� */
        unsigned int  gt_clk_hieps_axi     : 1;  /* bit[10]   : AXI����ʱ�ӵ����ſ� */
        unsigned int  gt_clk_hieps_pdbg    : 1;  /* bit[11]   : ARC PDBG�ӿڿ������ʱ�ӵ����ſ� */
        unsigned int  gt_clk_hieps_atb     : 1;  /* bit[12]   : ARC ATB�ӿڿ������ʱ�ӵ����ſ� */
        unsigned int  gt_clk_hieps_mmu     : 1;  /* bit[13]   : MMU�����ſ� */
        unsigned int  gt_clk_ddr_crpt      : 1;  /* bit[14]   : DDR����ʱ�ӵ����ſ� */
        unsigned int  gt_clk_hieps_cmp     : 1;  /* bit[15]   : ѹ��ģ��ʱ�ӵ����ſ� */
        unsigned int  gt_clk_hieps_arc_brg : 1;  /* bit[16]   : arc brgʱ�ӵ����ſ� */
        unsigned int  gt_clk_hieps_pke2    : 1;  /* bit[17]   : PKE2ʱ�ӵ����ſ� */
        unsigned int  gt_clk_hieps_sce2    : 1;  /* bit[18]   : SCE2ʱ�ӵ����ſ� */
        unsigned int  gt_pclk_hieps_i2c    : 1;  /* bit[19]   : I2Cʱ�ӵ����ſ� */
        unsigned int  gt_pclk_hieps_spi    : 1;  /* bit[20]   : SPIʱ�ӵ����ſ� */
        unsigned int  reserved             : 11; /* bit[21-31]: ����ʱ��ʹ�ܿ��ƣ�
                                                                0��д0��Ч����
                                                                1��ʹ��IPʱ�ӡ� */
    } reg;
} SOC_CONFIG_HIEPS_PEREN0_UNION;
#endif
#define SOC_CONFIG_HIEPS_PEREN0_gt_pclk_hieps_ipc_START     (0)
#define SOC_CONFIG_HIEPS_PEREN0_gt_pclk_hieps_ipc_END       (0)
#define SOC_CONFIG_HIEPS_PEREN0_gt_pclk_hieps_wdog_START    (1)
#define SOC_CONFIG_HIEPS_PEREN0_gt_pclk_hieps_wdog_END      (1)
#define SOC_CONFIG_HIEPS_PEREN0_gt_pclk_hieps_timer_START   (2)
#define SOC_CONFIG_HIEPS_PEREN0_gt_pclk_hieps_timer_END     (2)
#define SOC_CONFIG_HIEPS_PEREN0_gt_pclk_hieps_uart_START    (3)
#define SOC_CONFIG_HIEPS_PEREN0_gt_pclk_hieps_uart_END      (3)
#define SOC_CONFIG_HIEPS_PEREN0_gt_pclk_hieps_trng_START    (4)
#define SOC_CONFIG_HIEPS_PEREN0_gt_pclk_hieps_trng_END      (4)
#define SOC_CONFIG_HIEPS_PEREN0_gt_clk_hieps_sce_km_START   (5)
#define SOC_CONFIG_HIEPS_PEREN0_gt_clk_hieps_sce_km_END     (5)
#define SOC_CONFIG_HIEPS_PEREN0_gt_clk_hieps_pke_START      (6)
#define SOC_CONFIG_HIEPS_PEREN0_gt_clk_hieps_pke_END        (6)
#define SOC_CONFIG_HIEPS_PEREN0_gt_aclk_hieps_qic_START     (7)
#define SOC_CONFIG_HIEPS_PEREN0_gt_aclk_hieps_qic_END       (7)
#define SOC_CONFIG_HIEPS_PEREN0_gt_clk_hieps_arc_START      (8)
#define SOC_CONFIG_HIEPS_PEREN0_gt_clk_hieps_arc_END        (8)
#define SOC_CONFIG_HIEPS_PEREN0_gt_clk_hieps_arc_rtt_START  (9)
#define SOC_CONFIG_HIEPS_PEREN0_gt_clk_hieps_arc_rtt_END    (9)
#define SOC_CONFIG_HIEPS_PEREN0_gt_clk_hieps_axi_START      (10)
#define SOC_CONFIG_HIEPS_PEREN0_gt_clk_hieps_axi_END        (10)
#define SOC_CONFIG_HIEPS_PEREN0_gt_clk_hieps_pdbg_START     (11)
#define SOC_CONFIG_HIEPS_PEREN0_gt_clk_hieps_pdbg_END       (11)
#define SOC_CONFIG_HIEPS_PEREN0_gt_clk_hieps_atb_START      (12)
#define SOC_CONFIG_HIEPS_PEREN0_gt_clk_hieps_atb_END        (12)
#define SOC_CONFIG_HIEPS_PEREN0_gt_clk_hieps_mmu_START      (13)
#define SOC_CONFIG_HIEPS_PEREN0_gt_clk_hieps_mmu_END        (13)
#define SOC_CONFIG_HIEPS_PEREN0_gt_clk_ddr_crpt_START       (14)
#define SOC_CONFIG_HIEPS_PEREN0_gt_clk_ddr_crpt_END         (14)
#define SOC_CONFIG_HIEPS_PEREN0_gt_clk_hieps_cmp_START      (15)
#define SOC_CONFIG_HIEPS_PEREN0_gt_clk_hieps_cmp_END        (15)
#define SOC_CONFIG_HIEPS_PEREN0_gt_clk_hieps_arc_brg_START  (16)
#define SOC_CONFIG_HIEPS_PEREN0_gt_clk_hieps_arc_brg_END    (16)
#define SOC_CONFIG_HIEPS_PEREN0_gt_clk_hieps_pke2_START     (17)
#define SOC_CONFIG_HIEPS_PEREN0_gt_clk_hieps_pke2_END       (17)
#define SOC_CONFIG_HIEPS_PEREN0_gt_clk_hieps_sce2_START     (18)
#define SOC_CONFIG_HIEPS_PEREN0_gt_clk_hieps_sce2_END       (18)
#define SOC_CONFIG_HIEPS_PEREN0_gt_pclk_hieps_i2c_START     (19)
#define SOC_CONFIG_HIEPS_PEREN0_gt_pclk_hieps_i2c_END       (19)
#define SOC_CONFIG_HIEPS_PEREN0_gt_pclk_hieps_spi_START     (20)
#define SOC_CONFIG_HIEPS_PEREN0_gt_pclk_hieps_spi_END       (20)


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
        unsigned int  gt_pclk_hieps_ipc    : 1;  /* bit[0]    : IPCʱ�ӵĽ�ֹ���� */
        unsigned int  gt_pclk_hieps_wdog   : 1;  /* bit[1]    : WDOGʱ�ӵĽ�ֹ���� */
        unsigned int  gt_pclk_hieps_timer  : 1;  /* bit[2]    : TIMERʱ�ӵĽ�ֹ���� */
        unsigned int  gt_pclk_hieps_uart   : 1;  /* bit[3]    : UARTʱ�ӵĽ�ֹ���� */
        unsigned int  gt_pclk_hieps_trng   : 1;  /* bit[4]    : TRNGʱ�ӵĽ�ֹ���� */
        unsigned int  gt_clk_hieps_sce_km  : 1;  /* bit[5]    : SCE��KMʱ�ӵĽ�ֹ���� */
        unsigned int  gt_clk_hieps_pke     : 1;  /* bit[6]    : PKEʱ�ӵĽ�ֹ���� */
        unsigned int  gt_aclk_hieps_qic    : 1;  /* bit[7]    : ɾ��gt_clk_hieps_mmu_autogt������gt_aclk_hieps_qic */
        unsigned int  gt_clk_hieps_arc     : 1;  /* bit[8]    : ARC ��ʱ�ӵĽ�ֹ���� */
        unsigned int  gt_clk_hieps_arc_rtt : 1;  /* bit[9]    : ARC RTT�ӿڿ������ʱ�ӵĽ�ֹ���� */
        unsigned int  gt_clk_hieps_axi     : 1;  /* bit[10]   : AXI����ʱ�ӵĽ�ֹ���� */
        unsigned int  gt_clk_hieps_pdbg    : 1;  /* bit[11]   : ARC PDBG�ӿڿ������ʱ�ӵĽ�ֹ���� */
        unsigned int  gt_clk_hieps_atb     : 1;  /* bit[12]   : ARC ATB�ӿڿ������ʱ�ӵĽ�ֹ���� */
        unsigned int  gt_clk_hieps_mmu     : 1;  /* bit[13]   : MMU��ʱ�ӽ�ֹ���� */
        unsigned int  gt_clk_ddr_crpt      : 1;  /* bit[14]   : DDR����ʱ�ӵĽ�ֹ���� */
        unsigned int  gt_clk_hieps_cmp     : 1;  /* bit[15]   : ѹ��ģ��ʱ�ӵĽ�ֹ���� */
        unsigned int  gt_clk_hieps_arc_brg : 1;  /* bit[16]   : arc brgʱ�ӵĽ�ֹ���� */
        unsigned int  gt_clk_hieps_pke2    : 1;  /* bit[17]   : PKE2ʱ�ӵĽ�ֹ���� */
        unsigned int  gt_clk_hieps_sce2    : 1;  /* bit[18]   : SCE2ʱ�ӵĽ�ֹ���� */
        unsigned int  gt_pclk_hieps_i2c    : 1;  /* bit[19]   : I2Cʱ�ӵĽ�ֹ���� */
        unsigned int  gt_pclk_hieps_spi    : 1;  /* bit[20]   : SPIʱ�ӵĽ�ֹ���� */
        unsigned int  reserved             : 11; /* bit[21-31]: ����ʱ�ӽ�ֹ���ƣ�
                                                                0��д0��Ч����
                                                                1����ֹIPʱ�ӡ� */
    } reg;
} SOC_CONFIG_HIEPS_PERDIS0_UNION;
#endif
#define SOC_CONFIG_HIEPS_PERDIS0_gt_pclk_hieps_ipc_START     (0)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_pclk_hieps_ipc_END       (0)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_pclk_hieps_wdog_START    (1)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_pclk_hieps_wdog_END      (1)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_pclk_hieps_timer_START   (2)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_pclk_hieps_timer_END     (2)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_pclk_hieps_uart_START    (3)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_pclk_hieps_uart_END      (3)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_pclk_hieps_trng_START    (4)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_pclk_hieps_trng_END      (4)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_clk_hieps_sce_km_START   (5)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_clk_hieps_sce_km_END     (5)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_clk_hieps_pke_START      (6)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_clk_hieps_pke_END        (6)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_aclk_hieps_qic_START     (7)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_aclk_hieps_qic_END       (7)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_clk_hieps_arc_START      (8)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_clk_hieps_arc_END        (8)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_clk_hieps_arc_rtt_START  (9)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_clk_hieps_arc_rtt_END    (9)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_clk_hieps_axi_START      (10)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_clk_hieps_axi_END        (10)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_clk_hieps_pdbg_START     (11)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_clk_hieps_pdbg_END       (11)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_clk_hieps_atb_START      (12)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_clk_hieps_atb_END        (12)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_clk_hieps_mmu_START      (13)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_clk_hieps_mmu_END        (13)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_clk_ddr_crpt_START       (14)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_clk_ddr_crpt_END         (14)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_clk_hieps_cmp_START      (15)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_clk_hieps_cmp_END        (15)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_clk_hieps_arc_brg_START  (16)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_clk_hieps_arc_brg_END    (16)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_clk_hieps_pke2_START     (17)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_clk_hieps_pke2_END       (17)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_clk_hieps_sce2_START     (18)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_clk_hieps_sce2_END       (18)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_pclk_hieps_i2c_START     (19)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_pclk_hieps_i2c_END       (19)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_pclk_hieps_spi_START     (20)
#define SOC_CONFIG_HIEPS_PERDIS0_gt_pclk_hieps_spi_END       (20)


/*****************************************************************************
 �ṹ��    : SOC_CONFIG_HIEPS_PERCLKEN0_UNION
 �ṹ˵��  : HIEPS_PERCLKEN0 �Ĵ����ṹ���塣��ַƫ����:0x108����ֵ:0x001FFFFF�����:32
 �Ĵ���˵��: ����ʱ��ʹ��״̬�Ĵ���0��
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  gt_pclk_hieps_ipc    : 1;  /* bit[0]    : IPCʱ�ӵ���״̬ */
        unsigned int  gt_pclk_hieps_wdog   : 1;  /* bit[1]    : WDOGʱ��ʹ��״̬ */
        unsigned int  gt_pclk_hieps_timer  : 1;  /* bit[2]    : TIMERʱ��ʹ��״̬ */
        unsigned int  gt_pclk_hieps_uart   : 1;  /* bit[3]    : UARTʱ��ʹ��״̬ */
        unsigned int  gt_pclk_hieps_trng   : 1;  /* bit[4]    : TRNGʱ��ʹ��״̬ */
        unsigned int  gt_clk_hieps_sce_km  : 1;  /* bit[5]    : SCE��KMʱ��ʹ��״̬ */
        unsigned int  gt_clk_hieps_pke     : 1;  /* bit[6]    : PKEʱ��ʹ��״̬ */
        unsigned int  gt_aclk_hieps_qic    : 1;  /* bit[7]    : ɾ��gt_clk_hieps_mmu_autogt������gt_aclk_hieps_qic */
        unsigned int  gt_clk_hieps_arc     : 1;  /* bit[8]    : ARC ��ʱ��ʹ��״̬ */
        unsigned int  gt_clk_hieps_arc_rtt : 1;  /* bit[9]    : ARC RTT�ӿڿ������ʱ��ʹ��״̬ */
        unsigned int  gt_clk_hieps_axi     : 1;  /* bit[10]   : AXI����ʱ��ʹ��״̬ */
        unsigned int  gt_clk_hieps_pdbg    : 1;  /* bit[11]   : ARC PDBG�ӿڿ������ʱ��ʹ��״̬ */
        unsigned int  gt_clk_hieps_atb     : 1;  /* bit[12]   : ARC ATB�ӿڿ������ʱ��ʹ��״̬ */
        unsigned int  gt_clk_hieps_mmu     : 1;  /* bit[13]   : MMU��ʱ��ʹ��״̬��ͬʱ����bclk��cclk */
        unsigned int  gt_clk_ddr_crpt      : 1;  /* bit[14]   : DDR����ʱ�ӵ�ʹ��״̬ */
        unsigned int  gt_clk_hieps_cmp     : 1;  /* bit[15]   : ѹ��ģ��ʱ�ӵ�ʹ��״̬ */
        unsigned int  gt_clk_hieps_arc_brg : 1;  /* bit[16]   : arc brgʱ�ӵ�ʹ��״̬ */
        unsigned int  gt_clk_hieps_pke2    : 1;  /* bit[17]   : PKE2ʱ�ӵ�ʹ��״̬ */
        unsigned int  gt_clk_hieps_sce2    : 1;  /* bit[18]   : SCE2ʱ�ӵ�ʹ��״̬ */
        unsigned int  gt_pclk_hieps_i2c    : 1;  /* bit[19]   : I2Cʱ�ӵ�ʹ��״̬ */
        unsigned int  gt_pclk_hieps_spi    : 1;  /* bit[20]   : SPIʱ�ӵ�ʹ��״̬ */
        unsigned int  reserved             : 11; /* bit[21-31]: ����ʱ��ʹ��״̬��
                                                                0��IPʱ��ʹ�ܳ���״̬��
                                                                1��IPʱ��ʹ��״̬�� */
    } reg;
} SOC_CONFIG_HIEPS_PERCLKEN0_UNION;
#endif
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_pclk_hieps_ipc_START     (0)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_pclk_hieps_ipc_END       (0)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_pclk_hieps_wdog_START    (1)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_pclk_hieps_wdog_END      (1)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_pclk_hieps_timer_START   (2)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_pclk_hieps_timer_END     (2)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_pclk_hieps_uart_START    (3)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_pclk_hieps_uart_END      (3)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_pclk_hieps_trng_START    (4)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_pclk_hieps_trng_END      (4)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_clk_hieps_sce_km_START   (5)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_clk_hieps_sce_km_END     (5)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_clk_hieps_pke_START      (6)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_clk_hieps_pke_END        (6)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_aclk_hieps_qic_START     (7)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_aclk_hieps_qic_END       (7)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_clk_hieps_arc_START      (8)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_clk_hieps_arc_END        (8)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_clk_hieps_arc_rtt_START  (9)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_clk_hieps_arc_rtt_END    (9)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_clk_hieps_axi_START      (10)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_clk_hieps_axi_END        (10)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_clk_hieps_pdbg_START     (11)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_clk_hieps_pdbg_END       (11)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_clk_hieps_atb_START      (12)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_clk_hieps_atb_END        (12)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_clk_hieps_mmu_START      (13)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_clk_hieps_mmu_END        (13)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_clk_ddr_crpt_START       (14)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_clk_ddr_crpt_END         (14)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_clk_hieps_cmp_START      (15)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_clk_hieps_cmp_END        (15)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_clk_hieps_arc_brg_START  (16)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_clk_hieps_arc_brg_END    (16)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_clk_hieps_pke2_START     (17)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_clk_hieps_pke2_END       (17)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_clk_hieps_sce2_START     (18)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_clk_hieps_sce2_END       (18)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_pclk_hieps_i2c_START     (19)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_pclk_hieps_i2c_END       (19)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_pclk_hieps_spi_START     (20)
#define SOC_CONFIG_HIEPS_PERCLKEN0_gt_pclk_hieps_spi_END       (20)


/*****************************************************************************
 �ṹ��    : SOC_CONFIG_HIEPS_PERSTAT0_UNION
 �ṹ˵��  : HIEPS_PERSTAT0 �Ĵ����ṹ���塣��ַƫ����:0x10C����ֵ:0x801FFFFF�����:32
 �Ĵ���˵��: '����ʱ������״̬�Ĵ���0��
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  st_pclk_hieps_ipc        : 1;  /* bit[0]    : IPC��ʱ��״̬ */
        unsigned int  st_pclk_hieps_wdog       : 1;  /* bit[1]    : WDOG��ʱ��״̬ */
        unsigned int  st_pclk_hieps_timer      : 1;  /* bit[2]    : TIMER��ʱ��״̬ */
        unsigned int  st_pclk_hieps_uart       : 1;  /* bit[3]    : UART��ʱ��״̬ */
        unsigned int  st_pclk_hieps_trng       : 1;  /* bit[4]    : TRNG��ʱ��״̬ */
        unsigned int  st_clk_hieps_sce_km      : 1;  /* bit[5]    : SCE��KM��ʱ��״̬ */
        unsigned int  st_clk_hieps_pke         : 1;  /* bit[6]    : PKE��ʱ��״̬ */
        unsigned int  st_aclk_hieps_qic        : 1;  /* bit[7]    : ɾ��st_clk_hieps_mmu_autogt������st_aclk_hieps_qic */
        unsigned int  st_clk_hieps_arc         : 1;  /* bit[8]    : ARC �˵�ʱ��״̬ */
        unsigned int  st_clk_hieps_arc_rtt     : 1;  /* bit[9]    : ARC rtt�ӿڵ�ʱ��״̬ */
        unsigned int  st_clk_hieps_axi         : 1;  /* bit[10]   : AXI���ߵ�ʱ��״̬ */
        unsigned int  st_clk_hieps_pdbg        : 1;  /* bit[11]   : ARC pdbg�ӿڵ�ʱ��״̬ */
        unsigned int  st_clk_hieps_atb         : 1;  /* bit[12]   : ARC atb�ӿڵ�ʱ��״̬ */
        unsigned int  st_clk_hieps_mmu_bclk    : 1;  /* bit[13]   : �Զ�gating��mmu bclk��״̬��mmu_bclk��״̬�������Զ��ſ� */
        unsigned int  st_clk_ddr_crpt          : 1;  /* bit[14]   : DDR���ܵ�ʱ��״̬ */
        unsigned int  st_clk_hieps_cmp         : 1;  /* bit[15]   : ѹ��ģ���ʱ��״̬ */
        unsigned int  st_clk_hieps_arc_brg     : 1;  /* bit[16]   : arc brg��ʱ��״̬ */
        unsigned int  st_clk_hieps_pke2        : 1;  /* bit[17]   : PKE2��ʱ��״̬ */
        unsigned int  st_clk_hieps_sce2        : 1;  /* bit[18]   : SCE2��ʱ��״̬ */
        unsigned int  st_pclk_hieps_i2c        : 1;  /* bit[19]   : I2C��ʱ��״̬ */
        unsigned int  st_pclk_hieps_spi        : 1;  /* bit[20]   : SPI��ʱ��״̬ */
        unsigned int  reserved                 : 10; /* bit[21-30]: reserved */
        unsigned int  st_clk_hieps_arc_brg_h2h : 1;  /* bit[31]   : ����ʱ������״̬��
                                                                    0��IPʱ�ӽ�ֹ״̬��
                                                                    1��IPʱ��ʹ��״̬�� */
    } reg;
} SOC_CONFIG_HIEPS_PERSTAT0_UNION;
#endif
#define SOC_CONFIG_HIEPS_PERSTAT0_st_pclk_hieps_ipc_START         (0)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_pclk_hieps_ipc_END           (0)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_pclk_hieps_wdog_START        (1)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_pclk_hieps_wdog_END          (1)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_pclk_hieps_timer_START       (2)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_pclk_hieps_timer_END         (2)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_pclk_hieps_uart_START        (3)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_pclk_hieps_uart_END          (3)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_pclk_hieps_trng_START        (4)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_pclk_hieps_trng_END          (4)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_clk_hieps_sce_km_START       (5)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_clk_hieps_sce_km_END         (5)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_clk_hieps_pke_START          (6)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_clk_hieps_pke_END            (6)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_aclk_hieps_qic_START         (7)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_aclk_hieps_qic_END           (7)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_clk_hieps_arc_START          (8)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_clk_hieps_arc_END            (8)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_clk_hieps_arc_rtt_START      (9)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_clk_hieps_arc_rtt_END        (9)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_clk_hieps_axi_START          (10)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_clk_hieps_axi_END            (10)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_clk_hieps_pdbg_START         (11)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_clk_hieps_pdbg_END           (11)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_clk_hieps_atb_START          (12)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_clk_hieps_atb_END            (12)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_clk_hieps_mmu_bclk_START     (13)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_clk_hieps_mmu_bclk_END       (13)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_clk_ddr_crpt_START           (14)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_clk_ddr_crpt_END             (14)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_clk_hieps_cmp_START          (15)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_clk_hieps_cmp_END            (15)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_clk_hieps_arc_brg_START      (16)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_clk_hieps_arc_brg_END        (16)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_clk_hieps_pke2_START         (17)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_clk_hieps_pke2_END           (17)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_clk_hieps_sce2_START         (18)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_clk_hieps_sce2_END           (18)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_pclk_hieps_i2c_START         (19)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_pclk_hieps_i2c_END           (19)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_pclk_hieps_spi_START         (20)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_pclk_hieps_spi_END           (20)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_clk_hieps_arc_brg_h2h_START  (31)
#define SOC_CONFIG_HIEPS_PERSTAT0_st_clk_hieps_arc_brg_h2h_END    (31)


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
        unsigned int  ip_prst_hieps_ipc   : 1;  /* bit[0]    : IP��λʹ�ܣ�
                                                               0��IP��λʹ��״̬���䣻
                                                               1��IP��λʹ�ܡ� */
        unsigned int  ip_prst_hieps_timer : 1;  /* bit[1]    : ͬbit0 */
        unsigned int  ip_prst_hieps_uart  : 1;  /* bit[2]    : ͬbit0 */
        unsigned int  ip_prst_hieps_trng  : 1;  /* bit[3]    : ͬbit0 */
        unsigned int  ip_rst_hieps_sce_km : 1;  /* bit[4]    : ͬbit0 */
        unsigned int  ip_rst_hieps_pke    : 1;  /* bit[5]    : ͬbit0 */
        unsigned int  ip_rst_hieps_mmu    : 1;  /* bit[6]    : ͬbit0 */
        unsigned int  ip_rst_hieps_arc    : 1;  /* bit[7]    : ͬbit0 */
        unsigned int  ip_rst_ddr_crpt     : 1;  /* bit[8]    : ͬbit0 */
        unsigned int  ip_rst_hieps_axi    : 1;  /* bit[9]    : ͬbit0 */
        unsigned int  ip_rst_hieps_cmp    : 1;  /* bit[10]   : ͬbit0 */
        unsigned int  ip_rst_hieps_sce2   : 1;  /* bit[11]   : ͬbit0 */
        unsigned int  ip_rst_hieps_pke2   : 1;  /* bit[12]   : ͬbit0 */
        unsigned int  ip_prst_hieps_i2c   : 1;  /* bit[13]   : ͬbit0 */
        unsigned int  ip_prst_hieps_spi   : 1;  /* bit[14]   : ͬbit0 */
        unsigned int  reserved            : 17; /* bit[15-31]: IP��λʹ�ܣ�
                                                               0��IP��λʹ��״̬���䣻
                                                               1��IP��λʹ�ܡ� */
    } reg;
} SOC_CONFIG_PERRSTEN0_UNION;
#endif
#define SOC_CONFIG_PERRSTEN0_ip_prst_hieps_ipc_START    (0)
#define SOC_CONFIG_PERRSTEN0_ip_prst_hieps_ipc_END      (0)
#define SOC_CONFIG_PERRSTEN0_ip_prst_hieps_timer_START  (1)
#define SOC_CONFIG_PERRSTEN0_ip_prst_hieps_timer_END    (1)
#define SOC_CONFIG_PERRSTEN0_ip_prst_hieps_uart_START   (2)
#define SOC_CONFIG_PERRSTEN0_ip_prst_hieps_uart_END     (2)
#define SOC_CONFIG_PERRSTEN0_ip_prst_hieps_trng_START   (3)
#define SOC_CONFIG_PERRSTEN0_ip_prst_hieps_trng_END     (3)
#define SOC_CONFIG_PERRSTEN0_ip_rst_hieps_sce_km_START  (4)
#define SOC_CONFIG_PERRSTEN0_ip_rst_hieps_sce_km_END    (4)
#define SOC_CONFIG_PERRSTEN0_ip_rst_hieps_pke_START     (5)
#define SOC_CONFIG_PERRSTEN0_ip_rst_hieps_pke_END       (5)
#define SOC_CONFIG_PERRSTEN0_ip_rst_hieps_mmu_START     (6)
#define SOC_CONFIG_PERRSTEN0_ip_rst_hieps_mmu_END       (6)
#define SOC_CONFIG_PERRSTEN0_ip_rst_hieps_arc_START     (7)
#define SOC_CONFIG_PERRSTEN0_ip_rst_hieps_arc_END       (7)
#define SOC_CONFIG_PERRSTEN0_ip_rst_ddr_crpt_START      (8)
#define SOC_CONFIG_PERRSTEN0_ip_rst_ddr_crpt_END        (8)
#define SOC_CONFIG_PERRSTEN0_ip_rst_hieps_axi_START     (9)
#define SOC_CONFIG_PERRSTEN0_ip_rst_hieps_axi_END       (9)
#define SOC_CONFIG_PERRSTEN0_ip_rst_hieps_cmp_START     (10)
#define SOC_CONFIG_PERRSTEN0_ip_rst_hieps_cmp_END       (10)
#define SOC_CONFIG_PERRSTEN0_ip_rst_hieps_sce2_START    (11)
#define SOC_CONFIG_PERRSTEN0_ip_rst_hieps_sce2_END      (11)
#define SOC_CONFIG_PERRSTEN0_ip_rst_hieps_pke2_START    (12)
#define SOC_CONFIG_PERRSTEN0_ip_rst_hieps_pke2_END      (12)
#define SOC_CONFIG_PERRSTEN0_ip_prst_hieps_i2c_START    (13)
#define SOC_CONFIG_PERRSTEN0_ip_prst_hieps_i2c_END      (13)
#define SOC_CONFIG_PERRSTEN0_ip_prst_hieps_spi_START    (14)
#define SOC_CONFIG_PERRSTEN0_ip_prst_hieps_spi_END      (14)


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
        unsigned int  ip_prst_hieps_ipc   : 1;  /* bit[0]    : IP��λ���룺
                                                               0��IP��λʹ��״̬���䣻
                                                               1��IP��λ���롣 */
        unsigned int  ip_prst_hieps_timer : 1;  /* bit[1]    : ͬbit0 */
        unsigned int  ip_prst_hieps_uart  : 1;  /* bit[2]    : ͬbit0 */
        unsigned int  ip_prst_hieps_trng  : 1;  /* bit[3]    : ͬbit0 */
        unsigned int  ip_rst_hieps_sce_km : 1;  /* bit[4]    : ͬbit0 */
        unsigned int  ip_rst_hieps_pke    : 1;  /* bit[5]    : ͬbit0 */
        unsigned int  ip_rst_hieps_mmu    : 1;  /* bit[6]    : ͬbit0 */
        unsigned int  ip_rst_hieps_arc    : 1;  /* bit[7]    : ͬbit0 */
        unsigned int  ip_rst_ddr_crpt     : 1;  /* bit[8]    : ͬbit0 */
        unsigned int  ip_rst_hieps_axi    : 1;  /* bit[9]    : ͬbit0 */
        unsigned int  ip_rst_hieps_cmp    : 1;  /* bit[10]   : ͬbit0 */
        unsigned int  ip_rst_hieps_sce2   : 1;  /* bit[11]   : ͬbit0 */
        unsigned int  ip_rst_hieps_pke2   : 1;  /* bit[12]   : ͬbit0 */
        unsigned int  ip_prst_hieps_i2c   : 1;  /* bit[13]   : ͬbit0 */
        unsigned int  ip_prst_hieps_spi   : 1;  /* bit[14]   : ͬbit0 */
        unsigned int  reserved            : 17; /* bit[15-31]: IP��λ���룺
                                                               0��IP��λʹ��״̬���䣻
                                                               1��IP��λ���롣 */
    } reg;
} SOC_CONFIG_HIEPS_PERRSTDIS0_UNION;
#endif
#define SOC_CONFIG_HIEPS_PERRSTDIS0_ip_prst_hieps_ipc_START    (0)
#define SOC_CONFIG_HIEPS_PERRSTDIS0_ip_prst_hieps_ipc_END      (0)
#define SOC_CONFIG_HIEPS_PERRSTDIS0_ip_prst_hieps_timer_START  (1)
#define SOC_CONFIG_HIEPS_PERRSTDIS0_ip_prst_hieps_timer_END    (1)
#define SOC_CONFIG_HIEPS_PERRSTDIS0_ip_prst_hieps_uart_START   (2)
#define SOC_CONFIG_HIEPS_PERRSTDIS0_ip_prst_hieps_uart_END     (2)
#define SOC_CONFIG_HIEPS_PERRSTDIS0_ip_prst_hieps_trng_START   (3)
#define SOC_CONFIG_HIEPS_PERRSTDIS0_ip_prst_hieps_trng_END     (3)
#define SOC_CONFIG_HIEPS_PERRSTDIS0_ip_rst_hieps_sce_km_START  (4)
#define SOC_CONFIG_HIEPS_PERRSTDIS0_ip_rst_hieps_sce_km_END    (4)
#define SOC_CONFIG_HIEPS_PERRSTDIS0_ip_rst_hieps_pke_START     (5)
#define SOC_CONFIG_HIEPS_PERRSTDIS0_ip_rst_hieps_pke_END       (5)
#define SOC_CONFIG_HIEPS_PERRSTDIS0_ip_rst_hieps_mmu_START     (6)
#define SOC_CONFIG_HIEPS_PERRSTDIS0_ip_rst_hieps_mmu_END       (6)
#define SOC_CONFIG_HIEPS_PERRSTDIS0_ip_rst_hieps_arc_START     (7)
#define SOC_CONFIG_HIEPS_PERRSTDIS0_ip_rst_hieps_arc_END       (7)
#define SOC_CONFIG_HIEPS_PERRSTDIS0_ip_rst_ddr_crpt_START      (8)
#define SOC_CONFIG_HIEPS_PERRSTDIS0_ip_rst_ddr_crpt_END        (8)
#define SOC_CONFIG_HIEPS_PERRSTDIS0_ip_rst_hieps_axi_START     (9)
#define SOC_CONFIG_HIEPS_PERRSTDIS0_ip_rst_hieps_axi_END       (9)
#define SOC_CONFIG_HIEPS_PERRSTDIS0_ip_rst_hieps_cmp_START     (10)
#define SOC_CONFIG_HIEPS_PERRSTDIS0_ip_rst_hieps_cmp_END       (10)
#define SOC_CONFIG_HIEPS_PERRSTDIS0_ip_rst_hieps_sce2_START    (11)
#define SOC_CONFIG_HIEPS_PERRSTDIS0_ip_rst_hieps_sce2_END      (11)
#define SOC_CONFIG_HIEPS_PERRSTDIS0_ip_rst_hieps_pke2_START    (12)
#define SOC_CONFIG_HIEPS_PERRSTDIS0_ip_rst_hieps_pke2_END      (12)
#define SOC_CONFIG_HIEPS_PERRSTDIS0_ip_prst_hieps_i2c_START    (13)
#define SOC_CONFIG_HIEPS_PERRSTDIS0_ip_prst_hieps_i2c_END      (13)
#define SOC_CONFIG_HIEPS_PERRSTDIS0_ip_prst_hieps_spi_START    (14)
#define SOC_CONFIG_HIEPS_PERRSTDIS0_ip_prst_hieps_spi_END      (14)


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
        unsigned int  ip_prst_hieps_ipc   : 1;  /* bit[0]    : Ĭ�Ͻ⸴λ */
        unsigned int  ip_prst_hieps_timer : 1;  /* bit[1]    : Ĭ�Ͻ⸴λ */
        unsigned int  ip_prst_hieps_uart  : 1;  /* bit[2]    : Ĭ�Ͻ⸴λ */
        unsigned int  ip_prst_hieps_trng  : 1;  /* bit[3]    : Ĭ�Ͻ⸴λ */
        unsigned int  ip_rst_hieps_sce_km : 1;  /* bit[4]    : Ĭ�Ͻ⸴λ */
        unsigned int  ip_rst_hieps_pke    : 1;  /* bit[5]    : Ĭ�Ͻ⸴λ */
        unsigned int  ip_rst_hieps_mmu    : 1;  /* bit[6]    : Ĭ�Ͻ⸴λ */
        unsigned int  ip_rst_hieps_arc    : 1;  /* bit[7]    : Ĭ�Ͻ⸴λ */
        unsigned int  ip_rst_ddr_crpt     : 1;  /* bit[8]    : Ĭ�Ͻ⸴λ */
        unsigned int  ip_rst_hieps_axi    : 1;  /* bit[9]    : Ĭ�Ͻ⸴λ */
        unsigned int  ip_rst_hieps_cmp    : 1;  /* bit[10]   : Ĭ�Ͻ⸴λ */
        unsigned int  ip_rst_hieps_sce2   : 1;  /* bit[11]   : Ĭ�Ͻ⸴λ */
        unsigned int  ip_rst_hieps_pke2   : 1;  /* bit[12]   : Ĭ�Ͻ⸴λ */
        unsigned int  ip_prst_hieps_i2c   : 1;  /* bit[13]   : Ĭ�Ͻ⸴λ */
        unsigned int  ip_prst_hieps_spi   : 1;  /* bit[14]   : Ĭ�Ͻ⸴λ */
        unsigned int  reserved            : 17; /* bit[15-31]: IP��λʹ��״̬��
                                                               0��IP���ڸ�λ����״̬��
                                                               1��IP������λʹ��״̬�� */
    } reg;
} SOC_CONFIG_HIEPS_PERRSTSTAT0_UNION;
#endif
#define SOC_CONFIG_HIEPS_PERRSTSTAT0_ip_prst_hieps_ipc_START    (0)
#define SOC_CONFIG_HIEPS_PERRSTSTAT0_ip_prst_hieps_ipc_END      (0)
#define SOC_CONFIG_HIEPS_PERRSTSTAT0_ip_prst_hieps_timer_START  (1)
#define SOC_CONFIG_HIEPS_PERRSTSTAT0_ip_prst_hieps_timer_END    (1)
#define SOC_CONFIG_HIEPS_PERRSTSTAT0_ip_prst_hieps_uart_START   (2)
#define SOC_CONFIG_HIEPS_PERRSTSTAT0_ip_prst_hieps_uart_END     (2)
#define SOC_CONFIG_HIEPS_PERRSTSTAT0_ip_prst_hieps_trng_START   (3)
#define SOC_CONFIG_HIEPS_PERRSTSTAT0_ip_prst_hieps_trng_END     (3)
#define SOC_CONFIG_HIEPS_PERRSTSTAT0_ip_rst_hieps_sce_km_START  (4)
#define SOC_CONFIG_HIEPS_PERRSTSTAT0_ip_rst_hieps_sce_km_END    (4)
#define SOC_CONFIG_HIEPS_PERRSTSTAT0_ip_rst_hieps_pke_START     (5)
#define SOC_CONFIG_HIEPS_PERRSTSTAT0_ip_rst_hieps_pke_END       (5)
#define SOC_CONFIG_HIEPS_PERRSTSTAT0_ip_rst_hieps_mmu_START     (6)
#define SOC_CONFIG_HIEPS_PERRSTSTAT0_ip_rst_hieps_mmu_END       (6)
#define SOC_CONFIG_HIEPS_PERRSTSTAT0_ip_rst_hieps_arc_START     (7)
#define SOC_CONFIG_HIEPS_PERRSTSTAT0_ip_rst_hieps_arc_END       (7)
#define SOC_CONFIG_HIEPS_PERRSTSTAT0_ip_rst_ddr_crpt_START      (8)
#define SOC_CONFIG_HIEPS_PERRSTSTAT0_ip_rst_ddr_crpt_END        (8)
#define SOC_CONFIG_HIEPS_PERRSTSTAT0_ip_rst_hieps_axi_START     (9)
#define SOC_CONFIG_HIEPS_PERRSTSTAT0_ip_rst_hieps_axi_END       (9)
#define SOC_CONFIG_HIEPS_PERRSTSTAT0_ip_rst_hieps_cmp_START     (10)
#define SOC_CONFIG_HIEPS_PERRSTSTAT0_ip_rst_hieps_cmp_END       (10)
#define SOC_CONFIG_HIEPS_PERRSTSTAT0_ip_rst_hieps_sce2_START    (11)
#define SOC_CONFIG_HIEPS_PERRSTSTAT0_ip_rst_hieps_sce2_END      (11)
#define SOC_CONFIG_HIEPS_PERRSTSTAT0_ip_rst_hieps_pke2_START    (12)
#define SOC_CONFIG_HIEPS_PERRSTSTAT0_ip_rst_hieps_pke2_END      (12)
#define SOC_CONFIG_HIEPS_PERRSTSTAT0_ip_prst_hieps_i2c_START    (13)
#define SOC_CONFIG_HIEPS_PERRSTSTAT0_ip_prst_hieps_i2c_END      (13)
#define SOC_CONFIG_HIEPS_PERRSTSTAT0_ip_prst_hieps_spi_START    (14)
#define SOC_CONFIG_HIEPS_PERRSTSTAT0_ip_prst_hieps_spi_END      (14)


/*****************************************************************************
 �ṹ��    : SOC_CONFIG_HIEPS_DIV0_UNION
 �ṹ˵��  : HIEPS_DIV0 �Ĵ����ṹ���塣��ַƫ����:0x11C����ֵ:0x00000BD5�����:32
 �Ĵ���˵��: ʱ�ӷ�Ƶ�ȿ��ƼĴ���0��
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  div_hieps_arc_atb          : 2;  /* bit[0-1]  : Ĭ��Ϊ1������2��Ƶ */
        unsigned int  div_hieps_timer            : 2;  /* bit[2-3]  : Ĭ��Ϊ1������19.2Mhz��2��Ƶ9.6MHz�� */
        unsigned int  div_hieps_arc_brg          : 2;  /* bit[4-5]  : ARC��Χ�첽��ʱ�ӷ�Ƶ���ķ�Ƶϵ�� */
        unsigned int  div_hieps_arc_bus_tp       : 5;  /* bit[6-10] : Ĭ��F��16��Ƶ */
        unsigned int  sc_gt_clk_hieps_arc_bus_tp : 1;  /* bit[11]   : testpointʱ���ſ� */
        unsigned int  reserved_0                 : 4;  /* bit[12-15]: ������ */
        unsigned int  reserved_1                 : 16; /* bit[16-31]: bitmasken:ÿ������λ��ʹ��λ,
                                                                      ֻ�е�bitmasken��Ӧ�ı���λΪ1'b1����Ӧ�ı���λ�������á�bitmasken[0]����[0]��maskʹ��λ��д1��Ч�� */
    } reg;
} SOC_CONFIG_HIEPS_DIV0_UNION;
#endif
#define SOC_CONFIG_HIEPS_DIV0_div_hieps_arc_atb_START           (0)
#define SOC_CONFIG_HIEPS_DIV0_div_hieps_arc_atb_END             (1)
#define SOC_CONFIG_HIEPS_DIV0_div_hieps_timer_START             (2)
#define SOC_CONFIG_HIEPS_DIV0_div_hieps_timer_END               (3)
#define SOC_CONFIG_HIEPS_DIV0_div_hieps_arc_brg_START           (4)
#define SOC_CONFIG_HIEPS_DIV0_div_hieps_arc_brg_END             (5)
#define SOC_CONFIG_HIEPS_DIV0_div_hieps_arc_bus_tp_START        (6)
#define SOC_CONFIG_HIEPS_DIV0_div_hieps_arc_bus_tp_END          (10)
#define SOC_CONFIG_HIEPS_DIV0_sc_gt_clk_hieps_arc_bus_tp_START  (11)
#define SOC_CONFIG_HIEPS_DIV0_sc_gt_clk_hieps_arc_bus_tp_END    (11)


/*****************************************************************************
 �ṹ��    : SOC_CONFIG_HIEPS_COMMON_CTRL0_UNION
 �ṹ˵��  : HIEPS_COMMON_CTRL0 �Ĵ����ṹ���塣��ַƫ����:0x120����ֵ:0x0000001C�����:32
 �Ĵ���˵��: CRG���ƼĴ���0��
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  timer0_soft_en           : 1;  /* bit[0]    : timer1����ʹ�ܵ�������أ�Ĭ�Ϲرա� */
        unsigned int  timer1_soft_en           : 1;  /* bit[1]    : timer0����ʹ�ܵ�������أ�Ĭ�Ϲرա� */
        unsigned int  hieps_timer0_en_sel      : 1;  /* bit[2]    : 32k����19.2Mhz��Ƶʱ�ӣ�
                                                                    Ĭ��timer�ļ���ʹ��ʱ��Ϊ9.6Mhz
                                                                    0��32K����ʹ��
                                                                    1��ѡ��19.2M�ķ�Ƶʱ�� */
        unsigned int  hieps_timer1_en_sel      : 1;  /* bit[3]    : 32k����19.2Mhz��Ƶʱ�ӣ�
                                                                    Ĭ��timer�ļ���ʹ��ʱ��Ϊ9.6Mhz
                                                                    0��32K����ʹ��
                                                                    1��ѡ��19.2M�ķ�Ƶʱ�� */
        unsigned int  lbus_en_arc_wfi_bypass   : 1;  /* bit[4]    : ARC����sleep��ʱ���Զ�gating�Ŀ��أ�
                                                                    1��ʾ�������Զ�gating��
                                                                    0ʹ���Զ�gating */
        unsigned int  wdog_soft_en             : 1;  /* bit[5]    : watchdog����ʹ�ܵ�������أ�Ĭ�Ϲرա� */
        unsigned int  timer_en_arc_halt_bypass : 1;  /* bit[6]    : ARC����halt���Ƿ�ֹͣtimer������bypass���ƣ�
                                                                    0��timerֹͣ����
                                                                    1��timer��ֹͣ���� */
        unsigned int  reserved_0               : 9;  /* bit[7-15] : ������ */
        unsigned int  reserved_1               : 16; /* bit[16-31]: bitmasken:ÿ������λ��ʹ��λ,
                                                                    ֻ�е�bitmasken��Ӧ�ı���λΪ1'b1����Ӧ�ı���λ�������á�bitmasken[0]����[0]��maskʹ��λ��д1��Ч�� */
    } reg;
} SOC_CONFIG_HIEPS_COMMON_CTRL0_UNION;
#endif
#define SOC_CONFIG_HIEPS_COMMON_CTRL0_timer0_soft_en_START            (0)
#define SOC_CONFIG_HIEPS_COMMON_CTRL0_timer0_soft_en_END              (0)
#define SOC_CONFIG_HIEPS_COMMON_CTRL0_timer1_soft_en_START            (1)
#define SOC_CONFIG_HIEPS_COMMON_CTRL0_timer1_soft_en_END              (1)
#define SOC_CONFIG_HIEPS_COMMON_CTRL0_hieps_timer0_en_sel_START       (2)
#define SOC_CONFIG_HIEPS_COMMON_CTRL0_hieps_timer0_en_sel_END         (2)
#define SOC_CONFIG_HIEPS_COMMON_CTRL0_hieps_timer1_en_sel_START       (3)
#define SOC_CONFIG_HIEPS_COMMON_CTRL0_hieps_timer1_en_sel_END         (3)
#define SOC_CONFIG_HIEPS_COMMON_CTRL0_lbus_en_arc_wfi_bypass_START    (4)
#define SOC_CONFIG_HIEPS_COMMON_CTRL0_lbus_en_arc_wfi_bypass_END      (4)
#define SOC_CONFIG_HIEPS_COMMON_CTRL0_wdog_soft_en_START              (5)
#define SOC_CONFIG_HIEPS_COMMON_CTRL0_wdog_soft_en_END                (5)
#define SOC_CONFIG_HIEPS_COMMON_CTRL0_timer_en_arc_halt_bypass_START  (6)
#define SOC_CONFIG_HIEPS_COMMON_CTRL0_timer_en_arc_halt_bypass_END    (6)


/*****************************************************************************
 �ṹ��    : SOC_CONFIG_HIEPS_COMMON_CTRL1_UNION
 �ṹ˵��  : HIEPS_COMMON_CTRL1 �Ĵ����ṹ���塣��ַƫ����:0x124����ֵ:0x00003FFF�����:32
 �Ĵ���˵��: CRG���ƼĴ���0��
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  gt_bclk_smmuo_bypass      : 1;  /* bit[0]    : MMU TBU�Զ��ſص�bypass���ƣ��źű��������ܲ�ʹ��
                                                                     0��MMU TBU�����Զ��ſ�
                                                                     1��MMU TBU�������Զ��ſأ��Զ��ſ��߼���bypass */
        unsigned int  cactive_smmu0_bclk_cfgcnt : 6;  /* bit[1-6]  : ��������SMMU���Զ��ſ�ʹ��ʱ����TBU����ʱ��ʱ�ӱ��ִ�״̬��ʱ�䡣�źű��������ܲ�ʹ�� */
        unsigned int  gt_cclk_smmuo_bypass      : 1;  /* bit[7]    : MMU TCU�Զ��ſص�bypass���ƣ��źű��������ܲ�ʹ��
                                                                     0��MMU TCU�����Զ��ſ�
                                                                     1��MMU TCU�������Զ��ſأ��Զ��ſ��߼���bypass */
        unsigned int  cactive_smmu0_cclk_cfgcnt : 6;  /* bit[8-13] : ��������SMMU���Զ��ſ�ʹ��ʱ����TCU����ʱ��ʱ�ӱ��ִ�״̬��ʱ�䡣�źű��������ܲ�ʹ�� */
        unsigned int  reserved_0                : 2;  /* bit[14-15]: ������ */
        unsigned int  reserved_1                : 16; /* bit[16-31]: bitmasken:ÿ������λ��ʹ��λ,
                                                                     ֻ�е�bitmasken��Ӧ�ı���λΪ1'b1����Ӧ�ı���λ�������á�bitmasken[0]����[0]��maskʹ��λ��д1��Ч�� */
    } reg;
} SOC_CONFIG_HIEPS_COMMON_CTRL1_UNION;
#endif
#define SOC_CONFIG_HIEPS_COMMON_CTRL1_gt_bclk_smmuo_bypass_START       (0)
#define SOC_CONFIG_HIEPS_COMMON_CTRL1_gt_bclk_smmuo_bypass_END         (0)
#define SOC_CONFIG_HIEPS_COMMON_CTRL1_cactive_smmu0_bclk_cfgcnt_START  (1)
#define SOC_CONFIG_HIEPS_COMMON_CTRL1_cactive_smmu0_bclk_cfgcnt_END    (6)
#define SOC_CONFIG_HIEPS_COMMON_CTRL1_gt_cclk_smmuo_bypass_START       (7)
#define SOC_CONFIG_HIEPS_COMMON_CTRL1_gt_cclk_smmuo_bypass_END         (7)
#define SOC_CONFIG_HIEPS_COMMON_CTRL1_cactive_smmu0_cclk_cfgcnt_START  (8)
#define SOC_CONFIG_HIEPS_COMMON_CTRL1_cactive_smmu0_cclk_cfgcnt_END    (13)


/*****************************************************************************
 �ṹ��    : SOC_CONFIG_HIEPS_IPCLKRST_BYPASS0_UNION
 �ṹ˵��  : HIEPS_IPCLKRST_BYPASS0 �Ĵ����ṹ���塣��ַƫ����:0x128����ֵ:0x00000000�����:32
 �Ĵ���˵��: CRG���ƼĴ���0��
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  hieps_ipc_clkrst_bypass      : 1;  /* bit[0]    : ������ָʾ�Ƿ�bypass
                                                                        1��������flag�øߣ�����slave���������߼���bypass
                                                                        0���������߼���Ч */
        unsigned int  hieps_timer_clkrst_bypass    : 1;  /* bit[1]    : ͬbit0 */
        unsigned int  hieps_uart_clkrst_bypass     : 1;  /* bit[2]    : ͬbit0 */
        unsigned int  hieps_trng_clkrst_bypass     : 1;  /* bit[3]    : ͬbit0 */
        unsigned int  hieps_wdog_clkrst_bypass     : 1;  /* bit[4]    : ͬbit0 */
        unsigned int  hieps_sce_km_clkrst_bypass   : 1;  /* bit[5]    : ͬbit0 */
        unsigned int  hieps_pke_clkrst_bypass      : 1;  /* bit[6]    : ͬbit0 */
        unsigned int  hieps_arc_clkrst_bypass      : 1;  /* bit[7]    : ͬbit0 */
        unsigned int  hieps_mmu_clkrst_bypass      : 1;  /* bit[8]    : ͬbit0 */
        unsigned int  hieps_ddr_crpt_clkrst_bypass : 1;  /* bit[9]    : ͬbit0 */
        unsigned int  hieps_sce2_clkrst_bypass     : 1;  /* bit[10]   : ͬbit0 */
        unsigned int  hieps_pke2_clkrst_bypass     : 1;  /* bit[11]   : ͬbit0 */
        unsigned int  hieps_i2c_clkrst_bypass      : 1;  /* bit[12]   : ͬbit0 */
        unsigned int  hieps_spi_clkrst_bypass      : 1;  /* bit[13]   : ͬbit0 */
        unsigned int  reserved                     : 18; /* bit[14-31]:  */
    } reg;
} SOC_CONFIG_HIEPS_IPCLKRST_BYPASS0_UNION;
#endif
#define SOC_CONFIG_HIEPS_IPCLKRST_BYPASS0_hieps_ipc_clkrst_bypass_START       (0)
#define SOC_CONFIG_HIEPS_IPCLKRST_BYPASS0_hieps_ipc_clkrst_bypass_END         (0)
#define SOC_CONFIG_HIEPS_IPCLKRST_BYPASS0_hieps_timer_clkrst_bypass_START     (1)
#define SOC_CONFIG_HIEPS_IPCLKRST_BYPASS0_hieps_timer_clkrst_bypass_END       (1)
#define SOC_CONFIG_HIEPS_IPCLKRST_BYPASS0_hieps_uart_clkrst_bypass_START      (2)
#define SOC_CONFIG_HIEPS_IPCLKRST_BYPASS0_hieps_uart_clkrst_bypass_END        (2)
#define SOC_CONFIG_HIEPS_IPCLKRST_BYPASS0_hieps_trng_clkrst_bypass_START      (3)
#define SOC_CONFIG_HIEPS_IPCLKRST_BYPASS0_hieps_trng_clkrst_bypass_END        (3)
#define SOC_CONFIG_HIEPS_IPCLKRST_BYPASS0_hieps_wdog_clkrst_bypass_START      (4)
#define SOC_CONFIG_HIEPS_IPCLKRST_BYPASS0_hieps_wdog_clkrst_bypass_END        (4)
#define SOC_CONFIG_HIEPS_IPCLKRST_BYPASS0_hieps_sce_km_clkrst_bypass_START    (5)
#define SOC_CONFIG_HIEPS_IPCLKRST_BYPASS0_hieps_sce_km_clkrst_bypass_END      (5)
#define SOC_CONFIG_HIEPS_IPCLKRST_BYPASS0_hieps_pke_clkrst_bypass_START       (6)
#define SOC_CONFIG_HIEPS_IPCLKRST_BYPASS0_hieps_pke_clkrst_bypass_END         (6)
#define SOC_CONFIG_HIEPS_IPCLKRST_BYPASS0_hieps_arc_clkrst_bypass_START       (7)
#define SOC_CONFIG_HIEPS_IPCLKRST_BYPASS0_hieps_arc_clkrst_bypass_END         (7)
#define SOC_CONFIG_HIEPS_IPCLKRST_BYPASS0_hieps_mmu_clkrst_bypass_START       (8)
#define SOC_CONFIG_HIEPS_IPCLKRST_BYPASS0_hieps_mmu_clkrst_bypass_END         (8)
#define SOC_CONFIG_HIEPS_IPCLKRST_BYPASS0_hieps_ddr_crpt_clkrst_bypass_START  (9)
#define SOC_CONFIG_HIEPS_IPCLKRST_BYPASS0_hieps_ddr_crpt_clkrst_bypass_END    (9)
#define SOC_CONFIG_HIEPS_IPCLKRST_BYPASS0_hieps_sce2_clkrst_bypass_START      (10)
#define SOC_CONFIG_HIEPS_IPCLKRST_BYPASS0_hieps_sce2_clkrst_bypass_END        (10)
#define SOC_CONFIG_HIEPS_IPCLKRST_BYPASS0_hieps_pke2_clkrst_bypass_START      (11)
#define SOC_CONFIG_HIEPS_IPCLKRST_BYPASS0_hieps_pke2_clkrst_bypass_END        (11)
#define SOC_CONFIG_HIEPS_IPCLKRST_BYPASS0_hieps_i2c_clkrst_bypass_START       (12)
#define SOC_CONFIG_HIEPS_IPCLKRST_BYPASS0_hieps_i2c_clkrst_bypass_END         (12)
#define SOC_CONFIG_HIEPS_IPCLKRST_BYPASS0_hieps_spi_clkrst_bypass_START       (13)
#define SOC_CONFIG_HIEPS_IPCLKRST_BYPASS0_hieps_spi_clkrst_bypass_END         (13)


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
        unsigned int  reserved            : 26; /* bit[6-31]:  */
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
        unsigned int  reserved             : 6;  /* bit[26-31]: ����RSA/ARC/SM9 SPRAM
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
                                                             SPA����ʹ��bit[13:11][15:14] */
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
 �ṹ˵��  : HIEPS_INTR_MASK �Ĵ����ṹ���塣��ַƫ����:0x214����ֵ:0x0001FFFF�����:32
 �Ĵ���˵��: �ж�MASK
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  hieps2ap_intr_mask       : 1;  /* bit[0]    : EPS��۵��쳣�ж��ͳ�ǰ��һ��mask��
                                                                    1��:���Σ����͸��ⲿ�жϣ�Ĭ������
                                                                    0�������� */
        unsigned int  cfg_alarm_km_mask        : 1;  /* bit[1]    : Ĭ������ */
        unsigned int  cfg_alarm_sce_mask       : 1;  /* bit[2]    : Ĭ������ */
        unsigned int  cfg_alarm_rsa_mask       : 1;  /* bit[3]    : Ĭ������ */
        unsigned int  cfg_alarm_ecc_mask       : 1;  /* bit[4]    : Ĭ������ */
        unsigned int  cfg_alarm_trng_mask      : 1;  /* bit[5]    : Ĭ������ */
        unsigned int  cfg_int_trng_mask        : 1;  /* bit[6]    : Ĭ������ */
        unsigned int  cfg_intr_func_mbist      : 1;  /* bit[7]    : Ĭ�����Σ����ν���Function mbistʱ�ϱ����ж� */
        unsigned int  cfg_alarm_sm9_mask       : 1;  /* bit[8]    : Ĭ������ */
        unsigned int  cfg_alarm_ddrenc_mask    : 1;  /* bit[9]    : Ĭ������ */
        unsigned int  cfg_alarm_sce2_mask      : 1;  /* bit[10]   : Ĭ������ */
        unsigned int  cfg_alarm_rsa3_mask      : 1;  /* bit[11]   : Ĭ������ */
        unsigned int  cfg_alarm_rsa2_mask      : 1;  /* bit[12]   : Ĭ������ */
        unsigned int  cfg_npu_iso_posedge_mask : 1;  /* bit[13]   : NPUǶλʹ���ź��������жϵ����ο���
                                                                    1������
                                                                    0�������� */
        unsigned int  cfg_npu_rst_posedge_mask : 1;  /* bit[14]   : NPU��λ�ź��������жϵ����ο���
                                                                    1������
                                                                    0�������� */
        unsigned int  cfg_npu_iso_negedge_mask : 1;  /* bit[15]   : NPUǶλʹ���ź��½����жϵ����ο���
                                                                    1������
                                                                    0�������� */
        unsigned int  cfg_npu_rst_negedge_mask : 1;  /* bit[16]   : NPU��λ�ź��½����жϵ����ο���
                                                                    1������
                                                                    0�������� */
        unsigned int  reserved                 : 15; /* bit[17-31]:  */
    } reg;
} SOC_CONFIG_HIEPS_INTR_MASK_UNION;
#endif
#define SOC_CONFIG_HIEPS_INTR_MASK_hieps2ap_intr_mask_START        (0)
#define SOC_CONFIG_HIEPS_INTR_MASK_hieps2ap_intr_mask_END          (0)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_alarm_km_mask_START         (1)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_alarm_km_mask_END           (1)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_alarm_sce_mask_START        (2)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_alarm_sce_mask_END          (2)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_alarm_rsa_mask_START        (3)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_alarm_rsa_mask_END          (3)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_alarm_ecc_mask_START        (4)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_alarm_ecc_mask_END          (4)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_alarm_trng_mask_START       (5)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_alarm_trng_mask_END         (5)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_int_trng_mask_START         (6)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_int_trng_mask_END           (6)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_intr_func_mbist_START       (7)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_intr_func_mbist_END         (7)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_alarm_sm9_mask_START        (8)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_alarm_sm9_mask_END          (8)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_alarm_ddrenc_mask_START     (9)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_alarm_ddrenc_mask_END       (9)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_alarm_sce2_mask_START       (10)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_alarm_sce2_mask_END         (10)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_alarm_rsa3_mask_START       (11)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_alarm_rsa3_mask_END         (11)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_alarm_rsa2_mask_START       (12)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_alarm_rsa2_mask_END         (12)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_npu_iso_posedge_mask_START  (13)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_npu_iso_posedge_mask_END    (13)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_npu_rst_posedge_mask_START  (14)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_npu_rst_posedge_mask_END    (14)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_npu_iso_negedge_mask_START  (15)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_npu_iso_negedge_mask_END    (15)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_npu_rst_negedge_mask_START  (16)
#define SOC_CONFIG_HIEPS_INTR_MASK_cfg_npu_rst_negedge_mask_END    (16)


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
        unsigned int  hieps2lm_busy        : 3;  /* bit[0-2]  : ÿbit������ʾ��������������ĸ�ģ��Ĺ���״̬��
                                                                1��������load_monitor��״̬Ϊbusy��
                                                                0��������load_monitor��״̬Ϊidle�� */
        unsigned int  hieps_perf_stat_en   : 1;  /* bit[3]    : ֻ�ܾ�̬���á�
                                                                Ĭ�Ͽ����Ǽ���ͨ��
                                                                1������perf_stat���EPS AXI���߲�����
                                                                0��������perf_stat���EPS AXI���߲��� */
        unsigned int  hieps2qic_disable    : 1;  /* bit[4]    : ֻ�ܾ�̬���á�
                                                                �رպ��޷���ѯHiEPS QIC�Ƿ��в�����pending trans����
                                                                1���رգ����ɲ�ѯ��
                                                                0��Ĭ��Ϊ0 ���ɲ�ѯ */
        unsigned int  hieps_perf_stat_en_1 : 1;  /* bit[5]    : ֻ�ܾ�̬���á�
                                                                Ĭ�Ͽ�������ͨ��
                                                                1������perf_stat���EPS AXI���߲�����
                                                                0��������perf_stat���EPS AXI���߲��� */
        unsigned int  reserved_0           : 1;  /* bit[6]    : SCE����������MMU��stream ID�š�reserved */
        unsigned int  reserved_1           : 1;  /* bit[7]    : SCEд��������MMU��stream ID�š�Reserved */
        unsigned int  reserved_2           : 1;  /* bit[8]    : MMU�����ʲ���stream id�İ�ȫ���ƣ�Ĭ�Ϸǰ�ȫ��reserved
                                                                0:�ǰ�ȫ
                                                                1:��ȫ */
        unsigned int  reserved_3           : 1;  /* bit[9]    : MMUд����stream id�İ�ȫ���ƣ�Ĭ�Ϸǰ�ȫ��reserved
                                                                0:�ǰ�ȫ
                                                                1:��ȫ */
        unsigned int  cfg_trust2prot_en    : 1;  /* bit[10]   : ����MMU���ڴ��Ĳ���Ȩ�ޣ�
                                                                1��MMU���ڵ�Ȩ��Ϊprotected��
                                                                0��MMU���ڵ�Ȩ��ΪNon-trusted�� */
        unsigned int  reserved_4           : 21; /* bit[11-31]:  */
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
#define SOC_CONFIG_HIEPS_SEC_CTRL_cfg_trust2prot_en_START     (10)
#define SOC_CONFIG_HIEPS_SEC_CTRL_cfg_trust2prot_en_END       (10)


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
        unsigned int  reserved          : 21; /* bit[11-31]:  */
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
 �ṹ˵��  : SCE_MST_PRIORITY �Ĵ����ṹ���塣��ַƫ����:0x400����ֵ:0x0000006A�����:32
 �Ĵ���˵��: ���������ȼ����üĴ���
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  arc_mst_priority_unenc2to1 : 1;  /* bit[0]   : �Ǽ���ͨ�� AXI 2to1�� M1�����ȼ����� bit[0]��bit[1]���ʹ�ã�����Ϊ1�����ȼ���������Ϊ0�����ȼ�������������������ȼ���ͬ����ARC���ȼ��� */
        unsigned int  sce_mst_priority_unenc2to1 : 1;  /* bit[1]   : �Ǽ���ͨ�� AXI 2to1�� M2�����ȼ����� bit[0]��bit[1]���ʹ�ã�����Ϊ1�����ȼ���������Ϊ0�����ȼ�������������������ȼ���ͬ����ARC���ȼ��� */
        unsigned int  arc_mst_priority_enc2to1   : 1;  /* bit[2]   : ����ͨ�� AXI 2to1�� M1�����ȼ����� bit[2]��bit[3]���ʹ�ã�����Ϊ1�����ȼ���������Ϊ0�����ȼ�������������������ȼ���ͬ����ARC���ȼ��� */
        unsigned int  sce_mst_priority_enc2to1   : 1;  /* bit[3]   : ����ͨ�� AXI 2to1�� M2�����ȼ����� bit[2]��bit[3]���ʹ�ã�����Ϊ1�����ȼ���������Ϊ0�����ȼ�������������������ȼ���ͬ����ARC���ȼ��� */
        unsigned int  arc_mst_priority_cfg2to1   : 1;  /* bit[4]   : ���ÿ� AXI 2to1�� ARC���ȼ����� bit[4]��bit[5]���ʹ�ã�����Ϊ1�����ȼ���������Ϊ0�����ȼ�������������������ȼ���ͬ����SCE���ȼ��� */
        unsigned int  sce_mst_priority_cfg2to1   : 1;  /* bit[5]   : ���ÿ� AXI 2to1�� SCE���ȼ����� bit[4]��bit[5]���ʹ�ã�����Ϊ1�����ȼ���������Ϊ0�����ȼ�������������������ȼ���ͬ����SCE���ȼ��� */
        unsigned int  sce_mst_priority_sce2to3   : 1;  /* bit[6]   : AXI 2to3��SCE���ȼ����� bit[6]��bit[7]���ʹ�ã�����Ϊ1�����ȼ���������Ϊ0�����ȼ�������������������ȼ���ͬ����SCE1���ȼ��� */
        unsigned int  sce2_mst_priority_sce2to3  : 1;  /* bit[7]   : AXI 2to3��SCE2���ȼ����� bit[6]��bit[7]���ʹ�ã�����Ϊ1�����ȼ���������Ϊ0�����ȼ�������������������ȼ���ͬ����SCE1���ȼ��� */
        unsigned int  reserved                   : 24; /* bit[8-31]: reserved */
    } reg;
} SOC_CONFIG_SCE_MST_PRIORITY_UNION;
#endif
#define SOC_CONFIG_SCE_MST_PRIORITY_arc_mst_priority_unenc2to1_START  (0)
#define SOC_CONFIG_SCE_MST_PRIORITY_arc_mst_priority_unenc2to1_END    (0)
#define SOC_CONFIG_SCE_MST_PRIORITY_sce_mst_priority_unenc2to1_START  (1)
#define SOC_CONFIG_SCE_MST_PRIORITY_sce_mst_priority_unenc2to1_END    (1)
#define SOC_CONFIG_SCE_MST_PRIORITY_arc_mst_priority_enc2to1_START    (2)
#define SOC_CONFIG_SCE_MST_PRIORITY_arc_mst_priority_enc2to1_END      (2)
#define SOC_CONFIG_SCE_MST_PRIORITY_sce_mst_priority_enc2to1_START    (3)
#define SOC_CONFIG_SCE_MST_PRIORITY_sce_mst_priority_enc2to1_END      (3)
#define SOC_CONFIG_SCE_MST_PRIORITY_arc_mst_priority_cfg2to1_START    (4)
#define SOC_CONFIG_SCE_MST_PRIORITY_arc_mst_priority_cfg2to1_END      (4)
#define SOC_CONFIG_SCE_MST_PRIORITY_sce_mst_priority_cfg2to1_START    (5)
#define SOC_CONFIG_SCE_MST_PRIORITY_sce_mst_priority_cfg2to1_END      (5)
#define SOC_CONFIG_SCE_MST_PRIORITY_sce_mst_priority_sce2to3_START    (6)
#define SOC_CONFIG_SCE_MST_PRIORITY_sce_mst_priority_sce2to3_END      (6)
#define SOC_CONFIG_SCE_MST_PRIORITY_sce2_mst_priority_sce2to3_START   (7)
#define SOC_CONFIG_SCE_MST_PRIORITY_sce2_mst_priority_sce2to3_END     (7)


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
        unsigned int  arc_arhint  : 4;  /* bit[0-3]  : Arc��ͨ����hint�ź�����: ��axcacheΪnon_cacheable������£�4��h0��ʾ������system cache������ֵ�ɷ��ʵ�system cache */
        unsigned int  arc_awhint  : 4;  /* bit[4-7]  : Arcдͨ����hint�ź�����: ��axcacheΪnon_cacheable������£�4��h0��ʾ������system cache������ֵ�ɷ��ʵ�system cache */
        unsigned int  sce_arhint  : 4;  /* bit[8-11] : Sce��ͨ����hint�ź�����: ��axcacheΪnon_cacheable������£�4��h0��ʾ������system cache������ֵ�ɷ��ʵ�system cache */
        unsigned int  sce_awhint  : 4;  /* bit[12-15]: Sceдͨ����hint�ź�����: ��axcacheΪnon_cacheable������£�4��h0��ʾ������system cache������ֵ�ɷ��ʵ�system cache */
        unsigned int  sce2_arhint : 4;  /* bit[16-19]: Sce2��ͨ����hint�ź�����: ��axcacheΪnon_cacheable������£�4��h0��ʾ������system cache������ֵ�ɷ��ʵ�system cache */
        unsigned int  sce2_awhint : 4;  /* bit[20-23]: Sce2дͨ����hint�ź�����: ��axcacheΪnon_cacheable������£�4��h0��ʾ������system cache������ֵ�ɷ��ʵ�system cache */
        unsigned int  reserved    : 8;  /* bit[24-31]: reserved */
    } reg;
} SOC_CONFIG_HIEPS_HINT_UNION;
#endif
#define SOC_CONFIG_HIEPS_HINT_arc_arhint_START   (0)
#define SOC_CONFIG_HIEPS_HINT_arc_arhint_END     (3)
#define SOC_CONFIG_HIEPS_HINT_arc_awhint_START   (4)
#define SOC_CONFIG_HIEPS_HINT_arc_awhint_END     (7)
#define SOC_CONFIG_HIEPS_HINT_sce_arhint_START   (8)
#define SOC_CONFIG_HIEPS_HINT_sce_arhint_END     (11)
#define SOC_CONFIG_HIEPS_HINT_sce_awhint_START   (12)
#define SOC_CONFIG_HIEPS_HINT_sce_awhint_END     (15)
#define SOC_CONFIG_HIEPS_HINT_sce2_arhint_START  (16)
#define SOC_CONFIG_HIEPS_HINT_sce2_arhint_END    (19)
#define SOC_CONFIG_HIEPS_HINT_sce2_awhint_START  (20)
#define SOC_CONFIG_HIEPS_HINT_sce2_awhint_END    (23)


/*****************************************************************************
 �ṹ��    : SOC_CONFIG_HIEPS_SPI_I2C_CTRL_UNION
 �ṹ˵��  : HIEPS_SPI_I2C_CTRL �Ĵ����ṹ���塣��ַƫ����:0x420����ֵ:0x00000000�����:32
 �Ĵ���˵��: SPI/I2C���ÿ�������
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  hieps_spi_req : 4;  /* bit[0-3] : hieps_spi_reqʹ��4bit������ 4'b1010���л���hieps�ڲ���spi pin;
                                                        4'b0101���л���hieps�ⲿ��spi pin;
                                                        4'b0000��hieps��λʱ��ֵ����ʾ����֮ǰpin�ĸ���ѡ��
                                                        д������ֵΪ��ЧֵҲ�������쳣alarm�� */
        unsigned int  hieps_i2c_req : 4;  /* bit[4-7] : hieps_i2c_reqʹ��4bit������ 4'b1010���л���hieps�ڲ���i2c pin;
                                                        4'b0101���л���hieps�ⲿ��i2c pin;
                                                        4'b0000��hieps��λʱ��ֵ����ʾ����֮ǰpin�ĸ���ѡ��
                                                        д������ֵΪ��ЧֵҲ�������쳣alarm�� */
        unsigned int  reserved      : 24; /* bit[8-31]: reserved */
    } reg;
} SOC_CONFIG_HIEPS_SPI_I2C_CTRL_UNION;
#endif
#define SOC_CONFIG_HIEPS_SPI_I2C_CTRL_hieps_spi_req_START  (0)
#define SOC_CONFIG_HIEPS_SPI_I2C_CTRL_hieps_spi_req_END    (3)
#define SOC_CONFIG_HIEPS_SPI_I2C_CTRL_hieps_i2c_req_START  (4)
#define SOC_CONFIG_HIEPS_SPI_I2C_CTRL_hieps_i2c_req_END    (7)


/*****************************************************************************
 �ṹ��    : SOC_CONFIG_HIEPS_SPI_I2C_ACK_UNION
 �ṹ˵��  : HIEPS_SPI_I2C_ACK �Ĵ����ṹ���塣��ַƫ����:0x424����ֵ:0x00000055�����:32
 �Ĵ���˵��: SPI/I2C����״̬��ѯ
*****************************************************************************/
#ifndef __SOC_H_FOR_ASM__
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  hieps_spi_ack : 4;  /* bit[0-3] : ��ѯspi pin��״̬��
                                                        4'b1010���л���hieps�ڲ���spi pin;
                                                        4'b0101���л���hieps�ⲿ��spi pin; */
        unsigned int  hieps_i2c_ack : 4;  /* bit[4-7] : ��ѯi2c pin��״̬��
                                                        4'b1010���л���hieps�ڲ���i2c pin;
                                                        4'b0101���л���hieps�ⲿ��i2c pin; */
        unsigned int  reserved      : 24; /* bit[8-31]: reserved */
    } reg;
} SOC_CONFIG_HIEPS_SPI_I2C_ACK_UNION;
#endif
#define SOC_CONFIG_HIEPS_SPI_I2C_ACK_hieps_spi_ack_START  (0)
#define SOC_CONFIG_HIEPS_SPI_I2C_ACK_hieps_spi_ack_END    (3)
#define SOC_CONFIG_HIEPS_SPI_I2C_ACK_hieps_i2c_ack_START  (4)
#define SOC_CONFIG_HIEPS_SPI_I2C_ACK_hieps_i2c_ack_END    (7)


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
