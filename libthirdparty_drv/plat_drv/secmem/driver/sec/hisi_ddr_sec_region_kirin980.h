/*************************************************************
*�� �� �� ��:	hisi_ddr_sec_region_kirin980.h
*
*�� �� �� ��:	hisi_ddr_sec_region_kirin980.h
*
*�� �� �� ��:	���� l00353600
*
*�� �� ʱ ��:	2017-9-11
*************************************************************/

/*************************************************************
  ͷ�ļ�
*************************************************************/

/*************************************************************
  �궨��
*************************************************************/

/*should be the same as bl31*/
#define SEC_RGN_RESRVED_NUM 	(10)
#define SEC_RGN_KERNEL_READ_ONLY_RESERVED (10)	/*ASI CPU*/
#define SEC_RGN_XMODE_DUMP_RESERVED (10)		/*ASI subsys*/
#define SEC_RGN_IDENTIFICATION_RESERVED (9)
#define SEC_RGN_KERNEL_PROTECT_RESERVED (8)
#define SEC_RGN_HIFI_REBOOT_RESERVED (7)
#define SEC_RGN_ION_RESERVED (6)	/*rgn��ʼλ�� ����*/
#define SEC_RGN_ION_RESERVED_NUM (6) /*rgnԤ������*/
#define SEC_RGN_XMODE_DUMP_RESERVED_ASI0 (1)


#define REG_BASE_DMSS	(0xea980000)
#define ASI_NUM_MAX	(11)
#define CPU_ASI_NUM (6)
#define ADDR_SHIFT_MODE_1_START_ADDR    DDR_SIZE_8G
#define ADDR_SHIFT_MODE_1_END_ADDR      DDR_SIZE_8G512M
#define ADDR_SHIFT_MODE_2_START_ADDR    DDR_SIZE_15G512M
#define ADDR_SHIFT_MODE_2_END_ADDR      DDR_SIZE_16G

/*kirin980 sec rgn granularity is 64K (addr low 16bit should be 0)*/
#define SEC_RGN_ADDR_SHIFT (16)
#define SEC_RGN_ADDR_MASK (0xFFFFULL)

#define ALL_ASI_MASK (0x7FF)

/*sec region mid width mask*/
#define SEC_ASI0_MASK      (0x1F)
#define SEC_ASI12_MASK       (0xF)
#define SEC_ASI34_MASK       (0x1F)
#define SEC_ASI5_MASK       (0x3)
#define SEC_ASI679A_MASK       (0x7)
#define SEC_ASI8_MASK       (0x1F)

#define MODEM_CCPU_ASI_MASK		(0x1)
#define VDEC_ASI_MASK		((1<<1))
#define ISP_DSS_ASI_MASK	((1<<3))
#define IVP32_ASI_MASK		(1<<5)
#define CPU_GPU_ASI_MASK 	((1<<6)|(1<<9))
#define SUBSYS_ASI_MASK 	(1<<8)
#define DDR_SEC_ALL_ASI_MASK	(MODEM_CCPU_ASI_MASK | VDEC_ASI_MASK |\
	ISP_DSS_ASI_MASK | IVP32_ASI_MASK | CPU_GPU_ASI_MASK | SUBSYS_ASI_MASK)

/*KIRIN980 MID bit[0-4]*/
/*ASI 8*/
#define SOC_DJTAG_M_MID		(0x05)
#define SOC_CC712_MID		(0x0A)
#define SOC_TOP_CSSYS_MID	(0x0F)
#define SOC_DMAC_MID		(0x10)
#define DJTAG_M_MID		(SOC_DJTAG_M_MID & SEC_ASI8_MASK)
#define CC712_MID		(SOC_CC712_MID & SEC_ASI8_MASK)
#define TOP_CSSYS_MID	(SOC_TOP_CSSYS_MID & SEC_ASI8_MASK)
#define DMAC_MID		(SOC_DMAC_MID & SEC_ASI8_MASK)

/*ASI 1/2*/
#define SOC_ICS_MID					(0x68)
#define SOC_ICS2_MID				(0x6F)
#define ICS_MID		(SOC_ICS_MID & SEC_ASI12_MASK)
#define ICS2_MID	(SOC_ICS2_MID & SEC_ASI12_MASK)

/*ASI 6/7/9/10*/
#define SOC_CPU_ARTEMIS_MID            (0x78)
#define SOC_CPU_A53_MID             (0x79)

#define CPU_ARTEMIS_MID	(SOC_CPU_ARTEMIS_MID & SEC_ASI679A_MASK)
#define CPU_A53_MID			(SOC_CPU_A53_MID & SEC_ASI679A_MASK)
#define CPU_ALL	((1 << CPU_ARTEMIS_MID) | (1 << CPU_A53_MID))

#define FORBID_MID	(0x0)
#define ALL_MID	(0xFFFFFFFF)

/*************************************************************
  ö������
*************************************************************/

/*************************************************************
  �ṹ��
*************************************************************/
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  rtl_sec_rgn_num       : 6;  /* bit[0-5]  : ��ȫģ���regions������
                                                                 6'd0���ް�ȫģ�飻
                                                                 6'd1��1regions��
                                                                 6'd2��2regions��
                                                                 6'd3��3regions��
                                                                 ����
                                                                 ע�⣺���ް�ȫģ��ʱ����ȫ������ؼĴ�����Ч�� */
        unsigned int  reserved_0            : 2;  /* bit[6-7]  : ������ */
        unsigned int  rtl_sec_chk_mid_width : 3;  /* bit[8-10] : ��ȫģ���MID���λ��
                                                                 0x0���ް�ȫģ�飻
                                                                 0x1��ֻ��MID[0]����MIDȨ�޼�飻
                                                                 0x2��ֻ��MID[1:0]����MIDȨ�޼�飻
                                                                 ����
                                                                 0x5��ֻ��MID[4:0]����MIDȨ�޼�飻
                                                                 ע�⣺���ް�ȫģ��ʱ����ȫ������ؼĴ�����Ч�� */
        unsigned int  reserved_1            : 1;  /* bit[11]   : ������ */
        unsigned int  rtl_mpu_chk_mid_width : 3;  /* bit[12-14]: MPUģ���MID���λ��
                                                                 0x0���ް�ȫģ�飻
                                                                 0x1��ֻ��MID[0]����MIDȨ�޼�飻
                                                                 0x2��ֻ��MID[1:0]����MIDȨ�޼�飻
                                                                 ����
                                                                 0x5��ֻ��MID[4:0]����MIDȨ�޼�飻
                                                                 0x6��ֻ��MID[5:0]����MIDȨ�޼�飻
                                                                 ע�⣺����MPUģ��ʱ��MPU������ؼĴ�����Ч�� */
        unsigned int  reserved_2            : 1;  /* bit[15]   : ������ */
        unsigned int  rtl_rd_fifo_depth     : 5;  /* bit[16-20]: ������FIFO������ȣ�
                                                                 0x0�� 1 read transfer��
                                                                 0x1�� 2 read transfer��
                                                                 ����
                                                                 0x1F��32 read transfer�� */
        unsigned int  reserved_3            : 11; /* bit[21-31]: ������ */
    } reg;
} SOC_DMSS_ASI_RTL_INF2_UNION;
#define SOC_DMSS_ASI_RTL_INF2_rtl_sec_rgn_num_START        (0)
#define SOC_DMSS_ASI_RTL_INF2_rtl_sec_rgn_num_END          (5)
#define SOC_DMSS_ASI_RTL_INF2_rtl_sec_chk_mid_width_START  (8)
#define SOC_DMSS_ASI_RTL_INF2_rtl_sec_chk_mid_width_END    (10)
#define SOC_DMSS_ASI_RTL_INF2_rtl_mpu_chk_mid_width_START  (12)
#define SOC_DMSS_ASI_RTL_INF2_rtl_mpu_chk_mid_width_END    (14)
#define SOC_DMSS_ASI_RTL_INF2_rtl_rd_fifo_depth_START      (16)
#define SOC_DMSS_ASI_RTL_INF2_rtl_rd_fifo_depth_END        (20)
/*************************************************************
  ��������
*************************************************************/


