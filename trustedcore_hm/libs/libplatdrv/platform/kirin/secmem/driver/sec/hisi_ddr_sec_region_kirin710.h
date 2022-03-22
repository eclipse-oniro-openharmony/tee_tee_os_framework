/*************************************************************
*文 件 名 字:	hisi_ddr_sec_region_kirin710.h
*
*文 件 描 述:	hisi_ddr_sec_region_kirin710.h
*
*作 者 名 字:	刘聪 l00353600
*
*生 成 时 间:	2017-9-11
*************************************************************/

/*************************************************************
  头文件
*************************************************************/

/*************************************************************
  宏定义
*************************************************************/

/*should be the same as bl31*/
#define SEC_RGN_KERNEL_READ_ONLY_RESERVED (10)
#define SEC_RGN_TOP_CORESIGHT_RESERVED (9)
#define SEC_RGN_KERNEL_PROTECT_RESERVED (8)
#define SEC_RGN_XMODE_DUMP_RESERVED (7)
#define SEC_RGN_HIFI_REBOOT_RESERVED (6)
#define SEC_RGN_ION_RESERVED (5)	/*rgn起始位置 倒数*/
#define SEC_RGN_ION_RESERVED_NUM (5) /*rgn预留个数*/

#define REG_BASE_DMSS	(0xFFFC0000)
#define ASI_NUM_MAX	(8)
#define CPU_ASI_NUM (4)
#define ADDR_SHIFT_MODE_1_START_ADDR    DDR_SIZE_4G
#define ADDR_SHIFT_MODE_1_END_ADDR      DDR_SIZE_4G512M
#define ADDR_SHIFT_MODE_2_START_ADDR    DDR_SIZE_8G
#define ADDR_SHIFT_MODE_2_END_ADDR      DDR_SIZE_8G512M

/*kirin710 sec rgn granularity is 16K (addr low 14bit should be 0)*/
#define SEC_RGN_ADDR_SHIFT (14)
#define SEC_RGN_ADDR_MASK (0x3FFFULL)

#define ALL_ASI_MASK (0xFF)

/*sec region mid width mask*/
#define SEC_ASI0_MASK           (0x1F)
#define SEC_ASI1_MASK           (0xF)
#define SEC_ASI23_MASK          (0x1F)
#define SEC_ASI45_MASK          (0x3)
#define SEC_ASI6_MASK           (0x1F)
#define SEC_ASI7_MASK           (0x3)

#define MODEM_CCPU_ASI_MASK		(0x1)
#define VDEC_ASI_MASK		(1<<1)
#define ISP_DSS_ASI_MASK	((1<<2)|(1<<3))
#define CPU_GPU_ASI_MASK 	((1<<4)|(1<<5))
#define SUBSYS_ASI_MASK 	(1<<6)
#define IVP32_ASI_MASK		(1<<7)
#define DDR_SEC_ALL_ASI_MASK	(MODEM_CCPU_ASI_MASK | VDEC_ASI_MASK |\
	ISP_DSS_ASI_MASK | IVP32_ASI_MASK | CPU_GPU_ASI_MASK | SUBSYS_ASI_MASK)

/*KIRIN710 MID bit[0-4]*/
/*ASI 6*/
#define SOC_SEC_S_MID               (0x0A)
#define SOC_TOP_CSSYS_MID           (0x0F)
#define SEC_S_MID		(SOC_SEC_S_MID & SEC_ASI6_MASK)
#define TOP_CSSYS_MID	(SOC_TOP_CSSYS_MID & SEC_ASI6_MASK)

/*ASI 4/5*/
#define SOC_CPU_ARTEMIS_MID            (0x78)
#define SOC_CPU_A53_MID             (0x79)

#define CPU_ARTEMIS_MID	(SOC_CPU_ARTEMIS_MID & SEC_ASI45_MASK)
#define CPU_A53_MID			(SOC_CPU_A53_MID & SEC_ASI45_MASK)
#define CPU_ALL	((1 << CPU_ARTEMIS_MID) | (1 << CPU_A53_MID))

#define FORBID_MID	(0x0)
#define ALL_MID	(0xFFFFFFFF)

/*************************************************************
  枚举类型
*************************************************************/

/*************************************************************
  结构体
*************************************************************/
typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  rtl_sec_rgn_num       : 5;  /* bit[0-4]  : 安全模块的regions个数：
                                                                 5'd0：无安全模块；
                                                                 5'd1：1regions；
                                                                 5'd2：2regions；
                                                                 5'd3：3regions；
                                                                 ……
                                                                 注意：当无安全模块时，安全功能相关寄存器无效。 */
        unsigned int  reserved_0            : 3;  /* bit[5-7]  : 保留。 */
        unsigned int  rtl_sec_chk_mid_width : 3;  /* bit[8-10] : 安全模块的MID检查位宽：
                                                                 0x0：无安全模块；
                                                                 0x1：只对MID[0]进行MID权限检查；
                                                                 0x2：只对MID[1:0]进行MID权限检查；
                                                                 ……
                                                                 0x5：只对MID[4:0]进行MID权限检查；
                                                                 注意：当无安全模块时，安全功能相关寄存器无效。 */
        unsigned int  reserved_1            : 1;  /* bit[11]   : 保留。 */
        unsigned int  rtl_mpu_chk_mid_width : 3;  /* bit[12-14]: MPU模块的MID检查位宽：
                                                                 0x0：无安全模块；
                                                                 0x1：只对MID[0]进行MID权限检查；
                                                                 0x2：只对MID[1:0]进行MID权限检查；
                                                                 ……
                                                                 0x5：只对MID[4:0]进行MID权限检查；
                                                                 0x6：只对MID[5:0]进行MID权限检查；
                                                                 注意：当无MPU模块时，MPU功能相关寄存器无效。 */
        unsigned int  reserved_2            : 1;  /* bit[15]   : 保留。 */
        unsigned int  rtl_rd_fifo_depth     : 5;  /* bit[16-20]: 读数据FIFO配置深度：
                                                                 0x0： 1 read transfer；
                                                                 0x1： 2 read transfer；
                                                                 ……
                                                                 0x1F：32 read transfer。 */
        unsigned int  reserved_3            : 11; /* bit[21-31]: 保留。 */
    } reg;
} SOC_DMSS_ASI_RTL_INF2_UNION;
#define SOC_DMSS_ASI_RTL_INF2_rtl_sec_rgn_num_START        (0)
#define SOC_DMSS_ASI_RTL_INF2_rtl_sec_rgn_num_END          (4)
#define SOC_DMSS_ASI_RTL_INF2_rtl_sec_chk_mid_width_START  (8)
#define SOC_DMSS_ASI_RTL_INF2_rtl_sec_chk_mid_width_END    (10)
#define SOC_DMSS_ASI_RTL_INF2_rtl_mpu_chk_mid_width_START  (12)
#define SOC_DMSS_ASI_RTL_INF2_rtl_mpu_chk_mid_width_END    (14)
#define SOC_DMSS_ASI_RTL_INF2_rtl_rd_fifo_depth_START      (16)
#define SOC_DMSS_ASI_RTL_INF2_rtl_rd_fifo_depth_END        (20)
/*************************************************************
  函数声明
*************************************************************/


