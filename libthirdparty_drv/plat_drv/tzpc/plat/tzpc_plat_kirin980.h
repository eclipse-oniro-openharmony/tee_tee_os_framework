/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: kirin980 tzpc configure
 * Create: 2020-03-02
 */

#ifndef __TZPC_PLAT_KIRIN980__
#define __TZPC_PLAT_KIRIN980__

enum {
	/* PORT[0] */
	TZPC_SLAVE_PERI_IOC_REGION0,  /* bit0 */
	TZPC_SLAVE_PERI_IOC_REGION1,  /* bit1 */
	TZPC_SLAVE_PERI_IOC_REGION2,  /* bit2 */
	TZPC_SLAVE_PERI_IOC_REGION3,  /* bit3 */
	TZPC_SLAVE_PERI_IOC_REGION4,  /* bit4 */
	TZPC_SLAVE_PERI_IOC_REGION5,  /* bit5 */
	TZPC_SLAVE_PERI_IOC_REGION6,  /* bit6 */
	TZPC_SLAVE_PERI_IOC_REGION7,  /* bit7 */
	TZPC_SLAVE_PERI_IOC_REGION8,  /* bit8 */
	TZPC_SLAVE_PERI_IOC_REGION9,  /* bit9 */
	TZPC_SLAVE_PERI_IOC_REGION10, /* bit10 */
	TZPC_SLAVE_PERI_IOC_REGION16, /* bit16 */
	/* PORT[1] */
	TZPC_SLAVE_TIMER9,        /* bit2 */
	TZPC_SLAVE_TIMER10,       /* bit3 */
	TZPC_SLAVE_TIMER11,       /* bit4 */
	TZPC_SLAVE_TIMER12,       /* bit5 */
	TZPC_SLAVE_PCTRL_REGION1, /* bit6 */
	TZPC_SLAVE_PCTRL_REGION2, /* bit7 */
	TZPC_SLAVE_PCTRL_REGION3, /* bit8 */
	TZPC_SLAVE_PCTRL_REGION4, /* bit9 */
	TZPC_SLAVE_PWM,           /* bit10 */
	TZPC_SLAVE_CFG_BLPWM,     /* bit11 */
	TZPC_SLAVE_WATCHDOG0,     /* bit12 */
	TZPC_SLAVE_WATCHDOG1,     /* bit13 */
	TZPC_SLAVE_GPIO0,         /* bit14 */
	TZPC_SLAVE_GPIO1,         /* bit15 */
	TZPC_SLAVE_GPIO2,         /* bit16 */
	TZPC_SLAVE_GPIO3,         /* bit17 */
	TZPC_SLAVE_GPIO4,         /* bit18 */
	TZPC_SLAVE_GPIO5,         /* bit19 */
	TZPC_SLAVE_GPIO6,         /* bit20 */
	TZPC_SLAVE_GPIO7,         /* bit21 */
	TZPC_SLAVE_GPIO8,         /* bit22 */
	TZPC_SLAVE_GPIO9,         /* bit23 */
	TZPC_SLAVE_GPIO10,        /* bit24 */
	TZPC_SLAVE_GPIO11,        /* bit25 */
	TZPC_SLAVE_GPIO12,        /* bit26 */
	TZPC_SLAVE_GPIO13,        /* bit27 */
	TZPC_SLAVE_GPIO14,        /* bit28 */
	TZPC_SLAVE_GPIO15,        /* bit29 */
	TZPC_SLAVE_GPIO16,        /* bit30 */
	TZPC_SLAVE_GPIO17,        /* bit31 */
	/* PORT[2] */
	TZPC_SLAVE_GPIO20,                     /* bit2 */
	TZPC_SLAVE_GPIO21,                     /* bit3 */
	TZPC_SLAVE_PERI_LOADMONITOR0,          /* bit4 */
	TZPC_SLAVE_CTF,                        /* bit5 */
	TZPC_SLAVE_GPIO0_SE,                   /* bit6 */
	TZPC_SLAVE_ATGC,                       /* bit7 */
	TZPC_SLAVE_PERI_LOADMONITOR1,          /* bit8 */
	TZPC_SLAVE_G3D_FIREWALL_ENABLE,        /* bit16 */
	TZPC_SLAVE_G3D_FIREWALL_ERR_RESP,      /* bit17 */
	TZPC_SLAVE_G3D_FIREWALL_SEL0_SEL2_SEL, /* bit18 */
	TZPC_SLAVE_G3D_SECURE_PROPERTY0,       /* bit20 */
	TZPC_SLAVE_G3D_SECURE_PROPERTY1,       /* bit21 */
	/* PORT[3] */
	TZPC_SLAVE_PCIE_FIREWALL_ENABLE,         /* bit8 */
	TZPC_SLAVE_PCIE_FIREWALL_ERR_RESP,       /* bit9 */
	TZPC_SLAVE_PCIE_FIREWALL_ECURE_PROPERTY, /* bit10 */
	TZPC_SLAVE_SD30,                         /* bit28 */
	TZPC_SLAVE_SDIO0,                        /* bit29 */
	TZPC_SLAVE_MMC0_SYS_CTRL,                /* bit30 */
	/* PORT[4] */
	TZPC_SLAVE_USB3OTG,               /* bit1 */
	TZPC_SLAVE_USB3OTG_BC,            /* bit2 */
	TZPC_SLAVE_PERF_STAT,             /* bit3 */
	TZPC_SLAVE_IPCNS,                 /* bit5 */
	TZPC_SLAVE_IPC,                   /* bit6 */
	TZPC_SLAVE_CODEC_SSI,             /* bit11 */
	TZPC_SLAVE_IPC_MDM_S,             /* bit12 */
	TZPC_SLAVE_IPC_MDM_NS,            /* bit13 */
	TZPC_SLAVE_UART0,                 /* bit14 */
	TZPC_SLAVE_UART1,                 /* bit15 */
	TZPC_SLAVE_UART2,                 /* bit16 */
	TZPC_SLAVE_UART4,                 /* bit17 */
	TZPC_SLAVE_UART5,                 /* bit18 */
	TZPC_SLAVE_SPI1,                  /* bit19 */
	TZPC_SLAVE_I2C3,                  /* bit20 */
	TZPC_SLAVE_I2C4,                  /* bit21 */
	TZPC_SLAVE_DDRC_SECURE_BOOT_LOCK, /* bit22 */
	TZPC_SLAVE_I2C6,                  /* bit23 */
	TZPC_SLAVE_SPI4,                  /* bit25 */
	TZPC_SLAVE_I2C7,                  /* bit26 */
	TZPC_SLAVE_UFS_SYS_CTRL,          /* bit28 */
	TZPC_SLAVE_UFS_CFG,               /* bit29 */
	TZPC_SLAVE_MMC0_IOC,              /* bit30 */
	TZPC_SLAVE_MMC1_IOC,              /* bit31 */
	/* PORT[5] */
	TZPC_SLAVE_LPM3_PMUI2C1,           /* bit0 */
	TZPC_SLAVE_LPM3_TSENSORC,          /* bit2 */
	TZPC_SLAVE_LPM3_PMC,               /* bit3 */
	TZPC_SLAVE_LPM3_UART,              /* bit4 */
	TZPC_SLAVE_LPM3_PMUI2C0,           /* bit5 */
	TZPC_SLAVE_CPU_PERI_CRG_REGION1,   /* bit6 */
	TZPC_SLAVE_PERI_CRG_REGION1,       /* bit7 */
	TZPC_SLAVE_PERI_CRG_REGION2,       /* bit8 */
	TZPC_SLAVE_PERI_CRG_REGION3,       /* bit9 */
	TZPC_SLAVE_PERI_CRG_REGION4,       /* bit10 */
	TZPC_SLAVE_PERI_CRG_REGION5,       /* bit11 */
	TZPC_SLAVE_LPM3_WD,                /* bit12 */
	TZPC_SLAVE_LPM3_TIMER,             /* bit13 */
	TZPC_SLAVE_LPM3_CONFIG,            /* bit14 */
	TZPC_SLAVE_CPU_PERI_CRG_REGION0_3, /* bit15 */
	TZPC_SLAVE_LPM3_RAM,               /* bit17 */
	TZPC_SLAVE_CPU_PERI_CRG_REGION2,   /* bit19 */
	/* PORT[6] */
	TZPC_MASTER_LPM3,       /* bit0 */
	TZPC_MASTER_SD3,        /* bit5 */
	TZPC_MASTER_SDIO0,      /* bit6 */
	TZPC_MASTER_USB3OTG,    /* bit8 */
	TZPC_MASTER_G3D,        /* bit9 */
	TZPC_MASTER_PI_MONITOR, /* bit17 */
	TZPC_MASTER_PERF_STAT,  /* bit18 */
	TZPC_MASTER_UFS,        /* bit21 */
	TZPC_MASTER_PCIE0,      /* bit22 */
	/* PORT[7] */
	TZPC_SLAVE_PSAM_NS_REGION,    /* bit0 */
	TZPC_SLAVE_IPF_NS_REGION,     /* bit1 */
	TZPC_SLAVE_PSAM_S_REGION,     /* bit2 */
	TZPC_SLAVE_IPF_S_REGION,      /* bit3 */
	TZPC_SLAVE_MEDIA_CRG_REGION0, /* bit16 */
	TZPC_SLAVE_MEDIA_CRG_REGION1, /* bit17 */
	TZPC_SLAVE_MEDIA_CRG_REGION2, /* bit18 */
	TZPC_SLAVE_MEDIA_CRG_REGION3, /* bit19 */
	TZPC_SLAVE_MEDIA2_CRG,        /* bit20 */
	/* PORT[8] */
	TZPC_SLAVE_VIVOBUS_FIREWALL_ENABLE,             /* bit0 */
	TZPC_SLAVE_VIVOBUS_FIREWALL_ERR_RESP,           /* bit1 */
	TZPC_SLAVE_VIVOBUS_FIREWALL_SEL0_SEL2_SEL,      /* bit2 */
	TZPC_SLAVE_IVP_CFG_FIREWALL_ENABLE,             /* bit4  */
	TZPC_SLAVE_SMMU_FIREWALL_ENABLE,                /* bit5 */
	TZPC_SLAVE_ISP_CFG_SECURE_PROPERTY0,            /* bit6 */
	TZPC_SLAVE_ISP_CFG_SECURE_PROPERTY1,            /* bit7 */
	TZPC_SLAVE_IVP_CFG_SECURE_PROPERTY0,            /* bit8 */
	TZPC_SLAVE_IVP_CFG_SECURE_PROPERTY1,            /* bit9 */
	TZPC_SLAVE_VCODECBUS_FIREWALL_ENABLE,           /* bit12 */
	TZPC_SLAVE_VCODECBUS_FIREWALL_ERR_RESP,         /* bit13 */
	TZPC_SLAVE_VCODECBUS_FIREWALL_SEL0_SEL2_SEL,    /* bit14 */
	TZPC_SLAVE_DDRC_FIREWALL_ENABLE,                /* bit20 */
	TZPC_SLAVE_DDRC_FIREWALL_ERR_RESP,              /* bit21 */
	TZPC_SLAVE_DDRC_FIREWALL_SEL0_SEL2_SEL,         /* bit22 */
	TZPC_SLAVE_DDRC_MPU_INTERFACE_SECURE_PROPERTY0, /* bit24 */
	TZPC_SLAVE_DDRC_MPU_INTERFACE_SECURE_PROPERTY1, /* bit25 */
	/* PORT[0] */
	TZPC_SLAVE_EFUSEC,        /* bit0 */
	TZPC_SLAVE_RTC0,          /* bit1 */
	TZPC_SLAVE_RTC1,          /* bit2 */
	TZPC_SLAVE_SCI0,          /* bit3 */
	TZPC_SLAVE_SCI1,          /* bit4 */
	TZPC_SLAVE_SYSCNT,        /* bit5 */
	TZPC_SLAVE_SCTRL_REGION1, /* bit6 */
	TZPC_SLAVE_SCTRL_REGION2, /* bit7 */
	TZPC_SLAVE_SCTRL_REGION3, /* bit8 */
	TZPC_SLAVE_SCTRL_REGION4, /* bit9 */
	TZPC_SLAVE_SCTRL_REGION5, /* bit10 */
	TZPC_SLAVE_SCTRL_REGION6, /* bit11 */
	TZPC_SLAVE_GPIO22,        /* bit12 */
	TZPC_SLAVE_GPIO23,        /* bit13 */
	TZPC_SLAVE_GPIO24,        /* bit14 */
	TZPC_SLAVE_GPIO25,        /* bit15 */
	TZPC_SLAVE_GPIO26,        /* bit16 */
	TZPC_SLAVE_GPIO27,        /* bit17 */
	TZPC_SLAVE_WDT,           /* bit19 */
	TZPC_SLAVE_BB_DRX,        /* bit20 */
	TZPC_SLAVE_TIME0,         /* bit21 */
	TZPC_SLAVE_TIME1,         /* bit22 */
	TZPC_SLAVE_TIME2,         /* bit23 */
	TZPC_SLAVE_TIME3,         /* bit24 */
	TZPC_SLAVE_TIME4,         /* bit25 */
	TZPC_SLAVE_TIME5,         /* bit26 */
	TZPC_SLAVE_TIME6,         /* bit27 */
	TZPC_SLAVE_TIME7,         /* bit28 */
	TZPC_SLAVE_TIME8,         /* bit29 */
	/* PORT[1] */
	TZPC_SLAVE_GPIO28,         /* bit0 */
	TZPC_SLAVE_GPIO1_SE,       /* bit1 */
	TZPC_SLAVE_SPMI,           /* bit2 */
	TZPC_SLAVE_AO_IPC_S,       /* bit3 */
	TZPC_SLAVE_AO_IPC_NS,      /* bit4 */
	TZPC_SLAVE_AO_LOADMONITOR, /* bit5 */
	TZPC_SLAVE_GPIO18,         /* bit6 */
	TZPC_SLAVE_GPIO19,         /* bit7 */
	TZPC_SLAVE_SPI3,           /* bit8 */
	TZPC_SLAVE_SPMI_SEC_RTC,   /* bit10 */
	TZPC_SLAVE_GPIO29,         /* bit11 */
	TZPC_SLAVE_GPIO30,         /* bit12 */
	TZPC_SLAVE_GPIO31,         /* bit13 */
	TZPC_SLAVE_GPIO32,         /* bit14 */
	TZPC_SLAVE_GPIO33,         /* bit15 */
	/* PORT[2] */
	TZPC_SLAVE_AO_IOCG_IOMG_0,  /* bit0 */
	TZPC_SLAVE_AO_IOCG_IOMG_1,  /* bit1 */
	TZPC_SLAVE_AO_IOCG_IOMG_2,  /* bit2 */
	TZPC_SLAVE_AO_IOCG_IOMG_3,  /* bit3 */
	TZPC_SLAVE_AO_IOCG_IOMG_4,  /* bit4 */
	TZPC_SLAVE_AO_IOCG_IOMG_5,  /* bit5 */
	TZPC_SLAVE_AO_IOCG_IOMG_6,  /* bit6 */
	TZPC_SLAVE_AO_IOCG_IOMG_7,  /* bit7 */
	TZPC_SLAVE_AO_IOCG_IOMG_8,  /* bit8 */
	TZPC_SLAVE_AO_IOCG_IOMG_9,  /* bit9 */
	TZPC_SLAVE_AO_IOCG_IOMG_10, /* bit10 */
	TZPC_SLAVE_AO_IOCG_IOMG_11, /* bit11 */
	TZPC_SLAVE_AO_IOCG_IOMG_12, /* bit12 */
	TZPC_SLAVE_AO_IOCG_IOMG_13, /* bit13 */
	TZPC_SLAVE_AO_IOCG_IOMG_14, /* bit14 */
	TZPC_SLAVE_AO_IOCG_IOMG_15, /* bit15 */
	TZPC_SLAVE_AO_IOCG_IOMG_16, /* bit16 */
	TZPC_SLAVE_AO_IOCG_IOMG_17, /* bit17 */
	TZPC_SLAVE_AO_IOCG_IOMG_18, /* bit18 */
	TZPC_SLAVE_AO_IOCG_IOMG_19, /* bit19 */
	TZPC_SLAVE_AO_IOCG_IOMG_20, /* bit20 */
	TZPC_SLAVE_AO_IOCG_IOMG_21, /* bit21 */
	/* PORT[3] */
	TZPC_SLAVE_NOC_TRACE_SPIDEN, /* bit0 */
	TZPC_SLAVE_NOC_TRACE_DBGEN,  /* bit1 */

	TZPC_IP_NUM_MAX
};

#endif /* __TZPC_PLAT_KIRIN980__ */