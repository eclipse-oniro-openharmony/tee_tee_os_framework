/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: miamicw tzpc configure
 * Create: 2020-03-02
 */

#ifndef __TZPC_PLAT_MIAMICW__
#define __TZPC_PLAT_MIAMICW__

enum {
	/* PROT[0] */
	TZPC_SLAVE_EFUSEC = 0,         /* bit0 */
	TZPC_SLAVE_RTC_0,              /* bit1 */
	TZPC_SLAVE_RTC_1,              /* bit2 */
	TZPC_SLAVE_SCI_0,              /* bit3 */
	TZPC_SLAVE_SCI_1,              /* bit4 */
	TZPC_SLAVE_SYSCNT,             /* bit5 */
	TZPC_SLAVE_SCTRL_0,            /* bit6 */
	TZPC_SLAVE_SCTRL_1,            /* bit7 */
	TZPC_SLAVE_SCTRL_ASP,          /* bit8 */
	TZPC_SLAVE_SYSCTRL_SENSOR_SUB, /* bit9 */
	TZPC_SLAVE_SCTRL_HISEE,        /* bit10 */
	TZPC_SLAVE_SCTRL_OCB,          /* bit11 */
	TZPC_SLAVE_GPIO_22,            /* bit12 */
	TZPC_SLAVE_GPIO_23,            /* bit13 */
	TZPC_SLAVE_GPIO_24,            /* bit14 */
	TZPC_SLAVE_GPIO_25,            /* bit15 */
	TZPC_SLAVE_GPIO_26,            /* bit16 */
	TZPC_SLAVE_GPIO_27,            /* bit17 */
	TZPC_SLAVE_AO_IOC,             /* bit18 */
	TZPC_SLAVE_AO_IOC_GPIO,        /* bit19 */
	TZPC_SLAVE_BB_DRX,             /* bit20 */
	TZPC_SLAVE_TIMER_0,            /* bit21 */
	TZPC_SLAVE_TIMER_1,            /* bit22 */
	TZPC_SLAVE_TIMER_2,            /* bit23 */
	TZPC_SLAVE_TIMER_3,            /* bit24 */
	TZPC_SLAVE_TIMER_4,            /* bit25 */
	TZPC_SLAVE_TIMER_5,            /* bit26 */
	TZPC_SLAVE_TIMER_6,            /* bit27 */
	TZPC_SLAVE_TIMER_7,            /* bit28 */
	TZPC_SLAVE_TIMER_8,            /* bit29 */
	TZPC_SLAVE_MMBUF,              /* bit30 */
	TZPC_SLAVE_ASC,                /* bit31 */
	/* PROT[1] */
	TZPC_SLAVE_TIMER_9,  /* bit2 */
	TZPC_SLAVE_TIMER_10, /* bit3 */
	TZPC_SLAVE_TIMER_11, /* bit4 */
	TZPC_SLAVE_TIMER_12, /* bit5 */
	TZPC_SLAVE_PCTRL_0,  /* bit6 */
	TZPC_SLAVE_PCTRL_1,  /* bit7 */
	TZPC_SLAVE_PCTRL_2,  /* bit8 */
	TZPC_SLAVE_PCTRL_3,  /* bit9 */
	TZPC_SLAVE_PWM,      /* bit10 */
	TZPC_SLAVE_WDG_0,    /* bit12 */
	TZPC_SLAVE_WDG_1,    /* bit13 */
	TZPC_SLAVE_GPIO_0,   /* bit14 */
	TZPC_SLAVE_GPIO_1,   /* bit15 */
	TZPC_SLAVE_GPIO_2,   /* bit16 */
	TZPC_SLAVE_GPIO_3,   /* bit17 */
	TZPC_SLAVE_GPIO_4,   /* bit18 */
	TZPC_SLAVE_GPIO_5,   /* bit19 */
	TZPC_SLAVE_GPIO_6,   /* bit20 */
	TZPC_SLAVE_GPIO_7,   /* bit21 */
	TZPC_SLAVE_GPIO_8,   /* bit22 */
	TZPC_SLAVE_GPIO_9,   /* bit23 */
	TZPC_SLAVE_GPIO_10,  /* bit24 */
	TZPC_SLAVE_GPIO_11,  /* bit25 */
	TZPC_SLAVE_GPIO_12,  /* bit26 */
	TZPC_SLAVE_GPIO_13,  /* bit27 */
	TZPC_SLAVE_GPIO_14,  /* bit28 */
	TZPC_SLAVE_GPIO_15,  /* bit29 */
	TZPC_SLAVE_GPIO_16,  /* bit30 */
	TZPC_SLAVE_GPIO_17,  /* bit31 */
	/* PROT[2] */
	TZPC_SLAVE_GPIO_20,      /* bit2 */
	TZPC_SLAVE_GPIO_21,      /* bit3 */
	TZPC_SLAVE_LOAD_MONITOR, /* bit4 */
	TZPC_SLAVE_CTF,          /* bit5 */
	TZPC_SLAVE_GPIO0_SE,     /* bit6 */
	TZPC_SLAVE_ATGC,         /* bit7 */
	TZPC_SLAVE_G3D,          /* 18 */
	/* PROT[3] */
	TZPC_SLAVE_PCIE,       /* bit10 */
	TZPC_SLAVE_HKMEM,      /* bit18 */
	TZPC_SLAVE_GPIO0_EMMC, /* bit24 */
	TZPC_SLAVE_GPIO1_EMMC, /* bit25 */
	TZPC_SLAVE_EMMC_51,    /* bit26 */
	TZPC_SLAVE_SD30,       /* bit28 */
	TZPC_SLAVE_SDIO,       /* bit29 */
	TZPC_SLAVE_DDRC_CFG,   /* bit30 */
	/* PROT[4] */
	TZPC_SLAVE_USB3OTG_INTERNEL, /* bit1 */
	TZPC_SLAVE_USB3OTG_BC,       /* bit2 */
	TZPC_SLAVE_PERF_STAT,        /* bit3 */
	TZPC_SLAVE_IPCNS,            /* bit5 */
	TZPC_SLAVE_IPC,              /* bit6 */
	TZPC_SLAVE_IOC,              /* bit7 */
	TZPC_SLAVE_IOC_GPIO,         /* bit8 */
	TZPC_SLAVE_VCODECBUS,        /* bit9 */
	TZPC_SLAVE_HKADC_SSI,        /* bit10 */
	TZPC_SLAVE_CODEC_SSI,        /* bit11 */
	TZPC_SLAVE_IPC_MDM_S,        /* bit12 */
	TZPC_SLAVE_IPC_MDM,          /* bit13 */
	TZPC_SLAVE_UART_0,           /* bit14 */
	TZPC_SLAVE_UART_1,           /* bit15 */
	TZPC_SLAVE_UART_2,           /* bit16 */
	TZPC_SLAVE_UART_4,           /* bit17 */
	TZPC_SLAVE_UART_5,           /* bit18 */
	TZPC_SLAVE_SPI_1,            /* bit19 */
	TZPC_SLAVE_I2C_3,            /* bit20 */
	TZPC_SLAVE_I2C_4,            /* bit21 */
	TZPC_DDRC_SECURE_BOOT_LOCK,  /* bit22 */
	TZPC_SLAVE_SPI_4,            /* bit25 */
	TZPC_SLAVE_I2C_7,            /* bit26 */
	TZPC_SLAVE_UFS_SCTRL,        /* bit28 */
	TZPC_SLAVE_UFS,              /* bit29 */
	TZPC_SLAVE_MMC0_IOC,         /* bit30 */
	TZPC_SLAVE_MMC1_IOC,         /* bit31 */
	/* PROT[5] */
	TZPC_SLAVE_LPM3_PMUSSI1,     /* bit0 */
	TZPC_SLAVE_LPM3_TSENSORC,    /* bit2 */
	TZPC_SLAVE_LPM3_PMC,         /* bit3 */
	TZPC_SLAVE_LPM3_UART,        /* bit4 */
	TZPC_SLAVE_LPM3_PMUI2C,      /* bit5 */
	TZPC_SLAVE_LPM3_PMUSSI0,     /* bit6 */
	TZPC_SLAVE_CRG_1,            /* bit7 */
	TZPC_SLAVE_CRG_IVP,          /* bit8 */
	TZPC_SLAVE_CRG_ISP,          /* bit9 */
	TZPC_SLAVE_CRG_MDM,          /* bit10 */
	TZPC_SLAVE_CRG_5,            /* bit11 */
	TZPC_SLAVE_LPM3_WD,          /* bit12 */
	TZPC_SLAVE_LPM3_TIMER,       /* bit13 */
	TZPC_SLAVE_LPM3_CONFIG,      /* bit14 */
	TZPC_SLAVE_LPM3_NANDC,       /* bit15 */
	TZPC_SLAVE_LPM3_GNSPWM,      /* bit16 */
	TZPC_SLAVE_LPM3_RAM,         /* bit17 */
	TZPC_SLAVE_LPM3_PMUSSI2,     /* bit18 */
	TZPC_SLAVE_LPM3_PMUSSI0_RTC, /* bit19 */
	/* PROT[6] */
	TZPC_MASTER_LPMCU,     /* bit0 */
	TZPC_MASTER_EMMC_51,   /* bit3 */
	TZPC_MASTER_SD3,       /* bit5 */
	TZPC_MASTER_SDIO_0,    /* bit6 */
	TZPC_MASTER_USB3OTG,   /* bit8 */
	TZPC_MASTER_G3D,       /* bit9 */
	TZPC_MASTER_PERF_STAT, /* bit18 */
	TZPC_MASTER_IPF,       /* bit19 */
	TZPC_MASTER_PSAM,      /* bit20 */
	TZPC_MASTER_UFS,       /* bit21 */
	TZPC_MASTER_PCIE,      /* bit22 */
	/* PROT[7] */
	TZPC_SLAVE_PSAM_NS_REGION, /* bit0 */
	TZPC_SLAVE_IPF_NS_REGION,  /* bit1 */
	TZPC_SLAVE_PSAM_S_REGION,  /* bit2 */
	TZPC_SLAVE_IPF_S_REGION,   /* bit3 */
	TZPC_SLAVE_GPIO_18,        /* bit4 */
	TZPC_SLAVE_GPIO_19,        /* bit5 */
	TZPC_SLAVE_SPI_3,          /* bit6 */
	TZPC_SLAVE_IOC_FIX,        /* bit7 */
	TZPC_SLAVE_GPIO_28,        /* bit24 */
	TZPC_SLAVE_GPIO_1_SE,      /* bit25 */
	/* PROT[8] */
	TZPC_SLAVE_VIVOBUS, /* bit2 */
	TZPC_IP_NUM_MAX
};

#endif /* __TZPC_PLAT_MIAMICW__ */