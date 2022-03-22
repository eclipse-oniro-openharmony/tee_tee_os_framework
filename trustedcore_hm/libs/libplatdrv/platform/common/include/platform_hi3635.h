#ifndef __PLATFORM_HI3635_H
#define __PLATFORM_HI3635_H

#define REG_BASE_PMUSSI				(0xFFF34000)

#define REG_BASE_BOOTROM			(0xFFFF0000)

#define REG_BASE_PERI_CRG                       (0xFFF35000)

#define REG_BASE_LP_MCU				(0xFFF00000)

#define REG_BASE_CSSYS_APB			(0xFFFF0000)

#define REG_BASE_IO_MCU				(0xFFDE0000)

#define REG_BASE_SDIO1				(0xFFDDF000)

#define REG_BASE_EMMC				(0xFF1FE000)

#define REG_BASE_MMC0_PERI_NOC			(0xFFD80000)

#define REG_BASE_SD				(0xFF17F000)

#define REG_BASE_SDIO0				(0xFFD7E000)

#define REG_BASE_MMC1_PERI_NOC			(0xFFD00000)

#define REG_BASE_SOCP				(0xFF032000)

#define REG_BASE_USB2HST			(0xFF030000)

#define REG_BASE_SECENG_S			(0xFF020000)

#define REG_BASE_SECENG_P			(0xFF010000)

#define REG_BASE_DEBUG_SEC_NOC			(0xFF000000)

#define REG_BASE_CS_STM				(0xFE000000)

#define REG_BASE_DMA_PERI_NOC			(0xFDF30000)

#define REG_BASE_DMA				(0xFDF20000)

#define REG_BASE_TSI1				(0xFDF10000)

#define REG_BASE_TSI0				(0xFDF0F000)

#define REG_BASE_I2C5				(0xFDF0E000)

#define REG_BASE_I2C4				(0xFDF0D000)

#define REG_BASE_I2C3				(0xFDF0C000)

#define REG_BASE_I2C2				(0xFDF0B000)

#define REG_BASE_I2C1				(0xFDF0A000)

#define REG_BASE_I2C0				(0xFDF09000)

#define REG_BASE_SPI1				(0xFDF08000)

#define REG_BASE_SPI0				(0xFDF07000)

#define REG_BASE_UART5				(0xFDF05000)

#define REG_BASE_UART4				(0xFDF04000)

#define REG_BASE_UART3				(0xFDF03000)

#define REG_BASE_UART2				(0xFDF03000)

#define REG_BASE_UART1				(0xFDF00000)

#define REG_BASE_UART0				(0xFDF02000)

#define REG_BASE_UART				(0xFFF32000)

#define REG_BASE_DMA0				(0xFDF30000)

#define REG_BASE_SECRAM				(0xF8400000)

#define REG_BASE_HS_PERI_NOC			(0xF8304000)

#define REG_BASE_NANDC_CFG			(0xF8300000)
#define REG_BASE_NANDCC				(0xF8200000)
#define REG_BASE_USBOTG				(0xFF080000)
#define REG_BASE_PCIE				(0xF0000000)
#define REG_BASE_TZPC				(0xE8A21000)

#define REG_BASE_GPIO0				(0xE8A0B000)
#define REG_BASE_GPIO1				(0xE8A0C000)
#define REG_BASE_GPIO2				(0xE8A0D000)
#define REG_BASE_GPIO3				(0xE8A0E000)
#define REG_BASE_GPIO4				(0xE8A0F000)
#define REG_BASE_GPIO5				(0xE8A10000)
#define REG_BASE_GPIO6				(0xE8A11000)
#define REG_BASE_GPIO7				(0xE8A12000)
#define REG_BASE_GPIO8				(0xE8A13000)
#define REG_BASE_GPIO9				(0xE8A14000)
#define REG_BASE_GPIO10				(0xE8A15000)
#define REG_BASE_GPIO11				(0xE8A16000)
#define REG_BASE_GPIO12				(0xE8A17000)
#define REG_BASE_GPIO13				(0xE8A18000)
#define REG_BASE_GPIO14				(0xE8A19000)
#define REG_BASE_GPIO15				(0xE8A1A000)
#define REG_BASE_GPIO16				(0xE8A1B000)
#define REG_BASE_GPIO17				(0xE8A1C000)
#define REG_BASE_GPIO18				(0xE8A1D000)
#define REG_BASE_GPIO19				(0xE8A1E000)
#define REG_BASE_GPIO20				(0xE8A1F000)
#define REG_BASE_GPIO21				(0xE8A20000)
#define REG_BASE_GPIO22				(0xFFF0B000)
#define REG_BASE_GPIO23				(0xFFF0C000)
#define REG_BASE_GPIO24				(0xFFF0D000)
#define REG_BASE_GPIO25				(0xFFF0E000)
#define REG_BASE_GPIO26				(0xFFF0F000)

#define REG_BASE_IOC				(0xE8612000)
#define REG_BASE_IOC_SYS			(0xFFF11000)

#define REG_BASE_PCTRL				(0xE8A09000)
#define REG_BASE_SCTRL				(0xFFF0A000)

#define REG_BASE_EFUSEC				(0xFFF10000)
#define REG_BASE_WD1				(0xE8A07000)
#define REG_BASE_WD0				(0xE8A06000)
#define REG_BASE_PWM1				(0xE8A05000)
#define REG_BASE_PWM0				(0xE8A04000)

#define REG_BASE_TIMER7				(0xE8A03000)
#define REG_BASE_TIMER6				(0xE8A02000)
#define REG_BASE_TIMER5				(0xE8A01000)
#define REG_BASE_TIMER4				(0xE8A00000)
#define REG_BASE_TIMER3				(0xFFF03000)
#define REG_BASE_TIMER2				(0xFFF02000)
#define REG_BASE_TIMER1				(0xFFF01000)
#define REG_BASE_TIMER0				(0xFFF00000)


#define REG_BASE_IPC1				(0xE89FF000)
#define REG_BASE_IPC0				(0xE89FE000)
#define REG_BASE_VPP				(0xE89FD000)

#define REG_BASE_VDEC				(0xE8910000)
#define REG_BASE_VENC				(0xE8900000)
#define REG_BASE_G3D				(0xE8840000)
#define REG_BASE_G2D				(0xE8800000)

#define REG_BASE_VIVO_NOC			(0xE8500000)
#define REG_BASE_ISP				(0xE8400000)
#define REG_BASE_DCC				(0xE8340000)
#define REG_BASE_SMMU2				(0xE8320000)
#define REG_BASE_SMMU1				(0xE8310000)
#define REG_BASE_SMMU0				(0xE8300000)

#define REG_BASE_CFG_NOC			(0xE81F0000)
#define REG_BASE_HKADC_SSI			(0xE82B8000)
#define REG_BASE_ASP				(0xE8100000)
#define REG_BASE_GIC				(0xE80A0000)
#define REG_BASE_CCI_CFG			(0xE8290000)
#define REG_BASE_PMU_SSI			(0xFFF34000)
#define REG_BASE_DDRC_CFG			(0xFFF20000)

#define REG_BASE_ASP_CFG			(0xE804E000)
#define REG_BASE_SEC_RAM			(0xE8000000)

#define REG_BASE_PMUSPI				(0xFFF34000)
#define REG_BASE_PERICRG				(0xFFF35000)
#define REG_BASE_PMCCTRL				(0xFFF31000)
#define REG_BASE_DSSCTRL				(0xE8500000)
#define REG_BASE_SYSCTRL				(0xFFF0A000)
#define REG_BASE_ASPCTRL				(0xE804E000)
#define REG_BASE_ASPDMACCTRL				(0xE804B000)
#define REG_BASE_SYSCOUNT				(0xFFF08000)

/********************************************
 *  define gpio number in the way of group. *
 ********************************************/
#define GPIO_0_0    0
#define GPIO_0_1    1
#define GPIO_0_2    2
#define GPIO_0_3    3
#define GPIO_0_4    4
#define GPIO_0_5    5
#define GPIO_0_6    6
#define GPIO_0_7    7

#define GPIO_1_0    8
#define GPIO_1_1    9
#define GPIO_1_2    10
#define GPIO_1_3    11
#define GPIO_1_4    12
#define GPIO_1_5    13
#define GPIO_1_6    14
#define GPIO_1_7    15

#define GPIO_2_0    16
#define GPIO_2_1    17
#define GPIO_2_2    18
#define GPIO_2_3    19
#define GPIO_2_4    20
#define GPIO_2_5    21
#define GPIO_2_6    22
#define GPIO_2_7    23

#define GPIO_3_0    24
#define GPIO_3_1    25
#define GPIO_3_2    26
#define GPIO_3_3    27
#define GPIO_3_4    28
#define GPIO_3_5    29
#define GPIO_3_6    30
#define GPIO_3_7    31

#define GPIO_4_0    32
#define GPIO_4_1    33
#define GPIO_4_2    34
#define GPIO_4_3    35
#define GPIO_4_4    36
#define GPIO_4_5    37
#define GPIO_4_6    38
#define GPIO_4_7    39

#define GPIO_5_0    40
#define GPIO_5_1    41
#define GPIO_5_2    42
#define GPIO_5_3    43
#define GPIO_5_4    44
#define GPIO_5_5    45
#define GPIO_5_6    46
#define GPIO_5_7    47

#define GPIO_6_0    48
#define GPIO_6_1    49
#define GPIO_6_2    50
#define GPIO_6_3    51
#define GPIO_6_4    52
#define GPIO_6_5    53
#define GPIO_6_6    54
#define GPIO_6_7    55

#define GPIO_7_0    56
#define GPIO_7_1    57
#define GPIO_7_2    58
#define GPIO_7_3    59
#define GPIO_7_4    60
#define GPIO_7_5    61
#define GPIO_7_6    62
#define GPIO_7_7    63

#define GPIO_8_0    64
#define GPIO_8_1    65
#define GPIO_8_2    66
#define GPIO_8_3    67
#define GPIO_8_4    68
#define GPIO_8_5    69
#define GPIO_8_6    70
#define GPIO_8_7    71

#define GPIO_9_0    72
#define GPIO_9_1    73

#define GPIO_9_5    77
#define GPIO_9_6    78
#define GPIO_9_7    79

#define GPIO_10_0   80
#define GPIO_10_1   81
#define GPIO_10_2   82
#define GPIO_10_3   83
#define GPIO_10_4   84
#define GPIO_10_5   85
#define GPIO_10_6   86
#define GPIO_10_7   87

#define GPIO_11_0   88
#define GPIO_11_1   89
#define GPIO_11_2   90
#define GPIO_11_3   91
#define GPIO_11_4   92
#define GPIO_11_5   93
#define GPIO_11_6   94
#define GPIO_11_7   95

#define GPIO_12_0   96
#define GPIO_12_1   97
#define GPIO_12_2   98
#define GPIO_12_3   99
#define GPIO_12_4   100
#define GPIO_12_5   101
#define GPIO_12_6   102
#define GPIO_12_7   103

#define GPIO_13_0   104
#define GPIO_13_1   105
#define GPIO_13_2   106
#define GPIO_13_3   107
#define GPIO_13_4   108
#define GPIO_13_5   109
#define GPIO_13_6   110
#define GPIO_13_7   111

#define GPIO_14_0   112
#define GPIO_14_1   113
#define GPIO_14_2   114
#define GPIO_14_3   115
#define GPIO_14_4   116
#define GPIO_14_5   117
#define GPIO_14_6   118
#define GPIO_14_7   119

#define GPIO_15_0   120
#define GPIO_15_1   121
#define GPIO_15_2   122
#define GPIO_15_3   123
#define GPIO_15_4   124
#define GPIO_15_5   125
#define GPIO_15_6   126
#define GPIO_15_7   127

#define GPIO_16_0   128
#define GPIO_16_1   129
#define GPIO_16_2   130
#define GPIO_16_3   131
#define GPIO_16_4   132
#define GPIO_16_5   133
#define GPIO_16_6   134
#define GPIO_16_7   135

#define GPIO_17_0   136
#define GPIO_17_1   137
#define GPIO_17_2   138
#define GPIO_17_3   139
#define GPIO_17_4   140
#define GPIO_17_5   141
#define GPIO_17_6   142
#define GPIO_17_7   143

#define GPIO_18_0   144
#define GPIO_18_1   145
#define GPIO_18_2   146
#define GPIO_18_3   147
#define GPIO_18_4   148
#define GPIO_18_5   149
#define GPIO_18_6   150
#define GPIO_18_7   151

#define GPIO_19_0   152
#define GPIO_19_1   153
#define GPIO_19_2   154
#define GPIO_19_3   155
#define GPIO_19_4   156
#define GPIO_19_5   157
#define GPIO_19_6   158
#define GPIO_19_7   159

#define GPIO_20_0   160
#define GPIO_20_1   161
#define GPIO_20_2   162
#define GPIO_20_3   163
#define GPIO_20_4   164
#define GPIO_20_5   165
#define GPIO_20_6   166
#define GPIO_20_7   167

#define GPIO_21_0   168
#define GPIO_21_1   169
#define GPIO_21_2   170
#define GPIO_21_3   171
#define GPIO_21_4   172
#define GPIO_21_5   173
#define GPIO_21_6   174
#define GPIO_21_7   175

#define GPIO_22_0   176
#define GPIO_22_1   177
#define GPIO_22_2   178
#define GPIO_22_3   179
#define GPIO_22_4   180
#define GPIO_22_5   181
#define GPIO_22_6   182
#define GPIO_22_7   183

#define GPIO_23_0   184
#define GPIO_23_1   185
#define GPIO_23_2   186
#define GPIO_23_3   187
#define GPIO_23_4   188
#define GPIO_23_5   189
#define GPIO_23_6   190
#define GPIO_23_7   191

#define GPIO_24_0   192
#define GPIO_24_1   193
#define GPIO_24_2   194
#define GPIO_24_3   195
#define GPIO_24_4   196
#define GPIO_24_5   197
#define GPIO_24_6   198
#define GPIO_24_7   199

#define GPIO_25_0   200
#define GPIO_25_1   201
#define GPIO_25_2   202
#define GPIO_25_3   203
#define GPIO_25_4   204
#define GPIO_25_5   205
#define GPIO_25_6   206
#define GPIO_25_7   207

#define GPIO_26_0   208
#define GPIO_26_1   209
#define GPIO_26_2   210
#define GPIO_26_3   211
#define GPIO_26_4   212
#define GPIO_26_5   213

/********************************************
 *  define gpio number in the way of single.*
 ********************************************/

/*define GPIO 0 ~ GPIO 7*/
#define   GPIO_000     GPIO_0_0
#define   GPIO_001     GPIO_0_1
#define   GPIO_002     GPIO_0_2
#define   GPIO_003     GPIO_0_3
#define   GPIO_004     GPIO_0_4
#define   GPIO_005     GPIO_0_5
#define   GPIO_006     GPIO_0_6
#define   GPIO_007     GPIO_0_7

/*define GPIO 8 ~ GPIO 15*/
#define   GPIO_008     GPIO_1_0
#define   GPIO_009     GPIO_1_1
#define   GPIO_010     GPIO_1_2
#define   GPIO_011     GPIO_1_3
#define   GPIO_012     GPIO_1_4
#define   GPIO_013     GPIO_1_5
#define   GPIO_014     GPIO_1_6
#define   GPIO_015     GPIO_1_7

/*define GPIO 16 ~ GPIO 23*/
#define   GPIO_016     GPIO_2_0
#define   GPIO_017     GPIO_2_1
#define   GPIO_018     GPIO_2_2
#define   GPIO_019     GPIO_2_3
#define   GPIO_020     GPIO_2_4
#define   GPIO_021     GPIO_2_5
#define   GPIO_022     GPIO_2_6
#define   GPIO_023     GPIO_2_7

/*define GPIO 24 ~ GPIO 31*/
#define   GPIO_024     GPIO_3_0
#define   GPIO_025     GPIO_3_1
#define   GPIO_026     GPIO_3_2
#define   GPIO_027     GPIO_3_3
#define   GPIO_028     GPIO_3_4
#define   GPIO_029     GPIO_3_5
#define   GPIO_030     GPIO_3_6
#define   GPIO_031     GPIO_3_7

/*define GPIO 32 ~ GPIO 39*/
#define   GPIO_032     GPIO_4_0
#define   GPIO_033     GPIO_4_1
#define   GPIO_034     GPIO_4_2
#define   GPIO_035     GPIO_4_3
#define   GPIO_036     GPIO_4_4
#define   GPIO_037     GPIO_4_5
#define   GPIO_038     GPIO_4_6
#define   GPIO_039     GPIO_4_7

/*define GPIO 40 ~ GPIO 47*/
#define   GPIO_040     GPIO_5_0
#define   GPIO_041     GPIO_5_1
#define   GPIO_042     GPIO_5_2
#define   GPIO_043     GPIO_5_3
#define   GPIO_044     GPIO_5_4
#define   GPIO_045     GPIO_5_5
#define   GPIO_046     GPIO_5_6
#define   GPIO_047     GPIO_5_7

/*define GPIO 48 ~ GPIO 55*/
#define   GPIO_048     GPIO_6_0
#define   GPIO_049     GPIO_6_1
#define   GPIO_050     GPIO_6_2
#define   GPIO_051     GPIO_6_3
#define   GPIO_052     GPIO_6_4
#define   GPIO_053     GPIO_6_5
#define   GPIO_054     GPIO_6_6
#define   GPIO_055     GPIO_6_7

/*define GPIO 56 ~ GPIO 63*/
#define   GPIO_056     GPIO_7_0
#define   GPIO_057     GPIO_7_1
#define   GPIO_058     GPIO_7_2
#define   GPIO_059     GPIO_7_3
#define   GPIO_060     GPIO_7_4
#define   GPIO_061     GPIO_7_5
#define   GPIO_062     GPIO_7_6
#define   GPIO_063     GPIO_7_7

/*define GPIO 64 ~ GPIO 71*/
#define   GPIO_064     GPIO_8_0
#define   GPIO_065     GPIO_8_1
#define   GPIO_066     GPIO_8_2
#define   GPIO_067     GPIO_8_3
#define   GPIO_068     GPIO_8_4
#define   GPIO_069     GPIO_8_5
#define   GPIO_070     GPIO_8_6
#define   GPIO_071     GPIO_8_7

/*define GPIO 72 ~ GPIO 79*/
#define   GPIO_072     GPIO_9_0
#define   GPIO_073     GPIO_9_1
/*
#define   GPIO_074     GPIO_9_2
#define   GPIO_075     GPIO_9_3
#define   GPIO_076     GPIO_9_4
*/
#define   GPIO_077     GPIO_9_5
#define   GPIO_078     GPIO_9_6
#define   GPIO_079     GPIO_9_7

/*define GPIO 80 ~ GPIO 87*/
#define   GPIO_080     GPIO_10_0
#define   GPIO_081     GPIO_10_1
#define   GPIO_082     GPIO_10_2
#define   GPIO_083     GPIO_10_3
#define   GPIO_084     GPIO_10_4
#define   GPIO_085     GPIO_10_5
#define   GPIO_086     GPIO_10_6
#define   GPIO_087     GPIO_10_7

/*define GPIO 88 ~ GPIO 95*/
#define   GPIO_088     GPIO_11_0
#define   GPIO_089     GPIO_11_1
#define   GPIO_090     GPIO_11_2
#define   GPIO_091     GPIO_11_3
#define   GPIO_092     GPIO_11_4
#define   GPIO_093     GPIO_11_5
#define   GPIO_094     GPIO_11_6
#define   GPIO_095     GPIO_11_7

/*define GPIO 96 ~ GPIO 103*/
#define   GPIO_096     GPIO_12_0
#define   GPIO_097     GPIO_12_1
#define   GPIO_098     GPIO_12_2
#define   GPIO_099     GPIO_12_3
#define   GPIO_100     GPIO_12_4
#define   GPIO_101     GPIO_12_5
#define   GPIO_102     GPIO_12_6
#define   GPIO_103     GPIO_12_7

/*define GPIO 104 ~ GPIO 111*/
#define   GPIO_104     GPIO_13_0
#define   GPIO_105     GPIO_13_1
#define   GPIO_106     GPIO_13_2
#define   GPIO_107     GPIO_13_3
#define   GPIO_108     GPIO_13_4
#define   GPIO_109     GPIO_13_5
#define   GPIO_110     GPIO_13_6
#define   GPIO_111     GPIO_13_7

/*define GPIO 112 ~ GPIO 119*/
#define   GPIO_112     GPIO_14_0
#define   GPIO_113     GPIO_14_1
#define   GPIO_114     GPIO_14_2
#define   GPIO_115     GPIO_14_3
#define   GPIO_116     GPIO_14_4
#define   GPIO_117     GPIO_14_5
#define   GPIO_118     GPIO_14_6
#define   GPIO_119     GPIO_14_7

/*define GPIO 120 ~ GPIO 127*/
#define   GPIO_120     GPIO_15_0
#define   GPIO_121     GPIO_15_1
#define   GPIO_122     GPIO_15_2
#define   GPIO_123     GPIO_15_3
#define   GPIO_124     GPIO_15_4
#define   GPIO_125     GPIO_15_5
#define   GPIO_126     GPIO_15_6
#define   GPIO_127     GPIO_15_7

/*define GPIO 128 ~ GPIO 135*/
#define   GPIO_128     GPIO_16_0
#define   GPIO_129     GPIO_16_1
#define   GPIO_130     GPIO_16_2
#define   GPIO_131     GPIO_16_3
#define   GPIO_132     GPIO_16_4
#define   GPIO_133     GPIO_16_5
#define   GPIO_134     GPIO_16_6
#define   GPIO_135     GPIO_16_7

/*define GPIO 136 ~ GPIO 143*/
#define   GPIO_136     GPIO_17_0
#define   GPIO_137     GPIO_17_1
#define   GPIO_138     GPIO_17_2
#define   GPIO_139     GPIO_17_3
#define   GPIO_140     GPIO_17_4
#define   GPIO_141     GPIO_17_5
#define   GPIO_142     GPIO_17_6
#define   GPIO_143     GPIO_17_7

/*define GPIO 144 ~ GPIO 151*/
#define   GPIO_144     GPIO_18_0
#define   GPIO_145     GPIO_18_1
#define   GPIO_146     GPIO_18_2
#define   GPIO_147     GPIO_18_3
#define   GPIO_148     GPIO_18_4
#define   GPIO_149     GPIO_18_5
#define   GPIO_150     GPIO_18_6
#define   GPIO_151     GPIO_18_7

/*define GPIO 152 ~ GPIO 159*/
#define   GPIO_152     GPIO_19_0
#define   GPIO_153     GPIO_19_1
#define   GPIO_154     GPIO_19_2
#define   GPIO_155     GPIO_19_3
#define   GPIO_156     GPIO_19_4
#define   GPIO_157     GPIO_19_5
#define   GPIO_158     GPIO_19_6
#define   GPIO_159     GPIO_19_7

/*define GPIO 160 ~ GPIO 167*/
#define   GPIO_160     GPIO_20_0
#define   GPIO_161     GPIO_20_1
#define   GPIO_162     GPIO_20_2
#define   GPIO_163     GPIO_20_3
#define   GPIO_164     GPIO_20_4
#define   GPIO_165     GPIO_20_5
#define   GPIO_166     GPIO_20_6
#define   GPIO_167     GPIO_20_7

/*define GPIO 168 ~ GPIO 175*/
#define   GPIO_168     GPIO_21_0
#define   GPIO_169     GPIO_21_1
#define   GPIO_170     GPIO_21_2
#define   GPIO_171     GPIO_21_3
#define   GPIO_172     GPIO_21_4
#define   GPIO_173     GPIO_21_5
#define   GPIO_174     GPIO_21_6
#define   GPIO_175     GPIO_21_7


/*define GPIO 176 ~ GPIO 183*/
#define   GPIO_176     GPIO_22_0
#define   GPIO_177     GPIO_22_1
#define   GPIO_178     GPIO_22_2
#define   GPIO_179     GPIO_22_3
#define   GPIO_180     GPIO_22_4
#define   GPIO_181     GPIO_22_5
#define   GPIO_182     GPIO_22_6
#define   GPIO_183     GPIO_22_7

/*define GPIO 184 ~ GPIO 191*/
#define   GPIO_184     GPIO_23_0
#define   GPIO_185     GPIO_23_1
#define   GPIO_186     GPIO_23_2
#define   GPIO_187     GPIO_23_3
#define   GPIO_188     GPIO_23_4
#define   GPIO_189     GPIO_23_5
#define   GPIO_190     GPIO_23_6
#define   GPIO_191     GPIO_23_7

/*define GPIO 192 ~ GPIO 199*/
#define   GPIO_192     GPIO_24_0
#define   GPIO_193     GPIO_24_1
#define   GPIO_194     GPIO_24_2
#define   GPIO_195     GPIO_24_3
#define   GPIO_196     GPIO_24_4
#define   GPIO_197     GPIO_24_5
#define   GPIO_198     GPIO_24_6
#define   GPIO_199     GPIO_24_7

/*define GPIO 200 ~ GPIO 207*/
#define   GPIO_200     GPIO_25_0
#define   GPIO_201     GPIO_25_1
#define   GPIO_202     GPIO_25_2
#define   GPIO_203     GPIO_25_3
#define   GPIO_204     GPIO_25_4
#define   GPIO_205     GPIO_25_5
#define   GPIO_206     GPIO_25_6
#define   GPIO_207     GPIO_25_7

/*define GPIO 208 ~ GPIO 213*/
#define   GPIO_208     GPIO_26_0
#define   GPIO_209     GPIO_26_1
#define   GPIO_210     GPIO_26_2
#define   GPIO_211     GPIO_26_3
#define   GPIO_212     GPIO_26_4
#define   GPIO_213     GPIO_26_5

#define			EMMC_CMD			GPIO_006
#define			EMMC_CLK			GPIO_007
#define			EMMC_DATA0			GPIO_008
#define			EMMC_DATA1			GPIO_009
#define			EMMC_DATA2			GPIO_010
#define			EMMC_DATA3			GPIO_011
#define			EMMC_DATA4			GPIO_012
#define			EMMC_DATA5			GPIO_013
#define			EMMC_DATA6			GPIO_014
#define			EMMC_DATA7			GPIO_015
#define			CODEC_SSI			GPIO_016
#define			ISP_SCL0			GPIO_021
#define			ISP_SDA0			GPIO_022
#define			ISP_SCL1			GPIO_023
#define			ISP_SDA1			GPIO_024
#define			ISP_RESETB0			GPIO_025
#define			ISP_RESETB1			GPIO_026
#define			ISP_FSIN0			GPIO_027
#define			ISP_FSIN1			GPIO_028
#define			ISP_STROBE0			GPIO_029
#define			ISP_STROBE1			GPIO_030
#define			ISP_CCLK0			GPIO_031
#define			ISP_CCLK1			GPIO_032
#define			ISP_GPIO0			GPIO_033
#define			ISP_GPIO1			GPIO_034
#define			ISP_GPIO2			GPIO_035
#define			ISP_GPIO3			GPIO_036
#define			ISP_GPIO4			GPIO_037
#define			ISP_GPIO5			GPIO_038
#define			ISP_GPIO6			GPIO_039
#define			ISP_GPIO7			GPIO_040
#define			ISP_GPIO8			GPIO_041
#define			ISP_GPIO9			GPIO_042
#define			I2S1_DI				GPIO_043
#define			I2S1_DO				GPIO_044
#define			I2S1_XCLK			GPIO_045
#define			I2S1_XFS			GPIO_046
#define			I2C0_SCL			GPIO_047
#define			I2C0_SDA			GPIO_048
#define			I2C1_SCL			GPIO_049
#define			I2C1_SDA			GPIO_050
#define			I2C2_SCL			GPIO_051
#define			I2C2_SDA			GPIO_052
#define			I2C4_SCL			GPIO_053
#define			I2C4_SDA			GPIO_054
#define			I2C5_SCL			GPIO_055
#define			I2C5_SDA			GPIO_056
#define			SD_CLK				GPIO_057
#define			SD_CMD				GPIO_058
#define			SD_DATA0			GPIO_059
#define			SD_DATA1			GPIO_060
#define			SD_DATA2			GPIO_061
#define			SD_DATA3			GPIO_062
#define			SPI0_CLK			GPIO_063
#define			SPI0_DI				GPIO_064
#define			SPI0_DO				GPIO_065
#define			SPI0_CS0_N			GPIO_066
#define			SPI0_CS1_N			GPIO_067
#define			SPI0_CS2_N			GPIO_068
#define			SPI0_CS3_N			GPIO_069
#define			TSI1_CLK			GPIO_072
#define			TSI1_ERR			GPIO_073
#define			SDIO0_CLK			GPIO_077
#define			SDIO0_CMD			GPIO_078
#define			SDIO0_DATA0			GPIO_079
#define			SDIO0_DATA1			GPIO_080
#define			SDIO0_DATA2			GPIO_081
#define			SDIO0_DATA3			GPIO_082
#define			UART6_CTS_N			GPIO_083
#define			UART6_RTS_N			GPIO_084
#define			UART6_RXD			GPIO_085
#define			UART6_TXD			GPIO_086
#define			UART3_CTS_N			GPIO_087
#define			UART3_RTS_N			GPIO_088
#define			UART3_RXD			GPIO_089
#define			UART3_TXD			GPIO_090
#define			UART4_CTS_N			GPIO_091
#define			UART4_RTS_N			GPIO_092
#define			UART4_RXD			GPIO_093
#define			UART4_TXD			GPIO_094
#define			UART0_RXD			GPIO_083
#define			UART0_TXD			GPIO_084
#define			UART2_RXD			GPIO_148
#define			UART2_TXD			GPIO_149
#define			USB_DRV_VBUS			GPIO_095
#define			SPDIF				GPIO_096
#define			GPS_REF				GPIO_097
#define			PWM_OUT0			GPIO_098
#define			PWM_OUT1			GPIO_099
#define			PMU_HKADC_SSI			GPIO_100
#define			PMU_AUXDAC0_SSI			GPIO_101
#define			PMU_AUXDAC1_SSI			GPIO_102
#define			USIM0_CLK			GPIO_103
#define			USIM0_RST			GPIO_104
#define			USIM0_DATA			GPIO_105
#define			USIM1_CLK			GPIO_106
#define			USIM1_RST			GPIO_107
#define			USIM1_DATA			GPIO_108
#define			LTE_RX_ACTIVE			GPIO_109
#define			LTE_TX_ACTIVE			GPIO_110
#define			LTE_FRAME_SYNC			GPIO_111
#define			WLAN_BT_RX_PRIORITY		GPIO_112
#define			WLAN_BT_LDO_EN			GPIO_113
#define			WLAN_BT_TX_ACTIVE		GPIO_114
#define			CH0_RF_SSI			GPIO_115
#define			CH0_RF_TCVR_ON			GPIO_116
#define			CH0_APT_PDM			GPIO_117
#define			CH0_MIPI_CLK			GPIO_118
#define			CH0_MIPI_DATA			GPIO_119
#define			CH1_RF_SSI			GPIO_120
#define			CH1_RF_TCVR_ON			GPIO_121
#define			CH1_APT_PDM			GPIO_122
#define			CH1_MIPI_CLK			GPIO_123
#define			CH1_MIPI_DATA			GPIO_124
#define			CH0_AFC_PDM			GPIO_125
#define			CH1_AFC_PDM			GPIO_126
#define			ANTPA_SEL00			GPIO_127
#define			ANTPA_SEL01			GPIO_128
#define			ANTPA_SEL02			GPIO_129
#define			ANTPA_SEL03			GPIO_130
#define			ANTPA_SEL04			GPIO_131
#define			ANTPA_SEL05			GPIO_132
#define			ANTPA_SEL06			GPIO_133
#define			ANTPA_SEL07			GPIO_134
#define			ANTPA_SEL08			GPIO_135
#define			ANTPA_SEL09			GPIO_136
#define			ANTPA_SEL10			GPIO_137
#define			ANTPA_SEL11			GPIO_138
#define			ANTPA_SEL12			GPIO_139
#define			ANTPA_SEL13			GPIO_140
#define			ANTPA_SEL14			GPIO_141
#define			ANTPA_SEL15			GPIO_142
#define			ANTPA_SEL16			GPIO_143
#define			ANTPA_SEL17			GPIO_144
#define			ANTPA_SEL18			GPIO_145
#define			ANTPA_SEL19			GPIO_146
#define			ANTPA_SEL20			GPIO_147
#define			ANTPA_SEL21			GPIO_148
#define			ANTPA_SEL22			GPIO_149
#define			ANTPA_SEL23			GPIO_150
#define			ANTPA_SEL24			GPIO_151
#define			ANTPA_SEL25			GPIO_152
#define			ANTPA_SEL26			GPIO_153
#define			TEST_MODE_SEL0			GPIO_155
#define			TEST_MODE_SEL1			GPIO_156
#define			TSI1_SYNC			GPIO_157
#define			TSI1_VALID			GPIO_158
#define			TSI1_DATA			GPIO_159
#define			SYSCLK_SEL			GPIO_176
#define			SYSCLK_EN0			GPIO_177
#define			SYSCLK_EN1			GPIO_178
#define			CH0_RF_RESETN			GPIO_179
#define			CH1_RF_RESETN			GPIO_180
#define			CLK_OUT0			GPIO_181
#define			CLK_OUT1			GPIO_182
#define			I2S0_DI				GPIO_183
#define			I2S0_DO				GPIO_184
#define			I2S0_XCLK			GPIO_185
#define			I2S0_XFS			GPIO_186
#define			I2S2_DI				GPIO_187
#define			I2S2_DO				GPIO_188
#define			I2S2_XCLK			GPIO_189
#define			I2S2_XFS			GPIO_190
#define			ANTPA_SEL27			GPIO_191
#define			ANTPA_SEL28			GPIO_192
#define			ANTPA_SEL30			GPIO_194
#define         INVALID_VALUE_GPIO  (0xFFFFFFFF)

#endif
