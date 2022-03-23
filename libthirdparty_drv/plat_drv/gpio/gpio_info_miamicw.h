/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2016-2020. All rights reserved.
 * Description: define GPIO and IOCG and IOMG basedress .
 * Create: 2020-12-23
 */

#include "soc_acpu_baseaddr_interface.h"
#ifndef __GPIOINFO_MIAMICW_H
#define __GPIOINFO_MIAMICW_H

#define REG_BASE_GPIO28      SOC_ACPU_GPIO28_BASE_ADDR
#define REG_BASE_GPIO27      SOC_ACPU_GPIO27_BASE_ADDR
#define REG_BASE_GPIO26      SOC_ACPU_GPIO26_BASE_ADDR
#define REG_BASE_GPIO25      SOC_ACPU_GPIO25_BASE_ADDR
#define REG_BASE_GPIO24      SOC_ACPU_GPIO24_BASE_ADDR
#define REG_BASE_GPIO23      SOC_ACPU_GPIO23_BASE_ADDR
#define REG_BASE_GPIO22      SOC_ACPU_GPIO22_BASE_ADDR
#define REG_BASE_IOMCU_GPIO3 SOC_ACPU_IOMCU_GPIO3_BASE_ADDR
#define REG_BASE_IOMCU_GPIO2 SOC_ACPU_IOMCU_GPIO2_BASE_ADDR
#define REG_BASE_IOMCU_GPIO1 SOC_ACPU_IOMCU_GPIO1_BASE_ADDR
#define REG_BASE_IOMCU_GPIO0 SOC_ACPU_IOMCU_GPIO0_BASE_ADDR

#define REG_BASE_GPIO0_SE    SOC_ACPU_GPIO0_SE_BASE_ADDR
#define REG_BASE_GPIO1_SE    SOC_ACPU_GPIO1_SE_BASE_ADDR
#define REG_BASE_GPIO0       SOC_ACPU_GPIO0_BASE_ADDR
#define REG_BASE_GPIO1       SOC_ACPU_GPIO1_BASE_ADDR
#define REG_BASE_GPIO2       SOC_ACPU_GPIO2_BASE_ADDR
#define REG_BASE_GPIO3       SOC_ACPU_GPIO3_BASE_ADDR
#define REG_BASE_GPIO4       SOC_ACPU_GPIO4_BASE_ADDR
#define REG_BASE_GPIO5       SOC_ACPU_GPIO5_BASE_ADDR
#define REG_BASE_GPIO6       SOC_ACPU_GPIO6_BASE_ADDR
#define REG_BASE_GPIO7       SOC_ACPU_GPIO7_BASE_ADDR
#define REG_BASE_GPIO8       SOC_ACPU_GPIO8_BASE_ADDR
#define REG_BASE_GPIO9       SOC_ACPU_GPIO9_BASE_ADDR
#define REG_BASE_GPIO10      SOC_ACPU_GPIO10_BASE_ADDR
#define REG_BASE_GPIO11      SOC_ACPU_GPIO11_BASE_ADDR
#define REG_BASE_GPIO12      SOC_ACPU_GPIO12_BASE_ADDR
#define REG_BASE_GPIO13      SOC_ACPU_GPIO13_BASE_ADDR
#define REG_BASE_GPIO14      SOC_ACPU_GPIO14_BASE_ADDR
#define REG_BASE_GPIO15      SOC_ACPU_GPIO15_BASE_ADDR
#define REG_BASE_GPIO16      SOC_ACPU_GPIO16_BASE_ADDR
#define REG_BASE_GPIO17      SOC_ACPU_GPIO17_BASE_ADDR
#define REG_BASE_GPIO18      SOC_ACPU_GPIO18_BASE_ADDR
#define REG_BASE_GPIO19      SOC_ACPU_GPIO19_BASE_ADDR
#define REG_BASE_GPIO20      SOC_ACPU_GPIO20_BASE_ADDR
#define REG_BASE_GPIO21      SOC_ACPU_GPIO21_BASE_ADDR
#define REG_BASE_PCTRL       SOC_ACPU_PCTRL_BASE_ADDR

#define GPIO0_SE_0  232
#define GPIO0_SE_1  233
#define GPIO0_SE_2  234
#define GPIO0_SE_3  235
#define GPIO0_SE_4  236
#define GPIO0_SE_5  237
#define GPIO0_SE_6  238
#define GPIO0_SE_7  239

#define GPIO1_SE_0  240
#define GPIO1_SE_1  241
#define GPIO1_SE_2  242
#define GPIO1_SE_3  243
#define GPIO1_SE_4  244
#define GPIO1_SE_5  245
#define GPIO1_SE_6  246
#define GPIO1_SE_7  247

/*
 * define gpio number in the way of group.
 */
#define   GPIO_000      0
#define   GPIO_001      1
#define   GPIO_002      2
#define   GPIO_003      3
#define   GPIO_004      4
#define   GPIO_005      5
#define   GPIO_006      6
#define   GPIO_007      7

#define   GPIO_008      8
#define   GPIO_009      9
#define   GPIO_010      10
#define   GPIO_011      11
#define   GPIO_012      12
#define   GPIO_013      13
#define   GPIO_014      14
#define   GPIO_015      15

#define   GPIO_016      16
#define   GPIO_017      17
#define   GPIO_018      18
#define   GPIO_019      19
#define   GPIO_020      20
#define   GPIO_021      21
#define   GPIO_022      22
#define   GPIO_023      23

#define   GPIO_024      24
#define   GPIO_025      25
#define   GPIO_026      26
#define   GPIO_027      27
#define   GPIO_028      28
#define   GPIO_029      29
#define   GPIO_030      30
#define   GPIO_031      31

#define   GPIO_032      32
#define   GPIO_033      33
#define   GPIO_034      34
#define   GPIO_035      35
#define   GPIO_036      36
#define   GPIO_037      37
#define   GPIO_038      38
#define   GPIO_039      39

#define   GPIO_040      40
#define   GPIO_041      41
#define   GPIO_042      42
#define   GPIO_043      43
#define   GPIO_044      44
#define   GPIO_045      45
#define   GPIO_046      46
#define   GPIO_047      47

#define   GPIO_048      48
#define   GPIO_049      49
#define   GPIO_050      50
#define   GPIO_051      51
#define   GPIO_052      52
#define   GPIO_053      53
#define   GPIO_054      54
#define   GPIO_055      55

#define   GPIO_056      56
#define   GPIO_057      57
#define   GPIO_058      58
#define   GPIO_059      59
#define   GPIO_060      60
#define   GPIO_061      61
#define   GPIO_062      62
#define   GPIO_063      63

#define   GPIO_064      64
#define   GPIO_065      65
#define   GPIO_066      66
#define   GPIO_067      67
#define   GPIO_068      68
#define   GPIO_069      69
#define   GPIO_070      70
#define   GPIO_071      71

#define   GPIO_072      72
#define   GPIO_073      73
#define   GPIO_074      74
#define   GPIO_075      75
#define   GPIO_076      76
#define   GPIO_077      77
#define   GPIO_078      78
#define   GPIO_079      79

#define   GPIO_080      80
#define   GPIO_081      81
#define   GPIO_082      82
#define   GPIO_083      83
#define   GPIO_084      84
#define   GPIO_085      85
#define   GPIO_086      86
#define   GPIO_087      87

#define   GPIO_088      88
#define   GPIO_089      89
#define   GPIO_090      90
#define   GPIO_091      91
#define   GPIO_092      92
#define   GPIO_093      93
#define   GPIO_094      94
#define   GPIO_095      95

#define   GPIO_096      96
#define   GPIO_097      97
#define   GPIO_098      98
#define   GPIO_099      99
#define   GPIO_100      100
#define   GPIO_101      101
#define   GPIO_102      102
#define   GPIO_103      103

#define   GPIO_104      104
#define   GPIO_105      105
#define   GPIO_106      106
#define   GPIO_107      107
#define   GPIO_108      108
#define   GPIO_109      109
#define   GPIO_110      110
#define   GPIO_111      111

#define   GPIO_112      112
#define   GPIO_113      113
#define   GPIO_114      114
#define   GPIO_115      115
#define   GPIO_116      116
#define   GPIO_117      117
#define   GPIO_118      118
#define   GPIO_119      119

#define   GPIO_120      120
#define   GPIO_121      121
#define   GPIO_122      122
#define   GPIO_123      123
#define   GPIO_124      124
#define   GPIO_125      125
#define   GPIO_126      126
#define   GPIO_127      127

#define   GPIO_128      128
#define   GPIO_129      129
#define   GPIO_130      130
#define   GPIO_131      131
#define   GPIO_132      132
#define   GPIO_133      133
#define   GPIO_134      134
#define   GPIO_135      135

#define   GPIO_136      136
#define   GPIO_137      137
#define   GPIO_138      138
#define   GPIO_139      139
#define   GPIO_140      140
#define   GPIO_141      141
#define   GPIO_142      142
#define   GPIO_143      143

#define   GPIO_144      144
#define   GPIO_145      145
#define   GPIO_146      146
#define   GPIO_147      147
#define   GPIO_148      148
#define   GPIO_149      149
#define   GPIO_150      150
#define   GPIO_151      151

#define   GPIO_152      152
#define   GPIO_153      153
#define   GPIO_154      154
#define   GPIO_155      155
#define   GPIO_156      156
#define   GPIO_157      157
#define   GPIO_158      158
#define   GPIO_159      159

#define   GPIO_160      160
#define   GPIO_161      161
#define   GPIO_162      162
#define   GPIO_163      163
#define   GPIO_164      164
#define   GPIO_165      165
#define   GPIO_166      166
#define   GPIO_167      167

#define   GPIO_168      168
#define   GPIO_169      169
#define   GPIO_170      170
#define   GPIO_171      171
#define   GPIO_172      172
#define   GPIO_173      173
#define   GPIO_174      174
#define   GPIO_175      175

#define   GPIO_176      176
#define   GPIO_177      177
#define   GPIO_178      178
#define   GPIO_179      179
#define   GPIO_180      180
#define   GPIO_181      181
#define   GPIO_182      182
#define   GPIO_183      183

#define   GPIO_184      184
#define   GPIO_185      185
#define   GPIO_186      186
#define   GPIO_187      187
#define   GPIO_188      188
#define   GPIO_189      189
#define   GPIO_190      190
#define   GPIO_191      191

#define   GPIO_192      192
#define   GPIO_193      193
#define   GPIO_194      194
#define   GPIO_195      195
#define   GPIO_196      196
#define   GPIO_197      197
#define   GPIO_198      198
#define   GPIO_199      199

#define   GPIO_200      200
#define   GPIO_201      201
#define   GPIO_202      202
#define   GPIO_203      203
#define   GPIO_204      204
#define   GPIO_205      205
#define   GPIO_206      206
#define   GPIO_207      207

#define   GPIO_208      208
#define   GPIO_209      209
#define   GPIO_210      210
#define   GPIO_211      211
#define   GPIO_212      212
#define   GPIO_213      213
#define   GPIO_214      214
#define   GPIO_215      215

#define   GPIO_216      216
#define   GPIO_217      217
#define   GPIO_218      218
#define   GPIO_219      219
#define   GPIO_220      220
#define   GPIO_221      221
#define   GPIO_222      222
#define   GPIO_223      223

#define   GPIO_224      224
#define   GPIO_225      225
#define   GPIO_226      226
#define   GPIO_227      227
#define   GPIO_228      228
#define   GPIO_229      229
#define   GPIO_230      230
#define   GPIO_231      231

#define   GPIO_000_SE     GPIO0_SE_0
#define   GPIO_001_SE     GPIO0_SE_1
#define   GPIO_002_SE     GPIO0_SE_2
#define   GPIO_003_SE     GPIO0_SE_3
#define   GPIO_004_SE     GPIO0_SE_4
#define   GPIO_005_SE     GPIO0_SE_5
#define   GPIO_006_SE     GPIO0_SE_6
#define   GPIO_007_SE     GPIO0_SE_7

#define   GPIO_008_SE     GPIO1_SE_0
#define   GPIO_009_SE     GPIO1_SE_1
#define   GPIO_010_SE     GPIO1_SE_2
#define   GPIO_011_SE     GPIO1_SE_3
#define   GPIO_012_SE     GPIO1_SE_4
#define   GPIO_013_SE     GPIO1_SE_5
#define   GPIO_014_SE     GPIO1_SE_6
#define   GPIO_015_SE     GPIO1_SE_7

#define TEST_MODE GPIO_001
#define GPS_REF GPIO_004
#define I2C3_SCL GPIO_005
#define I2C3_SDA GPIO_006
#define SPI1_CLK GPIO_007
#define SPI1_DI GPIO_008
#define SPI1_DO GPIO_009
#define SPI1_CS_N GPIO_010
#define ISP_GPIO00_FTRSTN GPIO_011
#define ISP_GPIO01_BKRSTN GPIO_012
#define ISP_GPIO02_MNTRB GPIO_013
#define ISP_GPIO06_FSYNC GPIO_014
#define ISP_GPIO10_SBPWM GPIO_015
#define ISP_CLK0 GPIO_016
#define ISP_CLK1 GPIO_017
#define ISP_SCL0 GPIO_019
#define ISP_SDA0 GPIO_020
#define ISP_SCL1 GPIO_021
#define ISP_SDA1 GPIO_022
#define ISP_SCL2 GPIO_023
#define ISP_SDA2 GPIO_024
#define I2C4_SCL GPIO_025
#define I2C4_SDA GPIO_026
#define UART2_CTS_N GPIO_027
#define UART2_RTS_N GPIO_028
#define UART2_TXD GPIO_029
#define UART2_RXD GPIO_030
#define UART6_CTS_N GPIO_031
#define UART6_RTS_N GPIO_032
#define UART6_RXD GPIO_033
#define UART6_TXD GPIO_034
#define UART0_RXD_UC GPIO_035
#define UART0_TXD_UC GPIO_036
#define UART5_CTS_N GPIO_037
#define UART5_RTS_N GPIO_038
#define UART5_RXD GPIO_039
#define UART5_TXD GPIO_040
#define UART4_CTS_N GPIO_041
#define UART4_RTS_N GPIO_042
#define UART4_RXD GPIO_043
#define UART4_TXD GPIO_044
#define PWM_OUT1 GPIO_045
#define PMU_AUXDAC0_SSI GPIO_046
#define LTE_INACTIVE GPIO_047
#define LTE_RX_ACTIVE GPIO_048
#define LTE_TX_ACTIVE GPIO_049
#define ISM_PRIORITY GPIO_050
#define ANTPA_SEL00 GPIO_053
#define ANTPA_SEL01 GPIO_054
#define ANTPA_SEL02 GPIO_055
#define ANTPA_SEL03 GPIO_056
#define ANTPA_SEL04 GPIO_057
#define ANTPA_SEL05 GPIO_058
#define ANTPA_SEL06 GPIO_059
#define ANTPA_SEL07 GPIO_060
#define ANTPA_SEL08 GPIO_061
#define ANTPA_SEL09 GPIO_062
#define ANTPA_SEL10 GPIO_063
#define ANTPA_SEL11 GPIO_064
#define ANTPA_SEL12 GPIO_065
#define ANTPA_SEL13 GPIO_066
#define ANTPA_SEL14 GPIO_067
#define ANTPA_SEL15 GPIO_068
#define ANTPA_SEL16 GPIO_069
#define ANTPA_SEL17 GPIO_070
#define ANTPA_SEL18 GPIO_071
#define ANTPA_SEL19 GPIO_072
#define ANTPA_SEL20 GPIO_073
#define ANTPA_SEL21 GPIO_074
#define ANTPA_SEL22 GPIO_075
#define ANTPA_SEL23 GPIO_076
#define ANTPA_SEL24 GPIO_077
#define ANTPA_SEL25 GPIO_078
#define ANTPA_SEL26 GPIO_079
#define ANTPA_SEL27 GPIO_080
#define ANTPA_SEL28 GPIO_081
#define ANTPA_SEL29 GPIO_082
#define ANTPA_SEL30 GPIO_083
#define FE0_MIPI_CLK GPIO_084
#define FE0_MIPI_DATA GPIO_085
#define FE1_MIPI_CLK GPIO_086
#define FE1_MIPI_DATA GPIO_087
#define FE2_MIPI_CLK GPIO_088
#define FE2_MIPI_DATA GPIO_089
#define RFIC0_MIPI_CLK GPIO_090
#define RFIC0_MIPI_DATA GPIO_091
#define GMSK_PH0 GPIO_092
#define JTAG_TCK_SWCLK GPIO_178
#define JTAG_TMS_SWDIO GPIO_179
#define JTAG_TRST_N GPIO_180
#define JTAG_TDI GPIO_181
#define JTAG_TDO GPIO_182
#define BLPWM_CABC GPIO_185
#define BLPWM_BL GPIO_186
#define I2C0_SCL GPIO_187
#define I2C0_SDA GPIO_188
#define I2C1_SCL GPIO_189
#define I2C1_SDA GPIO_190
#define I2C2_SCL GPIO_191
#define I2C2_SDA GPIO_192
#define SLIMBUS_CLK GPIO_193
#define SLIMBUS_DATA GPIO_194
#define SPI2_CLK GPIO_214
#define SPI2_DI GPIO_215
#define SPI2_DO GPIO_216
#define SPI2_CS0_N GPIO_217
#define SPI2_CS1_N GPIO_218
#define SPI2_CS2_N GPIO_219
#define SPI2_CS3_N GPIO_220
#define SPMI_DATA GPIO_226
#define SPMI_CLK GPIO_227
#define SPI0_CLK GPIO_228
#define SPI0_DI GPIO_229
#define SPI0_DO GPIO_230
#define SPI0_CS0_N GPIO_231
#define SPI0_CS1_N GPIO_144
#define SD_CLK GPIO_160
#define SD_CMD GPIO_161
#define SD_DATA0 GPIO_162
#define SD_DATA1 GPIO_163
#define SD_DATA2 GPIO_164
#define SD_DATA3 GPIO_165
#define USIM0_CLK GPIO_166
#define USIM0_RST GPIO_167
#define USIM0_DATA GPIO_168
#define USIM1_CLK GPIO_169
#define USIM1_RST GPIO_170
#define USIM1_DATA GPIO_171
#define SDIO_CLK GPIO_128
#define SDIO_CMD GPIO_129
#define SDIO_DATA0 GPIO_130
#define SDIO_DATA1 GPIO_131
#define SDIO_DATA2 GPIO_132
#define SDIO_DATA3 GPIO_133

#define INVALID_VALUE_GPIO 0xFFFFFFFF
#define NO_IOMG 0xFFFFFFFF

#endif
