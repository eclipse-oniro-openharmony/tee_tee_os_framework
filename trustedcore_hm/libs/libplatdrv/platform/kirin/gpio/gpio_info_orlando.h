/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * Description: define GPIO and IOCG and IOMG basedress.
 * Author: hisilicon
 * Create: 2019-08-7
 */

#include "soc_acpu_baseaddr_interface.h"
#ifndef __GPIOINFO_ORLANDO_H
#define __GPIOINFO_ORLANDO_H


#define REG_BASE_GPIO33                 SOC_ACPU_GPIO33_BASE_ADDR
#define REG_BASE_GPIO32                 SOC_ACPU_GPIO32_BASE_ADDR
#define REG_BASE_GPIO31                 SOC_ACPU_GPIO31_BASE_ADDR
#define REG_BASE_GPIO30                 SOC_ACPU_GPIO30_BASE_ADDR
#define REG_BASE_GPIO29                 SOC_ACPU_GPIO29_BASE_ADDR
#define REG_BASE_GPIO28                 SOC_ACPU_GPIO28_BASE_ADDR
#define REG_BASE_GPIO27					SOC_ACPU_GPIO27_BASE_ADDR
#define REG_BASE_GPIO26					SOC_ACPU_GPIO26_BASE_ADDR
#define REG_BASE_GPIO25					SOC_ACPU_GPIO25_BASE_ADDR
#define REG_BASE_GPIO24					SOC_ACPU_GPIO24_BASE_ADDR
#define REG_BASE_GPIO23					SOC_ACPU_GPIO23_BASE_ADDR
#define REG_BASE_GPIO22					SOC_ACPU_GPIO22_BASE_ADDR
#define REG_BASE_GPIO0_SE               SOC_ACPU_GPIO0_SE_BASE_ADDR
#define REG_BASE_GPIO1_SE               SOC_ACPU_GPIO1_SE_BASE_ADDR
#define REG_BASE_GPIO0					SOC_ACPU_GPIO0_BASE_ADDR
#define REG_BASE_GPIO1					SOC_ACPU_GPIO1_BASE_ADDR
#define REG_BASE_GPIO2					SOC_ACPU_GPIO2_BASE_ADDR
#define REG_BASE_GPIO3					SOC_ACPU_GPIO3_BASE_ADDR
#define REG_BASE_GPIO4					SOC_ACPU_GPIO4_BASE_ADDR
#define REG_BASE_GPIO5					SOC_ACPU_GPIO5_BASE_ADDR
#define REG_BASE_GPIO6					SOC_ACPU_GPIO6_BASE_ADDR
#define REG_BASE_GPIO7					SOC_ACPU_GPIO7_BASE_ADDR
#define REG_BASE_GPIO8					SOC_ACPU_GPIO8_BASE_ADDR
#define REG_BASE_GPIO9					SOC_ACPU_GPIO9_BASE_ADDR
#define REG_BASE_GPIO10					SOC_ACPU_GPIO10_BASE_ADDR
#define REG_BASE_GPIO11					SOC_ACPU_GPIO11_BASE_ADDR
#define REG_BASE_GPIO12					SOC_ACPU_GPIO12_BASE_ADDR
#define REG_BASE_GPIO13					SOC_ACPU_GPIO13_BASE_ADDR
#define REG_BASE_GPIO14					SOC_ACPU_GPIO14_BASE_ADDR
#define REG_BASE_GPIO15					SOC_ACPU_GPIO15_BASE_ADDR
#define REG_BASE_GPIO16					SOC_ACPU_GPIO16_BASE_ADDR
#define REG_BASE_GPIO17					SOC_ACPU_GPIO17_BASE_ADDR
#define REG_BASE_GPIO18					SOC_ACPU_GPIO18_BASE_ADDR
#define REG_BASE_GPIO19					SOC_ACPU_GPIO19_BASE_ADDR
#define REG_BASE_GPIO20					SOC_ACPU_GPIO20_BASE_ADDR
#define REG_BASE_GPIO21					SOC_ACPU_GPIO21_BASE_ADDR
#define REG_BASE_PCTRL					SOC_ACPU_PCTRL_BASE_ADDR

/* 
 *  define gpio number in the way of group. *
 */
  
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

#define GPIO_9_2    74
#define GPIO_9_3    75
#define GPIO_9_4    76

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
#define GPIO_26_6   214
#define GPIO_26_7   215

#define GPIO_27_0   216
#define GPIO_27_1   217
#define GPIO_27_2   218
#define GPIO_27_3   219
#define GPIO_27_4   220
#define GPIO_27_5   221
#define GPIO_27_6   222
#define GPIO_27_7   223

#define GPIO_28_0   224
#define GPIO_28_1   225
#define GPIO_28_2   226
#define GPIO_28_3   227
#define GPIO_28_4   228
#define GPIO_28_5   229
#define GPIO_28_6   230
#define GPIO_28_7   231

#define GPIO_29_0   232
#define GPIO_29_1   233
#define GPIO_29_2   234
#define GPIO_29_3   235
#define GPIO_29_4   236
#define GPIO_29_5   237
#define GPIO_29_6   238
#define GPIO_29_7   239

#define GPIO_30_0   240
#define GPIO_30_1   241
#define GPIO_30_2   242
#define GPIO_30_3   243
#define GPIO_30_4   244
#define GPIO_30_5   245
#define GPIO_30_6   246
#define GPIO_30_7   247

#define GPIO_31_0   248
#define GPIO_31_1   249
#define GPIO_31_2   250
#define GPIO_31_3   251
#define GPIO_31_4   252
#define GPIO_31_5   253
#define GPIO_31_6   254
#define GPIO_31_7   255

#define GPIO_32_0   256
#define GPIO_32_1   257
#define GPIO_32_2   258
#define GPIO_32_3   259
#define GPIO_32_4   260
#define GPIO_32_5   261
#define GPIO_32_6   262
#define GPIO_32_7   263

#define GPIO_33_0   264
#define GPIO_33_1   265
#define GPIO_33_2   266
#define GPIO_33_3   267
#define GPIO_33_4   268
#define GPIO_33_5   269
#define GPIO_33_6   270
#define GPIO_33_7   271

#define GPIO0_SE_0  272
#define GPIO0_SE_1  273
#define GPIO0_SE_2  274
#define GPIO0_SE_3  275
#define GPIO0_SE_4  276
#define GPIO0_SE_5  277
#define GPIO0_SE_6  278
#define GPIO0_SE_7  279

#define GPIO1_SE_0  280
#define GPIO1_SE_1  281
#define GPIO1_SE_2  282
#define GPIO1_SE_3  283
#define GPIO1_SE_4  284
#define GPIO1_SE_5  285
#define GPIO1_SE_6  286
#define GPIO1_SE_7  287

/* define GPIO 0 ~ GPIO 7 */
#define   GPIO_000     GPIO_0_0
#define   GPIO_001     GPIO_0_1
#define   GPIO_002     GPIO_0_2
#define   GPIO_003     GPIO_0_3
#define   GPIO_004     GPIO_0_4
#define   GPIO_005     GPIO_0_5
#define   GPIO_006     GPIO_0_6
#define   GPIO_007     GPIO_0_7

/* define GPIO 8 ~ GPIO 15 */
#define   GPIO_008     GPIO_1_0
#define   GPIO_009     GPIO_1_1
#define   GPIO_010     GPIO_1_2
#define   GPIO_011     GPIO_1_3
#define   GPIO_012     GPIO_1_4
#define   GPIO_013     GPIO_1_5
#define   GPIO_014     GPIO_1_6
#define   GPIO_015     GPIO_1_7

/* define GPIO 16 ~ GPIO 23 */
#define   GPIO_016     GPIO_2_0
#define   GPIO_017     GPIO_2_1
#define   GPIO_018     GPIO_2_2
#define   GPIO_019     GPIO_2_3
#define   GPIO_020     GPIO_2_4
#define   GPIO_021     GPIO_2_5
#define   GPIO_022     GPIO_2_6
#define   GPIO_023     GPIO_2_7

/* define GPIO 24 ~ GPIO 31 */
#define   GPIO_024     GPIO_3_0
#define   GPIO_025     GPIO_3_1
#define   GPIO_026     GPIO_3_2
#define   GPIO_027     GPIO_3_3
#define   GPIO_028     GPIO_3_4
#define   GPIO_029     GPIO_3_5
#define   GPIO_030     GPIO_3_6
#define   GPIO_031     GPIO_3_7

/* define GPIO 32 ~ GPIO 39 */
#define   GPIO_032     GPIO_4_0
#define   GPIO_033     GPIO_4_1
#define   GPIO_034     GPIO_4_2
#define   GPIO_035     GPIO_4_3
#define   GPIO_036     GPIO_4_4
#define   GPIO_037     GPIO_4_5
#define   GPIO_038     GPIO_4_6
#define   GPIO_039     GPIO_4_7

/* define GPIO 40 ~ GPIO 47 */
#define   GPIO_040     GPIO_5_0
#define   GPIO_041     GPIO_5_1
#define   GPIO_042     GPIO_5_2
#define   GPIO_043     GPIO_5_3
#define   GPIO_044     GPIO_5_4
#define   GPIO_045     GPIO_5_5
#define   GPIO_046     GPIO_5_6
#define   GPIO_047     GPIO_5_7

/* define GPIO 48 ~ GPIO 55 */
#define   GPIO_048     GPIO_6_0
#define   GPIO_049     GPIO_6_1
#define   GPIO_050     GPIO_6_2
#define   GPIO_051     GPIO_6_3
#define   GPIO_052     GPIO_6_4
#define   GPIO_053     GPIO_6_5
#define   GPIO_054     GPIO_6_6
#define   GPIO_055     GPIO_6_7

/* define GPIO 56 ~ GPIO 63 */
#define   GPIO_056     GPIO_7_0
#define   GPIO_057     GPIO_7_1
#define   GPIO_058     GPIO_7_2
#define   GPIO_059     GPIO_7_3
#define   GPIO_060     GPIO_7_4
#define   GPIO_061     GPIO_7_5
#define   GPIO_062     GPIO_7_6
#define   GPIO_063     GPIO_7_7

/* define GPIO 64 ~ GPIO 71 */
#define   GPIO_064     GPIO_8_0
#define   GPIO_065     GPIO_8_1
#define   GPIO_066     GPIO_8_2
#define   GPIO_067     GPIO_8_3
#define   GPIO_068     GPIO_8_4
#define   GPIO_069     GPIO_8_5
#define   GPIO_070     GPIO_8_6
#define   GPIO_071     GPIO_8_7

/* define GPIO 72 ~ GPIO 79 */
#define   GPIO_072     GPIO_9_0
#define   GPIO_073     GPIO_9_1

#define   GPIO_074     GPIO_9_2
#define   GPIO_075     GPIO_9_3
#define   GPIO_076     GPIO_9_4

#define   GPIO_077     GPIO_9_5
#define   GPIO_078     GPIO_9_6
#define   GPIO_079     GPIO_9_7

/* define GPIO 80 ~ GPIO 87 */
#define   GPIO_080     GPIO_10_0
#define   GPIO_081     GPIO_10_1
#define   GPIO_082     GPIO_10_2
#define   GPIO_083     GPIO_10_3
#define   GPIO_084     GPIO_10_4
#define   GPIO_085     GPIO_10_5
#define   GPIO_086     GPIO_10_6
#define   GPIO_087     GPIO_10_7

/* define GPIO 88 ~ GPIO 95 */
#define   GPIO_088     GPIO_11_0
#define   GPIO_089     GPIO_11_1
#define   GPIO_090     GPIO_11_2
#define   GPIO_091     GPIO_11_3
#define   GPIO_092     GPIO_11_4
#define   GPIO_093     GPIO_11_5
#define   GPIO_094     GPIO_11_6
#define   GPIO_095     GPIO_11_7

/* define GPIO 96 ~ GPIO 103 */
#define   GPIO_096     GPIO_12_0
#define   GPIO_097     GPIO_12_1
#define   GPIO_098     GPIO_12_2
#define   GPIO_099     GPIO_12_3
#define   GPIO_100     GPIO_12_4
#define   GPIO_101     GPIO_12_5
#define   GPIO_102     GPIO_12_6
#define   GPIO_103     GPIO_12_7

/* define GPIO 104 ~ GPIO 111 */
#define   GPIO_104     GPIO_13_0
#define   GPIO_105     GPIO_13_1
#define   GPIO_106     GPIO_13_2
#define   GPIO_107     GPIO_13_3
#define   GPIO_108     GPIO_13_4
#define   GPIO_109     GPIO_13_5
#define   GPIO_110     GPIO_13_6
#define   GPIO_111     GPIO_13_7

/* define GPIO 112 ~ GPIO 119 */
#define   GPIO_112     GPIO_14_0
#define   GPIO_113     GPIO_14_1
#define   GPIO_114     GPIO_14_2
#define   GPIO_115     GPIO_14_3
#define   GPIO_116     GPIO_14_4
#define   GPIO_117     GPIO_14_5
#define   GPIO_118     GPIO_14_6
#define   GPIO_119     GPIO_14_7

/* define GPIO 120 ~ GPIO 127 */
#define   GPIO_120     GPIO_15_0
#define   GPIO_121     GPIO_15_1
#define   GPIO_122     GPIO_15_2
#define   GPIO_123     GPIO_15_3
#define   GPIO_124     GPIO_15_4
#define   GPIO_125     GPIO_15_5
#define   GPIO_126     GPIO_15_6
#define   GPIO_127     GPIO_15_7

/* define GPIO 128 ~ GPIO 135 */
#define   GPIO_128     GPIO_16_0
#define   GPIO_129     GPIO_16_1
#define   GPIO_130     GPIO_16_2
#define   GPIO_131     GPIO_16_3
#define   GPIO_132     GPIO_16_4
#define   GPIO_133     GPIO_16_5
#define   GPIO_134     GPIO_16_6
#define   GPIO_135     GPIO_16_7

/* define GPIO 136 ~ GPIO 143 */
#define   GPIO_136     GPIO_17_0
#define   GPIO_137     GPIO_17_1
#define   GPIO_138     GPIO_17_2
#define   GPIO_139     GPIO_17_3
#define   GPIO_140     GPIO_17_4
#define   GPIO_141     GPIO_17_5
#define   GPIO_142     GPIO_17_6
#define   GPIO_143     GPIO_17_7

/* define GPIO 144 ~ GPIO 151 */
#define   GPIO_144     GPIO_18_0
#define   GPIO_145     GPIO_18_1
#define   GPIO_146     GPIO_18_2
#define   GPIO_147     GPIO_18_3
#define   GPIO_148     GPIO_18_4
#define   GPIO_149     GPIO_18_5
#define   GPIO_150     GPIO_18_6
#define   GPIO_151     GPIO_18_7

/* define GPIO 152 ~ GPIO 159 */
#define   GPIO_152     GPIO_19_0
#define   GPIO_153     GPIO_19_1
#define   GPIO_154     GPIO_19_2
#define   GPIO_155     GPIO_19_3
#define   GPIO_156     GPIO_19_4
#define   GPIO_157     GPIO_19_5
#define   GPIO_158     GPIO_19_6
#define   GPIO_159     GPIO_19_7

/* define GPIO 160 ~ GPIO 167 */
#define   GPIO_160     GPIO_20_0
#define   GPIO_161     GPIO_20_1
#define   GPIO_162     GPIO_20_2
#define   GPIO_163     GPIO_20_3
#define   GPIO_164     GPIO_20_4
#define   GPIO_165     GPIO_20_5
#define   GPIO_166     GPIO_20_6
#define   GPIO_167     GPIO_20_7

/* define GPIO 168 ~ GPIO 175 */
#define   GPIO_168     GPIO_21_0
#define   GPIO_169     GPIO_21_1
#define   GPIO_170     GPIO_21_2
#define   GPIO_171     GPIO_21_3
#define   GPIO_172     GPIO_21_4
#define   GPIO_173     GPIO_21_5
#define   GPIO_174     GPIO_21_6
#define   GPIO_175     GPIO_21_7


/* define GPIO 176 ~ GPIO 183 */
#define   GPIO_176     GPIO_22_0
#define   GPIO_177     GPIO_22_1
#define   GPIO_178     GPIO_22_2
#define   GPIO_179     GPIO_22_3
#define   GPIO_180     GPIO_22_4
#define   GPIO_181     GPIO_22_5
#define   GPIO_182     GPIO_22_6
#define   GPIO_183     GPIO_22_7

/* define GPIO 184 ~ GPIO 191 */
#define   GPIO_184     GPIO_23_0
#define   GPIO_185     GPIO_23_1
#define   GPIO_186     GPIO_23_2
#define   GPIO_187     GPIO_23_3
#define   GPIO_188     GPIO_23_4
#define   GPIO_189     GPIO_23_5
#define   GPIO_190     GPIO_23_6
#define   GPIO_191     GPIO_23_7

/* define GPIO 192 ~ GPIO 199 */
#define   GPIO_192     GPIO_24_0
#define   GPIO_193     GPIO_24_1
#define   GPIO_194     GPIO_24_2
#define   GPIO_195     GPIO_24_3
#define   GPIO_196     GPIO_24_4
#define   GPIO_197     GPIO_24_5
#define   GPIO_198     GPIO_24_6
#define   GPIO_199     GPIO_24_7

/* define GPIO 200 ~ GPIO 207 */
#define   GPIO_200     GPIO_25_0
#define   GPIO_201     GPIO_25_1
#define   GPIO_202     GPIO_25_2
#define   GPIO_203     GPIO_25_3
#define   GPIO_204     GPIO_25_4
#define   GPIO_205     GPIO_25_5
#define   GPIO_206     GPIO_25_6
#define   GPIO_207     GPIO_25_7

/* define GPIO 208 ~ GPIO 215 */
#define   GPIO_208     GPIO_26_0
#define   GPIO_209     GPIO_26_1
#define   GPIO_210     GPIO_26_2
#define   GPIO_211     GPIO_26_3
#define   GPIO_212     GPIO_26_4
#define   GPIO_213     GPIO_26_5
#define   GPIO_214     GPIO_26_6
#define   GPIO_215     GPIO_26_7

/* define GPIO 216 ~ GPIO 223 */
#define   GPIO_216     GPIO_27_0
#define   GPIO_217     GPIO_27_1
#define   GPIO_218     GPIO_27_2
#define   GPIO_219     GPIO_27_3
#define   GPIO_220     GPIO_27_4
#define   GPIO_221     GPIO_27_5
#define   GPIO_222     GPIO_27_6
#define   GPIO_223     GPIO_27_7

/* define GPIO 224 ~ GPIO 231 */
#define   GPIO_224     GPIO_28_0
#define   GPIO_225     GPIO_28_1
#define   GPIO_226     GPIO_28_2
#define   GPIO_227     GPIO_28_3
#define   GPIO_228     GPIO_28_4
#define   GPIO_229     GPIO_28_5
#define   GPIO_230     GPIO_28_6
#define   GPIO_231     GPIO_28_7

/* define GPIO 232 ~ GPIO 239 */
#define   GPIO_232     GPIO_29_0
#define   GPIO_233     GPIO_29_1
#define   GPIO_234     GPIO_29_2
#define   GPIO_235     GPIO_29_3
#define   GPIO_236     GPIO_29_4
#define   GPIO_237     GPIO_29_5
#define   GPIO_238     GPIO_29_6
#define   GPIO_239     GPIO_29_7

/* define GPIO 240 ~ GPIO 247 */
#define   GPIO_240     GPIO_30_0
#define   GPIO_241     GPIO_30_1
#define   GPIO_242     GPIO_30_2
#define   GPIO_243     GPIO_30_3
#define   GPIO_244     GPIO_30_4
#define   GPIO_245     GPIO_30_5
#define   GPIO_246     GPIO_30_6
#define   GPIO_247     GPIO_30_7

/* define GPIO 248 ~ GPIO 255 */
#define   GPIO_248     GPIO_31_0
#define   GPIO_249     GPIO_31_1
#define   GPIO_250     GPIO_31_2
#define   GPIO_251     GPIO_31_3
#define   GPIO_252     GPIO_31_4
#define   GPIO_253     GPIO_31_5
#define   GPIO_254     GPIO_31_6
#define   GPIO_255     GPIO_31_7

/* define GPIO 256 ~ GPIO 263 */
#define   GPIO_256     GPIO_32_0
#define   GPIO_257     GPIO_32_1
#define   GPIO_258     GPIO_32_2
#define   GPIO_259     GPIO_32_3
#define   GPIO_260     GPIO_32_4
#define   GPIO_261     GPIO_32_5
#define   GPIO_262     GPIO_32_6
#define   GPIO_263     GPIO_32_7

/* define GPIO 264 ~ GPIO 271 */
#define   GPIO_264     GPIO_33_0
#define   GPIO_265     GPIO_33_1
#define   GPIO_266     GPIO_33_2
#define   GPIO_267     GPIO_33_3
#define   GPIO_268     GPIO_33_4
#define   GPIO_269     GPIO_33_5
#define   GPIO_270     GPIO_33_6
#define   GPIO_271     GPIO_33_7

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

#define   TEST_MODE   GPIO_001
#define   PMU_AUXDAC0_SSI   GPIO_002
#define   LCD_TE0   GPIO_003
#define   GMSK_PH0   GPIO_004
#define   I2C3_SCL   GPIO_005
#define   I2C3_SDA   GPIO_006
#define   ISP_GPIO00_FTRSTN   GPIO_007
#define   ISP_GPIO01_BKRSTN   GPIO_008
#define   ISP_GPIO02_MNTRB   GPIO_009
#define   ISP_GPIO06_SBPWM   GPIO_010
#define   ISP_GPIO10_FSYNC   GPIO_011
#define   BOOT_UFS   GPIO_014
#define   VBAT_DROP_PROT   GPIO_015
#define   ISP_CLK0   GPIO_016
#define   ISP_CLK1   GPIO_017
#define   ISP_CLK2   GPIO_018
#define   ISP_SCL0   GPIO_019
#define   ISP_SDA0   GPIO_020
#define   ISP_SCL1   GPIO_021
#define   ISP_SDA1   GPIO_022
#define   ISP_SCL2   GPIO_023
#define   ISP_SDA2   GPIO_024
#define   I2C4_SCL   GPIO_025
#define   I2C4_SDA   GPIO_026
#define   UART2_CTS_N   GPIO_027
#define   UART2_RTS_N   GPIO_028
#define   UART2_TXD   GPIO_029
#define   UART2_RXD   GPIO_030
#define   I2C6_SDA   GPIO_031
#define   I2C6_SCL   GPIO_032
#define   ANTPA_SEL00   GPIO_038
#define   ANTPA_SEL01   GPIO_039
#define   ANTPA_SEL02   GPIO_040
#define   ANTPA_SEL03   GPIO_041
#define   ANTPA_SEL04   GPIO_042
#define   ANTPA_SEL05   GPIO_043
#define   ANTPA_SEL06   GPIO_044
#define   ANTPA_SEL07   GPIO_045
#define   ANTPA_SEL08   GPIO_046
#define   ANTPA_SEL09   GPIO_047
#define   ANTPA_SEL10   GPIO_048
#define   ANTPA_SEL11   GPIO_049
#define   ANTPA_SEL12   GPIO_050
#define   ANTPA_SEL13   GPIO_051
#define   ANTPA_SEL14   GPIO_052
#define   ANTPA_SEL15   GPIO_053
#define   ANTPA_SEL16   GPIO_054
#define   ANTPA_SEL19   GPIO_055
#define   ANTPA_SEL20   GPIO_056
#define   ANTPA_SEL21   GPIO_057
#define   ANTPA_SEL22   GPIO_058
#define   ANTPA_SEL27   GPIO_059
#define   ANTPA_SEL28   GPIO_060
#define   ANTPA_SEL29   GPIO_061
#define   ANTPA_SEL30   GPIO_062
#define   FE0_MIPI_CLK   GPIO_063
#define   FE0_MIPI_DATA   GPIO_064
#define   FE1_MIPI_CLK   GPIO_065
#define   FE1_MIPI_DATA   GPIO_066
#define   RFIC0_MIPI_CLK   GPIO_067
#define   RFIC0_MIPI_DATA   GPIO_068
#define   SDIO_CLK   GPIO_128
#define   SDIO_CMD   GPIO_129
#define   SDIO_DATA0   GPIO_130
#define   SDIO_DATA1   GPIO_131
#define   SDIO_DATA2   GPIO_132
#define   SDIO_DATA3   GPIO_133
#define   SD_CLK   GPIO_160
#define   SD_CMD   GPIO_161
#define   SD_DATA0   GPIO_162
#define   SD_DATA1   GPIO_163
#define   SD_DATA2   GPIO_164
#define   SD_DATA3   GPIO_165
#define   USIM0_CLK   GPIO_166
#define   USIM0_RST   GPIO_167
#define   USIM0_DATA   GPIO_168
#define   USIM1_CLK   GPIO_169
#define   USIM1_RST   GPIO_170
#define   USIM1_DATA   GPIO_171
#define   JTAG_TCK_SWCLK   GPIO_178
#define   JTAG_TMS_SWDIO   GPIO_179
#define   JTAG_TRST_N   GPIO_180
#define   JTAG_TDI   GPIO_181
#define   JTAG_TDO   GPIO_182
#define   BLPWM_CABC   GPIO_185
#define   BLPWM_BL   GPIO_186
#define   I2C0_SCL   GPIO_187
#define   I2C0_SDA   GPIO_188
#define   I2C1_SCL   GPIO_189
#define   I2C1_SDA   GPIO_190
#define   I3C3_SCL   GPIO_191
#define   I3C3_SDA   GPIO_192
#define   SIF_CLK   GPIO_193
#define   SIF_DO0   GPIO_194
#define   I2S1_DI   GPIO_195
#define   I2S1_DO   GPIO_196
#define   I2S1_XCLK   GPIO_197
#define   I2S1_XFS   GPIO_198
#define   I2S2_DI   GPIO_199
#define   I2S2_DO   GPIO_200
#define   I2S2_XCLK   GPIO_201
#define   I2S2_XFS   GPIO_202
#define   SIF_DI0   GPIO_203
#define   SIF_SYNC   GPIO_204
#define   SIF_DO1   GPIO_210
#define   SPI2_CLK   GPIO_212
#define   SPI2_DI   GPIO_213
#define   SPI2_DO   GPIO_214
#define   SPI2_CS0_N   GPIO_215
#define   SPI2_CS1_N   GPIO_216
#define   I2S3_DI   GPIO_219
#define   I2S3_DO   GPIO_220
#define   I2S3_XCLK   GPIO_221
#define   I2S3_XFS   GPIO_222
#define   SIF_DI1   GPIO_223
#define   SPI0_CLK   GPIO_224
#define   SPI0_DI   GPIO_225
#define   SPI0_DO   GPIO_226
#define   SPI0_CS0_N   GPIO_227
#define   SPI0_CS1_N   GPIO_228
#define   SPI3_CLK   GPIO_229
#define   SPI3_DI   GPIO_230
#define   SPI3_DO   GPIO_231
#define   SPI3_CS0_N   GPIO_232
#define   SPI3_CS1_N   GPIO_233
#define   SPI1_CLK   GPIO_234
#define   SPI1_DI   GPIO_235
#define   SPI1_DO   GPIO_236
#define   SPI1_CS0_N   GPIO_237
#define   SPI1_CS1_N   GPIO_238
#define   I3C2_SCL   GPIO_239
#define   I3C2_SDA   GPIO_240
#define   SPMI_DATA   GPIO_241
#define   SPMI_CLK   GPIO_242
#define   GPS_REF   GPIO_243
#define   UART0_RXD_UC   GPIO_244
#define   UART0_TXD_UC   GPIO_245
#define   UART6_CTS_N   GPIO_246
#define   UART6_RTS_N   GPIO_247
#define   UART6_RXD   GPIO_248
#define   UART6_TXD   GPIO_249
#define   UART3_CTS_N   GPIO_250
#define   UART3_RTS_N   GPIO_251
#define   UART3_RXD   GPIO_252
#define   UART3_TXD   GPIO_253
#define   UART4_CTS_N   GPIO_254
#define   UART4_RTS_N   GPIO_255
#define   UART4_RXD   GPIO_256
#define   UART4_TXD   GPIO_257
#define   LTE_INACTIVE   GPIO_258
#define   LTE_RX_ACTIVE   GPIO_259
#define   LTE_TX_ACTIVE   GPIO_260
#define   ISM_PRIORITY   GPIO_261
#define   UFS_RST_N   GPIO_262
#define   INVALID_VALUE_GPIO    0xFFFFFFFF
#define     NO_IOMG                   0xFFFFFFFF
#endif
