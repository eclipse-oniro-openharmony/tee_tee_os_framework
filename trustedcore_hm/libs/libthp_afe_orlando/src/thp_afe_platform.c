/*
* Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
* Description: common interface file
* Author: l00492120 & c00414356
* Create: 2017-01-20
* Notes: this file's api is for all TP modules platform wrapper interface
*/
#include "self_adapt_supplier.h"

#define afe_tui_fun_wrapper(key) key##_saipan_snps
#include "thp_afe_supplier.h"
#undef afe_tui_fun_wrapper
#define afe_tui_fun_wrapper(key) key##_saipan_nova
#include "thp_afe_supplier.h"
#undef afe_tui_fun_wrapper
#define afe_tui_fun_wrapper(key) key##_saipan_focal
#include "thp_afe_supplier.h"
#undef afe_tui_fun_wrapper
#define afe_tui_fun_wrapper(key) key##_b141_goodix
#include "thp_afe_supplier.h"
#undef afe_tui_fun_wrapper
#define afe_tui_fun_wrapper(key) key##_yale_snps
#include "thp_afe_supplier.h"
#undef afe_tui_fun_wrapper
#define afe_tui_fun_wrapper(key) key##_yale_nova
#include "thp_afe_supplier.h"

struct_supplier(saipan_snps);
struct_supplier(saipan_nova);
struct_supplier(saipan_focal);
struct_supplier(b141_goodix);
struct_supplier(yale_snps);
struct_supplier(yale_nova);

thp_afe_api* g_afe_api_type[] = {
    &thp_afe_api_saipan_focal,
    &thp_afe_api_saipan_snps,
    &thp_afe_api_saipan_snps,
    &thp_afe_api_saipan_nova,
    &thp_afe_api_saipan_nova,
    &thp_afe_api_b141_goodix,
    &thp_afe_api_saipan_nova,
    &thp_afe_api_yale_snps,
    &thp_afe_api_yale_snps,
    &thp_afe_api_yale_snps,
    &thp_afe_api_yale_snps,
    &thp_afe_api_yale_nova,
    &thp_afe_api_yale_nova,
    &thp_afe_api_yale_nova,
    NULL
};

char* g_projectid_text[] = {
    "B146681400", /* saipan focal + ctc */
    "B146691100", /* saipan snps + tm */
    "B146691110", /* saipan snps + tm TD4320B */
    "B146771400", /* saipan nova + ctc */
    "B146771300", /* saipan nova + boe */
    "B141780900", /* seattle goodix + samsung */
    "B146771100", /* saipan nova + tm */
    "B121691100",
    "B121691110",
    "B121691120", /* yale_se snps_b + tm */
    "B121691130", /* yale_se snps_nb + tm */
    "B121771100", /* yale nova + tm */
    "B121771300", /* yale nova + boe */
    "B121771400", /* yale_se nova + ctc */
    "N/A"         /* NA AFE THP */
};
