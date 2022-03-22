/*
* Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
* Description: common interface file
* Author: l00492120 & c00414356
* Create: 2017-01-20
* Notes: this file's api is for all TP modules platform wrapper interface
*/
#include "self_adapt_supplier.h"

#define afe_tui_fun_wrapper(key) key##_jdi
#include "thp_afe_supplier.h"
#undef afe_tui_fun_wrapper
#define afe_tui_fun_wrapper(key) key##_nova
#include "thp_afe_supplier.h"
#undef afe_tui_fun_wrapper
#define afe_tui_fun_wrapper(key) key##_snps
#include "thp_afe_supplier.h"
#undef afe_tui_fun_wrapper
#define afe_tui_fun_wrapper(key) key##_hima_nova
#include "thp_afe_supplier.h"
#undef afe_tui_fun_wrapper
#define afe_tui_fun_wrapper(key) key##_hima_snps
#include "thp_afe_supplier.h"
#undef afe_tui_fun_wrapper
#define afe_tui_fun_wrapper(key) key##_hima_himax
#include "thp_afe_supplier.h"
#undef afe_tui_fun_wrapper
#define afe_tui_fun_wrapper(key) key##_goodix
#include "thp_afe_supplier.h"
#undef afe_tui_fun_wrapper
#define afe_tui_fun_wrapper(key) key##_tui_for085_goodix
#include "thp_afe_supplier.h"
#undef afe_tui_fun_wrapper
#define afe_tui_fun_wrapper(key) key##_solomon
#include "thp_afe_supplier.h"
#undef afe_tui_fun_wrapper
#define afe_tui_fun_wrapper(key) key##_yale_snps
#include "thp_afe_supplier.h"
#undef afe_tui_fun_wrapper
#define afe_tui_fun_wrapper(key) key##_yale_focal
#include "thp_afe_supplier.h"
#undef afe_tui_fun_wrapper
#define afe_tui_fun_wrapper(key) key##_yale_nova
#include "thp_afe_supplier.h"
#undef afe_tui_fun_wrapper
#define afe_tui_fun_wrapper(key) key##_b141_goodix
#include "thp_afe_supplier.h"

struct_supplier(hima_nova);
struct_supplier(hima_snps);
struct_supplier(hima_himax);
struct_supplier(goodix);
struct_supplier(solomon);
struct_supplier(yale_snps);
struct_supplier(yale_focal);
struct_supplier(yale_nova);
struct_supplier(b141_goodix);
struct_supplier(tui_for085_goodix);

thp_afe_api* g_afe_api_type[] = {
    &thp_afe_api_hima_nova,
    &thp_afe_api_hima_snps,
    &thp_afe_api_hima_snps,
    &thp_afe_api_hima_himax,
    &thp_afe_api_goodix,
    &thp_afe_api_goodix,
    &thp_afe_api_goodix,
    &thp_afe_api_goodix,
    &thp_afe_api_tui_for085_goodix,
    &thp_afe_api_goodix,
    &thp_afe_api_goodix,
    &thp_afe_api_solomon,
    &thp_afe_api_yale_snps,
    &thp_afe_api_yale_snps,
    &thp_afe_api_yale_snps,
    &thp_afe_api_yale_snps,
    &thp_afe_api_yale_focal,
    &thp_afe_api_yale_nova,
    &thp_afe_api_yale_nova,
    &thp_afe_api_yale_nova,
    &thp_afe_api_yale_focal,
    &thp_afe_api_yale_snps,
    &thp_afe_api_yale_snps,
    &thp_afe_api_yale_snps,
    &thp_afe_api_b141_goodix,
    NULL
};

char* g_projectid_text[] = {
    "HIMA651000",          // hima novatek lg
    "HIMA620800",          // hima synaptics jdi
    "HIMA621600",          // hima synaptics sharp
    "HIMA661300",          // hima himax boe
    "P085780900",          // SDC
    "P085780910",          // SDC TRX mapping
    "P085780920",          // no pressure
    "P085780930",          // replace cg
    "P085932900",          // Visionox Goodix_9896
    "P086781300",          // sensoralps
    "P086781310",          // sensorDW
    "P086811000",          // solomon
    "B121691000",
    "B121691100",
    "B121691010",
    "B121691110",
    "B121681400",
    "B121771400",
    "B121771100",          // yale nova + tm
    "B121771300",          // yale nova + boe
    "B121681000",          // yale focal +lg
    "B121691020",          // yale syna + lg
    "B121691120",          // yale syna + tm
    "B121691130",          // yale syna + tm 12Z
    "B141780900",          // seattle goodix + samsung
    "N/A"                  // NA AFE THP
};
