/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
 * Description: common interface file
 * Author: l00492120 & c00414356
 * Create: 2019-11-10
 * Notes: this file's api is for all TP modules platform wrapper interface
 */
#include "self_adapt_supplier.h"

#define afe_tui_fun_wrapper(key) key##_st
#include "thp_afe_supplier.h"
#undef afe_tui_fun_wrapper
#define afe_tui_fun_wrapper(key) key##_goodix
#include "thp_afe_supplier.h"
#undef afe_tui_fun_wrapper
#define afe_tui_fun_wrapper(key) key##_dp167_goodix
#include "thp_afe_supplier.h"


struct_supplier(st);
struct_supplier(goodix);
struct_supplier(dp167_goodix);

thp_afe_api *g_afe_api_type[] = {
    &thp_afe_api_st,
    &thp_afe_api_st,
    &thp_afe_api_st,
    &thp_afe_api_st,
    &thp_afe_api_st,
    &thp_afe_api_st,
    &thp_afe_api_dp167_goodix,
    &thp_afe_api_dp167_goodix,
    &thp_afe_api_goodix,
    &thp_afe_api_goodix,
    &thp_afe_api_goodix,
    &thp_afe_api_goodix,
    NULL
};

char *g_projectid_text[] = {
    "P1679R1300",          // Teton
    "P1679R1320",          // Teton sku3st newsensor
    "P1679R1330",          // Teton sku4st emitap
    "P1679R1340",          // Teton sku5st cof
    "P1679R1351",          // Teton sku7st ddic
    "P1679R0900",          // Teton sdc sku1 st
    "P1679X1301",          // Teton sku8 rd_goodix
    "P1679X1310",          // Teton sku9 nova_goodix
    "P085780900",          // SDC
    "P085780910",          // SDC TRX mapping
    "P085780920",          // no pressure
    "P085780930",          // replace cg
    "N/A"                  // NA AFE THP
};
