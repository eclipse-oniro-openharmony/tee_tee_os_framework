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
#define afe_tui_fun_wrapper(key) key##_emily_snps
#include "thp_afe_supplier.h"

struct_supplier(jdi);
struct_supplier(nova);
struct_supplier(emily_snps);

thp_afe_api* g_afe_api_type[] = {
    &thp_afe_api_jdi,
    &thp_afe_api_nova,
    &thp_afe_api_nova,
    &thp_afe_api_jdi,
    &thp_afe_api_emily_snps,
    &thp_afe_api_emily_snps,
    &thp_afe_api_nova,
    NULL
};

char* g_projectid_text[] = {
    "ALPS470800",   /* ALPS AFE THP*/
    "ALPS491600",   /* ALPS AFE THP*/
    "ALPS491000",   /* ALPS AFE THP*/
    "VCTO320800",   /* VTR AFE THP*/
    "EMLY621600",   /* emily syps sharp */
    "EMLY620800",   /* emily syps jdi */
    "EMLY651000",   /* emily novatek lg */
    "N/A"           /* NA AFE THP */
};
