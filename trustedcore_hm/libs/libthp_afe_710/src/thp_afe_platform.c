/*
* Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
* Description: common interface file
* Author: l00492120 & c00414356
* Create: 2017-01-20
* Notes: this file's api is for all TP modules platform wrapper interface
*/
#include "self_adapt_supplier.h"

#define afe_tui_fun_wrapper(key) key##_hp_nova
#include "thp_afe_supplier.h"
#undef afe_tui_fun_wrapper
#define afe_tui_fun_wrapper(key) key##_hp_td4320
#include "thp_afe_supplier.h"
#undef afe_tui_fun_wrapper
#define afe_tui_fun_wrapper(key) key##_hp_td4330
#include "thp_afe_supplier.h"

struct_supplier(hp_nova);
struct_supplier(hp_td4320);
struct_supplier(hp_td4330);

thp_afe_api* g_afe_api_type[] = {
    &thp_afe_api_hp_nova,
    &thp_afe_api_hp_nova,
    &thp_afe_api_hp_nova,
    &thp_afe_api_hp_td4320,
    &thp_afe_api_hp_td4320,
    &thp_afe_api_hp_td4320,
    &thp_afe_api_hp_nova,
    &thp_afe_api_hp_nova,
    &thp_afe_api_hp_nova,
    &thp_afe_api_hp_td4320,
    &thp_afe_api_hp_td4320,
    &thp_afe_api_hp_td4320,
    &thp_afe_api_hp_td4330,
    &thp_afe_api_hp_td4330,
    NULL
};

char* g_projectid_text[] = {
    "HARY771300",          // HARRY novatek BOE
    "HARY771100",          // HARRY novatek TM
    "HARY771700",          // HARRY novatek AUO
    "HARY691300",          // HARRY syps BOE
    "HARY691100",          // HARRY syps TM
    "HARY690300",          // HARRY syps MUTTO
    "POTR771300",          // POTTER novatek BOE
    "POTR771100",          // POTTER novatek TM
    "POTR771700",          // POTTER novatek AUO
    "POTR691300",          // POTTER syps BOE
    "POTR691100",          // POTTER syps TM
    "POTR690300",          // POTTER syps MUTTO
    "HARY861100",          // HARRY TD4330 TM
    "POTR861300",          // POTTER TD4330 BOE
    "N/A"                  // NA AFE THP
};
