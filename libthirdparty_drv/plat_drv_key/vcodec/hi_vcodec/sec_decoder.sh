#!/bin/bash
# Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
# Description: sec_decoder
set -e
sec_decoder_name=""

if [ -z "$1" ];then
echo "please input the product name, e.g. hi3660, kirin970 and so on"
elif [ -z "$2" ];then
echo "please input chip type for parameter 2, e.g. es, cs"
else

typeset -u chip_type_name
chip_type_name="$2"
plat_form_name="$1"

if [ "$1" = "kirin710" ];then
plat_form_name="hi6260"
elif [ "$1" = "kirin980" ];then
plat_form_name="hi3680"
elif [ "$1" = "kirin970" ];then
plat_form_name="hi3670"
fi

if [ "$1" = "kirin710" ] || [ "$1" = "kirin970" ];
then
sec_decoder_name=$plat_form_name/libsec_decoder.a
else
sec_decoder_name=$plat_form_name/$chip_type_name/libsec_decoder.a
fi

if [ -f "$sec_decoder_name" ]; then
rm $sec_decoder_name
fi

sec_decoder_name=../../../../../../../../../../out/target/product/$1/obj/STATIC_LIBRARIES/libsec_decoder_intermediates/libsec_decoder.a
if [ -f "$sec_decoder_name" ]; then
rm $sec_decoder_name
fi
source ../../../../../../../../../../build/envsetup.sh

export HM_OPEN=true
mm -j chip_type=$2

if [ "$1" = "kirin710" ] || [ "$1" = "kirin970" ];then
cp $sec_decoder_name ./$plat_form_name/ -fv
else
cp $sec_decoder_name ./$plat_form_name/$chip_type_name/ -fv
fi
fi