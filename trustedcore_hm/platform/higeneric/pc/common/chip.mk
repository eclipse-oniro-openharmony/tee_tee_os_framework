# platform compile rules
# Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.

flags += -DTEE_SUPPORT_ATTESTATION_TA
flags += -DTEE_SUPPORT_TZMP2
flags += -DTEE_SUPPORT_HIVCODEC

ifeq ($(WITH_ENG_VERSION),true)
flags += -DVCODEC_ENG_VERSION
asflags += -DVCODEC_ENG_VERSION
else
flags := $(filter-out -DVCODEC_ENG_VERSION,$(flags))
asflags := $(filter-out -DVCODEC_ENG_VERSION,$(asflags))
endif

export WITH_MODEM := false
