# Copyright (c) Huawei Technologies Co., Ltd. 2018-2021. All rights reserved.

# config for libfuzzer

#set path of elfs used by libfuzzer
ifeq ($(LIBFUZZER_LIBS_PATH),)
	LIBFUZZER_LIBS_PATH := $(PREBUILD_LIBS)/aarch64/
endif
ifeq ($(CONFIG_TOOLCHAIN_LLVM_BASEVER),)
	LLVM_TOOLCHAIN_BASEVER := 8.0.1
else
	LLVM_TOOLCHAIN_BASEVER := ${CONFIG_TOOLCHAIN_LLVM_BASEVER}
endif

USESANITIZERS := n

ifeq ($(ENABLE_LIBFUZZER), y)
    USESANITIZERS := y
endif
ifeq ($(ENABLE_PROFILE), y)
    USESANITIZERS := y
endif

ifeq ($(USESANITIZERS), y)
    COMPILERT_PATH := $(LIBFUZZER_LIBS_PATH)/
    UBSAN_C_LIB:= $(COMPILERT_PATH)/libclang_rt.ubsan_standalone-aarch64.a
    UBSAN_C_LIB_SYM := $(COMPILERT_PATH)/libclang_rt.ubsan_standalone-aarch64.a.syms
    LIBFUZZER_PATH := $(COMPILERT_PATH)/libclang_rt.fuzzer_no_main-aarch64.a
    BUILTIN_PATH := $(COMPILERT_PATH)/libclang_rt.builtins-aarch64.a
    PROFILE_PATH := $(COMPILERT_PATH)/libclang_rt.profile-aarch64.a
    LIBFUZZER := $(LIBFUZZER_PATH) $(BUILTIN_PATH)
    flags:= $(filter-out -Oz, $(flags))
    flags:= $(filter-out -flto, $(flags))
    flags:= $(filter-out -fsanitize=cfi, $(flags))
    flags:= $(filter-out -Werror, $(flags))
    flags += -femulated-tls
	ifeq ($(LLVM_TOOLCHAIN_BASEVER), 8.0.1)
	    UBSAN := --dynamic-list=$(UBSAN_C_LIB_SYM) -whole-archive $(UBSAN_C_LIB) -no-whole-archive
		PROFILE := -whole-archive $(PROFILE_PATH) -no-whole-archive
	else
	    UBSAN := --dynamic-list=$(UBSAN_C_LIB_SYM) --whole-archive $(UBSAN_C_LIB) --no-whole-archive
        PROFILE := --whole-archive $(PROFILE_PATH) --no-whole-archive
	endif
endif
ifeq ($(ENABLE_LIBFUZZER), y)
    flags += -fsanitize=fuzzer
    flags += -D__FUZZER__
    TA_LDFLAGS += $(LIBFUZZER) $(UBSAN)
endif
ifeq ($(ENABLE_PROFILE), y)
    flags += -fprofile-instr-generate
    flags += -fcoverage-mapping
    flags += -D__PROFILE__
    TA_LDFLAGS += $(PROFILE)
endif
ifeq ($(USESANITIZERS), y)
	ifneq ($(LLVM_TOOLCHAIN_BASEVER), 8.0.1)
	TA_LDFLAGS += --no-dependent-libraries
    endif
endif
$(info $(flags) )
