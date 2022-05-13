# Copyright (c) Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
# compile TEE_C_FLAGS for libfuzzer
set(LIBFUZZER_LIBS_PATH $(PREBUILD_LIBS)/aarch64/)

if(NOT DEFINED ENV{CONFIG_TOOLCHAIN_LLVM_BASEVER})
    message(STATUS "set LLVM_TOOLCHAIN_BASEVER=8.0.1")
    set(LLVM_TOOLCHAIN_BASEVER 8.0.1)
else()
    set(LLVM_TOOLCHAIN_BASEVER $ENV{CONFIG_TOOLCHAIN_LLVM_BASEVER})
    message(STATUS "set LLVM_TOOLCHAIN_BASEVER=${LLVM_TOOLCHAIN_BASEVER}")
endif()

if(("${ENABLE_LIBFUZZER}" STREQUAL "y") OR ("${ENABLE_PROFILE}" STREQUAL "y"))
    set(UBSAN_C_LIB ${LIBFUZZER_LIBS_PATH}/libclang_rt.ubsan_standalone-aarch64.a)
    set(UBSAN_C_LIB_SYM ${LIBFUZZER_LIBS_PATH}/libclang_rt.ubsan_standalone-aarch64.a.syms)
    set(LIBFUZZER_PATH ${LIBFUZZER_LIBS_PATH}/libclang_rt.fuzzer_no_main-aarch64.a)
    set(BUILTIN_PATH ${LIBFUZZER_LIBS_PATH}/libclang_rt.builtins-aarch64.a)
    set(PROFILE_PATH ${LIBFUZZER_LIBS_PATH}/libclang_rt.profile-aarch64.a)
    set(LIBFUZZER ${LIBFUZZER_PATH} ${BUILTIN_PATH})
    if("${LLVM_TOOLCHAIN_BASEVER}" STREQUAL "8.0.1")
        set(UBSAN --dynamic-list=${UBSAN_C_LIB_SYM} -whole-archive ${UBSAN_C_LIB} -no-whole-archive)
        set(PROFILE -whole-archive ${PROFILE_PATH} -no-whole-archive)
    else()
        set(UBSAN --dynamic-list=${UBSAN_C_LIB_SYM} --whole-archive ${UBSAN_C_LIB} --no-whole-archive)
        set(PROFILE --whole-archive ${PROFILE_PATH} --no-whole-archive)
    endif()
    list(REMOVE_ITEM TEE_C_FLAGS
        "-Werror"
        "-Oz"
        "-flto"
        "-fsanitize=cfi"
        )
    list(APPEND TEE_C_FLAGS
        -femulated-tls
        )
endif()
if(("${ENABLE_LIBFUZZER}" STREQUAL "y") OR ("${ENABLE_PROFILE}" STREQUAL "y"))
    if("${ENABLE_LIBFUZZER}" STREQUAL "y")
        list(APPEND TEE_C_FLAGS
            -fsanitize=fuzzer
            -D__FUZZER__
        )
    set(TA_LDFLAGS ${TA_LDFLAGS} ${LIBFUZZER} ${UBSAN})
    endif()
    if("${ENABLE_PROFILE}" STREQUAL "y")
        list(APPEND TEE_C_FLAGS
            -fprofile-instr-generate
            -fcoverage-mapping
            -D__PROFILE__
            )
        set(TA_LDFLAGS ${TA_LDFLAGS} ${PROFILE})
    endif()
    if (NOT "${LLVM_TOOLCHAIN_BASEVER}" STREQUAL "8.0.1")
        set(NODEP --no-dependent-libraries)
        set(TA_LDFLAGS ${TA_LDFLAGS} ${NODEP})
    endif()
endif()
