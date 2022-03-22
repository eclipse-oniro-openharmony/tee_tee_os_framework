set(TARGET_IS_TA y)
set(TARGET_IS_EXT_LIB y)
include(apps_common)

list(APPEND TEE_C_FLAGS
    -I${PREBUILD_LIBC_INC}
    -I${PREBUILD_LIBC_INC}/arch/generic
    -I${PREBUILD_LIBC_INC}/arch/${ARCH}
    -I${PREBUILD_HEADER}/gen/arch/${ARCH}
    -I${PREBUILD_LIBC_INC}/hm
    -I${PREBUILD_LIBC_INC}/arch/${ARCH}/bits
)

list(APPEND TEE_C_FLAGS
    -Wall
    -Wextra
    -fPIC
    -fdata-sections
    -ffunction-sections
    -nostdinc
    -nodefaultlibs
    -fno-omit-frame-pointer
    -fstack-protector-strong
    -fno-short-enums
    -DARM_PAE=1
    -include${PREBUILD_DIR}/headers/autoconf.h
)
