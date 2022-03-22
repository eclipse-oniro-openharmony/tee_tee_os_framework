# for include autoconf.h
list(APPEND TEE_INCLUDE_PATH ${PREBUILD_HEADER})

list(APPEND SDK_INCLUDE_PATH_COMMON
    ${PREBUILD_SDK}/teeapi/common
    ${PREBUILD_SDK}/gpapi/common
)

list(APPEND KERNEL_INCLUDE_PATH_COMMON
    ${PREBUILD_KERNEL}
    ${PREBUILD_KERNEL}/uapi
    ${PREBUILD_KERNEL}/arch/arm/uapi
    ${PREBUILD_KERNEL}
)

list(APPEND INNER_SDK_INCLUDE_PATH_COMMON
    ${HDR_L_DIR}
    ${PREBUILD_INNER_SDK}/teeapi/common
    ${PREBUILD_INNER_SDK}/legacy/
    ${PREBUILD_INNER_SDK}/legacy/uapi
    ${PREBUILD_INNER_SDK}/hmapi
)

list(APPEND DDK_INCLUDE_PATH_COMMON
    ${PREBUILD_DDK}/hmapi/
    ${PREBUILD_DDK}/legacy/uapi
    ${PREBUILD_DDK}/legacy/
)

list(APPEND SYS_INCLUDE_PATH
    ${PREBUILD_SYS}/hmapi
    ${PREBUILD_SYS}/teeapi
    ${PREBUILD_SYS}/legacy
    ${PREBUILD_SYS}/legacy/uapi
)
