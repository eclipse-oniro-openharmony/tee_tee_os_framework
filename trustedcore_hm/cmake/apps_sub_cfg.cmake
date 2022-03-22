if ("${TARGET_IS_SYS}" STREQUAL "y")
    list(APPEND TEE_INCLUDE_PATH
        ${SYS_INCLUDE_PATH}
        ${DDK_INCLUDE_PATH_COMMON}
        ${SDK_INCLUDE_PATH_COMMON}
        ${INNER_SDK_INCLUDE_PATH_COMMON}
        ${KERNEL_INCLUDE_PATH_COMMON}
        ${PREBUILD_INNER_SDK}/teeapi/tui
        ${PREBUILD_INNER_SDK}/teeapi
        ${PREBUILD_SDK}/gpapi
        ${PREBUILD_SDK}/teeapi
    )
endif()

if ("${TARGET_IS_DRV}" STREQUAL "y")
    list(APPEND TEE_INCLUDE_PATH
        ${SDK_INCLUDE_PATH_COMMON}
        ${INNER_SDK_INCLUDE_PATH_COMMON}
        ${DDK_INCLUDE_PATH_COMMON}
        ${PREBUILD_DDK}
        ${KERNEL_INCLUDE_PATH_COMMON}
        ${PREBUILD_INNER_SDK}/teeapi
        ${PREBUILD_SDK}/gpapi
    )
endif()

if ("${TARGET_IS_TA}" STREQUAL "y")
    list(APPEND TEE_INCLUDE_PATH
        ${SDK_INCLUDE_PATH_COMMON}
        ${INNER_SDK_INCLUDE_PATH_COMMON}
        ${KERNEL_INCLUDE_PATH_COMMON}
        ${PREBUILD_INNER_SDK}/internal
        ${PREBUILD_INNER_SDK}/teeapi/tui
        ${PREBUILD_INNER_SDK}/teeapi
        ${PREBUILD_INNER_SDK}/gpapi
        ${PREBUILD_SDK}/teeapi
        ${PREBUILD_SDK}/gpapi
    )
endif()
