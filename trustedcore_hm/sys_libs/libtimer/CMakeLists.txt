add_custom_target(libtimer_headers
    COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_CURRENT_SOURCE_DIR}/include ${HDR_L_DIR}
    VERBATIM)

include(apps_lib_common)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)

list(APPEND TEE_C_FLAGS
    -fno-builtin
)

list(APPEND TEE_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeconfig/include/TEE_ext
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeconfig/include/kernel
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeconfig/include
    ${PROJECT_SOURCE_DIR}/drivers/platdrv/include
    ${PROJECT_SOURCE_DIR}/drivers/drv_timer/src
    ${PROJECT_SOURCE_DIR}/platform/${PLATFORM_NAME}/${PRODUCT_NAME}/${CHIP_NAME}/timer/include
    ${PROJECT_SOURCE_DIR}/drivers/drv_timer/platform/${PLATFORM_NAME}/include
    ${PREBUILD_DIR}/headers/sys/timemgr
    ${PREBUILD_DIR}/headers/include/uapi
)

if ("${chip_type}" STREQUAL "es")
    list(APPEND TEE_INCLUDE_PATH
        ${PROJECT_SOURCE_DIR}/../../../../hisi/ap/platform/${${TARGET_BOARD_PLATFORM}_es}
    )
else()
    if ("${chip_type}" STREQUAL "cs2")
        list(APPEND TEE_INCLUDE_PATH
            ${PROJECT_SOURCE_DIR}/../../../../hisi/ap/platform/${${TARGET_BOARD_PLATFORM}_cs2}
        )
    else()
        list(APPEND TEE_INCLUDE_PATH
            ${PROJECT_SOURCE_DIR}/../../../../hisi/ap/platform/${TARGET_BOARD_PLATFORM}
        )
    endif()
endif()

if ("${ARCH}" STREQUAL "aarch64")
    list(APPEND TEE_INCLUDE_PATH
        ${PROJECT_SOURCE_DIR}/sys_libs/libtimer/include/aarch64
    )
else()
    list(APPEND TEE_INCLUDE_PATH
        ${PROJECT_SOURCE_DIR}/sys_libs/libtimer/include/arm
    )
endif()

list(APPEND LIB_TIMER_C_SOURCES
    src/sleep.c
    src/timer.c
    src/localtime.c
    src/nanosleep.c
    src/localtime_r.c
    src/tee_time_api.c
    src/timer_export.c
    src/timer_event_api.c
)

if ("${CONFIG_LIB_TIMEMGR}" STREQUAL "y")
    list(APPEND LIB_TIMER_C_SOURCES
        src/classic_timer_api.c
    )
endif()


tee_add_library(timer STATIC
    SOURCES
    ${LIB_TIMER_C_SOURCES}

    COMPILE_TOOL
    clang

    COMPILER_FLAGS
    ${TEE_C_FLAGS}

    COMPILER_DEFINITIONS
    ${TEE_C_DEFINITIONS}

    PRIVATE_INCLUDES
    ${TEE_INCLUDE_PATH}

    NO_INSTALL
)
