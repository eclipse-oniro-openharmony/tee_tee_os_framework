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
    ${PREBUILD_DIR}/headers/sys/timemgr
)

if ("${ARCH}" STREQUAL "aarch64")
    list(APPEND TEE_INCLUDE_PATH
        ${PROJECT_SOURCE_DIR}/sys_libs/libtimer/include/aarch64
    )
else()
    list(APPEND TEE_INCLUDE_PATH
        ${PROJECT_SOURCE_DIR}/sys_libs/libtimer/include/arm
    )
endif()

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

set(LIB_TIMER_C_SOURCES
    ${LIB_TIMER_C_SOURCES}
    src/tee_gp_time_api.c
    src/tee_time_event.c
    src/tee_time_sleep.c
    src/tee_time_sys.c
    src/timer_adapt/tee_generic_timer_adapt.c
)

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
