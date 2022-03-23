list(APPEND PLATDRV_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/common
)
list(APPEND TEE_C_SOURCES
    platform/common/gatekeeper/key_factor.c
)
