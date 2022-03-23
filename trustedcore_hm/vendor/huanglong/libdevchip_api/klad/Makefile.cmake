list(APPEND TEE_C_SOURCES
    ${PROJECT_SOURCE_DIR}/vendor/huanglong/libdevchip_api/klad/hi_tee_klad.c
    ${PROJECT_SOURCE_DIR}/vendor/huanglong/libdevchip_api/klad/tee_klad.c
    ${PROJECT_SOURCE_DIR}/vendor/huanglong/libdevchip_api/klad/tee_klad_msg_queue.c
    ${PROJECT_SOURCE_DIR}/vendor/huanglong/libdevchip_api/klad/tee_klad_utils.c
    ${PROJECT_SOURCE_DIR}/vendor/huanglong/libdevchip_api/klad/tee_klad_func.c
    ${PROJECT_SOURCE_DIR}/vendor/huanglong/libdevchip_api/klad/tee_klad_mgmt.c
    ${PROJECT_SOURCE_DIR}/vendor/huanglong/libdevchip_api/klad/tee_klad_bitmap.c
    ${PROJECT_SOURCE_DIR}/vendor/huanglong/libdevchip_api/klad/tee_klad_syscall.c
)

if ("${CFG_ADVCA_NAGRA}" STREQUAL "y")
list(APPEND TEE_C_SOURCES
    ${PROJECT_SOURCE_DIR}/vendor/huanglong/libdevchip_api/klad/nagra/hi_tee_cert.c
    ${PROJECT_SOURCE_DIR}/vendor/huanglong/libdevchip_api/klad/nagra/tee_cert.c
)
list(APPEND TEE_C_FLAGS
    -DHI_TEE_KLAD_CERT
    -fstack-protector-all
)
list(APPEND TEE_INCLUDE_PATH
    ${PROJECT_SOURCE_DIR}/vendor/huanglong/libdevchip_api/klad/nagra/
)
endif()