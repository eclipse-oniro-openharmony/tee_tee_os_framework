list(APPEND TEE_C_SOURCES
    ${PROJECT_SOURCE_DIR}/vendor/huanglong/libdevchip_api/otp/tee_otp.c
    ${PROJECT_SOURCE_DIR}/vendor/huanglong/libdevchip_api/otp/tee_otp_func.c
    ${PROJECT_SOURCE_DIR}/vendor/huanglong/libdevchip_api/otp/tee_otp_syscall.c
    ${PROJECT_SOURCE_DIR}/vendor/huanglong/libdevchip_api/otp/otp_data_hi3796cv300.c
)

list(APPEND TEE_C_FLAGS
    -fstack-protector-all
)

if ("${CFG_ADVCA_NAGRA}" STREQUAL "y")
    list(APPEND TEE_C_SOURCES
        ${PROJECT_SOURCE_DIR}/vendor/huanglong/libdevchip_api/otp/otp_data_hi3796cv300.c
    )
endif()