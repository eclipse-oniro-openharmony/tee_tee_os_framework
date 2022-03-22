list(APPEND TEE_C_SOURCES
    ${PROJECT_SOURCE_DIR}/vendor/huanglong/libdevchip_api/keyslot/tee_keyslot.c
)
list(APPEND TEE_C_FLAGS
    -fstack-protector-all
)
