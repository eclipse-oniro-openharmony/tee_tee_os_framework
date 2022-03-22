list(APPEND TEE_C_FLAGS
    -DTEE_SUPPORT_ATTESTATION_TA
    -DTEE_SUPPORT_TZMP2
    -DTEE_SUPPORT_HIVCODEC
)
if ("${CONFIG_DRIVER_DYN_MOD}" STREQUAL "true")
    list(APPEND TEE_C_FLAGS
        -DCONFIG_DRIVER_DYN_MOD
    )
endif()

if ("${CONFIG_CRYPTO_AGENT}" STREQUAL "true")
    list(APPEND TEE_C_FLAGS
        -DTEE_SUPPORT_CRYPTO_AGENT
    )
endif()

if ("${WITH_ENG_VERSION}" STREQUAL "true")
    list(APPEND TEE_C_FLAGS
        -DVCODEC_ENG_VERSION
    )
    list(APPEND TEE_AS_FLAGS
        -DVCODEC_ENG_VERSION
    )
else()
    list(REMOVE_ITEM TEE_C_FLAGS
        -DVCODEC_ENG_VERSION
    )
    list(REMOVE_ITEM TEE_AS_FLAGS
        -DVCODEC_ENG_VERSION
    )
endif()

if ("${product_type}" STREQUAL "armpc")
    set(WITH_MODEM false)
elseif ("${extra_modem}" STREQUAL "hi9500_udp")
    set(WITH_MODEM false)
elseif ("${CFG_HISI_MINI_AP}" STREQUAL "true")
    set(WITH_MODEM false)
else()
    set(WITH_MODEM true)
endif()
