list(APPEND TEE_C_FLAGS
    -DTEE_SUPPORT_ATTESTATION_TA
    -DTEE_SUPPORT_HIVCODEC
    -DTEE_SUPPORT_TZMP2
)
if ("${WITH_ENG_VERSION}" STREQUAL "true")
    list(APPEND TEE_C_FLAGS
        -DVCODEC_ENG_VERSION
    )
endif()

# for singleAP
ifeq ("${CFG_HISI_MINI_AP}" STREQUAL "true")
    set(WITH_MODEM false)
else()
    set(WITH_MODEM true)
endif
