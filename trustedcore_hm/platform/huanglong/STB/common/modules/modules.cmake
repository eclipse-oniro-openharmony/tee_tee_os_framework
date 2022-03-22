if ("${CONFIG_SEC_FLASH}" STREQUAL "true")
    list(APPEND PRODUCT_RELEASE_64 sec_flash.elf)
    list(APPEND PRODUCT_RELEASE_32 sec_flash.elf)
    if ("${CONFIG_DRV_64BIT}" STREQUAL "true")
        list(APPEND PRODUCT_APPS_64
            sec_flash.elf
        )
    endif()
    if ("${CONFIG_DRV_64BIT}" STREQUAL "false")
        list(APPEND PRODUCT_APPS_32
            sec_flash.elf
        )
    endif()
endif()

if ("${CONFIG_SE_SERVICE_64BIT}" STREQUAL "true" OR "${CONFIG_SE_SERVICE_32BIT}" STREQUAL "true")
    list(APPEND PRODUCT_RELEASE_64 se_service.elf)
    list(APPEND PRODUCT_RELEASE_32 se_service.elf)
    if ("${CONFIG_SE_SERVICE_64BIT}" STREQUAL "true")
        list(APPEND PRODUCT_APPS_64
            se_service.elf
        )
    endif()
    if ("${CONFIG_SE_SERVICE_32BIT}" STREQUAL "true")
        list(APPEND PRODUCT_APPS_32
            se_service.elf
        )
    endif()
endif()

if ("${CONFIG_GATEKEEPER_64BIT}" STREQUAL "true" OR "${CONFIG_GATEKEEPER_32BIT}" STREQUAL "true")
    list(APPEND PRODUCT_RELEASE_64 gatekeeper.elf)
    list(APPEND PRODUCT_RELEASE_32 gatekeeper.elf)
    if ("${CONFIG_GATEKEEPER_64BIT}" STREQUAL "true")
        list(APPEND PRODUCT_APPS_64
            gatekeeper.elf
        )
    endif()
    if ("${CONFIG_GATEKEEPER_32BIT}" STREQUAL "true")
        list(APPEND PRODUCT_APPS_32
            gatekeeper.elf
        )
    endif()
endif()

if ("${CONFIG_KEYMASTER_64BIT}" STREQUAL "true" OR "${CONFIG_KEYMASTER_32BIT}" STREQUAL "true")
    list(APPEND PRODUCT_RELEASE_64 keymaster.elf)
    list(APPEND PRODUCT_RELEASE_32 keymaster.elf)
    if ("${CONFIG_KEYMASTER_64BIT}" STREQUAL "true")
        list(APPEND PRODUCT_APPS_64
            keymaster.elf
        )
    endif()
    if ("${CONFIG_KEYMASTER_32BIT}" STREQUAL "true")
        list(APPEND PRODUCT_APPS_32
            keymaster.elf
        )
    endif()
endif()

if ("${CONFIG_ANTIROOT}" STREQUAL "true")
    list(APPEND PRODUCT_RELEASE_64 antiroot.elf)
    list(APPEND PRODUCT_RELEASE_32 antiroot.elf)
    if ("${CONFIG_DRV_64BIT}" STREQUAL "true")
        list(APPEND PRODUCT_APPS_64
            antiroot.elf
        )
    endif()
    if ("${CONFIG_DRV_64BIT}" STREQUAL "false")
        list(APPEND PRODUCT_APPS_32
            antiroot.elf
        )
    endif()
endif()
