list(APPEND PRODUCT_RELEASE_64
    vendor_shared
    vendor_static
)
list(APPEND PRODUCT_RELEASE_32
    vendor_shared
    vendor_static
)

if ("${CONFIG_TA_64BIT}" STREQUAL "true")
    list(APPEND PRODUCT_APPS_64
        vendor_shared
    )
    list(APPEND CHECK_SYMS
        libvendor_shared.so
    )
endif()
if ("${CONFIG_TA_32BIT}" STREQUAL "true")
    list(APPEND PRODUCT_APPS_32
        vendor_shared
    )
    list(APPEND CHECK_SYMS
        libvendor_shared.so
    )
endif()
