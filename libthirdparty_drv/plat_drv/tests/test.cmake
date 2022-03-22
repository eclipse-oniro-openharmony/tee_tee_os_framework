if ("${WITH_ENG_VERSION}" STREQUAL "true")
list(APPEND TEE_C_SOURCES
    platform/kirin/tests/test_driver.c
)
endif()