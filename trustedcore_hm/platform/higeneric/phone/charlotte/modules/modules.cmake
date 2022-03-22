if ("${CONFIG_TUI_32BIT}" STREQUAL "true")
    include(${PLATFORM_DIR}/${PLATFORM_NAME}/${PRODUCT_NAME}/${CHIP_NAME}/modules/tui.cmake)
endif()
