if ("${CONFIG_TUI_32BIT}" STREQUAL "true")
    list(APPEND PRODUCT_RELEASE_32 tui.elf libtui_internal_shared_a32.so)
    list(APPEND PRODUCT_APPS_32 tui.elf)
endif()
