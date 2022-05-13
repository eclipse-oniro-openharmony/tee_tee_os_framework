vendor_libs += libvendor_shared libvendor_static

ifeq ($(CONFIG_TA_64BIT), true)
    product_apps += $(OUTPUTDIR)/aarch64/obj/aarch64/libvendor_shared/libvendor_shared.so
    check-a64-syms-y += $(OUTPUTDIR)/aarch64/obj/aarch64/libvendor_shared/libvendor_shared.so
endif

ifeq ($(CONFIG_TA_32BIT), true)
    product_apps += $(OUTPUTDIR)/arm/obj/arm/libvendor_shared/libvendor_shared_a32.so
    check-syms-y += $(OUTPUTDIR)/arm/obj/arm/libvendor_shared/libvendor_shared_a32.so
endif