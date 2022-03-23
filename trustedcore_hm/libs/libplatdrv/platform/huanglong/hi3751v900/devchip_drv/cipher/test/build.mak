SRC_DIR := $(SDK_DIR)/../test/cipher/tee/drv
DST_DIR := $(CIPHER_DIR)/test

$(shell test -f $(DST_DIR)/test_crys_aes.c          || ln -s $(SRC_DIR)/test_crys_aes.c $(DST_DIR)/)
$(shell test -f $(DST_DIR)/test_crys_kg.c           || ln -s $(SRC_DIR)/test_crys_kg.c $(DST_DIR)/)
$(shell test -f $(DST_DIR)/test_crys_prim.c         || ln -s $(SRC_DIR)/test_crys_prim.c $(DST_DIR)/)
$(shell test -f $(DST_DIR)/test_crys_rsa.c          || ln -s $(SRC_DIR)/test_crys_rsa.c $(DST_DIR)/)
$(shell test -f $(DST_DIR)/test_crys_hash.c         || ln -s $(SRC_DIR)/test_crys_hash.c $(DST_DIR)/)
$(shell test -f $(DST_DIR)/test_crys_ecdsa.c        || ln -s $(SRC_DIR)/test_crys_ecdsa.c $(DST_DIR)/)
$(shell test -f $(DST_DIR)/test_crys_ecpki_build.c  || ln -s $(SRC_DIR)/test_crys_ecpki_build.c $(DST_DIR)/)
$(shell test -f $(DST_DIR)/test_crys_hmac.c         || ln -s $(SRC_DIR)/test_crys_hmac.c $(DST_DIR)/)
$(shell test -f $(DST_DIR)/test_cts.c               || ln -s $(SRC_DIR)/test_cts.c $(DST_DIR)/)
$(shell test -f $(DST_DIR)/test_cenc.c              || ln -s $(SRC_DIR)/test_cenc.c $(DST_DIR)/)
$(shell test -f $(DST_DIR)/test_main.c              || ln -s $(SRC_DIR)/test_main.c $(DST_DIR)/)
$(shell test -f $(DST_DIR)/test_main.h]             || ln -s $(SRC_DIR)/test_main.h $(DST_DIR)/)

CFLAGS += -I$(CIPHER_DIR)/test
CIPHER_OBJS += test/test_crys_aes.o  \
               test/test_crys_kg.o  \
               test/test_crys_prim.o  \
               test/test_crys_rsa.o  \
               test/test_crys_hash.o  \
               test/test_crys_ecdsa.o  \
               test/test_crys_ecpki_build.o \
               test/test_crys_hmac.o  \
               test/test_cts.o  \
               test/test_cenc.o  \
               test/test_main.o