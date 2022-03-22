# file list for gmssl

LOCAL_C_INCLUDES := include/ \
		    crypto/sms4/ \
		    crypto/sm2/ \
		    crypto/ec/ \
		    crypto/modes \
		    crypto/include \
		    include/usr/include \
		    crypto/lhash \
		    crypto/ecies

SM3_SRC := crypto/sm3/sm3.c \
	   crypto/sm3/sm3_hmac.c

SM4_SRC := crypto/sms4/sms4_cbc.c \
	   crypto/sms4/sms4_cfb.c \
	   crypto/sms4/sms4_common.c \
	   crypto/sms4/sms4_ctr.c \
	   crypto/sms4/sms4_ecb.c \
	   crypto/sms4/sms4_enc.c \
	   crypto/sms4/sms4_enc_nblks.c \
	   crypto/sms4/sms4_ofb.c \
	   crypto/sms4/sms4_setkey.c \
	   crypto/sms4/sms4_wrap.c

SM2_SRC := crypto/sm2/sm2_asn1.c \
	   crypto/sm2/sm2_enc.c \
	   crypto/sm2/sm2_err.c \
	   crypto/sm2/sm2_oct.c \
	   crypto/sm2/sm2_kmeth.c \
	   crypto/sm2/sm2_sign.c \
	   crypto/sm2/sm2_exch.c \
	   crypto/sm2/sm2_id.c

MODE_SRC := crypto/modes/cbc128.c \
	   crypto/modes/ctr128.c \
	   crypto/modes/cfb128.c \
	   crypto/modes/ofb128.c \
	   crypto/modes/ocb128.c \
	   crypto/modes/gcm128.c \
	   crypto/modes/wrap128.c \
	   crypto/modes/xts128.c \
	   crypto/modes/cts128.c  \
	   crypto/modes/ccm128.c

CRYPTO_LIB_SRC := \
	crypto/mem_clr.c \
	crypto/mem.c \
	crypto/cryptlib.c \
	crypto/o_str.c \
	crypto/mem_sec.c \
	crypto/mem_dbg.c \
	crypto/ex_data.c \
	crypto/init.c \
	crypto/threads_pthread.c

EVP_SRC := crypto/evp/m_sm3.c \
	   crypto/evp/names.c \
	   crypto/evp/digest.c \
	   crypto/evp/evp_lib.c \
	   crypto/evp/p_lib.c \
	   crypto/evp/pmeth_lib.c \
	   crypto/evp/c_allc.c \
	   crypto/evp/e_sms4_ccm.c \
	   crypto/evp/e_sms4_gcm.c \
	   crypto/evp/e_sms4.c \
	   crypto/evp/e_sms4_ocb.c \
	   crypto/evp/e_sms4_wrap.c \
	   crypto/evp/e_sms4_xts.c \
	   crypto/evp/evp_enc.c \
	   crypto/evp/evp_pbe.c \
	   crypto/evp/c_alld.c

EC_SRC := crypto/ec/ec_oct.c \
	  crypto/ec/ec_key.c \
	  crypto/ec/ecp_oct.c \
	  crypto/ec/ec_mult.c \
	  crypto/ec/ec2_mult.c \
	  crypto/ec/ec2_oct.c \
	  crypto/ec/ecdh_ossl.c \
	  crypto/ec/ec_cvt.c \
	  crypto/ec/ec_asn1.c \
	  crypto/ec/ecp_mont.c \
	  crypto/ec/ecp_smpl.c \
	  crypto/ec/ec2_smpl.c \
	  crypto/ec/ec_kmeth.c \
	  crypto/ec/ecdsa_ossl.c \
	  crypto/ec/ecdsa_sign.c \
	  crypto/ec/ecdsa_vrf.c \
	  crypto/ec/ec_curve.c \
	  crypto/ec/ec_lib.c

BN_SRC :=  crypto/bn/bn_lib.c \
	   crypto/bn/bn_add.c \
	   crypto/bn/bn_word.c \
	   crypto/bn/bn_shift.c \
	   crypto/bn/bn_print.c \
	   crypto/bn/bn_ctx.c \
	   crypto/bn/bn_intern.c \
	   crypto/bn/bn_mul.c \
	   crypto/bn/bn_mont.c \
	   crypto/bn/bn_mod.c \
	   crypto/bn/bn_sqr.c \
	   crypto/bn/bn_div.c \
	   crypto/bn/bn_rand.c \
	   crypto/bn/bn_kron.c \
	   crypto/bn/bn_gf2m.c \
	   crypto/bn/bn_exp.c \
	   crypto/bn/bn_recp.c \
	   crypto/bn/bn_sqrt.c \
	   crypto/bn/bn_gcd.c \
	   crypto/bn/bn_asm.c


ASN1_SRC := crypto/asn1/tasn_dec.c \
	        crypto/asn1/tasn_enc.c \
		crypto/asn1/tasn_typ.c \
		crypto/asn1/x_bignum.c \
		crypto/asn1/asn1_lib.c \
		crypto/asn1/tasn_fre.c \
		crypto/asn1/asn1_lib.c \
		crypto/asn1/a_dup.c \
		crypto/asn1/a_int.c \
		crypto/asn1/a_type.c \
		crypto/asn1/a_bitstr.c \
		crypto/asn1/tasn_utl.c \
		crypto/asn1/a_octet.c \
		crypto/asn1/a_object.c \
		crypto/asn1/tasn_new.c

KDF2_SRC := \
	crypto/kdf2/kdf_x9_63.c

LHASH_SRC := crypto/lhash/lhash.c

OBJDAT_SRC := crypto/objects/obj_dat.c \
	      crypto/objects/o_names.c \
	      crypto/objects/obj_xref.c \
	      crypto/objects/obj_lib.c


STACK_SRC := crypto/stack/stack.c

RANDLIB_SRC := crypto/rand/rand_lib.c \
	       crypto/rand/md_rand.c \
	       crypto/rand/rand_unix.c

ERR_SRC := crypto/err/err.c \
	   crypto/err/err_all.c \
	   crypto/err/err_prn.c

ECIES_SRC := crypto/ecies/ecies_lib.c
	     #crypto/ecies/ecies_asn1.c

ASYNC_SRC := \
	     crypto/async/arch/async_null.c \
	     crypto/async/arch/async_posix.c \
	     crypto/async/arch/async_win.c \
	     crypto/async/async_err.c \
	     crypto/async/async.c \
	     crypto/async/async_wait.c


BUF_SRC := crypto/buffer/buffer.c
	   #crypto/buffer/buf_err.c

LOCAL_SRC_FILES := \
	$(SM2_SRC) \
	$(EVP_SRC) \
	$(OBJDAT_SRC) \
	$(ASN1_SRC) \
	$(LHASH_SRC) \
	$(BN_SRC) \
	$(RANDLIB_SRC) \
	$(EC_SRC) \
	$(BUF_SRC) \
	$(ERR_SRC) \
	$(STACK_SRC) \
	$(KDF2_SRC) \
	$(ECIES_SRC) \
	$(CRYPTO_LIB_SRC) \
	$(SM4_SRC) \
	$(SM3_SRC) \
	$(MODE_SRC)
