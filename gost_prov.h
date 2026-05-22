#pragma once

/**********************************************************************
 *                 gost_prov.h - The provider itself                  *
 *                                                                    *
 *      Copyright (c) 2021 Richard Levitte <richard@levitte.org>      *
 *     This file is distributed under the same license as OpenSSL     *
 *                                                                    *
 *                Requires OpenSSL 3.0 for compilation                *
 **********************************************************************/

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/tls1.h>

/* OID constants for GOST algorithms */
#define OID_id_GostR3410_2001        "1.2.643.2.2.19"
#define OID_id_GostR3410_2001DH      "1.2.643.2.2.98"
#define OID_id_GostR3410_2012_256    "1.2.643.7.1.1.1.1"
#define OID_id_GostR3410_2012_512    "1.2.643.7.1.1.1.2"
#define OID_id_GostR3411_94_with_GostR3410_2001 "1.2.643.2.2.3"
#define OID_id_tc26_signwithdigest_gost3410_2012_256   "1.2.643.7.1.1.3.2"
#define OID_id_tc26_signwithdigest_gost3410_2012_512   "1.2.643.7.1.1.3.3"

/* Algorithm name constants for initializing OSSL_ALGORITHM */
#define ALG_NAME_GOST2001      \
    SN_id_GostR3410_2001 ":"   \
    LN_id_GostR3410_2001 ":"   \
    OID_id_GostR3410_2001

#define ALG_NAME_GOST2001DH    \
    SN_id_GostR3410_2001DH ":" \
    LN_id_GostR3410_2001DH ":" \
    OID_id_GostR3410_2001DH

#define ALG_NAME_GOST2012_256  \
    SN_id_GostR3410_2012_256 ":" \
    LN_id_GostR3410_2012_256 ":" \
    OID_id_GostR3410_2012_256

#define ALG_NAME_GOST2012_512  \
    SN_id_GostR3410_2012_512 ":" \
    LN_id_GostR3410_2012_512 ":" \
    OID_id_GostR3410_2012_512

#define GOST_SIGALG_2012_256A "gostr34102012_256a"
#define GOST_SIGALG_2012_256B "gostr34102012_256b"
#define GOST_SIGALG_2012_256C "gostr34102012_256c"
#define GOST_SIGALG_2012_256D "gostr34102012_256d"
#define GOST_SIGALG_2012_512A "gostr34102012_512a"
#define GOST_SIGALG_2012_512B "gostr34102012_512b"
#define GOST_SIGALG_2012_512C "gostr34102012_512c"

/* Utilities for checking and working with bit flags */
#define FLAGS_CONTAIN(flags, subset) (((flags)&(subset)) == (subset))
#define FLAGS_INTERSECT(flags, subset) (((flags)&(subset)) != 0)

typedef struct gost_tls_sigalg_desc_st {
    const char *iana_name;
    const char *signature_name;
    const char *keymgmt_name;
    const char *digest_name;
    const char *sigalg_oid;
    unsigned int code_point;
    unsigned int secbits;
    int key_type;
    int param_nid;
} GOST_TLS_SIGALG_DESC;

const GOST_TLS_SIGALG_DESC *gost_tls_sigalg_descs(size_t *count);
const GOST_TLS_SIGALG_DESC *gost_tls_sigalg_desc_by_name(const char *name);
const GOST_TLS_SIGALG_DESC *gost_tls_sigalg_desc_by_paramset(int key_type,
                                                             int param_nid);

OSSL_FUNC_keymgmt_dup_fn keymgmt_dup;
OSSL_FUNC_keymgmt_free_fn keymgmt_free;
OSSL_FUNC_keymgmt_match_fn keymgmt_match;

struct provider_ctx_st {
    OSSL_LIB_CTX *libctx;
    const OSSL_CORE_HANDLE *core_handle;
    struct proverr_functions_st *proverr_handle;
};
typedef struct provider_ctx_st PROV_CTX;

typedef struct gost_key_data_st
{
    EC_KEY *ec;
    int type;
    int param_nid;
} GOST_KEY_DATA;

int gost_get_max_keyexch_size(const GOST_KEY_DATA *);
int gost_get_max_signature_size(const GOST_KEY_DATA *);

extern const OSSL_ALGORITHM GOST_prov_ciphers[];
extern const OSSL_ALGORITHM GOST_prov_keymgmt[];
extern const OSSL_ALGORITHM GOST_prov_encoder[];
extern const OSSL_ALGORITHM GOST_prov_signature[];
extern const OSSL_ALGORITHM GOST_prov_decoder[];
extern const OSSL_ALGORITHM GOST_prov_keyexch[];
