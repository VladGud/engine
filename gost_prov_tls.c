#include "gost_prov_tls.h"

#include <openssl/core_names.h>
#include <openssl/objects.h>
#include <openssl/params.h>
#include <openssl/prov_ssl.h>
#include <openssl/obj_mac.h>

#define OSSL_TLS_GROUP_ID_gc256A           0x0022
#define OSSL_TLS_GROUP_ID_gc256B           0x0023
#define OSSL_TLS_GROUP_ID_gc256C           0x0024
#define OSSL_TLS_GROUP_ID_gc256D           0x0025
#define OSSL_TLS_GROUP_ID_gc512A           0x0026
#define OSSL_TLS_GROUP_ID_gc512B           0x0027
#define OSSL_TLS_GROUP_ID_gc512C           0x0028
#define GOST_NELEM(x) (sizeof(x) / sizeof((x)[0]))

typedef struct tls_group_constants_st {
    unsigned int group_id;   /* Group ID */
    unsigned int secbits;    /* Bits of security */
    int mintls;              /* Minimum TLS version, -1 unsupported */
    int maxtls;              /* Maximum TLS version (or 0 for undefined) */
    int mindtls;             /* Minimum DTLS version, -1 unsupported */
    int maxdtls;             /* Maximum DTLS version (or 0 for undefined) */
} TLS_GROUP_CONSTANTS;

static const TLS_GROUP_CONSTANTS group_list[] = {
    { OSSL_TLS_GROUP_ID_gc256A, 128, TLS1_3_VERSION, 0, -1, -1 },
    { OSSL_TLS_GROUP_ID_gc256B, 128, TLS1_3_VERSION, 0, -1, -1 },
    { OSSL_TLS_GROUP_ID_gc256C, 128, TLS1_3_VERSION, 0, -1, -1 },
    { OSSL_TLS_GROUP_ID_gc256D, 128, TLS1_3_VERSION, 0, -1, -1 },
    { OSSL_TLS_GROUP_ID_gc512A, 256, TLS1_3_VERSION, 0, -1, -1 },
    { OSSL_TLS_GROUP_ID_gc512B, 256, TLS1_3_VERSION, 0, -1, -1 },
    { OSSL_TLS_GROUP_ID_gc512C, 256, TLS1_3_VERSION, 0, -1, -1 },
};

#define TLS_GROUP_ENTRY(group_name, name_internal, alg, idx) \
    { \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_NAME, \
                               group_name, sizeof(group_name)), \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_NAME_INTERNAL, \
                               name_internal, sizeof(name_internal)), \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_ALG, \
                               alg, sizeof(alg)), \
        OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_GROUP_ID, \
                        (unsigned int *)&group_list[idx].group_id), \
        OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_GROUP_SECURITY_BITS, \
                        (unsigned int *)&group_list[idx].secbits), \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MIN_TLS, \
                       (unsigned int *)&group_list[idx].mintls), \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MAX_TLS, \
                       (unsigned int *)&group_list[idx].maxtls), \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MIN_DTLS, \
                       (unsigned int *)&group_list[idx].mindtls), \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MAX_DTLS, \
                       (unsigned int *)&group_list[idx].maxdtls), \
        OSSL_PARAM_END \
    }

static const OSSL_PARAM param_group_list[][10] = {
    TLS_GROUP_ENTRY("GC256A", "TCA", GOST_SIGALG_2012_256A, 0),
    TLS_GROUP_ENTRY("GC256B", "TCB", GOST_SIGALG_2012_256B, 1),
    TLS_GROUP_ENTRY("GC256C", "TCC", GOST_SIGALG_2012_256C, 2),
    TLS_GROUP_ENTRY("GC256D", "TCD", GOST_SIGALG_2012_256D, 3),
    TLS_GROUP_ENTRY("GC512A", "A", GOST_SIGALG_2012_512A, 4),
    TLS_GROUP_ENTRY("GC512B", "B", GOST_SIGALG_2012_512B, 5),
    TLS_GROUP_ENTRY("GC512C", "C", GOST_SIGALG_2012_512C, 6),
};

int gost_prov_get_tls_group_capability(OSSL_CALLBACK *cb, void *arg)
{
    size_t i;

    for (i = 0; i < sizeof(param_group_list) / sizeof(param_group_list[0]); i++)
        if (!cb(param_group_list[i], arg))
            return 0;
    return 1;
}

#define TLS_SIGALG_gostr34102012_256a  0x0709
#define TLS_SIGALG_gostr34102012_256b  0x070A
#define TLS_SIGALG_gostr34102012_256c  0x070B
#define TLS_SIGALG_gostr34102012_256d  0x070C
#define TLS_SIGALG_gostr34102012_512a  0x070D
#define TLS_SIGALG_gostr34102012_512b  0x070E
#define TLS_SIGALG_gostr34102012_512c  0x070F

/*
 * Private OIDs for GOST TLS 1.3 paramset-specific sigalgs.
 * Sub-arc 1.2.643.7.1.1.3 (tc26 signwithdigest); .2 and .3 are taken
 * by the generic 256- and 512-bit variants.
 */
#define OID_gostr34102012_256a  "1.2.643.7.1.1.3.4"
#define OID_gostr34102012_256b  "1.2.643.7.1.1.3.5"
#define OID_gostr34102012_256c  "1.2.643.7.1.1.3.6"
#define OID_gostr34102012_256d  "1.2.643.7.1.1.3.7"
#define OID_gostr34102012_512a  "1.2.643.7.1.1.3.8"
#define OID_gostr34102012_512b  "1.2.643.7.1.1.3.9"
#define OID_gostr34102012_512c  "1.2.643.7.1.1.3.10"

static const GOST_TLS_SIGALG_DESC gost_tls_sigalg_map[] = {
    { GOST_SIGALG_2012_256A, GOST_SIGALG_2012_256A, GOST_SIGALG_2012_256A,
      SN_id_GostR3411_2012_256, OID_gostr34102012_256a,
      TLS_SIGALG_gostr34102012_256a, 128,
      NID_id_GostR3410_2012_256, NID_id_tc26_gost_3410_2012_256_paramSetA },
    { GOST_SIGALG_2012_256B, GOST_SIGALG_2012_256B, GOST_SIGALG_2012_256B,
      SN_id_GostR3411_2012_256, OID_gostr34102012_256b,
      TLS_SIGALG_gostr34102012_256b, 128,
      NID_id_GostR3410_2012_256, NID_id_tc26_gost_3410_2012_256_paramSetB },
    { GOST_SIGALG_2012_256C, GOST_SIGALG_2012_256C, GOST_SIGALG_2012_256C,
      SN_id_GostR3411_2012_256, OID_gostr34102012_256c,
      TLS_SIGALG_gostr34102012_256c, 128,
      NID_id_GostR3410_2012_256, NID_id_tc26_gost_3410_2012_256_paramSetC },
    { GOST_SIGALG_2012_256D, GOST_SIGALG_2012_256D, GOST_SIGALG_2012_256D,
      SN_id_GostR3411_2012_256, OID_gostr34102012_256d,
      TLS_SIGALG_gostr34102012_256d, 128,
      NID_id_GostR3410_2012_256, NID_id_tc26_gost_3410_2012_256_paramSetD },
    { GOST_SIGALG_2012_512A, GOST_SIGALG_2012_512A, GOST_SIGALG_2012_512A,
      SN_id_GostR3411_2012_512, OID_gostr34102012_512a,
      TLS_SIGALG_gostr34102012_512a, 256,
      NID_id_GostR3410_2012_512, NID_id_tc26_gost_3410_2012_512_paramSetA },
    { GOST_SIGALG_2012_512B, GOST_SIGALG_2012_512B, GOST_SIGALG_2012_512B,
      SN_id_GostR3411_2012_512, OID_gostr34102012_512b,
      TLS_SIGALG_gostr34102012_512b, 256,
      NID_id_GostR3410_2012_512, NID_id_tc26_gost_3410_2012_512_paramSetB },
    { GOST_SIGALG_2012_512C, GOST_SIGALG_2012_512C, GOST_SIGALG_2012_512C,
      SN_id_GostR3411_2012_512, OID_gostr34102012_512c,
      TLS_SIGALG_gostr34102012_512c, 256,
      NID_id_GostR3410_2012_512, NID_id_tc26_gost_3410_2012_512_paramSetC },
};

typedef struct tls_sigalg_constants_st {
    int mintls;              /* Minimum TLS version, -1 unsupported */
    int maxtls;              /* Maximum TLS version (or 0 for undefined) */
} TLS_SIGALG_CONSTANTS;

static const TLS_SIGALG_CONSTANTS gost_sigalg_constants[] = {
    { TLS1_3_VERSION, TLS1_3_VERSION },
    { TLS1_3_VERSION, TLS1_3_VERSION },
    { TLS1_3_VERSION, TLS1_3_VERSION },
    { TLS1_3_VERSION, TLS1_3_VERSION },
    { TLS1_3_VERSION, TLS1_3_VERSION },
    { TLS1_3_VERSION, TLS1_3_VERSION },
    { TLS1_3_VERSION, TLS1_3_VERSION },
};

#define TLS_SIGALG_ENTRY(idx) \
    { \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_SIGALG_IANA_NAME, \
                               (char *)gost_tls_sigalg_map[idx].iana_name, \
                               sizeof(gost_tls_sigalg_map[idx].iana_name)), \
        OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_SIGALG_CODE_POINT, \
                        (unsigned int *)&gost_tls_sigalg_map[idx].code_point), \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_SIGALG_NAME, \
                               (char *)gost_tls_sigalg_map[idx].signature_name, \
                               sizeof(gost_tls_sigalg_map[idx].signature_name)), \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_SIGALG_OID, \
                               (char *)gost_tls_sigalg_map[idx].sigalg_oid, \
                               0), \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_SIGALG_HASH_NAME, \
                               (char *)gost_tls_sigalg_map[idx].digest_name, \
                               sizeof(gost_tls_sigalg_map[idx].digest_name)), \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_SIGALG_KEYTYPE, \
                               (char *)gost_tls_sigalg_map[idx].keymgmt_name, \
                               0), \
        OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_SIGALG_SECURITY_BITS, \
                        (unsigned int *)&gost_tls_sigalg_map[idx].secbits), \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_SIGALG_MIN_TLS, \
                       (int *)&gost_sigalg_constants[idx].mintls), \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_SIGALG_MAX_TLS, \
                       (int *)&gost_sigalg_constants[idx].maxtls), \
        OSSL_PARAM_END \
    }

static const OSSL_PARAM param_sigalg_list[][10] = {
    TLS_SIGALG_ENTRY(0),
    TLS_SIGALG_ENTRY(1),
    TLS_SIGALG_ENTRY(2),
    TLS_SIGALG_ENTRY(3),
    TLS_SIGALG_ENTRY(4),
    TLS_SIGALG_ENTRY(5),
    TLS_SIGALG_ENTRY(6)
};

const GOST_TLS_SIGALG_DESC *gost_tls_sigalg_descs(size_t *count)
{
    if (count != NULL)
        *count = GOST_NELEM(gost_tls_sigalg_map);
    return gost_tls_sigalg_map;
}

const GOST_TLS_SIGALG_DESC *gost_tls_sigalg_desc_by_name(const char *name)
{
    size_t i;

    if (name == NULL)
        return NULL;

    for (i = 0; i < GOST_NELEM(gost_tls_sigalg_map); i++) {
        if (strcmp(name, gost_tls_sigalg_map[i].iana_name) == 0
            || strcmp(name, gost_tls_sigalg_map[i].signature_name) == 0
            || strcmp(name, gost_tls_sigalg_map[i].keymgmt_name) == 0)
            return &gost_tls_sigalg_map[i];
    }

    return NULL;
}

const GOST_TLS_SIGALG_DESC *gost_tls_sigalg_desc_by_paramset(int key_type,
                                                             int param_nid)
{
    size_t i;

    if (param_nid == NID_undef)
        return NULL;

    for (i = 0; i < GOST_NELEM(gost_tls_sigalg_map); i++) {
        if (gost_tls_sigalg_map[i].key_type == key_type
            && gost_tls_sigalg_map[i].param_nid == param_nid)
            return &gost_tls_sigalg_map[i];
    }

    return NULL;
}

int gost_prov_get_tls_sigalg_capability(OSSL_CALLBACK *cb, void *arg)
{
    size_t i;

    for (i = 0; i < sizeof(param_sigalg_list) / sizeof(param_sigalg_list[0]); i++)
        if (!cb(param_sigalg_list[i], arg))
            return 0;

    return 1;
}
