/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "cf_mock.h"

using namespace std;
using namespace testing::ext;

using namespace CFMock;

#ifdef __cplusplus
extern "C" {
#endif

int __real_OPENSSL_sk_num(const OPENSSL_STACK *st);
void *__real_OPENSSL_sk_value(const OPENSSL_STACK *st, int i);
BIO *__real_BIO_new_mem_buf(const void *buf, int len);
CfResult __real_HcfX509CertificateCreate(const CfEncodingBlob *inStream, HcfX509Certificate **returnObj);
OPENSSL_STACK *__real_OPENSSL_sk_new_null(void);
int __real_i2d_X509(X509 *a, unsigned char **out);
int __real_X509_STORE_add_cert(X509_STORE *ctx, X509 *x);
X509_STORE_CTX *__real_X509_STORE_CTX_new(void);
X509_STORE *__real_X509_STORE_new(void);
int __real_X509_STORE_CTX_init(X509_STORE_CTX *ctx, X509_STORE *store, X509 *x509, STACK_OF(X509) * chain);
int __real_X509_verify_cert(X509_STORE_CTX *ctx);
int __real_i2d_PUBKEY(EVP_PKEY *a, unsigned char **pp);
void *__real_X509_get_ext_d2i(const X509 *x, int nid, int *crit, int *idx);
int __real_i2d_ASN1_OCTET_STRING(ASN1_OCTET_STRING *a, unsigned char **out);
int __real_i2d_AUTHORITY_KEYID(AUTHORITY_KEYID *a, unsigned char **out);
CfResult __real_DeepCopyDataToBlob(const unsigned char *data, uint32_t len, CfBlob *outBlob);
ASN1_TIME *__real_ASN1_TIME_new(void);
EVP_PKEY *__real_X509_get_pubkey(X509 *x);
ASN1_OBJECT *__real_OBJ_nid2obj(int n);
int __real_OBJ_obj2txt(char *buf, int buf_len, const ASN1_OBJECT *a, int no_name);
BIGNUM *__real_BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret);
const ASN1_INTEGER *__real_X509_get0_serialNumber(const X509 *x);
int __real_i2d_ASN1_INTEGER(ASN1_INTEGER *a, unsigned char **out);
int __real_ASN1_TIME_normalize(ASN1_TIME *s);
ASN1_TIME *__real_X509_getm_notBefore(const X509 *x);
ASN1_TIME *__real_X509_getm_notAfter(const X509 *x);
void __real_X509_ALGOR_get0(const ASN1_OBJECT **paobj, int *pptype, const void **ppval, const X509_ALGOR *algor);
ASN1_TYPE *__real_ASN1_TYPE_new(void);
int __real_ASN1_TYPE_set1(ASN1_TYPE *a, int type, const void *value);
int __real_i2d_ASN1_TYPE(ASN1_TYPE *a, unsigned char **out);
long __real_ASN1_INTEGER_get(const ASN1_INTEGER *a);
const unsigned char *__real_ASN1_STRING_get0_data(const ASN1_STRING *x);
int __real_i2d_GENERAL_NAME(GENERAL_NAME *a, unsigned char **out);
X509_EXTENSION *__real_X509_get_ext(const X509 *x, X509_EXTENSION *loc);
void *__real_X509V3_EXT_d2i(X509_EXTENSION *ext);
void *__real_GENERAL_NAME_get0_value(const GENERAL_NAME *a, int *ptype);
int __real_X509_verify(X509 *a, EVP_PKEY *r);
CfResult __real_DeepCopyBlobToBlob(const CfBlob *inBlob, CfBlob **outBlob);
char *__real_X509_NAME_oneline(const X509_NAME *a, char *buf, int size);
int __real_OPENSSL_sk_push(OPENSSL_STACK *st, const int data);
int __real_i2d_X509_REVOKED(X509_REVOKED *a, unsigned char **out);
int __real_i2d_X509_CRL(X509_CRL *a, unsigned char **out);
OPENSSL_STACK *__real_OPENSSL_sk_deep_copy(const OPENSSL_STACK *, OPENSSL_sk_copyfunc c, OPENSSL_sk_freefunc f);
int __real_OBJ_obj2nid(const ASN1_OBJECT *o);
X509 *__real_X509_dup(X509 *x509);
int __real_i2d_X509_EXTENSIONS(X509_EXTENSIONS *a, unsigned char **out);
int __real_X509_check_host(X509 *x, const char *chk, size_t chklen, unsigned int flags, char **peername);
OCSP_REQUEST *__real_OCSP_REQUEST_new(void);
X509_CRL *__real_X509_CRL_load_http(const char *url, BIO *bio, BIO *rbio, int timeout);
struct stack_st_OPENSSL_STRING *__real_X509_get1_ocsp(X509 *x);
int __real_OSSL_HTTP_parse_url(const char *url, int *pssl, char **puser, char **phost, char **pport, int *pport_num,
    char **ppath, char **pquery, char **pfrag);
int __real_X509_NAME_get0_der(X509_NAME *nm, const unsigned char **pder, size_t *pderlen);
const char *__real_OBJ_nid2sn(int n);
int __real_ASN1_STRING_length(const ASN1_STRING *x);
CfResult __real_DeepCopyDataToOut(const char *data, uint32_t len, CfBlob *out);
char *__real_CRYPTO_strdup(const char *str, const char *file, int line);
X509_NAME *__real_X509_NAME_new(void);
int __real_OBJ_txt2nid(const char *s);
int __real_X509_NAME_add_entry_by_NID(
    X509_NAME *name, int nid, int type, const unsigned char *bytes, int len, int loc, int set);
BIO *__real_BIO_new(const BIO_METHOD *type);
int __real_X509_print(BIO *bp, X509 *x);
long __real_BIO_ctrl(BIO *bp, int cmd, long larg, void *parg);
int __real_i2d_X509_bio(BIO *bp, X509 *x509);

#ifdef __cplusplus
}
#endif

static bool g_mockTagX509Openssl = false;

NiceMock<X509OpensslMock> &X509OpensslMock::GetInstance(void)
{
    static NiceMock<X509OpensslMock> gX509OpensslMock;
    return gX509OpensslMock;
}

void X509OpensslMock::SetMockFunDefaultBehaviorPartOne(void)
{
    ON_CALL(*this, X509_dup).WillByDefault([this](X509 *x509) { return __real_X509_dup(x509); });

    ON_CALL(*this, OBJ_obj2nid).WillByDefault([this](const ASN1_OBJECT *o) { return __real_OBJ_obj2nid(o); });

    ON_CALL(*this, OPENSSL_sk_deep_copy)
        .WillByDefault([this](const OPENSSL_STACK *st, OPENSSL_sk_copyfunc c, OPENSSL_sk_freefunc f) {
            return __real_OPENSSL_sk_deep_copy(st, c, f);
        });

    ON_CALL(*this, i2d_X509_CRL).WillByDefault([this](X509_CRL *a, unsigned char **out) {
        return __real_i2d_X509_CRL(a, out);
    });

    ON_CALL(*this, i2d_X509_REVOKED).WillByDefault([this](X509_REVOKED *a, unsigned char **out) {
        return __real_i2d_X509_REVOKED(a, out);
    });

    ON_CALL(*this, OPENSSL_sk_push).WillByDefault([this](OPENSSL_STACK *st, const int data) {
        return __real_OPENSSL_sk_push(st, data);
    });

    ON_CALL(*this, X509_NAME_oneline).WillByDefault([this](const X509_NAME *a, char *buf, int size) {
        return __real_X509_NAME_oneline(a, buf, size);
    });

    ON_CALL(*this, DeepCopyBlobToBlob).WillByDefault([this](const CfBlob *inBlob, CfBlob **outBlob) {
        return __real_DeepCopyBlobToBlob(inBlob, outBlob);
    });

    ON_CALL(*this, X509_verify).WillByDefault([this](X509 *a, EVP_PKEY *r) { return __real_X509_verify(a, r); });

    ON_CALL(*this, GENERAL_NAME_get0_value).WillByDefault([this](const GENERAL_NAME *a, int *ptype) {
        return __real_GENERAL_NAME_get0_value(a, ptype);
    });

    ON_CALL(*this, X509V3_EXT_d2i).WillByDefault([this](X509_EXTENSION *ext) { return __real_X509V3_EXT_d2i(ext); });

    ON_CALL(*this, X509_get_ext).WillByDefault([this](const X509 *x, X509_EXTENSION *loc) {
        return __real_X509_get_ext(x, loc);
    });

    ON_CALL(*this, i2d_GENERAL_NAME).WillByDefault([this](GENERAL_NAME *a, unsigned char **out) {
        return __real_i2d_GENERAL_NAME(a, out);
    });

    ON_CALL(*this, ASN1_STRING_get0_data).WillByDefault([this](const ASN1_STRING *x) {
        return __real_ASN1_STRING_get0_data(x);
    });

    ON_CALL(*this, ASN1_INTEGER_get).WillByDefault([this](const ASN1_INTEGER *a) {
        return __real_ASN1_INTEGER_get(a);
    });
}

void X509OpensslMock::SetMockFunDefaultBehaviorPartTwo(void)
{
    ON_CALL(*this, i2d_ASN1_TYPE).WillByDefault([this](ASN1_TYPE *a, unsigned char **out) {
        return __real_i2d_ASN1_TYPE(a, out);
    });

    ON_CALL(*this, ASN1_TYPE_set1).WillByDefault([this](ASN1_TYPE *a, int type, const void *value) {
        return __real_ASN1_TYPE_set1(a, type, value);
    });

    ON_CALL(*this, ASN1_TYPE_new).WillByDefault([this](void) { return __real_ASN1_TYPE_new(); });
    ON_CALL(*this, ASN1_TIME_normalize).WillByDefault([this](ASN1_TIME *s) { return __real_ASN1_TIME_normalize(s); });
    ON_CALL(*this, X509_getm_notBefore).WillByDefault([this](const X509 *x) { return __real_X509_getm_notBefore(x); });
    ON_CALL(*this, X509_getm_notAfter).WillByDefault([this](const X509 *x) { return __real_X509_getm_notAfter(x); });
    ON_CALL(*this, OPENSSL_sk_num).WillByDefault([this](const OPENSSL_STACK *st) { return __real_OPENSSL_sk_num(st); });

    ON_CALL(*this, BIO_new_mem_buf).WillByDefault([this](const void *buf, int len) {
        return __real_BIO_new_mem_buf(buf, len);
    });

    ON_CALL(*this, i2d_X509).WillByDefault([this](X509 *a, unsigned char **out) { return __real_i2d_X509(a, out); });

    ON_CALL(*this, X509_verify_cert).WillByDefault([this](X509_STORE_CTX *ctx) {
        return __real_X509_verify_cert(ctx);
    });

    ON_CALL(*this, HcfX509CertificateCreate)
        .WillByDefault([this](const CfEncodingBlob *inStream, HcfX509Certificate **returnObj) {
            return __real_HcfX509CertificateCreate(inStream, returnObj);
        });

    ON_CALL(*this, OPENSSL_sk_new_null).WillByDefault([this](void) { return __real_OPENSSL_sk_new_null(); });

    ON_CALL(*this, X509_STORE_CTX_new).WillByDefault([this](void) { return __real_X509_STORE_CTX_new(); });

    ON_CALL(*this, X509_STORE_new).WillByDefault([this](void) { return __real_X509_STORE_new(); });

    ON_CALL(*this, X509_STORE_CTX_init)
        .WillByDefault([this](X509_STORE_CTX *ctx, X509_STORE *store, X509 *x509, STACK_OF(X509) * chain) {
            return __real_X509_STORE_CTX_init(ctx, store, x509, chain);
        });

    ON_CALL(*this, X509_STORE_add_cert).WillByDefault([this](X509_STORE *ctx, X509 *x) {
        return __real_X509_STORE_add_cert(ctx, x);
    });

    ON_CALL(*this, OPENSSL_sk_value).WillByDefault([this](const OPENSSL_STACK *st, int i) {
        return __real_OPENSSL_sk_value(st, i);
    });

    ON_CALL(*this, i2d_PUBKEY).WillByDefault([this](EVP_PKEY *a, unsigned char **pp) {
        return __real_i2d_PUBKEY(a, pp);
    });
}

void X509OpensslMock::SetMockFunDefaultBehaviorPartThree(void)
{
    ON_CALL(*this, X509_get_ext_d2i).WillByDefault([this](const X509 *x, int nid, int *crit, int *idx) {
        return __real_X509_get_ext_d2i(x, nid, crit, idx);
    });

    ON_CALL(*this, i2d_ASN1_OCTET_STRING).WillByDefault([this](ASN1_OCTET_STRING *a, unsigned char **out) {
        return __real_i2d_ASN1_OCTET_STRING(a, out);
    });

    ON_CALL(*this, i2d_AUTHORITY_KEYID).WillByDefault([this](AUTHORITY_KEYID *a, unsigned char **out) {
        return __real_i2d_AUTHORITY_KEYID(a, out);
    });

    ON_CALL(*this, DeepCopyDataToBlob).WillByDefault([this](const unsigned char *data, uint32_t len, CfBlob *outBlob) {
        return __real_DeepCopyDataToBlob(data, len, outBlob);
    });

    ON_CALL(*this, ASN1_TIME_new).WillByDefault([this](void) { return __real_ASN1_TIME_new(); });

    ON_CALL(*this, X509_get_pubkey).WillByDefault([this](X509 *x) { return __real_X509_get_pubkey(x); });

    ON_CALL(*this, OBJ_nid2obj).WillByDefault([this](int n) { return __real_OBJ_nid2obj(n); });

    ON_CALL(*this, OBJ_obj2txt).WillByDefault([this](char *buf, int buf_len, const ASN1_OBJECT *a, int no_name) {
        return __real_OBJ_obj2txt(buf, buf_len, a, no_name);
    });

    ON_CALL(*this, BN_bin2bn).WillByDefault([this](const unsigned char *s, int len, BIGNUM *ret) {
        return __real_BN_bin2bn(s, len, ret);
    });

    ON_CALL(*this, X509_get0_serialNumber).WillByDefault([this](const X509 *x) {
        return __real_X509_get0_serialNumber(x);
    });

    ON_CALL(*this, i2d_ASN1_INTEGER).WillByDefault([this](ASN1_INTEGER *a, unsigned char **out) {
        return __real_i2d_ASN1_INTEGER(a, out);
    });

    ON_CALL(*this, X509_check_host)
        .WillByDefault([this](X509 *x, const char *chk, size_t chklen, unsigned int flags, char **peername) {
            return __real_X509_check_host(x, chk, chklen, flags, peername);
        });

    ON_CALL(*this, OCSP_REQUEST_new).WillByDefault([this](void) { return __real_OCSP_REQUEST_new(); });

    ON_CALL(*this, X509_CRL_load_http).WillByDefault([this](const char *url, BIO *bio, BIO *rbio, int timeout) {
        return __real_X509_CRL_load_http(url, bio, rbio, timeout);
    });

    ON_CALL(*this, X509_get1_ocsp).WillByDefault([this](X509 *x) { return __real_X509_get1_ocsp(x); });
}

void X509OpensslMock::SetMockFunDefaultBehaviorPartFour(void)
{
    ON_CALL(*this, OSSL_HTTP_parse_url)
        .WillByDefault([this](const char *url, int *pssl, char **puser, char **phost, char **pport, int *pport_num,
                           char **ppath, char **pquery, char **pfrag) {
            return __real_OSSL_HTTP_parse_url(url, pssl, puser, phost, pport, pport_num, ppath, pquery, pfrag);
        });
    ON_CALL(*this, X509_NAME_get0_der)
        .WillByDefault([this](X509_NAME *nm, const unsigned char **pder, size_t *pderlen) {
            return __real_X509_NAME_get0_der(nm, pder, pderlen);
        });

    ON_CALL(*this, OBJ_nid2sn).WillByDefault([this](int n) { return __real_OBJ_nid2sn(n); });

    ON_CALL(*this, ASN1_STRING_length).WillByDefault([this](const ASN1_STRING *x) {
        return __real_ASN1_STRING_length(x);
    });

    ON_CALL(*this, DeepCopyDataToOut).WillByDefault([this](const char *data, uint32_t len, CfBlob *out) {
        return __real_DeepCopyDataToOut(data, len, out);
    });

    ON_CALL(*this, CRYPTO_strdup).WillByDefault([this](const char *str, const char *file, int line) {
        return __real_CRYPTO_strdup(str, file, line);
    });

    ON_CALL(*this, X509_NAME_new).WillByDefault([this](void) { return __real_X509_NAME_new(); });

    ON_CALL(*this, OBJ_txt2nid).WillByDefault([this](const char *s) { return __real_OBJ_txt2nid(s); });

    ON_CALL(*this, X509_NAME_add_entry_by_NID)
        .WillByDefault(
        [this](X509_NAME *name, int nid, int type, const unsigned char *bytes, int len, int loc, int set) {
            return __real_X509_NAME_add_entry_by_NID(name, nid, type, bytes, len, loc, set);
        });

    ON_CALL(*this, BIO_new).WillByDefault([this](const BIO_METHOD *type) { return __real_BIO_new(type); });

    ON_CALL(*this, X509_print).WillByDefault([this](BIO *bp, X509 *x) { return __real_X509_print(bp, x); });

    ON_CALL(*this, BIO_ctrl).WillByDefault([this](BIO *bp, int cmd, long larg, void *parg) {
        return __real_BIO_ctrl(bp, cmd, larg, parg);
    });

    ON_CALL(*this, i2d_X509_bio).WillByDefault([this](BIO *bp, X509 *x509) { return __real_i2d_X509_bio(bp, x509); });
}

X509OpensslMock::X509OpensslMock()
{
    SetMockFunDefaultBehaviorPartOne();
    SetMockFunDefaultBehaviorPartTwo();
    SetMockFunDefaultBehaviorPartThree();
    SetMockFunDefaultBehaviorPartFour();
}

X509OpensslMock::~X509OpensslMock() {}

void X509OpensslMock::SetMockFlag(bool flag)
{
    g_mockTagX509Openssl = flag;
}

bool X509OpensslMock::GetMockFlag(void)
{
    return g_mockTagX509Openssl;
}

#ifdef __cplusplus
extern "C" {
#endif

int __wrap_i2d_X509_EXTENSIONS(X509_EXTENSIONS *a, unsigned char **out)
{
    if (g_mockTagX509Openssl) {
        return X509OpensslMock::GetInstance().i2d_X509_EXTENSIONS(a, out);
    } else {
        return __real_i2d_X509_EXTENSIONS(a, out);
    }
}

int __wrap_OPENSSL_sk_num(const OPENSSL_STACK *st)
{
    if (g_mockTagX509Openssl) {
        return X509OpensslMock::GetInstance().OPENSSL_sk_num(st);
    } else {
        return __real_OPENSSL_sk_num(st);
    }
}

ASN1_TIME *__wrap_X509_getm_notBefore(const X509 *x)
{
    if (g_mockTagX509Openssl) {
        return X509OpensslMock::GetInstance().X509_getm_notBefore(x);
    } else {
        return __real_X509_getm_notBefore(x);
    }
}

ASN1_TIME *__wrap_X509_getm_notAfter(const X509 *x)
{
    if (g_mockTagX509Openssl) {
        return X509OpensslMock::GetInstance().X509_getm_notAfter(x);
    } else {
        return __real_X509_getm_notAfter(x);
    }
}

char *__wrap_X509_NAME_oneline(const X509_NAME *a, char *buf, int size)
{
    if (g_mockTagX509Openssl) {
        return X509OpensslMock::GetInstance().X509_NAME_oneline(a, buf, size);
    } else {
        return __real_X509_NAME_oneline(a, buf, size);
    }
}

int __wrap_i2d_X509(X509 *a, unsigned char **out)
{
    if (g_mockTagX509Openssl) {
        return X509OpensslMock::GetInstance().i2d_X509(a, out);
    } else {
        return __real_i2d_X509(a, out);
    }
}

BIO *__wrap_BIO_new_mem_buf(const void *buf, int len)
{
    if (g_mockTagX509Openssl) {
        return X509OpensslMock::GetInstance().BIO_new_mem_buf(buf, len);
    } else {
        return __real_BIO_new_mem_buf(buf, len);
    }
}

void *__wrap_OPENSSL_sk_value(const OPENSSL_STACK *st, int i)
{
    if (g_mockTagX509Openssl) {
        return X509OpensslMock::GetInstance().OPENSSL_sk_value(st, i);
    } else {
        return __real_OPENSSL_sk_value(st, i);
    }
}

CfResult __wrap_HcfX509CertificateCreate(const CfEncodingBlob *inStream, HcfX509Certificate **returnObj)
{
    if (g_mockTagX509Openssl) {
        return X509OpensslMock::GetInstance().HcfX509CertificateCreate(inStream, returnObj);
    } else {
        return __real_HcfX509CertificateCreate(inStream, returnObj);
    }
}

OPENSSL_STACK *__wrap_OPENSSL_sk_new_null(void)
{
    if (g_mockTagX509Openssl) {
        return X509OpensslMock::GetInstance().OPENSSL_sk_new_null();
    } else {
        return __real_OPENSSL_sk_new_null();
    }
}

int __wrap_X509_STORE_add_cert(X509_STORE *ctx, X509 *x)
{
    if (g_mockTagX509Openssl) {
        return X509OpensslMock::GetInstance().X509_STORE_add_cert(ctx, x);
    } else {
        return __real_X509_STORE_add_cert(ctx, x);
    }
}

X509_STORE_CTX *__wrap_X509_STORE_CTX_new(void)
{
    if (g_mockTagX509Openssl) {
        return X509OpensslMock::GetInstance().X509_STORE_CTX_new();
    } else {
        return __real_X509_STORE_CTX_new();
    }
}

X509_STORE *__wrap_X509_STORE_new(void)
{
    if (g_mockTagX509Openssl) {
        return X509OpensslMock::GetInstance().X509_STORE_new();
    } else {
        return __real_X509_STORE_new();
    }
}

int __wrap_X509_STORE_CTX_init(X509_STORE_CTX *ctx, X509_STORE *store, X509 *x509, STACK_OF(X509) * chain)
{
    if (g_mockTagX509Openssl) {
        return X509OpensslMock::GetInstance().X509_STORE_CTX_init(ctx, store, x509, chain);
    } else {
        return __real_X509_STORE_CTX_init(ctx, store, x509, chain);
    }
}

int __wrap_X509_verify_cert(X509_STORE_CTX *ctx)
{
    if (g_mockTagX509Openssl) {
        return X509OpensslMock::GetInstance().X509_verify_cert(ctx);
    } else {
        return __real_X509_verify_cert(ctx);
    }
}

int __wrap_i2d_PUBKEY(EVP_PKEY *a, unsigned char **pp)
{
    if (g_mockTagX509Openssl) {
        return X509OpensslMock::GetInstance().i2d_PUBKEY(a, pp);
    } else {
        return __real_i2d_PUBKEY(a, pp);
    }
}

void *__wrap_X509_get_ext_d2i(const X509 *x, int nid, int *crit, int *idx)
{
    if (g_mockTagX509Openssl) {
        return X509OpensslMock::GetInstance().X509_get_ext_d2i(x, nid, crit, idx);
    } else {
        return __real_X509_get_ext_d2i(x, nid, crit, idx);
    }
}

int __wrap_i2d_ASN1_OCTET_STRING(ASN1_OCTET_STRING *a, unsigned char **out)
{
    if (g_mockTagX509Openssl) {
        return X509OpensslMock::GetInstance().i2d_ASN1_OCTET_STRING(a, out);
    } else {
        return __real_i2d_ASN1_OCTET_STRING(a, out);
    }
}

int __wrap_i2d_AUTHORITY_KEYID(AUTHORITY_KEYID *a, unsigned char **out)
{
    if (g_mockTagX509Openssl) {
        return X509OpensslMock::GetInstance().i2d_AUTHORITY_KEYID(a, out);
    } else {
        return __real_i2d_AUTHORITY_KEYID(a, out);
    }
}

CfResult __wrap_DeepCopyDataToBlob(const unsigned char *data, uint32_t len, CfBlob *outBlob)
{
    if (g_mockTagX509Openssl) {
        return X509OpensslMock::GetInstance().DeepCopyDataToBlob(data, len, outBlob);
    } else {
        return __real_DeepCopyDataToBlob(data, len, outBlob);
    }
}

ASN1_TIME *__wrap_ASN1_TIME_new(void)
{
    if (g_mockTagX509Openssl) {
        return X509OpensslMock::GetInstance().ASN1_TIME_new();
    } else {
        return __real_ASN1_TIME_new();
    }
}

const ASN1_INTEGER *__wrap_X509_get0_serialNumber(const X509 *x)
{
    if (g_mockTagX509Openssl) {
        return X509OpensslMock::GetInstance().X509_get0_serialNumber(x);
    } else {
        return __real_X509_get0_serialNumber(x);
    }
}

int __wrap_i2d_ASN1_INTEGER(ASN1_INTEGER *a, unsigned char **out)
{
    if (g_mockTagX509Openssl) {
        return X509OpensslMock::GetInstance().i2d_ASN1_INTEGER(a, out);
    } else {
        return __real_i2d_ASN1_INTEGER(a, out);
    }
}

EVP_PKEY *__wrap_X509_get_pubkey(X509 *x)
{
    if (g_mockTagX509Openssl) {
        return X509OpensslMock::GetInstance().X509_get_pubkey(x);
    } else {
        return __real_X509_get_pubkey(x);
    }
}

ASN1_OBJECT *__wrap_OBJ_nid2obj(int n)
{
    if (g_mockTagX509Openssl) {
        return X509OpensslMock::GetInstance().OBJ_nid2obj(n);
    } else {
        return __real_OBJ_nid2obj(n);
    }
}

int __wrap_OBJ_obj2txt(char *buf, int buf_len, const ASN1_OBJECT *a, int no_name)
{
    if (g_mockTagX509Openssl) {
        return X509OpensslMock::GetInstance().OBJ_obj2txt(buf, buf_len, a, no_name);
    } else {
        return __real_OBJ_obj2txt(buf, buf_len, a, no_name);
    }
}

BIGNUM *__wrap_BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret)
{
    if (g_mockTagX509Openssl) {
        return X509OpensslMock::GetInstance().BN_bin2bn(s, len, ret);
    } else {
        return __real_BN_bin2bn(s, len, ret);
    }
}

int __wrap_ASN1_TIME_normalize(ASN1_TIME *s)
{
    if (g_mockTagX509Openssl) {
        return X509OpensslMock::GetInstance().ASN1_TIME_normalize(s);
    } else {
        return __real_ASN1_TIME_normalize(s);
    }
}

void __wrap_X509_ALGOR_get0(const ASN1_OBJECT **paobj, int *pptype, const void **ppval, const X509_ALGOR *algor)
{
    if (g_mockTagX509Openssl) {
        return X509OpensslMock::GetInstance().X509_ALGOR_get0(paobj, pptype, ppval, algor);
    } else {
        return __real_X509_ALGOR_get0(paobj, pptype, ppval, algor);
    }
}

ASN1_TYPE *__wrap_ASN1_TYPE_new(void)
{
    if (g_mockTagX509Openssl) {
        return X509OpensslMock::GetInstance().ASN1_TYPE_new();
    } else {
        return __real_ASN1_TYPE_new();
    }
}

int __wrap_ASN1_TYPE_set1(ASN1_TYPE *a, int type, const void *value)
{
    if (g_mockTagX509Openssl) {
        return X509OpensslMock::GetInstance().ASN1_TYPE_set1(a, type, value);
    } else {
        return __real_ASN1_TYPE_set1(a, type, value);
    }
}

int __wrap_i2d_ASN1_TYPE(ASN1_TYPE *a, unsigned char **out)
{
    if (g_mockTagX509Openssl) {
        return X509OpensslMock::GetInstance().i2d_ASN1_TYPE(a, out);
    } else {
        return __real_i2d_ASN1_TYPE(a, out);
    }
}

long __wrap_ASN1_INTEGER_get(const ASN1_INTEGER *a)
{
    if (g_mockTagX509Openssl) {
        return X509OpensslMock::GetInstance().ASN1_INTEGER_get(a);
    } else {
        return __real_ASN1_INTEGER_get(a);
    }
}

const unsigned char *__wrap_ASN1_STRING_get0_data(const ASN1_STRING *x)
{
    if (g_mockTagX509Openssl) {
        return X509OpensslMock::GetInstance().ASN1_STRING_get0_data(x);
    } else {
        return __real_ASN1_STRING_get0_data(x);
    }
}

int __wrap_i2d_GENERAL_NAME(GENERAL_NAME *a, unsigned char **out)
{
    if (g_mockTagX509Openssl) {
        return X509OpensslMock::GetInstance().i2d_GENERAL_NAME(a, out);
    } else {
        return __real_i2d_GENERAL_NAME(a, out);
    }
}

X509_EXTENSION *__wrap_X509_get_ext(const X509 *x, X509_EXTENSION *loc)
{
    if (g_mockTagX509Openssl) {
        return X509OpensslMock::GetInstance().X509_get_ext(x, loc);
    } else {
        return __real_X509_get_ext(x, loc);
    }
}

void *__wrap_X509V3_EXT_d2i(X509_EXTENSION *ext)
{
    if (g_mockTagX509Openssl) {
        return X509OpensslMock::GetInstance().X509V3_EXT_d2i(ext);
    } else {
        return __real_X509V3_EXT_d2i(ext);
    }
}

void *__wrap_GENERAL_NAME_get0_value(const GENERAL_NAME *a, int *ptype)
{
    if (g_mockTagX509Openssl) {
        return X509OpensslMock::GetInstance().GENERAL_NAME_get0_value(a, ptype);
    } else {
        return __real_GENERAL_NAME_get0_value(a, ptype);
    }
}

int __wrap_X509_verify(X509 *a, EVP_PKEY *r)
{
    if (g_mockTagX509Openssl) {
        return X509OpensslMock::GetInstance().X509_verify(a, r);
    } else {
        return __real_X509_verify(a, r);
    }
}

CfResult __wrap_DeepCopyBlobToBlob(const CfBlob *inBlob, CfBlob **outBlob)
{
    if (g_mockTagX509Openssl) {
        return X509OpensslMock::GetInstance().DeepCopyBlobToBlob(inBlob, outBlob);
    } else {
        return __real_DeepCopyBlobToBlob(inBlob, outBlob);
    }
}

int __wrap_OPENSSL_sk_push(OPENSSL_STACK *st, const int data)
{
    if (g_mockTagX509Openssl) {
        return X509OpensslMock::GetInstance().OPENSSL_sk_push(st, data);
    } else {
        return __real_OPENSSL_sk_push(st, data);
    }
}

int __wrap_i2d_X509_REVOKED(X509_REVOKED *a, unsigned char **out)
{
    if (g_mockTagX509Openssl) {
        return X509OpensslMock::GetInstance().i2d_X509_REVOKED(a, out);
    } else {
        return __real_i2d_X509_REVOKED(a, out);
    }
}

int __wrap_i2d_X509_CRL(X509_CRL *a, unsigned char **out)
{
    if (g_mockTagX509Openssl) {
        return X509OpensslMock::GetInstance().i2d_X509_CRL(a, out);
    } else {
        return __real_i2d_X509_CRL(a, out);
    }
}

OPENSSL_STACK *__wrap_OPENSSL_sk_deep_copy(const OPENSSL_STACK *st, OPENSSL_sk_copyfunc c, OPENSSL_sk_freefunc f)
{
    if (g_mockTagX509Openssl) {
        return X509OpensslMock::GetInstance().OPENSSL_sk_deep_copy(st, c, f);
    } else {
        return __real_OPENSSL_sk_deep_copy(st, c, f);
    }
}

int __wrap_OBJ_obj2nid(const ASN1_OBJECT *o)
{
    if (g_mockTagX509Openssl) {
        return X509OpensslMock::GetInstance().OBJ_obj2nid(o);
    } else {
        return __real_OBJ_obj2nid(o);
    }
}

X509 *__wrap_X509_dup(X509 *x509)
{
    if (g_mockTagX509Openssl) {
        return X509OpensslMock::GetInstance().X509_dup(x509);
    } else {
        return __real_X509_dup(x509);
    }
}

int __wrap_X509_check_host(X509 *x, const char *chk, size_t chklen, unsigned int flags, char **peername)
{
    if (g_mockTagX509Openssl) {
        return X509OpensslMock::GetInstance().X509_check_host(x, chk, chklen, flags, peername);
    } else {
        return __real_X509_check_host(x, chk, chklen, flags, peername);
    }
}

OCSP_REQUEST *__wrap_OCSP_REQUEST_new(void)
{
    if (g_mockTagX509Openssl) {
        return X509OpensslMock::GetInstance().OCSP_REQUEST_new();
    } else {
        return __real_OCSP_REQUEST_new();
    }
}

X509_CRL *__wrap_X509_CRL_load_http(const char *url, BIO *bio, BIO *rbio, int timeout)
{
    if (g_mockTagX509Openssl) {
        return X509OpensslMock::GetInstance().X509_CRL_load_http(url, bio, rbio, timeout);
    } else {
        return __real_X509_CRL_load_http(url, bio, rbio, timeout);
    }
}

struct stack_st_OPENSSL_STRING *__wrap_X509_get1_ocsp(X509 *x)
{
    if (g_mockTagX509Openssl) {
        return X509OpensslMock::GetInstance().X509_get1_ocsp(x);
    } else {
        return __real_X509_get1_ocsp(x);
    }
}

int __wrap_OSSL_HTTP_parse_url(const char *url, int *pssl, char **puser, char **phost, char **pport, int *pport_num,
    char **ppath, char **pquery, char **pfrag)
{
    if (g_mockTagX509Openssl) {
        return X509OpensslMock::GetInstance().OSSL_HTTP_parse_url(
            url, pssl, puser, phost, pport, pport_num, ppath, pquery, pfrag);
    } else {
        return __real_OSSL_HTTP_parse_url(url, pssl, puser, phost, pport, pport_num, ppath, pquery, pfrag);
    }
}

int __wrap_X509_NAME_get0_der(X509_NAME *nm, const unsigned char **pder, size_t *pderlen)
{
    if (g_mockTagX509Openssl) {
        return X509OpensslMock::GetInstance().X509_NAME_get0_der(nm, pder, pderlen);
    } else {
        return __real_X509_NAME_get0_der(nm, pder, pderlen);
    }
}

const char *__wrap_OBJ_nid2sn(int n)
{
    if (g_mockTagX509Openssl) {
        return X509OpensslMock::GetInstance().OBJ_nid2sn(n);
    } else {
        return __real_OBJ_nid2sn(n);
    }
}

int __wrap_ASN1_STRING_length(const ASN1_STRING *x)
{
    if (g_mockTagX509Openssl) {
        return X509OpensslMock::GetInstance().ASN1_STRING_length(x);
    } else {
        return __real_ASN1_STRING_length(x);
    }
}

CfResult __wrap_DeepCopyDataToOut(const char *data, uint32_t len, CfBlob *out)
{
    if (g_mockTagX509Openssl) {
        return X509OpensslMock::GetInstance().DeepCopyDataToOut(data, len, out);
    } else {
        return __real_DeepCopyDataToOut(data, len, out);
    }
}

char *__wrap_CRYPTO_strdup(const char *str, const char *file, int line)
{
    if (g_mockTagX509Openssl) {
        return X509OpensslMock::GetInstance().CRYPTO_strdup(str, file, line);
    } else {
        return __real_CRYPTO_strdup(str, file, line);
    }
}

X509_NAME *__wrap_X509_NAME_new(void)
{
    if (g_mockTagX509Openssl) {
        return X509OpensslMock::GetInstance().X509_NAME_new();
    } else {
        return __real_X509_NAME_new();
    }
}

int __wrap_OBJ_txt2nid(const char *s)
{
    if (g_mockTagX509Openssl) {
        return X509OpensslMock::GetInstance().OBJ_txt2nid(s);
    } else {
        return __real_OBJ_txt2nid(s);
    }
}

int __wrap_X509_NAME_add_entry_by_NID(
    X509_NAME *name, int nid, int type, const unsigned char *bytes, int len, int loc, int set)
{
    if (g_mockTagX509Openssl) {
        return X509OpensslMock::GetInstance().X509_NAME_add_entry_by_NID(name, nid, type, bytes, len, loc, set);
    } else {
        return __real_X509_NAME_add_entry_by_NID(name, nid, type, bytes, len, loc, set);
    }
}

BIO *__wrap_BIO_new(const BIO_METHOD *type)
{
    if (g_mockTagX509Openssl) {
        return X509OpensslMock::GetInstance().BIO_new(type);
    } else {
        return __real_BIO_new(type);
    }
}

int __wrap_X509_print(BIO *bp, X509 *x)
{
    if (g_mockTagX509Openssl) {
        return X509OpensslMock::GetInstance().X509_print(bp, x);
    } else {
        return __real_X509_print(bp, x);
    }
}

long __wrap_BIO_ctrl(BIO *bp, int cmd, long larg, void *parg)
{
    if (g_mockTagX509Openssl) {
        return X509OpensslMock::GetInstance().BIO_ctrl(bp, cmd, larg, parg);
    } else {
        return __real_BIO_ctrl(bp, cmd, larg, parg);
    }
}

int __wrap_i2d_X509_bio(BIO *bp, X509 *x509)
{
    if (g_mockTagX509Openssl) {
        return X509OpensslMock::GetInstance().i2d_X509_bio(bp, x509);
    } else {
        return __real_i2d_X509_bio(bp, x509);
    }
}

#ifdef __cplusplus
}
#endif
