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
#include "cf_log.h"

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
int __real_OPENSSL_sk_push(OPENSSL_STACK *st, const void *data);
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
int __real_PKCS12_parse(PKCS12 *p12, const char *pass, EVP_PKEY **pkey, X509 **cert, STACK_OF(X509) **ca);
bool __real_CheckIsSelfSigned(const X509 *cert);
int __real_X509_check_private_key(const X509 *x, const EVP_PKEY *k);
int __real_X509_digest(const X509 *cert, const EVP_MD *md, unsigned char *data, unsigned int *len);
PKCS12_SAFEBAG *__real_PKCS12_add_cert(STACK_OF(PKCS12_SAFEBAG) **pbags, X509 *cert);
int __real_PKCS12_add_localkeyid(PKCS12_SAFEBAG *bag, unsigned char *name, int namelen);
PKCS7 *__real_PKCS12_pack_p7encdata_ex(int pbe_nid, const char *pass, int passlen, unsigned char *salt, int saltlen,
    int iter, STACK_OF(PKCS12_SAFEBAG) *bags, OSSL_LIB_CTX *ctx, const char *propq);
PKCS7 *__real_PKCS12_pack_p7data(STACK_OF(PKCS12_SAFEBAG) *sk);
PKCS12 *__real_PKCS12_add_safes_ex(STACK_OF(PKCS7) *safes, int nid_p7, OSSL_LIB_CTX *ctx, const char *propq);
int __real_PKCS12_set_mac(PKCS12 *p12, const char *pass, int passlen, unsigned char *salt, int saltlen,
    int iter, const EVP_MD *md_type);
PKCS12_SAFEBAG *__real_PKCS12_SAFEBAG_create_pkcs8_encrypt_ex(int pbe_nid, const char *pass, int passlen,
    unsigned char *salt, int saltlen, int iter, PKCS8_PRIV_KEY_INFO *p8inf, OSSL_LIB_CTX *ctx, const char *propq);
int __real_i2d_PKCS12(PKCS12 *a, unsigned char **pp);
int __real_PKCS12_add_safe(STACK_OF(PKCS7) **psafes, STACK_OF(PKCS12_SAFEBAG) *bags,
    int nid_safe, int iter, const char *pass);
EVP_PKEY_CTX *__real_CMS_SignerInfo_get0_pkey_ctx(CMS_SignerInfo *si);
int __real_EVP_PKEY_CTX_set_rsa_padding(EVP_PKEY_CTX *ctx, int pad_mode);
const ASN1_OBJECT *__real_CMS_get0_type(const CMS_ContentInfo *cms);
CMS_RecipientInfo *__real_CMS_add1_recipient_cert(CMS_ContentInfo *cms, X509 *recip,
                                                  unsigned int flags);
EVP_PKEY_CTX *__real_CMS_RecipientInfo_get0_pkey_ctx(CMS_RecipientInfo *ri);
int __real_EVP_PKEY_CTX_set_ecdh_kdf_md(EVP_PKEY_CTX *ctx, const EVP_MD *md);
STACK_OF(CMS_SignerInfo) *__real_CMS_get0_SignerInfos(CMS_ContentInfo *cms);
CMS_ContentInfo *__real_CMS_AuthEnvelopedData_create(const EVP_CIPHER *cipher);
CMS_ContentInfo *__real_CMS_EnvelopedData_create(const EVP_CIPHER *cipher);
bool __real_CfIsClassMatch(const CfObjectBase *obj, const char *className);
int __real_CMS_set_detached(CMS_ContentInfo *cms, int detached);
EVP_PKEY *__real_X509_get0_pubkey(X509 *x);
int __real_CMS_verify(CMS_ContentInfo *cms, STACK_OF(X509) *certs, X509_STORE *store,
    BIO *dcont, BIO *out, unsigned int flags);
int __real_CMS_decrypt(CMS_ContentInfo *cms, EVP_PKEY *pkey, X509 *cert,
    BIO *dcont, BIO *out, unsigned int flags);
CMS_ContentInfo *__real_PEM_read_bio_CMS(BIO *bp, CMS_ContentInfo **x, pem_password_cb *cb, void *u);
CMS_ContentInfo *__real_d2i_CMS_bio(BIO *bp, CMS_ContentInfo **cms);
CMS_ContentInfo *__real_CMS_sign_ex(X509 *signcert, EVP_PKEY *pkey, STACK_OF(X509) *certs,
    BIO *data, unsigned int flags, OSSL_LIB_CTX *libctx, const char *propq);
int __real_CMS_final(CMS_ContentInfo *cms, BIO *data, BIO *dcont, unsigned int flags);
ASN1_OCTET_STRING **__real_CMS_get0_content(CMS_ContentInfo *cms);
STACK_OF(X509) *__real_CMS_get1_certs(CMS_ContentInfo *cms);
int __real_BIO_write(BIO *b, const void *data, int dlen);
#ifdef __cplusplus
}
#endif

static bool g_mockTagX509Openssl = false;

static bool g_mockTagX509HcfCert = false;

NiceMock<X509OpensslMock> &X509OpensslMock::GetInstance(void)
{
    static NiceMock<X509OpensslMock> gX509OpensslMock;
    return gX509OpensslMock;
}

void X509OpensslMock::SetMockFunDefaultBehaviorPartOne(void)
{
    ON_CALL(*this, X509_dup).WillByDefault([this](X509 *x509) { return __real_X509_dup(x509); });

    ON_CALL(*this, i2d_X509_EXTENSIONS).WillByDefault([this](X509_EXTENSIONS *a, unsigned char **out) {
        return __real_i2d_X509_EXTENSIONS(a, out);
    });

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

    ON_CALL(*this, OPENSSL_sk_push).WillByDefault([this](OPENSSL_STACK *st, const void *data) {
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
    ON_CALL(*this, X509_ALGOR_get0)
        .WillByDefault([this](const ASN1_OBJECT **paobj, int *pptype, const void **ppval, const X509_ALGOR *algor) {
            return __real_X509_ALGOR_get0(paobj, pptype, ppval, algor);
        });

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

    ON_CALL(*this, PKCS12_parse)
        .WillByDefault([this](PKCS12 *p12, const char *pass, EVP_PKEY **pkey, X509 **cert, STACK_OF(X509) **ca) {
            return __real_PKCS12_parse(p12, pass, pkey, cert, ca);
        });

    ON_CALL(*this, CheckIsSelfSigned).WillByDefault([this](const X509 *cert) {
        return __real_CheckIsSelfSigned(cert);
        });
}

void X509OpensslMock::SetMockFunDefaultBehaviorPartFive(void)
{
    ON_CALL(*this, X509_check_private_key)
        .WillByDefault([this](const X509 *x, const EVP_PKEY *k) {
            return __real_X509_check_private_key(x, k);
        });

    ON_CALL(*this, X509_digest)
        .WillByDefault([this](const X509 *cert, const EVP_MD *md, unsigned char *data, unsigned int *len) {
            return __real_X509_digest(cert, md, data, len);
        });

    ON_CALL(*this, PKCS12_add_cert)
        .WillByDefault([this](STACK_OF(PKCS12_SAFEBAG) **pbags, X509 *cert) {
            return __real_PKCS12_add_cert(pbags, cert);
        });

    ON_CALL(*this, PKCS12_add_localkeyid)
        .WillByDefault([this](PKCS12_SAFEBAG *bag, unsigned char *name, int namelen) {
            return __real_PKCS12_add_localkeyid(bag, name, namelen);
        });

    ON_CALL(*this, PKCS12_pack_p7encdata_ex)
        .WillByDefault([this](int pbe_nid, const char *pass, int passlen, unsigned char *salt, int saltlen, int iter,
            STACK_OF(PKCS12_SAFEBAG) *bags, OSSL_LIB_CTX *ctx, const char *propq) {
            return __real_PKCS12_pack_p7encdata_ex(pbe_nid, pass, passlen, salt, saltlen, iter, bags, ctx, propq);
        });
    
    ON_CALL(*this, PKCS12_pack_p7data)
        .WillByDefault([this](STACK_OF(PKCS12_SAFEBAG) *sk) {
            return __real_PKCS12_pack_p7data(sk);
        });
    
    ON_CALL(*this, PKCS12_add_safes_ex)
        .WillByDefault([this](STACK_OF(PKCS7) *safes, int nid_p7, OSSL_LIB_CTX *ctx, const char *propq) {
            return __real_PKCS12_add_safes_ex(safes, nid_p7, ctx, propq);
        });
    
    ON_CALL(*this, PKCS12_set_mac)
        .WillByDefault([this](PKCS12 *p12, const char *pass, int passlen, unsigned char *salt, int saltlen, int iter,
                              const EVP_MD *md_type) {
            return __real_PKCS12_set_mac(p12, pass, passlen, salt, saltlen, iter, md_type);
        });
    
    ON_CALL(*this, PKCS12_SAFEBAG_create_pkcs8_encrypt_ex)
        .WillByDefault([this](int pbe_nid, const char *pass, int passlen, unsigned char *salt,
                              int saltlen, int iter, PKCS8_PRIV_KEY_INFO *p8inf, OSSL_LIB_CTX *ctx, const char *propq) {
            return __real_PKCS12_SAFEBAG_create_pkcs8_encrypt_ex(pbe_nid, pass, passlen, salt, saltlen, iter,
                                                                 p8inf, ctx, propq);
        });
    
    ON_CALL(*this, i2d_PKCS12)
        .WillByDefault([this](PKCS12 *a, unsigned char **pp) {
            return __real_i2d_PKCS12(a, pp);
        });
    
    ON_CALL(*this, PKCS12_add_safe)
        .WillByDefault([this](STACK_OF(PKCS7) **psafes, STACK_OF(PKCS12_SAFEBAG) *bags,
                              int nid_safe, int iter, const char *pass) {
            return __real_PKCS12_add_safe(psafes, bags, nid_safe, iter, pass);
        });
}

void X509OpensslMock::SetMockFunDefaultBehaviorPartSix(void)
{
    ON_CALL(*this, CMS_SignerInfo_get0_pkey_ctx).WillByDefault([this](CMS_SignerInfo *si) {
        return __real_CMS_SignerInfo_get0_pkey_ctx(si);
    });

    ON_CALL(*this, EVP_PKEY_CTX_set_rsa_padding).WillByDefault([this](EVP_PKEY_CTX *ctx, int pad_mode) {
        return __real_EVP_PKEY_CTX_set_rsa_padding(ctx, pad_mode);
    });

    ON_CALL(*this, CMS_get0_type).WillByDefault([this](const CMS_ContentInfo *cms) {
        return __real_CMS_get0_type(cms);
    });

    ON_CALL(*this, CMS_add1_recipient_cert).WillByDefault([this](CMS_ContentInfo *cms, X509 *recip,
                                                                 unsigned int flags) {
        return __real_CMS_add1_recipient_cert(cms, recip, flags);
    });

    ON_CALL(*this, CMS_RecipientInfo_get0_pkey_ctx).WillByDefault([this](CMS_RecipientInfo *ri) {
        return __real_CMS_RecipientInfo_get0_pkey_ctx(ri);
    });

    ON_CALL(*this, EVP_PKEY_CTX_set_ecdh_kdf_md).WillByDefault([this](EVP_PKEY_CTX *ctx, const EVP_MD *md) {
        return __real_EVP_PKEY_CTX_set_ecdh_kdf_md(ctx, md);
    });

    ON_CALL(*this, CMS_get0_SignerInfos).WillByDefault([this](CMS_ContentInfo *cms) {
        return __real_CMS_get0_SignerInfos(cms);
    });

    ON_CALL(*this, CMS_AuthEnvelopedData_create).WillByDefault([this](const EVP_CIPHER *cipher) {
        return __real_CMS_AuthEnvelopedData_create(cipher);
    });

    ON_CALL(*this, CMS_EnvelopedData_create).WillByDefault([this](const EVP_CIPHER *cipher) {
        return __real_CMS_EnvelopedData_create(cipher);
    });

    ON_CALL(*this, CfIsClassMatch).WillByDefault([this](const CfObjectBase *obj, const char *className) {
        return __real_CfIsClassMatch(obj, className);
    });

    ON_CALL(*this, CMS_set_detached).WillByDefault([this](CMS_ContentInfo *cms, int detached) {
        return __real_CMS_set_detached(cms, detached);
    });

    ON_CALL(*this, X509_get0_pubkey).WillByDefault([this](X509 *x) { return __real_X509_get0_pubkey(x); });
}

void X509OpensslMock::SetMockFunDefaultBehaviorPartSeven(void)
{
    ON_CALL(*this, CMS_verify).WillByDefault([this](CMS_ContentInfo *cms, STACK_OF(X509) *certs,
                                                    X509_STORE *store, BIO *dcont, BIO *out, unsigned int flags) {
        return __real_CMS_verify(cms, certs, store, dcont, out, flags);
    });

    ON_CALL(*this, CMS_decrypt).WillByDefault([this](CMS_ContentInfo *cms, EVP_PKEY *pkey, X509 *cert,
                                                     BIO *dcont, BIO *out, unsigned int flags) {
        return __real_CMS_decrypt(cms, pkey, cert, dcont, out, flags);
    });

    ON_CALL(*this, PEM_read_bio_CMS).WillByDefault([this](BIO *bp, CMS_ContentInfo **x,
                                                          pem_password_cb *cb, void *u) {
        return __real_PEM_read_bio_CMS(bp, x, cb, u);
    });

    ON_CALL(*this, d2i_CMS_bio).WillByDefault([this](BIO *bp, CMS_ContentInfo **cms) {
        return __real_d2i_CMS_bio(bp, cms);
    });

    ON_CALL(*this, CMS_sign_ex).WillByDefault([this](X509 *signcert, EVP_PKEY *pkey, STACK_OF(X509) *certs,
                                                     BIO *data, unsigned int flags, OSSL_LIB_CTX *libctx,
                                                     const char *propq) {
        return __real_CMS_sign_ex(signcert, pkey, certs, data, flags, libctx, propq);
    });

    ON_CALL(*this, CMS_final).WillByDefault([this](CMS_ContentInfo *cms, BIO *data,
                                                   BIO *dcont, unsigned int flags) {
        return __real_CMS_final(cms, data, dcont, flags);
    });
}

void X509OpensslMock::SetMockFunDefaultBehaviorPartEight(void)
{
    ON_CALL(*this, CMS_get0_content).WillByDefault([this](CMS_ContentInfo *cms) {
        return __real_CMS_get0_content(cms);
    });

    ON_CALL(*this, CMS_get1_certs).WillByDefault([this](CMS_ContentInfo *cms) {
        return __real_CMS_get1_certs(cms);
    });

    ON_CALL(*this, BIO_write).WillByDefault([this](BIO *b, const void *data, int dlen) {
        return __real_BIO_write(b, data, dlen);
    });
}

X509OpensslMock::X509OpensslMock()
{
    SetMockFunDefaultBehaviorPartOne();
    SetMockFunDefaultBehaviorPartTwo();
    SetMockFunDefaultBehaviorPartThree();
    SetMockFunDefaultBehaviorPartFour();
    SetMockFunDefaultBehaviorPartFive();
    SetMockFunDefaultBehaviorPartSix();
    SetMockFunDefaultBehaviorPartSeven();
    SetMockFunDefaultBehaviorPartEight();
}

X509OpensslMock::~X509OpensslMock() {}

void X509OpensslMock::SetMockFlag(bool flag)
{
    g_mockTagX509Openssl = flag;
}

void X509OpensslMock::SetHcfMockFlag(bool flag)
{
    g_mockTagX509HcfCert = flag;
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
        CF_LOG_I("X509OpensslMock i2d_X509_EXTENSIONS");
        return X509OpensslMock::GetInstance().i2d_X509_EXTENSIONS(a, out);
    } else {
        return __real_i2d_X509_EXTENSIONS(a, out);
    }
}

int __wrap_OPENSSL_sk_num(const OPENSSL_STACK *st)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock OPENSSL_sk_num");
        return X509OpensslMock::GetInstance().OPENSSL_sk_num(st);
    } else {
        return __real_OPENSSL_sk_num(st);
    }
}

ASN1_TIME *__wrap_X509_getm_notBefore(const X509 *x)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock X509_getm_notBefore");
        return X509OpensslMock::GetInstance().X509_getm_notBefore(x);
    } else {
        return __real_X509_getm_notBefore(x);
    }
}

ASN1_TIME *__wrap_X509_getm_notAfter(const X509 *x)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock X509_getm_notAfter");
        return X509OpensslMock::GetInstance().X509_getm_notAfter(x);
    } else {
        return __real_X509_getm_notAfter(x);
    }
}

char *__wrap_X509_NAME_oneline(const X509_NAME *a, char *buf, int size)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock X509_NAME_oneline");
        return X509OpensslMock::GetInstance().X509_NAME_oneline(a, buf, size);
    } else {
        return __real_X509_NAME_oneline(a, buf, size);
    }
}

int __wrap_i2d_X509(X509 *a, unsigned char **out)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock i2d_X509");
        return X509OpensslMock::GetInstance().i2d_X509(a, out);
    } else {
        return __real_i2d_X509(a, out);
    }
}

BIO *__wrap_BIO_new_mem_buf(const void *buf, int len)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock BIO_new_mem_buf");
        return X509OpensslMock::GetInstance().BIO_new_mem_buf(buf, len);
    } else {
        return __real_BIO_new_mem_buf(buf, len);
    }
}

void *__wrap_OPENSSL_sk_value(const OPENSSL_STACK *st, int i)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock OPENSSL_sk_value");
        return X509OpensslMock::GetInstance().OPENSSL_sk_value(st, i);
    } else {
        return __real_OPENSSL_sk_value(st, i);
    }
}

CfResult __wrap_HcfX509CertificateCreate(const CfEncodingBlob *inStream, HcfX509Certificate **returnObj)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock HcfX509CertificateCreate");
        return X509OpensslMock::GetInstance().HcfX509CertificateCreate(inStream, returnObj);
    } else {
        return __real_HcfX509CertificateCreate(inStream, returnObj);
    }
}

OPENSSL_STACK *__wrap_OPENSSL_sk_new_null(void)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock OPENSSL_sk_new_null");
        return X509OpensslMock::GetInstance().OPENSSL_sk_new_null();
    } else {
        return __real_OPENSSL_sk_new_null();
    }
}

int __wrap_X509_STORE_add_cert(X509_STORE *ctx, X509 *x)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock X509_STORE_add_cert");
        return X509OpensslMock::GetInstance().X509_STORE_add_cert(ctx, x);
    } else {
        return __real_X509_STORE_add_cert(ctx, x);
    }
}

X509_STORE_CTX *__wrap_X509_STORE_CTX_new(void)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock X509_STORE_CTX_new");
        return X509OpensslMock::GetInstance().X509_STORE_CTX_new();
    } else {
        return __real_X509_STORE_CTX_new();
    }
}

X509_STORE *__wrap_X509_STORE_new(void)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock X509_STORE_new");
        return X509OpensslMock::GetInstance().X509_STORE_new();
    } else {
        return __real_X509_STORE_new();
    }
}

int __wrap_X509_STORE_CTX_init(X509_STORE_CTX *ctx, X509_STORE *store, X509 *x509, STACK_OF(X509) * chain)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock X509_STORE_CTX_init");
        return X509OpensslMock::GetInstance().X509_STORE_CTX_init(ctx, store, x509, chain);
    } else {
        return __real_X509_STORE_CTX_init(ctx, store, x509, chain);
    }
}

int __wrap_X509_verify_cert(X509_STORE_CTX *ctx)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock X509_verify_cert");
        return X509OpensslMock::GetInstance().X509_verify_cert(ctx);
    } else {
        return __real_X509_verify_cert(ctx);
    }
}

int __wrap_i2d_PUBKEY(EVP_PKEY *a, unsigned char **pp)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock i2d_PUBKEY");
        return X509OpensslMock::GetInstance().i2d_PUBKEY(a, pp);
    } else {
        return __real_i2d_PUBKEY(a, pp);
    }
}

void *__wrap_X509_get_ext_d2i(const X509 *x, int nid, int *crit, int *idx)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock X509_get_ext_d2i");
        return X509OpensslMock::GetInstance().X509_get_ext_d2i(x, nid, crit, idx);
    } else {
        return __real_X509_get_ext_d2i(x, nid, crit, idx);
    }
}

int __wrap_i2d_ASN1_OCTET_STRING(ASN1_OCTET_STRING *a, unsigned char **out)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock i2d_ASN1_OCTET_STRING");
        return X509OpensslMock::GetInstance().i2d_ASN1_OCTET_STRING(a, out);
    } else {
        return __real_i2d_ASN1_OCTET_STRING(a, out);
    }
}

int __wrap_i2d_AUTHORITY_KEYID(AUTHORITY_KEYID *a, unsigned char **out)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock i2d_AUTHORITY_KEYID");
        return X509OpensslMock::GetInstance().i2d_AUTHORITY_KEYID(a, out);
    } else {
        return __real_i2d_AUTHORITY_KEYID(a, out);
    }
}

CfResult __wrap_DeepCopyDataToBlob(const unsigned char *data, uint32_t len, CfBlob *outBlob)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock DeepCopyDataToBlob");
        return X509OpensslMock::GetInstance().DeepCopyDataToBlob(data, len, outBlob);
    } else {
        return __real_DeepCopyDataToBlob(data, len, outBlob);
    }
}

ASN1_TIME *__wrap_ASN1_TIME_new(void)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock ASN1_TIME_new");
        return X509OpensslMock::GetInstance().ASN1_TIME_new();
    } else {
        return __real_ASN1_TIME_new();
    }
}

const ASN1_INTEGER *__wrap_X509_get0_serialNumber(const X509 *x)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock X509_get0_serialNumber");
        return X509OpensslMock::GetInstance().X509_get0_serialNumber(x);
    } else {
        return __real_X509_get0_serialNumber(x);
    }
}

int __wrap_i2d_ASN1_INTEGER(ASN1_INTEGER *a, unsigned char **out)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock i2d_ASN1_INTEGER");
        return X509OpensslMock::GetInstance().i2d_ASN1_INTEGER(a, out);
    } else {
        return __real_i2d_ASN1_INTEGER(a, out);
    }
}

EVP_PKEY *__wrap_X509_get_pubkey(X509 *x)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock X509_get_pubkey");
        return X509OpensslMock::GetInstance().X509_get_pubkey(x);
    } else {
        return __real_X509_get_pubkey(x);
    }
}

ASN1_OBJECT *__wrap_OBJ_nid2obj(int n)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock OBJ_nid2obj");
        return X509OpensslMock::GetInstance().OBJ_nid2obj(n);
    } else {
        return __real_OBJ_nid2obj(n);
    }
}

int __wrap_OBJ_obj2txt(char *buf, int buf_len, const ASN1_OBJECT *a, int no_name)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock OBJ_obj2txt");
        return X509OpensslMock::GetInstance().OBJ_obj2txt(buf, buf_len, a, no_name);
    } else {
        return __real_OBJ_obj2txt(buf, buf_len, a, no_name);
    }
}

BIGNUM *__wrap_BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock BN_bin2bn");
        return X509OpensslMock::GetInstance().BN_bin2bn(s, len, ret);
    } else {
        return __real_BN_bin2bn(s, len, ret);
    }
}

int __wrap_ASN1_TIME_normalize(ASN1_TIME *s)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock ASN1_TIME_normalize");
        return X509OpensslMock::GetInstance().ASN1_TIME_normalize(s);
    } else {
        return __real_ASN1_TIME_normalize(s);
    }
}

void __wrap_X509_ALGOR_get0(const ASN1_OBJECT **paobj, int *pptype, const void **ppval, const X509_ALGOR *algor)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock X509_ALGOR_get0");
        return X509OpensslMock::GetInstance().X509_ALGOR_get0(paobj, pptype, ppval, algor);
    } else {
        return __real_X509_ALGOR_get0(paobj, pptype, ppval, algor);
    }
}

ASN1_TYPE *__wrap_ASN1_TYPE_new(void)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock ASN1_TYPE_new");
        return X509OpensslMock::GetInstance().ASN1_TYPE_new();
    } else {
        return __real_ASN1_TYPE_new();
    }
}

int __wrap_ASN1_TYPE_set1(ASN1_TYPE *a, int type, const void *value)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock ASN1_TYPE_set1");
        return X509OpensslMock::GetInstance().ASN1_TYPE_set1(a, type, value);
    } else {
        return __real_ASN1_TYPE_set1(a, type, value);
    }
}

int __wrap_i2d_ASN1_TYPE(ASN1_TYPE *a, unsigned char **out)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock i2d_ASN1_TYPE");
        return X509OpensslMock::GetInstance().i2d_ASN1_TYPE(a, out);
    } else {
        return __real_i2d_ASN1_TYPE(a, out);
    }
}

long __wrap_ASN1_INTEGER_get(const ASN1_INTEGER *a)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock ASN1_INTEGER_get");
        return X509OpensslMock::GetInstance().ASN1_INTEGER_get(a);
    } else {
        return __real_ASN1_INTEGER_get(a);
    }
}

const unsigned char *__wrap_ASN1_STRING_get0_data(const ASN1_STRING *x)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock ASN1_STRING_get0_data");
        return X509OpensslMock::GetInstance().ASN1_STRING_get0_data(x);
    } else {
        return __real_ASN1_STRING_get0_data(x);
    }
}

int __wrap_i2d_GENERAL_NAME(GENERAL_NAME *a, unsigned char **out)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock i2d_GENERAL_NAME");
        return X509OpensslMock::GetInstance().i2d_GENERAL_NAME(a, out);
    } else {
        return __real_i2d_GENERAL_NAME(a, out);
    }
}

X509_EXTENSION *__wrap_X509_get_ext(const X509 *x, X509_EXTENSION *loc)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock X509_get_ext");
        return X509OpensslMock::GetInstance().X509_get_ext(x, loc);
    } else {
        return __real_X509_get_ext(x, loc);
    }
}

void *__wrap_X509V3_EXT_d2i(X509_EXTENSION *ext)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock X509V3_EXT_d2i");
        return X509OpensslMock::GetInstance().X509V3_EXT_d2i(ext);
    } else {
        return __real_X509V3_EXT_d2i(ext);
    }
}

void *__wrap_GENERAL_NAME_get0_value(const GENERAL_NAME *a, int *ptype)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock GENERAL_NAME_get0_value");
        return X509OpensslMock::GetInstance().GENERAL_NAME_get0_value(a, ptype);
    } else {
        return __real_GENERAL_NAME_get0_value(a, ptype);
    }
}

int __wrap_X509_verify(X509 *a, EVP_PKEY *r)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock X509_verify");
        return X509OpensslMock::GetInstance().X509_verify(a, r);
    } else {
        return __real_X509_verify(a, r);
    }
}

CfResult __wrap_DeepCopyBlobToBlob(const CfBlob *inBlob, CfBlob **outBlob)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock DeepCopyBlobToBlob");
        return X509OpensslMock::GetInstance().DeepCopyBlobToBlob(inBlob, outBlob);
    } else {
        return __real_DeepCopyBlobToBlob(inBlob, outBlob);
    }
}

int __wrap_OPENSSL_sk_push(OPENSSL_STACK *st, const void *data)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock OPENSSL_sk_push");
        return X509OpensslMock::GetInstance().OPENSSL_sk_push(st, data);
    } else {
        return __real_OPENSSL_sk_push(st, data);
    }
}

int __wrap_i2d_X509_REVOKED(X509_REVOKED *a, unsigned char **out)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock i2d_X509_REVOKED");
        return X509OpensslMock::GetInstance().i2d_X509_REVOKED(a, out);
    } else {
        return __real_i2d_X509_REVOKED(a, out);
    }
}

int __wrap_i2d_X509_CRL(X509_CRL *a, unsigned char **out)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock i2d_X509_CRL");
        return X509OpensslMock::GetInstance().i2d_X509_CRL(a, out);
    } else {
        return __real_i2d_X509_CRL(a, out);
    }
}

OPENSSL_STACK *__wrap_OPENSSL_sk_deep_copy(const OPENSSL_STACK *st, OPENSSL_sk_copyfunc c, OPENSSL_sk_freefunc f)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock OPENSSL_sk_deep_copy");
        return X509OpensslMock::GetInstance().OPENSSL_sk_deep_copy(st, c, f);
    } else {
        return __real_OPENSSL_sk_deep_copy(st, c, f);
    }
}

int __wrap_OBJ_obj2nid(const ASN1_OBJECT *o)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock OBJ_obj2nid");
        return X509OpensslMock::GetInstance().OBJ_obj2nid(o);
    } else {
        return __real_OBJ_obj2nid(o);
    }
}

X509 *__wrap_X509_dup(X509 *x509)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock X509_dup");
        return X509OpensslMock::GetInstance().X509_dup(x509);
    } else {
        return __real_X509_dup(x509);
    }
}

int __wrap_X509_check_host(X509 *x, const char *chk, size_t chklen, unsigned int flags, char **peername)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock X509_check_host");
        return X509OpensslMock::GetInstance().X509_check_host(x, chk, chklen, flags, peername);
    } else {
        return __real_X509_check_host(x, chk, chklen, flags, peername);
    }
}

OCSP_REQUEST *__wrap_OCSP_REQUEST_new(void)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock OCSP_REQUEST_new");
        return X509OpensslMock::GetInstance().OCSP_REQUEST_new();
    } else {
        return __real_OCSP_REQUEST_new();
    }
}

X509_CRL *__wrap_X509_CRL_load_http(const char *url, BIO *bio, BIO *rbio, int timeout)
{
    if (g_mockTagX509Openssl || g_mockTagX509HcfCert) {
        CF_LOG_I("X509OpensslMock X509_CRL_load_http");
        return X509OpensslMock::GetInstance().X509_CRL_load_http(url, bio, rbio, timeout);
    } else {
        return __real_X509_CRL_load_http(url, bio, rbio, timeout);
    }
}

struct stack_st_OPENSSL_STRING *__wrap_X509_get1_ocsp(X509 *x)
{
    if (g_mockTagX509Openssl || g_mockTagX509HcfCert) {
        CF_LOG_I("X509OpensslMock X509_get1_ocsp");
        return X509OpensslMock::GetInstance().X509_get1_ocsp(x);
    } else {
        return __real_X509_get1_ocsp(x);
    }
}

int __wrap_OSSL_HTTP_parse_url(const char *url, int *pssl, char **puser, char **phost, char **pport, int *pport_num,
    char **ppath, char **pquery, char **pfrag)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock OSSL_HTTP_parse_url");
        return X509OpensslMock::GetInstance().OSSL_HTTP_parse_url(
            url, pssl, puser, phost, pport, pport_num, ppath, pquery, pfrag);
    } else {
        return __real_OSSL_HTTP_parse_url(url, pssl, puser, phost, pport, pport_num, ppath, pquery, pfrag);
    }
}

int __wrap_X509_NAME_get0_der(X509_NAME *nm, const unsigned char **pder, size_t *pderlen)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock X509_NAME_get0_der");
        return X509OpensslMock::GetInstance().X509_NAME_get0_der(nm, pder, pderlen);
    } else {
        return __real_X509_NAME_get0_der(nm, pder, pderlen);
    }
}

const char *__wrap_OBJ_nid2sn(int n)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock OBJ_nid2sn");
        return X509OpensslMock::GetInstance().OBJ_nid2sn(n);
    } else {
        return __real_OBJ_nid2sn(n);
    }
}

int __wrap_ASN1_STRING_length(const ASN1_STRING *x)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock ASN1_STRING_length");
        return X509OpensslMock::GetInstance().ASN1_STRING_length(x);
    } else {
        return __real_ASN1_STRING_length(x);
    }
}

CfResult __wrap_DeepCopyDataToOut(const char *data, uint32_t len, CfBlob *out)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock DeepCopyDataToOut");
        return X509OpensslMock::GetInstance().DeepCopyDataToOut(data, len, out);
    } else {
        return __real_DeepCopyDataToOut(data, len, out);
    }
}

char *__wrap_CRYPTO_strdup(const char *str, const char *file, int line)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock CRYPTO_strdup");
        return X509OpensslMock::GetInstance().CRYPTO_strdup(str, file, line);
    } else {
        return __real_CRYPTO_strdup(str, file, line);
    }
}

X509_NAME *__wrap_X509_NAME_new(void)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock X509_NAME_new");
        return X509OpensslMock::GetInstance().X509_NAME_new();
    } else {
        return __real_X509_NAME_new();
    }
}

int __wrap_OBJ_txt2nid(const char *s)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock OBJ_txt2nid");
        return X509OpensslMock::GetInstance().OBJ_txt2nid(s);
    } else {
        return __real_OBJ_txt2nid(s);
    }
}

int __wrap_X509_NAME_add_entry_by_NID(
    X509_NAME *name, int nid, int type, const unsigned char *bytes, int len, int loc, int set)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock X509_NAME_add_entry_by_NID");
        return X509OpensslMock::GetInstance().X509_NAME_add_entry_by_NID(name, nid, type, bytes, len, loc, set);
    } else {
        return __real_X509_NAME_add_entry_by_NID(name, nid, type, bytes, len, loc, set);
    }
}

BIO *__wrap_BIO_new(const BIO_METHOD *type)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock BIO_new");
        return X509OpensslMock::GetInstance().BIO_new(type);
    } else {
        return __real_BIO_new(type);
    }
}

int __wrap_X509_print(BIO *bp, X509 *x)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock X509_print");
        return X509OpensslMock::GetInstance().X509_print(bp, x);
    } else {
        return __real_X509_print(bp, x);
    }
}

long __wrap_BIO_ctrl(BIO *bp, int cmd, long larg, void *parg)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock BIO_ctrl");
        return X509OpensslMock::GetInstance().BIO_ctrl(bp, cmd, larg, parg);
    } else {
        return __real_BIO_ctrl(bp, cmd, larg, parg);
    }
}

int __wrap_i2d_X509_bio(BIO *bp, X509 *x509)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock i2d_X509_bio");
        return X509OpensslMock::GetInstance().i2d_X509_bio(bp, x509);
    } else {
        return __real_i2d_X509_bio(bp, x509);
    }
}

int __wrap_PKCS12_parse(PKCS12 *p12, const char *pass, EVP_PKEY **pkey, X509 **cert, STACK_OF(X509) **ca)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock PKCS12_parse");
        return X509OpensslMock::GetInstance().PKCS12_parse(p12, pass, pkey, cert, ca);
    } else {
        return __real_PKCS12_parse(p12, pass, pkey, cert, ca);
    }
}

bool __wrap_CheckIsSelfSigned(const X509 *cert)
{
    if (g_mockTagX509Openssl || g_mockTagX509HcfCert) {
        CF_LOG_I("X509OpensslMock CheckIsSelfSigned");
        return X509OpensslMock::GetInstance().CheckIsSelfSigned(cert);
    } else {
        return __real_CheckIsSelfSigned(cert);
    }
}

int __wrap_X509_check_private_key(const X509 *x, const EVP_PKEY *k)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock X509_check_private_key");
        return X509OpensslMock::GetInstance().X509_check_private_key(x, k);
    } else {
        return __real_X509_check_private_key(x, k);
    }
}

int __wrap_X509_digest(const X509 *cert, const EVP_MD *md, unsigned char *data, unsigned int *len)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock X509_digest");
        return X509OpensslMock::GetInstance().X509_digest(cert, md, data, len);
    } else {
        return __real_X509_digest(cert, md, data, len);
    }
}

PKCS12_SAFEBAG * __wrap_PKCS12_add_cert(STACK_OF(PKCS12_SAFEBAG) **pbags, X509 *cert)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock PKCS12_add_cert");
        return X509OpensslMock::GetInstance().PKCS12_add_cert(pbags, cert);
    } else {
        return __real_PKCS12_add_cert(pbags, cert);
    }
}

int __wrap_PKCS12_add_localkeyid(PKCS12_SAFEBAG *bag, unsigned char *name, int namelen)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock PKCS12_add_localkeyid");
        return X509OpensslMock::GetInstance().PKCS12_add_localkeyid(bag, name, namelen);
    } else {
        return __real_PKCS12_add_localkeyid(bag, name, namelen);
    }
}

PKCS7 * __wrap_PKCS12_pack_p7encdata_ex(int pbe_nid, const char *pass, int passlen, unsigned char *salt,
    int saltlen, int iter, STACK_OF(PKCS12_SAFEBAG) *bags, OSSL_LIB_CTX *ctx, const char *propq)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock PKCS12_pack_p7encdata_ex");
        return X509OpensslMock::GetInstance().PKCS12_pack_p7encdata_ex(pbe_nid, pass, passlen, salt, saltlen, iter,
                                                                       bags, ctx, propq);
    } else {
        return __real_PKCS12_pack_p7encdata_ex(pbe_nid, pass, passlen, salt, saltlen, iter, bags, ctx, propq);
    }
}

PKCS7 * __wrap_PKCS12_pack_p7data(STACK_OF(PKCS12_SAFEBAG) *sk)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock PKCS12_pack_p7data");
        return X509OpensslMock::GetInstance().PKCS12_pack_p7data(sk);
    } else {
        return __real_PKCS12_pack_p7data(sk);
    }
}

PKCS12 * __wrap_PKCS12_add_safes_ex(STACK_OF(PKCS7) *safes, int nid_p7, OSSL_LIB_CTX *ctx, const char *propq)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock PKCS12_add_safes_ex");
        return X509OpensslMock::GetInstance().PKCS12_add_safes_ex(safes, nid_p7, ctx, propq);
    } else {
        return __real_PKCS12_add_safes_ex(safes, nid_p7, ctx, propq);
    }
}

int  __wrap_PKCS12_set_mac(PKCS12 *p12, const char *pass, int passlen, unsigned char *salt, int saltlen,
    int iter, const EVP_MD *md_type)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock PKCS12_set_mac");
        return X509OpensslMock::GetInstance().PKCS12_set_mac(p12, pass, passlen, salt, saltlen, iter, md_type);
    } else {
        return __real_PKCS12_set_mac(p12, pass, passlen, salt, saltlen, iter, md_type);
    }
}

PKCS12_SAFEBAG *__wrap_PKCS12_SAFEBAG_create_pkcs8_encrypt_ex(int pbe_nid, const char *pass, int passlen,
    unsigned char *salt, int saltlen, int iter, PKCS8_PRIV_KEY_INFO *p8inf, OSSL_LIB_CTX *ctx, const char *propq)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock PKCS12_SAFEBAG_create_pkcs8_encrypt_ex");
        return X509OpensslMock::GetInstance().PKCS12_SAFEBAG_create_pkcs8_encrypt_ex(pbe_nid, pass, passlen, salt,
            saltlen, iter, p8inf, ctx, propq);
    } else {
        return __real_PKCS12_SAFEBAG_create_pkcs8_encrypt_ex(pbe_nid, pass, passlen, salt, saltlen, iter, p8inf,
            ctx, propq);
    }
}

int __wrap_i2d_PKCS12(PKCS12 *a, unsigned char **pp)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock i2d_PKCS12");
        return X509OpensslMock::GetInstance().i2d_PKCS12(a, pp);
    } else {
        return __real_i2d_PKCS12(a, pp);
    }
}

int __wrap_PKCS12_add_safe(STACK_OF(PKCS7) **psafes, STACK_OF(PKCS12_SAFEBAG) *bags, int nid_safe,
    int iter, const char *pass)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock PKCS12_add_safe");
        return X509OpensslMock::GetInstance().PKCS12_add_safe(psafes, bags, nid_safe, iter, pass);
    } else {
        return __real_PKCS12_add_safe(psafes, bags, nid_safe, iter, pass);
    }
}

EVP_PKEY_CTX *__wrap_CMS_SignerInfo_get0_pkey_ctx(CMS_SignerInfo *si)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock CMS_SignerInfo_get0_pkey_ctx");
        return X509OpensslMock::GetInstance().CMS_SignerInfo_get0_pkey_ctx(si);
    } else {
        return __real_CMS_SignerInfo_get0_pkey_ctx(si);
    }
}

int __wrap_EVP_PKEY_CTX_set_rsa_padding(EVP_PKEY_CTX *ctx, int pad_mode)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock EVP_PKEY_CTX_set_rsa_padding");
        return X509OpensslMock::GetInstance().EVP_PKEY_CTX_set_rsa_padding(ctx, pad_mode);
    } else {
        return __real_EVP_PKEY_CTX_set_rsa_padding(ctx, pad_mode);
    }
}

const ASN1_OBJECT *__wrap_CMS_get0_type(const CMS_ContentInfo *cms)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock CMS_get0_type");
        return X509OpensslMock::GetInstance().CMS_get0_type(cms);
    } else {
        return __real_CMS_get0_type(cms);
    }
}

CMS_RecipientInfo *__wrap_CMS_add1_recipient_cert(CMS_ContentInfo *cms, X509 *recip,
                                                  unsigned int flags)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock CMS_add1_recipient_cert");
        return X509OpensslMock::GetInstance().CMS_add1_recipient_cert(cms, recip, flags);
    } else {
        return __real_CMS_add1_recipient_cert(cms, recip, flags);
    }
}

EVP_PKEY_CTX *__wrap_CMS_RecipientInfo_get0_pkey_ctx(CMS_RecipientInfo *ri)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock CMS_RecipientInfo_get0_pkey_ctx");
        return X509OpensslMock::GetInstance().CMS_RecipientInfo_get0_pkey_ctx(ri);
    } else {
        return __real_CMS_RecipientInfo_get0_pkey_ctx(ri);
    }
}

int __wrap_EVP_PKEY_CTX_set_ecdh_kdf_md(EVP_PKEY_CTX *ctx, const EVP_MD *md)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock EVP_PKEY_CTX_set_ecdh_kdf_md");
        return X509OpensslMock::GetInstance().EVP_PKEY_CTX_set_ecdh_kdf_md(ctx, md);
    } else {
        return __real_EVP_PKEY_CTX_set_ecdh_kdf_md(ctx, md);
    }
}

STACK_OF(CMS_SignerInfo) *__wrap_CMS_get0_SignerInfos(CMS_ContentInfo *cms)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock CMS_get0_SignerInfos");
        return X509OpensslMock::GetInstance().CMS_get0_SignerInfos(cms);
    } else {
        return __real_CMS_get0_SignerInfos(cms);
    }
}

CMS_ContentInfo *__wrap_CMS_AuthEnvelopedData_create(const EVP_CIPHER *cipher)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock CMS_AuthEnvelopedData_create");
        return X509OpensslMock::GetInstance().CMS_AuthEnvelopedData_create(cipher);
    } else {
        return __real_CMS_AuthEnvelopedData_create(cipher);
    }
}

CMS_ContentInfo *__wrap_CMS_EnvelopedData_create(const EVP_CIPHER *cipher)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock CMS_EnvelopedData_create");
        return X509OpensslMock::GetInstance().CMS_EnvelopedData_create(cipher);
    } else {
        return __real_CMS_EnvelopedData_create(cipher);
    }
}

bool __wrap_CfIsClassMatch(const CfObjectBase *obj, const char *className)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock CfIsClassMatch");
        return X509OpensslMock::GetInstance().CfIsClassMatch(obj, className);
    } else {
        return __real_CfIsClassMatch(obj, className);
    }
}

int __wrap_CMS_set_detached(CMS_ContentInfo *cms, int detached)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock CMS_set_detached");
        return X509OpensslMock::GetInstance().CMS_set_detached(cms, detached);
    } else {
        return __real_CMS_set_detached(cms, detached);
    }
}

EVP_PKEY *__wrap_X509_get0_pubkey(X509 *x)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock X509_get0_pubkey");
        return X509OpensslMock::GetInstance().X509_get0_pubkey(x);
    } else {
        return __real_X509_get0_pubkey(x);
    }
}

int __wrap_CMS_verify(CMS_ContentInfo *cms, STACK_OF(X509) *certs, X509_STORE *store,
    BIO *dcont, BIO *out, unsigned int flags)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock CMS_verify");
        return X509OpensslMock::GetInstance().CMS_verify(cms, certs, store, dcont, out, flags);
    } else {
        return __real_CMS_verify(cms, certs, store, dcont, out, flags);
    }
}

int __wrap_CMS_decrypt(CMS_ContentInfo *cms, EVP_PKEY *pkey, X509 *cert,
    BIO *dcont, BIO *out, unsigned int flags)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock CMS_decrypt");
        return X509OpensslMock::GetInstance().CMS_decrypt(cms, pkey, cert, dcont, out, flags);
    } else {
        return __real_CMS_decrypt(cms, pkey, cert, dcont, out, flags);
    }
}

CMS_ContentInfo *__wrap_PEM_read_bio_CMS(BIO *bp, CMS_ContentInfo **x, pem_password_cb *cb, void *u)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock PEM_read_bio_CMS");
        return X509OpensslMock::GetInstance().PEM_read_bio_CMS(bp, x, cb, u);
    } else {
        return __real_PEM_read_bio_CMS(bp, x, cb, u);
    }
}

CMS_ContentInfo *__wrap_d2i_CMS_bio(BIO *bp, CMS_ContentInfo **cms)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock d2i_CMS_bio");
        return X509OpensslMock::GetInstance().d2i_CMS_bio(bp, cms);
    } else {
        return __real_d2i_CMS_bio(bp, cms);
    }
}

CMS_ContentInfo *__wrap_CMS_sign_ex(X509 *signcert, EVP_PKEY *pkey, STACK_OF(X509) *certs,
    BIO *data, unsigned int flags, OSSL_LIB_CTX *libctx, const char *propq)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock CMS_sign_ex");
        return X509OpensslMock::GetInstance().CMS_sign_ex(signcert, pkey, certs, data, flags, libctx, propq);
    } else {
        return __real_CMS_sign_ex(signcert, pkey, certs, data, flags, libctx, propq);
    }
}

int __wrap_CMS_final(CMS_ContentInfo *cms, BIO *data, BIO *dcont, unsigned int flags)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock CMS_final");
        return X509OpensslMock::GetInstance().CMS_final(cms, data, dcont, flags);
    } else {
        return __real_CMS_final(cms, data, dcont, flags);
    }
}

ASN1_OCTET_STRING **__wrap_CMS_get0_content(CMS_ContentInfo *cms)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock CMS_get0_content");
        return X509OpensslMock::GetInstance().CMS_get0_content(cms);
    } else {
        return __real_CMS_get0_content(cms);
    }
}

STACK_OF(X509) *__wrap_CMS_get1_certs(CMS_ContentInfo *cms)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock CMS_get1_certs");
        return X509OpensslMock::GetInstance().CMS_get1_certs(cms);
    } else {
        return __real_CMS_get1_certs(cms);
    }
}

int __wrap_BIO_write(BIO *b, const void *data, int dlen)
{
    if (g_mockTagX509Openssl) {
        CF_LOG_I("X509OpensslMock BIO_write");
        return X509OpensslMock::GetInstance().BIO_write(b, data, dlen);
    } else {
        return __real_BIO_write(b, data, dlen);
    }
}
#ifdef __cplusplus
}
#endif
