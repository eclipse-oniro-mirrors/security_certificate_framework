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

#ifndef CF_MOCK_H
#define CF_MOCK_H
#include <gmock/gmock.h>
#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/ocsp.h>
#include <openssl/x509v3.h>

#include "certificate_openssl_common.h"
#include "x509_certificate.h"
#include "x509_certificate_openssl.h"

using ::testing::NiceMock;

namespace CFMock {
class X509OpensslMock {
public:
    MOCK_METHOD(int, i2d_X509_EXTENSIONS, (X509_EXTENSIONS * a, unsigned char **out));
    MOCK_METHOD(int, OPENSSL_sk_num, (const OPENSSL_STACK *st));
    MOCK_METHOD(ASN1_TIME *, X509_getm_notBefore, (const X509 *x));
    MOCK_METHOD(ASN1_TIME *, X509_getm_notAfter, (const X509 *x));
    MOCK_METHOD(char *, X509_NAME_oneline, (const X509_NAME *a, char *buf, int size));
    MOCK_METHOD(int, i2d_X509, (X509 * a, unsigned char **out));
    MOCK_METHOD(BIO *, BIO_new_mem_buf, (const void *buf, int len));
    MOCK_METHOD(void *, OPENSSL_sk_value, (const OPENSSL_STACK *st, int i));
    MOCK_METHOD(CfResult, HcfX509CertificateCreate, (const CfEncodingBlob *inStream, HcfX509Certificate **returnObj));
    MOCK_METHOD(OPENSSL_STACK *, OPENSSL_sk_new_null, ());
    MOCK_METHOD(int, X509_STORE_add_cert, (X509_STORE * ctx, X509 *x));
    MOCK_METHOD(X509_STORE_CTX *, X509_STORE_CTX_new, ());
    MOCK_METHOD(X509_STORE *, X509_STORE_new, ());
    MOCK_METHOD(
        int, X509_STORE_CTX_init, (X509_STORE_CTX * ctx, X509_STORE *store, X509 *x509, STACK_OF(X509) * chain));
    MOCK_METHOD(int, X509_verify_cert, (X509_STORE_CTX * ctx));
    MOCK_METHOD(int, i2d_PUBKEY, (EVP_PKEY * a, unsigned char **pp));
    MOCK_METHOD(void *, X509_get_ext_d2i, (const X509 *x, int nid, int *crit, int *idx));
    MOCK_METHOD(int, i2d_ASN1_OCTET_STRING, (ASN1_OCTET_STRING * a, unsigned char **out));
    MOCK_METHOD(int, i2d_AUTHORITY_KEYID, (AUTHORITY_KEYID * a, unsigned char **out));
    MOCK_METHOD(CfResult, DeepCopyDataToBlob, (const unsigned char *data, uint32_t len, CfBlob *outBlob));
    MOCK_METHOD(ASN1_TIME *, ASN1_TIME_new, ());
    MOCK_METHOD(const ASN1_INTEGER *, X509_get0_serialNumber, (const X509 *x));
    MOCK_METHOD(int, i2d_ASN1_INTEGER, (ASN1_INTEGER * a, unsigned char **out));
    MOCK_METHOD(EVP_PKEY *, X509_get_pubkey, (X509 * x));
    MOCK_METHOD(ASN1_OBJECT *, OBJ_nid2obj, (int n));
    MOCK_METHOD(int, OBJ_obj2txt, (char *buf, int buf_len, const ASN1_OBJECT *a, int no_name));
    MOCK_METHOD(BIGNUM *, BN_bin2bn, (const unsigned char *s, int len, BIGNUM *ret));
    MOCK_METHOD(int, ASN1_TIME_normalize, (ASN1_TIME * s));
    MOCK_METHOD(
        void, X509_ALGOR_get0, (const ASN1_OBJECT **paobj, int *pptype, const void **ppval, const X509_ALGOR *algor));
    MOCK_METHOD(ASN1_TYPE *, ASN1_TYPE_new, ());
    MOCK_METHOD(int, ASN1_TYPE_set1, (ASN1_TYPE * a, int type, const void *value));
    MOCK_METHOD(int, i2d_ASN1_TYPE, (ASN1_TYPE * a, unsigned char **out));
    MOCK_METHOD(long, ASN1_INTEGER_get, (const ASN1_INTEGER *a));
    MOCK_METHOD(const unsigned char *, ASN1_STRING_get0_data, (const ASN1_STRING *x));
    MOCK_METHOD(int, i2d_GENERAL_NAME, (GENERAL_NAME * a, unsigned char **out));
    MOCK_METHOD(X509_EXTENSION *, X509_get_ext, (const X509 *x, X509_EXTENSION *loc));
    MOCK_METHOD(void *, X509V3_EXT_d2i, (X509_EXTENSION * ext));
    MOCK_METHOD(void *, GENERAL_NAME_get0_value, (const GENERAL_NAME *a, int *ptype));
    MOCK_METHOD(int, X509_verify, (X509 * a, EVP_PKEY *r));
    MOCK_METHOD(CfResult, DeepCopyBlobToBlob, (const CfBlob *inBlob, CfBlob **outBlob));
    MOCK_METHOD(int, OPENSSL_sk_push, (OPENSSL_STACK * st, const int data));
    MOCK_METHOD(int, i2d_X509_REVOKED, (X509_REVOKED * a, unsigned char **out));
    MOCK_METHOD(int, i2d_X509_CRL, (X509_CRL * a, unsigned char **out));
    MOCK_METHOD(
        OPENSSL_STACK *, OPENSSL_sk_deep_copy, (const OPENSSL_STACK *, OPENSSL_sk_copyfunc c, OPENSSL_sk_freefunc f));
    MOCK_METHOD(int, OBJ_obj2nid, (const ASN1_OBJECT *o));
    MOCK_METHOD(X509 *, X509_dup, (X509 * x509));
    MOCK_METHOD(int, X509_check_host, (X509 * x, const char *chk, size_t chklen, unsigned int flags, char **peername));
    MOCK_METHOD(OCSP_REQUEST *, OCSP_REQUEST_new, ());
    MOCK_METHOD(X509_CRL *, X509_CRL_load_http, (const char *url, BIO *bio, BIO *rbio, int timeout));
    MOCK_METHOD(struct stack_st_OPENSSL_STRING *, X509_get1_ocsp, (X509 * x));
    MOCK_METHOD(int, OSSL_HTTP_parse_url,
        (const char *url, int *pssl, char **puser, char **phost, char **pport, int *pport_num, char **ppath,
            char **pquery, char **pfrag));

    MOCK_METHOD(int, X509_NAME_get0_der, (X509_NAME * nm, const unsigned char **pder, size_t *pderlen));
    MOCK_METHOD(const char *, OBJ_nid2sn, (int n));
    MOCK_METHOD(int, ASN1_STRING_length, (const ASN1_STRING *x));
    MOCK_METHOD(CfResult, DeepCopyDataToOut, (const char *data, uint32_t len, CfBlob *out));
    MOCK_METHOD(char *, CRYPTO_strdup, (const char *str, const char *file, int line));
    MOCK_METHOD(X509_NAME *, X509_NAME_new, ());
    MOCK_METHOD(int, OBJ_txt2nid, (const char *s));
    MOCK_METHOD(int, X509_NAME_add_entry_by_NID,
        (X509_NAME * name, int nid, int type, const unsigned char *bytes, int len, int loc, int set));
    MOCK_METHOD(BIO *, BIO_new, (const BIO_METHOD *type));
    MOCK_METHOD(int, X509_print, (BIO * bp, X509 *x));
    MOCK_METHOD(int, BIO_ctrl, (BIO * bp, int cmd, long larg, void *parg));
    MOCK_METHOD(int, i2d_X509_bio, (BIO * bp, X509 *x509));

    static NiceMock<X509OpensslMock> &GetInstance(void);
    static void SetMockFlag(bool flag);
    static bool GetMockFlag(void);

    X509OpensslMock();
    ~X509OpensslMock();

private:
    void SetMockFunDefaultBehaviorPartOne(void);
    void SetMockFunDefaultBehaviorPartTwo(void);
    void SetMockFunDefaultBehaviorPartThree(void);
    void SetMockFunDefaultBehaviorPartFour(void);
};
} // namespace CFMock
#endif /* CF_MOCK_H */
