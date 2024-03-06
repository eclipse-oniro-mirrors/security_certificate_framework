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
#include <openssl/x509v3.h>

#include "certificate_openssl_common.h"
#include "x509_certificate.h"
#include "x509_certificate_openssl.h"

namespace CFMock {
class X509OpensslMock {
public:
    MOCK_METHOD2(i2d_X509_EXTENSIONS, int(X509_EXTENSIONS *a, unsigned char **out));
    MOCK_METHOD1(OPENSSL_sk_num, int(const OPENSSL_STACK *st));
    MOCK_METHOD1(X509_getm_notBefore, ASN1_TIME *(const X509 *x));
    MOCK_METHOD1(X509_getm_notAfter, ASN1_TIME *(const X509 *x));
    MOCK_METHOD3(X509_NAME_oneline, char *(const X509_NAME *a, char *buf, int size));
    MOCK_METHOD2(i2d_X509, int(X509 *a, unsigned char **out));
    MOCK_METHOD2(BIO_new_mem_buf, BIO *(const void *buf, int len));
    MOCK_METHOD2(OPENSSL_sk_value, void *(const OPENSSL_STACK *st, int i));
    MOCK_METHOD2(HcfX509CertificateCreate, CfResult(const CfEncodingBlob *inStream, HcfX509Certificate **returnObj));
    MOCK_METHOD0(OPENSSL_sk_new_null, OPENSSL_STACK *(void));
    MOCK_METHOD2(X509_STORE_add_cert, int(X509_STORE *ctx, X509 *x));
    MOCK_METHOD0(X509_STORE_CTX_new, X509_STORE_CTX *(void));
    MOCK_METHOD0(X509_STORE_new, X509_STORE *(void));
    MOCK_METHOD4(X509_STORE_CTX_init, int(X509_STORE_CTX *ctx, X509_STORE *store, X509 *x509, STACK_OF(X509) * chain));
    MOCK_METHOD1(X509_verify_cert, int(X509_STORE_CTX *ctx));
    MOCK_METHOD2(i2d_PUBKEY, int(EVP_PKEY *a, unsigned char **pp));
    MOCK_METHOD4(X509_get_ext_d2i, void *(const X509 *x, int nid, int *crit, int *idx));
    MOCK_METHOD2(i2d_ASN1_OCTET_STRING, int(ASN1_OCTET_STRING *a, unsigned char **out));
    MOCK_METHOD2(i2d_AUTHORITY_KEYID, int(AUTHORITY_KEYID *a, unsigned char **out));
    MOCK_METHOD3(DeepCopyDataToBlob, CfResult(const unsigned char *data, uint32_t len, CfBlob *outBlob));
    MOCK_METHOD0(ASN1_TIME_new, ASN1_TIME *(void));
    MOCK_METHOD1(X509_get0_serialNumber, const ASN1_INTEGER *(const X509 *x));
    MOCK_METHOD2(i2d_ASN1_INTEGER, int(ASN1_INTEGER *a, unsigned char **out));
    MOCK_METHOD1(X509_get_pubkey, EVP_PKEY *(X509 *x));
    MOCK_METHOD1(OBJ_nid2obj, ASN1_OBJECT *(int n));
    MOCK_METHOD4(OBJ_obj2txt, int(char *buf, int buf_len, const ASN1_OBJECT *a, int no_name));
    MOCK_METHOD3(BN_bin2bn, BIGNUM *(const unsigned char *s, int len, BIGNUM *ret));
    MOCK_METHOD1(ASN1_TIME_normalize, int(ASN1_TIME *s));
    MOCK_METHOD4(
        X509_ALGOR_get0, void(const ASN1_OBJECT **paobj, int *pptype, const void **ppval, const X509_ALGOR *algor));
    MOCK_METHOD0(ASN1_TYPE_new, ASN1_TYPE *(void));
    MOCK_METHOD3(ASN1_TYPE_set1, int(ASN1_TYPE *a, int type, const void *value));
    MOCK_METHOD2(i2d_ASN1_TYPE, int(ASN1_TYPE *a, unsigned char **out));
    MOCK_METHOD1(ASN1_INTEGER_get, long(const ASN1_INTEGER *a));
    MOCK_METHOD1(ASN1_STRING_get0_data, const unsigned char *(const ASN1_STRING *x));
    MOCK_METHOD2(i2d_GENERAL_NAME, int(GENERAL_NAME *a, unsigned char **out));
    MOCK_METHOD2(X509_get_ext, X509_EXTENSION *(const X509 *x, X509_EXTENSION *loc));
    MOCK_METHOD1(X509V3_EXT_d2i, void *(X509_EXTENSION *ext));
    MOCK_METHOD2(GENERAL_NAME_get0_value, void *(const GENERAL_NAME *a, int *ptype));
    MOCK_METHOD2(X509_verify, int(X509 *a, EVP_PKEY *r));
    MOCK_METHOD2(DeepCopyBlobToBlob, CfResult(const CfBlob *inBlob, CfBlob **outBlob));
    MOCK_METHOD2(OPENSSL_sk_push, int(OPENSSL_STACK *st, const int data));
    MOCK_METHOD2(i2d_X509_REVOKED, int(X509_REVOKED *a, unsigned char **out));
    MOCK_METHOD2(i2d_X509_CRL, int(X509_CRL *a, unsigned char **out));
    MOCK_METHOD3(
        OPENSSL_sk_deep_copy, OPENSSL_STACK *(const OPENSSL_STACK *, OPENSSL_sk_copyfunc c, OPENSSL_sk_freefunc f));
    MOCK_METHOD1(OBJ_obj2nid, int(const ASN1_OBJECT *o));
    MOCK_METHOD1(X509_dup, X509 *(X509 *x509));

    static X509OpensslMock &GetInstance(void);
    static void SetMockFlag(bool flag);
    static bool GetMockFlag(void);

private:
    X509OpensslMock();
    virtual ~X509OpensslMock();

    void SetMockFunDefaultBehaviorPartOne(void);
    void SetMockFunDefaultBehaviorPartTwo(void);
    void SetMockFunDefaultBehaviorPartThree(void);
};
} // namespace CFMock
#endif /* CF_MOCK_H */
