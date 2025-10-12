/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>

#include <openssl/pem.h>

#include "cert_crl_common.h"
#include "cf_blob.h"
#include "cf_log.h"
#include "cf_mock.h"
#include "cf_object_base.h"
#include "cf_result.h"
#include "crypto_x509_test_common.h"
#include "memory_mock.h"
#include "securec.h"
#include "string"
#include "x509_cert_chain.h"
#include "x509_cert_chain_openssl.h"
#include "x509_certificate_openssl.h"

using namespace std;
using namespace testing::ext;
using namespace CFMock;

using ::testing::_;
using ::testing::AnyNumber;
using ::testing::Invoke;
using ::testing::Return;

#ifdef __cplusplus
extern "C" {
#endif

int __real_OPENSSL_sk_num(const OPENSSL_STACK *st);
void *__real_OPENSSL_sk_value(const OPENSSL_STACK *st, int i);
int __real_OPENSSL_sk_push(OPENSSL_STACK *st, const void *data);
OPENSSL_STACK *__real_OPENSSL_sk_new_null(void);
void *__real_X509_get_ext_d2i(const X509 *x, int nid, int *crit, int *idx);
X509_CRL *__real_X509_CRL_load_http(const char *url, BIO *bio, BIO *rbio, int timeout);
OCSP_REQUEST *__real_OCSP_REQUEST_new(void);
struct stack_st_OPENSSL_STRING *__real_X509_get1_ocsp(X509 *x);
int __real_OSSL_HTTP_parse_url(const char *url, int *pssl, char **puser, char **phost, char **pport, int *pport_num,
    char **ppath, char **pquery, char **pfrag);
BIO *__real_BIO_new_mem_buf(const void *buf, int len);
CfResult __real_HcfX509CertificateCreate(const CfEncodingBlob *inStream, HcfX509Certificate **returnObj);
int __real_i2d_X509(X509 *a, unsigned char **out);
int __real_X509_STORE_add_cert(X509_STORE *ctx, X509 *x);
X509_STORE_CTX *__real_X509_STORE_CTX_new(void);
X509_STORE *__real_X509_STORE_new(void);
int __real_X509_STORE_CTX_init(X509_STORE_CTX *ctx, X509_STORE *store, X509 *x509, STACK_OF(X509) * chain);
int __real_X509_verify_cert(X509_STORE_CTX *ctx);
int __real_i2d_PUBKEY(EVP_PKEY *a, unsigned char **pp);
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
int __real_i2d_X509_REVOKED(X509_REVOKED *a, unsigned char **out);
int __real_i2d_X509_CRL(X509_CRL *a, unsigned char **out);
OPENSSL_STACK *__real_OPENSSL_sk_deep_copy(const OPENSSL_STACK *, OPENSSL_sk_copyfunc c, OPENSSL_sk_freefunc f);
int __real_OBJ_obj2nid(const ASN1_OBJECT *o);
X509 *__real_X509_dup(X509 *x509);
int __real_i2d_X509_EXTENSIONS(X509_EXTENSIONS *a, unsigned char **out);
int __real_X509_check_host(X509 *x, const char *chk, size_t chklen, unsigned int flags, char **peername);
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

int PKCS12_parse_mock(PKCS12 *p12, const char *pass, EVP_PKEY **pkey, X509 **cert, STACK_OF(X509) **ca) {
    CF_LOG_I("PKCS12_parse_mock");
    *cert  = X509_new();
    if (*cert == nullptr) {
        CF_LOG_E("Failed to malloc cert.");
        return 0;
    }
    return 1;
}

#ifdef __cplusplus
}
#endif

void ResetMockFunctionPartOne(void)
{
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        OPENSSL_sk_num(_)).Times(AnyNumber()).WillRepeatedly(Invoke(__real_OPENSSL_sk_num));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        OPENSSL_sk_value(_, _)).Times(AnyNumber()).WillRepeatedly(Invoke(__real_OPENSSL_sk_value));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        BIO_new_mem_buf(_, _)).Times(AnyNumber()).WillRepeatedly(Invoke(__real_BIO_new_mem_buf));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        HcfX509CertificateCreate(_, _)).Times(AnyNumber()).WillRepeatedly(Invoke(__real_HcfX509CertificateCreate));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        OPENSSL_sk_new_null()).Times(AnyNumber()).WillRepeatedly(Invoke(__real_OPENSSL_sk_new_null));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        i2d_X509(_, _)).Times(AnyNumber()).WillRepeatedly(Invoke(__real_i2d_X509));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        X509_STORE_add_cert(_, _)).Times(AnyNumber()).WillRepeatedly(Invoke(__real_X509_STORE_add_cert));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        X509_STORE_CTX_new()).Times(AnyNumber()).WillRepeatedly(Invoke(__real_X509_STORE_CTX_new));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        X509_STORE_new()).Times(AnyNumber()).WillRepeatedly(Invoke(__real_X509_STORE_new));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        X509_STORE_CTX_init(_, _, _, _)).Times(AnyNumber()).WillRepeatedly(Invoke(__real_X509_STORE_CTX_init));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        X509_verify_cert(_)).Times(AnyNumber()).WillRepeatedly(Invoke(__real_X509_verify_cert));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        i2d_PUBKEY(_, _)).Times(AnyNumber()).WillRepeatedly(Invoke(__real_i2d_PUBKEY));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        X509_get_ext_d2i(_, _, _, _)).Times(AnyNumber()).WillRepeatedly(Invoke(__real_X509_get_ext_d2i));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        i2d_ASN1_OCTET_STRING(_, _)).Times(AnyNumber()).WillRepeatedly(Invoke(__real_i2d_ASN1_OCTET_STRING));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        i2d_AUTHORITY_KEYID(_, _)).Times(AnyNumber()).WillRepeatedly(Invoke(__real_i2d_AUTHORITY_KEYID));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        DeepCopyDataToBlob(_, _, _)).Times(AnyNumber()).WillRepeatedly(Invoke(__real_DeepCopyDataToBlob));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        ASN1_TIME_new()).Times(AnyNumber()).WillRepeatedly(Invoke(__real_ASN1_TIME_new));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        X509_get_pubkey(_)).Times(AnyNumber()).WillRepeatedly(Invoke(__real_X509_get_pubkey));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        OBJ_nid2obj(_)).Times(AnyNumber()).WillRepeatedly(Invoke(__real_OBJ_nid2obj));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        OBJ_obj2txt(_, _, _, _)).Times(AnyNumber()).WillRepeatedly(Invoke(__real_OBJ_obj2txt));
}

void ResetMockFunctionPartTwo(void)
{
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        BN_bin2bn(_, _, _)).Times(AnyNumber()).WillRepeatedly(Invoke(__real_BN_bin2bn));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        X509_get0_serialNumber(_)).Times(AnyNumber()).WillRepeatedly(Invoke(__real_X509_get0_serialNumber));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        i2d_ASN1_INTEGER(_, _)).Times(AnyNumber()).WillRepeatedly(Invoke(__real_i2d_ASN1_INTEGER));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        ASN1_TIME_normalize(_)).Times(AnyNumber()).WillRepeatedly(Invoke(__real_ASN1_TIME_normalize));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        X509_getm_notBefore(_)).Times(AnyNumber()).WillRepeatedly(Invoke(__real_X509_getm_notBefore));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        X509_getm_notAfter(_)).Times(AnyNumber()).WillRepeatedly(Invoke(__real_X509_getm_notAfter));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        X509_ALGOR_get0(_, _, _, _)).Times(AnyNumber()).WillRepeatedly(Invoke(__real_X509_ALGOR_get0));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        ASN1_TYPE_new()).Times(AnyNumber()).WillRepeatedly(Invoke(__real_ASN1_TYPE_new));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        ASN1_TYPE_set1(_, _, _)).Times(AnyNumber()).WillRepeatedly(Invoke(__real_ASN1_TYPE_set1));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        i2d_ASN1_TYPE(_, _)).Times(AnyNumber()).WillRepeatedly(Invoke(__real_i2d_ASN1_TYPE));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        ASN1_INTEGER_get(_)).Times(AnyNumber()).WillRepeatedly(Invoke(__real_ASN1_INTEGER_get));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        ASN1_STRING_get0_data(_)).Times(AnyNumber()).WillRepeatedly(Invoke(__real_ASN1_STRING_get0_data));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        i2d_GENERAL_NAME(_, _)).Times(AnyNumber()).WillRepeatedly(Invoke(__real_i2d_GENERAL_NAME));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        X509_get_ext(_, _)).Times(AnyNumber()).WillRepeatedly(Invoke(__real_X509_get_ext));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        X509V3_EXT_d2i(_)).Times(AnyNumber()).WillRepeatedly(Invoke(__real_X509V3_EXT_d2i));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        GENERAL_NAME_get0_value(_, _)).Times(AnyNumber()).WillRepeatedly(Invoke(__real_GENERAL_NAME_get0_value));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        X509_verify(_, _)).Times(AnyNumber()).WillRepeatedly(Invoke(__real_X509_verify));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        DeepCopyBlobToBlob(_, _)).Times(AnyNumber()).WillRepeatedly(Invoke(__real_DeepCopyBlobToBlob));
}

void ResetMockFunctionPartThree(void)
{
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        X509_NAME_oneline(_, _, _)).Times(AnyNumber()).WillRepeatedly(Invoke(__real_X509_NAME_oneline));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        OPENSSL_sk_push(_, _)).Times(AnyNumber()).WillRepeatedly(Invoke(__real_OPENSSL_sk_push));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        i2d_X509_REVOKED(_, _)).Times(AnyNumber()).WillRepeatedly(Invoke(__real_i2d_X509_REVOKED));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        i2d_X509_CRL(_, _)).Times(AnyNumber()).WillRepeatedly(Invoke(__real_i2d_X509_CRL));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        OPENSSL_sk_deep_copy(_, _, _)).Times(AnyNumber()).WillRepeatedly(Invoke(__real_OPENSSL_sk_deep_copy));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        OBJ_obj2nid(_)).Times(AnyNumber()).WillRepeatedly(Invoke(__real_OBJ_obj2nid));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        X509_dup(_)).Times(AnyNumber()).WillRepeatedly(Invoke(__real_X509_dup));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        i2d_X509_EXTENSIONS(_, _)).Times(AnyNumber()).WillRepeatedly(Invoke(__real_i2d_X509_EXTENSIONS));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        X509_check_host(_, _, _, _, _)).Times(AnyNumber()).WillRepeatedly(Invoke(__real_X509_check_host));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        OCSP_REQUEST_new()).Times(AnyNumber()).WillRepeatedly(Invoke(__real_OCSP_REQUEST_new));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        X509_CRL_load_http(_, _, _, _)).Times(AnyNumber()).WillRepeatedly(Invoke(__real_X509_CRL_load_http));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        X509_get1_ocsp(_)).Times(AnyNumber()).WillRepeatedly(Invoke(__real_X509_get1_ocsp));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        OSSL_HTTP_parse_url(_, _, _, _, _, _, _, _, _)).
        Times(AnyNumber()).WillRepeatedly(Invoke(__real_OSSL_HTTP_parse_url));
}

void ResetMockFunctionPartFour(void)
{
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        X509_NAME_get0_der(_, _, _)).Times(AnyNumber()).WillRepeatedly(Invoke(__real_X509_NAME_get0_der));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        OBJ_nid2sn(_)).Times(AnyNumber()).WillRepeatedly(Invoke(__real_OBJ_nid2sn));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        ASN1_STRING_length(_)).Times(AnyNumber()).WillRepeatedly(Invoke(__real_ASN1_STRING_length));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        DeepCopyDataToOut(_, _, _)).Times(AnyNumber()).WillRepeatedly(Invoke(__real_DeepCopyDataToOut));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        CRYPTO_strdup(_, _, _)).Times(AnyNumber()).WillRepeatedly(Invoke(__real_CRYPTO_strdup));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        X509_NAME_new()).Times(AnyNumber()).WillRepeatedly(Invoke(__real_X509_NAME_new));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        OBJ_txt2nid(_)).Times(AnyNumber()).WillRepeatedly(Invoke(__real_OBJ_txt2nid));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        X509_NAME_add_entry_by_NID(_, _, _, _, _, _, _)).
        Times(AnyNumber()).WillRepeatedly(Invoke(__real_X509_NAME_add_entry_by_NID));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        BIO_new(_)).Times(AnyNumber()).WillRepeatedly(Invoke(__real_BIO_new));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        X509_print(_, _)).Times(AnyNumber()).WillRepeatedly(Invoke(__real_X509_print));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        BIO_ctrl(_, _, _, _)).Times(AnyNumber()).WillRepeatedly(Invoke(__real_BIO_ctrl));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        i2d_X509_bio(_, _)).Times(AnyNumber()).WillRepeatedly(Invoke(__real_i2d_X509_bio));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        PKCS12_parse(_, _, _, _, _)).Times(AnyNumber()).WillRepeatedly(Invoke(__real_PKCS12_parse));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        CheckIsSelfSigned(_)).Times(AnyNumber()).WillRepeatedly(Invoke(__real_CheckIsSelfSigned));
}

void ResetMockFunction(void)
{
    ResetMockFunctionPartOne();
    ResetMockFunctionPartTwo();
    ResetMockFunctionPartThree();
    ResetMockFunctionPartFour();
}

namespace {
class CryptoX509CertChainTestPart2 : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

static HcfX509CertChainSpi *g_certChainPemSpi = nullptr;
static HcfX509CertChainSpi *g_certChainPemSpi163 = nullptr;

static CfBlob g_blobDownloadURI = { .size = strlen(g_crlDownloadURI) + 1,
    .data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_crlDownloadURI)) };

static CfBlob g_ocspDigest = { .size = strlen(g_digest) + 1,
    .data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_digest)) };

static void FreeHcfRevocationCheckParam(HcfRevocationCheckParam *param)
{
    if (param == nullptr) {
        return;
    }

    if (param->options != nullptr) {
        if (param->options->data != nullptr) {
            CfFree(param->options->data);
        }

        CfFree(param->options);
    }

    if (param->ocspResponses != nullptr) {
        CfFree(param->ocspResponses);
    }

    if (param->ocspResponderCert != nullptr) {
        CfObjDestroy(param->ocspResponderCert);
    }

    CfFree(param);
}

static HcfRevocationCheckParam *ConstructHcfRevocationCheckParam(HcfRevChkOption *data, size_t size,
    CfBlob *ocspResponderURI = NULL, CfBlob *crlDownloadURI = NULL,
    const CfEncodingBlob *ocspResponderCertStream = NULL)
{
    HcfRevChkOpArray *revChkOpArray = (HcfRevChkOpArray *)CfMalloc(sizeof(HcfRevChkOpArray), 0);
    if (revChkOpArray == nullptr) {
        return nullptr;
    }

    revChkOpArray->count = size;
    revChkOpArray->data = (HcfRevChkOption *)CfMalloc(revChkOpArray->count * sizeof(HcfRevChkOption), 0);
    if (revChkOpArray->data == nullptr) {
        CfFree(revChkOpArray);
        return nullptr;
    }

    for (size_t i = 0; i < revChkOpArray->count; i++) {
        revChkOpArray->data[i] = data[i];
    }

    CfBlob *resp = (CfBlob *)CfMalloc(sizeof(CfBlob), 0);
    if (resp == nullptr) {
        CfFree(revChkOpArray->data);
        CfFree(revChkOpArray);
        return nullptr;
    }
    resp->data = (uint8_t *)(&g_testOcspResponses[0]);
    resp->size = sizeof(g_testOcspResponses);

    HcfRevocationCheckParam *param = (HcfRevocationCheckParam *)CfMalloc(sizeof(HcfRevocationCheckParam), 0);
    if (param == nullptr) {
        CfFree(revChkOpArray->data);
        CfFree(revChkOpArray);
        return nullptr;
    }

    param->options = revChkOpArray;
    param->ocspResponses = resp;
    param->ocspResponderURI = ocspResponderURI;
    param->crlDownloadURI = crlDownloadURI;
    param->ocspDigest = &g_ocspDigest;

    if (ocspResponderCertStream != NULL) {
        (void)HcfX509CertificateCreate(&g_inStreamOcspResponderCert, &(param->ocspResponderCert));
        if (param->ocspResponderCert == nullptr) {
            FreeHcfRevocationCheckParam(param);
            return nullptr;
        }
    }

    return param;
}

void CryptoX509CertChainTestPart2::SetUpTestCase()
{
    CfResult ret;

    HcfX509CertChainSpi *certChainSpi = nullptr;
    ret = HcfX509CertChainByEncSpiCreate(&g_inStreamChainDataPem, &certChainSpi);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainSpi, nullptr);
    g_certChainPemSpi = certChainSpi;

    certChainSpi = nullptr;
    ret = HcfX509CertChainByEncSpiCreate(&g_inStreamChainDataPem163, &certChainSpi);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainSpi, nullptr);
    g_certChainPemSpi163 = certChainSpi;
}

void CryptoX509CertChainTestPart2::TearDownTestCase()
{
    CfObjDestroy(g_certChainPemSpi);
    CfObjDestroy(g_certChainPemSpi163);
}

void CryptoX509CertChainTestPart2::SetUp() {}

void CryptoX509CertChainTestPart2::TearDown() {}

HWTEST_F(CryptoX509CertChainTestPart2, ValidateOpensslPolicyTest001, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslPolicyTest001");
    ASSERT_NE(g_certChainPemSpi, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainDataPemRoot, trustAnchorArray);

    HcfX509CertChainValidateParams params = { 0 };
    params.trustAnchors = &trustAnchorArray;

    HcfX509CertChainValidateResult result = { 0 };
    CfResult ret;

    // test ValidatePolicy failed case
    params.policy = (HcfValPolicyType)-1;
    ret = g_certChainPemSpi->engineValidate(g_certChainPemSpi, &params, &result);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    params.policy = VALIDATION_POLICY_TYPE_SSL;
    ret = g_certChainPemSpi->engineValidate(g_certChainPemSpi, &params, &result);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    CfBlob sslHostname = { 0 };
    params.sslHostname = &sslHostname;
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_check_host(_, _, _, _, _)).WillRepeatedly(Return(0));
    ret = g_certChainPemSpi->engineValidate(g_certChainPemSpi, &params, &result);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    FreeTrustAnchorArr(trustAnchorArray);
}

HWTEST_F(CryptoX509CertChainTestPart2, ValidateOpensslUseageTest001, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslUseageTest001");
    ASSERT_NE(g_certChainPemSpi, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainDataPemRoot, trustAnchorArray);

    HcfX509CertChainValidateParams params = { 0 };
    params.trustAnchors = &trustAnchorArray;

    HcfKuArray kuArray = { 0 };
    kuArray.count = 9;
    kuArray.data = (HcfKeyUsageType *)CfMalloc(kuArray.count * sizeof(HcfKeyUsageType), 0);
    kuArray.data[0] = KEYUSAGE_DIGITAL_SIGNATURE;
    kuArray.data[1] = KEYUSAGE_NON_REPUDIATION;
    kuArray.data[2] = KEYUSAGE_KEY_ENCIPHERMENT;
    kuArray.data[3] = KEYUSAGE_DATA_ENCIPHERMENT;
    kuArray.data[4] = KEYUSAGE_KEY_AGREEMENT;
    kuArray.data[5] = KEYUSAGE_KEY_CERT_SIGN;
    kuArray.data[6] = KEYUSAGE_CRL_SIGN;
    kuArray.data[7] = KEYUSAGE_ENCIPHER_ONLY;
    kuArray.data[8] = KEYUSAGE_DECIPHER_ONLY;

    params.keyUsage = &kuArray;

    HcfX509CertChainValidateResult result = { 0 };
    CfResult ret;

    ret = g_certChainPemSpi->engineValidate(g_certChainPemSpi, &params, &result);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);

    kuArray.data[8] = (HcfKeyUsageType)-1;
    ret = g_certChainPemSpi->engineValidate(g_certChainPemSpi, &params, &result);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    // test ValidatePolicy failed case
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), OPENSSL_sk_value(_, _))
        .WillOnce(Return(nullptr))
        .WillRepeatedly(Invoke(__real_OPENSSL_sk_value));
    ret = g_certChainPemSpi->engineValidate(g_certChainPemSpi, &params, &result);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);
    X509OpensslMock::SetMockFlag(false);

    CfFree(kuArray.data);
    FreeTrustAnchorArr(trustAnchorArray);
}

HWTEST_F(CryptoX509CertChainTestPart2, ValidateOpensslPart2Test001, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslPart2Test001");
    ASSERT_NE(g_certChainPemSpi, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainDataPemRoot, trustAnchorArray);

    HcfX509CertChainValidateParams params = { 0 };
    params.trustAnchors = &trustAnchorArray;

    HcfX509CertChainValidateResult result = { 0 };
    CfResult ret;

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), OPENSSL_sk_value(_, _))
        .WillOnce(Return(nullptr))
        .WillRepeatedly(Invoke(__real_OPENSSL_sk_value));
    ret = g_certChainPemSpi->engineValidate(g_certChainPemSpi, &params, &result);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    FreeTrustAnchorArr(trustAnchorArray);
}

HWTEST_F(CryptoX509CertChainTestPart2, ValidateOpensslInvaidCertId, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslInvaidCertId");
    ASSERT_NE(g_certChainPemSpi, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainDataPemRoot, trustAnchorArray);

    HcfX509CertChainValidateParams params = { 0 };
    params.trustAnchors = &trustAnchorArray;

    HcfRevChkOpArray revChkOpArray = { 0 };
    revChkOpArray.count = 1;
    revChkOpArray.data = (HcfRevChkOption *)CfMalloc(revChkOpArray.count * sizeof(HcfRevChkOption), 0);
    ASSERT_NE(revChkOpArray.data, nullptr);
    revChkOpArray.data[0] = REVOCATION_CHECK_OPTION_PREFER_OCSP;

    HcfRevocationCheckParam rcp = { 0 };
    rcp.options = &revChkOpArray;
    params.revocationCheckParam = &rcp;

    HcfX509CertChainValidateResult result = { 0 };
    CfResult ret;

    // test ValidateOcspLocal failed case
    ret = g_certChainPemSpi->engineValidate(g_certChainPemSpi, &params, &result);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);
    FreeValidateResult(result);

    // test VerifyOcspSigner failed case
    CfBlob resp;
    resp.data = (uint8_t *)(&g_testOcspResponses[0]);
    resp.size = sizeof(g_testOcspResponses);
    rcp.ocspResponses = &resp;

    ret = g_certChainPemSpi->engineValidate(g_certChainPemSpi, &params, &result);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);
    FreeValidateResult(result);

    FreeTrustAnchorArr(trustAnchorArray);
    CfFree(revChkOpArray.data);
}

HWTEST_F(CryptoX509CertChainTestPart2, ValidateOpensslRevocationLocalTest001, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslRevocationLocalTest001");
    ASSERT_NE(g_certChainPemSpi163, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainDataPemRoot163, trustAnchorArray);

    HcfX509CertChainValidateParams params = { 0 };
    params.trustAnchors = &trustAnchorArray;

    HcfRevChkOption data[] = { REVOCATION_CHECK_OPTION_PREFER_OCSP };
    params.revocationCheckParam = ConstructHcfRevocationCheckParam(data, sizeof(data) / sizeof(data[0]));
    ASSERT_NE(params.revocationCheckParam, nullptr);

    HcfX509CertChainValidateResult result = { 0 };

    // test ValidateOcspLocal failed case
    CfResult ret = g_certChainPemSpi163->engineValidate(g_certChainPemSpi163, &params, &result);
    EXPECT_EQ(ret, CF_SUCCESS);
    FreeValidateResult(result);

    FreeTrustAnchorArr(trustAnchorArray);
    FreeHcfRevocationCheckParam(params.revocationCheckParam);
}

HWTEST_F(CryptoX509CertChainTestPart2, ValidateOpensslRevocationOnLineTest006, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslRevocationOnLineTest006");
    ASSERT_NE(g_certChainPemSpi163, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainDataPemRoot163, trustAnchorArray);

    HcfX509CertChainValidateParams params = { 0 };
    params.trustAnchors = &trustAnchorArray;

    HcfRevChkOption data[] = { REVOCATION_CHECK_OPTION_ACCESS_NETWORK };
    params.revocationCheckParam =
        ConstructHcfRevocationCheckParam(data, sizeof(data) / sizeof(data[0]), &g_blobDownloadURI, nullptr);
    ASSERT_NE(params.revocationCheckParam, nullptr);

    FreeTrustAnchorArr(trustAnchorArray);
    FreeHcfRevocationCheckParam(params.revocationCheckParam);
}

HWTEST_F(CryptoX509CertChainTestPart2, ValidateOpensslRevocationOnLineTest009, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslRevocationOnLineTest009");
    ASSERT_NE(g_certChainPemSpi163, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainDataPemRoot163, trustAnchorArray);

    HcfX509CertChainValidateParams params = { 0 };
    params.trustAnchors = &trustAnchorArray;

    HcfRevChkOption data[] = { REVOCATION_CHECK_OPTION_PREFER_OCSP, REVOCATION_CHECK_OPTION_FALLBACK_NO_PREFER,
        REVOCATION_CHECK_OPTION_FALLBACK_LOCAL };
    params.revocationCheckParam =
        ConstructHcfRevocationCheckParam(data, sizeof(data) / sizeof(data[0]), &g_blobDownloadURI);
    ASSERT_NE(params.revocationCheckParam, nullptr);

    HcfX509CertChainValidateResult result = { 0 };
    CfResult ret;

    CF_LOG_I("ValidateOpensslRevocationOnLineTest009 - 1");
    // test ValidateOcspLocal failed case
    ret = g_certChainPemSpi163->engineValidate(g_certChainPemSpi163, &params, &result);
    EXPECT_EQ(ret, CF_SUCCESS);
    FreeValidateResult(result);

    CF_LOG_I("ValidateOpensslRevocationOnLineTest009 - 2");
    (void)HcfX509CertificateCreate(&g_inStreamOcspResponderCert, &(params.revocationCheckParam->ocspResponderCert));
    ASSERT_NE(params.revocationCheckParam->ocspResponderCert, nullptr);
    ret = g_certChainPemSpi163->engineValidate(g_certChainPemSpi163, &params, &result);
    EXPECT_EQ(ret, CF_SUCCESS);
    FreeValidateResult(result);

    FreeTrustAnchorArr(trustAnchorArray);
    FreeHcfRevocationCheckParam(params.revocationCheckParam);
    CF_LOG_I("ValidateOpensslRevocationOnLineTest009 - ok");
}

HWTEST_F(CryptoX509CertChainTestPart2, ValidateOpensslRevocationOnLineTest010, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslRevocationOnLineTest010");
    ASSERT_NE(g_certChainPemSpi163, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainDataPemRoot163, trustAnchorArray);

    HcfX509CertChainValidateParams params = { 0 };
    params.trustAnchors = &trustAnchorArray;

    HcfRevChkOption data[] = { REVOCATION_CHECK_OPTION_FALLBACK_NO_PREFER, REVOCATION_CHECK_OPTION_FALLBACK_LOCAL };
    params.revocationCheckParam =
        ConstructHcfRevocationCheckParam(data, sizeof(data) / sizeof(data[0]), &g_blobDownloadURI);
    ASSERT_NE(params.revocationCheckParam, nullptr);

    HcfX509CertChainValidateResult result = { 0 };
    CfResult ret;

    CF_LOG_I("ValidateOpensslRevocationOnLineTest010 - 1");
    // test ValidateOcspLocal failed case
    ret = g_certChainPemSpi163->engineValidate(g_certChainPemSpi163, &params, &result);
    EXPECT_EQ(ret, CF_SUCCESS);
    FreeValidateResult(result);

    CF_LOG_I("ValidateOpensslRevocationOnLineTest010 - 2");
    (void)HcfX509CertificateCreate(&g_inStreamOcspResponderCert, &(params.revocationCheckParam->ocspResponderCert));
    ASSERT_NE(params.revocationCheckParam->ocspResponderCert, nullptr);
    ret = g_certChainPemSpi163->engineValidate(g_certChainPemSpi163, &params, &result);
    EXPECT_EQ(ret, CF_SUCCESS);
    FreeValidateResult(result);

    FreeTrustAnchorArr(trustAnchorArray);
    FreeHcfRevocationCheckParam(params.revocationCheckParam);
    CF_LOG_I("ValidateOpensslRevocationOnLineTest010 - ok");
}

static void BuildX509CertMatchParamsData(
    const CfEncodingBlob *certInStream, const CfEncodingBlob *crlInStream, HcfX509CertChainValidateParams *params)
{
    if (certInStream == nullptr || params == nullptr) {
        return;
    }

    CfBlob *blob = (CfBlob *)CfMalloc(sizeof(CfBlob), 0);
    ASSERT_NE(blob, nullptr);
    blob->data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testUpdateDateTime));
    blob->size = strlen(g_testUpdateDateTime) + 1;
    params->date = blob;

    HcfX509TrustAnchorArray *trustAnchorArray =
        (HcfX509TrustAnchorArray *)CfMalloc(sizeof(HcfX509TrustAnchorArray), 0);
    ASSERT_NE(trustAnchorArray, nullptr);
    BuildAnchorArr(*certInStream, *trustAnchorArray);

    HcfCertCRLCollectionArray *certCRLCollections =
        (HcfCertCRLCollectionArray *)CfMalloc(sizeof(HcfCertCRLCollectionArray), 0);
    ASSERT_NE(certCRLCollections, nullptr);
    BuildCollectionArr(certInStream, crlInStream, *certCRLCollections);

    params->trustAnchors = trustAnchorArray;
    params->certCRLCollections = certCRLCollections;
}

static void FreeX509CertMatchParamsData(HcfX509CertChainValidateParams *params)
{
    if (params == nullptr) {
        return;
    }

    if (params->date != nullptr) {
        CfFree(params->date);
        params->date = nullptr;
    }

    if (params->trustAnchors != nullptr) {
        FreeTrustAnchorArr(*(params->trustAnchors));
        CfFree(params->trustAnchors);
        params->trustAnchors = nullptr;
    }

    if (params->certCRLCollections != nullptr) {
        FreeCertCrlCollectionArr(*(params->certCRLCollections));
        CfFree(params->certCRLCollections);
        params->certCRLCollections = nullptr;
    }
}

HWTEST_F(CryptoX509CertChainTestPart2, HcfX509CertChainByParamsSpiCreateTest001, TestSize.Level0)
{
    CF_LOG_I("HcfX509CertChainByParamsSpiCreateTest001");
    HcfX509CertChainBuildParameters inParams;
    memset_s(&inParams, sizeof(HcfX509CertChainBuildParameters), 0, sizeof(HcfX509CertChainBuildParameters));
    HcfX509CertChainSpi *spi = nullptr;

    CfResult result;

    inParams.maxlength = -1;

    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testSelfSignedCaCertValid));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testSelfSignedCaCertValid) + 1;

    BuildX509CertMatchParamsData(&inStream, NULL, &inParams.validateParameters);

    CfBlob issue;
    issue.data = const_cast<uint8_t *>(g_testIssuerValid);
    issue.size = sizeof(g_testIssuerValid);
    inParams.certMatchParameters.issuer = &issue;
    inParams.certMatchParameters.minPathLenConstraint = -1;

    result = HcfX509CertChainByParamsSpiCreate(&inParams, &spi);
    EXPECT_EQ(result, CF_SUCCESS);
    EXPECT_NE(spi, nullptr);
    CfObjDestroy(spi);

    // test inParams.maxlength
    inParams.maxlength = 2;
    result = HcfX509CertChainByParamsSpiCreate(&inParams, &spi);
    EXPECT_EQ(result, CF_SUCCESS);
    EXPECT_NE(spi, nullptr);
    CfObjDestroy(spi);

    FreeX509CertMatchParamsData(&inParams.validateParameters);
}

HWTEST_F(CryptoX509CertChainTestPart2, HcfX509CertChainByParamsSpiCreateInvalidParamTest, TestSize.Level0)
{
    CF_LOG_I("HcfX509CertChainByParamsSpiCreateInvalidParamTest");
    HcfX509CertChainBuildParameters inParams;
    memset_s(&inParams, sizeof(HcfX509CertChainBuildParameters), 0, sizeof(HcfX509CertChainBuildParameters));
    HcfX509CertChainSpi *spi = nullptr;

    CfResult result = HcfX509CertChainByParamsSpiCreate(NULL, &spi);
    EXPECT_EQ(result, CF_INVALID_PARAMS);

    result = HcfX509CertChainByParamsSpiCreate(&inParams, NULL);
    EXPECT_EQ(result, CF_INVALID_PARAMS);

    result = HcfX509CertChainByParamsSpiCreate(NULL, NULL);
    EXPECT_EQ(result, CF_INVALID_PARAMS);
}

HWTEST_F(CryptoX509CertChainTestPart2, HcfX509CertChainByParamsSpiCreateTest002, TestSize.Level0)
{
    CF_LOG_I("HcfX509CertChainByParamsSpiCreateTest002");
    HcfX509CertChainBuildParameters inParams;
    memset_s(&inParams, sizeof(HcfX509CertChainBuildParameters), 0, sizeof(HcfX509CertChainBuildParameters));
    HcfX509CertChainSpi *spi = nullptr;

    inParams.maxlength = -1;

    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testSelfSignedCaCertValid));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testSelfSignedCaCertValid) + 1;

    BuildX509CertMatchParamsData(&inStream, NULL, &inParams.validateParameters);

    CfBlob issue;
    issue.data = const_cast<uint8_t *>(g_testIssuerValid);
    issue.size = sizeof(g_testIssuerValid);
    inParams.certMatchParameters.issuer = &issue;
    inParams.certMatchParameters.minPathLenConstraint = -1;

    // test HcfX509CertChainByParamsSpiCreate failed case
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), OPENSSL_sk_new_null())
        .WillOnce(Return(nullptr))
        .WillRepeatedly(Invoke(__real_OPENSSL_sk_new_null));
    CfResult result = HcfX509CertChainByParamsSpiCreate(&inParams, &spi);
    EXPECT_EQ(result, CF_ERR_MALLOC);
    X509OpensslMock::SetMockFlag(false);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), OPENSSL_sk_new_null())
        .WillOnce(Invoke(__real_OPENSSL_sk_new_null))
        .WillOnce(Return(nullptr))
        .WillRepeatedly(Invoke(__real_OPENSSL_sk_new_null));
    result = HcfX509CertChainByParamsSpiCreate(&inParams, &spi);
    EXPECT_EQ(result, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), OPENSSL_sk_new_null())
        .WillOnce(Invoke(__real_OPENSSL_sk_new_null))
        .WillOnce(Invoke(__real_OPENSSL_sk_new_null))
        .WillOnce(Return(nullptr))
        .WillRepeatedly(Invoke(__real_OPENSSL_sk_new_null));
    result = HcfX509CertChainByParamsSpiCreate(&inParams, &spi);
    EXPECT_EQ(result, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    // test CfMalloc failed case in HcfX509CertChainByParamsSpiCreate
    SetMockFlag(true);
    result = HcfX509CertChainByParamsSpiCreate(&inParams, &spi);
    EXPECT_EQ(result, CF_ERR_MALLOC);
    SetMockFlag(false);

    FreeX509CertMatchParamsData(&inParams.validateParameters);
}

HWTEST_F(CryptoX509CertChainTestPart2, HcfX509CertChainByParamsSpiCreateTest003, TestSize.Level0)
{
    CF_LOG_I("HcfX509CertChainByParamsSpiCreateTest003");
    HcfX509CertChainBuildParameters inParams;
    memset_s(&inParams, sizeof(HcfX509CertChainBuildParameters), 0, sizeof(HcfX509CertChainBuildParameters));
    HcfX509CertChainSpi *spi = nullptr;

    CfResult result;

    inParams.maxlength = -1;

    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testSelfSignedCaCertValid));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testSelfSignedCaCertValid) + 1;

    BuildX509CertMatchParamsData(&inStream, NULL, &inParams.validateParameters);

    CfBlob issue;
    issue.data = const_cast<uint8_t *>(g_testIssuerValid);
    issue.size = sizeof(g_testIssuerValid);
    inParams.certMatchParameters.issuer = &issue;
    inParams.certMatchParameters.minPathLenConstraint = -1;

    X509OpensslMock::SetMockFlag(true);
    ResetMockFunction();
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_dup(_))
        .WillOnce(Return(nullptr))
        .WillRepeatedly(Invoke(__real_X509_dup));
    result = HcfX509CertChainByParamsSpiCreate(&inParams, &spi);
    EXPECT_EQ(result, CF_ERR_MALLOC);

    ResetMockFunction();
    EXPECT_CALL(X509OpensslMock::GetInstance(), OPENSSL_sk_push(_, _))
        .WillOnce(Return(-1))
        .WillRepeatedly(Invoke(__real_OPENSSL_sk_push));
    result = HcfX509CertChainByParamsSpiCreate(&inParams, &spi);
    EXPECT_EQ(result, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);


    X509OpensslMock::SetHcfMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), CheckIsSelfSigned(_))
        .WillRepeatedly(Return(true))
        .RetiresOnSaturation();
    result = HcfX509CertChainByParamsSpiCreate(&inParams, &spi);
    EXPECT_EQ(result, CF_INVALID_PARAMS);
    X509OpensslMock::SetHcfMockFlag(false);

    FreeX509CertMatchParamsData(&inParams.validateParameters);
}

static void FreeHcfX509CertChainBuildResult(HcfX509CertChainBuildResult *result)
{
    if (result == nullptr) {
        return;
    }

    CfObjDestroy(result->certChain);
    CfFree(result);
}

HWTEST_F(CryptoX509CertChainTestPart2, HcfCertChainBuildResultCreateTest001, TestSize.Level0)
{
    CF_LOG_I("HcfCertChainBuildResultCreateTest001");
    HcfX509CertChainBuildParameters inParams;
    memset_s(&inParams, sizeof(HcfX509CertChainBuildParameters), 0, sizeof(HcfX509CertChainBuildParameters));
    HcfX509CertChainBuildResult *returnObj = nullptr;
    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testSelfSignedCaCertValid));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testSelfSignedCaCertValid) + 1;

    BuildX509CertMatchParamsData(&inStream, NULL, &inParams.validateParameters);

    inParams.maxlength = 100;

    CfBlob issue;
    issue.data = const_cast<uint8_t *>(g_testIssuerValid);
    issue.size = sizeof(g_testIssuerValid);
    inParams.certMatchParameters.issuer = &issue;
    inParams.certMatchParameters.minPathLenConstraint = -1;

    CfResult result = HcfCertChainBuildResultCreate(&inParams, &returnObj);
    EXPECT_EQ(result, CF_SUCCESS);
    EXPECT_NE(returnObj, nullptr);
    FreeHcfX509CertChainBuildResult(returnObj);
    returnObj = nullptr;

    result = HcfCertChainBuildResultCreate(NULL, &returnObj);
    EXPECT_EQ(result, CF_INVALID_PARAMS);

    result = HcfCertChainBuildResultCreate(&inParams, NULL);
    EXPECT_EQ(result, CF_INVALID_PARAMS);

    result = HcfCertChainBuildResultCreate(NULL, NULL);
    EXPECT_EQ(result, CF_INVALID_PARAMS);

    FreeX509CertMatchParamsData(&inParams.validateParameters);
}

HWTEST_F(CryptoX509CertChainTestPart2, HcfX509CreateTrustAnchorWithKeyStoreFuncTest001, TestSize.Level0)
{
    CF_LOG_I("HcfX509CreateTrustAnchorWithKeyStoreFuncTest001");
    CfBlob keyStore;
    CfBlob pwd;
    HcfX509TrustAnchorArray *trustAnchorArray = NULL;

    keyStore.data = const_cast<uint8_t *>(g_testChainKeystore);
    keyStore.size = sizeof(g_testChainKeystore);
    pwd.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testKeystorePwd));
    pwd.size = strlen(g_testKeystorePwd) + 1;
    CfResult result = HcfX509CreateTrustAnchorWithKeyStoreFunc(&keyStore, &pwd, &trustAnchorArray);
    EXPECT_EQ(result, CF_SUCCESS);
    EXPECT_EQ(trustAnchorArray != NULL, true);
    assert(trustAnchorArray->count > 0);
    FreeTrustAnchorArr(*trustAnchorArray);
    CfFree(trustAnchorArray);
    trustAnchorArray = NULL;

    result = HcfX509CreateTrustAnchorWithKeyStoreFunc(NULL, &pwd, &trustAnchorArray);
    EXPECT_EQ(result, CF_INVALID_PARAMS);

    result = HcfX509CreateTrustAnchorWithKeyStoreFunc(&keyStore, NULL, &trustAnchorArray);
    EXPECT_EQ(result, CF_INVALID_PARAMS);

    result = HcfX509CreateTrustAnchorWithKeyStoreFunc(&keyStore, &pwd, NULL);
    EXPECT_EQ(result, CF_INVALID_PARAMS);

    result = HcfX509CreateTrustAnchorWithKeyStoreFunc(NULL, NULL, &trustAnchorArray);
    EXPECT_EQ(result, CF_INVALID_PARAMS);

    result = HcfX509CreateTrustAnchorWithKeyStoreFunc(NULL, NULL, NULL);
    EXPECT_EQ(result, CF_INVALID_PARAMS);

    result = HcfX509CreateTrustAnchorWithKeyStoreFunc(&keyStore, NULL, NULL);
    EXPECT_EQ(result, CF_INVALID_PARAMS);

    keyStore.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testSelfSignedCaCert));
    keyStore.size = strlen(g_testSelfSignedCaCert) + 1;

    result = HcfX509CreateTrustAnchorWithKeyStoreFunc(&keyStore, &pwd, &trustAnchorArray);
    EXPECT_EQ(result, CF_ERR_CRYPTO_OPERATION);
}

HWTEST_F(CryptoX509CertChainTestPart2, HcfX509CreateTrustAnchorWithKeyStoreFuncTest002, TestSize.Level0)
{
    CF_LOG_I("HcfX509CreateTrustAnchorWithKeyStoreFuncTest002");
    CfBlob keyStore;
    CfBlob pwd;
    HcfX509TrustAnchorArray *trustAnchorArray = NULL;

    keyStore.data = const_cast<uint8_t *>(g_testChainKeystore);
    keyStore.size = sizeof(g_testChainKeystore);
    pwd.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testKeystorePwd));
    pwd.size = strlen(g_testKeystorePwd) + 1;

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), PKCS12_parse(_, _, _, _, _))
        .WillOnce(Return(0))
        .WillRepeatedly(Invoke(__real_PKCS12_parse));
    CfResult result = HcfX509CreateTrustAnchorWithKeyStoreFunc(&keyStore, &pwd, &trustAnchorArray);
    EXPECT_EQ(result, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), PKCS12_parse(_, _, _, _, _))
        .WillOnce(Return(1))
        .WillRepeatedly(Invoke(__real_PKCS12_parse));
    result = HcfX509CreateTrustAnchorWithKeyStoreFunc(&keyStore, &pwd, &trustAnchorArray);
    EXPECT_EQ(result, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), PKCS12_parse(_, _, _, _, _))
        .WillOnce(Return(1))
        .WillRepeatedly(Invoke(__real_PKCS12_parse));
    result = HcfX509CreateTrustAnchorWithKeyStoreFunc(&keyStore, &pwd, &trustAnchorArray);
    EXPECT_EQ(result, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), PKCS12_parse(_, _, _, _, _))
        .WillOnce(Invoke(PKCS12_parse_mock))
        .WillRepeatedly(Invoke(__real_PKCS12_parse));
    result = HcfX509CreateTrustAnchorWithKeyStoreFunc(&keyStore, &pwd, &trustAnchorArray);
    EXPECT_EQ(result, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);
}

HWTEST_F(CryptoX509CertChainTestPart2, HcfX509CreateTrustAnchorWithKeyStoreFuncTest003, TestSize.Level0)
{
    CF_LOG_I("HcfX509CreateTrustAnchorWithKeyStoreFuncTest003");
    CfBlob keyStore;
    CfBlob pwd;
    HcfX509TrustAnchorArray *trustAnchorArray = NULL;

    keyStore.data = const_cast<uint8_t *>(g_testChainKeystore);
    keyStore.size = sizeof(g_testChainKeystore);
    pwd.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testKeystorePwd));
    pwd.size = strlen(g_testKeystorePwd) + 1;

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), OPENSSL_sk_num(_))
        .WillOnce(Return(-1))
        .WillRepeatedly(Invoke(__real_OPENSSL_sk_num));
    CfResult result = HcfX509CreateTrustAnchorWithKeyStoreFunc(&keyStore, &pwd, &trustAnchorArray);
    EXPECT_EQ(result, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    SetMockFlag(true);
    result = HcfX509CreateTrustAnchorWithKeyStoreFunc(&keyStore, &pwd, &trustAnchorArray);
    EXPECT_EQ(result, CF_ERR_MALLOC);
    SetMockFlag(false);

    StartRecordMallocNum();
    SetMockMallocIndex(1);
    result = HcfX509CreateTrustAnchorWithKeyStoreFunc(&keyStore, &pwd, &trustAnchorArray);
    EXPECT_EQ(result, CF_ERR_MALLOC);
    EndRecordMallocNum();

    StartRecordMallocNum();
    SetMockMallocIndex(2);
    result = HcfX509CreateTrustAnchorWithKeyStoreFunc(&keyStore, &pwd, &trustAnchorArray);
    EXPECT_EQ(result, CF_ERR_MALLOC);
    EndRecordMallocNum();
}

HWTEST_F(CryptoX509CertChainTestPart2, HcfX509CreateTrustAnchorWithKeyStoreFuncTest004, TestSize.Level0)
{
    CF_LOG_I("HcfX509CreateTrustAnchorWithKeyStoreFuncTest004");
    CfBlob keyStore;
    CfBlob pwd;
    HcfX509TrustAnchorArray *trustAnchorArray = NULL;

    keyStore.data = const_cast<uint8_t *>(g_testChainKeystore);
    keyStore.size = sizeof(g_testChainKeystore);
    pwd.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testKeystorePwd));
    pwd.size = strlen(g_testKeystorePwd) + 1;

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), OPENSSL_sk_num(_))
        .WillOnce(Invoke(__real_OPENSSL_sk_num))
        .WillOnce(Return(-1))
        .WillRepeatedly(Invoke(__real_OPENSSL_sk_num));
    CfResult result = HcfX509CreateTrustAnchorWithKeyStoreFunc(&keyStore, &pwd, &trustAnchorArray);
    EXPECT_EQ(result, CF_SUCCESS);
    X509OpensslMock::SetMockFlag(false);
    FreeTrustAnchorArr(*trustAnchorArray);
    CfFree(trustAnchorArray);
    trustAnchorArray = NULL;

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), OPENSSL_sk_value(_, _))
        .WillOnce(Return(nullptr))
        .WillRepeatedly(Invoke(__real_OPENSSL_sk_value));
    result = HcfX509CreateTrustAnchorWithKeyStoreFunc(&keyStore, &pwd, &trustAnchorArray);
    EXPECT_EQ(result, CF_SUCCESS);
    X509OpensslMock::SetMockFlag(false);
    FreeTrustAnchorArr(*trustAnchorArray);
    CfFree(trustAnchorArray);
    trustAnchorArray = NULL;
}

HWTEST_F(CryptoX509CertChainTestPart2, HcfX509CreateTrustAnchorWithKeyStoreFuncTest005, TestSize.Level0)
{
    CF_LOG_I("HcfX509CreateTrustAnchorWithKeyStoreFuncTest005");
    CfBlob keyStore;
    CfBlob pwd;
    HcfX509TrustAnchorArray *trustAnchorArray = NULL;

    keyStore.data = const_cast<uint8_t *>(g_testChainKeystore);
    keyStore.size = sizeof(g_testChainKeystore);
    pwd.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testKeystorePwd));
    pwd.size = strlen(g_testKeystorePwd) + 1;

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), i2d_X509(_, _))
        .WillOnce(Return(-1))
        .WillRepeatedly(Invoke(__real_i2d_X509));
    CfResult result = HcfX509CreateTrustAnchorWithKeyStoreFunc(&keyStore, &pwd, &trustAnchorArray);
    EXPECT_EQ(result, CF_SUCCESS);
    X509OpensslMock::SetMockFlag(false);
    FreeTrustAnchorArr(*trustAnchorArray);
    CfFree(trustAnchorArray);
    trustAnchorArray = NULL;

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), HcfX509CertificateCreate(_, _))
        .WillOnce(Return(CF_INVALID_PARAMS))
        .WillRepeatedly(Invoke(__real_HcfX509CertificateCreate));
    result = HcfX509CreateTrustAnchorWithKeyStoreFunc(&keyStore, &pwd, &trustAnchorArray);
    EXPECT_EQ(result, CF_SUCCESS);
    X509OpensslMock::SetMockFlag(false);
    FreeTrustAnchorArr(*trustAnchorArray);
    CfFree(trustAnchorArray);
    trustAnchorArray = NULL;
}

HWTEST_F(CryptoX509CertChainTestPart2, HcfCreateTrustAnchorWithKeyStoreTest001, TestSize.Level0)
{
    CF_LOG_I("HcfCreateTrustAnchorWithKeyStoreTest001");
    CfBlob keyStore = {};
    CfBlob pwd = {};
    HcfX509TrustAnchorArray *trustAnchorArray = NULL;
    CfResult result = HcfCreateTrustAnchorWithKeyStore(&keyStore, &pwd, &trustAnchorArray);
    EXPECT_EQ(result, CF_INVALID_PARAMS);

    keyStore.data = const_cast<uint8_t *>(g_testChainKeystore);
    keyStore.size = sizeof(g_testChainKeystore);
    result = HcfCreateTrustAnchorWithKeyStore(&keyStore, &pwd, &trustAnchorArray);
    EXPECT_EQ(result, CF_INVALID_PARAMS);

    pwd.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testKeystorePwd));
    pwd.size = sizeof(g_testKeystorePwd);
    result = HcfCreateTrustAnchorWithKeyStore(&keyStore, &pwd, &trustAnchorArray);
    EXPECT_EQ(result, CF_SUCCESS);
    ASSERT_TRUE(trustAnchorArray != NULL);
    assert(trustAnchorArray->count > 0);
    FreeTrustAnchorArr(*trustAnchorArray);
    CfFree(trustAnchorArray);
    trustAnchorArray = NULL;

    result = HcfCreateTrustAnchorWithKeyStore(NULL, &pwd, &trustAnchorArray);
    EXPECT_EQ(result, CF_INVALID_PARAMS);

    result = HcfCreateTrustAnchorWithKeyStore(&keyStore, NULL, &trustAnchorArray);
    EXPECT_EQ(result, CF_INVALID_PARAMS);

    result = HcfCreateTrustAnchorWithKeyStore(&keyStore, &pwd, NULL);
    EXPECT_EQ(result, CF_INVALID_PARAMS);

    result = HcfCreateTrustAnchorWithKeyStore(NULL, NULL, &trustAnchorArray);
    EXPECT_EQ(result, CF_INVALID_PARAMS);

    result = HcfCreateTrustAnchorWithKeyStore(NULL, NULL, NULL);
    EXPECT_EQ(result, CF_INVALID_PARAMS);

    result = HcfCreateTrustAnchorWithKeyStore(&keyStore, NULL, NULL);
    EXPECT_EQ(result, CF_INVALID_PARAMS);

    keyStore.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testSelfSignedCaCert));
    keyStore.size = strlen(g_testSelfSignedCaCert) + 1;
    result = HcfCreateTrustAnchorWithKeyStore(&keyStore, &pwd, &trustAnchorArray);
    EXPECT_EQ(result, CF_ERR_CRYPTO_OPERATION);
}

static void FreeHcfX509P12Collection(HcfX509P12Collection *p12Collection)
{
    if (p12Collection == NULL) {
        return;
    }
    if (p12Collection->cert != NULL) {
        CfFree(p12Collection->cert);
    }
    if (p12Collection->prikey != NULL && p12Collection->prikey->data != NULL) {
        CfFree(p12Collection->prikey->data);
        CfFree(p12Collection->prikey);
    }
    if (p12Collection->otherCerts != NULL && p12Collection->otherCertsCount != 0) {
        for (uint32_t i = 0; i < p12Collection->otherCertsCount; i++) {
            if (p12Collection->otherCerts[i] != NULL) {
                CfFree(p12Collection->otherCerts[i]);
            }
        }
        CfFree(p12Collection->otherCerts);
    }
    CfFree(p12Collection);
}

HWTEST_F(CryptoX509CertChainTestPart2, HcfParsePKCS12Test001, TestSize.Level0)
{
    CF_LOG_I("HcfParsePKCS12Test001");
    CfBlob keyStore = {};
    CfBlob pwd = {};
    HcfX509P12Collection *p12Collection = NULL;
    HcfParsePKCS12Conf conf = { 0 };
    CfResult result = HcfParsePKCS12(&keyStore, &conf, &p12Collection);
    EXPECT_EQ(result, CF_INVALID_PARAMS);

    keyStore.data = const_cast<uint8_t *>(g_testChainKeystore);
    keyStore.size = sizeof(g_testChainKeystore);
    pwd.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testKeystorePwd));
    pwd.size = strlen(g_testKeystorePwd) + 1;
    conf.pwd = &pwd;
    result = HcfParsePKCS12(&keyStore, &conf, &p12Collection);
    EXPECT_EQ(result, CF_SUCCESS);
    EXPECT_EQ(p12Collection != NULL, true);
    FreeHcfX509P12Collection(p12Collection);
    p12Collection = NULL;

    result = HcfParsePKCS12(NULL, &conf, &p12Collection);
    EXPECT_EQ(result, CF_INVALID_PARAMS);

    result = HcfParsePKCS12(&keyStore, NULL, &p12Collection);
    EXPECT_EQ(result, CF_INVALID_PARAMS);

    result = HcfParsePKCS12(&keyStore, &conf, NULL);
    EXPECT_EQ(result, CF_INVALID_PARAMS);

    result = HcfParsePKCS12(NULL, NULL, &p12Collection);
    EXPECT_EQ(result, CF_INVALID_PARAMS);

    result = HcfParsePKCS12(NULL, NULL, NULL);
    EXPECT_EQ(result, CF_INVALID_PARAMS);

    result = HcfParsePKCS12(&keyStore, NULL, NULL);
    EXPECT_EQ(result, CF_INVALID_PARAMS);

    keyStore.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testSelfSignedCaCert));
    keyStore.size = strlen(g_testSelfSignedCaCert) + 1;

    result = HcfParsePKCS12(&keyStore, &conf, &p12Collection);
    EXPECT_EQ(result, CF_ERR_CRYPTO_OPERATION);
}

HWTEST_F(CryptoX509CertChainTestPart2, HcfParsePKCS12Test002, TestSize.Level0)
{
    CF_LOG_I("HcfParsePKCS12Test002");
    CfBlob keyStore;
    CfBlob pwd;
    HcfX509P12Collection *p12Collection = NULL;
    HcfParsePKCS12Conf conf = { 0 };

    keyStore.data = const_cast<uint8_t *>(g_testChainKeystore);
    keyStore.size = sizeof(g_testChainKeystore);
    pwd.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testKeystorePwd));
    pwd.size = strlen(g_testKeystorePwd) + 1;
    conf.pwd = &pwd;

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), PKCS12_parse(_, _, _, _, _))
        .WillOnce(Return(0))
        .WillRepeatedly(Invoke(__real_PKCS12_parse));
    CfResult result = HcfParsePKCS12(&keyStore, &conf, &p12Collection);
    EXPECT_EQ(result, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), PKCS12_parse(_, _, _, _, _))
        .WillOnce(Return(1))
        .WillRepeatedly(Invoke(__real_PKCS12_parse));
    result = HcfParsePKCS12(&keyStore, &conf, &p12Collection);
    EXPECT_EQ(result, CF_SUCCESS);
    FreeHcfX509P12Collection(p12Collection);
    p12Collection = NULL;
    X509OpensslMock::SetMockFlag(false);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), PKCS12_parse(_, _, _, _, _))
        .WillOnce(Return(1))
        .WillRepeatedly(Invoke(__real_PKCS12_parse));
    result = HcfParsePKCS12(&keyStore, &conf, &p12Collection);
    EXPECT_EQ(result, CF_SUCCESS);
    FreeHcfX509P12Collection(p12Collection);
    p12Collection = NULL;
    X509OpensslMock::SetMockFlag(false);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), PKCS12_parse(_, _, _, _, _))
        .WillOnce(Invoke(PKCS12_parse_mock))
        .WillRepeatedly(Invoke(__real_PKCS12_parse));
    result = HcfParsePKCS12(&keyStore, &conf, &p12Collection);
    EXPECT_EQ(result, CF_SUCCESS);
    FreeHcfX509P12Collection(p12Collection);
    p12Collection = NULL;
    X509OpensslMock::SetMockFlag(false);
}

HWTEST_F(CryptoX509CertChainTestPart2, HcfParsePKCS12Test003, TestSize.Level0)
{
    CF_LOG_I("HcfParsePKCS12Test003");
    CfBlob keyStore;
    CfBlob pwd;
    HcfX509P12Collection *p12Collection = NULL;
    HcfParsePKCS12Conf conf = { 0 };

    keyStore.data = const_cast<uint8_t *>(g_testChainKeystore);
    keyStore.size = sizeof(g_testChainKeystore);
    pwd.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testKeystorePwd));
    pwd.size = strlen(g_testKeystorePwd) + 1;
    conf.pwd = &pwd;

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), OPENSSL_sk_num(_))
        .WillOnce(Return(-1))
        .WillRepeatedly(Invoke(__real_OPENSSL_sk_num));
    CfResult result = HcfParsePKCS12(&keyStore, &conf, &p12Collection);
    EXPECT_EQ(result, CF_SUCCESS);
    FreeHcfX509P12Collection(p12Collection);
    p12Collection = NULL;
    X509OpensslMock::SetMockFlag(false);

    SetMockFlag(true);
    result = HcfParsePKCS12(&keyStore, &conf, &p12Collection);
    EXPECT_EQ(result, CF_ERR_MALLOC);
    SetMockFlag(false);

    StartRecordMallocNum();
    SetMockMallocIndex(1);
    result = HcfParsePKCS12(&keyStore, &conf, &p12Collection);
    EXPECT_EQ(result, CF_SUCCESS);
    FreeHcfX509P12Collection(p12Collection);
    p12Collection = NULL;
    EndRecordMallocNum();

    StartRecordMallocNum();
    SetMockMallocIndex(2);
    result = HcfParsePKCS12(&keyStore, &conf, &p12Collection);
    EXPECT_EQ(result, CF_SUCCESS);
    FreeHcfX509P12Collection(p12Collection);
    p12Collection = NULL;
    EndRecordMallocNum();
}

HWTEST_F(CryptoX509CertChainTestPart2, HcfParsePKCS12Test004, TestSize.Level0)
{
    CF_LOG_I("HcfParsePKCS12Test004");
    CfBlob keyStore;
    CfBlob pwd;
    HcfX509P12Collection *p12Collection = NULL;
    HcfParsePKCS12Conf conf = { 0 };

    keyStore.data = const_cast<uint8_t *>(g_testChainKeystore);
    keyStore.size = sizeof(g_testChainKeystore);
    pwd.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testKeystorePwd));
    pwd.size = strlen(g_testKeystorePwd) + 1;
    conf.pwd = &pwd;

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), OPENSSL_sk_num(_))
        .WillOnce(Invoke(__real_OPENSSL_sk_num))
        .WillOnce(Return(-1))
        .WillRepeatedly(Invoke(__real_OPENSSL_sk_num));
    CfResult result = HcfParsePKCS12(&keyStore, &conf, &p12Collection);
    EXPECT_EQ(result, CF_SUCCESS);
    X509OpensslMock::SetMockFlag(false);
    FreeHcfX509P12Collection(p12Collection);
    p12Collection = NULL;

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), OPENSSL_sk_value(_, _))
        .WillOnce(Return(nullptr))
        .WillRepeatedly(Invoke(__real_OPENSSL_sk_value));
    result = HcfParsePKCS12(&keyStore, &conf, &p12Collection);
    EXPECT_EQ(result, CF_SUCCESS);
    X509OpensslMock::SetMockFlag(false);
    FreeHcfX509P12Collection(p12Collection);
    p12Collection = NULL;
}

HWTEST_F(CryptoX509CertChainTestPart2, HcfParsePKCS12Test005, TestSize.Level0)
{
    CF_LOG_I("HcfParsePKCS12Test005");
    CfBlob keyStore;
    CfBlob pwd;
    HcfX509P12Collection *p12Collection = NULL;
    HcfParsePKCS12Conf conf = { 0 };

    keyStore.data = const_cast<uint8_t *>(g_testChainKeystore);
    keyStore.size = sizeof(g_testChainKeystore);
    pwd.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testKeystorePwd));
    pwd.size = strlen(g_testKeystorePwd) + 1;
    conf.pwd = &pwd;

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), i2d_X509(_, _))
        .WillOnce(Return(-1))
        .WillRepeatedly(Invoke(__real_i2d_X509));
    CfResult result = HcfParsePKCS12(&keyStore, &conf, &p12Collection);
    EXPECT_EQ(result, CF_SUCCESS);
    X509OpensslMock::SetMockFlag(false);
    FreeHcfX509P12Collection(p12Collection);
    p12Collection = NULL;

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), HcfX509CertificateCreate(_, _))
        .WillOnce(Return(CF_INVALID_PARAMS))
        .WillRepeatedly(Invoke(__real_HcfX509CertificateCreate));
    result = HcfParsePKCS12(&keyStore, &conf, &p12Collection);
    EXPECT_EQ(result, CF_SUCCESS);
    X509OpensslMock::SetMockFlag(false);
    FreeHcfX509P12Collection(p12Collection);
    p12Collection = NULL;
}

HWTEST_F(CryptoX509CertChainTestPart2, ValidateLocalCrlEndEntityOnlyTest001, TestSize.Level0)
{
    CF_LOG_I("ValidateLocalCrlEndEntityOnlyTest001");
    HcfX509CertChainSpi *certChainPemOnlyCrl = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&g_inStreamChainLocalCrlOnlyCheckEndEntityCert, &certChainPemOnlyCrl);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainPemOnlyCrl, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainLocalCrlCaCert, trustAnchorArray);

    HcfCertCRLCollectionArray certCRLCollections = { 0 };
    BuildCollectionArr(&g_inStreamChainLocalCrlCaCert, &g_inStreamChainLocalCrl, certCRLCollections);

    HcfX509CertChainValidateParams params = { 0 };
    params.trustAnchors = &trustAnchorArray;
    params.certCRLCollections = &certCRLCollections;

    HcfRevChkOption data[] = { REVOCATION_CHECK_OPTION_LOCAL_CRL_ONLY_CHECK_END_ENTITY_CERT };
    params.revocationCheckParam = ConstructHcfRevocationCheckParam(data, sizeof(data) / sizeof(data[0]));
    ASSERT_NE(params.revocationCheckParam, nullptr);

    HcfX509CertChainValidateResult result = { 0 };

    ret = certChainPemOnlyCrl->engineValidate(certChainPemOnlyCrl, &params, &result);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);
    EXPECT_EQ(result.entityCert, nullptr);
    EXPECT_EQ(result.trustAnchor, nullptr);

    FreeValidateResult(result);
    FreeTrustAnchorArr(trustAnchorArray);
    FreeCertCrlCollectionArr(certCRLCollections);
    FreeHcfRevocationCheckParam(params.revocationCheckParam);
    CfObjDestroy(certChainPemOnlyCrl);
}

HWTEST_F(CryptoX509CertChainTestPart2, ValidateLocalCrlEndEntityOnlyTest002, TestSize.Level0)
{
    CF_LOG_I("ValidateLocalCrlEndEntityOnlyTest002");
    HcfX509CertChainSpi *certChainPemOnlyCrl = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&g_inStreamChainLocalCrlOnlyCheckEndEntityCert, &certChainPemOnlyCrl);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainPemOnlyCrl, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainLocalCrlCaCert, trustAnchorArray);

    HcfCertCRLCollectionArray certCRLCollections = { 0 };
    BuildCollectionArr(&g_inStreamChainLocalCrlCaCert, &g_inStreamChainInitialLocalCrl, certCRLCollections);

    HcfX509CertChainValidateParams params = { 0 };
    params.trustAnchors = &trustAnchorArray;
    params.certCRLCollections = &certCRLCollections;

    HcfRevChkOption data[] = { REVOCATION_CHECK_OPTION_LOCAL_CRL_ONLY_CHECK_END_ENTITY_CERT };
    params.revocationCheckParam = ConstructHcfRevocationCheckParam(data, sizeof(data) / sizeof(data[0]));
    ASSERT_NE(params.revocationCheckParam, nullptr);

    HcfX509CertChainValidateResult result = { 0 };

    ret = certChainPemOnlyCrl->engineValidate(certChainPemOnlyCrl, &params, &result);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(result.entityCert, nullptr);
    EXPECT_NE(result.trustAnchor, nullptr);

    FreeValidateResult(result);
    FreeTrustAnchorArr(trustAnchorArray);
    FreeCertCrlCollectionArr(certCRLCollections);
    FreeHcfRevocationCheckParam(params.revocationCheckParam);
    CfObjDestroy(certChainPemOnlyCrl);
}

HWTEST_F(CryptoX509CertChainTestPart2, ValidateLocalCrlEndEntityOnlyTest003, TestSize.Level0)
{
    CF_LOG_I("ValidateLocalCrlEndEntityOnlyTest002");
    HcfX509CertChainSpi *certChainPemOnlyCrl = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&g_inStreamChainLocalCrlOnlyCheckEndEntityCert, &certChainPemOnlyCrl);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainPemOnlyCrl, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainLocalCrlCaCert, trustAnchorArray);

    HcfCertCRLCollectionArray certCRLCollections = { 0 };
    BuildCollectionArr(&g_inStreamChainLocalCrlCaCert, &g_inStreamChainInitialLocalCrl, certCRLCollections);

    HcfX509CertChainValidateParams params = { 0 };
    params.trustAnchors = &trustAnchorArray;
    params.certCRLCollections = &certCRLCollections;

    HcfRevChkOption data[] = { REVOCATION_CHECK_OPTION_ACCESS_NETWORK, REVOCATION_CHECK_OPTION_PREFER_OCSP,
        REVOCATION_CHECK_OPTION_FALLBACK_LOCAL, REVOCATION_CHECK_OPTION_LOCAL_CRL_ONLY_CHECK_END_ENTITY_CERT
     };
    params.revocationCheckParam = ConstructHcfRevocationCheckParam(data, sizeof(data) / sizeof(data[0]));
    ASSERT_NE(params.revocationCheckParam, nullptr);

    HcfX509CertChainValidateResult result = { 0 };

    ret = certChainPemOnlyCrl->engineValidate(certChainPemOnlyCrl, &params, &result);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(result.entityCert, nullptr);
    EXPECT_NE(result.trustAnchor, nullptr);

    FreeValidateResult(result);
    FreeTrustAnchorArr(trustAnchorArray);
    FreeCertCrlCollectionArr(certCRLCollections);
    FreeHcfRevocationCheckParam(params.revocationCheckParam);
    CfObjDestroy(certChainPemOnlyCrl);
}

HWTEST_F(CryptoX509CertChainTestPart2, ValidateLocalCrlEndEntityOnlyTest004, TestSize.Level0)
{
    CF_LOG_I("ValidateLocalCrlEndEntityOnlyTest002");
    HcfX509CertChainSpi *certChainPemOnlyCrl = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&g_inStreamChainLocalCrlOnlyCheckEndEntityCert, &certChainPemOnlyCrl);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainPemOnlyCrl, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainLocalCrlCaCert, trustAnchorArray);

    HcfCertCRLCollectionArray certCRLCollections = { 0 };
    BuildCollectionArr(&g_inStreamChainLocalCrlCaCert, &g_inStreamChainInitialLocalCrl, certCRLCollections);

    HcfX509CertChainValidateParams params = { 0 };
    params.trustAnchors = &trustAnchorArray;
    params.certCRLCollections = &certCRLCollections;

    HcfRevChkOption data[] = { REVOCATION_CHECK_OPTION_ACCESS_NETWORK, REVOCATION_CHECK_OPTION_FALLBACK_LOCAL,
        REVOCATION_CHECK_OPTION_LOCAL_CRL_ONLY_CHECK_END_ENTITY_CERT
     };
    params.revocationCheckParam = ConstructHcfRevocationCheckParam(data, sizeof(data) / sizeof(data[0]));
    ASSERT_NE(params.revocationCheckParam, nullptr);

    HcfX509CertChainValidateResult result = { 0 };

    ret = certChainPemOnlyCrl->engineValidate(certChainPemOnlyCrl, &params, &result);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(result.entityCert, nullptr);
    EXPECT_NE(result.trustAnchor, nullptr);

    FreeValidateResult(result);
    FreeTrustAnchorArr(trustAnchorArray);
    FreeCertCrlCollectionArr(certCRLCollections);
    FreeHcfRevocationCheckParam(params.revocationCheckParam);
    CfObjDestroy(certChainPemOnlyCrl);
}

HWTEST_F(CryptoX509CertChainTestPart2, ValidateLocalCrlEndEntityOnlyTest005, TestSize.Level0)
{
    CF_LOG_I("ValidateLocalCrlEndEntityOnlyTest002");
    HcfX509CertChainSpi *certChainPemOnlyCrl = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&g_inStreamChainLocalCrlOnlyCheckEndEntityCert, &certChainPemOnlyCrl);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainPemOnlyCrl, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainLocalCrlCaCert, trustAnchorArray);

    HcfCertCRLCollectionArray certCRLCollections = { 0 };
    BuildCollectionArr(&g_inStreamChainLocalCrlCaCert, &g_inStreamChainInitialLocalCrl, certCRLCollections);

    HcfX509CertChainValidateParams params = { 0 };
    params.trustAnchors = &trustAnchorArray;
    params.certCRLCollections = &certCRLCollections;

    HcfRevChkOption data[] = { REVOCATION_CHECK_OPTION_ACCESS_NETWORK, REVOCATION_CHECK_OPTION_PREFER_OCSP,
        REVOCATION_CHECK_OPTION_LOCAL_CRL_ONLY_CHECK_END_ENTITY_CERT
     };
    params.revocationCheckParam = ConstructHcfRevocationCheckParam(data, sizeof(data) / sizeof(data[0]));
    ASSERT_NE(params.revocationCheckParam, nullptr);

    HcfX509CertChainValidateResult result = { 0 };

    ret = certChainPemOnlyCrl->engineValidate(certChainPemOnlyCrl, &params, &result);
    EXPECT_NE(ret, CF_SUCCESS);
    EXPECT_EQ(result.entityCert, nullptr);
    EXPECT_EQ(result.trustAnchor, nullptr);

    FreeValidateResult(result);
    FreeTrustAnchorArr(trustAnchorArray);
    FreeCertCrlCollectionArr(certCRLCollections);
    FreeHcfRevocationCheckParam(params.revocationCheckParam);
    CfObjDestroy(certChainPemOnlyCrl);
}

HWTEST_F(CryptoX509CertChainTestPart2, ValidateLocalCrlEndEntityOnlyTest006, TestSize.Level0)
{
    CF_LOG_I("ValidateLocalCrlEndEntityOnlyTest002");
    HcfX509CertChainSpi *certChainPemOnlyCrl = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&g_inStreamChainLocalCrlOnlyCheckEndEntityCert, &certChainPemOnlyCrl);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainPemOnlyCrl, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainLocalCrlCaCert, trustAnchorArray);

    HcfCertCRLCollectionArray certCRLCollections = { 0 };
    BuildCollectionArr(&g_inStreamChainLocalCrlCaCert, &g_inStreamChainInitialLocalCrl, certCRLCollections);

    HcfX509CertChainValidateParams params = { 0 };
    params.trustAnchors = &trustAnchorArray;
    params.certCRLCollections = &certCRLCollections;

    HcfRevChkOption data[] = { REVOCATION_CHECK_OPTION_ACCESS_NETWORK, REVOCATION_CHECK_OPTION_PREFER_OCSP,
        REVOCATION_CHECK_OPTION_FALLBACK_NO_PREFER, REVOCATION_CHECK_OPTION_LOCAL_CRL_ONLY_CHECK_END_ENTITY_CERT };
    params.revocationCheckParam = ConstructHcfRevocationCheckParam(data, sizeof(data) / sizeof(data[0]));
    ASSERT_NE(params.revocationCheckParam, nullptr);

    HcfX509CertChainValidateResult result = { 0 };

    ret = certChainPemOnlyCrl->engineValidate(certChainPemOnlyCrl, &params, &result);
    EXPECT_NE(ret, CF_SUCCESS);
    EXPECT_EQ(result.entityCert, nullptr);
    EXPECT_EQ(result.trustAnchor, nullptr);

    FreeValidateResult(result);
    FreeTrustAnchorArr(trustAnchorArray);
    FreeCertCrlCollectionArr(certCRLCollections);
    FreeHcfRevocationCheckParam(params.revocationCheckParam);
    CfObjDestroy(certChainPemOnlyCrl);
}

HWTEST_F(CryptoX509CertChainTestPart2, ValidateOnlyCaCertTest001, TestSize.Level0)
{
    CF_LOG_I("ValidateOnlyCaCertTest001");
    HcfX509CertChainSpi *certChainPemOnlyCaCert = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&g_inStreamChainOnlyCenterCaCert, &certChainPemOnlyCaCert);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainPemOnlyCaCert, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainTrustAnchorCaCert, trustAnchorArray);


    HcfX509CertChainValidateParams params = { 0 };
    params.trustAnchors = &trustAnchorArray;

    HcfRevChkOption data[] = { REVOCATION_CHECK_OPTION_ACCESS_NETWORK,
        REVOCATION_CHECK_OPTION_CHECK_INTERMEDIATE_CA_ONLINE };
    params.revocationCheckParam = ConstructHcfRevocationCheckParam(data, sizeof(data) / sizeof(data[0]));
    ASSERT_NE(params.revocationCheckParam, nullptr);

    HcfX509CertChainValidateResult result = { 0 };

    ret = certChainPemOnlyCaCert->engineValidate(certChainPemOnlyCaCert, &params, &result);
    EXPECT_NE(ret, CF_SUCCESS);
    EXPECT_EQ(result.entityCert, nullptr);
    EXPECT_EQ(result.trustAnchor, nullptr);

    FreeValidateResult(result);
    FreeTrustAnchorArr(trustAnchorArray);
    FreeHcfRevocationCheckParam(params.revocationCheckParam);
    CfObjDestroy(certChainPemOnlyCaCert);
}
} // namespace
