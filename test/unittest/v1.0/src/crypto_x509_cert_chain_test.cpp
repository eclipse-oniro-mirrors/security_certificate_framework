/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "certificate_openssl_common.h"
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
#include "crypto_x509_cert_chain_data_pem.h"
#include "crypto_x509_cert_chain_data_pem_added.h"
#include "cert_crl_common.h"
#include "fwk_class.h"

#define OID_STR_MAX_LEN 128
#define MAX_CERT_NUM 256
#define DEMO_CERT_ARRAY_SIZE 2

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
int __real_PKCS12_parse(PKCS12 *p12, const char *pass, EVP_PKEY **pkey, X509 **cert, STACK_OF(X509) **ca);
bool __real_CheckIsSelfSigned(const X509 *cert);

int PKCS12_parse_mock(PKCS12 *p12, const char *pass, EVP_PKEY **pkey, X509 **cert, STACK_OF(X509) **ca) {
    CF_LOG_I("PKCS12_parse_mock");
    *cert = static_cast<X509 *>(malloc(sizeof(X509 *)));
    if (*cert == nullptr) {
        CF_LOG_E("Failed to malloc cert.");
        return 0;
    }
    return 1;
}

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

#ifdef __cplusplus
}
#endif

namespace {
class CryptoX509CertChainTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

static HcfCertChain *g_certChainP7b = nullptr;
static HcfX509Certificate *g_x509CertObj = nullptr;
static HcfX509CertChainSpi *g_certChainP7bSpi = nullptr;
static HcfX509CertChainSpi *g_certChainPemSpi = nullptr;
static HcfX509CertChainSpi *g_certChainDerSpi = nullptr;
constexpr uint32_t TEST_MAX_CERT_NUM = 257; /* max certs number of a certchain */

static const char *GetInvalidCertChainClass(void)
{
    return "HcfInvalidCertChain";
}

void CryptoX509CertChainTest::SetUpTestCase()
{
    CfResult ret = HcfCertChainCreate(&g_inStreamChainDataP7b, nullptr, &g_certChainP7b);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(g_certChainP7b, nullptr);

    HcfX509Certificate *x509CertObj = nullptr;
    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testSelfSignedCaCert));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testSelfSignedCaCert) + 1;
    (void)HcfX509CertificateCreate(&inStream, &x509CertObj);
    ASSERT_NE(x509CertObj, nullptr);
    g_x509CertObj = x509CertObj;

    HcfX509CertChainSpi *certChainSpi = nullptr;
    ret = HcfX509CertChainByEncSpiCreate(&g_inStreamChainDataP7b, &certChainSpi);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainSpi, nullptr);
    g_certChainP7bSpi = certChainSpi;

    certChainSpi = nullptr;
    ret = HcfX509CertChainByEncSpiCreate(&g_inStreamChainDataPem, &certChainSpi);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainSpi, nullptr);
    g_certChainPemSpi = certChainSpi;

    certChainSpi = nullptr;
    ret = HcfX509CertChainByEncSpiCreate(&g_inStreamChainDataDer, &certChainSpi);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainSpi, nullptr);
    g_certChainDerSpi = certChainSpi;
}

void CryptoX509CertChainTest::TearDownTestCase()
{
    CfObjDestroy(g_x509CertObj);
    CfObjDestroy(g_certChainP7b);
    CfObjDestroy(g_certChainP7bSpi);
    CfObjDestroy(g_certChainPemSpi);
    CfObjDestroy(g_certChainDerSpi);
}

void CryptoX509CertChainTest::SetUp() {}

void CryptoX509CertChainTest::TearDown() {}

/* invalid encodingBlob. */
HWTEST_F(CryptoX509CertChainTest, CertChainByEncSpiCreateTest001, TestSize.Level0)
{
    HcfX509CertChainSpi *certChainSpi = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(nullptr, &certChainSpi);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);
}

/* invalid certChainSpi. */
HWTEST_F(CryptoX509CertChainTest, CertChainByEncSpiCreateTest002, TestSize.Level0)
{
    CfResult ret = HcfX509CertChainByEncSpiCreate(&g_inStreamChainDataP7b, nullptr);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);
}

/* The encoding format is CF_FORMAT_PKCS7 */
HWTEST_F(CryptoX509CertChainTest, CertChainByEncSpiCreateTest003, TestSize.Level0)
{
    HcfX509CertChainSpi *certChainSpi = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&g_inStreamChainDataP7b, &certChainSpi);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainSpi, nullptr);

    CfObjDestroy(certChainSpi);
}

HWTEST_F(CryptoX509CertChainTest, CertChainByEncSpiCreateTest004, TestSize.Level0)
{
    HcfX509CertChainSpi *certChainSpi = nullptr;
    CfEncodingBlob inStream = { nullptr, 0, CF_FORMAT_PKCS7 };
    inStream.data = static_cast<uint8_t *>(CfMalloc(g_inStreamChainDataP7b.len, 0));
    ASSERT_NE(inStream.data, nullptr);
    memcpy_s(inStream.data, g_inStreamChainDataP7b.len, g_inStreamChainDataP7b.data, g_inStreamChainDataP7b.len);
    inStream.len = g_inStreamChainDataP7b.len;
    inStream.encodingFormat = g_inStreamChainDataP7b.encodingFormat;
    inStream.data[0] = 0x77; // magic code 0x77

    CfResult ret = HcfX509CertChainByEncSpiCreate(&inStream, &certChainSpi);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);

    CfFree(inStream.data);
}

HWTEST_F(CryptoX509CertChainTest, CertChainByEncSpiCreateTest005, TestSize.Level0)
{
    HcfX509CertChainSpi *certChainSpi = nullptr;
    CfEncodingBlob inStream = { nullptr, 0, CF_FORMAT_PKCS7 };
    inStream.data = static_cast<uint8_t *>(CfMalloc(g_inStreamChainDataDer.len, 0));
    ASSERT_NE(inStream.data, nullptr);
    memcpy_s(inStream.data, g_inStreamChainDataDer.len, g_inStreamChainDataDer.data, g_inStreamChainDataDer.len);
    inStream.len = g_inStreamChainDataDer.len;

    CfResult ret = HcfX509CertChainByEncSpiCreate(&inStream, &certChainSpi);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);

    CfFree(inStream.data);
}

HWTEST_F(CryptoX509CertChainTest, CertChainByEncSpiCreateTest006, TestSize.Level0)
{
    HcfX509CertChainSpi *certChainSpi = nullptr;
    CfEncodingBlob inStream = { nullptr, 0, CF_FORMAT_PKCS7 };

    CfResult ret = HcfX509CertChainByEncSpiCreate(&inStream, &certChainSpi);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);
}

/* The encoding format is CF_FORMAT_DER */
HWTEST_F(CryptoX509CertChainTest, CertChainByEncSpiCreateTest007, TestSize.Level0)
{
    HcfX509CertChainSpi *certChainSpi = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&g_inStreamChainDataDer, &certChainSpi);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainSpi, nullptr);

    CfObjDestroy(certChainSpi);
}

/* Invalid encoding format. */
HWTEST_F(CryptoX509CertChainTest, CertChainByEncSpiCreateTest008, TestSize.Level0)
{
    HcfX509CertChainSpi *certChainSpi = nullptr;
    CfEncodingBlob inStream = { nullptr, 0, (CfEncodingFormat)(CF_FORMAT_PKCS7 + 1) };
    inStream.data = static_cast<uint8_t *>(CfMalloc(g_inStreamChainDataDer.len, 0));
    memcpy_s(inStream.data, g_inStreamChainDataDer.len, g_inStreamChainDataDer.data, g_inStreamChainDataDer.len);
    inStream.len = g_inStreamChainDataDer.len;

    CfResult ret = HcfX509CertChainByEncSpiCreate(&inStream, &certChainSpi);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);

    CfFree(inStream.data);
}

HWTEST_F(CryptoX509CertChainTest, CertChainByEncSpiCreateTest009, TestSize.Level0)
{
    HcfX509CertChainSpi *certChainSpi = nullptr;
    CfEncodingBlob inStream = { nullptr, 0, CF_FORMAT_PEM };
    inStream.data = static_cast<uint8_t *>(CfMalloc(g_inStreamChainDataPem.len, 0));
    memcpy_s(inStream.data, g_inStreamChainDataDer.len, g_inStreamChainDataPem.data, g_inStreamChainDataPem.len);
    inStream.len = g_inStreamChainDataPem.len;

    CfResult ret = HcfX509CertChainByEncSpiCreate(&inStream, &certChainSpi);
    ASSERT_EQ(ret, CF_SUCCESS);

    CfFree(inStream.data);
    CfObjDestroy(certChainSpi);
}

HWTEST_F(CryptoX509CertChainTest, CertChainByEncSpiCreateTest010, TestSize.Level0)
{
    HcfX509CertChainSpi *certChainSpi = nullptr;
    CfEncodingBlob inStream = { nullptr, 0, CF_FORMAT_PKCS7 };
    inStream.data = static_cast<uint8_t *>(CfMalloc(g_inStreamChainDataDer.len, 0));
    memcpy_s(inStream.data, g_inStreamChainDataDer.len, g_inStreamChainDataDer.data, g_inStreamChainDataDer.len);
    inStream.len = ~0;

    CfResult ret = HcfX509CertChainByEncSpiCreate(&inStream, &certChainSpi);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);

    CfFree(inStream.data);
}

HWTEST_F(CryptoX509CertChainTest, CertChainByEncSpiCreateTest011, TestSize.Level0)
{
    HcfX509CertChainSpi *certChainSpi = nullptr;
    CfEncodingBlob inStream = { nullptr, 0, CF_FORMAT_PEM };

    CfResult ret = HcfX509CertChainByEncSpiCreate(&inStream, &certChainSpi);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);
}

HWTEST_F(CryptoX509CertChainTest, CertChainByEncSpiCreateTest012, TestSize.Level0)
{
    HcfX509CertChainSpi *certChainSpi = nullptr;
    CfEncodingBlob inStream = { nullptr, 0, CF_FORMAT_DER };
    inStream.data = static_cast<uint8_t *>(CfMalloc(g_inStreamChainDataDer.len, 0));
    memcpy_s(inStream.data, g_inStreamChainDataDer.len, g_inStreamChainDataDer.data, g_inStreamChainDataDer.len);
    inStream.len = g_inStreamChainDataDer.len;
    inStream.encodingFormat = g_inStreamChainDataDer.encodingFormat;
    inStream.data[0] = 0x77; // magic code 0x77

    CfResult ret = HcfX509CertChainByEncSpiCreate(&inStream, &certChainSpi);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);

    CfFree(inStream.data);
}

HWTEST_F(CryptoX509CertChainTest, CertChainByEncSpiCreateTest013, TestSize.Level0)
{
    HcfX509CertChainSpi *certChainSpi = nullptr;
    SetMockFlag(true);
    CfResult ret = HcfX509CertChainByEncSpiCreate(&g_inStreamChainDataP7b, &certChainSpi);
    ASSERT_EQ(ret, CF_ERR_MALLOC);
    SetMockFlag(false);
}

HWTEST_F(CryptoX509CertChainTest, CertChainByArrSpiCreateTest001, TestSize.Level0)
{
    HcfX509CertChainSpi *certChainSpi;
    CfResult ret = HcfX509CertChainByArrSpiCreate(nullptr, &certChainSpi);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);
}

HWTEST_F(CryptoX509CertChainTest, CertChainByArrSpiCreateTest002, TestSize.Level0)
{
    HcfX509CertificateArray certArray;
    CfResult ret = HcfX509CertChainByArrSpiCreate(&certArray, nullptr);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);
}

HWTEST_F(CryptoX509CertChainTest, CertChainByArrSpiCreateTest003, TestSize.Level0)
{
    HcfX509CertChainSpi *certChainSpi = nullptr;
    HcfX509CertificateArray certArray;

    HcfX509Certificate *x509CertObj = nullptr;
    (void)HcfX509CertificateCreate(&g_inStreamSelfSignedCaCert, &x509CertObj);

    certArray.data = static_cast<HcfX509Certificate **>(CfMalloc(1 * sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(certArray.data, nullptr);
    certArray.data[0] = x509CertObj;
    certArray.count = 1;

    CfResult ret = HcfX509CertChainByArrSpiCreate(&certArray, &certChainSpi);
    ASSERT_EQ(ret, CF_SUCCESS);

    // free memory
    CfFree(certArray.data);
    CfObjDestroy(x509CertObj);
    CfObjDestroy(certChainSpi);
}

HWTEST_F(CryptoX509CertChainTest, CertChainByArrSpiCreateTest004, TestSize.Level0)
{
    HcfX509CertChainSpi *certChainSpi = nullptr;
    HcfX509CertificateArray certArray;

    HcfX509Certificate *x509CertObj = nullptr;
    CfEncodingBlob inStream = { 0 };
    inStream.data = (uint8_t *)g_testSelfSignedCaCert;
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testSelfSignedCaCert) + 1;
    (void)HcfX509CertificateCreate(&inStream, &x509CertObj);

    certArray.data = static_cast<HcfX509Certificate **>(CfMalloc(1 * sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(certArray.data, nullptr);
    certArray.data[0] = x509CertObj;
    certArray.count = 0;

    CfResult ret = HcfX509CertChainByArrSpiCreate(&certArray, &certChainSpi);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);

    // free memory
    CfFree(certArray.data);
    CfObjDestroy(x509CertObj);
    CfObjDestroy(certChainSpi);
}

HWTEST_F(CryptoX509CertChainTest, CertChainByArrSpiCreateTest005, TestSize.Level0)
{
    HcfX509CertChainSpi *certChainSpi = nullptr;
    HcfX509CertificateArray certArray;

    HcfX509Certificate *x509CertObj = nullptr;
    (void)HcfX509CertificateCreate(&g_inStreamSelfSignedCaCert, &x509CertObj);

    certArray.data = static_cast<HcfX509Certificate **>(CfMalloc(1 * sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(certArray.data, nullptr);
    certArray.data[0] = x509CertObj;
    certArray.count = TEST_MAX_CERT_NUM;

    CfResult ret = HcfX509CertChainByArrSpiCreate(&certArray, &certChainSpi);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);

    // free memory
    CfFree(certArray.data);
    CfObjDestroy(x509CertObj);
    CfObjDestroy(certChainSpi);
}

HWTEST_F(CryptoX509CertChainTest, CertChainByArrSpiCreateTest006, TestSize.Level0)
{
    ASSERT_NE(g_x509CertObj, nullptr);
    HcfX509CertChainSpi *certChainSpi = nullptr;
    HcfX509CertificateArray certArray;

    HcfX509Certificate *x509CertObj = nullptr;
    (void)HcfX509CertificateCreate(&g_inStreamSelfSignedCaCert, &x509CertObj);

    certArray.data = static_cast<HcfX509Certificate **>(CfMalloc(1 * sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(certArray.data, nullptr);
    certArray.data[0] = x509CertObj;
    certArray.count = 1;

    x509CertObj->base.base.getClass = GetInvalidCertClass;
    CfResult ret = HcfX509CertChainByArrSpiCreate(&certArray, &certChainSpi);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);

    x509CertObj->base.base.getClass = g_x509CertObj->base.base.getClass;

    CfFree(certArray.data);
    CfObjDestroy(x509CertObj);
}

HWTEST_F(CryptoX509CertChainTest, CertChainByArrSpiCreateTest007, TestSize.Level0)
{
    HcfX509CertificateArray certArray;
    HcfX509Certificate *x509CertObj = nullptr;
    (void)HcfX509CertificateCreate(&g_inStreamSelfSignedCaCert, &x509CertObj);

    certArray.data = static_cast<HcfX509Certificate **>(CfMalloc(1 * sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(certArray.data, nullptr);
    certArray.data[0] = x509CertObj;
    certArray.count = 1;

    SetMockFlag(true);
    HcfX509CertChainSpi *certChainSpi = nullptr;
    CfResult ret = HcfX509CertChainByArrSpiCreate(&certArray, &certChainSpi);
    ASSERT_EQ(ret, CF_ERR_MALLOC);
    SetMockFlag(false);

    CfFree(certArray.data);
    CfObjDestroy(x509CertObj);
}

HWTEST_F(CryptoX509CertChainTest, CertChainCreateTest001, TestSize.Level0)
{
    HcfX509CertificateArray certArray;
    CfResult ret = HcfCertChainCreate(&g_inStreamChainDataP7b, &certArray, nullptr);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);
}

HWTEST_F(CryptoX509CertChainTest, CertChainCreateTest002, TestSize.Level0)
{
    HcfCertChain *pCertChain = nullptr;
    CfResult ret = HcfCertChainCreate(nullptr, nullptr, &pCertChain);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);
}

HWTEST_F(CryptoX509CertChainTest, CertChainCreateTest003, TestSize.Level0)
{
    HcfCertChain *pCertChain = nullptr;
    HcfX509CertificateArray certArray;
    CfResult ret = HcfCertChainCreate(&g_inStreamChainDataP7b, &certArray, &pCertChain);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);
}

HWTEST_F(CryptoX509CertChainTest, CertChainCreateTest004, TestSize.Level0)
{
    HcfCertChain *pCertChain = nullptr;
    CfResult ret = HcfCertChainCreate(&g_inStreamChainDataP7b, nullptr, &pCertChain);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(pCertChain, nullptr);

    CfObjDestroy(pCertChain);
}

HWTEST_F(CryptoX509CertChainTest, CertChainCreateTest005, TestSize.Level0)
{
    HcfCertChain *pCertChain = nullptr;
    CfEncodingBlob inStream = { nullptr, 0, (CfEncodingFormat)(CF_FORMAT_PKCS7 + 1) };
    inStream.data = static_cast<uint8_t *>(CfMalloc(g_inStreamChainDataDer.len, 0));
    memcpy_s(inStream.data, g_inStreamChainDataDer.len, g_inStreamChainDataDer.data, g_inStreamChainDataDer.len);
    inStream.len = g_inStreamChainDataDer.len;

    CfResult ret = HcfCertChainCreate(&inStream, nullptr, &pCertChain);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);

    CfFree(inStream.data);
}

HWTEST_F(CryptoX509CertChainTest, GetCertlistOpensslTest001, TestSize.Level0)
{
    ASSERT_NE(g_certChainP7bSpi, nullptr);
    HcfX509CertificateArray certsList;
    CfResult ret = g_certChainP7bSpi->engineGetCertList(nullptr, &certsList);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);
}

HWTEST_F(CryptoX509CertChainTest, GetCertlistOpensslTest002, TestSize.Level0)
{
    ASSERT_NE(g_certChainP7bSpi, nullptr);
    CfResult ret = g_certChainP7bSpi->engineGetCertList(g_certChainP7bSpi, nullptr);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);
}

HWTEST_F(CryptoX509CertChainTest, GetCertlistOpensslTest003, TestSize.Level0)
{
    ASSERT_NE(g_certChainP7bSpi, nullptr);
    HcfX509CertChainSpi *certChainSpi = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&g_inStreamChainDataP7b, &certChainSpi);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainSpi, nullptr);

    certChainSpi->base.getClass = GetInvalidCertClass;
    ret = certChainSpi->engineGetCertList(certChainSpi, nullptr);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);

    certChainSpi->base.getClass = g_certChainP7bSpi->base.getClass;

    CfObjDestroy(certChainSpi);
}

HWTEST_F(CryptoX509CertChainTest, GetCertlistOpensslTest004, TestSize.Level0)
{
    ASSERT_NE(g_certChainP7bSpi, nullptr);

    HcfX509CertificateArray certsList = { nullptr, 0 };
    CfResult ret = g_certChainP7bSpi->engineGetCertList(g_certChainP7bSpi, &certsList);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_EQ(certsList.count > 0, true);
    ASSERT_NE(certsList.data, nullptr);

    FreeCertArrayData(&certsList);
}

HWTEST_F(CryptoX509CertChainTest, GetCertlistOpensslTest005, TestSize.Level0)
{
    ASSERT_NE(g_certChainP7bSpi, nullptr);
    HcfX509CertChainSpi *certChainSpi = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&g_inStreamChainDataP7b, &certChainSpi);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainSpi, nullptr);
    certChainSpi->base.getClass = GetInvalidCertChainClass;

    HcfX509CertificateArray certsList = { nullptr, 0 };
    ret = certChainSpi->engineGetCertList(certChainSpi, &certsList);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);

    certChainSpi->base.getClass = g_certChainP7bSpi->base.getClass;
    CfObjDestroy(certChainSpi);
}

HWTEST_F(CryptoX509CertChainTest, GetCertListCoreTest001, TestSize.Level0)
{
    ASSERT_NE(g_certChainP7b, nullptr);
    HcfX509CertificateArray certsArray = { 0 };
    CfResult ret = g_certChainP7b->getCertList(nullptr, &certsArray);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);
}

HWTEST_F(CryptoX509CertChainTest, GetCertListCoreTest002, TestSize.Level0)
{
    ASSERT_NE(g_certChainP7b, nullptr);
    CfResult ret = g_certChainP7b->getCertList(g_certChainP7b, nullptr);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);
}

HWTEST_F(CryptoX509CertChainTest, GetCertListCoreTest003, TestSize.Level0)
{
    ASSERT_NE(g_certChainP7b, nullptr);
    HcfCertChain *pCertChain = nullptr;
    CfResult ret = HcfCertChainCreate(&g_inStreamChainDataP7b, nullptr, &pCertChain);
    ASSERT_EQ(ret, CF_SUCCESS);

    pCertChain->base.getClass = GetInvalidCertChainClass;
    ret = g_certChainP7b->getCertList(pCertChain, nullptr);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);

    pCertChain->base.getClass = g_certChainP7b->base.getClass;
    CfObjDestroy(pCertChain);
}

HWTEST_F(CryptoX509CertChainTest, GetCertListCoreTest004, TestSize.Level0)
{
    ASSERT_NE(g_certChainP7b, nullptr);
    HcfX509CertificateArray out = { nullptr, 0 };
    CfResult ret = g_certChainP7b->getCertList(g_certChainP7b, &out);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_EQ(out.count > 0, true);

    FreeCertArrayData(&out);
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest001, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslTest001");
    HcfX509CertChainSpi *certChainSpi = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&g_inStreamChainDataP7b, &certChainSpi);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainSpi, nullptr);

    ret = certChainSpi->engineValidate(nullptr, nullptr, nullptr);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);

    CfObjDestroy(certChainSpi);
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest002, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslTest002");
    ASSERT_NE(g_certChainP7bSpi, nullptr);
    CfResult ret = g_certChainP7bSpi->engineValidate(g_certChainP7bSpi, nullptr, nullptr);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest003, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslTest003");
    ASSERT_NE(g_certChainP7bSpi, nullptr);
    HcfX509TrustAnchor anchor = { 0 };
    CfEncodingBlob inStream = { 0 };
    inStream.data = (uint8_t *)g_testSelfSignedCaCert;
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testSelfSignedCaCert) + 1;
    (void)HcfX509CertificateCreate(&inStream, &anchor.CACert);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    trustAnchorArray.data = static_cast<HcfX509TrustAnchor **>(CfMalloc(1 * sizeof(HcfX509TrustAnchor *), 0));
    ASSERT_NE(trustAnchorArray.data, nullptr);
    trustAnchorArray.data[0] = &anchor;
    trustAnchorArray.count = 1;

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    ASSERT_EQ(pCertChainValidateParams.date, nullptr);               // test
    ASSERT_EQ(pCertChainValidateParams.certCRLCollections, nullptr); // test
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;

    CfResult ret = g_certChainP7bSpi->engineValidate(g_certChainP7bSpi, &pCertChainValidateParams, nullptr);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);

    CfFree(trustAnchorArray.data);
    CfObjDestroy(anchor.CACert);
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest004, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslTest004");
    ASSERT_NE(g_certChainP7bSpi, nullptr);

    HcfX509CertChainSpi *certChainSpi = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&g_inStreamChainDataP7b, &certChainSpi);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainSpi, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainDataPemRoot, trustAnchorArray);

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;

    certChainSpi->base.getClass = GetInvalidCertChainClass;
    HcfX509CertChainValidateResult result = { 0 };
    ret = certChainSpi->engineValidate(certChainSpi, &pCertChainValidateParams, &result);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);

    certChainSpi->base.getClass = g_certChainP7bSpi->base.getClass;
    FreeTrustAnchorArr(trustAnchorArray);
    CfObjDestroy(certChainSpi);
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest005, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslTest005");
    ASSERT_NE(g_certChainPemSpi, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainDataPemRoot, trustAnchorArray);

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;

    HcfX509CertChainValidateResult result = { 0 };
    CfResult ret = g_certChainPemSpi->engineValidate(g_certChainPemSpi, &pCertChainValidateParams, &result);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(result.entityCert, nullptr);
    ASSERT_NE(result.trustAnchor, nullptr);

    FreeTrustAnchorArr(trustAnchorArray);
    FreeValidateResult(result);
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest006, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslTest006");
    ASSERT_NE(g_certChainPemSpi, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamSelfSignedCaCert, trustAnchorArray);

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;

    HcfX509CertChainValidateResult result = { 0 };
    CfResult ret = g_certChainPemSpi->engineValidate(g_certChainPemSpi, &pCertChainValidateParams, &result);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);

    FreeTrustAnchorArr(trustAnchorArray);
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest007, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslTest007");
    ASSERT_NE(g_certChainPemSpi, nullptr);

    HcfX509TrustAnchor anchor = { 0 };

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    trustAnchorArray.data = static_cast<HcfX509TrustAnchor **>(CfMalloc(1 * sizeof(HcfX509TrustAnchor *), 0));
    ASSERT_NE(trustAnchorArray.data, nullptr);
    trustAnchorArray.data[0] = &anchor;
    trustAnchorArray.count = 1;

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;

    HcfX509CertChainValidateResult result = { 0 };
    CfResult ret = g_certChainPemSpi->engineValidate(g_certChainPemSpi, &pCertChainValidateParams, &result);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);

    CfFree(trustAnchorArray.data);
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest008, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslTest008");
    ASSERT_NE(g_certChainPemSpi, nullptr);

    CfBlob pubkey = { 0, nullptr };
    pubkey.data = (uint8_t *)(&g_testChainPubkeyPemRootData[0]);
    pubkey.size = g_testChainPubkeyPemRootDataSize;

    HcfX509TrustAnchor anchor = { 0 };

    anchor.CAPubKey = &pubkey;

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    trustAnchorArray.data = static_cast<HcfX509TrustAnchor **>(CfMalloc(1 * sizeof(HcfX509TrustAnchor *), 0));
    ASSERT_NE(trustAnchorArray.data, nullptr);
    trustAnchorArray.data[0] = &anchor;
    trustAnchorArray.count = 1;

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;

    HcfX509CertChainValidateResult result = { 0 };
    CfResult ret = g_certChainPemSpi->engineValidate(g_certChainPemSpi, &pCertChainValidateParams, &result);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(result.entityCert, nullptr);
    ASSERT_NE(result.trustAnchor, nullptr);

    CfFree(trustAnchorArray.data);
    FreeValidateResult(result);
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest009, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslTest009");
    ASSERT_NE(g_certChainPemSpi, nullptr);

    CfBlob pubkey = { 0, nullptr };
    pubkey.data = (uint8_t *)(&g_testCrlSubAndIssNameDerData[0]);
    pubkey.size = g_testCrlSubAndIssNameDerDataSize;

    HcfX509TrustAnchor anchor = { 0 };
    anchor.CAPubKey = &pubkey;

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    trustAnchorArray.data = static_cast<HcfX509TrustAnchor **>(CfMalloc(1 * sizeof(HcfX509TrustAnchor *), 0));
    ASSERT_NE(trustAnchorArray.data, nullptr);
    trustAnchorArray.data[0] = &anchor;
    trustAnchorArray.count = 1;

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;

    HcfX509CertChainValidateResult result = { 0 };
    CfResult ret = g_certChainPemSpi->engineValidate(g_certChainPemSpi, &pCertChainValidateParams, &result);
    ASSERT_EQ(ret, CF_ERR_CRYPTO_OPERATION);

    CfFree(trustAnchorArray.data);
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest010, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslTest010");
    ASSERT_NE(g_certChainPemSpi, nullptr);

    CfBlob pubkey = { 0, nullptr };
    pubkey.data = (uint8_t *)(&g_testChainPubkeyPemRootData[0]);
    pubkey.size = g_testChainPubkeyPemRootDataSize;

    CfBlob subject = { 0, nullptr };
    subject.data = (uint8_t *)(&g_testChainSubjectPemRootData[0]);
    subject.size = g_testChainSubjectPemRootDataSize;

    HcfX509TrustAnchor anchor = { 0 };
    anchor.CAPubKey = &pubkey;
    anchor.CASubject = &subject;

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    trustAnchorArray.data = static_cast<HcfX509TrustAnchor **>(CfMalloc(1 * sizeof(HcfX509TrustAnchor *), 0));
    ASSERT_NE(trustAnchorArray.data, nullptr);
    trustAnchorArray.data[0] = &anchor;
    trustAnchorArray.count = 1;

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;

    HcfX509CertChainValidateResult result = { 0 };
    CfResult ret = g_certChainPemSpi->engineValidate(g_certChainPemSpi, &pCertChainValidateParams, &result);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(result.entityCert, nullptr);
    ASSERT_NE(result.trustAnchor, nullptr);

    CfFree(trustAnchorArray.data);
    FreeValidateResult(result);
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest011, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslTest011");
    ASSERT_NE(g_certChainPemSpi, nullptr);

    CfBlob pubkey = { 0, nullptr };
    pubkey.data = (uint8_t *)(&g_testChainPubkeyPemRootData[0]);
    pubkey.size = g_testChainPubkeyPemRootDataSize;

    CfBlob subject = { 0, nullptr };
    subject.data = (uint8_t *)(&g_testChainSubjectPemOtherSubjectData[0]);
    subject.size = g_testChainSubjectPemOtherSubjectDataSize;

    HcfX509TrustAnchor anchor = { 0 };
    anchor.CAPubKey = &pubkey;
    anchor.CASubject = &subject;

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    trustAnchorArray.data = static_cast<HcfX509TrustAnchor **>(CfMalloc(1 * sizeof(HcfX509TrustAnchor *), 0));
    ASSERT_NE(trustAnchorArray.data, nullptr);
    trustAnchorArray.data[0] = &anchor;
    trustAnchorArray.count = 1;

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;

    HcfX509CertChainValidateResult result = { 0 };
    CfResult ret = g_certChainPemSpi->engineValidate(g_certChainPemSpi, &pCertChainValidateParams, &result);

    ASSERT_EQ(ret, CF_INVALID_PARAMS);

    CfFree(trustAnchorArray.data);
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest012, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslTest012");
    ASSERT_NE(g_certChainPemSpi, nullptr);

    CfBlob pubkey = { 0, nullptr };
    pubkey.data = (uint8_t *)(&g_testChainPubkeyPemRootData[0]);
    pubkey.size = g_testChainPubkeyPemRootDataSize;

    HcfX509TrustAnchor anchor = { 0 };
    anchor.CAPubKey = &pubkey;
    anchor.CASubject = &pubkey;

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    trustAnchorArray.data = static_cast<HcfX509TrustAnchor **>(CfMalloc(1 * sizeof(HcfX509TrustAnchor *), 0));
    ASSERT_NE(trustAnchorArray.data, nullptr);
    trustAnchorArray.data[0] = &anchor;
    trustAnchorArray.count = 1;

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;

    HcfX509CertChainValidateResult result = { 0 };
    CfResult ret = g_certChainPemSpi->engineValidate(g_certChainPemSpi, &pCertChainValidateParams, &result);
    ASSERT_EQ(ret, CF_ERR_CRYPTO_OPERATION);

    CfFree(trustAnchorArray.data);
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest013, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslTest013");
    ASSERT_NE(g_certChainPemSpi, nullptr);

    CfBlob pubkey = { 0, nullptr };
    pubkey.data = (uint8_t *)(&g_testCrlSubAndIssNameDerData[0]);
    pubkey.size = g_testCrlSubAndIssNameDerDataSize;

    HcfX509TrustAnchor anchor = { 0 };

    anchor.CAPubKey = &pubkey;
    anchor.CASubject = &pubkey;

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    trustAnchorArray.data = static_cast<HcfX509TrustAnchor **>(CfMalloc(1 * sizeof(HcfX509TrustAnchor *), 0));
    ASSERT_NE(trustAnchorArray.data, nullptr);
    trustAnchorArray.data[0] = &anchor;
    trustAnchorArray.count = 1;

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;

    HcfX509CertChainValidateResult result = { 0 };
    CfResult ret = g_certChainPemSpi->engineValidate(g_certChainPemSpi, &pCertChainValidateParams, &result);
    ASSERT_EQ(ret, CF_ERR_CRYPTO_OPERATION);

    CfFree(trustAnchorArray.data);
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest014, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslTest014");
    HcfX509CertChainSpi *certChainSpi = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&g_inStreamChainDataPemNoRoot, &certChainSpi);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainSpi, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainDataPemRoot, trustAnchorArray);

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;

    HcfX509CertChainValidateResult result = { 0 };
    ret = certChainSpi->engineValidate(certChainSpi, &pCertChainValidateParams, &result);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(result.entityCert, nullptr);
    ASSERT_NE(result.trustAnchor, nullptr);

    FreeTrustAnchorArr(trustAnchorArray);
    FreeValidateResult(result);
    CfObjDestroy(certChainSpi);
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest015, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslTest015");
    HcfX509CertChainSpi *certChainSpi = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&g_inStreamChainPemNoRootHasPubKey, &certChainSpi);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainSpi, nullptr);

    CfBlob pubkey = { 0, nullptr };
    pubkey.data = (uint8_t *)(&g_testChainPubkeyPemRootHasPubKey[0]);
    pubkey.size = g_testChainPubkeyPemRootHasPubKeySize;

    HcfX509TrustAnchor anchor = { 0 };
    anchor.CAPubKey = &pubkey;

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    trustAnchorArray.data = static_cast<HcfX509TrustAnchor **>(CfMalloc(1 * sizeof(HcfX509TrustAnchor *), 0));
    ASSERT_NE(trustAnchorArray.data, nullptr);
    trustAnchorArray.data[0] = &anchor;
    trustAnchorArray.count = 1;

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;

    HcfX509CertChainValidateResult result = { 0 };
    ret = certChainSpi->engineValidate(certChainSpi, &pCertChainValidateParams, &result);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(result.entityCert, nullptr);
    ASSERT_NE(result.trustAnchor, nullptr);

    CfFree(trustAnchorArray.data);
    CfObjDestroy(certChainSpi);
    FreeValidateResult(result);
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest016, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslTest016");
    ASSERT_NE(g_certChainPemSpi, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainDataPemMid, trustAnchorArray);

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;

    HcfX509CertChainValidateResult result = { 0 };
    CfResult ret = g_certChainPemSpi->engineValidate(g_certChainPemSpi, &pCertChainValidateParams, &result);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);

    FreeTrustAnchorArr(trustAnchorArray);
    FreeValidateResult(result);
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest017, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslTest017");
    HcfX509CertChainSpi *certChainSpi = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&g_inStreamChainDataPemRoot, &certChainSpi);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainSpi, nullptr);

    CfBlob pubkey = { 0, nullptr };
    pubkey.data = (uint8_t *)(&g_testCrlSubAndIssNameDerData[0]);
    pubkey.size = g_testCrlSubAndIssNameDerDataSize;

    HcfX509TrustAnchor anchor = { 0 };
    (void)HcfX509CertificateCreate(&g_inStreamChainDataPemRoot, &anchor.CACert);
    anchor.CAPubKey = &pubkey;

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    trustAnchorArray.data = static_cast<HcfX509TrustAnchor **>(CfMalloc(1 * sizeof(HcfX509TrustAnchor *), 0));
    ASSERT_NE(trustAnchorArray.data, nullptr);
    trustAnchorArray.data[0] = &anchor;
    trustAnchorArray.count = 1;

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;

    HcfX509CertChainValidateResult result = { 0 };
    ret = certChainSpi->engineValidate(certChainSpi, &pCertChainValidateParams, &result);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(result.entityCert, nullptr);
    ASSERT_NE(result.trustAnchor, nullptr);

    FreeValidateResult(result);
    CfFree(trustAnchorArray.data);
    CfObjDestroy(anchor.CACert);
    CfObjDestroy(certChainSpi);
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest018, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslTest018");
    ASSERT_NE(g_certChainPemSpi, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainDataPemRoot, trustAnchorArray);

    const char *date = "20231205073900Z";
    CfBlob validDate = { 0 };
    validDate.data = reinterpret_cast<uint8_t *>(const_cast<char *>(date));
    validDate.size = strlen(date) + 1;
    // validatetime :notBeforeDate: 2023-12-05 07:39:00 UTC , notAfterDate: 2024-09-01 23:59:00 UTC

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;
    pCertChainValidateParams.date = &validDate;

    HcfX509CertChainValidateResult result = { 0 };
    CfResult ret = g_certChainPemSpi->engineValidate(g_certChainPemSpi, &pCertChainValidateParams, &result);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(result.entityCert, nullptr);
    ASSERT_NE(result.trustAnchor, nullptr);

    FreeTrustAnchorArr(trustAnchorArray);
    FreeValidateResult(result);
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest019, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslTest019");
    ASSERT_NE(g_certChainPemSpi, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainDataPemRoot, trustAnchorArray);

    const char *date = "20240901235900Z";
    CfBlob validDate = { 0 };
    validDate.data = reinterpret_cast<uint8_t *>(const_cast<char *>(date));
    validDate.size = strlen(date) + 1;
    // validatetime :notBeforeDate: 2023-12-05 07:39:00 UTC , notAfterDate: 2024-09-01 23:59:00 UTC

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;
    pCertChainValidateParams.date = &validDate;

    HcfX509CertChainValidateResult result = { 0 };
    CfResult ret = g_certChainPemSpi->engineValidate(g_certChainPemSpi, &pCertChainValidateParams, &result);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(result.entityCert, nullptr);
    ASSERT_NE(result.trustAnchor, nullptr);

    FreeTrustAnchorArr(trustAnchorArray);
    FreeValidateResult(result);
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest020, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslTest020");
    ASSERT_NE(g_certChainPemSpi, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainDataPemRoot, trustAnchorArray);

    const char *date = "231205073900Z";
    CfBlob validDate = { 0 };
    validDate.data = reinterpret_cast<uint8_t *>(const_cast<char *>(date));
    validDate.size = strlen(date) + 1;
    // validatetime :notBeforeDate: 2023-12-05 07:39:00 UTC , notAfterDate: 2024-09-01 23:59:00 UTC

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;
    pCertChainValidateParams.date = &validDate;

    HcfX509CertChainValidateResult result = { 0 };
    CfResult ret = g_certChainPemSpi->engineValidate(g_certChainPemSpi, &pCertChainValidateParams, &result);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(result.entityCert, nullptr);
    ASSERT_NE(result.trustAnchor, nullptr);

    FreeTrustAnchorArr(trustAnchorArray);
    FreeValidateResult(result);
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest021, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslTest021");
    ASSERT_NE(g_certChainPemSpi, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainDataPemRoot, trustAnchorArray);

    const char *date = "231206090000";
    CfBlob validDate = { 0 };
    validDate.data = reinterpret_cast<uint8_t *>(const_cast<char *>(date));
    validDate.size = strlen(date); // len is wrong.
    // validatetime :notBeforeDate: 2023-12-05 07:39:00 UTC , notAfterDate: 2024-09-01 23:59:00 UTC

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;
    pCertChainValidateParams.date = &validDate;

    HcfX509CertChainValidateResult result = { 0 };
    CfResult ret = g_certChainPemSpi->engineValidate(g_certChainPemSpi, &pCertChainValidateParams, &result);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);

    FreeTrustAnchorArr(trustAnchorArray);
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest022, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslTest022");
    ASSERT_NE(g_certChainPemSpi, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainDataPemRoot, trustAnchorArray);

    const char *date = "abc"; // format is not correct.
    CfBlob validDate = { 0 };
    validDate.data = reinterpret_cast<uint8_t *>(const_cast<char *>(date));
    validDate.size = strlen(date) + 1;
    // validatetime :notBeforeDate: 2023-12-05 07:39:00 UTC , notAfterDate: 2024-09-01 23:59:00 UTC

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;
    pCertChainValidateParams.date = &validDate;

    HcfX509CertChainValidateResult result = { 0 };
    CfResult ret = g_certChainPemSpi->engineValidate(g_certChainPemSpi, &pCertChainValidateParams, &result);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);

    FreeTrustAnchorArr(trustAnchorArray);
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest023, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslTest023");
    ASSERT_NE(g_certChainPemSpi, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainDataPemRoot, trustAnchorArray);

    const char *date = "20231205073500Z";
    CfBlob validDate = { 0 };
    validDate.data = reinterpret_cast<uint8_t *>(const_cast<char *>(date));
    validDate.size = strlen(date) + 1;
    // validatetime :notBeforeDate: 2023-12-05 07:39:00 UTC , notAfterDate: 2024-09-01 23:59:00 UTC

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;
    pCertChainValidateParams.date = &validDate;

    HcfX509CertChainValidateResult result = { 0 };
    CfResult ret = g_certChainPemSpi->engineValidate(g_certChainPemSpi, &pCertChainValidateParams, &result);
    ASSERT_EQ(ret, CF_ERR_CERT_NOT_YET_VALID);

    FreeTrustAnchorArr(trustAnchorArray);
    FreeValidateResult(result);
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest024, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslTest024");
    ASSERT_NE(g_certChainPemSpi, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainDataPemRoot, trustAnchorArray);

    const char *date = "20240901235901Z";
    CfBlob validDate = { 0 };
    validDate.data = reinterpret_cast<uint8_t *>(const_cast<char *>(date));
    validDate.size = strlen(date) + 1;
    // validatetime :notBeforeDate: 2023-12-05 07:39:00 UTC , notAfterDate: 2024-09-01 23:59:00 UTC

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;
    pCertChainValidateParams.date = &validDate;

    HcfX509CertChainValidateResult result = { 0 };
    CfResult ret = g_certChainPemSpi->engineValidate(g_certChainPemSpi, &pCertChainValidateParams, &result);
    ASSERT_EQ(ret, CF_ERR_CERT_HAS_EXPIRED);

    FreeTrustAnchorArr(trustAnchorArray);
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest025, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslTest025");
    ASSERT_NE(g_certChainPemSpi, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainDataPemRoot, trustAnchorArray);

    HcfCertCRLCollectionArray certCRLCollections = { 0 };
    BuildCollectionArr(&g_inStreamChainDataPemRoot, &g_crlDerInStream, certCRLCollections);

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;
    pCertChainValidateParams.certCRLCollections = &certCRLCollections;

    HcfX509CertChainValidateResult result = { 0 };
    CfResult ret = g_certChainPemSpi->engineValidate(g_certChainPemSpi, &pCertChainValidateParams, &result);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(result.entityCert, nullptr);
    ASSERT_NE(result.trustAnchor, nullptr);

    FreeTrustAnchorArr(trustAnchorArray);
    FreeCertCrlCollectionArr(certCRLCollections);
    FreeValidateResult(result);
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest026, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslTest026");
    ASSERT_NE(g_certChainPemSpi, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainDataPemRoot, trustAnchorArray);

    HcfCertCRLCollectionArray certCRLCollections = { 0 };
    BuildCollectionArr(&g_inStreamChainDataPemMid, &g_inStreamChainDataPemMidCRL, certCRLCollections);

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;
    pCertChainValidateParams.certCRLCollections = &certCRLCollections;

    HcfX509CertChainValidateResult result = { 0 };
    CfResult ret = g_certChainPemSpi->engineValidate(g_certChainPemSpi, &pCertChainValidateParams, &result);
    ASSERT_EQ(ret, CF_ERR_CRYPTO_OPERATION);

    FreeTrustAnchorArr(trustAnchorArray);
    FreeCertCrlCollectionArr(certCRLCollections);
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest027, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslTest027");
    ASSERT_NE(g_certChainPemSpi, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainDataPemRoot, trustAnchorArray);

    HcfCertCRLCollectionArray certCRLCollections = { 0 };
    BuildCollectionArr(&g_inStreamChainDataPemRoot, &g_crlDerInStream, certCRLCollections);

    const char *date = "20231212080000Z";
    CfBlob validDate = { 0 };
    validDate.data = reinterpret_cast<uint8_t *>(const_cast<char *>(date));
    validDate.size = strlen(date) + 1;
    // validatetime :notBeforeDate: 20231205080000, notAfterDate: 20241205075959

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;
    pCertChainValidateParams.date = &validDate;
    pCertChainValidateParams.certCRLCollections = &certCRLCollections;

    HcfX509CertChainValidateResult result = { 0 };
    CfResult ret = g_certChainPemSpi->engineValidate(g_certChainPemSpi, &pCertChainValidateParams, &result);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(result.entityCert, nullptr);
    ASSERT_NE(result.trustAnchor, nullptr);

    FreeTrustAnchorArr(trustAnchorArray);
    FreeCertCrlCollectionArr(certCRLCollections);
    FreeValidateResult(result);
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest028, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslTest028");
    for (unsigned int i = 0; i < 1000; i++) {
        HcfX509TrustAnchorArray trustAnchorArray = { 0 };
        BuildAnchorArr(g_inStreamChainDataPemRoot, trustAnchorArray);

        HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
        pCertChainValidateParams.trustAnchors = &trustAnchorArray;

        HcfX509CertChainValidateResult result = { 0 };
        CfResult ret = g_certChainPemSpi->engineValidate(g_certChainPemSpi, &pCertChainValidateParams, &result);
        ASSERT_EQ(ret, CF_SUCCESS);
        ASSERT_NE(result.entityCert, nullptr);
        ASSERT_NE(result.trustAnchor, nullptr);

        FreeTrustAnchorArr(trustAnchorArray);
        FreeValidateResult(result);
    }
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest029, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslTest029");
    HcfX509CertChainSpi *certChainSpi = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&g_inStreamChainPemNoRootHasPubKey, &certChainSpi);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainSpi, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainPemNoRootLast, trustAnchorArray);

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;

    HcfX509CertChainValidateResult result = { 0 };
    ret = certChainSpi->engineValidate(certChainSpi, &pCertChainValidateParams, &result);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(result.entityCert, nullptr);
    ASSERT_NE(result.trustAnchor, nullptr);

    FreeTrustAnchorArr(trustAnchorArray);
    FreeValidateResult(result);
    CfObjDestroy(certChainSpi);
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest030, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslTest030");
    ASSERT_NE(g_certChainPemSpi, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainDataPemRoot, trustAnchorArray);

    HcfCertCRLCollectionArray certCRLCollections = { 0 };
    BuildCollectionArr(&g_inStreamChainDataPemRoot, nullptr, certCRLCollections);

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;
    pCertChainValidateParams.certCRLCollections = &certCRLCollections;

    HcfX509CertChainValidateResult result = { 0 };
    CfResult ret = g_certChainPemSpi->engineValidate(g_certChainPemSpi, &pCertChainValidateParams, &result);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(result.entityCert, nullptr);
    ASSERT_NE(result.trustAnchor, nullptr);

    FreeTrustAnchorArr(trustAnchorArray);
    FreeCertCrlCollectionArr(certCRLCollections);
    FreeValidateResult(result);
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest031, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslTest031");
    HcfX509CertChainSpi *certChainSpi = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&g_inStreamChainDataPemDisorder, &certChainSpi);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainSpi, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainDataPemRoot, trustAnchorArray);

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;

    HcfX509CertChainValidateResult result = { 0 };
    ret = certChainSpi->engineValidate(certChainSpi, &pCertChainValidateParams, &result);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);

    FreeTrustAnchorArr(trustAnchorArray);
    CfObjDestroy(certChainSpi);
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest032, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslTest032");
    HcfX509CertChainSpi *certChainSpi = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&g_inStreamChainPemNoRootHasPubKey, &certChainSpi);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainSpi, nullptr);

    CfBlob pubkey = { 0, nullptr };
    pubkey.data = (uint8_t *)(&g_testChainPubkeyPemNoRootLast[0]);
    pubkey.size = g_testChainPubkeyPemNoRootLastSize;

    HcfX509TrustAnchor anchor = { 0 };
    anchor.CAPubKey = &pubkey;

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    trustAnchorArray.data = static_cast<HcfX509TrustAnchor **>(CfMalloc(1 * sizeof(HcfX509TrustAnchor *), 0));
    ASSERT_NE(trustAnchorArray.data, nullptr);
    trustAnchorArray.data[0] = &anchor;
    trustAnchorArray.count = 1;

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;

    HcfX509CertChainValidateResult result = { 0 };
    ret = certChainSpi->engineValidate(certChainSpi, &pCertChainValidateParams, &result);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(result.entityCert, nullptr);
    ASSERT_NE(result.trustAnchor, nullptr);

    CfFree(trustAnchorArray.data);
    CfObjDestroy(certChainSpi);
    FreeValidateResult(result);
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest033, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslTest033");
    HcfX509CertChainSpi *certChainSpi = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&g_inStreamChainPemNoRootHasPubKey, &certChainSpi);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainSpi, nullptr);

    CfBlob pubkey = { 0, nullptr };
    pubkey.data = (uint8_t *)(&g_testChainPubkeyPemNoRootLast[0]);
    pubkey.size = g_testChainPubkeyPemNoRootLastSize;

    CfBlob subject = { 0, nullptr };
    subject.data = (uint8_t *)(&g_testChainSubjectPemNoRootLastUp[0]);
    subject.size = g_testChainSubjectPemNoRootLastUpSize;

    HcfX509TrustAnchor anchor = { 0 };
    anchor.CAPubKey = &pubkey;
    anchor.CASubject = &subject;

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    trustAnchorArray.data = static_cast<HcfX509TrustAnchor **>(CfMalloc(1 * sizeof(HcfX509TrustAnchor *), 0));
    ASSERT_NE(trustAnchorArray.data, nullptr);
    trustAnchorArray.data[0] = &anchor;
    trustAnchorArray.count = 1;

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;

    HcfX509CertChainValidateResult result = { 0 };
    ret = certChainSpi->engineValidate(certChainSpi, &pCertChainValidateParams, &result);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);

    CfFree(trustAnchorArray.data);
    CfObjDestroy(certChainSpi);
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest034, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslTest034");
    HcfX509CertChainSpi *certChainSpi = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&g_inStreamChainPemNoRootHasPubKey, &certChainSpi);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainSpi, nullptr);

    CfBlob pubkey = { 0, nullptr };
    pubkey.data = (uint8_t *)(&g_testChainPubkeyPemNoRootLastUp[0]);
    pubkey.size = g_testChainPubkeyPemNoRootLastUpSize;

    CfBlob subject = { 0, nullptr };
    subject.data = (uint8_t *)(&g_testChainSubjectPemNoRootLast[0]);
    subject.size = g_testChainSubjectPemNoRootLastSize;

    HcfX509TrustAnchor anchor = { 0 };
    anchor.CAPubKey = &pubkey;
    anchor.CASubject = &subject;

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    trustAnchorArray.data = static_cast<HcfX509TrustAnchor **>(CfMalloc(1 * sizeof(HcfX509TrustAnchor *), 0));
    ASSERT_NE(trustAnchorArray.data, nullptr);
    trustAnchorArray.data[0] = &anchor;
    trustAnchorArray.count = 1;

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;

    HcfX509CertChainValidateResult result = { 0 };
    ret = certChainSpi->engineValidate(certChainSpi, &pCertChainValidateParams, &result);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);

    CfFree(trustAnchorArray.data);
    CfObjDestroy(certChainSpi);
}

HWTEST_F(CryptoX509CertChainTest, ValidateCoreTest001, TestSize.Level0)
{
    CF_LOG_I("ValidateCoreTest001");
    HcfCertChain *pCertChain = nullptr;
    CfResult ret = HcfCertChainCreate(&g_inStreamChainDataP7b, nullptr, &pCertChain);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(pCertChain, nullptr);

    ret = pCertChain->validate(nullptr, nullptr, nullptr);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);

    CfObjDestroy(pCertChain);
}

HWTEST_F(CryptoX509CertChainTest, ValidateCoreTest002, TestSize.Level0)
{
    CF_LOG_I("ValidateCoreTest002");
    HcfCertChain *pCertChain = nullptr;
    CfResult ret = HcfCertChainCreate(&g_inStreamChainDataP7b, nullptr, &pCertChain);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(pCertChain, nullptr);

    ret = pCertChain->validate(pCertChain, nullptr, nullptr);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);

    CfObjDestroy(pCertChain);
}

HWTEST_F(CryptoX509CertChainTest, ValidateCoreTest003, TestSize.Level0)
{
    CF_LOG_I("ValidateCoreTest003");
    ASSERT_NE(g_certChainP7b, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamSelfSignedCaCert, trustAnchorArray);

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;

    CfResult ret = g_certChainP7b->validate(g_certChainP7b, &pCertChainValidateParams, nullptr);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);

    FreeTrustAnchorArr(trustAnchorArray);
}

HWTEST_F(CryptoX509CertChainTest, ValidateCoreTest004, TestSize.Level0)
{
    CF_LOG_I("ValidateCoreTest004");
    HcfCertChain *pCertChain = nullptr;
    CfResult ret = HcfCertChainCreate(&g_inStreamChainDataPem, nullptr, &pCertChain);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(pCertChain, nullptr);
    pCertChain->base.getClass = GetInvalidCertChainClass;

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };

    HcfX509CertChainValidateResult result = { 0 };
    ret = pCertChain->validate(pCertChain, &pCertChainValidateParams, &result);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);

    pCertChain->base.getClass = g_certChainP7b->base.getClass;
    CfObjDestroy(pCertChain);
}

HWTEST_F(CryptoX509CertChainTest, ValidateCoreTest005, TestSize.Level0)
{
    ASSERT_NE(g_certChainPemSpi, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainDataPemRoot, trustAnchorArray);

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;

    HcfX509CertChainValidateResult result = { 0 };
    CfResult ret = g_certChainPemSpi->engineValidate(g_certChainPemSpi, &pCertChainValidateParams, &result);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(result.entityCert, nullptr);
    ASSERT_NE(result.trustAnchor, nullptr);

    FreeTrustAnchorArr(trustAnchorArray);
    FreeValidateResult(result);
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

HWTEST_F(CryptoX509CertChainTest, HcfX509CertChainByParamsSpiCreateTest001, TestSize.Level0)
{
    CF_LOG_I("HcfX509CertChainByParamsSpiCreateTest001");
    HcfX509CertChainBuildParameters inParams;
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

HWTEST_F(CryptoX509CertChainTest, HcfX509CertChainByParamsSpiCreateInvalidParamTest, TestSize.Level0)
{
    CF_LOG_I("HcfX509CertChainByParamsSpiCreateInvalidParamTest");
    HcfX509CertChainBuildParameters inParams;
    HcfX509CertChainSpi *spi = nullptr;

    CfResult result = HcfX509CertChainByParamsSpiCreate(NULL, &spi);
    EXPECT_EQ(result, CF_INVALID_PARAMS);

    result = HcfX509CertChainByParamsSpiCreate(&inParams, NULL);
    EXPECT_EQ(result, CF_INVALID_PARAMS);

    result = HcfX509CertChainByParamsSpiCreate(NULL, NULL);
    EXPECT_EQ(result, CF_INVALID_PARAMS);
}

HWTEST_F(CryptoX509CertChainTest, HcfX509CertChainByParamsSpiCreateTest002, TestSize.Level0)
{
    CF_LOG_I("HcfX509CertChainByParamsSpiCreateTest002");
    HcfX509CertChainBuildParameters inParams;
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
        .WillOnce(Return(NULL))
        .WillRepeatedly(Invoke(__real_OPENSSL_sk_new_null));
    CfResult result = HcfX509CertChainByParamsSpiCreate(&inParams, &spi);
    EXPECT_EQ(result, CF_ERR_MALLOC);
    X509OpensslMock::SetMockFlag(false);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), OPENSSL_sk_new_null())
        .WillOnce(Invoke(__real_OPENSSL_sk_new_null))
        .WillOnce(Return(NULL))
        .WillRepeatedly(Invoke(__real_OPENSSL_sk_new_null));
    result = HcfX509CertChainByParamsSpiCreate(&inParams, &spi);
    EXPECT_EQ(result, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), OPENSSL_sk_new_null())
        .WillOnce(Invoke(__real_OPENSSL_sk_new_null))
        .WillOnce(Invoke(__real_OPENSSL_sk_new_null))
        .WillOnce(Return(NULL))
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

HWTEST_F(CryptoX509CertChainTest, HcfX509CertChainByParamsSpiCreateTest003, TestSize.Level0)
{
    CF_LOG_I("HcfX509CertChainByParamsSpiCreateTest003");
    HcfX509CertChainBuildParameters inParams;
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
        .WillOnce(Return(NULL))
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

HWTEST_F(CryptoX509CertChainTest, HcfCertChainBuildResultCreateTest001, TestSize.Level0)
{
    CF_LOG_I("HcfCertChainBuildResultCreateTest001");
    HcfX509CertChainBuildParameters inParams;
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

HWTEST_F(CryptoX509CertChainTest, HcfX509CreateTrustAnchorWithKeyStoreFuncTest001, TestSize.Level0)
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
    EXPECT_NE(trustAnchorArray, NULL);
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

HWTEST_F(CryptoX509CertChainTest, HcfX509CreateTrustAnchorWithKeyStoreFuncTest002, TestSize.Level0)
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

HWTEST_F(CryptoX509CertChainTest, HcfX509CreateTrustAnchorWithKeyStoreFuncTest003, TestSize.Level0)
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

HWTEST_F(CryptoX509CertChainTest, HcfX509CreateTrustAnchorWithKeyStoreFuncTest004, TestSize.Level0)
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

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), OPENSSL_sk_value(_, _))
        .WillOnce(Return(NULL))
        .WillRepeatedly(Invoke(__real_OPENSSL_sk_value));
    result = HcfX509CreateTrustAnchorWithKeyStoreFunc(&keyStore, &pwd, &trustAnchorArray);
    EXPECT_EQ(result, CF_SUCCESS);
    X509OpensslMock::SetMockFlag(false);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), i2d_X509(_, _))
        .WillOnce(Return(-1))
        .WillRepeatedly(Invoke(__real_i2d_X509));
    result = HcfX509CreateTrustAnchorWithKeyStoreFunc(&keyStore, &pwd, &trustAnchorArray);
    EXPECT_EQ(result, CF_SUCCESS);
    X509OpensslMock::SetMockFlag(false);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), HcfX509CertificateCreate(_, _))
        .WillOnce(Return(CF_INVALID_PARAMS))
        .WillRepeatedly(Invoke(__real_HcfX509CertificateCreate));
    result = HcfX509CreateTrustAnchorWithKeyStoreFunc(&keyStore, &pwd, &trustAnchorArray);
    EXPECT_EQ(result, CF_SUCCESS);
    X509OpensslMock::SetMockFlag(false);
}

HWTEST_F(CryptoX509CertChainTest, HcfCreateTrustAnchorWithKeyStoreTest001, TestSize.Level0)
{
    CF_LOG_I("HcfCreateTrustAnchorWithKeyStoreTest001");
    CfBlob keyStore;
    CfBlob pwd;
    HcfX509TrustAnchorArray *trustAnchorArray = NULL;

    keyStore.data = const_cast<uint8_t *>(g_testChainKeystore);
    keyStore.size = sizeof(g_testChainKeystore);
    pwd.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testKeystorePwd));
    pwd.size = sizeof(g_testKeystorePwd);
    CfResult result = HcfCreateTrustAnchorWithKeyStore(&keyStore, &pwd, &trustAnchorArray);
    EXPECT_EQ(result, CF_SUCCESS);
    EXPECT_NE(trustAnchorArray, NULL);
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
} // namespace
