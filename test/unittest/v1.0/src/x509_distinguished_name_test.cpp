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
#include "x509_distinguished_name.h"
#include "x509_distinguished_name_openssl.h"
#include "x509_distinguished_name_spi.h"

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

int __real_ASN1_STRING_length(const ASN1_STRING *x);
X509_NAME *__real_X509_NAME_new(void);
int __real_OBJ_txt2nid(const char *s);

#ifdef __cplusplus
}
#endif

namespace {
#define HCF_X509_DIST_NAME_VALID_CLASS "HcfX509DistinguishedName"
#define X509_DISTINGUISHED_NAME_OPENSSL_CLASS "X509DistinguishedNameOpensslClass"

typedef struct {
    HcfX509DistinguishedName base;
    HcfX509DistinguishedNameSpi *spiObj;
    const char *certType;
} HcfX509DistinguishedNameImpl;

static const char *GetValidX509DistinguishedNameClass(void)
{
    return HCF_X509_DIST_NAME_VALID_CLASS;
}

static const char *GetX509DistinguishedNameOpensslClass(void)
{
    return X509_DISTINGUISHED_NAME_OPENSSL_CLASS;
}

class X509DistinguishedNameTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

static HcfX509Certificate *g_x509CertObj = nullptr;
static HcfX509DistinguishedName *g_x509Name = nullptr;
static HcfX509DistinguishedNameSpi *g_x509NameSpi = nullptr;

void X509DistinguishedNameTest::SetUpTestCase()
{
    HcfX509Certificate *x509CertObj = nullptr;
    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testSelfSignedCaCert));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testSelfSignedCaCert) + 1;
    (void)HcfX509CertificateCreate(&inStream, &x509CertObj);
    ASSERT_NE(x509CertObj, nullptr);
    g_x509CertObj = x509CertObj;

    CfBlob out = { 0 };
    CfResult ret = g_x509CertObj->getIssuerName(g_x509CertObj, &out);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(out.data, nullptr);

    HcfX509DistinguishedName *x509Name = nullptr;
    ret = HcfX509DistinguishedNameCreate(&out, true, &x509Name);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509Name, nullptr);
    g_x509Name = x509Name;

    HcfX509DistinguishedNameImpl *x509NameImpl = (HcfX509DistinguishedNameImpl *)x509Name;
    g_x509NameSpi = x509NameImpl->spiObj;

    CfBlobDataClearAndFree(&out);
}

void X509DistinguishedNameTest::TearDownTestCase()
{
    // test DestroyX509DistinguishedNameOpenssl failed case
    g_x509NameSpi->base.destroy(NULL);

    g_x509NameSpi->base.getClass = GetInvalidCertClass;
    g_x509NameSpi->base.destroy((CfObjectBase *)g_x509NameSpi);

    // restore getClass
    g_x509NameSpi->base.getClass = GetX509DistinguishedNameOpensslClass;

    CfObjDestroy(g_x509CertObj);
    CfObjDestroy(g_x509Name);
}

void X509DistinguishedNameTest::SetUp() {}

void X509DistinguishedNameTest::TearDown() {}

HWTEST_F(X509DistinguishedNameTest, HcfX509DistinguishedNameCreateTest001, TestSize.Level0)
{
    CF_LOG_I("HcfX509DistinguishedNameCreateTest001");
    ASSERT_NE(g_x509CertObj, nullptr);

    CfBlob out = { 0 };
    CfResult ret = g_x509CertObj->getIssuerName(g_x509CertObj, &out);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(out.data, nullptr);

    HcfX509DistinguishedName *x509Name = nullptr;
    ret = HcfX509DistinguishedNameCreate(&out, true, &x509Name);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509Name, nullptr);

    // test DestroyX509DistinguishedName failed case
    x509Name->base.destroy(NULL);

    x509Name->base.getClass = GetInvalidCertClass;
    CfObjDestroy(x509Name);

    // restore getClass
    x509Name->base.getClass = GetValidX509DistinguishedNameClass;
    CfObjDestroy(x509Name);

    CfBlobDataClearAndFree(&out);
}

HWTEST_F(X509DistinguishedNameTest, HcfX509DistinguishedNameCreateTest002, TestSize.Level0)
{
    CF_LOG_I("HcfX509DistinguishedNameCreateTest002");
    ASSERT_NE(g_x509CertObj, nullptr);

    CfBlob out = { 0 };
    CfResult ret = g_x509CertObj->getIssuerName(g_x509CertObj, &out);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(out.data, nullptr);

    HcfX509DistinguishedName *x509Name = nullptr;
    ret = HcfX509DistinguishedNameCreate(&out, false, &x509Name);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);

    ret = HcfX509DistinguishedNameCreate(NULL, true, &x509Name);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = HcfX509DistinguishedNameCreate(&out, true, NULL);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = HcfX509DistinguishedNameCreate(NULL, true, NULL);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    CfBlobDataClearAndFree(&out);
}

HWTEST_F(X509DistinguishedNameTest, OpensslX509DistinguishedNameSpiCreateTest001, TestSize.Level0)
{
    CF_LOG_I("OpensslX509DistinguishedNameSpiCreateTest001");
    ASSERT_NE(g_x509CertObj, nullptr);

    CfBlob out = { 0 };
    CfResult ret = g_x509CertObj->getIssuerName(g_x509CertObj, &out);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(out.data, nullptr);

    HcfX509DistinguishedNameSpi *spi = nullptr;
    ret = OpensslX509DistinguishedNameSpiCreate(&out, true, &spi);
    EXPECT_EQ(ret, CF_SUCCESS);
    CfObjDestroy(spi);

    SetMockFlag(true);
    ret = OpensslX509DistinguishedNameSpiCreate(&out, true, &spi);
    EXPECT_EQ(ret, CF_ERR_MALLOC);
    SetMockFlag(false);

    ret = OpensslX509DistinguishedNameSpiCreate(NULL, true, &spi);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = OpensslX509DistinguishedNameSpiCreate(&out, true, NULL);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = OpensslX509DistinguishedNameSpiCreate(NULL, true, NULL);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    // test CollectAndParseName failed case
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), OBJ_txt2nid(_))
        .WillOnce(Return(NID_undef))
        .WillRepeatedly(Invoke(__real_OBJ_txt2nid));
    ret = OpensslX509DistinguishedNameSpiCreate(&out, true, &spi);
    EXPECT_EQ(ret, CF_SUCCESS);
    X509OpensslMock::SetMockFlag(false);

    // test ParseName failed case
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_NAME_add_entry_by_NID(_, _, _, _, _, _, _))
        .Times(AnyNumber())
        .WillOnce(Return(0));
    ret = OpensslX509DistinguishedNameSpiCreate(&out, true, &spi);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    CF_LOG_I("OpensslX509DistinguishedNameSpiCreateTest001 - 1");
    out.data[3] = '+';
    ret = OpensslX509DistinguishedNameSpiCreate(&out, true, &spi);
    EXPECT_EQ(ret, CF_SUCCESS);

    CF_LOG_I("OpensslX509DistinguishedNameSpiCreateTest001 - 2");
    out.data[3] = '\\';
    out.data[4] = '\0';
    ret = OpensslX509DistinguishedNameSpiCreate(&out, true, &spi);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);

    CF_LOG_I("OpensslX509DistinguishedNameSpiCreateTest001 - 3");
    out.data[2] = '\0';
    ret = OpensslX509DistinguishedNameSpiCreate(&out, true, &spi);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);

    CfBlobDataClearAndFree(&out);
}

HWTEST_F(X509DistinguishedNameTest, OpensslX509DistinguishedNameSpiCreateTest002, TestSize.Level0)
{
    CF_LOG_I("OpensslX509DistinguishedNameSpiCreateTest002");
    ASSERT_NE(g_x509CertObj, nullptr);

    CfBlob out = { 0 };
    CfResult ret = g_x509CertObj->getIssuerName(g_x509CertObj, &out);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(out.data, nullptr);

    HcfX509DistinguishedNameSpi *spi = nullptr;
    ret = OpensslX509DistinguishedNameSpiCreate(&out, true, &spi);
    EXPECT_EQ(ret, CF_SUCCESS);
    CfObjDestroy(spi);

    // test ParseName failed case
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_NAME_new())
        .WillOnce(Return(NULL))
        .WillRepeatedly(Invoke(__real_X509_NAME_new));
    ret = OpensslX509DistinguishedNameSpiCreate(&out, true, &spi);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    // test ParseName failed case
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), CRYPTO_strdup(_, _, _)).Times(AnyNumber()).WillOnce(Return(NULL));
    ret = OpensslX509DistinguishedNameSpiCreate(&out, true, &spi);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    // test ParseName cp != / failed case
    out.data[0] = 'a';
    ret = OpensslX509DistinguishedNameSpiCreate(&out, true, &spi);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);

    CfBlobDataClearAndFree(&out);
}

HWTEST_F(X509DistinguishedNameTest, GetEncodeTest001, TestSize.Level0)
{
    CF_LOG_I("GetEncodeTest001");
    ASSERT_NE(g_x509Name, nullptr);

    CfEncodingBlob blob = { nullptr, 0, CF_FORMAT_DER };
    CfResult ret = g_x509Name->getEncode(g_x509Name, &blob);
    EXPECT_EQ(ret, CF_SUCCESS);
    CfEncodingBlobDataFree(&blob);

    HcfX509DistinguishedName x509Name;
    x509Name.base.getClass = GetInvalidCertClass;

    ret = g_x509Name->getEncode(&x509Name, &blob);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_x509Name->getEncode(NULL, &blob);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_x509Name->getEncode(g_x509Name, NULL);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_x509Name->getEncode(NULL, NULL);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    SetMockFlag(true);
    ret = g_x509Name->getEncode(g_x509Name, &blob);
    EXPECT_EQ(ret, CF_ERR_MALLOC);
    SetMockFlag(false);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_NAME_get0_der(_, _, _)).Times(AnyNumber()).WillOnce(Return(-1));
    ret = g_x509Name->getEncode(g_x509Name, &blob);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);
}

HWTEST_F(X509DistinguishedNameTest, GetNameTest001, TestSize.Level0)
{
    CF_LOG_I("GetNameTest001");
    ASSERT_NE(g_x509Name, nullptr);

    // PARAM0
    CfBlob blob = { 0, nullptr };
    CfResult ret = g_x509Name->getName(g_x509Name, NULL, &blob, NULL);
    EXPECT_EQ(ret, CF_SUCCESS);
    CfBlobDataFree(&blob);

    // test GetNameOpenssl failed case
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_NAME_oneline(_, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(NULL));
    ret = g_x509Name->getName(g_x509Name, NULL, &blob, NULL);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    // PARAM1
    CfBlob inPara = { 0, nullptr };
    CfArray outArr = { nullptr, CF_FORMAT_DER, 0 };
    ret = g_x509Name->getName(g_x509Name, &inPara, NULL, &outArr);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);
    CfArrayDataClearAndFree(&outArr);

    inPara.data = (uint8_t *)"emailAddress";
    inPara.size = strlen("emailAddress") + 1;

    SetMockFlag(true);
    ret = g_x509Name->getName(g_x509Name, &inPara, NULL, &outArr);
    EXPECT_EQ(ret, CF_ERR_MALLOC);
    SetMockFlag(false);

    ret = g_x509Name->getName(g_x509Name, &inPara, NULL, &outArr);
    EXPECT_EQ(ret, CF_SUCCESS);

    ret = g_x509Name->getName(g_x509Name, NULL, NULL, NULL);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_x509Name->getName(g_x509Name, &inPara, NULL, NULL);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    inPara.data = (uint8_t *)"test";
    inPara.size = strlen("test") + 1;
    ret = g_x509Name->getName(g_x509Name, &inPara, NULL, &outArr);
    EXPECT_EQ(ret, CF_SUCCESS);

    HcfX509DistinguishedName x509Name;
    x509Name.base.getClass = GetInvalidCertClass;

    ret = g_x509Name->getName(&x509Name, NULL, &blob, NULL);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_x509Name->getName(NULL, NULL, &blob, NULL);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);
}

HWTEST_F(X509DistinguishedNameTest, GetNameTest002, TestSize.Level0)
{
    CF_LOG_I("GetNameTest001");
    ASSERT_NE(g_x509Name, nullptr);

    CfResult ret;
    CfBlob inPara = { 0, nullptr };
    CfArray outArr = { nullptr, CF_FORMAT_DER, 0 };

    inPara.data = (uint8_t *)"emailAddress";
    inPara.size = strlen("emailAddress") + 1;

    // test GetDataByEntryOpenssl failed case
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), ASN1_STRING_length(_))
        .WillOnce(Return(-1))
        .WillRepeatedly(Invoke(__real_ASN1_STRING_length));
    ret = g_x509Name->getName(g_x509Name, &inPara, NULL, &outArr);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), DeepCopyDataToOut(_, _, _))
        .Times(AnyNumber())
        .WillOnce(Return(CF_ERR_CRYPTO_OPERATION));
    ret = g_x509Name->getName(g_x509Name, &inPara, NULL, &outArr);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    // test GetNameByTypeOpenssl failed case
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), OBJ_nid2sn(_)).Times(AnyNumber()).WillRepeatedly(Return(NULL));
    ret = g_x509Name->getName(g_x509Name, &inPara, NULL, &outArr);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);
}

HWTEST_F(X509DistinguishedNameTest, HcfX509DistinguishedNameSpiEngineGetEncodeTest001, TestSize.Level0)
{
    CF_LOG_I("GetEncodeTest001");
    ASSERT_NE(g_x509NameSpi, nullptr);

    CfEncodingBlob blob = { nullptr, 0, CF_FORMAT_DER };
    CfResult ret = g_x509NameSpi->engineGetEncode(g_x509NameSpi, &blob);
    EXPECT_EQ(ret, CF_SUCCESS);
    CfEncodingBlobDataFree(&blob);

    HcfX509DistinguishedNameSpi invalidDistinguishedNameSpi;
    invalidDistinguishedNameSpi.base.getClass = GetInvalidCertClass;

    ret = g_x509NameSpi->engineGetEncode(&invalidDistinguishedNameSpi, &blob);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_x509NameSpi->engineGetEncode(NULL, &blob);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_x509NameSpi->engineGetEncode(g_x509NameSpi, NULL);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_x509NameSpi->engineGetEncode(NULL, NULL);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);
}

HWTEST_F(X509DistinguishedNameTest, HcfX509DistinguishedNameSpiEngineGetNameTest001, TestSize.Level0)
{
    CF_LOG_I("HcfX509DistinguishedNameSpiEngineGetNameTest001");
    ASSERT_NE(g_x509NameSpi, nullptr);

    // PARAM0
    CfBlob blob = { 0, nullptr };
    CfResult ret = g_x509NameSpi->engineGetName(g_x509NameSpi, NULL, &blob, NULL);
    EXPECT_EQ(ret, CF_SUCCESS);
    CfBlobDataFree(&blob);

    // PARAM1
    CfBlob inPara = { 0, nullptr };
    CfArray outArr = { nullptr, CF_FORMAT_DER, 0 };
    ret = g_x509NameSpi->engineGetName(g_x509NameSpi, &inPara, NULL, &outArr);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);
    CfArrayDataClearAndFree(&outArr);

    HcfX509DistinguishedNameSpi invalidDistinguishedNameSpi;
    invalidDistinguishedNameSpi.base.getClass = GetInvalidCertClass;

    ret = g_x509NameSpi->engineGetName(&invalidDistinguishedNameSpi, NULL, &blob, NULL);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_x509NameSpi->engineGetName(NULL, NULL, &blob, NULL);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);
}

} // namespace
