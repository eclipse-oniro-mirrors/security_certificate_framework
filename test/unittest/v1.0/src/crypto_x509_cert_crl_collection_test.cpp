/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>

#include "cert_crl_collection.h"
#include "certificate_openssl_common.h"
#include "cf_api.h"
#include "cf_blob.h"
#include "cf_param.h"
#include "cf_result.h"
#include "cf_type.h"
#include "crypto_x509_test_common.h"
#include "memory_mock.h"
#include "securec.h"
#include "x509_certificate.h"
#include "x509_certificate_openssl.h"

using namespace std;
using namespace testing::ext;

namespace {
static HcfCertCrlCollection *g_x509CertCrlCollection = nullptr;
static HcfX509Certificate *g_x509CertObj = nullptr;
static HcfX509Crl *g_x509Crl = nullptr;

class CryptoX509CertCrlCollectionTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void CryptoX509CertCrlCollectionTest::SetUpTestCase(void)
{
    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testSelfSignedCaCert));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testSelfSignedCaCert) + 1;
    CfResult ret = HcfX509CertificateCreate(&inStream, &g_x509CertObj);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(g_x509CertObj, nullptr);

    ret = HcfX509CrlCreate(&g_crlDerInStream, &g_x509Crl);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(g_x509Crl, nullptr);

    HcfX509CertificateArray certArray = { 0 };
    HcfX509CrlArray crlArray = { 0 };

    certArray.data = static_cast<HcfX509Certificate **>(CfMalloc(1 * sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(certArray.data, nullptr);
    certArray.data[0] = g_x509CertObj;
    certArray.count = 1;

    crlArray.data = static_cast<HcfX509Crl **>(CfMalloc(1 * sizeof(HcfX509Crl *), 0));
    ASSERT_NE(crlArray.data, nullptr);
    crlArray.data[0] = g_x509Crl;
    crlArray.count = 1;

    ret = HcfCertCrlCollectionCreate(&certArray, &crlArray, &g_x509CertCrlCollection);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(g_x509CertCrlCollection, nullptr);

    CfFree(certArray.data);
    CfFree(crlArray.data);
}

void CryptoX509CertCrlCollectionTest::TearDownTestCase(void)
{
    CfObjDestroy(g_x509CertObj);
    CfObjDestroy(g_x509Crl);
    CfObjDestroy(g_x509CertCrlCollection);
}

void CryptoX509CertCrlCollectionTest::SetUp() {}

void CryptoX509CertCrlCollectionTest::TearDown() {}

static const char *GetInvalidCertCrlCollectionClass(void)
{
    return "INVALID_CERT_CRL_COLLECTION_CLASS";
}

static void FreeCertArrayData(HcfX509CertificateArray *certs)
{
    if (certs == NULL) {
        return;
    }
    for (uint32_t i = 0; i < certs->count; ++i) {
        CfObjDestroy(certs->data[i]);
    }
    CfFree(certs->data);
    certs->data = NULL;
    certs->count = 0;
}

static void FreeCrlArrayData(HcfX509CrlArray *crls)
{
    if (crls == NULL) {
        return;
    }
    for (uint32_t i = 0; i < crls->count; ++i) {
        CfObjDestroy(crls->data[i]);
    }
    CfFree(crls->data);
    crls->data = NULL;
    crls->count = 0;
}

HWTEST_F(CryptoX509CertCrlCollectionTest, SelectCertsTest001, TestSize.Level0)
{
    ASSERT_NE(g_x509CertCrlCollection, nullptr);
    HcfX509CertificateArray retCerts;
    HcfX509CertMatchParams matchParams;
    CfResult ret = g_x509CertCrlCollection->selectCerts(nullptr, &matchParams, &retCerts);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);
}

HWTEST_F(CryptoX509CertCrlCollectionTest, SelectCertsTest002, TestSize.Level0)
{
    HcfCertCrlCollection *invalidTypeCollection = nullptr;
    HcfX509CertificateArray *certArray =
        static_cast<HcfX509CertificateArray *>(CfMalloc(sizeof(HcfX509CertificateArray), 0));
    ASSERT_NE(certArray, nullptr);

    HcfX509CrlArray *crlArray = static_cast<HcfX509CrlArray *>(CfMalloc(sizeof(HcfX509CrlArray), 0));
    ASSERT_NE(crlArray, nullptr);

    CfResult ret = HcfCertCrlCollectionCreate(certArray, crlArray, &invalidTypeCollection);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(invalidTypeCollection, nullptr);
    invalidTypeCollection->base.getClass = GetInvalidCertCrlCollectionClass;

    HcfX509CertMatchParams matchCertParams;
    HcfX509CertificateArray retCerts;
    ret = invalidTypeCollection->selectCerts(invalidTypeCollection, &matchCertParams, &retCerts);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    HcfX509CrlArray retCrls;
    HcfX509CrlMatchParams matchCrlParams;
    ret = invalidTypeCollection->selectCRLs(invalidTypeCollection, &matchCrlParams, &retCrls);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    // destroy invalid type class:failed
    CfObjDestroy(invalidTypeCollection);

    // destroy normal type class:success
    ASSERT_NE(g_x509CertCrlCollection, nullptr);
    invalidTypeCollection->base.getClass = g_x509CertCrlCollection->base.getClass;
    CfObjDestroy(invalidTypeCollection);

    CfFree(certArray);
    CfFree(crlArray);
    FreeCertArrayData(&retCerts);
    FreeCrlArrayData(&retCrls);
}

HWTEST_F(CryptoX509CertCrlCollectionTest, SelectCertsTest003, TestSize.Level0)
{
    ASSERT_NE(g_x509CertCrlCollection, nullptr);
    HcfX509CertMatchParams matchParams;
    CfResult ret = g_x509CertCrlCollection->selectCerts(g_x509CertCrlCollection, &matchParams, nullptr);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);
}

HWTEST_F(CryptoX509CertCrlCollectionTest, SelectCertsTest004, TestSize.Level0)
{
    HcfCertCrlCollection *x509CertCrlCollection = nullptr;
    HcfX509CertificateArray *certArray =
        static_cast<HcfX509CertificateArray *>(CfMalloc(sizeof(HcfX509CertificateArray), 0));
    ASSERT_NE(certArray, nullptr);

    HcfX509CrlArray *crlArray = static_cast<HcfX509CrlArray *>(CfMalloc(sizeof(HcfX509CrlArray), 0));
    ASSERT_NE(crlArray, nullptr);

    CfResult ret = HcfCertCrlCollectionCreate(certArray, crlArray, &x509CertCrlCollection);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(x509CertCrlCollection, nullptr);

    HcfX509CertificateArray retCerts;
    HcfX509CertMatchParams matchParams;
    ret = x509CertCrlCollection->selectCerts(x509CertCrlCollection, &matchParams, &retCerts);
    EXPECT_NE(ret, CF_SUCCESS);

    CfFree(certArray);
    CfFree(crlArray);
    CfObjDestroy(x509CertCrlCollection);
    FreeCertArrayData(&retCerts);
}

HWTEST_F(CryptoX509CertCrlCollectionTest, SelectCertsTest005, TestSize.Level0)
{
    ASSERT_NE(g_x509CertCrlCollection, nullptr);
    HcfX509CertificateArray retCerts;
    CfResult ret = g_x509CertCrlCollection->selectCerts(g_x509CertCrlCollection, nullptr, &retCerts);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);
}

HWTEST_F(CryptoX509CertCrlCollectionTest, SelectCertsTest006, TestSize.Level0)
{
    ASSERT_NE(g_x509CertCrlCollection, nullptr);

    HcfX509Certificate *x509Cert = nullptr;
    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_secondCert));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_secondCert) + 1;
    CfResult ret = HcfX509CertificateCreate(&inStream, &x509Cert);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509Cert, nullptr);

    HcfX509CertificateArray retCerts;
    HcfX509CertMatchParams matchParams;
    matchParams.x509Cert = &(x509Cert->base);
    ret = g_x509CertCrlCollection->selectCerts(g_x509CertCrlCollection, &matchParams, &retCerts);
    EXPECT_EQ(ret, CF_SUCCESS);

    CfObjDestroy(x509Cert);
    FreeCertArrayData(&retCerts);
}

HWTEST_F(CryptoX509CertCrlCollectionTest, SelectCertsTest007, TestSize.Level0)
{
    ASSERT_NE(g_x509CertCrlCollection, nullptr);

    HcfX509Certificate *x509Cert = nullptr;
    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testSelfSignedCaCert));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testSelfSignedCaCert) + 1;
    CfResult ret = HcfX509CertificateCreate(&inStream, &x509Cert);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509Cert, nullptr);

    HcfX509CertificateArray retCerts;
    HcfX509CertMatchParams matchParams;
    matchParams.x509Cert = &(x509Cert->base);
    ret = g_x509CertCrlCollection->selectCerts(g_x509CertCrlCollection, &matchParams, &retCerts);
    EXPECT_EQ(ret, CF_SUCCESS);

    CfObjDestroy(x509Cert);
    FreeCertArrayData(&retCerts);
}

HWTEST_F(CryptoX509CertCrlCollectionTest, SelectCertsTest008, TestSize.Level0)
{
    HcfCertCrlCollection *x509CertCrlCollection = nullptr;
    HcfX509CertificateArray *certArray =
        static_cast<HcfX509CertificateArray *>(CfMalloc(sizeof(HcfX509CertificateArray), 0));
    ASSERT_NE(certArray, nullptr);

    HcfX509CrlArray *crlArray = static_cast<HcfX509CrlArray *>(CfMalloc(sizeof(HcfX509CrlArray), 0));
    ASSERT_NE(crlArray, nullptr);

    CfResult ret = HcfCertCrlCollectionCreate(certArray, crlArray, &x509CertCrlCollection);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(x509CertCrlCollection, nullptr);

    certArray->count = 1;
    crlArray->count = 1;

    HcfX509CertificateArray retCerts;
    HcfX509CertMatchParams matchParams;
    ret = x509CertCrlCollection->selectCerts(x509CertCrlCollection, &matchParams, &retCerts);
    EXPECT_NE(ret, CF_SUCCESS);

    HcfX509CrlArray retCrls;
    HcfX509CrlMatchParams matchCrlParams;
    ret = x509CertCrlCollection->selectCRLs(x509CertCrlCollection, &matchCrlParams, &retCrls);
    EXPECT_NE(ret, CF_SUCCESS);

    CfFree(certArray);
    CfFree(crlArray);
    CfObjDestroy(x509CertCrlCollection);
}

HWTEST_F(CryptoX509CertCrlCollectionTest, SelectCertsTest009, TestSize.Level0)
{
    HcfCertCrlCollection *x509CertCrlCollection = nullptr;
    HcfX509CertificateArray *certArray =
        static_cast<HcfX509CertificateArray *>(CfMalloc(sizeof(HcfX509CertificateArray), 0));
    ASSERT_NE(certArray, nullptr);

    certArray->data = static_cast<HcfX509Certificate **>(CfMalloc(1 * sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(certArray->data, nullptr);
    certArray->data[0] = g_x509CertObj;
    certArray->count = MAX_LEN_OF_CERT_CRL_ARR + 1;

    HcfX509CrlArray *crlArray = static_cast<HcfX509CrlArray *>(CfMalloc(sizeof(HcfX509CrlArray), 0));
    ASSERT_NE(crlArray, nullptr);

    CfResult ret = HcfCertCrlCollectionCreate(certArray, crlArray, &x509CertCrlCollection);
    ASSERT_NE(ret, CF_SUCCESS);

    CfFree(certArray->data);
    CfFree(certArray);
    CfFree(crlArray);
}

HWTEST_F(CryptoX509CertCrlCollectionTest, SelectCRLsTest001, TestSize.Level0)
{
    ASSERT_NE(g_x509CertCrlCollection, nullptr);

    HcfX509CrlArray retCrls;
    HcfX509CrlMatchParams matchParams;
    CfResult ret = g_x509CertCrlCollection->selectCRLs(nullptr, &matchParams, &retCrls);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);
}

HWTEST_F(CryptoX509CertCrlCollectionTest, SelectCRLsTest002, TestSize.Level0)
{
    ASSERT_NE(g_x509CertCrlCollection, nullptr);

    HcfX509CrlArray retCrls;
    CfResult ret = g_x509CertCrlCollection->selectCRLs(g_x509CertCrlCollection, nullptr, &retCrls);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);
}

HWTEST_F(CryptoX509CertCrlCollectionTest, SelectCRLsTest003, TestSize.Level0)
{
    ASSERT_NE(g_x509CertCrlCollection, nullptr);

    HcfX509CrlMatchParams matchParams;
    CfResult ret = g_x509CertCrlCollection->selectCRLs(g_x509CertCrlCollection, &matchParams, nullptr);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);
}

HWTEST_F(CryptoX509CertCrlCollectionTest, SelectCRLsTest004, TestSize.Level0)
{
    HcfCertCrlCollection *x509CertCrlCollection = nullptr;
    HcfX509CertificateArray *certArray =
        static_cast<HcfX509CertificateArray *>(CfMalloc(sizeof(HcfX509CertificateArray), 0));
    ASSERT_NE(certArray, nullptr);

    HcfX509CrlArray *crlArray = static_cast<HcfX509CrlArray *>(CfMalloc(sizeof(HcfX509CrlArray), 0));
    ASSERT_NE(crlArray, nullptr);

    CfResult ret = HcfCertCrlCollectionCreate(certArray, crlArray, &x509CertCrlCollection);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(x509CertCrlCollection, nullptr);

    HcfX509CrlMatchParams matchParams;
    HcfX509CrlArray retCrls;
    ret = x509CertCrlCollection->selectCRLs(x509CertCrlCollection, &matchParams, &retCrls);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    CfFree(certArray);
    CfFree(crlArray);
    CfObjDestroy(x509CertCrlCollection);
}

HWTEST_F(CryptoX509CertCrlCollectionTest, SelectCRLsTest005, TestSize.Level0)
{
    ASSERT_NE(g_x509CertCrlCollection, nullptr);

    HcfX509Certificate *x509Cert = nullptr;
    CfEncodingBlob inStreamCert = { nullptr, 0, CF_FORMAT_PEM };
    inStreamCert.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testErrorCert));
    inStreamCert.encodingFormat = CF_FORMAT_PEM;
    inStreamCert.len = strlen(g_testErrorCert) + 1;
    CfResult ret = HcfX509CertificateCreate(&inStreamCert, &x509Cert);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509Cert, nullptr);

    HcfX509CrlMatchParams matchParams;
    matchParams.x509Cert = &(x509Cert->base);
    HcfX509CrlArray retCrls;
    ret = g_x509CertCrlCollection->selectCRLs(g_x509CertCrlCollection, &matchParams, &retCrls);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(retCrls.data, nullptr);
    CfObjDestroy(x509Cert);
}

HWTEST_F(CryptoX509CertCrlCollectionTest, SelectCRLsTest006, TestSize.Level0)
{
    ASSERT_NE(g_x509CertCrlCollection, nullptr);

    // Get cert
    HcfX509Certificate *x509Cert = nullptr;
    CfResult ret = HcfX509CertificateCreate(&g_inStreamCert, &x509Cert);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509Cert, nullptr);

    HcfX509CrlMatchParams matchParams;
    matchParams.x509Cert = &(x509Cert->base);
    HcfX509CrlArray retCrls;
    ret = g_x509CertCrlCollection->selectCRLs(g_x509CertCrlCollection, &matchParams, &retCrls);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(retCrls.count > 0, true);
    EXPECT_NE(retCrls.data, nullptr);
    CfObjDestroy(x509Cert);
    FreeCrlArrayData(&retCrls);
}

HWTEST_F(CryptoX509CertCrlCollectionTest, SelectCRLsTest007, TestSize.Level0)
{
    HcfX509CertificateArray *certArray =
        static_cast<HcfX509CertificateArray *>(CfMalloc(sizeof(HcfX509CertificateArray), 0));
    ASSERT_NE(certArray, nullptr);

    HcfX509CrlArray *crlArray = static_cast<HcfX509CrlArray *>(CfMalloc(sizeof(HcfX509CrlArray), 0));
    ASSERT_NE(crlArray, nullptr);

    CfResult ret = HcfCertCrlCollectionCreate(certArray, crlArray, nullptr);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    CfFree(certArray);
    CfFree(crlArray);
}

HWTEST_F(CryptoX509CertCrlCollectionTest, SelectCRLsTest008, TestSize.Level0)
{
    HcfCertCrlCollection *x509CertCrlCollection = nullptr;
    HcfX509CertificateArray *certArray =
        static_cast<HcfX509CertificateArray *>(CfMalloc(sizeof(HcfX509CertificateArray), 0));
    ASSERT_NE(certArray, nullptr);

    HcfX509CrlArray *crlArray = static_cast<HcfX509CrlArray *>(CfMalloc(sizeof(HcfX509CrlArray), 0));
    ASSERT_NE(crlArray, nullptr);

    HcfX509Crl *x509Crl = nullptr;
    CfResult ret = HcfX509CrlCreate(&g_crlDerInStream, &x509Crl);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(x509Crl, nullptr);

    crlArray->data = static_cast<HcfX509Crl **>(CfMalloc(1 * sizeof(HcfX509Crl *), 0));
    ASSERT_NE(crlArray->data, nullptr);
    crlArray->data[0] = x509Crl;
    crlArray->count = MAX_LEN_OF_CERT_CRL_ARR + 1;

    ret = HcfCertCrlCollectionCreate(certArray, crlArray, &x509CertCrlCollection);
    ASSERT_NE(ret, CF_SUCCESS);

    CfFree(crlArray->data);
    CfFree(certArray);
    CfFree(crlArray);
    CfObjDestroy(x509Crl);
}

HWTEST_F(CryptoX509CertCrlCollectionTest, InvalidCert, TestSize.Level0)
{
    HcfCertCrlCollection *x509CertCrlCollection = nullptr;
    HcfX509CertificateArray *certArray =
        static_cast<HcfX509CertificateArray *>(CfMalloc(sizeof(HcfX509CertificateArray), 0));
    ASSERT_NE(certArray, nullptr);

    HcfX509CrlArray *crlArray = static_cast<HcfX509CrlArray *>(CfMalloc(sizeof(HcfX509CrlArray), 0));
    ASSERT_NE(crlArray, nullptr);

    HcfX509Certificate *x509CertObj = nullptr;
    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testSelfSignedCaCert));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testSelfSignedCaCert) + 1;
    (void)HcfX509CertificateCreate(&inStream, &x509CertObj);
    x509CertObj->base.base.getClass = GetInvalidCertClass;

    HcfX509Crl *x509Crl = nullptr;
    CfResult ret = HcfX509CrlCreate(&g_crlDerInStream, &x509Crl);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(x509Crl, nullptr);

    certArray->data = static_cast<HcfX509Certificate **>(CfMalloc(1 * sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(certArray->data, nullptr);
    certArray->data[0] = x509CertObj;
    certArray->count = 1;

    crlArray->data = static_cast<HcfX509Crl **>(CfMalloc(1 * sizeof(HcfX509Crl *), 0));
    ASSERT_NE(crlArray->data, nullptr);
    crlArray->data[0] = x509Crl;
    crlArray->count = 1;

    ret = HcfCertCrlCollectionCreate(certArray, crlArray, &x509CertCrlCollection);
    ASSERT_NE(ret, CF_SUCCESS);

    x509CertObj->base.base.getClass = g_x509CertObj->base.base.getClass;

    CfObjDestroy(x509CertObj);
    CfObjDestroy(x509Crl);
    CfFree(certArray->data);
    CfFree(crlArray->data);
    CfFree(certArray);
    CfFree(crlArray);
}

HWTEST_F(CryptoX509CertCrlCollectionTest, InvalidCrl, TestSize.Level0)
{
    HcfCertCrlCollection *x509CertCrlCollection = nullptr;
    HcfX509CertificateArray *certArray =
        static_cast<HcfX509CertificateArray *>(CfMalloc(sizeof(HcfX509CertificateArray), 0));
    ASSERT_NE(certArray, nullptr);

    HcfX509CrlArray *crlArray = static_cast<HcfX509CrlArray *>(CfMalloc(sizeof(HcfX509CrlArray), 0));
    ASSERT_NE(crlArray, nullptr);

    HcfX509Certificate *x509CertObj = nullptr;
    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testSelfSignedCaCert));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testSelfSignedCaCert) + 1;
    (void)HcfX509CertificateCreate(&inStream, &x509CertObj);

    HcfX509Crl *x509Crl = nullptr;
    CfResult ret = HcfX509CrlCreate(&g_crlDerInStream, &x509Crl);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(x509Crl, nullptr);

    certArray->data = static_cast<HcfX509Certificate **>(CfMalloc(1 * sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(certArray->data, nullptr);
    certArray->data[0] = x509CertObj;
    certArray->count = 1;

    crlArray->data = static_cast<HcfX509Crl **>(CfMalloc(1 * sizeof(HcfX509Crl *), 0));
    ASSERT_NE(crlArray->data, nullptr);
    crlArray->data[0] = x509Crl;
    crlArray->count = 1;
    x509Crl->base.base.getClass = GetInvalidCrlClass;

    ret = HcfCertCrlCollectionCreate(certArray, crlArray, &x509CertCrlCollection);
    ASSERT_NE(ret, CF_SUCCESS);

    x509Crl->base.base.getClass = g_x509Crl->base.base.getClass;

    CfObjDestroy(x509CertObj);
    CfObjDestroy(x509Crl);
    CfFree(certArray->data);
    CfFree(crlArray->data);
    CfFree(certArray);
    CfFree(crlArray);
}

} // namespace
