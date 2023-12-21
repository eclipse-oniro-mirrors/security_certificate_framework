/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "cf_blob.h"
#include "cf_object_base.h"
#include "cf_result.h"
#include "crypto_x509_test_common.h"
#include "memory_mock.h"
#include "securec.h"
#include "string"
#include "x509_cert_chain.h"
#include "x509_cert_chain_openssl.h"
#include "x509_certificate_openssl.h"
#include "cert_crl_common.h"

using namespace std;
using namespace testing::ext;

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
constexpr uint32_t DATE_TIME_LENGTH = 16;

static const char *GetInvalidCertChainClass(void)
{
    return "HcfInvalidCertChain";
}

static void FreeTrustAnchor(HcfX509TrustAnchor *&trustAnchor)
{
    if (trustAnchor == nullptr) {
        return;
    }
    CfBlobFree(&trustAnchor->CAPubKey);
    CfBlobFree(&trustAnchor->CASubject);
    CfObjDestroy(trustAnchor->CACert);
    trustAnchor->CACert = nullptr;
    CfFree(trustAnchor);
    trustAnchor = nullptr;
}

static void BuildAnchorArr(const CfEncodingBlob &certInStream, HcfX509TrustAnchorArray &trustAnchorArray)
{
    HcfX509TrustAnchor *anchor = (HcfX509TrustAnchor *)HcfMalloc(sizeof(HcfX509TrustAnchor), 0);
    ASSERT_NE(anchor, nullptr);

    (void)HcfX509CertificateCreate(&certInStream, &anchor->CACert);
    trustAnchorArray.data = (HcfX509TrustAnchor **)HcfMalloc(1 * sizeof(HcfX509TrustAnchor *), 0);
    ASSERT_NE(trustAnchorArray.data, nullptr);
    trustAnchorArray.data[0] = anchor;
    trustAnchorArray.count = 1;
}

static void FreeTrustAnchorArr(HcfX509TrustAnchorArray &trustAnchorArray)
{
    for (uint32_t i = 0; i < trustAnchorArray.count; ++i) {
        HcfX509TrustAnchor *anchor = trustAnchorArray.data[i];
        FreeTrustAnchor(anchor);
    }
    CfFree(trustAnchorArray.data);
    trustAnchorArray.data = nullptr;
    trustAnchorArray.count = 0;
}

static void BuildCollectionArr(const CfEncodingBlob *certInStream, const CfEncodingBlob *crlInStream,
    HcfCertCRLCollectionArray &certCRLCollections)
{
    CfResult ret = CF_SUCCESS;
    HcfX509CertificateArray *certArray = nullptr;
    if (certInStream != nullptr) {
        certArray = (HcfX509CertificateArray *)HcfMalloc(sizeof(HcfX509CertificateArray), 0);
        ASSERT_NE(certArray, nullptr);

        HcfX509Certificate *x509CertObj = nullptr;
        (void)HcfX509CertificateCreate(certInStream, &x509CertObj);
        ASSERT_NE(x509CertObj, nullptr);

        certArray->data = (HcfX509Certificate **)HcfMalloc(1 * sizeof(HcfX509Certificate *), 0);
        ASSERT_NE(certArray->data, nullptr);
        certArray->data[0] = x509CertObj;
        certArray->count = 1;
    }

    HcfX509CrlArray *crlArray = nullptr;
    if (crlInStream != nullptr) {
        crlArray = (HcfX509CrlArray *)HcfMalloc(sizeof(HcfX509CrlArray), 0);
        ASSERT_NE(crlArray, nullptr);

        HcfX509Crl *x509Crl = nullptr;
        ret = HcfX509CrlCreate(crlInStream, &x509Crl);
        ASSERT_EQ(ret, CF_SUCCESS);
        ASSERT_NE(x509Crl, nullptr);

        crlArray->data = (HcfX509Crl **)HcfMalloc(1 * sizeof(HcfX509Crl *), 0);
        ASSERT_NE(crlArray->data, nullptr);
        crlArray->data[0] = x509Crl;
        crlArray->count = 1;
    }

    HcfCertCrlCollection *x509CertCrlCollection = nullptr;
    ret = HcfCertCrlCollectionCreate(certArray, crlArray, &x509CertCrlCollection);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(x509CertCrlCollection, nullptr);

    certCRLCollections.data = (HcfCertCrlCollection **)HcfMalloc(1 * sizeof(HcfCertCrlCollection *), 0);
    ASSERT_NE(certCRLCollections.data, nullptr);
    certCRLCollections.data[0] = x509CertCrlCollection;
    certCRLCollections.count = 1;

    FreeCertArrayData(certArray);
    CfFree(certArray);
    FreeCrlArrayData(crlArray);
    CfFree(crlArray);
}

void CryptoX509CertChainTest::SetUpTestCase()
{
    CfResult ret = HcfCertChainCreate(&g_inStreamChainDataP7b, nullptr, &g_certChainP7b);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(g_certChainP7b, nullptr);

    HcfX509Certificate *x509CertObj = nullptr;
    CfEncodingBlob inStream = { 0 };
    inStream.data = (uint8_t *)g_testSelfSignedCaCert;
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

static void FreeCertCrlCollectionArr(HcfCertCRLCollectionArray &certCRLCollections)
{
    for (uint32_t i = 0; i < certCRLCollections.count; ++i) {
        HcfCertCrlCollection *collection = certCRLCollections.data[i];
        CfObjDestroy(collection);
    }
    CfFree(certCRLCollections.data);
    certCRLCollections.data = nullptr;
    certCRLCollections.count = 0;
}

static void FreeValidateResult(HcfX509CertChainValidateResult &result)
{
    if (result.entityCert != nullptr) {
        CfObjDestroy(result.entityCert);
        result.entityCert = nullptr;
    }

    if (result.trustAnchor != nullptr) {
        FreeTrustAnchor(result.trustAnchor);
    }
}

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
    inStream.data = (uint8_t *)HcfMalloc(g_inStreamChainDataP7b.len, 0);
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
    inStream.data = (uint8_t *)HcfMalloc(g_inStreamChainDataDer.len, 0);
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
    inStream.data = (uint8_t *)HcfMalloc(g_inStreamChainDataDer.len, 0);
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
    inStream.data = (uint8_t *)HcfMalloc(g_inStreamChainDataPem.len, 0);
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
    inStream.data = (uint8_t *)HcfMalloc(g_inStreamChainDataDer.len, 0);
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
    inStream.data = (uint8_t *)HcfMalloc(g_inStreamChainDataDer.len, 0);
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

    certArray.data = (HcfX509Certificate **)HcfMalloc(1 * sizeof(HcfX509Certificate *), 0);
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

    certArray.data = (HcfX509Certificate **)HcfMalloc(1 * sizeof(HcfX509Certificate *), 0);
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

    certArray.data = (HcfX509Certificate **)HcfMalloc(1 * sizeof(HcfX509Certificate *), 0);
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

    certArray.data = (HcfX509Certificate **)HcfMalloc(1 * sizeof(HcfX509Certificate *), 0);
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

    certArray.data = (HcfX509Certificate **)HcfMalloc(1 * sizeof(HcfX509Certificate *), 0);
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
    inStream.data = (uint8_t *)HcfMalloc(g_inStreamChainDataDer.len, 0);
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
    ASSERT_NE(g_certChainP7bSpi, nullptr);
    CfResult ret = g_certChainP7bSpi->engineValidate(g_certChainP7bSpi, nullptr, nullptr);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest003, TestSize.Level0)
{
    ASSERT_NE(g_certChainP7bSpi, nullptr);
    HcfX509TrustAnchor anchor = { 0 };
    CfEncodingBlob inStream = { 0 };
    inStream.data = (uint8_t *)g_testSelfSignedCaCert;
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testSelfSignedCaCert) + 1;
    (void)HcfX509CertificateCreate(&inStream, &anchor.CACert);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    trustAnchorArray.data = (HcfX509TrustAnchor **)HcfMalloc(1 * sizeof(HcfX509TrustAnchor *), 0);
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
    ASSERT_NE(g_certChainPemSpi, nullptr);

    HcfX509TrustAnchor anchor = { 0 };

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    trustAnchorArray.data = (HcfX509TrustAnchor **)HcfMalloc(1 * sizeof(HcfX509TrustAnchor *), 0);
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
    ASSERT_NE(g_certChainPemSpi, nullptr);

    CfBlob pubkey = { 0, nullptr };
    pubkey.data = (uint8_t *)(&g_testChainPubkeyPemRootData[0]);
    pubkey.size = g_testChainPubkeyPemRootDataSize;

    HcfX509TrustAnchor anchor = { 0 };

    anchor.CAPubKey = &pubkey;

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    trustAnchorArray.data = (HcfX509TrustAnchor **)HcfMalloc(1 * sizeof(HcfX509TrustAnchor *), 0);
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
    ASSERT_NE(g_certChainPemSpi, nullptr);

    CfBlob pubkey = { 0, nullptr };
    pubkey.data = (uint8_t *)(&g_testCrlSubAndIssNameDerData[0]);
    pubkey.size = g_testCrlSubAndIssNameDerDataSize;

    HcfX509TrustAnchor anchor = { 0 };
    anchor.CAPubKey = &pubkey;

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    trustAnchorArray.data = (HcfX509TrustAnchor **)HcfMalloc(1 * sizeof(HcfX509TrustAnchor *), 0);
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

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest01001, TestSize.Level0)
{
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
    trustAnchorArray.data = (HcfX509TrustAnchor **)HcfMalloc(1 * sizeof(HcfX509TrustAnchor *), 0);
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

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest01002, TestSize.Level0)
{
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
    trustAnchorArray.data = (HcfX509TrustAnchor **)HcfMalloc(1 * sizeof(HcfX509TrustAnchor *), 0);
    ASSERT_NE(trustAnchorArray.data, nullptr);
    trustAnchorArray.data[0] = &anchor;
    trustAnchorArray.count = 1;

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;

    HcfX509CertChainValidateResult result = { 0 };
    CfResult ret = g_certChainPemSpi->engineValidate(g_certChainPemSpi, &pCertChainValidateParams, &result);

    ASSERT_NE(ret, CF_SUCCESS);

    CfFree(trustAnchorArray.data);
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest011, TestSize.Level0)
{
    ASSERT_NE(g_certChainPemSpi, nullptr);

    CfBlob pubkey = { 0, nullptr };
    pubkey.data = (uint8_t *)(&g_testChainPubkeyPemRootData[0]);
    pubkey.size = g_testChainPubkeyPemRootDataSize;

    HcfX509TrustAnchor anchor = { 0 };
    anchor.CAPubKey = &pubkey;
    anchor.CASubject = &pubkey;

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    trustAnchorArray.data = (HcfX509TrustAnchor **)HcfMalloc(1 * sizeof(HcfX509TrustAnchor *), 0);
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

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest012, TestSize.Level0)
{
    ASSERT_NE(g_certChainPemSpi, nullptr);

    CfBlob pubkey = { 0, nullptr };
    pubkey.data = (uint8_t *)(&g_testCrlSubAndIssNameDerData[0]);
    pubkey.size = g_testCrlSubAndIssNameDerDataSize;

    HcfX509TrustAnchor anchor = { 0 };

    anchor.CAPubKey = &pubkey;
    anchor.CASubject = &pubkey;

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    trustAnchorArray.data = (HcfX509TrustAnchor **)HcfMalloc(1 * sizeof(HcfX509TrustAnchor *), 0);
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

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest014, TestSize.Level0)
{
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
    trustAnchorArray.data = (HcfX509TrustAnchor **)HcfMalloc(1 * sizeof(HcfX509TrustAnchor *), 0);
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

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest015, TestSize.Level0)
{
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

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest016, TestSize.Level0)
{
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
    trustAnchorArray.data = (HcfX509TrustAnchor **)HcfMalloc(1 * sizeof(HcfX509TrustAnchor *), 0);
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

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest01701, TestSize.Level0)
{
    ASSERT_NE(g_certChainPemSpi, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainDataPemRoot, trustAnchorArray);

    const char *date = "20231212080000Z";
    CfBlob validDate = { 0 };
    validDate.data = (uint8_t *)date;
    validDate.size = strlen(date) + 1;
    // validatetime :notBeforeDate: 20231205080000, notAfterDate: 20241205075959

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

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest01702, TestSize.Level0)
{
    ASSERT_NE(g_certChainPemSpi, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainDataPemRoot, trustAnchorArray);

    const char *date = "231212080000";
    CfBlob validDate = { 0 };
    validDate.data = (uint8_t *)date;
    validDate.size = strlen(date) + 1;
    // validatetime :notBeforeDate: 20231205080000, notAfterDate: 20241205075959

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

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest01703, TestSize.Level0)
{
    ASSERT_NE(g_certChainPemSpi, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainDataPemRoot, trustAnchorArray);

    const char *date = "2023121208Z";
    CfBlob validDate = { 0 };
    validDate.data = (uint8_t *)date;
    validDate.size = DATE_TIME_LENGTH;
    // validatetime :notBeforeDate: 20231205080000, notAfterDate: 20241205075959

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

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest01704, TestSize.Level0)
{
    ASSERT_NE(g_certChainPemSpi, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainDataPemRoot, trustAnchorArray);

    const char *date = "23121208";
    CfBlob validDate = { 0 };
    validDate.data = (uint8_t *)date;
    validDate.size = strlen(date) + 1;
    // validatetime :notBeforeDate: 20231205080000, notAfterDate: 20241205075959

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

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest01801, TestSize.Level0)
{
    ASSERT_NE(g_certChainPemSpi, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainDataPemRoot, trustAnchorArray);

    const char *date = "20231204080000Z";
    CfBlob validDate = { 0 };
    validDate.data = (uint8_t *)date;
    validDate.size = strlen(date) + 1;
    // validatetime :notBeforeDate: 20231205080000, notAfterDate: 20241205075959

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;
    pCertChainValidateParams.date = &validDate;

    HcfX509CertChainValidateResult result = { 0 };
    CfResult ret = g_certChainPemSpi->engineValidate(g_certChainPemSpi, &pCertChainValidateParams, &result);
    ASSERT_EQ(ret, CF_ERR_CERT_NOT_YET_VALID);

    FreeTrustAnchorArr(trustAnchorArray);
    FreeValidateResult(result);
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest01802, TestSize.Level0)
{
    ASSERT_NE(g_certChainPemSpi, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainDataPemRoot, trustAnchorArray);

    const char *date = "20241206075959Z";
    CfBlob validDate = { 0 };
    validDate.data = (uint8_t *)date;
    validDate.size = strlen(date) + 1;
    // validatetime :notBeforeDate: 20231205080000, notAfterDate: 20241205075959

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;
    pCertChainValidateParams.date = &validDate;

    HcfX509CertChainValidateResult result = { 0 };
    CfResult ret = g_certChainPemSpi->engineValidate(g_certChainPemSpi, &pCertChainValidateParams, &result);
    ASSERT_EQ(ret, CF_ERR_CERT_HAS_EXPIRED);

    FreeTrustAnchorArr(trustAnchorArray);
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest019, TestSize.Level0)
{
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

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest020, TestSize.Level0)
{
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

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest021, TestSize.Level0)
{
    ASSERT_NE(g_certChainPemSpi, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainDataPemRoot, trustAnchorArray);

    HcfCertCRLCollectionArray certCRLCollections = { 0 };
    BuildCollectionArr(&g_inStreamChainDataPemRoot, &g_crlDerInStream, certCRLCollections);

    const char *date = "20231212080000Z";
    CfBlob validDate = { 0 };
    validDate.data = (uint8_t *)date;
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

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest022, TestSize.Level0)
{
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

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest023, TestSize.Level0)
{
    HcfX509CertChainSpi *certChainSpi = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&g_inStreamChainPemNoRootHasPubKey, &certChainSpi);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainSpi, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainPem2, trustAnchorArray);

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

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest024, TestSize.Level0)
{
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

HWTEST_F(CryptoX509CertChainTest, ValidateCoreTest001, TestSize.Level0)
{
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

} // namespace
