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
#include <openssl/pem.h>

#include "securec.h"

#include "x509_certificate.h"
#include "cf_blob.h"
#include "crypto_x509_test_common.h"
#include "memory_mock.h"

#include "certificate_openssl_common.h"
#include "x509_certificate_openssl.h"
#include "certificate_openssl_class.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoX509CertificateTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

constexpr int TEST_CERT_VERSION = 3;
constexpr int TEST_CERT_CHAIN_LEN = 2;
constexpr int TEST_CERT_SERIAL_NUMBER = 272;
constexpr uint32_t HCF_MAX_BUFFER_LEN = 8192;

static HcfX509Certificate *g_x509CertObj = nullptr;

void CryptoX509CertificateTest::SetUpTestCase()
{
    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testSelfSignedCaCert));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testSelfSignedCaCert) + 1;
    (void)HcfX509CertificateCreate(&inStream, &g_x509CertObj);
}

void CryptoX509CertificateTest::TearDownTestCase()
{
    CfObjDestroy(g_x509CertObj);
}

void CryptoX509CertificateTest::SetUp()
{
}

void CryptoX509CertificateTest::TearDown()
{
}

/**
 * @tc.name: CryptoX509CertificateTest.GenerateCert001
 * @tc.desc: Generate valid PEM format certificate.
 * @tc.type: FUNC
 * @tc.require: I5QDNN
 */
HWTEST_F(CryptoX509CertificateTest, GenerateCert001, TestSize.Level0)
{
    HcfX509Certificate *x509Cert = nullptr;
    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testSelfSignedCaCert));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testSelfSignedCaCert) + 1;
    CfResult ret = HcfX509CertificateCreate(&inStream, &x509Cert);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509Cert, nullptr);
    CfObjDestroy(x509Cert);
}

/* Invalid input. */
HWTEST_F(CryptoX509CertificateTest, GenerateCert002, TestSize.Level0)
{
    HcfX509Certificate *x509Cert = nullptr;
    CfEncodingBlob inStream = { 0 };
    CfResult ret = HcfX509CertificateCreate(&inStream, &x509Cert);
    EXPECT_NE(ret, CF_SUCCESS);
    EXPECT_EQ(x509Cert, nullptr);
    CfObjDestroy(x509Cert);
}

/* Invalid PEM format. */
HWTEST_F(CryptoX509CertificateTest, GenerateCert003, TestSize.Level0)
{
    HcfX509Certificate *x509Cert = nullptr;
    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testInvalidCert));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testInvalidCert) + 1;
    CfResult ret = HcfX509CertificateCreate(&inStream, &x509Cert);
    EXPECT_NE(ret, CF_SUCCESS);
    EXPECT_EQ(x509Cert, nullptr);
    CfObjDestroy(x509Cert);
}

/* Valid DER format. */
HWTEST_F(CryptoX509CertificateTest, GenerateCert004, TestSize.Level0)
{
    CfEncodingBlob derBlob = { 0 };
    CfResult ret = g_x509CertObj->base.getEncoded(reinterpret_cast<HcfCertificate *>(g_x509CertObj), &derBlob);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(derBlob.data, nullptr);
    EXPECT_EQ(derBlob.encodingFormat, CF_FORMAT_DER);
    HcfX509Certificate *certFromDerData = nullptr;
    ret = HcfX509CertificateCreate(&derBlob, &certFromDerData);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(certFromDerData, nullptr);

    free(derBlob.data);
    CfObjDestroy(certFromDerData);
}

/* verify self signed cert. */
HWTEST_F(CryptoX509CertificateTest, Verify001, TestSize.Level0)
{
    HcfPubKey *keyOut = nullptr;
    CfResult ret = g_x509CertObj->base.getPublicKey(reinterpret_cast<HcfCertificate *>(g_x509CertObj),
        (void **)&keyOut);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(keyOut, nullptr);
    ret = g_x509CertObj->base.verify(reinterpret_cast<HcfCertificate *>(g_x509CertObj), keyOut);
    EXPECT_EQ(ret, CF_SUCCESS);
    CfObjDestroy(keyOut);
}

/* use root ca cert's public key to verify next cert. */
HWTEST_F(CryptoX509CertificateTest, Verify002, TestSize.Level0)
{
    HcfX509Certificate *rootCert = nullptr;
    CfEncodingBlob root = { 0 };
    root.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_rootCert));
    root.encodingFormat = CF_FORMAT_PEM;
    root.len = strlen(g_rootCert) + 1;
    CfResult ret = HcfX509CertificateCreate(&root, &rootCert);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(rootCert, nullptr);
    HcfPubKey *rootkeyOut = nullptr;
    ret = rootCert->base.getPublicKey(reinterpret_cast<HcfCertificate *>(rootCert), (void **)&rootkeyOut);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(rootkeyOut, nullptr);

    HcfX509Certificate *secondCert = nullptr;
    CfEncodingBlob second = { 0 };
    second.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_secondCert));
    second.encodingFormat = CF_FORMAT_PEM;
    second.len = strlen(g_secondCert) + 1;
    ret = HcfX509CertificateCreate(&root, &secondCert);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(rootCert, nullptr);
    ret = secondCert->base.verify(reinterpret_cast<HcfCertificate *>(secondCert), rootkeyOut);
    EXPECT_EQ(ret, CF_SUCCESS);
    CfObjDestroy(rootkeyOut);
    CfObjDestroy(rootCert);
    CfObjDestroy(secondCert);
}

/* verify cert with wrong pub key. */
HWTEST_F(CryptoX509CertificateTest, Verify003, TestSize.Level0)
{
    HcfX509Certificate *rootCert = nullptr;
    CfEncodingBlob root = { 0 };
    root.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_rootCert));
    root.encodingFormat = CF_FORMAT_PEM;
    root.len = strlen(g_rootCert) + 1;
    CfResult ret = HcfX509CertificateCreate(&root, &rootCert);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(rootCert, nullptr);
    HcfPubKey *rootkeyOut = nullptr;
    ret = rootCert->base.getPublicKey(reinterpret_cast<HcfCertificate *>(rootCert), (void **)&rootkeyOut);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(rootkeyOut, nullptr);

    ret = g_x509CertObj->base.verify(reinterpret_cast<HcfCertificate *>(g_x509CertObj), rootkeyOut);
    EXPECT_NE(ret, CF_SUCCESS);
    CfObjDestroy(rootkeyOut);
    CfObjDestroy(rootCert);
}

/* verify cert with invalid input pub key. */
HWTEST_F(CryptoX509CertificateTest, Verify004, TestSize.Level0)
{
    CfResult ret = g_x509CertObj->base.verify(reinterpret_cast<HcfCertificate *>(g_x509CertObj), nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
}

HWTEST_F(CryptoX509CertificateTest, GetEncoded001, TestSize.Level0)
{
    CfEncodingBlob encodingBlob = { 0 };
    CfResult ret = g_x509CertObj->base.getEncoded(reinterpret_cast<HcfCertificate *>(g_x509CertObj), &encodingBlob);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(encodingBlob.data, nullptr);
    EXPECT_EQ(encodingBlob.encodingFormat, CF_FORMAT_DER);
    CfEncodingBlobDataFree(&encodingBlob);
}

/* Invalid input. */
HWTEST_F(CryptoX509CertificateTest, GetEncoded002, TestSize.Level0)
{
    CfResult ret = g_x509CertObj->base.getEncoded(reinterpret_cast<HcfCertificate *>(g_x509CertObj), nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
}

HWTEST_F(CryptoX509CertificateTest, GetPublicKey, TestSize.Level0)
{
    HcfPubKey *keyOut = nullptr;
    CfResult ret = g_x509CertObj->base.getPublicKey(reinterpret_cast<HcfCertificate *>(g_x509CertObj),
        (void **)&keyOut);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(keyOut, nullptr);
    CfObjDestroy(keyOut);
}

/* Input valid date. YYMMDDHHMMSSZ */
HWTEST_F(CryptoX509CertificateTest, CheckValidityWithDate001, TestSize.Level0)
{
    const char *date = "231018162433Z";
    // validatetime :2022/08/19 - 2032/08/16
    CfResult ret = g_x509CertObj->checkValidityWithDate(g_x509CertObj, date);
    EXPECT_EQ(ret, CF_SUCCESS);
}

/* Input valid date. time format: YYYYMMDDHHMMSSZ */
HWTEST_F(CryptoX509CertificateTest, CheckValidityWithDate002, TestSize.Level0)
{
    const char *date = "20231018162433Z";
    // validatetime :2022/08/19 - 2032/08/16
    CfResult ret = g_x509CertObj->checkValidityWithDate(g_x509CertObj, date);
    EXPECT_EQ(ret, CF_SUCCESS);
}

/* Input invalid date--expiered. */
HWTEST_F(CryptoX509CertificateTest, CheckValidityWithDate003, TestSize.Level0)
{
    const char *date = "20991018162433Z";
    // validatetime :2022/08/19 - 2032/08/16
    CfResult ret = g_x509CertObj->checkValidityWithDate(g_x509CertObj, date);
    EXPECT_EQ(ret, CF_ERR_CERT_HAS_EXPIRED);
}

/* Input invalid date. */
HWTEST_F(CryptoX509CertificateTest, CheckValidityWithDate004, TestSize.Level0)
{
    const char *date = "20191018162433Z";
    // validatetime :2022/08/19 - 2032/08/16
    CfResult ret = g_x509CertObj->checkValidityWithDate(g_x509CertObj, date);
    EXPECT_EQ(ret, CF_ERR_CERT_NOT_YET_VALID);
}

/* Input invalid date form. */
HWTEST_F(CryptoX509CertificateTest, CheckValidityWithDate005, TestSize.Level0)
{
    const char *date = "20191018";
    // validatetime :2022/08/19 - 2032/08/16
    CfResult ret = g_x509CertObj->checkValidityWithDate(g_x509CertObj, date);
    EXPECT_NE(ret, CF_SUCCESS);
}

HWTEST_F(CryptoX509CertificateTest, GetVersion, TestSize.Level0)
{
    long ver = g_x509CertObj->getVersion(g_x509CertObj);
    EXPECT_EQ(ver, TEST_CERT_VERSION);
}

HWTEST_F(CryptoX509CertificateTest, GetSerialNumber, TestSize.Level0)
{
    CfBlob out = { 0, nullptr };
    CfResult ret = g_x509CertObj->getSerialNumber(g_x509CertObj, &out);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(out.data, nullptr);
    EXPECT_EQ(out.size, 2); /* out size: 2 bytes */
    EXPECT_EQ(out.data[0] * 0x100 + out.data[1], TEST_CERT_SERIAL_NUMBER);
    CfBlobDataClearAndFree(&out);
}

HWTEST_F(CryptoX509CertificateTest, GetIssuerName001, TestSize.Level0)
{
    CfBlob out = { 0 };
    CfResult ret = g_x509CertObj->getIssuerName(g_x509CertObj, &out);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(out.data, nullptr);
    CfBlobDataClearAndFree(&out);
}

/* invalid input. */
HWTEST_F(CryptoX509CertificateTest, GetIssuerName002, TestSize.Level0)
{
    CfResult ret = g_x509CertObj->getIssuerName(g_x509CertObj, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
}

HWTEST_F(CryptoX509CertificateTest, GetSubjectName001, TestSize.Level0)
{
    CfBlob out = { 0 };
    CfResult ret = g_x509CertObj->getSubjectName(g_x509CertObj, &out);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(out.data, nullptr);
    CfBlobDataClearAndFree(&out);
}

/* invalid input. */
HWTEST_F(CryptoX509CertificateTest, GetSubjectName002, TestSize.Level0)
{
    CfResult ret = g_x509CertObj->getSubjectName(g_x509CertObj, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
}

HWTEST_F(CryptoX509CertificateTest, GetNotBeforeTime001, TestSize.Level0)
{
    CfBlob out = { 0 };
    CfResult ret = g_x509CertObj->getNotBeforeTime(g_x509CertObj, &out);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(out.data, nullptr);
    CfBlobDataClearAndFree(&out);
}

/* invalid input. */
HWTEST_F(CryptoX509CertificateTest, GetNotBeforeTime002, TestSize.Level0)
{
    CfResult ret = g_x509CertObj->getNotBeforeTime(g_x509CertObj, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
}

HWTEST_F(CryptoX509CertificateTest, GetNotAfterTime001, TestSize.Level0)
{
    CfBlob out = { 0 };
    CfResult ret = g_x509CertObj->getNotAfterTime(g_x509CertObj, &out);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(out.data, nullptr);
    CfBlobDataClearAndFree(&out);
}

/* invalid input. */
HWTEST_F(CryptoX509CertificateTest, GetNotAfterTime002, TestSize.Level0)
{
    CfResult ret = g_x509CertObj->getNotAfterTime(g_x509CertObj, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
}

HWTEST_F(CryptoX509CertificateTest, GetSignature001, TestSize.Level0)
{
    CfBlob sigOut = { 0 };
    CfResult ret = g_x509CertObj->getSignature(g_x509CertObj, &sigOut);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(sigOut.data, nullptr);
    CfBlobDataClearAndFree(&sigOut);
}

/* invalid input. */
HWTEST_F(CryptoX509CertificateTest, GetSignature002, TestSize.Level0)
{
    CfResult ret = g_x509CertObj->getSignature(g_x509CertObj, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
}

HWTEST_F(CryptoX509CertificateTest, GetSignatureAlgName001, TestSize.Level0)
{
    CfBlob sigAlgName = { 0 };
    CfResult ret = g_x509CertObj->getSignatureAlgName(g_x509CertObj, &sigAlgName);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(sigAlgName.data, nullptr);
    CfBlobDataClearAndFree(&sigAlgName);
}

/* invalid input. */
HWTEST_F(CryptoX509CertificateTest, GetSignatureAlgName002, TestSize.Level0)
{
    CfResult ret = g_x509CertObj->getSignatureAlgName(g_x509CertObj, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
}

HWTEST_F(CryptoX509CertificateTest, GetSignatureAlgOid001, TestSize.Level0)
{
    CfBlob sigAlgOid = { 0 };
    CfResult ret = g_x509CertObj->getSignatureAlgOid(g_x509CertObj, &sigAlgOid);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(sigAlgOid.data, nullptr);
    CfBlobDataClearAndFree(&sigAlgOid);
}

/* invalid input. */
HWTEST_F(CryptoX509CertificateTest, GetSignatureAlgOid002, TestSize.Level0)
{
    CfResult ret = g_x509CertObj->getSignatureAlgOid(g_x509CertObj, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
}

HWTEST_F(CryptoX509CertificateTest, GetSignatureAlgParams001, TestSize.Level0)
{
    CfBlob sigAlgParamsOut = { 0 };
    CfResult ret = g_x509CertObj->getSignatureAlgParams(g_x509CertObj, &sigAlgParamsOut);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(sigAlgParamsOut.data, nullptr);
    CfBlobDataClearAndFree(&sigAlgParamsOut);
}

/* invalid input. */
HWTEST_F(CryptoX509CertificateTest, GetSignatureAlgParams002, TestSize.Level0)
{
    CfResult ret = g_x509CertObj->getSignatureAlgParams(g_x509CertObj, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
}

HWTEST_F(CryptoX509CertificateTest, GetKeyUsage, TestSize.Level0)
{
    CfBlob out = { 0 };
    CfResult ret = g_x509CertObj->getKeyUsage(g_x509CertObj, &out);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(out.data, nullptr);
    CfBlobDataClearAndFree(&out);
}

HWTEST_F(CryptoX509CertificateTest, GetExtKeyUsage001, TestSize.Level0)
{
    CfArray keyUsageOut = { 0 };
    CfResult ret = g_x509CertObj->getExtKeyUsage(g_x509CertObj, &keyUsageOut);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(keyUsageOut.data, nullptr);
    CfArrayDataClearAndFree(&keyUsageOut);
}

/* Cert which has no extended key usage. */
HWTEST_F(CryptoX509CertificateTest, GetExtKeyUsage002, TestSize.Level0)
{
    CfArray keyUsageOut = { 0 };
    HcfX509Certificate *x509Cert = nullptr;
    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_secondCert));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_secondCert) + 1;
    CfResult ret = HcfX509CertificateCreate(&inStream, &x509Cert);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509Cert, nullptr);
    ret = x509Cert->getExtKeyUsage(x509Cert, &keyUsageOut);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    EXPECT_EQ(keyUsageOut.data, nullptr);
    CfObjDestroy(x509Cert);
}

/* not a CA cert */
HWTEST_F(CryptoX509CertificateTest, GetBasicConstraints001, TestSize.Level0)
{
    HcfX509Certificate *x509Cert = nullptr;
    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_deviceTestCert));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_deviceTestCert) + 1;
    CfResult ret = HcfX509CertificateCreate(&inStream, &x509Cert);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509Cert, nullptr);
    int32_t pathLen = x509Cert->getBasicConstraints(x509Cert);
    EXPECT_EQ(pathLen, -1); /* cert path len is only valid for CA. */
    CfObjDestroy(x509Cert);
}

/* CA cert */
HWTEST_F(CryptoX509CertificateTest, GetBasicConstraints002, TestSize.Level0)
{
    int32_t pathLen = g_x509CertObj->getBasicConstraints(g_x509CertObj);
    EXPECT_EQ(pathLen, TEST_CERT_CHAIN_LEN); /* g_testSelfSignedCaCert is CA and it's path len is 2. */
}

/* invalid input. */
HWTEST_F(CryptoX509CertificateTest, GetBasicConstraints003, TestSize.Level0)
{
    int32_t pathLen = g_x509CertObj->getBasicConstraints(nullptr);
    EXPECT_EQ(pathLen, -1);
}

HWTEST_F(CryptoX509CertificateTest, GetSubjectAltNames001, TestSize.Level0)
{
    CfArray outName = { 0 };
    CfResult ret = g_x509CertObj->getSubjectAltNames(g_x509CertObj, &outName);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(outName.data, nullptr);
    CfArrayDataClearAndFree(&outName);
}

/* cert without subject alternative names. */
HWTEST_F(CryptoX509CertificateTest, GetSubjectAltNames002, TestSize.Level0)
{
    CfArray outName = { 0 };
    HcfX509Certificate *x509Cert = nullptr;
    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_secondCert));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_secondCert) + 1;
    CfResult ret = HcfX509CertificateCreate(&inStream, &x509Cert);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509Cert, nullptr);
    ret = x509Cert->getSubjectAltNames(x509Cert, &outName);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    EXPECT_EQ(outName.data, nullptr);
    CfObjDestroy(x509Cert);
}

/* invalid input. */
HWTEST_F(CryptoX509CertificateTest, GetSubjectAltNames003, TestSize.Level0)
{
    HcfX509Certificate *x509Cert = nullptr;
    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_secondCert));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_secondCert) + 1;
    CfResult ret = HcfX509CertificateCreate(&inStream, &x509Cert);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509Cert, nullptr);
    ret = x509Cert->getSubjectAltNames(x509Cert, nullptr);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);
    CfObjDestroy(x509Cert);
}

HWTEST_F(CryptoX509CertificateTest, GetIssuerAltNames001, TestSize.Level0)
{
    CfArray outName = { 0 };
    CfResult ret = g_x509CertObj->getIssuerAltNames(g_x509CertObj, &outName);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(outName.data, nullptr);
    CfArrayDataClearAndFree(&outName);
}

/* cert without issuer alternative names. */
HWTEST_F(CryptoX509CertificateTest, GetIssuerAltNames002, TestSize.Level0)
{
    CfArray outName = { 0 };
    HcfX509Certificate *x509Cert = nullptr;
    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_secondCert));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_secondCert) + 1;
    CfResult ret = HcfX509CertificateCreate(&inStream, &x509Cert);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509Cert, nullptr);
    ret = x509Cert->getIssuerAltNames(x509Cert, &outName);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    EXPECT_EQ(outName.data, nullptr);
    CfObjDestroy(x509Cert);
}

/* invalid input. */
HWTEST_F(CryptoX509CertificateTest, GetIssuerAltNames003, TestSize.Level0)
{
    HcfX509Certificate *x509Cert = nullptr;
    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_secondCert));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_secondCert) + 1;
    CfResult ret = HcfX509CertificateCreate(&inStream, &x509Cert);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509Cert, nullptr);
    ret = x509Cert->getIssuerAltNames(x509Cert, nullptr);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);
    CfObjDestroy(x509Cert);
}

/* oid is nullptr */
HWTEST_F(CryptoX509CertificateTest, GetAlgorithmName001, TestSize.Level0)
{
    const char *str = GetAlgorithmName(nullptr);
    EXPECT_EQ(str, nullptr);
}

/* oid not found */
HWTEST_F(CryptoX509CertificateTest, GetAlgorithmName002, TestSize.Level0)
{
    char oid[] = "1.2.840.113549.1.1.255";
    const char *str = GetAlgorithmName(oid);
    EXPECT_EQ(str, nullptr);
}

/* self point is nullptr */
HWTEST_F(CryptoX509CertificateTest, MatchX509CertTest001, TestSize.Level0)
{
    bool bResult = true;
    HcfX509CertMatchParams matchParams;
    matchParams.x509Cert = &(g_x509CertObj->base);
    CfResult ret = g_x509CertObj->match(nullptr, &matchParams, &bResult);
    EXPECT_NE(ret, CF_SUCCESS);
}

/* x509Cert point is nullptr */
HWTEST_F(CryptoX509CertificateTest, MatchX509CertTest002, TestSize.Level0)
{
    bool bResult = true;
    CfResult ret = g_x509CertObj->match(g_x509CertObj, nullptr, &bResult);
    EXPECT_NE(ret, CF_SUCCESS);
}

/* out point is nullptr */
HWTEST_F(CryptoX509CertificateTest, MatchX509CertTest003, TestSize.Level0)
{
    HcfX509CertMatchParams matchParams;
    matchParams.x509Cert = &(g_x509CertObj->base);
    CfResult ret = g_x509CertObj->match(g_x509CertObj, &matchParams, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
}

/* self is not a invalidCertClass */
HWTEST_F(CryptoX509CertificateTest, MatchX509CertTest004, TestSize.Level0)
{
    HcfX509CertificateSpi invalidSpi = { { 0 } };
    invalidSpi.base.getClass = GetInvalidCertClass;

    HcfX509CertMatchParams matchParams;
    matchParams.x509Cert = &(g_x509CertObj->base);

    CfResult ret = g_x509CertObj->match((HcfX509Certificate *)&invalidSpi, &matchParams, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
}

/* self cert encodedBlob is not equal to  x509Cert */
HWTEST_F(CryptoX509CertificateTest, MatchX509CertTest005, TestSize.Level0)
{
    HcfX509Certificate *x509Cert = nullptr;
    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_secondCert));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_secondCert) + 1;
    CfResult ret = HcfX509CertificateCreate(&inStream, &x509Cert);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509Cert, nullptr);

    bool bResult = true;
    HcfX509CertMatchParams matchParams;
    matchParams.x509Cert = &(x509Cert->base);
    ret = g_x509CertObj->match(g_x509CertObj, &matchParams, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);

    CfObjDestroy(x509Cert);
}

/* self encodedBlob length equales to  x509Cert */
HWTEST_F(CryptoX509CertificateTest, MatchX509CertTest006, TestSize.Level0)
{
    ASSERT_NE(g_x509CertObj, nullptr);
    bool bResult = true;
    HcfX509CertMatchParams matchParams;
    matchParams.x509Cert = &(g_x509CertObj->base);
    CfResult ret = g_x509CertObj->match(g_x509CertObj, &matchParams, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, true);
}

/* HcfX509CertMatchParams`s subject is valid */
HWTEST_F(CryptoX509CertificateTest, MatchX509CertTest007, TestSize.Level0)
{
    ASSERT_NE(g_x509CertObj, nullptr);
    bool bResult = true;
    CfBlob cfBlobDataParam = { 0 };
    cfBlobDataParam.data = (uint8_t *)(&g_testSubjectAndIssuerNameDerData[0]);
    cfBlobDataParam.size = g_testSubjectAndIssuerNameDerDataSize;

    HcfX509CertMatchParams matchParams;
    matchParams.subject = &cfBlobDataParam;
    CfResult ret = g_x509CertObj->match(g_x509CertObj, &matchParams, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, true);
}

/* HcfX509CertMatchParams`s subject is invalid */
HWTEST_F(CryptoX509CertificateTest, MatchX509CertTest008, TestSize.Level0)
{
    ASSERT_NE(g_x509CertObj, nullptr);
    bool bResult = true;
    CfBlob cfBlobDataParam = { 0 };
    cfBlobDataParam.data = (uint8_t *)(&g_deviceTestCert[0]);
    cfBlobDataParam.size = g_deviceTestCertSize;

    HcfX509CertMatchParams matchParams;
    matchParams.subject = &cfBlobDataParam;
    CfResult ret = g_x509CertObj->match(g_x509CertObj, &matchParams, &bResult);
    EXPECT_NE(ret, CF_SUCCESS);
}

/* HcfX509CertMatchParams`s validDate is less than start time(20220819124906Z) */
HWTEST_F(CryptoX509CertificateTest, MatchX509CertTest009, TestSize.Level0)
{
    ASSERT_NE(g_x509CertObj, nullptr);
    bool bResult = true;
    const char *date = "20220819124900Z";
    CfBlob validDate = { 0 };
    validDate.data = reinterpret_cast<uint8_t *>(const_cast<char *>(date));
    validDate.size = strlen(date) + 1;
    HcfX509CertMatchParams matchParams;
    matchParams.validDate = &validDate;
    // validatetime :2022/08/19 - 2032/08/16
    CfResult ret = g_x509CertObj->match(g_x509CertObj, &matchParams, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);
}

/* HcfX509CertMatchParams`s validDate is equal to start time(20220819124906Z) */
HWTEST_F(CryptoX509CertificateTest, MatchX509CertTest010, TestSize.Level0)
{
    ASSERT_NE(g_x509CertObj, nullptr);
    bool bResult = true;
    const char *date = "20220819124906Z";
    CfBlob validDate = { 0 };
    validDate.data = reinterpret_cast<uint8_t *>(const_cast<char *>(date));
    validDate.size = strlen(date) + 1;
    HcfX509CertMatchParams matchParams;
    matchParams.validDate = &validDate;
    // validatetime :2022/08/19 - 2032/08/16
    CfResult ret = g_x509CertObj->match(g_x509CertObj, &matchParams, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, true);
}

/* HcfX509CertMatchParams`s validDate is valid */
HWTEST_F(CryptoX509CertificateTest, MatchX509CertTest011, TestSize.Level0)
{
    ASSERT_NE(g_x509CertObj, nullptr);
    bool bResult = true;
    const char *date = "20231018162433Z";
    CfBlob validDate = { 0 };
    validDate.data = reinterpret_cast<uint8_t *>(const_cast<char *>(date));
    validDate.size = strlen(date) + 1;
    HcfX509CertMatchParams matchParams;
    matchParams.validDate = &validDate;
    // validatetime :2022/08/19 - 2032/08/16
    CfResult ret = g_x509CertObj->match(g_x509CertObj, &matchParams, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, true);
}

/* HcfX509CertMatchParams`s validDate is equal to end time(20320816124906Z) */
HWTEST_F(CryptoX509CertificateTest, MatchX509CertTest012, TestSize.Level0)
{
    ASSERT_NE(g_x509CertObj, nullptr);
    bool bResult = true;
    const char *date = "20320816124906Z";
    CfBlob validDate = { 0 };
    validDate.data = reinterpret_cast<uint8_t *>(const_cast<char *>(date));
    validDate.size = strlen(date) + 1;
    HcfX509CertMatchParams matchParams;
    matchParams.validDate = &validDate;
    // validatetime :2022/08/19 - 2032/08/16
    CfResult ret = g_x509CertObj->match(g_x509CertObj, &matchParams, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, true);
}

/* HcfX509CertMatchParams`s validDate is more than end time(20320816124906Z) */
HWTEST_F(CryptoX509CertificateTest, MatchX509CertTest013, TestSize.Level0)
{
    ASSERT_NE(g_x509CertObj, nullptr);
    bool bResult = true;
    const char *date = "20330816124906Z";
    CfBlob validDate = { 0 };
    validDate.data = reinterpret_cast<uint8_t *>(const_cast<char *>(date));
    validDate.size = strlen(date) + 1;
    HcfX509CertMatchParams matchParams;
    matchParams.validDate = &validDate;
    // validatetime :2022/08/19 - 2032/08/16
    CfResult ret = g_x509CertObj->match(g_x509CertObj, &matchParams, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);
}

/* HcfX509CertMatchParams`s validDate is empty string */
HWTEST_F(CryptoX509CertificateTest, MatchX509CertTest014, TestSize.Level0)
{
    ASSERT_NE(g_x509CertObj, nullptr);
    bool bResult = true;
    string emptyData = "";
    const char *date = emptyData.c_str();
    CfBlob validDate = { 0 };
    validDate.data = reinterpret_cast<uint8_t *>(const_cast<char *>(date));
    validDate.size = strlen(date) + 1;
    HcfX509CertMatchParams matchParams;
    matchParams.validDate = &validDate;
    // validatetime :2022/08/19 - 2032/08/16
    CfResult ret = g_x509CertObj->match(g_x509CertObj, &matchParams, &bResult);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
}

/* HcfX509CertMatchParams`s issuer is valid */
HWTEST_F(CryptoX509CertificateTest, MatchX509CertTest015, TestSize.Level0)
{
    ASSERT_NE(g_x509CertObj, nullptr);
    bool bResult = true;
    CfBlob cfBlobDataParam = { 0 };
    cfBlobDataParam.data = (uint8_t *)(&g_testSubjectAndIssuerNameDerData[0]);
    cfBlobDataParam.size = g_testSubjectAndIssuerNameDerDataSize;

    HcfX509CertMatchParams matchParams;
    matchParams.issuer = &cfBlobDataParam;
    CfResult ret = g_x509CertObj->match(g_x509CertObj, &matchParams, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, true);
}

/* HcfX509CertMatchParams`s issuer is invalid */
HWTEST_F(CryptoX509CertificateTest, MatchX509CertTest016, TestSize.Level0)
{
    ASSERT_NE(g_x509CertObj, nullptr);
    bool bResult = true;
    CfBlob cfBlobDataParam = { 0 };
    cfBlobDataParam.data = (uint8_t *)(&g_deviceTestCert[0]);
    cfBlobDataParam.size = g_deviceTestCertSize;

    HcfX509CertMatchParams matchParams;
    matchParams.issuer = &cfBlobDataParam;
    CfResult ret = g_x509CertObj->match(g_x509CertObj, &matchParams, &bResult);
    EXPECT_NE(ret, CF_SUCCESS);
}

/* HcfX509CertMatchParams`s keyUsage is valid */
HWTEST_F(CryptoX509CertificateTest, MatchX509CertTest017, TestSize.Level0)
{
    ASSERT_NE(g_x509CertObj, nullptr);
    bool bResult = true;
    CfBlob cfBlobDataParam = { 0 };
    CfResult ret = g_x509CertObj->getKeyUsage(g_x509CertObj, &cfBlobDataParam);
    EXPECT_EQ(ret, CF_SUCCESS);

    HcfX509CertMatchParams matchParams;
    matchParams.keyUsage = &cfBlobDataParam;
    ret = g_x509CertObj->match(g_x509CertObj, &matchParams, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, true);
    CfBlobDataClearAndFree(&cfBlobDataParam);
}

/* HcfX509CertMatchParams`s keyUsage`s length is smaller */
HWTEST_F(CryptoX509CertificateTest, MatchX509CertTest018, TestSize.Level0)
{
    ASSERT_NE(g_x509CertObj, nullptr);
    bool bResult = true;
    CfBlob cfBlobDataParam = { 0 };
    CfBlob cfBlobDataSelf = { 0 };
    CfResult ret = g_x509CertObj->getKeyUsage(g_x509CertObj, &cfBlobDataSelf);
    EXPECT_EQ(ret, CF_SUCCESS);

    uint8_t *data = static_cast<uint8_t *>(CfMalloc(cfBlobDataSelf.size - 1, 0));
    for (uint32_t index = 0; index < cfBlobDataSelf.size - 1; index++) {
        data[index] = cfBlobDataSelf.data[index];
    }
    cfBlobDataParam.size = cfBlobDataSelf.size - 1;
    cfBlobDataParam.data = data;
    HcfX509CertMatchParams matchParams;
    matchParams.keyUsage = &cfBlobDataParam;
    ret = g_x509CertObj->match(g_x509CertObj, &matchParams, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);

    CfFree(data);
    CfBlobDataClearAndFree(&cfBlobDataSelf);
}

/* HcfX509CertMatchParams`s keyUsage`s length is greater */
HWTEST_F(CryptoX509CertificateTest, MatchX509CertTest019, TestSize.Level0)
{
    ASSERT_NE(g_x509CertObj, nullptr);
    bool bResult = true;
    CfBlob cfBlobDataParam = { 0 };
    CfBlob cfBlobDataSelf = { 0 };
    CfResult ret = g_x509CertObj->getKeyUsage(g_x509CertObj, &cfBlobDataSelf);
    EXPECT_EQ(ret, CF_SUCCESS);

    uint8_t *data = static_cast<uint8_t *>(CfMalloc(cfBlobDataSelf.size + 1, 0));
    uint32_t index = 0;
    for (index = 0; index < cfBlobDataSelf.size; index++) {
        data[index] = cfBlobDataSelf.data[index];
    }
    data[index] = 1;

    cfBlobDataParam.size = cfBlobDataSelf.size + 1;
    cfBlobDataParam.data = data;
    HcfX509CertMatchParams matchParams;
    matchParams.keyUsage = &cfBlobDataParam;
    ret = g_x509CertObj->match(g_x509CertObj, &matchParams, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);

    CfFree(data);
    CfBlobDataClearAndFree(&cfBlobDataSelf);
}

/* HcfX509CertMatchParams`s keyUsage`s length is greater */
HWTEST_F(CryptoX509CertificateTest, MatchX509CertTest020, TestSize.Level0)
{
    ASSERT_NE(g_x509CertObj, nullptr);
    bool bResult = true;
    CfBlob cfBlobDataParam = { 0 };
    CfBlob cfBlobDataSelf = { 0 };
    CfResult ret = g_x509CertObj->getKeyUsage(g_x509CertObj, &cfBlobDataSelf);
    EXPECT_EQ(ret, CF_SUCCESS);

    uint8_t *data = static_cast<uint8_t *>(CfMalloc(cfBlobDataSelf.size + 1, 0));
    uint32_t index = 0;
    for (index = 0; index < cfBlobDataSelf.size; index++) {
        data[index] = cfBlobDataSelf.data[index];
    }
    data[index] = 0;

    cfBlobDataParam.size = cfBlobDataSelf.size + 1;
    cfBlobDataParam.data = data;
    HcfX509CertMatchParams matchParams;
    matchParams.keyUsage = &cfBlobDataParam;
    ret = g_x509CertObj->match(g_x509CertObj, &matchParams, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, true);

    CfFree(data);
    CfBlobDataClearAndFree(&cfBlobDataSelf);
}

/* HcfX509CertMatchParams`s keyUsage`s length is equals to self`s */
HWTEST_F(CryptoX509CertificateTest, MatchX509CertTest021, TestSize.Level0)
{
    ASSERT_NE(g_x509CertObj, nullptr);
    bool bResult = true;
    CfBlob cfBlobDataParam = { 0 };
    CfBlob cfBlobDataSelf = { 0 };
    CfResult ret = g_x509CertObj->getKeyUsage(g_x509CertObj, &cfBlobDataSelf);
    EXPECT_EQ(ret, CF_SUCCESS);

    uint8_t *data = static_cast<uint8_t *>(CfMalloc(cfBlobDataSelf.size, 0));
    for (uint32_t index = 0; index < cfBlobDataSelf.size; index++) {
        data[index] = (cfBlobDataSelf.data[index]) ? 0 : 1;
    }
    cfBlobDataParam.size = cfBlobDataSelf.size;
    cfBlobDataParam.data = data;
    HcfX509CertMatchParams matchParams;
    matchParams.keyUsage = &cfBlobDataParam;
    ret = g_x509CertObj->match(g_x509CertObj, &matchParams, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);

    CfFree(data);
    CfBlobDataClearAndFree(&cfBlobDataSelf);
}

/* HcfX509CertMatchParams's serialNumber is equals to self's */
HWTEST_F(CryptoX509CertificateTest, MatchX509CertTest022, TestSize.Level0)
{
    ASSERT_NE(g_x509CertObj, nullptr);
    // Serial Number: 272 (0x110)
    uint8_t testSn[] = { 0x01, 0x10 };
    CfBlob testSnBlob = { sizeof(testSn) / sizeof(testSn[0]), testSn };
    HcfX509CertMatchParams matchParams;
    matchParams.serialNumber = &testSnBlob;

    bool bResult = true;
    CfResult ret = g_x509CertObj->match(g_x509CertObj, &matchParams, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, true);
}

/* HcfX509CertMatchParams's serialNumber is not equals to self's */
HWTEST_F(CryptoX509CertificateTest, MatchX509CertTest023, TestSize.Level0)
{
    ASSERT_NE(g_x509CertObj, nullptr);
    // Serial Number: 272 (0x110)
    uint8_t testSn[] = { 0x01, 0x11 };
    CfBlob testSnBlob = { sizeof(testSn) / sizeof(testSn[0]), testSn };
    HcfX509CertMatchParams matchParams;
    matchParams.serialNumber = &testSnBlob;

    bool bResult = true;
    CfResult ret = g_x509CertObj->match(g_x509CertObj, &matchParams, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);
}

/* HcfX509CertMatchParams's public key is valid */
HWTEST_F(CryptoX509CertificateTest, MatchX509CertTest024, TestSize.Level0)
{
    ASSERT_NE(g_x509CertObj, nullptr);
    bool bResult = true;
    CfBlob cfBlobDataParam = { 0 };
    cfBlobDataParam.data = reinterpret_cast<uint8_t *>(const_cast<uint8_t *>(&g_testPublicKeyDerData[0]));
    cfBlobDataParam.size = g_testPublicKeyDerDataSize;

    HcfX509CertMatchParams matchParams;
    matchParams.publicKey = &cfBlobDataParam;
    CfResult ret = g_x509CertObj->match(g_x509CertObj, &matchParams, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, true);
}

/* HcfX509CertMatchParams's public key is invalid */
HWTEST_F(CryptoX509CertificateTest, MatchX509CertTest025, TestSize.Level0)
{
    ASSERT_NE(g_x509CertObj, nullptr);
    bool bResult = true;
    CfBlob cfBlobDataParam = { 0 };
    cfBlobDataParam.data = const_cast<uint8_t *>(g_testSubjectAndIssuerNameDerData);
    cfBlobDataParam.size = g_testSubjectAndIssuerNameDerDataSize;

    HcfX509CertMatchParams matchParams;
    matchParams.publicKey = &cfBlobDataParam;
    CfResult ret = g_x509CertObj->match(g_x509CertObj, &matchParams, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);
}

/* HcfX509CertMatchParams's public key algorithm oid is valid */
HWTEST_F(CryptoX509CertificateTest, MatchX509CertTest026, TestSize.Level0)
{
    ASSERT_NE(g_x509CertObj, nullptr);
    bool bResult = true;
    const char *data = "1.2.840.113549.1.1.1";
    CfBlob cfBlobDataParam = { 0 };
    cfBlobDataParam.data = reinterpret_cast<uint8_t *>(const_cast<char *>(data));
    cfBlobDataParam.size = strlen(data) + 1;
    HcfX509CertMatchParams matchParams;
    matchParams.publicKeyAlgID = &cfBlobDataParam;
    CfResult ret = g_x509CertObj->match(g_x509CertObj, &matchParams, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, true);
}

/* HcfX509CertMatchParams's public key algorithm oid is invalid */
HWTEST_F(CryptoX509CertificateTest, MatchX509CertTest027, TestSize.Level0)
{
    ASSERT_NE(g_x509CertObj, nullptr);
    bool bResult = true;
    const char *data = "3.1.4.1.5.926";
    CfBlob cfBlobDataParam = { 0 };
    cfBlobDataParam.data = reinterpret_cast<uint8_t *>(const_cast<char *>(data));
    cfBlobDataParam.size = strlen(data) + 1;
    HcfX509CertMatchParams matchParams;
    matchParams.publicKeyAlgID = &cfBlobDataParam;
    CfResult ret = g_x509CertObj->match(g_x509CertObj, &matchParams, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);
}

/* HcfX509CertMatchParams's public key algorithm oid is empty */
HWTEST_F(CryptoX509CertificateTest, MatchX509CertTest028, TestSize.Level0)
{
    ASSERT_NE(g_x509CertObj, nullptr);
    bool bResult = true;
    string emptyData = "";
    const char *data = emptyData.c_str();
    CfBlob cfBlobDataParam = { 0 };
    cfBlobDataParam.data = reinterpret_cast<uint8_t *>(const_cast<char *>(data));
    cfBlobDataParam.size = strlen(data) + 1;
    HcfX509CertMatchParams matchParams;
    matchParams.publicKeyAlgID = &cfBlobDataParam;
    CfResult ret = g_x509CertObj->match(g_x509CertObj, &matchParams, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);
}

/* HcfX509CertMatchParams's subject length is 0 */
HWTEST_F(CryptoX509CertificateTest, MatchX509CertTest029, TestSize.Level0)
{
    ASSERT_NE(g_x509CertObj, nullptr);
    bool bResult = true;
    CfBlob cfBlobDataParam = { 0 };
    cfBlobDataParam.data = reinterpret_cast<uint8_t *>(const_cast<char *>(&g_deviceTestCert[0]));
    cfBlobDataParam.size = 0;

    HcfX509CertMatchParams matchParams;
    matchParams.subject = &cfBlobDataParam;
    CfResult ret = g_x509CertObj->match(g_x509CertObj, &matchParams, &bResult);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);
}

/* match all params */
HWTEST_F(CryptoX509CertificateTest, MatchX509CertTest030, TestSize.Level0)
{
    ASSERT_NE(g_x509CertObj, nullptr);
    bool bResult = true;
    HcfX509CertMatchParams matchParams;
    CfBlob cfDataSubject = { 0 };
    cfDataSubject.data = const_cast<uint8_t *>(&g_testSubjectAndIssuerNameDerData[0]);
    cfDataSubject.size = g_testSubjectAndIssuerNameDerDataSize;
    const char *date = "20220819124906Z";
    CfBlob validDate = { 0 };
    validDate.data = reinterpret_cast<uint8_t *>(const_cast<char *>(date));
    validDate.size = strlen(date) + 1;
    CfBlob cfDataIssuer = { 0 };
    cfDataIssuer.data = const_cast<uint8_t *>(&g_testSubjectAndIssuerNameDerData[0]);
    cfDataIssuer.size = g_testSubjectAndIssuerNameDerDataSize;
    CfBlob cfDataKeyUsage = { 0 };
    CfResult ret = g_x509CertObj->getKeyUsage(g_x509CertObj, &cfDataKeyUsage);
    uint8_t testSn[] = { 0x01, 0x10 };
    CfBlob testSnBlob = { sizeof(testSn) / sizeof(testSn[0]), testSn };
    CfBlob cfDataPublicKey = { 0 };
    cfDataPublicKey.data = const_cast<uint8_t *>(&g_testPublicKeyDerData[0]);
    cfDataPublicKey.size = g_testPublicKeyDerDataSize;
    const char *dataOid = "1.2.840.113549.1.1.1";
    CfBlob cfDataPublicKeyAlgID = { 0 };
    cfDataPublicKeyAlgID.data = reinterpret_cast<uint8_t *>(const_cast<char *>(dataOid));
    cfDataPublicKeyAlgID.size = strlen(dataOid) + 1;

    matchParams.x509Cert = &(g_x509CertObj->base);
    matchParams.subject = &cfDataSubject;
    matchParams.validDate = &validDate;
    matchParams.issuer = &cfDataIssuer;
    matchParams.keyUsage = &cfDataKeyUsage;
    matchParams.serialNumber = &testSnBlob;
    matchParams.publicKey = &cfDataPublicKey;
    matchParams.publicKeyAlgID = &cfDataPublicKeyAlgID;
    ret = g_x509CertObj->match(g_x509CertObj, &matchParams, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, true);

    CfFree(cfDataKeyUsage.data);
}

HWTEST_F(CryptoX509CertificateTest, DeepCopyDataToBlobTest001, TestSize.Level0)
{
    SetMockFlag(true);
    CfResult ret = DeepCopyDataToBlob(nullptr, 0, nullptr);
    EXPECT_EQ(ret, CF_ERR_MALLOC);
    SetMockFlag(false);
}

HWTEST_F(CryptoX509CertificateTest, DeepCopyBlobToBlobTest001, TestSize.Level0)
{
    CfResult ret = DeepCopyBlobToBlob(nullptr, nullptr);
    EXPECT_EQ(ret, CF_SUCCESS);
}

HWTEST_F(CryptoX509CertificateTest, DeepCopyBlobToBlobTest002, TestSize.Level0)
{
    CfBlob inBlob = { 0 };
    CfBlob *outBlob = nullptr;
    SetMockFlag(true);
    CfResult ret = DeepCopyBlobToBlob(&inBlob, &outBlob);
    EXPECT_EQ(ret, CF_ERR_MALLOC);
    SetMockFlag(false);
}

HWTEST_F(CryptoX509CertificateTest, CopyExtensionsToBlobTest001, TestSize.Level0)
{
    CfBlob outBlob = { 0 };

    X509_EXTENSIONS *exts = sk_X509_EXTENSION_new_null();

    CfResult ret = CopyExtensionsToBlob(exts, &outBlob);
    EXPECT_EQ(ret, CF_SUCCESS);

    sk_X509_EXTENSION_free(exts);
}

/* ConvertNameDerDataToString : data is nullptr */
HWTEST_F(CryptoX509CertificateTest, ConvertNameDerDataToStringTest001, TestSize.Level0)
{
    uint32_t derLen = 10;
    CfBlob out = { 0, nullptr };
    CfResult ret = ConvertNameDerDataToString(nullptr, derLen, &out);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);
}

/* ConvertNameDerDataToString : out is nullptr */
HWTEST_F(CryptoX509CertificateTest, ConvertNameDerDataToStringTest002, TestSize.Level0)
{
    const char *data = "abc";
    uint32_t derLen = 10;
    CfResult ret = ConvertNameDerDataToString((const unsigned char *)&data, derLen, nullptr);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);
}

/* ConvertNameDerDataToString : derLen = 0 */
HWTEST_F(CryptoX509CertificateTest, ConvertNameDerDataToStringTest003, TestSize.Level0)
{
    const char *data = "abc";
    CfBlob out = { 0, nullptr };
    CfResult ret = ConvertNameDerDataToString((const unsigned char *)&data, 0, &out);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);
}

/* ConvertNameDerDataToString : The incoming DER data is valid */
HWTEST_F(CryptoX509CertificateTest, ConvertNameDerDataToStringTest004, TestSize.Level0)
{
    const unsigned char data[] = { 0x30, 0x1A, 0x31, 0x18, 0x30, 0x16, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x0F, 0x45,
        0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x20, 0x52, 0x6F, 0x6F, 0x74, 0x20, 0x43, 0x41 };
    uint32_t derLen = sizeof(data);
    CfBlob out = { 0, nullptr };

    CfResult ret = ConvertNameDerDataToString((const unsigned char *)&data, derLen, &out);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(out.data, nullptr);
    CfBlobDataClearAndFree(&out);
}

/* ConvertNameDerDataToString : The incoming data is the issuer of the DER certificate */
HWTEST_F(CryptoX509CertificateTest, ConvertNameDerDataToStringTest005, TestSize.Level0)
{
    const unsigned char data[] = { 0x30, 0x1A, 0x31, 0x18, 0x30, 0x16, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x0F, 0x45,
        0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x20, 0x52, 0x6F, 0x6F, 0x74, 0x20, 0x43, 0x41 };
    uint32_t derLen = sizeof(data);
    CfBlob out = { 0, nullptr };

    CfResult ret = ConvertNameDerDataToString((const unsigned char *)&data, derLen, &out);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(out.data, nullptr);
    CfBlobDataClearAndFree(&out);
}

/* ConvertNameDerDataToString : The incoming data is the subject of the DER certificate */
HWTEST_F(CryptoX509CertificateTest, ConvertNameDerDataToStringTest006, TestSize.Level0)
{
    const unsigned char data[] = { 0x30, 0x1A, 0x31, 0x18, 0x30, 0x16, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x0F, 0x45,
        0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x20, 0x52, 0x6F, 0x6F, 0x74, 0x20, 0x43, 0x41 };
    uint32_t derLen = sizeof(data);
    CfBlob out = { 0, nullptr };

    CfResult ret = ConvertNameDerDataToString((const unsigned char *)&data, derLen, &out);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(out.data, nullptr);
    CfBlobDataClearAndFree(&out);
}

/* ConvertNameDerDataToString : d2i_X509_NAME is NULL */
HWTEST_F(CryptoX509CertificateTest, ConvertNameDerDataToStringTest007, TestSize.Level0)
{
    const char *data = "abc";
    uint32_t derLen = sizeof(data);
    CfBlob out = { 0, nullptr };

    CfResult ret = ConvertNameDerDataToString((const unsigned char *)&data, derLen, &out);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
}

HWTEST_F(CryptoX509CertificateTest, ConvertNameDerDataToStringTest008, TestSize.Level0)
{
    const unsigned char data[] = "error data";
    uint32_t derLen = sizeof(data);
    CfBlob out = { 0, nullptr };
    CfResult ret = ConvertNameDerDataToString(data, derLen, &out);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
}

/* CompareBigNum : CfBlob lhs and CfBlob rhs is NULL */
HWTEST_F(CryptoX509CertificateTest, CompareBigNumTest001, TestSize.Level0)
{
    CfBlob lhs = { 0 };
    CfBlob rhs = { 0 };
    lhs.data = (unsigned char *)"1234567890";
    lhs.size = 10;
    rhs.data = (unsigned char *)"4567890123";
    rhs.size = 10;
    int out;

    lhs.data = nullptr;
    rhs.data = nullptr;
    CfResult ret = CompareBigNum(&lhs, &rhs, &out);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);
}

/* CompareBigNum : CfBlob lhs and CfBlob rhs is NULL */
HWTEST_F(CryptoX509CertificateTest, CompareBigNumTest002, TestSize.Level0)
{
    CfBlob lhs = { 0 };
    CfBlob rhs = { 0 };
    lhs.data = (unsigned char *)"1234567890";
    lhs.size = 0;
    rhs.data = (unsigned char *)"4567890123";
    rhs.size = 0;
    int out;

    CfResult ret = CompareBigNum(&lhs, &rhs, &out);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);
}

/* CompareBigNum : CfBlob lhs and CfBlob rhs parameters are valid and of equal size */
HWTEST_F(CryptoX509CertificateTest, CompareBigNumTest003, TestSize.Level0)
{
    CfBlob lhs = { 0 };
    uint8_t testBigNum1[] = { 0xFF, 0x01, 0xFF, 0x01, 0xFF, 0x01, 0xFF, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01 };
    lhs.data = testBigNum1;
    lhs.size = sizeof(lhs.data);
    int out;

    CfResult ret = CompareBigNum(&lhs, &lhs, &out);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(out, 0);
}

/* CompareBigNum : CfBlob lhs and CfBlob rhs parameters are valid and have different sizes */
HWTEST_F(CryptoX509CertificateTest, CompareBigNumTest004, TestSize.Level0)
{
    CfBlob lhs = { 0 };
    CfBlob rhs = { 0 };
    uint8_t testBigNum1[] = { 0xFF, 0x01, 0xFF, 0x01, 0xFF, 0x01, 0xFF, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01 };
    uint8_t testBigNum2[] = { 0xFF, 0x01, 0xFF, 0x01, 0xFF, 0x01, 0xFF, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x02 };
    lhs.data = testBigNum1;
    lhs.size = sizeof(testBigNum1) / sizeof(testBigNum1[0]);
    rhs.data = testBigNum2;
    rhs.size = sizeof(testBigNum2) / sizeof(testBigNum2[0]);
    EXPECT_EQ(lhs.size, rhs.size);
    int out;

    CfResult ret = CompareBigNum(&lhs, &rhs, &out);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(out < 0, true);
    ret = CompareBigNum(&rhs, &lhs, &out);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(out > 0, true);
}

/* CompareBigNum : CfBlob lhs and CfBlob rhs parameters are valid but conversion to large number failed */
HWTEST_F(CryptoX509CertificateTest, CompareBigNumTest005, TestSize.Level0)
{
    CfBlob lhs = { 0 };
    uint8_t testBigNum1[] = { 0xFF, 0x01, 0xFF, 0x01, 0xFF, 0x01, 0xFF, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01 };
    lhs.data = testBigNum1;
    lhs.size = ~0;
    int out;

    CfResult ret = CompareBigNum(&lhs, &lhs, &out);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);
}

/* CompareBigNum : CfBlob lhs and CfBlob rhs parameters are valid but conversion to large number failed */
HWTEST_F(CryptoX509CertificateTest, CompareBigNumTest006, TestSize.Level0)
{
    CfBlob lhs = { 0 };
    CfBlob rhs = { 0 };
    lhs.data = (unsigned char *)"1234567890";
    lhs.size = 0;
    rhs.data = (unsigned char *)"4567890123";
    rhs.size = 10;
    int out;

    lhs.data = nullptr;
    CfResult ret = CompareBigNum(&lhs, &rhs, &out);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);
}

/* CompareBigNum : CfBlob lhs and CfBlob rhs parameters are valid but conversion to large number failed */
HWTEST_F(CryptoX509CertificateTest, CompareBigNumTest007, TestSize.Level0)
{
    CfBlob lhs = { 0 };
    CfBlob rhs = { 0 };
    lhs.data = (unsigned char *)"1234567890";
    lhs.size = 10;
    rhs.data = (unsigned char *)"4567890123";
    rhs.size = 0;
    int out;

    rhs.data = nullptr;
    CfResult ret = CompareBigNum(&lhs, &rhs, &out);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);
}

HWTEST_F(CryptoX509CertificateTest, CompareBigNumTest008, TestSize.Level0)
{
    CfBlob lhs = { 0 };
    CfBlob rhs = { 0 };
    uint8_t testBigNum1[] = { 0xFF, 0x01, 0xFF, 0x01, 0xFF, 0x01, 0xFF, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01 };
    uint8_t testBigNum2[] = { 0xFF, 0x01, 0xFF, 0x01, 0xFF, 0x01, 0xFF, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x02 };
    lhs.data = testBigNum1;
    lhs.size = sizeof(testBigNum1) / sizeof(testBigNum1[0]);
    rhs.data = testBigNum2;
    rhs.size = ~0;
    int out;

    CfResult ret = CompareBigNum(&lhs, &rhs, &out);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);
}

/* GetX509EncodedDataStream : certificate is NULL */
HWTEST_F(CryptoX509CertificateTest, GetX509EncodedDataStreamTest001, TestSize.Level0)
{
    int dataLength;

    uint8_t *ret = GetX509EncodedDataStream(nullptr, &dataLength);
    EXPECT_EQ(ret, nullptr);
}

HWTEST_F(CryptoX509CertificateTest, GetX509EncodedDataStreamTest002, TestSize.Level0)
{
    int dataLength;
    X509 *certificate = nullptr;
    BIO *bio = BIO_new_mem_buf(g_testCertChainPemMid, sizeof(g_testCertChainPemMid));
    EXPECT_NE(bio, nullptr);
    certificate = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    SetMockFlag(true);
    uint8_t *ret = GetX509EncodedDataStream(certificate, &dataLength);
    EXPECT_EQ(ret, nullptr);
    SetMockFlag(false);
    X509_free(certificate);
}

HWTEST_F(CryptoX509CertificateTest, NullInput, TestSize.Level0)
{
    (void)HcfX509CertificateCreate(nullptr, nullptr);
    HcfPubKey *keyOut = nullptr;
    CfResult ret = g_x509CertObj->base.getPublicKey(reinterpret_cast<HcfCertificate *>(g_x509CertObj),
        (void **)&keyOut);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(keyOut, nullptr);
    (void)g_x509CertObj->base.base.destroy(nullptr);
    (void)keyOut->base.getAlgorithm(&(keyOut->base));
    (void)keyOut->base.getEncoded(&(keyOut->base), nullptr);
    (void)keyOut->base.getFormat(&(keyOut->base));
    ret = g_x509CertObj->base.verify(nullptr, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = g_x509CertObj->base.getEncoded(nullptr, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = g_x509CertObj->base.getPublicKey(nullptr, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
    (void)g_x509CertObj->checkValidityWithDate(nullptr, nullptr);
    (void)g_x509CertObj->getVersion(nullptr);
    (void)g_x509CertObj->getSerialNumber(nullptr, nullptr);
    (void)g_x509CertObj->getIssuerName(nullptr, nullptr);
    (void)g_x509CertObj->getSubjectName(nullptr, nullptr);
    (void)g_x509CertObj->getNotBeforeTime(nullptr, nullptr);
    (void)g_x509CertObj->getNotAfterTime(nullptr, nullptr);
    (void)g_x509CertObj->getSignature(nullptr, nullptr);
    (void)g_x509CertObj->getSignatureAlgName(nullptr, nullptr);
    (void)g_x509CertObj->getSignatureAlgOid(nullptr, nullptr);
    (void)g_x509CertObj->getSignatureAlgParams(nullptr, nullptr);
    (void)g_x509CertObj->getKeyUsage(nullptr, nullptr);
    (void)g_x509CertObj->getExtKeyUsage(nullptr, nullptr);
    (void)g_x509CertObj->getBasicConstraints(nullptr);
    (void)g_x509CertObj->getSubjectAltNames(nullptr, nullptr);
    (void)g_x509CertObj->getIssuerAltNames(nullptr, nullptr);
    CfObjDestroy(keyOut);
}

HWTEST_F(CryptoX509CertificateTest, NullInput002, TestSize.Level0)
{
    CfEncodingBlob inStream = { nullptr, 0, CF_FORMAT_PEM };
    HcfX509Certificate *x509Cert = nullptr;
    (void)HcfX509CertificateCreate(&inStream, &x509Cert); /* inStream.data is nullptr */

    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testSelfSignedCaCert));
    inStream.len = HCF_MAX_BUFFER_LEN + 1;
    (void)HcfX509CertificateCreate(&inStream, &x509Cert); /* inStream.len is bigger than HCF_MAX_BUFFER_LEN */

    inStream.len = strlen(g_testSelfSignedCaCert) + 1;
    (void)HcfX509CertificateCreate(&inStream, nullptr); /* inStream is valid */

    CfResult ret = HcfX509CertificateCreate(&inStream, &x509Cert);
    ASSERT_EQ(ret, CF_SUCCESS);

    (void)x509Cert->base.getPublicKey(reinterpret_cast<HcfCertificate *>(x509Cert), nullptr);
    (void)x509Cert->checkValidityWithDate(x509Cert, nullptr);
    (void)x509Cert->getSerialNumber(x509Cert, nullptr);
    (void)x509Cert->getIssuerName(x509Cert, nullptr);
    (void)x509Cert->getSubjectName(x509Cert, nullptr);
    (void)x509Cert->getNotBeforeTime(x509Cert, nullptr);
    (void)x509Cert->getNotAfterTime(x509Cert, nullptr);
    (void)x509Cert->getSignature(x509Cert, nullptr);
    (void)x509Cert->getSignatureAlgName(x509Cert, nullptr);
    (void)x509Cert->getSignatureAlgOid(x509Cert, nullptr);
    (void)x509Cert->getSignatureAlgParams(x509Cert, nullptr);
    (void)x509Cert->getKeyUsage(x509Cert, nullptr);
    (void)x509Cert->getExtKeyUsage(x509Cert, nullptr);
    (void)x509Cert->getSubjectAltNames(x509Cert, nullptr);
    (void)x509Cert->getIssuerAltNames(x509Cert, nullptr);
    CfObjDestroy(x509Cert);
}

HWTEST_F(CryptoX509CertificateTest, NullSpiInput, TestSize.Level0)
{
    HcfX509CertificateSpi *spiObj = nullptr;
    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testSelfSignedCaCert));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testSelfSignedCaCert) + 1;
    (void)OpensslX509CertSpiCreate(nullptr, nullptr);
    CfResult ret = OpensslX509CertSpiCreate(&inStream, &spiObj);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(spiObj, nullptr);
    (void)spiObj->base.destroy(nullptr);
    ret = spiObj->engineVerify(nullptr, nullptr);
    ret = spiObj->engineGetEncoded(nullptr, nullptr);
    ret = spiObj->engineGetPublicKey(nullptr, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = spiObj->engineCheckValidityWithDate(nullptr, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
    long ver = spiObj->engineGetVersion(nullptr);
    EXPECT_EQ(ver, -1);
    ret = spiObj->engineGetSerialNumber(nullptr, nullptr);
    ret = spiObj->engineGetIssuerName(nullptr, nullptr);
    ret = spiObj->engineGetSubjectName(nullptr, nullptr);
    ret = spiObj->engineGetNotBeforeTime(nullptr, nullptr);
    ret = spiObj->engineGetNotAfterTime(nullptr, nullptr);
    ret = spiObj->engineGetSignature(nullptr, nullptr);
    ret = spiObj->engineGetSignatureAlgName(nullptr, nullptr);
    ret = spiObj->engineGetSignatureAlgOid(nullptr, nullptr);
    ret = spiObj->engineGetSignatureAlgParams(nullptr, nullptr);
    ret = spiObj->engineGetKeyUsage(nullptr, nullptr);
    ret = spiObj->engineGetExtKeyUsage(nullptr, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
    long basicLen = spiObj->engineGetBasicConstraints(nullptr);
    EXPECT_EQ(basicLen, -1);
    ret = spiObj->engineGetSubjectAltNames(nullptr, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = spiObj->engineGetIssuerAltNames(nullptr, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
    bool bResutlt = true;
    HcfX509CertMatchParams matchParams;
    ret = spiObj->engineMatch(nullptr, &matchParams, &bResutlt);
    EXPECT_NE(ret, CF_SUCCESS);
    CfObjDestroy(spiObj);
}

HWTEST_F(CryptoX509CertificateTest, NullSpiInput002, TestSize.Level0)
{
    HcfX509CertificateSpi *spiObj = nullptr;
    CfEncodingBlob inStream = { nullptr, 0, CF_FORMAT_PEM };
    (void)OpensslX509CertSpiCreate(&inStream, &spiObj);

    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testSelfSignedCaCert));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testSelfSignedCaCert) + 1;
    (void)OpensslX509CertSpiCreate(&inStream, nullptr);
    CfResult ret = OpensslX509CertSpiCreate(&inStream, &spiObj);
    ASSERT_EQ(ret, CF_SUCCESS);
    ret = spiObj->engineVerify(spiObj, nullptr);
    ret = spiObj->engineGetEncoded(spiObj, nullptr);
    ret = spiObj->engineGetPublicKey(spiObj, nullptr);
    ret = spiObj->engineCheckValidityWithDate(spiObj, nullptr);
    ret = spiObj->engineGetSerialNumber(spiObj, nullptr);
    ret = spiObj->engineGetIssuerName(spiObj, nullptr);
    ret = spiObj->engineGetSubjectName(spiObj, nullptr);
    ret = spiObj->engineGetNotBeforeTime(spiObj, nullptr);
    ret = spiObj->engineGetNotAfterTime(spiObj, nullptr);
    ret = spiObj->engineGetSignature(spiObj, nullptr);
    ret = spiObj->engineGetSignatureAlgName(spiObj, nullptr);
    ret = spiObj->engineGetSignatureAlgOid(spiObj, nullptr);
    ret = spiObj->engineGetSignatureAlgParams(spiObj, nullptr);
    ret = spiObj->engineGetKeyUsage(spiObj, nullptr);
    ret = spiObj->engineGetExtKeyUsage(spiObj, nullptr);
    ret = spiObj->engineGetSubjectAltNames(spiObj, nullptr);
    ret = spiObj->engineGetIssuerAltNames(spiObj, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
    bool bResutlt = true;
    HcfX509CertMatchParams matchParams;
    ret = spiObj->engineMatch(spiObj, nullptr, &bResutlt);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = spiObj->engineMatch(spiObj, &matchParams, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
    CfObjDestroy(spiObj);
}

/* HcfX509CertMatchParams's public key is valid, but the operation is error! */
HWTEST_F(CryptoX509CertificateTest, NullSpiInput003, TestSize.Level0)
{
    HcfX509CertificateSpi *spiObj = nullptr;
    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testSelfSignedCaCert));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testSelfSignedCaCert) + 1;
    CfResult ret = OpensslX509CertSpiCreate(&inStream, &spiObj);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(spiObj, nullptr);

    HcfOpensslX509Cert *realCert = reinterpret_cast<HcfOpensslX509Cert *>(spiObj);
    X509 *bk = realCert->x509;
    realCert->x509 = nullptr;

    CfBlob cfBlobDataParam = { 0 };
    cfBlobDataParam.data = (uint8_t *)(&g_testPublicKeyDerData[0]);
    cfBlobDataParam.size = g_testPublicKeyDerDataSize;
    HcfX509CertMatchParams matchParams;
    matchParams.publicKey = &cfBlobDataParam;
    bool bResult = false;
    ret = spiObj->engineMatch(spiObj, &matchParams, &bResult);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);

    realCert->x509 = bk;
    CfObjDestroy(spiObj);
}

HWTEST_F(CryptoX509CertificateTest, InvalidSpiClass, TestSize.Level0)
{
    HcfX509CertificateSpi *spiObj = nullptr;
    HcfX509CertificateSpi invalidSpi = { { 0 } };
    invalidSpi.base.getClass = GetInvalidCertClass;
    CfBlob invalidOut = { 0 };
    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testSelfSignedCaCert));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testSelfSignedCaCert) + 1;
    CfResult ret = OpensslX509CertSpiCreate(&inStream, &spiObj);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(spiObj, nullptr);
    (void)spiObj->base.destroy(&(invalidSpi.base));
    HcfPubKey pubKey;
    ret = spiObj->engineVerify(&invalidSpi, &pubKey);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = spiObj->engineGetEncoded(&invalidSpi, &inStream);
    EXPECT_NE(ret, CF_SUCCESS);
    HcfPubKey *pubKeyOut = nullptr;
    ret = spiObj->engineGetPublicKey(&invalidSpi, &pubKeyOut);
    EXPECT_NE(ret, CF_SUCCESS);
    const char *date = "2020";
    ret = spiObj->engineCheckValidityWithDate(&invalidSpi, date);
    EXPECT_NE(ret, CF_SUCCESS);
    long ver = spiObj->engineGetVersion(&invalidSpi);
    EXPECT_EQ(ver, -1);
    ret = spiObj->engineGetSerialNumber(&invalidSpi, &invalidOut);
    ret = spiObj->engineGetIssuerName(&invalidSpi, &invalidOut);
    ret = spiObj->engineGetSubjectName(&invalidSpi, &invalidOut);
    ret = spiObj->engineGetNotBeforeTime(&invalidSpi, &invalidOut);
    ret = spiObj->engineGetNotAfterTime(&invalidSpi, &invalidOut);
    ret = spiObj->engineGetSignature(&invalidSpi, &invalidOut);
    ret = spiObj->engineGetSignatureAlgName(&invalidSpi, &invalidOut);
    ret = spiObj->engineGetSignatureAlgOid(&invalidSpi, &invalidOut);
    ret = spiObj->engineGetSignatureAlgParams(&invalidSpi, &invalidOut);
    ret = spiObj->engineGetKeyUsage(&invalidSpi, &invalidOut);
    CfArray invalidArr = { 0 };
    ret = spiObj->engineGetExtKeyUsage(&invalidSpi, &invalidArr);
    long basicLen = spiObj->engineGetBasicConstraints(&invalidSpi);
    EXPECT_EQ(basicLen, -1);
    ret = spiObj->engineGetSubjectAltNames(&invalidSpi, &invalidArr);
    ret = spiObj->engineGetIssuerAltNames(&invalidSpi, &invalidArr);
    EXPECT_NE(ret, CF_SUCCESS);
    bool bResutlt = true;
    HcfX509CertMatchParams matchParams;
    ret = spiObj->engineMatch(&invalidSpi, &matchParams, &bResutlt);
    EXPECT_NE(ret, CF_SUCCESS);

    CfObjDestroy(spiObj);
}

HWTEST_F(CryptoX509CertificateTest, InvalidCertClass, TestSize.Level0)
{
    HcfX509Certificate invalidCert;
    invalidCert.base.base.getClass = GetInvalidCertClass;
    CfBlob invalidOut = { 0 };

    CfEncodingBlob inStream = { 0 };
    HcfPubKey keyOut;
    g_x509CertObj->base.base.destroy(&(invalidCert.base.base));
    CfResult ret = g_x509CertObj->base.verify(&(invalidCert.base), &keyOut);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = g_x509CertObj->base.getEncoded(&(invalidCert.base), &inStream);
    EXPECT_NE(ret, CF_SUCCESS);
    HcfPubKey *pubKeyOut = nullptr;
    ret = g_x509CertObj->base.getPublicKey(&(invalidCert.base), (void **)&pubKeyOut);
    EXPECT_NE(ret, CF_SUCCESS);
    const char *date = "2020";
    ret = g_x509CertObj->checkValidityWithDate(&invalidCert, date);
    long ver = g_x509CertObj->getVersion(&invalidCert);
    EXPECT_EQ(ver, -1);
    ret = g_x509CertObj->getSerialNumber(&invalidCert, &invalidOut);
    ret = g_x509CertObj->getIssuerName(&invalidCert, &invalidOut);
    ret = g_x509CertObj->getSubjectName(&invalidCert, &invalidOut);
    ret = g_x509CertObj->getNotBeforeTime(&invalidCert, &invalidOut);
    ret = g_x509CertObj->getNotAfterTime(&invalidCert, &invalidOut);
    ret = g_x509CertObj->getSignature(&invalidCert, &invalidOut);
    ret = g_x509CertObj->getSignatureAlgName(&invalidCert, &invalidOut);
    ret = g_x509CertObj->getSignatureAlgOid(&invalidCert, &invalidOut);
    ret = g_x509CertObj->getSignatureAlgParams(&invalidCert, &invalidOut);
    ret = g_x509CertObj->getKeyUsage(&invalidCert, &invalidOut);
    CfArray invalidArr = { 0 };
    ret = g_x509CertObj->getExtKeyUsage(&invalidCert, &invalidArr);
    long basicLen = g_x509CertObj->getBasicConstraints(&invalidCert);
    EXPECT_EQ(basicLen, -1);
    ret = g_x509CertObj->getSubjectAltNames(&invalidCert, &invalidArr);
    ret = g_x509CertObj->getIssuerAltNames(&invalidCert, &invalidArr);
    EXPECT_NE(ret, CF_SUCCESS);
}

HWTEST_F(CryptoX509CertificateTest, InvalidMalloc, TestSize.Level0)
{
    SetMockFlag(true);
    HcfX509Certificate *x509Cert = nullptr;
    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_secondCert));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_secondCert) + 1;
    CfResult ret = HcfX509CertificateCreate(&inStream, &x509Cert);
    EXPECT_NE(ret, CF_SUCCESS);
    CfBlob out = { 0 };
    CfArray arr = { 0 };
    ret = g_x509CertObj->base.getEncoded(&(g_x509CertObj->base), &inStream);
    EXPECT_NE(ret, CF_SUCCESS);
    HcfPubKey *pubKeyOut = nullptr;
    ret = g_x509CertObj->base.getPublicKey(&(g_x509CertObj->base), (void **)&pubKeyOut);
    EXPECT_NE(ret, CF_SUCCESS);
    const char *date = "2020";
    ret = g_x509CertObj->checkValidityWithDate(g_x509CertObj, date);
    ret = g_x509CertObj->getIssuerName(g_x509CertObj, &out);
    ret = g_x509CertObj->getSubjectName(g_x509CertObj, &out);
    ret = g_x509CertObj->getNotBeforeTime(g_x509CertObj, &out);
    ret = g_x509CertObj->getNotAfterTime(g_x509CertObj, &out);
    ret = g_x509CertObj->getSignature(g_x509CertObj, &out);
    ret = g_x509CertObj->getSignatureAlgName(g_x509CertObj, &out);
    ret = g_x509CertObj->getSignatureAlgOid(g_x509CertObj, &out);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = g_x509CertObj->getSignatureAlgParams(g_x509CertObj, &out);
    ret = g_x509CertObj->getKeyUsage(g_x509CertObj, &out);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = g_x509CertObj->getExtKeyUsage(g_x509CertObj, &arr);
    ret = g_x509CertObj->getSubjectAltNames(g_x509CertObj, &arr);
    ret = g_x509CertObj->getIssuerAltNames(g_x509CertObj, &arr);
    EXPECT_NE(ret, CF_SUCCESS);
    SetMockFlag(false);
}
}