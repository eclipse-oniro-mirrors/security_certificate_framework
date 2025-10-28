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
#include <string>
#include "securec.h"
#include "cf_blob.h"
#include "cf_object_base.h"
#include "x509_csr.h"
#include "x509_certificate.h"
#include "x509_distinguished_name.h"
#include "crypto_x509_test_common.h"

using namespace std;
using namespace testing::ext;

namespace {
class X509CertificateGenCsrTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

static HcfX509Certificate *g_x509CertObj = nullptr;
static HcfX509DistinguishedName *g_x509Name = nullptr;

static string g_rsaPrikey = "-----BEGIN RSA PRIVATE KEY-----\r\n"
    "MIICXQIBAAKBgQCwIN3mr21+N96ToxnVnaS+xyK9cNRAHiHGgrbjHw6RAj3V+l+W\r\n"
    "Y68IhIe3DudVlzE9oMjeOQwkMkq//HCxNlIlFR6O6pa0mrXSwPRE7YKG97CeKk2g\r\n"
    "YOS8YEh8toAvm7xKbiLkXuuMlxrjP2j/mb5iI/UASFSPZiQ/IyxDr0AQaQIDAQAB\r\n"
    "AoGAEvBFzBNa+7J4PXnRQlYEK/tvsd0bBZX33ceacMubHl6WVZbphltLq+fMTBPP\r\n"
    "LjXmtpC+aJ7Lvmyl+wTi/TsxE9vxW5JnbuRT48rnZ/Xwq0eozDeEeIBRrpsr7Rvr\r\n"
    "7ctrgzr4m4yMHq9aDgpxj8IR7oHkfwnmWr0wM3FuiVlj650CQQDineeNZ1hUTkj4\r\n"
    "D3O+iCi3mxEVEeJrpqrmSFolRMb+iozrIRKuJlgcOs+Gqi2fHfOTTL7LkpYe8SVg\r\n"
    "e3JxUdVLAkEAxvcZXk+byMFoetrnlcMR13VHUpoVeoV9qkv6CAWLlbMdgf7uKmgp\r\n"
    "a1Yp3QPDNQQqkPvrqtfR19JWZ4uy1qREmwJALTU3BjyBoH/liqb6fh4HkWk75Som\r\n"
    "MzeSjFIOubSYxhq5tgZpBZjcpvUMhV7Zrw54kwASZ+YcUJvmyvKViAm9NQJBAKF7\r\n"
    "DyXSKrem8Ws0m1ybM7HQx5As6l3EVhePDmDQT1eyRbKp+xaD74nkJpnwYdB3jyyY\r\n"
    "qc7A1tj5J5NmeEFolR0CQQCn76Xp8HCjGgLHw9vg7YyIL28y/XyfFyaZAzzK+Yia\r\n"
    "akNwQ6NeGtXSsuGCcyyfpacHp9xy8qXQNKSkw03/5vDO\r\n"
    "-----END RSA PRIVATE KEY-----\r\n";

static string g_rsaPrikeyWithPass = "-----BEGIN ENCRYPTED PRIVATE KEY-----\r\n"
"MIIBvTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQIuyVgAc9+xrMCAggA\r\n"
"MAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAECBBCF/4JkSXBKtMqZvVgWb1o1BIIB\r\n"
"YH7RtuVy5b+NjVW/8zfoWSeUxs5OB2HcAboiepwYZOyTyZyHCafUpQhMVuz6GaN/\r\n"
"JIVIrMFGRP2MdmILeASna7+IFoFPxcMU7rhQ5xpyo3oCOhFWBXZ2yanMDV8WiDCf\r\n"
"kPPtMXHrDoiwxHoKkrTlDMrfPwh5/K4xpyFOVqFtfsUS8rfsUQyHHt5NzsqgwKRh\r\n"
"y1DmMUSlz/ncLJdDhVFFKIUoZuaPDuw3g1YZpM2LWnc5AFqM3wYDx0AgNqG8Wckg\r\n"
"dZTweKY7rxYWfDkTt+KoUz16FFxjhunoBmC29Hv/vcxPPbYg8c5qd683AghTdND0\r\n"
"OKWK0yX19IJjcJy0TDpp0y3XAxXWKm5T/vLybv620iMdtxmGYVK5Wk/mZnbrb2d4\r\n"
"2eIcfx+TgOnIYNn4uSD/MuM5jmSKb7McsTAW9TTT7xBZWKxKcFZFw2/wpleP1jf3\r\n"
"Evuf/snUUCFMXLqtzFHTug8=\r\n"
"-----END ENCRYPTED PRIVATE KEY-----\r\n";
static string g_rsaPrikeyInvalid = "-----BEGIN RSA PRIVATE KEY-----\n"
    "InvalidKeyContent\n"
    "-----END RSA PRIVATE KEY-----\n";

void X509CertificateGenCsrTest::SetUpTestCase()
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
    CfBlobDataClearAndFree(&out);
}
void X509CertificateGenCsrTest::TearDownTestCase()
{
    CfObjDestroy(g_x509Name);
    CfObjDestroy(g_x509CertObj);
}
void X509CertificateGenCsrTest::SetUp() {}
void X509CertificateGenCsrTest::TearDown() {}


HWTEST_F(X509CertificateGenCsrTest, X509CsrTest001, TestSize.Level0)
{
    HcfGenCsrConf *csrConf = (HcfGenCsrConf *)CfMalloc(sizeof(HcfGenCsrConf), 0);
    char mdname[] = "SHA256";
    char attributeName[] = "challengePassword";
    char attributeValue[] = "test123456";

    csrConf->subject = g_x509Name;
    csrConf->isPem = true;
    csrConf->mdName = reinterpret_cast<char *>(mdname);

    HcfAttributesArray *attributeArray = (HcfAttributesArray *)CfMalloc(sizeof(HcfAttributesArray), 0);
    attributeArray->array = (HcfAttributes *)CfMalloc(sizeof(HcfAttributes), 0);
    attributeArray->attributeSize = 1;
    attributeArray->array->attributeName = reinterpret_cast<char *>(attributeName);
    attributeArray->array->attributeValue = reinterpret_cast<char *>(attributeValue);
    csrConf->attribute.array = attributeArray->array;
    csrConf->attribute.attributeSize = attributeArray->attributeSize;

    PrivateKeyInfo *privateKey = (PrivateKeyInfo *)CfMalloc(sizeof(PrivateKeyInfo), 0);
    privateKey->privateKey = (CfEncodingBlob *)CfMalloc(sizeof(CfEncodingBlob), 0);
    privateKey->privateKey->data = static_cast<uint8_t *>(malloc(g_rsaPrikey.length() + 1));
    privateKey->privateKey->encodingFormat = CF_FORMAT_PEM;
    if (privateKey->privateKey->data != nullptr) {
        (void)memcpy_s(privateKey->privateKey->data, g_rsaPrikey.length() + 1,
            g_rsaPrikey.c_str(), g_rsaPrikey.length() + 1);
        privateKey->privateKey->len = g_rsaPrikey.length() + 1;
    }

    CfBlob csrBlob = { 0 };
    EXPECT_EQ(HcfX509CertificateGenCsr(privateKey, csrConf, &csrBlob), CF_SUCCESS);
    EXPECT_NE(csrBlob.data, nullptr);

    char* csrString = reinterpret_cast<char*>(csrBlob.data);
    EXPECT_TRUE(strstr(csrString, "BEGIN CERTIFICATE REQUEST") != nullptr);
    EXPECT_TRUE(strstr(csrString, "END CERTIFICATE REQUEST") != nullptr);

    CfFree(attributeArray->array);
    CfFree(attributeArray);
    CfFree(privateKey->privateKey->data);
    CfFree(privateKey->privateKey);
    CfFree(privateKey);
    CfFree(csrConf);
    CfBlobDataFree(&csrBlob);
}

HWTEST_F(X509CertificateGenCsrTest, X509CsrTest002, TestSize.Level0)
{
    HcfGenCsrConf *csrConf = (HcfGenCsrConf *)CfMalloc(sizeof(HcfGenCsrConf), 0);
    csrConf->subject = g_x509Name;
    csrConf->isPem = true;

    PrivateKeyInfo *privateKey = (PrivateKeyInfo *)CfMalloc(sizeof(PrivateKeyInfo), 0);
    privateKey->privateKey = (CfEncodingBlob *)CfMalloc(sizeof(CfEncodingBlob), 0);
    privateKey->privateKey->data = static_cast<uint8_t *>(malloc(g_rsaPrikey.length() + 1));
    privateKey->privateKey->encodingFormat = CF_FORMAT_PEM;
    if (privateKey->privateKey->data != nullptr) {
        (void)memcpy_s(privateKey->privateKey->data, g_rsaPrikey.length() + 1,
            g_rsaPrikey.c_str(), g_rsaPrikey.length() + 1);
        privateKey->privateKey->len = g_rsaPrikey.length() + 1;
    }

    CfBlob csrBlob = { 0 };
    EXPECT_EQ(HcfX509CertificateGenCsr(privateKey, csrConf, &csrBlob), CF_ERR_CRYPTO_OPERATION);

    CfFree(privateKey->privateKey->data);
    CfFree(privateKey->privateKey);
    CfFree(privateKey);
    CfFree(csrConf);
    CfBlobDataFree(&csrBlob);
}

HWTEST_F(X509CertificateGenCsrTest, X509CsrTest003, TestSize.Level0)
{
    HcfGenCsrConf *csrConf = (HcfGenCsrConf *)CfMalloc(sizeof(HcfGenCsrConf), 0);
    PrivateKeyInfo *privateKey = (PrivateKeyInfo *)CfMalloc(sizeof(PrivateKeyInfo), 0);
    CfBlob csrBlob = { 0 };
    EXPECT_EQ(HcfX509CertificateGenCsr(nullptr, csrConf, &csrBlob), CF_INVALID_PARAMS);
    EXPECT_EQ(HcfX509CertificateGenCsr(privateKey, nullptr, &csrBlob), CF_INVALID_PARAMS);
    EXPECT_EQ(HcfX509CertificateGenCsr(privateKey, csrConf, nullptr), CF_INVALID_PARAMS);

    CfFree(privateKey);
    CfFree(csrConf);
}

HWTEST_F(X509CertificateGenCsrTest, X509CsrTest004, TestSize.Level0)
{
    const char* digestAlgorithms[] = {"SHA256", "SHA384", "SHA512"};

    for (const auto& digest : digestAlgorithms) {
        HcfGenCsrConf *csrConf = (HcfGenCsrConf *)CfMalloc(sizeof(HcfGenCsrConf), 0);
        csrConf->subject = g_x509Name;
        csrConf->isPem = true;
        csrConf->mdName = const_cast<char*>(digest);

        PrivateKeyInfo *privateKey = (PrivateKeyInfo *)CfMalloc(sizeof(PrivateKeyInfo), 0);
        privateKey->privateKey = (CfEncodingBlob *)CfMalloc(sizeof(CfEncodingBlob), 0);
        privateKey->privateKey->data = static_cast<uint8_t *>(malloc(g_rsaPrikey.length() + 1));
        privateKey->privateKey->encodingFormat = CF_FORMAT_PEM;
        if (privateKey->privateKey->data != nullptr) {
            (void)memcpy_s(privateKey->privateKey->data, g_rsaPrikey.length() + 1,
                g_rsaPrikey.c_str(), g_rsaPrikey.length() + 1);
            privateKey->privateKey->len = g_rsaPrikey.length() + 1;
        }

        CfBlob csrBlob = { 0 };
        EXPECT_EQ(HcfX509CertificateGenCsr(privateKey, csrConf, &csrBlob), CF_SUCCESS);

        CfFree(privateKey->privateKey->data);
        CfFree(privateKey->privateKey);
        CfFree(privateKey);
        CfFree(csrConf);
        CfBlobDataFree(&csrBlob);
    }
}
HWTEST_F(X509CertificateGenCsrTest, X509CsrTest005, TestSize.Level0)
{
    struct TestAttribute {
        const char* name;
        const char* value;
    };

    const TestAttribute testAttributes[] = {
        {"challengePassword", "test123456"},
        {"unstructuredName", "TestUnstructuredName"},
        {"emailAddress", "test@example.com"},
        {"subjectAltName", "DNS:test.example.com"}
    };
    const size_t attributeCount = sizeof(testAttributes) / sizeof(TestAttribute);

    for (size_t i = 0; i < attributeCount; i++) {
        HcfGenCsrConf *csrConf = (HcfGenCsrConf *)CfMalloc(sizeof(HcfGenCsrConf), 0);
        char mdname[] = "SHA256";

        csrConf->subject = g_x509Name;
        csrConf->isPem = true;
        csrConf->mdName = reinterpret_cast<char *>(mdname);

        HcfAttributesArray *attributeArray = (HcfAttributesArray *)CfMalloc(sizeof(HcfAttributesArray), 0);
        attributeArray->array = (HcfAttributes *)CfMalloc(sizeof(HcfAttributes), 0);
        attributeArray->attributeSize = 1;
        attributeArray->array->attributeName = const_cast<char*>(testAttributes[i].name);
        attributeArray->array->attributeValue = const_cast<char*>(testAttributes[i].value);
        csrConf->attribute.array = attributeArray->array;
        csrConf->attribute.attributeSize = attributeArray->attributeSize;

        PrivateKeyInfo *privateKey = (PrivateKeyInfo *)CfMalloc(sizeof(PrivateKeyInfo), 0);
        privateKey->privateKey = (CfEncodingBlob *)CfMalloc(sizeof(CfEncodingBlob), 0);
        privateKey->privateKey->data = static_cast<uint8_t *>(malloc(g_rsaPrikey.length() + 1));
        privateKey->privateKey->encodingFormat = CF_FORMAT_PEM;
        if (privateKey->privateKey->data != nullptr) {
            (void)memcpy_s(privateKey->privateKey->data, g_rsaPrikey.length() + 1,
                g_rsaPrikey.c_str(), g_rsaPrikey.length() + 1);
            privateKey->privateKey->len = g_rsaPrikey.length() + 1;
        }

        CfBlob csrBlob = { 0 };
        EXPECT_EQ(HcfX509CertificateGenCsr(privateKey, csrConf, &csrBlob), CF_SUCCESS);
        EXPECT_NE(csrBlob.data, nullptr);

        char* csrString = reinterpret_cast<char*>(csrBlob.data);
        EXPECT_TRUE(strstr(csrString, "BEGIN CERTIFICATE REQUEST") != nullptr);
        EXPECT_TRUE(strstr(csrString, "END CERTIFICATE REQUEST") != nullptr);


        CfFree(attributeArray->array);
        CfFree(attributeArray);
        CfFree(privateKey->privateKey->data);
        CfFree(privateKey->privateKey);
        CfFree(privateKey);
        CfFree(csrConf);
        CfBlobDataFree(&csrBlob);
    }
}


HWTEST_F(X509CertificateGenCsrTest, X509CsrTest006, TestSize.Level0)
{
    HcfGenCsrConf *csrConf = (HcfGenCsrConf *)CfMalloc(sizeof(HcfGenCsrConf), 0);
    char mdname[] = "SHA256";

    csrConf->subject = g_x509Name;
    csrConf->isPem = true;
    csrConf->mdName = reinterpret_cast<char *>(mdname);

    HcfAttributesArray *attributeArray = (HcfAttributesArray *)CfMalloc(sizeof(HcfAttributesArray), 0);
    attributeArray->array = new HcfAttributes[3];
    attributeArray->attributeSize = 3;

    attributeArray->array[0].attributeName = const_cast<char*>("challengePassword");
    attributeArray->array[0].attributeValue = const_cast<char*>("test123456");

    attributeArray->array[1].attributeName = const_cast<char*>("unstructuredName");
    attributeArray->array[1].attributeValue = const_cast<char*>("TestUnstructuredName");

    attributeArray->array[2].attributeName = const_cast<char*>("emailAddress");
    attributeArray->array[2].attributeValue = const_cast<char*>("test@example.com");

    csrConf->attribute.array = attributeArray->array;
    csrConf->attribute.attributeSize = attributeArray->attributeSize;

    PrivateKeyInfo *privateKey = (PrivateKeyInfo *)CfMalloc(sizeof(PrivateKeyInfo), 0);
    privateKey->privateKey = (CfEncodingBlob *)CfMalloc(sizeof(CfEncodingBlob), 0);
    privateKey->privateKey->data = static_cast<uint8_t *>(malloc(g_rsaPrikey.length() + 1));
    privateKey->privateKey->encodingFormat = CF_FORMAT_PEM;
    if (privateKey->privateKey->data != nullptr) {
        (void)memcpy_s(privateKey->privateKey->data, g_rsaPrikey.length() + 1,
            g_rsaPrikey.c_str(), g_rsaPrikey.length() + 1);
        privateKey->privateKey->len = g_rsaPrikey.length() + 1;
    }

    CfBlob csrBlob = { 0 };
    EXPECT_EQ(HcfX509CertificateGenCsr(privateKey, csrConf, &csrBlob), CF_SUCCESS);
    EXPECT_NE(csrBlob.data, nullptr);

    char* csrString = reinterpret_cast<char*>(csrBlob.data);
    EXPECT_TRUE(strstr(csrString, "BEGIN CERTIFICATE REQUEST") != nullptr);
    EXPECT_TRUE(strstr(csrString, "END CERTIFICATE REQUEST") != nullptr);

    delete[] attributeArray->array;
    CfFree(attributeArray);
    CfFree(privateKey->privateKey->data);
    CfFree(privateKey->privateKey);
    CfFree(privateKey);
    CfFree(csrConf);
    CfBlobDataFree(&csrBlob);
}

HWTEST_F(X509CertificateGenCsrTest, X509CsrTest007, TestSize.Level0)
{
    struct TestCase {
        const string& privateKey;
        const char* password;
        CfResult expectedResult;
    };

    TestCase testCases[] = {
        {g_rsaPrikey, nullptr, CF_ERR_CRYPTO_OPERATION},
        {g_rsaPrikeyWithPass, "password123", CF_ERR_CRYPTO_OPERATION},
        {g_rsaPrikeyInvalid, nullptr, CF_ERR_CRYPTO_OPERATION}
    };

    for (const auto& testCase : testCases) {
        HcfGenCsrConf *csrConf = (HcfGenCsrConf *)CfMalloc(sizeof(HcfGenCsrConf), 0);
        csrConf->subject = g_x509Name;
        csrConf->isPem = true;
        PrivateKeyInfo *privateKey = (PrivateKeyInfo *)CfMalloc(sizeof(PrivateKeyInfo), 0);
        privateKey->privateKey = (CfEncodingBlob *)CfMalloc(sizeof(CfEncodingBlob), 0);
        privateKey->privateKey->data = static_cast<uint8_t *>(malloc(testCase.privateKey.length() + 1));
        privateKey->privateKey->encodingFormat = CF_FORMAT_PEM;
        if (privateKey->privateKey->data != nullptr) {
            (void)memcpy_s(privateKey->privateKey->data, testCase.privateKey.length() + 1,
                testCase.privateKey.c_str(), testCase.privateKey.length() + 1);
            privateKey->privateKey->len = testCase.privateKey.length() + 1;
        }

        if (testCase.password != nullptr) {
            privateKey->privateKeyPassword = const_cast<char*>(testCase.password);
        }

        CfBlob csrBlob = { 0 };
        EXPECT_EQ(HcfX509CertificateGenCsr(privateKey, csrConf, &csrBlob), testCase.expectedResult);

        if (testCase.expectedResult == CF_SUCCESS) {
            EXPECT_NE(csrBlob.data, nullptr);
            char* csrString = reinterpret_cast<char*>(csrBlob.data);
            EXPECT_TRUE(strstr(csrString, "BEGIN CERTIFICATE REQUEST") != nullptr);
        }

        CfFree(privateKey->privateKey->data);
        CfFree(privateKey->privateKey);
        CfFree(privateKey);
        CfFree(csrConf);
        CfBlobDataFree(&csrBlob);
    }
}

HWTEST_F(X509CertificateGenCsrTest, X509CsrTest008, TestSize.Level0)
{
    HcfGenCsrConf *csrConf = (HcfGenCsrConf *)CfMalloc(sizeof(HcfGenCsrConf), 0);
    csrConf->subject = g_x509Name;
    csrConf->isPem = true;

    struct TestCase {
        const char* password;
        CfResult expectedResult;
    };

    TestCase testCases[] = {
        {"password123", CF_ERR_CRYPTO_OPERATION},
        {"wrongpassword", CF_ERR_CRYPTO_OPERATION},
        {nullptr, CF_ERR_CRYPTO_OPERATION},
        {"", CF_ERR_CRYPTO_OPERATION}
    };

    for (const auto& testCase : testCases) {
        PrivateKeyInfo *privateKey = (PrivateKeyInfo *)CfMalloc(sizeof(PrivateKeyInfo), 0);
        privateKey->privateKey = (CfEncodingBlob *)CfMalloc(sizeof(CfEncodingBlob), 0);
        privateKey->privateKey->data = static_cast<uint8_t *>(malloc(g_rsaPrikeyWithPass.length() + 1));
        privateKey->privateKey->encodingFormat = CF_FORMAT_PEM;
        if (privateKey->privateKey->data != nullptr) {
            (void)memcpy_s(privateKey->privateKey->data, g_rsaPrikeyWithPass.length() + 1,
                g_rsaPrikeyWithPass.c_str(), g_rsaPrikeyWithPass.length() + 1);
            privateKey->privateKey->len = g_rsaPrikeyWithPass.length() + 1;
        }

        privateKey->privateKeyPassword = const_cast<char*>(testCase.password);

        CfBlob csrBlob = { 0 };
        EXPECT_EQ(HcfX509CertificateGenCsr(privateKey, csrConf, &csrBlob), testCase.expectedResult);

        CfFree(privateKey->privateKey->data);
        CfFree(privateKey->privateKey);
        CfFree(privateKey);
        CfBlobDataFree(&csrBlob);
    }

    CfFree(csrConf);
}

HWTEST_F(X509CertificateGenCsrTest, X509CsrTest009, TestSize.Level0)
{
    HcfGenCsrConf *csrConf = (HcfGenCsrConf *)CfMalloc(sizeof(HcfGenCsrConf), 0);
    csrConf->subject = g_x509Name;
    csrConf->isPem = true;
    PrivateKeyInfo *privateKey = (PrivateKeyInfo *)CfMalloc(sizeof(PrivateKeyInfo), 0);
    privateKey->privateKey = (CfEncodingBlob *)CfMalloc(sizeof(CfEncodingBlob), 0);
    privateKey->privateKey->data = nullptr;
    privateKey->privateKey->len = 0;
    privateKey->privateKey->encodingFormat = CF_FORMAT_PEM;

    CfBlob csrBlob = { 0 };
    EXPECT_EQ(HcfX509CertificateGenCsr(privateKey, csrConf, &csrBlob), CF_ERR_CRYPTO_OPERATION);

    CfFree(privateKey->privateKey->data);
    CfFree(privateKey->privateKey);
    CfFree(privateKey);
    CfBlobDataFree(&csrBlob);

    CfFree(csrConf);
}

HWTEST_F(X509CertificateGenCsrTest, X509CsrTest010, TestSize.Level0)
{
    HcfGenCsrConf *csrConf = (HcfGenCsrConf *)CfMalloc(sizeof(HcfGenCsrConf), 0);
    csrConf->subject = g_x509Name;
    csrConf->isPem = true;

    PrivateKeyInfo *privateKey = (PrivateKeyInfo *)CfMalloc(sizeof(PrivateKeyInfo), 0);
    privateKey->privateKey = (CfEncodingBlob *)CfMalloc(sizeof(CfEncodingBlob), 0);
    privateKey->privateKey->data = static_cast<uint8_t *>(malloc(1));
    privateKey->privateKey->len = 0;
    privateKey->privateKey->encodingFormat = CF_FORMAT_PEM;

    CfBlob csrBlob = { 0 };
    EXPECT_EQ(HcfX509CertificateGenCsr(privateKey, csrConf, &csrBlob), CF_ERR_CRYPTO_OPERATION);

    CfFree(privateKey->privateKey->data);
    CfFree(privateKey->privateKey);
    CfFree(privateKey);
    CfFree(csrConf);
    CfBlobDataFree(&csrBlob);
}

HWTEST_F(X509CertificateGenCsrTest, X509CsrTest011, TestSize.Level0)
{
    HcfGenCsrConf *csrConf = (HcfGenCsrConf *)CfMalloc(sizeof(HcfGenCsrConf), 0);
    csrConf->subject = g_x509Name;
    csrConf->isPem = true;

    PrivateKeyInfo *privateKey = (PrivateKeyInfo *)CfMalloc(sizeof(PrivateKeyInfo), 0);
    privateKey->privateKey = (CfEncodingBlob *)CfMalloc(sizeof(CfEncodingBlob), 0);
    privateKey->privateKey->data = static_cast<uint8_t *>(malloc(g_rsaPrikeyWithPass.length() + 1));
    privateKey->privateKey->encodingFormat = CF_FORMAT_PEM;
    if (privateKey->privateKey->data != nullptr) {
        (void)memcpy_s(privateKey->privateKey->data, g_rsaPrikeyWithPass.length() + 1,
            g_rsaPrikeyWithPass.c_str(), g_rsaPrikeyWithPass.length() + 1);
        privateKey->privateKey->len = g_rsaPrikeyWithPass.length() + 1;
    }

    string longPassword(1024, 'a');
    privateKey->privateKeyPassword = const_cast<char*>(longPassword.c_str());

    CfBlob csrBlob = { 0 };
    EXPECT_EQ(HcfX509CertificateGenCsr(privateKey, csrConf, &csrBlob), CF_ERR_CRYPTO_OPERATION);

    CfFree(privateKey->privateKey->data);
    CfFree(privateKey->privateKey);
    CfFree(privateKey);
    CfFree(csrConf);
    CfBlobDataFree(&csrBlob);
}

}