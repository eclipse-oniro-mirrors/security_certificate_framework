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
#include "securec.h"

#include "x509_certificate.h"
#include "cf_blob.h"
#include "memory_mock.h"

#include "certificate_openssl_common.h"
#include "x509_certificate_openssl.h"

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

static char g_deviceTestCert[] =
"-----BEGIN CERTIFICATE-----\r\n"
"MIIBLzCB1QIUO/QDVJwZLIpeJyPjyTvE43xvE5cwCgYIKoZIzj0EAwIwGjEYMBYG\r\n"
"A1UEAwwPRXhhbXBsZSBSb290IENBMB4XDTIzMDkwNDExMjAxOVoXDTI2MDUzMDEx\r\n"
"MjAxOVowGjEYMBYGA1UEAwwPRXhhbXBsZSBSb290IENBMFkwEwYHKoZIzj0CAQYI\r\n"
"KoZIzj0DAQcDQgAEHjG74yMIueO7z3T+dyuEIrhxTg2fqgeNB3SGfsIXlsiUfLTa\r\n"
"tUsU0i/sePnrKglj2H8Abbx9PK0tsW/VgqwDIDAKBggqhkjOPQQDAgNJADBGAiEA\r\n"
"0ce/fvA4tckNZeB865aOApKXKlBjiRlaiuq5mEEqvNACIQDPD9WyC21MXqPBuRUf\r\n"
"BetUokslUfjT6+s/X4ByaxycAA==\r\n"
"-----END CERTIFICATE-----";

static char g_rootCert[] =
"-----BEGIN CERTIFICATE-----\r\n"
"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\r\n"
"jI6AaoTlr5I7zPhFbR8/XEs7DzI=\r\n"
"-----END CERTIFICATE-----\r\n";

static char g_secondCert[] =
"-----BEGIN CERTIFICATE-----\r\n"
"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\r\n"
"-----END CERTIFICATE-----\r\n";

static char g_testInvalidCert[] =
"-----xxxx CERTIFICATE-----\r\n"
"MIIDpzCCAo+gAwIBAgICAQAwDQYJKoZIhvcNAQELBQAwbDELMAkGA1UEBhMCQ04x\r\n"
"CzAJBgNVBAgMAkJKMQswCQYDVQQHDAJCSjELMAkGA1UECgwCSEQxDDAKBgNVBAsM\r\n"
"A2RldjELMAkGA1UEAwwCY2ExGzAZBgkqhkiG9w0BCQEWDGNhQHdvcmxkLmNvbTAe\r\n"
"Fw0yMjA4MTkwNTE2MTVaFw0yMzA4MTkwNTE2MTVaMGwxCzAJBgNVBAYTAkNOMQsw\r\n"
"CQYDVQQIDAJCSjELMAkGA1UEBwwCQkoxCzAJBgNVBAoMAkhEMQwwCgYDVQQLDANk\r\n"
"ZXYxCzAJBgNVBAMMAmNhMRswGQYJKoZIhvcNAQkBFgxjYUB3b3JsZC5jb20wggEi\r\n"
"MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCuvLoVT5em7ApBma8xtgpcFcaU\r\n"
"CbXBJSUl2NpFW2sriucbEOvKRdw9KvLa/tSP6CupPZVKIzHAP2oeW88aFBr23miG\r\n"
"iR49M52c73Iw3H3EG2ckK8M1mxEzXSqynivqiNZDKG+bA5cFzcfmk6Th1bJan9w9\r\n"
"Ci8HPSBvgg7Rc6pqNM4HjTHl3Bb6cf4Xh3/GgpjypTd9jAAEyq+l/+1pnTYVlIJA\r\n"
"WGh0Z26RosXfzwfFKH77ysTjoj9ambvGmFsMXvNXEyYmBCeYND6xGj4pa2lylsra\r\n"
"kfYmGxcFQ45Lj5oWdNQQVdvrQiYWu3SJOC/WqB5UIAq92PPrq1apznxfjqABAgMB\r\n"
"AAGjUzBRMB0GA1UdDgQWBBRI5iWwjBMAOCcgcUjUCYJdsvwEMjAfBgNVHSMEGDAW\r\n"
"gBRI5iWwjBMAOCcgcUjUCYJdsvwEMjAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3\r\n"
"DQEBCwUAA4IBAQABop7EJgS2czHKWVzdEwjbi9m5ZUPy6aOV9paV1e/5IyFNHwun\r\n"
"B64iwcg03+FmIWNuynb1mglHHrUoXygXu9GIR8cWfOI3W+Pnn8fDi8MxQMn/e/Jj\r\n"
"BuGcnRwKynRhyLdkyWYn1YwqenMuFJu9yzkhfAPltGFEuPYCWDatdhm6zhFdu1PE\r\n"
"EMErHpQOT45z5cgC4XqgKlE+n8L4/5RfZnbuUJ3bV+FuI+VApLGXJQlJQAOTqBDg\r\n"
"k7DMSgPUUxYYa6AGMFy6vqQ6hcgCMK08ko8LdjVd1MobKzM9Oh480GFZA/ubR3QW\r\n"
"lv3OuOhmnIxNGcPUiqpSiWKqR5tf1KUImIR9\r\n"
"-----END CERTIFICATE-----\r\n";

/* g_testSelfSignedCaCert
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 272 (0x110)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C = CN, ST = BJ, L = BJ, O = HD, OU = dev, CN = ca, emailAddress = ca@cryptoframework.com
        Validity
            Not Before: Aug 19 12:49:06 2022 GMT
            Not After : Aug 16 12:49:06 2032 GMT
        Subject: C = CN, ST = BJ, L = BJ, O = HD, OU = dev, CN = ca, emailAddress = ca@cryptoframework.com
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (2048 bit)
                Modulus:
                    00:9f:29:d0:85:84:ed:6c:30:6e:d0:13:83:e0:1b:
                    61:08:f7:dd:63:41:06:4b:54:fb:f0:15:7f:e4:e5:
                    d5:a0:1a:e1:33:9e:5b:6f:d9:01:17:38:b1:dc:0b:
                    55:3c:5d:5c:28:a9:16:c7:ae:88:63:77:d2:1c:17:
                    ad:71:54:1e:b7:0c:7f:4c:36:b0:29:33:9c:95:59:
                    fe:b4:1c:7c:43:b9:29:bd:6f:07:3e:83:10:47:20:
                    21:26:04:86:1a:8e:05:f6:01:8a:de:6a:7e:9a:b9:
                    47:6f:b6:47:f4:e1:ff:26:d5:fa:40:6b:52:5f:86:
                    b2:c5:db:0c:07:ba:a1:90:b2:e7:a9:46:a6:10:ef:
                    98:73:14:3b:b6:b5:de:3f:92:16:64:e1:31:b2:36:
                    c9:ec:ae:6b:52:da:81:2a:1a:04:97:d8:d4:9f:a2:
                    ee:35:8f:9a:61:05:47:47:50:da:9d:04:1a:31:d3:
                    81:01:a1:46:8e:55:bb:00:c7:8a:93:52:bf:45:cf:
                    f0:e5:00:fc:f6:1b:2f:f4:81:8f:51:6a:e0:2d:e0:
                    b5:fb:e3:7a:cc:14:6f:35:5a:32:8a:bf:c0:2b:b2:
                    d6:a7:17:23:cd:19:2d:ed:f0:85:1d:b8:73:47:17:
                    60:53:b4:b8:68:bd:7a:03:e9:db:87:f0:ef:26:06:
                    aa:01
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Subject Key Identifier:
                8C:A3:3B:42:63:01:B3:4D:51:F6:E4:2D:B5:83:7F:18:39:2F:B7:B5
            X509v3 Authority Key Identifier:
                keyid:8C:A3:3B:42:63:01:B3:4D:51:F6:E4:2D:B5:83:7F:18:39:2F:B7:B5

            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:2
            X509v3 Key Usage:
                Certificate Sign, CRL Sign
            X509v3 Extended Key Usage:
                TLS Web Server Authentication, TLS Web Client Authentication
            X509v3 Subject Alternative Name:
                email:ca@cryptoframework.com
            X509v3 Issuer Alternative Name:
                email:ca@cryptoframework.com
    Signature Algorithm: sha256WithRSAEncryption
         87:ee:11:13:a7:09:eb:6f:e0:2d:8b:2c:2e:47:3b:11:28:3b:
         7b:12:b0:66:59:a2:b0:7c:81:89:cb:b2:ff:e5:da:80:e6:77:
         71:36:e0:40:d5:e5:42:86:4a:6f:0f:e4:b3:f0:7f:70:89:db:
         40:66:1b:a4:09:b8:ed:2b:9d:a3:e2:3f:1b:dc:63:d1:7e:e0:
         40:1f:70:b5:2a:db:4a:d3:ac:e9:28:e7:2e:26:14:d3:11:5c:
         16:c7:34:8f:a9:36:4a:b9:72:8b:04:50:72:34:b8:3c:e2:a2:
         51:2d:02:9b:71:77:0c:71:9d:8f:9e:4f:94:19:17:c6:e7:57:
         0a:ad:95:dc:9d:d5:c0:a7:f6:6d:58:d0:6f:3c:f6:f8:cf:d0:
         d6:6f:8f:ec:58:41:f8:99:9e:3b:c7:9e:9a:4a:8c:43:4b:45:
         31:4d:c4:33:8e:35:36:97:a3:0b:98:85:54:01:a0:a3:09:c2:
         f1:2d:01:f9:fc:47:f5:d0:49:b8:73:3a:be:9c:44:5b:0d:dc:
         91:91:43:65:0d:64:77:dd:58:46:0a:fb:8d:8f:1f:73:4b:ff:
         4f:4b:73:1d:66:ce:11:5c:e4:94:42:01:58:bd:66:a2:6a:4b:
         04:2c:1e:d3:f1:b0:f8:13:ba:d1:b7:e2:d8:ca:09:c3:cb:76:
         21:c0:75:43
*/
static char g_testSelfSignedCaCert[] =
"-----BEGIN CERTIFICATE-----\r\n"
"MIIEMjCCAxqgAwIBAgICARAwDQYJKoZIhvcNAQELBQAwdjELMAkGA1UEBhMCQ04x\r\n"
"CzAJBgNVBAgMAkJKMQswCQYDVQQHDAJCSjELMAkGA1UECgwCSEQxDDAKBgNVBAsM\r\n"
"A2RldjELMAkGA1UEAwwCY2ExJTAjBgkqhkiG9w0BCQEWFmNhQGNyeXB0b2ZyYW1l\r\n"
"d29yay5jb20wHhcNMjIwODE5MTI0OTA2WhcNMzIwODE2MTI0OTA2WjB2MQswCQYD\r\n"
"VQQGEwJDTjELMAkGA1UECAwCQkoxCzAJBgNVBAcMAkJKMQswCQYDVQQKDAJIRDEM\r\n"
"MAoGA1UECwwDZGV2MQswCQYDVQQDDAJjYTElMCMGCSqGSIb3DQEJARYWY2FAY3J5\r\n"
"cHRvZnJhbWV3b3JrLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB\r\n"
"AJ8p0IWE7WwwbtATg+AbYQj33WNBBktU+/AVf+Tl1aAa4TOeW2/ZARc4sdwLVTxd\r\n"
"XCipFseuiGN30hwXrXFUHrcMf0w2sCkznJVZ/rQcfEO5Kb1vBz6DEEcgISYEhhqO\r\n"
"BfYBit5qfpq5R2+2R/Th/ybV+kBrUl+GssXbDAe6oZCy56lGphDvmHMUO7a13j+S\r\n"
"FmThMbI2yeyua1LagSoaBJfY1J+i7jWPmmEFR0dQ2p0EGjHTgQGhRo5VuwDHipNS\r\n"
"v0XP8OUA/PYbL/SBj1Fq4C3gtfvjeswUbzVaMoq/wCuy1qcXI80ZLe3whR24c0cX\r\n"
"YFO0uGi9egPp24fw7yYGqgECAwEAAaOByTCBxjAdBgNVHQ4EFgQUjKM7QmMBs01R\r\n"
"9uQttYN/GDkvt7UwHwYDVR0jBBgwFoAUjKM7QmMBs01R9uQttYN/GDkvt7UwEgYD\r\n"
"VR0TAQH/BAgwBgEB/wIBAjALBgNVHQ8EBAMCAQYwHQYDVR0lBBYwFAYIKwYBBQUH\r\n"
"AwEGCCsGAQUFBwMCMCEGA1UdEQQaMBiBFmNhQGNyeXB0b2ZyYW1ld29yay5jb20w\r\n"
"IQYDVR0SBBowGIEWY2FAY3J5cHRvZnJhbWV3b3JrLmNvbTANBgkqhkiG9w0BAQsF\r\n"
"AAOCAQEAh+4RE6cJ62/gLYssLkc7ESg7exKwZlmisHyBicuy/+XagOZ3cTbgQNXl\r\n"
"QoZKbw/ks/B/cInbQGYbpAm47Sudo+I/G9xj0X7gQB9wtSrbStOs6SjnLiYU0xFc\r\n"
"Fsc0j6k2SrlyiwRQcjS4POKiUS0Cm3F3DHGdj55PlBkXxudXCq2V3J3VwKf2bVjQ\r\n"
"bzz2+M/Q1m+P7FhB+JmeO8eemkqMQ0tFMU3EM441NpejC5iFVAGgownC8S0B+fxH\r\n"
"9dBJuHM6vpxEWw3ckZFDZQ1kd91YRgr7jY8fc0v/T0tzHWbOEVzklEIBWL1mompL\r\n"
"BCwe0/Gw+BO60bfi2MoJw8t2IcB1Qw==\r\n"
"-----END CERTIFICATE-----\r\n";

constexpr int TEST_CERT_VERSION = 3;
constexpr int TEST_CERT_CHAIN_LEN = 2;
constexpr int TEST_CERT_SERIAL_NUMBER = 272;

static HcfX509Certificate *g_x509CertObj = nullptr;

void CryptoX509CertificateTest::SetUpTestCase()
{
    CfEncodingBlob inStream = { 0 };
    inStream.data = (uint8_t *)g_testSelfSignedCaCert;
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
    inStream.data = (uint8_t *)g_testSelfSignedCaCert;
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
    inStream.data = (uint8_t *)g_testInvalidCert;
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
    CfResult ret = g_x509CertObj->base.getEncoded((HcfCertificate *)g_x509CertObj, &derBlob);
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
    CfResult ret = g_x509CertObj->base.getPublicKey((HcfCertificate *)g_x509CertObj, &keyOut);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(keyOut, nullptr);
    ret = g_x509CertObj->base.verify((HcfCertificate *)g_x509CertObj, keyOut);
    EXPECT_EQ(ret, CF_SUCCESS);
    CfObjDestroy(keyOut);
}

/* use root ca cert's public key to verify next cert. */
HWTEST_F(CryptoX509CertificateTest, Verify002, TestSize.Level0)
{
    HcfX509Certificate *rootCert = nullptr;
    CfEncodingBlob root = { 0 };
    root.data = (uint8_t *)g_rootCert;
    root.encodingFormat = CF_FORMAT_PEM;
    root.len = strlen(g_rootCert) + 1;
    CfResult ret = HcfX509CertificateCreate(&root, &rootCert);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(rootCert, nullptr);
    HcfPubKey *rootkeyOut = nullptr;
    ret = rootCert->base.getPublicKey((HcfCertificate *)rootCert, &rootkeyOut);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(rootkeyOut, nullptr);

    HcfX509Certificate *secondCert = nullptr;
    CfEncodingBlob second = { 0 };
    second.data = (uint8_t *)g_secondCert;
    second.encodingFormat = CF_FORMAT_PEM;
    second.len = strlen(g_secondCert) + 1;
    ret = HcfX509CertificateCreate(&root, &secondCert);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(rootCert, nullptr);
    ret = secondCert->base.verify((HcfCertificate *)secondCert, rootkeyOut);
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
    root.data = (uint8_t *)g_rootCert;
    root.encodingFormat = CF_FORMAT_PEM;
    root.len = strlen(g_rootCert) + 1;
    CfResult ret = HcfX509CertificateCreate(&root, &rootCert);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(rootCert, nullptr);
    HcfPubKey *rootkeyOut = nullptr;
    ret = rootCert->base.getPublicKey((HcfCertificate *)rootCert, &rootkeyOut);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(rootkeyOut, nullptr);

    ret = g_x509CertObj->base.verify((HcfCertificate *)g_x509CertObj, rootkeyOut);
    EXPECT_NE(ret, CF_SUCCESS);
    CfObjDestroy(rootkeyOut);
    CfObjDestroy(rootCert);
}

/* verify cert with invalid input pub key. */
HWTEST_F(CryptoX509CertificateTest, Verify004, TestSize.Level0)
{
    CfResult ret = g_x509CertObj->base.verify((HcfCertificate *)g_x509CertObj, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
}

HWTEST_F(CryptoX509CertificateTest, GetEncoded001, TestSize.Level0)
{
    CfEncodingBlob encodingBlob = { 0 };
    CfResult ret = g_x509CertObj->base.getEncoded((HcfCertificate *)g_x509CertObj, &encodingBlob);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(encodingBlob.data, nullptr);
    EXPECT_EQ(encodingBlob.encodingFormat, CF_FORMAT_DER);
    CfEncodingBlobDataFree(&encodingBlob);
}

/* Invalid input. */
HWTEST_F(CryptoX509CertificateTest, GetEncoded002, TestSize.Level0)
{
    CfResult ret = g_x509CertObj->base.getEncoded((HcfCertificate *)g_x509CertObj, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
}

HWTEST_F(CryptoX509CertificateTest, GetPublicKey, TestSize.Level0)
{
    HcfPubKey *keyOut = nullptr;
    CfResult ret = g_x509CertObj->base.getPublicKey((HcfCertificate *)g_x509CertObj, &keyOut);
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
    inStream.data = (uint8_t *)g_secondCert;
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
    inStream.data = (uint8_t *)g_deviceTestCert;
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
    inStream.data = (uint8_t *)g_secondCert;
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
    inStream.data = (uint8_t *)g_secondCert;
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
    inStream.data = (uint8_t *)g_secondCert;
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
    inStream.data = (uint8_t *)g_secondCert;
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

HWTEST_F(CryptoX509CertificateTest, NullInput, TestSize.Level0)
{
    (void)HcfX509CertificateCreate(nullptr, nullptr);
    HcfPubKey *keyOut = nullptr;
    CfResult ret = g_x509CertObj->base.getPublicKey((HcfCertificate *)g_x509CertObj, &keyOut);
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

HWTEST_F(CryptoX509CertificateTest, NullSpiInput, TestSize.Level0)
{
    HcfX509CertificateSpi *spiObj = nullptr;
    CfEncodingBlob inStream = { 0 };
    inStream.data = (uint8_t *)g_testSelfSignedCaCert;
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
    CfObjDestroy(spiObj);
}

static const char *GetInvalidCertClass(void)
{
    return "INVALID_CERT_CLASS";
}

HWTEST_F(CryptoX509CertificateTest, InvalidSpiClass, TestSize.Level0)
{
    HcfX509CertificateSpi *spiObj = nullptr;
    HcfX509CertificateSpi invalidSpi = { {0} };
    invalidSpi.base.getClass = GetInvalidCertClass;
    CfBlob invalidOut = { 0 };
    CfEncodingBlob inStream = { 0 };
    inStream.data = (uint8_t *)g_testSelfSignedCaCert;
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
    ret = g_x509CertObj->base.getPublicKey(&(invalidCert.base), &pubKeyOut);
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
    inStream.data = (uint8_t *)g_secondCert;
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_secondCert) + 1;
    CfResult ret = HcfX509CertificateCreate(&inStream, &x509Cert);
    EXPECT_NE(ret, CF_SUCCESS);
    CfBlob out = { 0 };
    CfArray arr = { 0 };
    ret = g_x509CertObj->base.getEncoded(&(g_x509CertObj->base), &inStream);
    EXPECT_NE(ret, CF_SUCCESS);
    HcfPubKey *pubKeyOut = nullptr;
    ret = g_x509CertObj->base.getPublicKey(&(g_x509CertObj->base), &pubKeyOut);
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