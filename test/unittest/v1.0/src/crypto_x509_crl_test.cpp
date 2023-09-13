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

#include "securec.h"

#include <gtest/gtest.h>
#include <openssl/x509.h>

#include "asy_key_generator.h"
#include "cipher.h"
#include "key_pair.h"
#include "cf_memory.h"
#include "memory_mock.h"
#include "certificate_openssl_class.h"
#include "x509_crl.h"
#include "x509_crl_openssl.h"
#include "x509_crl_entry_openssl.h"

using namespace std;
using namespace testing::ext;

namespace {
HcfX509Crl *g_x509Crl = nullptr;
constexpr int TEST_SN = 1000;

class CryptoX509CrlTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

static char g_testErrorCert[] =
"-----BEGIN CERTIFICATE-----\r\n"
"MIIBLzCB1QIUO/QDVJwZLIpeJyPjyTvE43xvE5cwCgYIKoZIzj0EAwIwGjEYMBYG\r\n"
"A1UEAwwPRXhhbXBsZSBSb290IENBMB4XDTIzMDkwNDExMjAxOVoXDTI2MDUzMDEx\r\n"
"MjAxOVowGjEYMBYGA1UEAwwPRXhhbXBsZSBSb290IENBMFkwEwYHKoZIzj0CAQYI\r\n"
"KoZIzj0DAQcDQgAEHjG74yMIueO7z3T+dyuEIrhxTg2fqgeNB3SGfsIXlsiUfLTa\r\n"
"tUsU0i/sePnrKglj2H8Abbx9PK0tsW/VgqwDIDAKBggqhkjOPQQDAgNJADBGAiEA\r\n"
"0ce/fvA4tckNZeB865aOApKXKlBjiRlaiuq5mEEqvNACIQDPD9WyC21MXqPBuRUf\r\n"
"BetUokslUfjT6+s/X4ByaxycAA==\r\n"
"-----END CERTIFICATE-----";

static char g_testCert[] =
"-----BEGIN CERTIFICATE-----\r\n"
"MIIDTzCCAjegAwIBAgICA+gwDQYJKoZIhvcNAQELBQAwLDELMAkGA1UEBhMCQ04x\r\n"
"DTALBgNVBAoMBHRlc3QxDjAMBgNVBAMMBXN1YmNhMB4XDTIzMDkxMjA2NDc0OVoX\r\n"
"DTMzMDkwOTA2NDc0OVowLDELMAkGA1UEBhMCQ04xDTALBgNVBAoMBHRlc3QxDjAM\r\n"
"BgNVBAMMBWxvY2FsMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuEcw\r\n"
"tv/K2MnMB+AX2oL2KsTMjKteaQncpr6BPfe/LvSXQImnETvzSSIX2Iy19ZEbEDxn\r\n"
"osFXGvmrE8iT1P8lP+LYC8WIjzArbQeBvM6n8gq7QW2jAlfAmVy2/SBeBhRFT1Eq\r\n"
"rwqld6qqGa0WTnRTnax7v52FddvpG9XBAexE2gQ6UyScWikAKuDgnSQsivz6SMTQ\r\n"
"vbax3ffiy2p2RjxH9ZrQTxpUFDRHqMxJvq57wBDLkAtG4TlhQMDIB86cbOQfHHam\r\n"
"VHPVSvyZgmr3V4kb9UlDwB9bjrjSMlRsnNqocGEepZQ57IKgLf5SCWRec5Oww+OO\r\n"
"3WJOa7ja10sZ0LDdxwIDAQABo3sweTAJBgNVHRMEAjAAMCwGCWCGSAGG+EIBDQQf\r\n"
"Fh1PcGVuU1NMIEdlbmVyYXRlZCBDZXJ0aWZpY2F0ZTAdBgNVHQ4EFgQURsHdrG4w\r\n"
"i4GQKaFbmEpdNyNkvB4wHwYDVR0jBBgwFoAUIisY3oTZME72Pd/X9ALtRCKEIOgw\r\n"
"DQYJKoZIhvcNAQELBQADggEBAKVdgTE4Q8Nl5nQUQVL/uZMVCmDRcpXdJHq3cyAH\r\n"
"4BtbFW/K3MbVcZl2j1tPl6bgI5pn9Tk4kkc+SfxGUKAPR7FQ01zfgEJipSlsmAxS\r\n"
"wOZL+PGUbYUL1jzU8207PZOIZcyD67Sj8LeOV4BCNLiBIo++MjpD++x77GnP3veg\r\n"
"bDKHfDSVILdH/qnqyGSAGJ4YGJld00tehnTAqBWzmkXVIgWk0bnPTNE0dn5Tj7ZY\r\n"
"7zh6YU5JILHnrkjRGdNGmpz8SXJ+bh7u8ffHc4R9FO1q4c9/1YSsOXQj0KazyDIP\r\n"
"IArlydFj8wK8sHvYC9WhPs+hiirrRb9Y2ApFzcYX5aYn46Y=\r\n"
"-----END CERTIFICATE-----\r\n";

static char g_testCrl[] =
"-----BEGIN X509 CRL-----\r\n"
"MIIB4zCBzAIBATANBgkqhkiG9w0BAQsFADAsMQswCQYDVQQGEwJDTjENMAsGA1UE\r\n"
"CgwEdGVzdDEOMAwGA1UEAwwFc3ViY2EXDTIzMDkxMjA2NDc1MFoXDTIzMTAxMjA2\r\n"
"NDc1MFowOzATAgID6BcNMjMwOTEyMDY0NzQ5WjAkAhMXXWqf7KkJ1xKySFKmPkj2\r\n"
"EpOpFw0yMzA5MTIwNjQyNTRaoC8wLTAfBgNVHSMEGDAWgBQiKxjehNkwTvY939f0\r\n"
"Au1EIoQg6DAKBgNVHRQEAwIBAjANBgkqhkiG9w0BAQsFAAOCAQEAQKGCXs5aXY56\r\n"
"06A/0HynLmq+frJ7p5Uj9cD2vwbZV4xaP2E5jXogBz7YCjmxp0PB995XC9oi3QKQ\r\n"
"gLVKY4Nz21WQRecmmZm1cDweDDPwGJ8/I0d2CwMTJfP7rEgsuhgIBq+JUjFcNNaW\r\n"
"dia2Gu/aAuIjlaJ5A4W7vvhGVUx9CDUdN8YF5knA3BoQ1uFc1z7gNckkIpTTccQL\r\n"
"zoELFDG8/z+bOnAuSg1lZCyv9fOz9lVafC+qaHo+NW9rdChxV1oC5S6jHTu879CO\r\n"
"MQnLr3jEBCszNzDjFI64l6f3JVnLZepp6NU1gdunjQL4gtWQXZFlFV75xR8aahd8\r\n"
"seB5oDTPQg==\r\n"
"-----END X509 CRL-----\r\n";

static char g_testIssuerCert[] =
"-----BEGIN CERTIFICATE-----\r\n"
"MIIDKDCCAhCgAwIBAgICA+gwDQYJKoZIhvcNAQELBQAwLTELMAkGA1UEBhMCQ04x\r\n"
"DTALBgNVBAoMBHRlc3QxDzANBgNVBAMMBnJvb3RjYTAeFw0yMzA5MTIwNjQ3NDla\r\n"
"Fw0zMzA5MDkwNjQ3NDlaMCwxCzAJBgNVBAYTAkNOMQ0wCwYDVQQKDAR0ZXN0MQ4w\r\n"
"DAYDVQQDDAVzdWJjYTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALpr\r\n"
"uLwlJjJ9uowa0N6aEmIIdf6YxR5+q6yDYg4it2cLJmkU/0P1Lt2Yl/MiBvW0t3DW\r\n"
"I6cKFv8rZ+GdwRIfIrTmINJhKjPwvrUqXJctFEkxEgtux4/+C8n06vZJypy5p6Vy\r\n"
"LFWbLIM1FGkPuBtwjnIQdyUxo+R+oBSVXyvA5w9CX0Ak08jRvsBWc1Oh2Avcm6nF\r\n"
"0T+ac4Kf0NzVkkMjKoYwUdoPMppjpYGDX0jdRzJhdFUFjGMLR3YQJtlqLeUqVGnO\r\n"
"mws5K7picMM/Z7tO3tIT6BBPljGzsLheu2tM5yuXBRt4A6D7j9qW+ufNnL7Lklvu\r\n"
"X6TWn5BKoA/h7cIgc5UCAwEAAaNTMFEwHQYDVR0OBBYEFCIrGN6E2TBO9j3f1/QC\r\n"
"7UQihCDoMB8GA1UdIwQYMBaAFP+lNpyMpRzNOeVYvU7ecYdvfIhSMA8GA1UdEwEB\r\n"
"/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBALKHwCrQWu3fHRrCO2usfxNdI2S7\r\n"
"SkkYDKHiuf4P5VMypSwCewCrEDZwkzLcMlFZ+RMnz1a14viBUvqb3CMbR9Hg52EF\r\n"
"aFjOeZOGEuJF6hCVi0gJ9AddS8hGaUAzo82BlNCGsM8SGHCP5GsOSyKbvRrWc3jR\r\n"
"0qDOnHzAbesV6lw2g3MoeXCXIw/HBtv7k9SlJZyAREtmMAkYRm0X4tekqFq/6Mwk\r\n"
"g9WNnnzPNI1tBp1Nvv3JD3jVHLVXQUp9iOej7KX/OC0NETjn8sXLsjc0ZS1Ub2Nw\r\n"
"wWFdrSrSmjNbibrOHqQaoP/cpcqNP2EA5lFWSYVjJVkpv2YojGjLhjwqxP0=\r\n"
"-----END CERTIFICATE-----\r\n";

static uint8_t g_crlDerData[] = {
    0x30, 0x82, 0x01, 0xE3, 0x30, 0x81, 0xCC, 0x02, 0x01, 0x01, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86,
    0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00, 0x30, 0x2C, 0x31, 0x0B, 0x30, 0x09, 0x06,
    0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x43, 0x4E, 0x31, 0x0D, 0x30, 0x0B, 0x06, 0x03, 0x55, 0x04,
    0x0A, 0x0C, 0x04, 0x74, 0x65, 0x73, 0x74, 0x31, 0x0E, 0x30, 0x0C, 0x06, 0x03, 0x55, 0x04, 0x03,
    0x0C, 0x05, 0x73, 0x75, 0x62, 0x63, 0x61, 0x17, 0x0D, 0x32, 0x33, 0x30, 0x39, 0x31, 0x32, 0x30,
    0x36, 0x34, 0x37, 0x35, 0x30, 0x5A, 0x17, 0x0D, 0x32, 0x33, 0x31, 0x30, 0x31, 0x32, 0x30, 0x36,
    0x34, 0x37, 0x35, 0x30, 0x5A, 0x30, 0x3B, 0x30, 0x13, 0x02, 0x02, 0x03, 0xE8, 0x17, 0x0D, 0x32,
    0x33, 0x30, 0x39, 0x31, 0x32, 0x30, 0x36, 0x34, 0x37, 0x34, 0x39, 0x5A, 0x30, 0x24, 0x02, 0x13,
    0x17, 0x5D, 0x6A, 0x9F, 0xEC, 0xA9, 0x09, 0xD7, 0x12, 0xB2, 0x48, 0x52, 0xA6, 0x3E, 0x48, 0xF6,
    0x12, 0x93, 0xA9, 0x17, 0x0D, 0x32, 0x33, 0x30, 0x39, 0x31, 0x32, 0x30, 0x36, 0x34, 0x32, 0x35,
    0x34, 0x5A, 0xA0, 0x2F, 0x30, 0x2D, 0x30, 0x1F, 0x06, 0x03, 0x55, 0x1D, 0x23, 0x04, 0x18, 0x30,
    0x16, 0x80, 0x14, 0x22, 0x2B, 0x18, 0xDE, 0x84, 0xD9, 0x30, 0x4E, 0xF6, 0x3D, 0xDF, 0xD7, 0xF4,
    0x02, 0xED, 0x44, 0x22, 0x84, 0x20, 0xE8, 0x30, 0x0A, 0x06, 0x03, 0x55, 0x1D, 0x14, 0x04, 0x03,
    0x02, 0x01, 0x02, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B,
    0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x40, 0xA1, 0x82, 0x5E, 0xCE, 0x5A, 0x5D, 0x8E, 0x7A,
    0xD3, 0xA0, 0x3F, 0xD0, 0x7C, 0xA7, 0x2E, 0x6A, 0xBE, 0x7E, 0xB2, 0x7B, 0xA7, 0x95, 0x23, 0xF5,
    0xC0, 0xF6, 0xBF, 0x06, 0xD9, 0x57, 0x8C, 0x5A, 0x3F, 0x61, 0x39, 0x8D, 0x7A, 0x20, 0x07, 0x3E,
    0xD8, 0x0A, 0x39, 0xB1, 0xA7, 0x43, 0xC1, 0xF7, 0xDE, 0x57, 0x0B, 0xDA, 0x22, 0xDD, 0x02, 0x90,
    0x80, 0xB5, 0x4A, 0x63, 0x83, 0x73, 0xDB, 0x55, 0x90, 0x45, 0xE7, 0x26, 0x99, 0x99, 0xB5, 0x70,
    0x3C, 0x1E, 0x0C, 0x33, 0xF0, 0x18, 0x9F, 0x3F, 0x23, 0x47, 0x76, 0x0B, 0x03, 0x13, 0x25, 0xF3,
    0xFB, 0xAC, 0x48, 0x2C, 0xBA, 0x18, 0x08, 0x06, 0xAF, 0x89, 0x52, 0x31, 0x5C, 0x34, 0xD6, 0x96,
    0x76, 0x26, 0xB6, 0x1A, 0xEF, 0xDA, 0x02, 0xE2, 0x23, 0x95, 0xA2, 0x79, 0x03, 0x85, 0xBB, 0xBE,
    0xF8, 0x46, 0x55, 0x4C, 0x7D, 0x08, 0x35, 0x1D, 0x37, 0xC6, 0x05, 0xE6, 0x49, 0xC0, 0xDC, 0x1A,
    0x10, 0xD6, 0xE1, 0x5C, 0xD7, 0x3E, 0xE0, 0x35, 0xC9, 0x24, 0x22, 0x94, 0xD3, 0x71, 0xC4, 0x0B,
    0xCE, 0x81, 0x0B, 0x14, 0x31, 0xBC, 0xFF, 0x3F, 0x9B, 0x3A, 0x70, 0x2E, 0x4A, 0x0D, 0x65, 0x64,
    0x2C, 0xAF, 0xF5, 0xF3, 0xB3, 0xF6, 0x55, 0x5A, 0x7C, 0x2F, 0xAA, 0x68, 0x7A, 0x3E, 0x35, 0x6F,
    0x6B, 0x74, 0x28, 0x71, 0x57, 0x5A, 0x02, 0xE5, 0x2E, 0xA3, 0x1D, 0x3B, 0xBC, 0xEF, 0xD0, 0x8E,
    0x31, 0x09, 0xCB, 0xAF, 0x78, 0xC4, 0x04, 0x2B, 0x33, 0x37, 0x30, 0xE3, 0x14, 0x8E, 0xB8, 0x97,
    0xA7, 0xF7, 0x25, 0x59, 0xCB, 0x65, 0xEA, 0x69, 0xE8, 0xD5, 0x35, 0x81, 0xDB, 0xA7, 0x8D, 0x02,
    0xF8, 0x82, 0xD5, 0x90, 0x5D, 0x91, 0x65, 0x15, 0x5E, 0xF9, 0xC5, 0x1F, 0x1A, 0x6A, 0x17, 0x7C,
    0xB1, 0xE0, 0x79, 0xA0, 0x34, 0xCF, 0x42
};

const CfEncodingBlob g_crlDerInStream = {
    g_crlDerData,
    sizeof(g_crlDerData),
    CF_FORMAT_DER
};

const CfEncodingBlob g_inStreamCrl = {
    reinterpret_cast<uint8_t *>(g_testCrl),
    sizeof(g_testCrl),
    CF_FORMAT_PEM
};

const CfEncodingBlob g_inStreamCert = {
    reinterpret_cast<uint8_t *>(g_testCert),
    sizeof(g_testCert),
    CF_FORMAT_PEM
};

const CfEncodingBlob g_inStreamIssuerCert = {
    reinterpret_cast<uint8_t *>(g_testIssuerCert),
    sizeof(g_testIssuerCert),
    CF_FORMAT_PEM
};

void CryptoX509CrlTest::SetUpTestCase()
{
    HcfX509Crl *x509Crl = nullptr;
    int32_t ret = HcfX509CrlCreate(&g_crlDerInStream, &x509Crl);
    ASSERT_EQ(ret, 0);
    ASSERT_NE(x509Crl, nullptr);
    g_x509Crl = x509Crl;
}

void CryptoX509CrlTest::TearDownTestCase()
{
    if (g_x509Crl != nullptr) {
        CfObjDestroy(g_x509Crl);
        g_x509Crl = nullptr;
    }
}
void CryptoX509CrlTest::SetUp() {}
void CryptoX509CrlTest::TearDown() {}

// Begin test crl create, test crl create PEM true
HWTEST_F(CryptoX509CrlTest, X509CrlTest001, TestSize.Level0)
{
    HcfX509Crl *x509Crl = nullptr;
    CfResult ret = HcfX509CrlCreate(&g_inStreamCrl, &x509Crl);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509Crl, nullptr);
    CfObjDestroy(x509Crl);
}

// Test crl create DER true
HWTEST_F(CryptoX509CrlTest, X509CrlTest002, TestSize.Level0)
{
    HcfX509Crl *x509Crl = nullptr;
    CfResult ret = HcfX509CrlCreate(&g_crlDerInStream, &x509Crl);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509Crl, nullptr);
    CfObjDestroy(x509Crl);
}

// Test crl create error | encodingFormat
HWTEST_F(CryptoX509CrlTest, X509CrlTest003, TestSize.Level0)
{
    HcfX509Crl *x509Crl = nullptr;
    CfEncodingBlob inStreamCrl = { nullptr, 0, CF_FORMAT_PEM };
    inStreamCrl.data = reinterpret_cast<uint8_t *>(g_testCrl);
    inStreamCrl.encodingFormat = CF_FORMAT_DER;
    inStreamCrl.len = strlen(g_testCrl) + 1;
    CfResult ret = HcfX509CrlCreate(&inStreamCrl, &x509Crl);
    EXPECT_NE(ret, CF_SUCCESS);
    EXPECT_EQ(x509Crl, nullptr);
}

// Test crl create error | Crl data
HWTEST_F(CryptoX509CrlTest, X509CrlTest004, TestSize.Level0)
{
    HcfX509Crl *x509Crl = nullptr;
    CfEncodingBlob inStreamCrl = { nullptr, 0, CF_FORMAT_PEM };
    inStreamCrl.data = nullptr;
    inStreamCrl.encodingFormat = CF_FORMAT_PEM;
    inStreamCrl.len = strlen(g_testCrl) + 1;
    CfResult ret = HcfX509CrlCreate(&inStreamCrl, &x509Crl);
    EXPECT_NE(ret, CF_SUCCESS);
    EXPECT_EQ(x509Crl, nullptr);
}

// Test crl create error | Crl len
HWTEST_F(CryptoX509CrlTest, X509CrlTest005, TestSize.Level0)
{
    HcfX509Crl *x509Crl = nullptr;
    CfEncodingBlob inStreamCrl = { nullptr, 0, CF_FORMAT_PEM };
    inStreamCrl.data = reinterpret_cast<uint8_t *>(g_testCrl);
    inStreamCrl.encodingFormat = CF_FORMAT_PEM;
    inStreamCrl.len = 0;
    CfResult ret = HcfX509CrlCreate(&inStreamCrl, &x509Crl);
    EXPECT_NE(ret, CF_SUCCESS);
    EXPECT_EQ(x509Crl, nullptr);
}

// Test crl create error | Crl nullptr
HWTEST_F(CryptoX509CrlTest, X509CrlTest006, TestSize.Level0)
{
    HcfX509Crl *x509Crl = nullptr;
    CfEncodingBlob *inStreamCrl = nullptr;
    CfResult ret = HcfX509CrlCreate(inStreamCrl, &x509Crl);
    EXPECT_NE(ret, CF_SUCCESS);
    EXPECT_EQ(x509Crl, nullptr);
}

// Begin test crl isRevoked, test crl isRevoked true
HWTEST_F(CryptoX509CrlTest, X509CrlTest011, TestSize.Level0)
{
    // Get cert
    HcfX509Certificate *x509Cert = nullptr;
    CfResult ret = HcfX509CertificateCreate(&g_inStreamCert, &x509Cert);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509Cert, nullptr);

    // Get crl
    HcfX509Crl *x509Crl = nullptr;
    ret = HcfX509CrlCreate(&g_inStreamCrl, &x509Crl);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509Crl, nullptr);

    bool resIsRevoked =
        x509Crl->base.isRevoked(reinterpret_cast<HcfCrl *>(x509Crl), reinterpret_cast<HcfCertificate *>(x509Cert));
    EXPECT_EQ(resIsRevoked, true);
    CfObjDestroy(x509Crl);
    CfObjDestroy(x509Cert);
}

// Test crl isRevoked error | crl null
HWTEST_F(CryptoX509CrlTest, X509CrlTest012, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    // Get cert
    HcfX509Certificate *x509Cert = nullptr;
    CfResult ret = HcfX509CertificateCreate(&g_inStreamCert, &x509Cert);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509Cert, nullptr);

    bool resIsRevoked = g_x509Crl->base.isRevoked(nullptr, reinterpret_cast<HcfCertificate *>(x509Cert));
    EXPECT_EQ(resIsRevoked, false);
    CfObjDestroy(x509Cert);
}

// Test crl isRevoked error | x509Cert null
HWTEST_F(CryptoX509CrlTest, X509CrlTest013, TestSize.Level0)
{
    // Get crl
    HcfX509Crl *x509Crl = nullptr;
    CfResult ret = HcfX509CrlCreate(&g_inStreamCrl, &x509Crl);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509Crl, nullptr);

    bool resIsRevoked = x509Crl->base.isRevoked(reinterpret_cast<HcfCrl *>(x509Crl), nullptr);
    EXPECT_EQ(resIsRevoked, false);
    CfObjDestroy(x509Crl);
}

// Test crl isRevoked - der
HWTEST_F(CryptoX509CrlTest, X509CrlTest014, TestSize.Level0)
{
    // Get cert
    HcfX509Certificate *x509Cert = nullptr;
    CfResult ret = HcfX509CertificateCreate(&g_inStreamCert, &x509Cert);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509Cert, nullptr);

    // Get crl
    HcfX509Crl *x509Crl = nullptr;
    ret = HcfX509CrlCreate(&g_crlDerInStream, &x509Crl);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509Crl, nullptr);

    bool resIsRevoked =
        x509Crl->base.isRevoked(reinterpret_cast<HcfCrl *>(x509Crl), reinterpret_cast<HcfCertificate *>(x509Cert));
    EXPECT_EQ(resIsRevoked, true);
    CfObjDestroy(x509Cert);
    CfObjDestroy(x509Crl);
}

// Test crl isRevoked error | x509Crl error
HWTEST_F(CryptoX509CrlTest, X509CrlTest015, TestSize.Level0)
{
    // Get cert
    HcfX509Certificate *x509Cert = nullptr;
    CfEncodingBlob inStreamCert = { nullptr, 0, CF_FORMAT_PEM };
    inStreamCert.data = reinterpret_cast<uint8_t *>(g_testErrorCert);
    inStreamCert.encodingFormat = CF_FORMAT_PEM;
    inStreamCert.len = strlen(g_testErrorCert) + 1;
    CfResult ret = HcfX509CertificateCreate(&inStreamCert, &x509Cert);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509Cert, nullptr);

    // Get crl
    HcfX509Crl *x509Crl = nullptr;
    ret = HcfX509CrlCreate(&g_inStreamCrl, &x509Crl);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509Crl, nullptr);

    bool resIsRevoked =
        x509Crl->base.isRevoked(reinterpret_cast<HcfCrl *>(x509Crl), reinterpret_cast<HcfCertificate *>(x509Cert));
    EXPECT_EQ(resIsRevoked, false);
    CfObjDestroy(x509Cert);
    CfObjDestroy(x509Crl);
}

// Test crl GetType true
HWTEST_F(CryptoX509CrlTest, X509CrlTest021, TestSize.Level0)
{
    // Get crl
    HcfX509Crl *x509Crl = nullptr;
    CfResult ret = HcfX509CrlCreate(&g_inStreamCrl, &x509Crl);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509Crl, nullptr);

    const char *resStr = x509Crl->base.getType(reinterpret_cast<HcfCrl *>(x509Crl));
    EXPECT_STREQ(resStr, "X509");
    CfObjDestroy(x509Crl);
}

// Test crl GetType error
HWTEST_F(CryptoX509CrlTest, X509CrlTest022, TestSize.Level0)
{
    // Get crl
    HcfX509Crl *x509Crl = nullptr;
    CfResult ret = HcfX509CrlCreate(&g_inStreamCrl, &x509Crl);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509Crl, nullptr);

    const char *resStr = x509Crl->base.getType(nullptr);
    EXPECT_EQ(resStr, nullptr);
    CfObjDestroy(x509Crl);
}

// Test crl getEncoded DER true
HWTEST_F(CryptoX509CrlTest, X509CrlTest031, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfEncodingBlob inStreamInput = { nullptr, 0, CF_FORMAT_PEM };
    CfResult ret = g_x509Crl->getEncoded(g_x509Crl, &inStreamInput);
    EXPECT_EQ(ret, CF_SUCCESS);

    HcfX509Crl *crl2 = nullptr;
    ret = HcfX509CrlCreate(&inStreamInput, &crl2);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(crl2, nullptr);
    CfObjDestroy(crl2);
    CfFree(inStreamInput.data);
}

// Test crl getEncoded PEM true
HWTEST_F(CryptoX509CrlTest, X509CrlTest032, TestSize.Level0)
{
    // Get crl
    HcfX509Crl *x509Crl = nullptr;
    CfResult ret = HcfX509CrlCreate(&g_inStreamCrl, &x509Crl);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509Crl, nullptr);

    CfEncodingBlob inStreamInput = { nullptr, 0, CF_FORMAT_PEM };
    ret = x509Crl->getEncoded(x509Crl, &inStreamInput);
    EXPECT_EQ(ret, CF_SUCCESS);

    HcfX509Crl *crl2 = nullptr;
    ret = HcfX509CrlCreate(&inStreamInput, &crl2);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(crl2, nullptr);
    CfFree(inStreamInput.data);
    CfObjDestroy(crl2);
    CfObjDestroy(x509Crl);
}

// Test crl getEncoded error
HWTEST_F(CryptoX509CrlTest, X509CrlTest033, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfResult ret = g_x509Crl->getEncoded(g_x509Crl, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
}

// Test crl getEncoded error
HWTEST_F(CryptoX509CrlTest, X509CrlTest034, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfEncodingBlob inStreamInput = { nullptr, 0, CF_FORMAT_PEM };
    CfResult ret = g_x509Crl->getEncoded(nullptr, &inStreamInput);
    EXPECT_NE(ret, CF_SUCCESS);
}

// Test crl getEncoded error
HWTEST_F(CryptoX509CrlTest, X509CrlTest035, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfResult ret = g_x509Crl->getEncoded(nullptr, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
}

// Test crl verify true
HWTEST_F(CryptoX509CrlTest, X509CrlTest041, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    HcfX509Certificate *x509CertObj = nullptr;
    CfResult ret = HcfX509CertificateCreate(&g_inStreamIssuerCert, &x509CertObj);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(x509CertObj, nullptr);

    HcfPubKey *keyOut = nullptr;
    ret = x509CertObj->base.getPublicKey((HcfCertificate *)x509CertObj, &keyOut);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(keyOut, nullptr);

    HcfBlob blob = { nullptr, 0 };
    HcfResult hcfRet = keyOut->base.getEncoded(&(keyOut->base), &blob);
    ASSERT_EQ(hcfRet, HCF_SUCCESS);

    HcfAsyKeyGenerator *generator = nullptr;
    hcfRet = HcfAsyKeyGeneratorCreate("RSA2048", &generator);
    ASSERT_EQ(hcfRet, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    hcfRet = generator->convertKey(generator, nullptr, &blob, nullptr, &dupKeyPair);
    ASSERT_EQ(hcfRet, HCF_SUCCESS);
    HcfPubKey *hcfPubkey = dupKeyPair->pubKey;

    ret = g_x509Crl->verify(g_x509Crl, hcfPubkey);
    EXPECT_EQ(ret, CF_SUCCESS);

    free(blob.data);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(keyOut);
    CfObjDestroy(x509CertObj);
}

// Test crl verify false
HWTEST_F(CryptoX509CrlTest, X509CrlTest042, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_3", &generator);
    ASSERT_EQ(ret, 0);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    ret = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(ret, 0);
    ASSERT_NE(keyPair, nullptr);

    CfResult ret1 = g_x509Crl->verify(g_x509Crl, keyPair->pubKey);
    EXPECT_NE(ret1, CF_SUCCESS);
    CfObjDestroy(keyPair);
    CfObjDestroy(generator);
}

// Test crl verify false
HWTEST_F(CryptoX509CrlTest, X509CrlTest043, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorCreate("RSA512|PRIMES_2", &generator);
    ASSERT_EQ(ret, 0);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    ret = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(ret, 0);
    ASSERT_NE(keyPair, nullptr);

    CfResult ret1 = g_x509Crl->verify(nullptr, keyPair->pubKey);
    EXPECT_NE(ret1, CF_SUCCESS);
}

// Test crl verify false
HWTEST_F(CryptoX509CrlTest, X509CrlTest044, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfResult ret = g_x509Crl->verify(g_x509Crl, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
}

// Test crl verify false
HWTEST_F(CryptoX509CrlTest, X509CrlTest045, TestSize.Level0)
{
    // Get crl
    HcfX509Crl *x509Crl = nullptr;
    CfResult ret = HcfX509CrlCreate(&g_inStreamCrl, &x509Crl);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509Crl, nullptr);

    ret = x509Crl->verify(x509Crl, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
    CfObjDestroy(x509Crl);
}

// Test crl getVersion true
HWTEST_F(CryptoX509CrlTest, X509CrlTest051, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    long version = g_x509Crl->getVersion(g_x509Crl);
    EXPECT_EQ(version, 2);
}

// Test crl getVersion false
HWTEST_F(CryptoX509CrlTest, X509CrlTest052, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    long version = g_x509Crl->getVersion(nullptr);
    EXPECT_EQ(version, -1);
}

// Test crl getIssuerName true
HWTEST_F(CryptoX509CrlTest, X509CrlTest061, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfBlob out = { 0, nullptr };
    CfResult ret = g_x509Crl->getIssuerName(g_x509Crl, &out);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(out.data, nullptr);
    EXPECT_STREQ("/C=CN/O=test/CN=subca", reinterpret_cast<char *>(out.data));
    CfFree(out.data);
}

// Test crl getIssuerName false
HWTEST_F(CryptoX509CrlTest, X509CrlTest062, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfBlob out = { 0, nullptr };
    CfResult ret = g_x509Crl->getIssuerName(nullptr, &out);
    EXPECT_NE(ret, CF_SUCCESS);
    EXPECT_EQ(out.data, nullptr);
}

// Test crl getIssuerName false
HWTEST_F(CryptoX509CrlTest, X509CrlTest063, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfResult ret = g_x509Crl->getIssuerName(g_x509Crl, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
}

// Test crl getIssuerName false
HWTEST_F(CryptoX509CrlTest, X509CrlTest064, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfResult ret = g_x509Crl->getIssuerName(nullptr, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
}

// Test crl getLastUpdate true
HWTEST_F(CryptoX509CrlTest, X509CrlTest071, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfBlob out = { 0, nullptr };
    CfResult ret = g_x509Crl->getLastUpdate(g_x509Crl, &out);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(out.data, nullptr);
    EXPECT_STREQ("230912064750Z", reinterpret_cast<char *>(out.data));
    CfFree(out.data);
}

// Test crl getLastUpdate false
HWTEST_F(CryptoX509CrlTest, X509CrlTest072, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfBlob out = { 0, nullptr };
    CfResult ret = g_x509Crl->getLastUpdate(nullptr, &out);
    EXPECT_NE(ret, CF_SUCCESS);
    EXPECT_EQ(out.data, nullptr);
}

// Test crl getLastUpdate false
HWTEST_F(CryptoX509CrlTest, X509CrlTest073, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfResult ret = g_x509Crl->getLastUpdate(g_x509Crl, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
}

// Test crl getLastUpdate false
HWTEST_F(CryptoX509CrlTest, X509CrlTest074, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfResult ret = g_x509Crl->getLastUpdate(nullptr, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
}

// Test crl getNextUpdate true
HWTEST_F(CryptoX509CrlTest, X509CrlTest081, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfBlob out = { 0, nullptr };
    CfResult ret = g_x509Crl->getNextUpdate(g_x509Crl, &out);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(out.data, nullptr);
    EXPECT_STREQ("231012064750Z", reinterpret_cast<char *>(out.data));
    CfFree(out.data);
}

// Test crl getNextUpdate false
HWTEST_F(CryptoX509CrlTest, X509CrlTest082, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfBlob out = { 0, nullptr };
    CfResult ret = g_x509Crl->getNextUpdate(nullptr, &out);
    EXPECT_NE(ret, CF_SUCCESS);
    EXPECT_EQ(out.data, nullptr);
}

// Test crl getNextUpdate false
HWTEST_F(CryptoX509CrlTest, X509CrlTest083, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfResult ret = g_x509Crl->getNextUpdate(g_x509Crl, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
}

// Test crl getNextUpdate false
HWTEST_F(CryptoX509CrlTest, X509CrlTest084, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfResult ret = g_x509Crl->getNextUpdate(nullptr, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
}

// Test crl getRevokedCert true
HWTEST_F(CryptoX509CrlTest, X509CrlTest091, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    HcfX509CrlEntry *crlEntry = nullptr;
    CfResult ret = g_x509Crl->getRevokedCert(g_x509Crl, TEST_SN, &crlEntry);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(crlEntry, nullptr);
    CfObjDestroy(crlEntry);
}

// Test crl getRevokedCert false
HWTEST_F(CryptoX509CrlTest, X509CrlTest092, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    HcfX509CrlEntry *crlEntry = nullptr;
    CfResult ret = g_x509Crl->getRevokedCert(g_x509Crl, 9999, &crlEntry);
    EXPECT_NE(ret, CF_SUCCESS);
}

// Test crl getRevokedCert false
HWTEST_F(CryptoX509CrlTest, X509CrlTest093, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfResult ret = g_x509Crl->getRevokedCert(g_x509Crl, TEST_SN, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
}

// Test crl getRevokedCert false
HWTEST_F(CryptoX509CrlTest, X509CrlTest094, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    HcfX509CrlEntry *crlEntry = nullptr;
    CfResult ret = g_x509Crl->getRevokedCert(nullptr, TEST_SN, &crlEntry);
    EXPECT_NE(ret, CF_SUCCESS);
}

// Test crl getRevokedCert false
HWTEST_F(CryptoX509CrlTest, X509CrlTest095, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfResult ret = g_x509Crl->getRevokedCert(nullptr, TEST_SN, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
}

// Test crl entry getSerialNumber true
HWTEST_F(CryptoX509CrlTest, X509CrlTest101, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    HcfX509CrlEntry *crlEntry = nullptr;
    CfResult ret = g_x509Crl->getRevokedCert(g_x509Crl, TEST_SN, &crlEntry);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(crlEntry, nullptr);
    CfBlob out = { 0, nullptr };
    ret = crlEntry->getSerialNumber(crlEntry, &out);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(out.size, 2); /* out size: 2 bytes */
    EXPECT_EQ(out.data[0] * 0x100 + out.data[1], TEST_SN);
    CfFree(out.data);
    CfObjDestroy(crlEntry);
}

// Test crl entry getSerialNumber false
HWTEST_F(CryptoX509CrlTest, X509CrlTest102, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    HcfX509CrlEntry *crlEntry = nullptr;
    CfResult ret = g_x509Crl->getRevokedCert(g_x509Crl, TEST_SN, &crlEntry);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(crlEntry, nullptr);
    ret = crlEntry->getSerialNumber(nullptr, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
    CfObjDestroy(crlEntry);
}

// Test crl entry getSerialNumber false
HWTEST_F(CryptoX509CrlTest, X509CrlTest103, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    HcfX509CrlEntry *crlEntry = nullptr;
    CfResult ret = g_x509Crl->getRevokedCert(g_x509Crl, TEST_SN, &crlEntry);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(crlEntry, nullptr);
    ret = crlEntry->getSerialNumber(nullptr, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
    CfObjDestroy(crlEntry);
}

// Test crl entry getEncoded true
HWTEST_F(CryptoX509CrlTest, X509CrlTest111, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    HcfX509CrlEntry *crlEntry = nullptr;
    CfResult ret = g_x509Crl->getRevokedCert(g_x509Crl, TEST_SN, &crlEntry);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(crlEntry, nullptr);

    CfEncodingBlob encodingBlob = { nullptr, 0, CF_FORMAT_PEM };
    ret = crlEntry->getEncoded(crlEntry, &encodingBlob);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(encodingBlob.data, nullptr);
    CfObjDestroy(crlEntry);
    CfFree(encodingBlob.data);
}

// Test crl entry getEncoded false
HWTEST_F(CryptoX509CrlTest, X509CrlTest112, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    HcfX509CrlEntry *crlEntry = nullptr;
    CfResult ret = g_x509Crl->getRevokedCert(g_x509Crl, TEST_SN, &crlEntry);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(crlEntry, nullptr);

    CfEncodingBlob encodingBlob = { nullptr, 0, CF_FORMAT_PEM };
    ret = crlEntry->getEncoded(nullptr, &encodingBlob);
    EXPECT_NE(ret, CF_SUCCESS);
    EXPECT_EQ(encodingBlob.data, nullptr);
    CfObjDestroy(crlEntry);
}

// Test crl entry getEncoded false
HWTEST_F(CryptoX509CrlTest, X509CrlTest113, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    HcfX509CrlEntry *crlEntry = nullptr;
    CfResult ret = g_x509Crl->getRevokedCert(g_x509Crl, TEST_SN, &crlEntry);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(crlEntry, nullptr);

    ret = crlEntry->getEncoded(crlEntry, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
    CfObjDestroy(crlEntry);
}

// Test crl entry getEncoded false
HWTEST_F(CryptoX509CrlTest, X509CrlTest114, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    HcfX509CrlEntry *crlEntry = nullptr;
    CfResult ret = g_x509Crl->getRevokedCert(g_x509Crl, TEST_SN, &crlEntry);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(crlEntry, nullptr);

    ret = crlEntry->getEncoded(nullptr, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
    CfObjDestroy(crlEntry);
}

// Test crl entry getCertIssuer true
HWTEST_F(CryptoX509CrlTest, X509CrlTest121, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    HcfX509CrlEntry *crlEntry = nullptr;
    CfResult ret = g_x509Crl->getRevokedCert(g_x509Crl, TEST_SN, &crlEntry);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(crlEntry, nullptr);

    CfBlob out = { 0, nullptr };
    ret = crlEntry->getCertIssuer(crlEntry, &out);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(out.data, nullptr);
    EXPECT_STREQ("/C=CN/O=test/CN=subca", reinterpret_cast<char *>(out.data));
    CfObjDestroy(crlEntry);
    CfFree(out.data);
}

// Test crl entry getCertIssuer false
HWTEST_F(CryptoX509CrlTest, X509CrlTest122, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    HcfX509CrlEntry *crlEntry = nullptr;
    CfResult ret = g_x509Crl->getRevokedCert(g_x509Crl, TEST_SN, &crlEntry);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(crlEntry, nullptr);

    CfBlob out = { 0, nullptr };
    ret = crlEntry->getCertIssuer(nullptr, &out);
    EXPECT_NE(ret, CF_SUCCESS);
    EXPECT_EQ(out.data, nullptr);
    CfObjDestroy(crlEntry);
}

// Test crl entry getCertIssuer false
HWTEST_F(CryptoX509CrlTest, X509CrlTest123, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    HcfX509CrlEntry *crlEntry = nullptr;
    CfResult ret = g_x509Crl->getRevokedCert(g_x509Crl, TEST_SN, &crlEntry);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(crlEntry, nullptr);

    ret = crlEntry->getCertIssuer(crlEntry, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
    CfObjDestroy(crlEntry);
}

// Test crl entry getRevocationDate true
HWTEST_F(CryptoX509CrlTest, X509CrlTest131, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    HcfX509CrlEntry *crlEntry = nullptr;
    CfResult ret = g_x509Crl->getRevokedCert(g_x509Crl, TEST_SN, &crlEntry);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(crlEntry, nullptr);

    CfBlob out = { 0, nullptr };
    ret = crlEntry->getRevocationDate(crlEntry, &out);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(out.data, nullptr);
    EXPECT_STREQ("230912064749Z", reinterpret_cast<char *>(out.data));
    CfObjDestroy(crlEntry);
    CfFree(out.data);
}

// Test crl entry getRevocationDate false
HWTEST_F(CryptoX509CrlTest, X509CrlTest132, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    HcfX509CrlEntry *crlEntry = nullptr;
    CfResult ret = g_x509Crl->getRevokedCert(g_x509Crl, TEST_SN, &crlEntry);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(crlEntry, nullptr);

    CfBlob out = { 0, nullptr };
    ret = crlEntry->getRevocationDate(nullptr, &out);
    EXPECT_NE(ret, CF_SUCCESS);
    EXPECT_EQ(out.data, nullptr);
    CfObjDestroy(crlEntry);
}

// Test crl entry getRevocationDate false
HWTEST_F(CryptoX509CrlTest, X509CrlTest133, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    HcfX509CrlEntry *crlEntry = nullptr;
    CfResult ret = g_x509Crl->getRevokedCert(g_x509Crl, TEST_SN, &crlEntry);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(crlEntry, nullptr);

    ret = crlEntry->getRevocationDate(crlEntry, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
    CfObjDestroy(crlEntry);
}

// Test crl getRevokedCertWithCert true
HWTEST_F(CryptoX509CrlTest, X509CrlTest141, TestSize.Level0)
{
    // Get cert
    HcfX509Certificate *x509Cert = nullptr;
    CfResult ret = HcfX509CertificateCreate(&g_inStreamCert, &x509Cert);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509Cert, nullptr);

    // Get crl
    HcfX509Crl *x509Crl = nullptr;
    ret = HcfX509CrlCreate(&g_inStreamCrl, &x509Crl);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509Crl, nullptr);

    HcfX509CrlEntry *crlEntry = nullptr;
    ret = x509Crl->getRevokedCertWithCert(x509Crl, x509Cert, &crlEntry);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(crlEntry, nullptr);

    CfBlob out = { 0, nullptr };
    ret = crlEntry->getRevocationDate(crlEntry, &out);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(out.data, nullptr);
    EXPECT_STREQ("230912064749Z", (char *)out.data);

    CfObjDestroy(x509Cert);
    CfObjDestroy(x509Crl);
    CfObjDestroy(crlEntry);
    CfFree(out.data);
}

// Test crl getRevokedCertWithCert true
HWTEST_F(CryptoX509CrlTest, X509CrlTest142, TestSize.Level0)
{
    // Get cert
    HcfX509Certificate *x509CertT142 = nullptr;
    CfResult ret = HcfX509CertificateCreate(&g_inStreamCert, &x509CertT142);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509CertT142, nullptr);

    // Get crl
    HcfX509Crl *x509Crl = nullptr;
    ret = HcfX509CrlCreate(&g_inStreamCrl, &x509Crl);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509Crl, nullptr);

    HcfX509CrlEntry *crlEntry = nullptr;
    ret = x509Crl->getRevokedCertWithCert(x509Crl, x509CertT142, &crlEntry);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(crlEntry, nullptr);

    CfBlob out = { 0, nullptr };
    ret = crlEntry->getCertIssuer(crlEntry, &out);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(out.data, nullptr);
    EXPECT_STREQ("/C=CN/O=test/CN=subca", (char *)out.data);

    CfObjDestroy(x509CertT142);
    CfObjDestroy(x509Crl);
    CfObjDestroy(crlEntry);
    CfFree(out.data);
}

// Test crl getRevokedCertWithCert true
HWTEST_F(CryptoX509CrlTest, X509CrlTest143, TestSize.Level0)
{
    // Get cert
    HcfX509Certificate *x509CertT143 = nullptr;
    CfResult ret = HcfX509CertificateCreate(&g_inStreamCert, &x509CertT143);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509CertT143, nullptr);

    // Get crl
    HcfX509Crl *x509Crl = nullptr;
    ret = HcfX509CrlCreate(&g_inStreamCrl, &x509Crl);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509Crl, nullptr);

    HcfX509CrlEntry *crlEntry = nullptr;
    ret = x509Crl->getRevokedCertWithCert(x509Crl, x509CertT143, &crlEntry);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(crlEntry, nullptr);

    CfEncodingBlob encodingBlob = { nullptr, 0, CF_FORMAT_PEM };
    ret = crlEntry->getEncoded(crlEntry, &encodingBlob);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(encodingBlob.data, nullptr);

    CfFree(encodingBlob.data);
    CfObjDestroy(x509CertT143);
    CfObjDestroy(x509Crl);
    CfObjDestroy(crlEntry);
}

// Test crl getRevokedCertWithCert false
HWTEST_F(CryptoX509CrlTest, X509CrlTest144, TestSize.Level0)
{
    // Get crl
    HcfX509Crl *x509Crl = nullptr;
    CfResult ret = HcfX509CrlCreate(&g_inStreamCrl, &x509Crl);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509Crl, nullptr);

    HcfX509CrlEntry *crlEntry = nullptr;
    ret = x509Crl->getRevokedCertWithCert(x509Crl, nullptr, &crlEntry);
    EXPECT_NE(ret, CF_SUCCESS);
    EXPECT_EQ(crlEntry, nullptr);

    CfObjDestroy(x509Crl);
}

// Test crl getRevokedCertWithCert false
HWTEST_F(CryptoX509CrlTest, X509CrlTest145, TestSize.Level0)
{
    // Get cert
    HcfX509Certificate *x509Cert = nullptr;
    CfResult ret = HcfX509CertificateCreate(&g_inStreamCert, &x509Cert);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509Cert, nullptr);

    // Get crl
    HcfX509Crl *x509Crl = nullptr;
    ret = HcfX509CrlCreate(&g_inStreamCrl, &x509Crl);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509Crl, nullptr);

    HcfX509CrlEntry *crlEntry = nullptr;
    ret = x509Crl->getRevokedCertWithCert(nullptr, x509Cert, &crlEntry);
    EXPECT_NE(ret, CF_SUCCESS);
    EXPECT_EQ(crlEntry, nullptr);

    CfObjDestroy(x509Cert);
    CfObjDestroy(x509Crl);
}

// Test crl getRevokedCertWithCert false
HWTEST_F(CryptoX509CrlTest, X509CrlTest146, TestSize.Level0)
{
    // Get cert
    HcfX509Certificate *x509CertT146 = nullptr;
    CfResult ret = HcfX509CertificateCreate(&g_inStreamCert, &x509CertT146);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509CertT146, nullptr);

    // Get crl
    HcfX509Crl *x509Crl = nullptr;
    ret = HcfX509CrlCreate(&g_inStreamCrl, &x509Crl);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509Crl, nullptr);

    ret = x509Crl->getRevokedCertWithCert(x509Crl, x509CertT146, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);

    CfObjDestroy(x509CertT146);
    CfObjDestroy(x509Crl);
}

// Test crl getRevokedCertWithCert false
HWTEST_F(CryptoX509CrlTest, X509CrlTest147, TestSize.Level0)
{
    // Get cert
    HcfX509Certificate *x509CertT147 = nullptr;
    CfResult ret = HcfX509CertificateCreate(&g_inStreamCert, &x509CertT147);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509CertT147, nullptr);

    // Get crl
    HcfX509Crl *x509Crl = nullptr;
    ret = HcfX509CrlCreate(&g_inStreamCrl, &x509Crl);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509Crl, nullptr);

    HcfX509CrlEntry *crlEntry = nullptr;
    ret = x509Crl->getRevokedCertWithCert(x509Crl, x509CertT147, &crlEntry);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(crlEntry, nullptr);

    CfBlob out = { 0, nullptr };
    ret = crlEntry->getRevocationDate(nullptr, &out);
    EXPECT_NE(ret, CF_SUCCESS);
    EXPECT_EQ(out.data, nullptr);

    CfObjDestroy(x509CertT147);
    CfObjDestroy(x509Crl);
    CfObjDestroy(crlEntry);
}

// Test crl entry getRevokedCerts true
HWTEST_F(CryptoX509CrlTest, X509CrlTest151, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfArray entrysOut = { nullptr, CF_FORMAT_PEM, 0 };
    CfResult ret = g_x509Crl->getRevokedCerts(g_x509Crl, &entrysOut);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(entrysOut.data, nullptr);

    HcfX509CrlEntry *crlEntry = reinterpret_cast<HcfX509CrlEntry *>(entrysOut.data[0].data);
    CfBlob out = { 0, nullptr };
    ret = crlEntry->getRevocationDate(crlEntry, &out);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(out.data, nullptr);
    EXPECT_STREQ("230912064749Z", reinterpret_cast<char *>(out.data));

    CfFree(out.data);
    CfObjDestroy(crlEntry);
}

// Test crl entry getRevokedCerts false
HWTEST_F(CryptoX509CrlTest, X509CrlTest152, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfResult ret = g_x509Crl->getRevokedCerts(g_x509Crl, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
}

// Test crl entry getRevokedCerts false
HWTEST_F(CryptoX509CrlTest, X509CrlTest153, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfArray entrysOut = { nullptr, CF_FORMAT_PEM, 0 };
    CfResult ret = g_x509Crl->getRevokedCerts(nullptr, &entrysOut);
    EXPECT_NE(ret, CF_SUCCESS);
    EXPECT_EQ(entrysOut.data, nullptr);
}

// Test crl entry getRevokedCerts false
HWTEST_F(CryptoX509CrlTest, X509CrlTest154, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfResult ret = g_x509Crl->getRevokedCerts(nullptr, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
}

// Test crl getTbsInfo true
HWTEST_F(CryptoX509CrlTest, X509CrlTest161, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfBlob tbsCertListOut = { 0, nullptr };
    CfResult ret = g_x509Crl->getTbsInfo(g_x509Crl, &tbsCertListOut);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(tbsCertListOut.data, nullptr);
    CfFree(tbsCertListOut.data);
}

// Test crl getTbsInfo false
HWTEST_F(CryptoX509CrlTest, X509CrlTest162, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfBlob tbsCertListOut = { 0, nullptr };
    CfResult ret = g_x509Crl->getTbsInfo(nullptr, &tbsCertListOut);
    EXPECT_NE(ret, CF_SUCCESS);
    EXPECT_EQ(tbsCertListOut.data, nullptr);
}

// Test crl  getTbsInfo false
HWTEST_F(CryptoX509CrlTest, X509CrlTest163, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfResult ret = g_x509Crl->getTbsInfo(g_x509Crl, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
}

// Test crl getTbsInfo false
HWTEST_F(CryptoX509CrlTest, X509CrlTest164, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfResult ret = g_x509Crl->getTbsInfo(nullptr, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
}

// Test crl getSignature true
HWTEST_F(CryptoX509CrlTest, X509CrlTest171, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfBlob signature = { 0, nullptr };
    CfResult ret = g_x509Crl->getSignature(g_x509Crl, &signature);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(signature.data, nullptr);
    CfFree(signature.data);
}

// Test crl getSignature false
HWTEST_F(CryptoX509CrlTest, X509CrlTest172, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfBlob signature = { 0, nullptr };
    CfResult ret = g_x509Crl->getSignature(nullptr, &signature);
    EXPECT_NE(ret, CF_SUCCESS);
    EXPECT_EQ(signature.data, nullptr);
}

// Test crl getSignature false
HWTEST_F(CryptoX509CrlTest, X509CrlTest173, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfResult ret = g_x509Crl->getSignature(g_x509Crl, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
}

// Test crl getSignature false
HWTEST_F(CryptoX509CrlTest, X509CrlTest174, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfResult ret = g_x509Crl->getSignature(nullptr, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
}

// Test crl getSignatureAlgName true
HWTEST_F(CryptoX509CrlTest, X509CrlTest181, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfBlob out = { 0, nullptr };
    CfResult ret = g_x509Crl->getSignatureAlgName(g_x509Crl, &out);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(out.data, nullptr);
    EXPECT_STREQ("SHA256withRSA", reinterpret_cast<char *>(out.data));
    CfFree(out.data);
}

// Test crl getSignatureAlgName false
HWTEST_F(CryptoX509CrlTest, X509CrlTest182, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfBlob out = { 0, nullptr };
    CfResult ret = g_x509Crl->getSignatureAlgName(nullptr, &out);
    EXPECT_NE(ret, CF_SUCCESS);
    EXPECT_EQ(out.data, nullptr);
}

// Test crl getSignatureAlgName false
HWTEST_F(CryptoX509CrlTest, X509CrlTest183, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfResult ret = g_x509Crl->getSignatureAlgName(g_x509Crl, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
}

// Test crl getSignatureAlgName false
HWTEST_F(CryptoX509CrlTest, X509CrlTest184, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfResult ret = g_x509Crl->getSignatureAlgName(nullptr, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
}

// Test crl getSignatureAlgOid true
HWTEST_F(CryptoX509CrlTest, X509CrlTest191, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfBlob out = { 0, nullptr };
    CfResult ret = g_x509Crl->getSignatureAlgOid(g_x509Crl, &out);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(out.data, nullptr);
    EXPECT_STREQ("1.2.840.113549.1.1.11", reinterpret_cast<char *>(out.data));
    CfFree(out.data);
}

// Test crl getSignatureAlgOid false
HWTEST_F(CryptoX509CrlTest, X509CrlTest192, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfBlob out = { 0, nullptr };
    CfResult ret = g_x509Crl->getSignatureAlgOid(nullptr, &out);
    EXPECT_NE(ret, CF_SUCCESS);
    EXPECT_EQ(out.data, nullptr);
}

// Test crl getSignatureAlgOid false
HWTEST_F(CryptoX509CrlTest, X509CrlTest193, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfResult ret = g_x509Crl->getSignatureAlgOid(g_x509Crl, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
}

// Test crl getSignatureAlgOid false
HWTEST_F(CryptoX509CrlTest, X509CrlTest194, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfResult ret = g_x509Crl->getSignatureAlgOid(nullptr, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
}

// Test crl getSignatureAlgParams true
HWTEST_F(CryptoX509CrlTest, X509CrlTest201, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfBlob sigAlgParamOut = { 0, nullptr };
    CfResult ret = g_x509Crl->getSignatureAlgParams(g_x509Crl, &sigAlgParamOut);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(sigAlgParamOut.data, nullptr);
    CfFree(sigAlgParamOut.data);
}

// Test crl getSignatureAlgParams false
HWTEST_F(CryptoX509CrlTest, X509CrlTest202, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfBlob sigAlgParamOut = { 0, nullptr };
    CfResult ret = g_x509Crl->getSignatureAlgParams(nullptr, &sigAlgParamOut);
    EXPECT_NE(ret, CF_SUCCESS);
    EXPECT_EQ(sigAlgParamOut.data, nullptr);
}

// Test crl getSignatureAlgParams false
HWTEST_F(CryptoX509CrlTest, X509CrlTest203, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfResult ret = g_x509Crl->getSignatureAlgParams(g_x509Crl, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
}

// Test crl getSignatureAlgParams false
HWTEST_F(CryptoX509CrlTest, X509CrlTest204, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfResult ret = g_x509Crl->getSignatureAlgParams(nullptr, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
}

HWTEST_F(CryptoX509CrlTest, NullSpi, TestSize.Level0)
{
    (void)HcfCX509CrlSpiCreate(nullptr, nullptr);
    (void)HcfCX509CRLEntryCreate(nullptr, nullptr, nullptr);
    HcfX509CrlSpi *spiObj = nullptr;
    CfResult ret = HcfCX509CrlSpiCreate(&g_crlDerInStream, &spiObj);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(spiObj, nullptr);

    (void)spiObj->base.destroy(nullptr);
    const char *tmp = spiObj->engineGetType(nullptr);
    EXPECT_EQ(tmp, nullptr);
    bool flag = spiObj->engineIsRevoked(nullptr, nullptr);
    EXPECT_EQ(flag, false);
    ret = spiObj->engineGetEncoded(nullptr, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = spiObj->engineVerify(nullptr, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
    long ver = spiObj->engineGetVersion(nullptr);
    EXPECT_EQ(ver, -1);
    ret = spiObj->engineGetIssuerName(nullptr, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = spiObj->engineGetLastUpdate(nullptr, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = spiObj->engineGetNextUpdate(nullptr, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = spiObj->engineGetRevokedCert(nullptr, 0, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = spiObj->engineGetRevokedCertWithCert(nullptr, nullptr, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = spiObj->engineGetRevokedCerts(nullptr, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = spiObj->engineGetTbsInfo(nullptr, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = spiObj->engineGetSignature(nullptr, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = spiObj->engineGetSignatureAlgName(nullptr, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = spiObj->engineGetSignatureAlgOid(nullptr, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = spiObj->engineGetSignatureAlgParams(nullptr, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);

    CfObjDestroy(spiObj);
}

static const char *GetInvalidCrlClass(void)
{
    return "INVALID_CRL_CLASS";
}

HWTEST_F(CryptoX509CrlTest, InvalidCrlSpiClass, TestSize.Level0)
{
    HcfX509CrlSpi invalidSpi = { {0} };
    invalidSpi.base.getClass = GetInvalidCrlClass;
    CfBlob invalidOut = { 0, nullptr };
    CfEncodingBlob encoding = { nullptr, 0, CF_FORMAT_PEM };
    HcfX509CrlEntry *entry = nullptr;
    HcfX509CrlSpi *spiObj = nullptr;
    CfResult ret = HcfCX509CrlSpiCreate(&g_crlDerInStream, &spiObj);
    (void)spiObj->base.destroy(&(invalidSpi.base));
    const char *tmp = spiObj->engineGetType(&invalidSpi);
    EXPECT_EQ(tmp, nullptr);
    HcfCertificate cert;
    bool flag = spiObj->engineIsRevoked(&invalidSpi, &cert);
    EXPECT_EQ(flag, false);
    ret = spiObj->engineGetEncoded(&invalidSpi, &encoding);
    EXPECT_NE(ret, CF_SUCCESS);
    HcfPubKey pubKey;
    ret = spiObj->engineVerify(&invalidSpi, &pubKey);
    EXPECT_NE(ret, CF_SUCCESS);
    long ver = spiObj->engineGetVersion(&invalidSpi);
    EXPECT_EQ(ver, -1);
    ret = spiObj->engineGetIssuerName(&invalidSpi, &invalidOut);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = spiObj->engineGetLastUpdate(&invalidSpi, &invalidOut);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = spiObj->engineGetNextUpdate(&invalidSpi, &invalidOut);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = spiObj->engineGetRevokedCert(&invalidSpi, 0, &entry);
    EXPECT_NE(ret, CF_SUCCESS);
    HcfX509Certificate x509Cert;
    ret = spiObj->engineGetRevokedCertWithCert(&invalidSpi, &x509Cert, &entry);
    EXPECT_NE(ret, CF_SUCCESS);
    CfArray invalidArr = { nullptr, CF_FORMAT_PEM, 0 };
    ret = spiObj->engineGetRevokedCerts(&invalidSpi, &invalidArr);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = spiObj->engineGetTbsInfo(&invalidSpi, &invalidOut);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = spiObj->engineGetSignature(&invalidSpi, &invalidOut);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = spiObj->engineGetSignatureAlgName(&invalidSpi, &invalidOut);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = spiObj->engineGetSignatureAlgOid(&invalidSpi, &invalidOut);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = spiObj->engineGetSignatureAlgParams(&invalidSpi, &invalidOut);
    EXPECT_NE(ret, CF_SUCCESS);
    CfObjDestroy(spiObj);
}

HWTEST_F(CryptoX509CrlTest, InvalidCrlClass, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    HcfX509Crl invalidCrl;
    invalidCrl.base.base.getClass = GetInvalidCrlClass;
    CfBlob invalidOut = { 0, nullptr };
    CfEncodingBlob encoding = { nullptr, 0, CF_FORMAT_PEM };
    HcfX509CrlEntry *entry = nullptr;

    g_x509Crl->base.base.destroy(nullptr);
    g_x509Crl->base.base.destroy(&(invalidCrl.base.base));
    const char *tmp = g_x509Crl->base.getType(&(invalidCrl.base));
    EXPECT_EQ(tmp, nullptr);
    HcfCertificate cert;
    bool flag = g_x509Crl->base.isRevoked(&(invalidCrl.base), &cert);
    EXPECT_EQ(flag, false);
    CfResult ret = g_x509Crl->getEncoded(&invalidCrl, &encoding);
    EXPECT_NE(ret, CF_SUCCESS);
    HcfPubKey pubKey;
    ret = g_x509Crl->verify(&invalidCrl, &pubKey);
    EXPECT_NE(ret, CF_SUCCESS);
    long ver = g_x509Crl->getVersion(&invalidCrl);
    EXPECT_EQ(ver, -1);
    ret = g_x509Crl->getIssuerName(&invalidCrl, &invalidOut);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = g_x509Crl->getLastUpdate(&invalidCrl, &invalidOut);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = g_x509Crl->getNextUpdate(&invalidCrl, &invalidOut);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = g_x509Crl->getRevokedCert(&invalidCrl, 0, &entry);
    EXPECT_NE(ret, CF_SUCCESS);
    HcfX509Certificate x509Cert;
    ret = g_x509Crl->getRevokedCertWithCert(&invalidCrl, &x509Cert, &entry);
    EXPECT_NE(ret, CF_SUCCESS);
    CfArray invalidArr = { nullptr, CF_FORMAT_PEM, 0 };
    ret = g_x509Crl->getRevokedCerts(&invalidCrl, &invalidArr);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = g_x509Crl->getTbsInfo(&invalidCrl, &invalidOut);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = g_x509Crl->getSignature(&invalidCrl, &invalidOut);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = g_x509Crl->getSignatureAlgName(&invalidCrl, &invalidOut);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = g_x509Crl->getSignatureAlgOid(&invalidCrl, &invalidOut);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = g_x509Crl->getSignatureAlgParams(&invalidCrl, &invalidOut);
    EXPECT_NE(ret, CF_SUCCESS);
}

HWTEST_F(CryptoX509CrlTest, InvalidMalloc, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    SetMockFlag(true);
    CfBlob out = { 0, nullptr };
    CfEncodingBlob encoding = { nullptr, 0, CF_FORMAT_PEM };
    HcfX509CrlEntry *entry = nullptr;
    CfResult ret = g_x509Crl->getEncoded(g_x509Crl, &encoding);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = g_x509Crl->getIssuerName(g_x509Crl, &out);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = g_x509Crl->getLastUpdate(g_x509Crl, &out);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = g_x509Crl->getNextUpdate(g_x509Crl, &out);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = g_x509Crl->getRevokedCert(g_x509Crl, 0, &entry);
    EXPECT_NE(ret, CF_SUCCESS);
    CfArray arr = { nullptr, CF_FORMAT_PEM, 0 };
    ret = g_x509Crl->getRevokedCerts(g_x509Crl, &arr);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = g_x509Crl->getTbsInfo(g_x509Crl, &out);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = g_x509Crl->getSignature(g_x509Crl, &out);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = g_x509Crl->getSignatureAlgName(g_x509Crl, &out);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = g_x509Crl->getSignatureAlgOid(g_x509Crl, &out);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = g_x509Crl->getSignatureAlgParams(g_x509Crl, &out);
    EXPECT_NE(ret, CF_SUCCESS);
    SetMockFlag(false);
}
}