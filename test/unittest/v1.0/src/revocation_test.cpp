/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <pthread.h>
#include <sys/stat.h>
#include <unistd.h>

#include "cf_blob.h"
#include "cf_memory.h"
#include "cf_result.h"
#include "hm_cert_revocation.h"
#include "revocation_cache.h"
#include "securec.h"
#include "x509_certificate.h"

#include "openssl/sha.h"
#include "openssl/x509.h"
#include "openssl/x509v3.h"

#define REVOCATION_TEST_DIR_MODE 0755  /* rwxr-xr-x */
#define REVOCATION_TEST_PATH_LEN 512
#define REVOCATION_TEST_CFG_LINE_LEN 80
#define REVOCATION_TEST_CFG_LINE_DUP_LEN 160
#define REVOCATION_TEST_MULTI_CERT_COUNT 2
#define REVOCATION_TEST_HEX_CHARS_PER_BYTE 2  /* 1 byte = 2 hex chars */
#define REVOCATION_TEST_TYPE2_CFG_LEN 128
#define REVOCATION_TEST_TYPE2_DUP_CFG_LEN 256
#define REVOCATION_TEST_AKI_HEX_LEN 40
#define REVOCATION_TEST_INVALID_DATA_COUNT 3
#define REVOCATION_TEST_DECIMAL_BASE 10
#define REVOCATION_TEST_DECIMAL_HUNDRED 100
#define REVOCATION_TEST_DECIMAL_THOUSAND 1000
#define REVOCATION_TEST_UTCTIME_YEAR_IDX 0
#define REVOCATION_TEST_UTCTIME_YEAR_LEN 2
#define REVOCATION_TEST_UTCTIME_MONTH_IDX 2
#define REVOCATION_TEST_UTCTIME_DAY_IDX 4
#define REVOCATION_TEST_GENYEAR_IDX 0
#define REVOCATION_TEST_GENMONTH_IDX 4
#define REVOCATION_TEST_GENDAY_IDX 6
#define REVOCATION_TEST_FORCECHECK_DIR REVOCATION_TEST_CFG_DIR
#define REVOCATION_TEST_ZERO_HASH \
    "1,0000000000000000000000000000000000000000000000000000000000000000\n"

/* Chain 1: root -> inter1 -> inter2 -> inter3 -> leaf (system time 2026-10-31) */
static const char *TEST_REVOC_ROOT_PEM =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBzTCCAXSgAwIBAgIUe1MKzeb4I5MZIwLjbvc/UdBXFz4wCgYIKoZIzj0EAwIw\n"
    "MzELMAkGA1UEBhMCQ04xDTALBgNVBAoMBFRlc3QxFTATBgNVBAMMDHRlc3QgUm9v\n"
    "dCBDQTAeFw0yNjExMTEwMTM0MzhaFw0zNjExMDgwMTM0MzhaMDMxCzAJBgNVBAYT\n"
    "AkNOMQ0wCwYDVQQKDARUZXN0MRUwEwYDVQQDDAx0ZXN0IFJvb3QgQ0EwWTATBgcq\n"
    "hkjOPQIBBggqhkjOPQMBBwNCAAQadGjWxWTYVtn9Xtj0aVV0wHjV6am2Gg9YaHTG\n"
    "HJFXWczne4EnZlmCN8zDiRbe5FpPwAPhVvC2vYg/ZSpxbAfbo2YwZDASBgNVHRMB\n"
    "Af8ECDAGAQH/AgEGMA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUuegs95KgyCsf\n"
    "YdPCrMWOflO2odMwHwYDVR0jBBgwFoAUuegs95KgyCsfYdPCrMWOflO2odMwCgYI\n"
    "KoZIzj0EAwIDRwAwRAIgXPLsmLe61G6z5G46YcM3BdNRvUDzGd+jCKYVRAt6xVQC\n"
    "IBh/ZXWKrOVDzsunlqIv0IykGaikMJG8aCn8vkpxoqqm\n"
    "-----END CERTIFICATE-----\n";

static const char *TEST_REVOC_LEAF_PEM =
    "-----BEGIN CERTIFICATE-----\n"
    "MIICGjCCAb+gAwIBAgIUWqGUtrTL9f52iRWkYZt8Px+GwTUwCgYIKoZIzj0EAwIw\n"
    "PTELMAkGA1UEBhMCQ04xDTALBgNVBAoMBFRlc3QxHzAdBgNVBAMMFnRlc3QgSW50\n"
    "ZXJtZWRpYXRlIENBIDMwHhcNMjYxMTExMDEzNDM5WhcNMzYxMTA4MDEzNDM5WjAw\n"
    "MQswCQYDVQQGEwJDTjENMAsGA1UECgwEVGVzdDESMBAGA1UEAwwJbG9jYWxob3N0\n"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEiFcwMCv/5lhIGxd+k2GpGTbItbeZ\n"
    "kMLf2+xlZl8WD6Oj3uSoxuGFMXVWa+s5ZvdTKKuBS0kfbFZLdSEc4HOLtaOBqTCB\n"
    "pjAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDAdBgNVHSUEFjAUBggrBgEF\n"
    "BQcDAQYIKwYBBQUHAwIwHQYDVR0OBBYEFHHpOhkEAuZgU1n8huqvG3oxDutRMB8G\n"
    "A1UdIwQYMBaAFOGGrLTqj+y5wP6eEZ7+UuLG4yFGMCcGA1UdEQQgMB6CCWxvY2Fs\n"
    "aG9zdIILZXhhbXBsZS5jb22HBH8AAAEwCgYIKoZIzj0EAwIDSQAwRgIhAMSh/9tT\n"
    "eaf+UiZJ7DrHwiQ9HO+/w+lX9qJLv1JN461NAiEAhwfKwxzSqAc3A4JgBhYDmTao\n"
    "1YGBzt2cbvONqfHt8eY=\n"
    "-----END CERTIFICATE-----\n";

/* Chain 2: inter2 -> new-inter3 -> new-inter4 -> new-inter5 -> new-leaf (system time 2026-10-31) */
static const char *TEST_REVOC_NEW_INTER3_PEM =
    "-----BEGIN CERTIFICATE-----\n"
    "MIICrjCCAlOgAwIBAgIUGJbpEH0rq0N8gL8wuPw2hz7Vfg0wCgYIKoZIzj0EAwIw\n"
    "PTELMAkGA1UEBhMCQ04xDTALBgNVBAoMBFRlc3QxHzAdBgNVBAMMFnRlc3QgSW50\n"
    "ZXJtZWRpYXRlIENBIDIwHhcNMjYxMTExMDEzNDUwWhcNMzYxMTA3MDEzNDUwWjA9\n"
    "MQswCQYDVQQGEwJDTjENMAsGA1UECgwEVGVzdDEfMB0GA1UEAwwWdGVzdCBJbnRl\n"
    "cm1lZGlhdGUgQ0EgMzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANjt\n"
    "ZWsytULqZFPwevtaLiGLCtrcC4Ea1lY6T3WWFlYxYf/yP4h1Jo6nHK1HZGiZD9u2\n"
    "j2NRA6eYrR4gwKZ8TYdWrbdmjE9d4zoxcT0oCblWl44tI27aRrTdpbUg0cOOEqMe\n"
    "BBllVSTs8H6dRqpq0/nCJfxklBvxclIAzf27U9GeJCnOe/irHOahrclRnJYXTp34\n"
    "yZpfkf8uEK658YZEi8gklK95sCceu8fesL6BXqiAVajgfTgKVwiLwRTSnzRzhB27\n"
    "HVcQTqBl+1zCcztXrFTXvHsD6SVWEEnETjUKvDoJ/GAy7hMY+sdmrLHlR5BnuCGh\n"
    "6HRZENAevkX0nsQvQqsCAwEAAaNmMGQwEgYDVR0TAQH/BAgwBgEB/wIBAzAOBgNV\n"
    "HQ8BAf8EBAMCAQYwHQYDVR0OBBYEFGNkwmUSNO+AwerTvtO8+YR4kB+EMB8GA1Ud\n"
    "IwQYMBaAFIbtCFHWnWc3OJ3pSRaFZpZxbjBAMAoGCCqGSM49BAMCA0kAMEYCIQCt\n"
    "mVyMlYjtADhKHFZIcrrHpkRhdvRd+6v4F0PEKRAJvwIhANmVSmo3q98Ly3LrHN39\n"
    "vlzsE1LujIl+BHGTTwLecEkx\n"
    "-----END CERTIFICATE-----\n";

static const char *TEST_REVOC_NEW_LEAF_PEM =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDpTCCAo2gAwIBAgIUL8sqhjIIpL9DBeqrLDodlUJ8GsIwDQYJKoZIhvcNAQEL\n"
    "BQAwPTELMAkGA1UEBhMCQ04xDTALBgNVBAoMBFRlc3QxHzAdBgNVBAMMFnRlc3Qg\n"
    "SW50ZXJtZWRpYXRlIENBIDUwHhcNMjYxMTExMDEzNDUxWhcNMzYxMTA3MDEzNDUx\n"
    "WjAwMQswCQYDVQQGEwJDTjENMAsGA1UECgwEVGVzdDESMBAGA1UEAwwJbG9jYWxo\n"
    "b3N0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApn44i7Wv8cKSsQIM\n"
    "WoCbBBaLdreUR3YOkSjf9EaNlur56JKila4c+wxR9jNDlSNo/kG/ATr5mXyQiwIo\n"
    "6E3IcKVgeIixPGIAWNBzJIGQD8XLbLOViIalXESlF8CAiTUmSEXRechnvBrY5eDe\n"
    "wUNFOtgzdk5yGHYNumS9MOg6QmxqHOliy0Ugq/A808Dx7OnqJvrXEaEBWKutVnlZ\n"
    "pFV2ExkSEISupnmsI9ojRna4+YAI7v4rabjD6pkRfmmfA6FNE5PZ+31xybdJ4vwh\n"
    "OnIxAQ6YG19EmPwLDpkrOkB6J3NceXHgtwfLbYWDu6e7ZnDVVj+aurw+ZRlUhMDu\n"
    "LN7WlwIDAQABo4GpMIGmMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgWgMB0G\n"
    "A1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAdBgNVHQ4EFgQUx4mpWWuuk2lu\n"
    "FUZ27wC6LcBdEn8wHwYDVR0jBBgwFoAUwuK3rNaQMr4uIgROSHuubkvFJe8wJwYD\n"
    "VR0RBCAwHoIJbG9jYWxob3N0ggtleGFtcGxlLmNvbYcEfwAAATANBgkqhkiG9w0B\n"
    "AQsFAAOCAQEAp9uCWSaMlTw0NgtD+yNWVESF0+5vB2z9J3New4RF3r2RzwclkCps\n"
    "giZs0KmXrSN34gkcwpmzvhVSFPlEh1LqsVdvnFxo4gKO+IwikzxL4g3pbbTUARZO\n"
    "xEwuoDTv0oyVRJ6n76+5uF/gj4h3hrA+hHOzOQyTNSB2z7H5x80hLaRfQFvkjgs8\n"
    "u9bO/NV7kfdu9cBGPjYhqnzCLV79RKbce+U0NOYR+domjX6E+ptrcH+ueC/96PVS\n"
    "fPc/Ttj9OJKStatR4D7hbRje4m8oNuxBuQnaY1pnYaYmW82sUsB9pU1UV6HS4ej7\n"
    "4K6R6OFW2HuWB4Kwo61N5Oxo7Qb8/P+5Cw==\n"
    "-----END CERTIFICATE-----\n";

/* Parent dir of REVOCATION_TEST_CFG_DIR, needed by mkdir (single-level) */
#define REVOCATION_TEST_PARENT_DIR "/data/test"

static bool EnsureTestDir(void)
{
    if (mkdir(REVOCATION_TEST_PARENT_DIR, REVOCATION_TEST_DIR_MODE) != 0 && errno != EEXIST) {
        return false;
    }
    if (mkdir(REVOCATION_TEST_FORCECHECK_DIR, REVOCATION_TEST_DIR_MODE) != 0 && errno != EEXIST) {
        return false;
    }
    return true;
}

static bool WriteCfgFile(const char *fileName, const char *content)
{
    if (!EnsureTestDir()) {
        return false;
    }
    char path[REVOCATION_TEST_PATH_LEN];
    if (snprintf_s(path, sizeof(path), sizeof(path) - 1, "%s/%s",
        REVOCATION_TEST_FORCECHECK_DIR, fileName) < 0) {
        return false;
    }
    FILE *fp = fopen(path, "w");
    if (fp == nullptr) {
        return false;
    }
    if (fputs(content, fp) == EOF) {
        (void)fclose(fp);
        return false;
    }
    if (fclose(fp) != 0) {
        return false;
    }
    return true;
}

static void RemoveCfgFile(const char *fileName)
{
    char path[REVOCATION_TEST_PATH_LEN];
    if (snprintf_s(path, sizeof(path), sizeof(path) - 1, "%s/%s",
        REVOCATION_TEST_FORCECHECK_DIR, fileName) < 0) {
        return;
    }
    (void)remove(path);
}

static void RemoveAllCfgFiles(void)
{
    RemoveCfgFile(REVOCATION_CLOUD_CFG);
    RemoveCfgFile(REVOCATION_USER_CFG);
}

static HcfX509Certificate *CreateCertFromPem(const char *pem)
{
    CfEncodingBlob encoded = { 0 };
    encoded.data = reinterpret_cast<uint8_t *>(const_cast<char *>(pem));
    encoded.len = strlen(pem);
    encoded.encodingFormat = CF_FORMAT_PEM;
    HcfX509Certificate *cert = nullptr;
    CfResult ret = HcfX509CertificateCreate(&encoded, &cert);
    if (ret != CF_SUCCESS) {
        return nullptr;
    }
    return cert;
}

static bool GetCertSpkiSha256(HcfX509Certificate *cert, uint8_t *digest)
{
    CfEncodingBlob encoded = { 0 };
    if (cert->base.getEncoded((HcfCertificate *)cert, &encoded) != CF_SUCCESS) {
        return false;
    }
    const uint8_t *p = encoded.data;
    X509 *x509 = d2i_X509(nullptr, &p, (long)encoded.len);
    CfFree(encoded.data);
    if (x509 == nullptr) {
        return false;
    }
    EVP_PKEY *pkey = X509_get_pubkey(x509);
    X509_free(x509);
    if (pkey == nullptr) {
        return false;
    }
    unsigned char *spkiDer = nullptr;
    int spkiLen = i2d_PUBKEY(pkey, &spkiDer);
    EVP_PKEY_free(pkey);
    if (spkiLen <= 0) {
        OPENSSL_free(spkiDer);
        return false;
    }
    if (SHA256(spkiDer, (size_t)spkiLen, digest) == nullptr) {
        OPENSSL_free(spkiDer);
        return false;
    }
    OPENSSL_free(spkiDer);
    return true;
}

#define REVOCATION_TEST_HEX_HIGH_BITS 4
#define REVOCATION_TEST_HEX_LOW_MASK 0xF

static void BytesToHex(const uint8_t *bytes, uint32_t len, char *hexOut)
{
    static const char hexChars[] = "0123456789abcdef";
    for (uint32_t i = 0; i < len; i++) {
        hexOut[i * REVOCATION_TEST_HEX_CHARS_PER_BYTE] = hexChars[(bytes[i] >> REVOCATION_TEST_HEX_HIGH_BITS) &
            REVOCATION_TEST_HEX_LOW_MASK];
        hexOut[i * REVOCATION_TEST_HEX_CHARS_PER_BYTE + 1] = hexChars[bytes[i] & REVOCATION_TEST_HEX_LOW_MASK];
    }
    hexOut[len * REVOCATION_TEST_HEX_CHARS_PER_BYTE] = '\0';
}

static bool WriteCfgFileChecked(const char *fileName, const char *content)
{
    return WriteCfgFile(fileName, content);
}

static void DestroyCert(HcfX509Certificate *cert)
{
    if (cert != nullptr) {
        cert->base.base.destroy(&cert->base.base);
    }
}

class RevocationTest : public testing::Test {
public:
    static void SetUpTestCase(void)
    {
        RemoveAllCfgFiles();
        HcfCertRevocationClearCache();
    }

    static void TearDownTestCase(void)
    {
        RemoveAllCfgFiles();
        HcfCertRevocationClearCache();
    }

    void SetUp() override
    {
        RemoveAllCfgFiles();
        HcfCertRevocationClearCache();
    }

    void TearDown() override
    {
        RemoveAllCfgFiles();
        HcfCertRevocationClearCache();
    }
};

/* Scenario: Indian CA private key leak.
 * intermediate-2 (AKI=CD62915B...) signed two chains:
 *   Chain 1: inter3 (SPKI=d8eaa0..., AKI=86ED0851...) notBefore=20261111
 *   Chain 2: new-inter3 (SPKI=c05011..., AKI=86ED0851...) notBefore=20261111
 * Both inter3 and new-inter3 have the same AKI (86ED0851...) pointing to inter2.
 * A type-2 rule "2,86ED0851D69D6737389DE94916856696716E3040,20261112-" would
 * revoke certs with notBefore >= 20261112. Since both certs have notBefore 20261111,
 * neither should be revoked by that rule.
 * A rule "2,86ED0851D69D6737389DE94916856696716E3040,-20990101" revokes all
 * certs from that CA regardless of date. Both chains should be revoked.
 */
HWTEST_F(RevocationTest, DualChainType2RevokeAllByAki, testing::ext::TestSize.Level0)
{
    HcfX509Certificate *chain1Cert = CreateCertFromPem(TEST_REVOC_LEAF_PEM);
    HcfX509Certificate *chain2Cert = CreateCertFromPem(TEST_REVOC_NEW_INTER3_PEM);
    ASSERT_NE(chain1Cert, nullptr);
    ASSERT_NE(chain2Cert, nullptr);

    /* AKI 86ED0851D69D6737389DE94916856696716E3040 = inter3's AKI pointing to inter2 */
    ASSERT_TRUE(WriteCfgFileChecked("certRevocationPolicy_cloud.cfg",
        "2,86ED0851D69D6737389DE94916856696716E3040,-20990101\n"));

    /* Check chain 1 cert (leaf, AKI=E186ACB4... -> won't match)
     * Check chain 2 cert (new-inter3, AKI=86ED0851... -> will match) */
    HcfX509Certificate *certs1[] = { chain1Cert };
    HcfX509CertificateArray arr1 = { certs1, 1 };
    int32_t blockedIndex1 = -1;
    CfResult ret1 = HcfCertRevocationCheck(&arr1, &blockedIndex1);
    EXPECT_EQ(ret1, CF_SUCCESS);
    EXPECT_EQ(blockedIndex1, -1);

    HcfX509Certificate *certs2[] = { chain2Cert };
    HcfX509CertificateArray arr2 = { certs2, 1 };
    int32_t blockedIndex2 = -1;
    CfResult ret2 = HcfCertRevocationCheck(&arr2, &blockedIndex2);
    EXPECT_EQ(ret2, CF_ERR_CERT_REVOKED);
    EXPECT_EQ(blockedIndex2, 0);

    DestroyCert(chain1Cert);
    DestroyCert(chain2Cert);
}

HWTEST_F(RevocationTest, DualChainType1RevokeChain2Only, testing::ext::TestSize.Level0)
{
    HcfX509Certificate *chain1Cert = CreateCertFromPem(TEST_REVOC_LEAF_PEM);
    HcfX509Certificate *chain2Cert = CreateCertFromPem(TEST_REVOC_NEW_LEAF_PEM);
    ASSERT_NE(chain1Cert, nullptr);
    ASSERT_NE(chain2Cert, nullptr);

    /* Revoke new-leaf by SPKI SHA256: 246ddf8a635e11413af03e2b35e7788a6264813d0a33cb1a2de73d99091d89ac */
    ASSERT_TRUE(WriteCfgFileChecked("certRevocationPolicy_cloud.cfg",
        "1,246ddf8a635e11413af03e2b35e7788a6264813d0a33cb1a2de73d99091d89ac\n"));

    HcfX509Certificate *certs1[] = { chain1Cert };
    HcfX509CertificateArray arr1 = { certs1, 1 };
    int32_t blockedIndex1 = -1;
    CfResult ret1 = HcfCertRevocationCheck(&arr1, &blockedIndex1);
    EXPECT_EQ(ret1, CF_SUCCESS);
    EXPECT_EQ(blockedIndex1, -1);

    HcfX509Certificate *certs2[] = { chain2Cert };
    HcfX509CertificateArray arr2 = { certs2, 1 };
    int32_t blockedIndex2 = -1;
    CfResult ret2 = HcfCertRevocationCheck(&arr2, &blockedIndex2);
    EXPECT_EQ(ret2, CF_ERR_CERT_REVOKED);
    EXPECT_EQ(blockedIndex2, 0);

    DestroyCert(chain1Cert);
    DestroyCert(chain2Cert);
}

HWTEST_F(RevocationTest, DualChainType2TimeRangeSelectiveRevoke, testing::ext::TestSize.Level0)
{
    HcfX509Certificate *chain1Inter3 = CreateCertFromPem(TEST_REVOC_LEAF_PEM);
    HcfX509Certificate *chain2Inter3 = CreateCertFromPem(TEST_REVOC_NEW_INTER3_PEM);
    ASSERT_NE(chain1Inter3, nullptr);
    ASSERT_NE(chain2Inter3, nullptr);

    /* Both certs have notBefore 20261111.
     * Rule "2,<AKI>,20261112-" revokes certs with notBefore >= 20261112.
     * Neither cert should be revoked (both have notBefore 20261111 < 20261112). */
    ASSERT_TRUE(WriteCfgFileChecked("certRevocationPolicy_cloud.cfg",
        "2,86ED0851D69D6737389DE94916856696716E3040,20261112-\n"));

    HcfX509Certificate *certs1[] = { chain1Inter3 };
    HcfX509CertificateArray arr1 = { certs1, 1 };
    int32_t blockedIndex1 = -1;
    CfResult ret1 = HcfCertRevocationCheck(&arr1, &blockedIndex1);
    EXPECT_EQ(ret1, CF_SUCCESS);
    EXPECT_EQ(blockedIndex1, -1);

    /* new-inter3's AKI = 86ED0851... which matches the rule, but notBefore=20261111 < 20261112 */
    HcfX509Certificate *certs2[] = { chain2Inter3 };
    HcfX509CertificateArray arr2 = { certs2, 1 };
    int32_t blockedIndex2 = -1;
    CfResult ret2 = HcfCertRevocationCheck(&arr2, &blockedIndex2);
    EXPECT_EQ(ret2, CF_SUCCESS);
    EXPECT_EQ(blockedIndex2, -1);

    DestroyCert(chain1Inter3);
    DestroyCert(chain2Inter3);
}

HWTEST_F(RevocationTest, DualChainType2TimeRangeRevokeBeforeDate, testing::ext::TestSize.Level0)
{
    HcfX509Certificate *chain2Inter3 = CreateCertFromPem(TEST_REVOC_NEW_INTER3_PEM);
    ASSERT_NE(chain2Inter3, nullptr);

    /* new-inter3 notBefore = 20261111.
     * Rule "2,<AKI>,-20261109" revokes certs with notBefore <= 20261109.
     * 20261111 > 20261109, so NOT revoked. */
    ASSERT_TRUE(WriteCfgFileChecked("certRevocationPolicy_cloud.cfg",
        "2,86ED0851D69D6737389DE94916856696716E3040,-20261109\n"));

    HcfX509Certificate *certs[] = { chain2Inter3 };
    HcfX509CertificateArray arr = { certs, 1 };
    int32_t blockedIndex = -1;
    CfResult ret = HcfCertRevocationCheck(&arr, &blockedIndex);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(blockedIndex, -1);

    DestroyCert(chain2Inter3);
}

HWTEST_F(RevocationTest, DualChainType2TimeRangeExactBoundaryMatch, testing::ext::TestSize.Level0)
{
    HcfX509Certificate *chain2Inter3 = CreateCertFromPem(TEST_REVOC_NEW_INTER3_PEM);
    ASSERT_NE(chain2Inter3, nullptr);

    /* new-inter3 notBefore = 20261111.
     * Rule "2,<AKI>,-20261111" revokes certs with notBefore <= 20261111 (inclusive).
     * 20261111 <= 20261111, so REVOKED. */
    ASSERT_TRUE(WriteCfgFileChecked("certRevocationPolicy_cloud.cfg",
        "2,86ED0851D69D6737389DE94916856696716E3040,-20261111\n"));

    HcfX509Certificate *certs[] = { chain2Inter3 };
    HcfX509CertificateArray arr = { certs, 1 };
    int32_t blockedIndex = -1;
    CfResult ret = HcfCertRevocationCheck(&arr, &blockedIndex);
    EXPECT_EQ(ret, CF_ERR_CERT_REVOKED);
    EXPECT_EQ(blockedIndex, 0);

    DestroyCert(chain2Inter3);
}

HWTEST_F(RevocationTest, DualChainMultiCertFirstMatch, testing::ext::TestSize.Level0)
{
    HcfX509Certificate *cert1 = CreateCertFromPem(TEST_REVOC_ROOT_PEM);
    HcfX509Certificate *cert2 = CreateCertFromPem(TEST_REVOC_NEW_INTER3_PEM);
    ASSERT_NE(cert1, nullptr);
    ASSERT_NE(cert2, nullptr);
    /* Revoke new-inter3 by SPKI: c0501170f3f0251be0fa3c52bc51f5490a9f49b2a2969b726139ac5494a24096 */
    ASSERT_TRUE(WriteCfgFileChecked("certRevocationPolicy_cloud.cfg",
        "1,c0501170f3f0251be0fa3c52bc51f5490a9f49b2a2969b726139ac5494a24096\n"));

    HcfX509Certificate *certs[] = { cert1, cert2 };
    HcfX509CertificateArray arr = { certs, REVOCATION_TEST_MULTI_CERT_COUNT };
    int32_t blockedIndex = -1;
    CfResult ret = HcfCertRevocationCheck(&arr, &blockedIndex);
    EXPECT_EQ(ret, CF_ERR_CERT_REVOKED);
    EXPECT_EQ(blockedIndex, 1);
    DestroyCert(cert1);
    DestroyCert(cert2);
}

static bool GetCertAkiKeyId(HcfX509Certificate *cert, uint8_t *akiOut)
{
    CfEncodingBlob encoded = { 0 };
    if (cert->base.getEncoded((HcfCertificate *)cert, &encoded) != CF_SUCCESS) {
        return false;
    }
    const uint8_t *p = encoded.data;
    X509 *x509 = d2i_X509(nullptr, &p, (long)encoded.len);
    CfFree(encoded.data);
    if (x509 == nullptr) {
        return false;
    }
    AUTHORITY_KEYID *akid = (AUTHORITY_KEYID *)X509_get_ext_d2i(x509, NID_authority_key_identifier, nullptr, nullptr);
    X509_free(x509);
    if (akid == nullptr || akid->keyid == nullptr) {
        if (akid != nullptr) {
            AUTHORITY_KEYID_free(akid);
        }
        return false;
    }
    bool ok = false;
    if (akid->keyid->length == REVOCATION_AKI_LEN && akid->keyid->data != nullptr) {
        if (memcpy_s(akiOut, REVOCATION_AKI_LEN, akid->keyid->data, REVOCATION_AKI_LEN) == EOK) {
            ok = true;
        }
    }
    AUTHORITY_KEYID_free(akid);
    return ok;
}

static void ParseUtcTimeDate(const char *date, uint32_t *year, uint32_t *month, uint32_t *day)
{
    uint32_t yy = static_cast<uint32_t>((date[REVOCATION_TEST_UTCTIME_YEAR_IDX] - '0') *
        REVOCATION_TEST_DECIMAL_BASE + date[REVOCATION_TEST_UTCTIME_YEAR_IDX + 1] - '0');
    *year = (yy >= REVOCATION_UTCTIME_YEAR_THRESHOLD) ?
        (REVOCATION_YEAR_BASE_1900 + yy) : (REVOCATION_YEAR_BASE_2000 + yy);
    *month = static_cast<uint32_t>((date[REVOCATION_TEST_UTCTIME_MONTH_IDX] - '0') *
        REVOCATION_TEST_DECIMAL_BASE + date[REVOCATION_TEST_UTCTIME_MONTH_IDX + 1] - '0');
    *day = static_cast<uint32_t>((date[REVOCATION_TEST_UTCTIME_DAY_IDX] - '0') *
        REVOCATION_TEST_DECIMAL_BASE + date[REVOCATION_TEST_UTCTIME_DAY_IDX + 1] - '0');
}

static void ParseGeneralizedTimeDate(const char *date, uint32_t *year, uint32_t *month, uint32_t *day)
{
    *year = static_cast<uint32_t>((date[REVOCATION_TEST_GENYEAR_IDX] - '0') * REVOCATION_TEST_DECIMAL_THOUSAND +
        (date[REVOCATION_TEST_GENYEAR_IDX + 1] - '0') * REVOCATION_TEST_DECIMAL_HUNDRED +
        (date[REVOCATION_TEST_GENYEAR_IDX + REVOCATION_TEST_UTCTIME_YEAR_LEN] - '0') *
        REVOCATION_TEST_DECIMAL_BASE +
        date[REVOCATION_TEST_GENYEAR_IDX + REVOCATION_TEST_UTCTIME_YEAR_LEN + 1] - '0');
    *month = static_cast<uint32_t>((date[REVOCATION_TEST_GENMONTH_IDX] - '0') *
        REVOCATION_TEST_DECIMAL_BASE + date[REVOCATION_TEST_GENMONTH_IDX + 1] - '0');
    *day = static_cast<uint32_t>((date[REVOCATION_TEST_GENDAY_IDX] - '0') *
        REVOCATION_TEST_DECIMAL_BASE + date[REVOCATION_TEST_GENDAY_IDX + 1] - '0');
}

static bool GetCertNotBeforeDate(HcfX509Certificate *cert, uint32_t *out)
{
    CfEncodingBlob encoded = { 0 };
    if (cert->base.getEncoded((HcfCertificate *)cert, &encoded) != CF_SUCCESS) {
        return false;
    }
    const uint8_t *p = encoded.data;
    X509 *x509 = d2i_X509(nullptr, &p, static_cast<long>(encoded.len));
    CfFree(encoded.data);
    if (x509 == nullptr) {
        return false;
    }
    ASN1_TIME *notBefore = X509_get_notBefore(x509);
    if (notBefore == nullptr) {
        X509_free(x509);
        return false;
    }
    const char *date = reinterpret_cast<const char *>(ASN1_STRING_get0_data(notBefore));
    uint32_t dateLen = static_cast<uint32_t>(ASN1_STRING_length(notBefore));
    if (date == nullptr || dateLen == 0) {
        X509_free(x509);
        return false;
    }
    uint32_t year;
    uint32_t month;
    uint32_t day;
    if (dateLen == REVOCATION_UTCTIME_LEN) {
        ParseUtcTimeDate(date, &year, &month, &day);
    } else if (dateLen == REVOCATION_GENERALIZEDTIME_LEN) {
        ParseGeneralizedTimeDate(date, &year, &month, &day);
    } else {
        X509_free(x509);
        return false;
    }
    X509_free(x509);
    *out = year * REVOCATION_YEAR_MONTH_DIVISOR + month * REVOCATION_MONTH_DAY_DIVISOR + day;
    return true;
}

HWTEST_F(RevocationTest, NoConfigFilesPass, testing::ext::TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_REVOC_LEAF_PEM);
    ASSERT_NE(cert, nullptr);
    HcfX509Certificate *certs[] = { cert };
    HcfX509CertificateArray arr = { certs, 1 };
    int32_t blockedIndex = -1;
    CfResult ret = HcfCertRevocationCheck(&arr, &blockedIndex);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(blockedIndex, -1);
    DestroyCert(cert);
}

HWTEST_F(RevocationTest, EmptyChainReturnsSuccess, testing::ext::TestSize.Level0)
{
    HcfX509CertificateArray arr = { nullptr, 0 };
    int32_t blockedIndex = -1;
    CfResult ret = HcfCertRevocationCheck(&arr, &blockedIndex);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(blockedIndex, -1);
}

HWTEST_F(RevocationTest, NullCertsReturnsParameterCheck, testing::ext::TestSize.Level0)
{
    int32_t blockedIndex = -1;
    CfResult ret = HcfCertRevocationCheck(nullptr, &blockedIndex);
    EXPECT_EQ(ret, CF_ERR_PARAMETER_CHECK);
}

HWTEST_F(RevocationTest, NullDataWithCountReturnsParameterCheck, testing::ext::TestSize.Level0)
{
    HcfX509CertificateArray arr = { nullptr, REVOCATION_TEST_INVALID_DATA_COUNT };
    int32_t blockedIndex = -1;
    CfResult ret = HcfCertRevocationCheck(&arr, &blockedIndex);
    EXPECT_EQ(ret, CF_ERR_PARAMETER_CHECK);
}

HWTEST_F(RevocationTest, NullBlockedIndexNoCrash, testing::ext::TestSize.Level0)
{
    /* Write an unrelated rule so the policy is available and the check succeeds. */
    ASSERT_TRUE(WriteCfgFileChecked("certRevocationPolicy_cloud.cfg", REVOCATION_TEST_ZERO_HASH));
    HcfX509Certificate *cert = CreateCertFromPem(TEST_REVOC_LEAF_PEM);
    ASSERT_NE(cert, nullptr);
    HcfX509Certificate *certs[] = { cert };
    HcfX509CertificateArray arr = { certs, 1 };
    CfResult ret = HcfCertRevocationCheck(&arr, nullptr);
    EXPECT_EQ(ret, CF_SUCCESS);
    DestroyCert(cert);
}

HWTEST_F(RevocationTest, Type1CloudMatch, testing::ext::TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_REVOC_LEAF_PEM);
    ASSERT_NE(cert, nullptr);
    uint8_t digest[REVOCATION_HASH_LEN];
    ASSERT_TRUE(GetCertSpkiSha256(cert, digest));
    char hex[REVOCATION_HASH_LEN * REVOCATION_TEST_HEX_CHARS_PER_BYTE + 1];
    BytesToHex(digest, REVOCATION_HASH_LEN, hex);
    char cfgLine[REVOCATION_TEST_CFG_LINE_LEN];
    if (snprintf_s(cfgLine, sizeof(cfgLine), sizeof(cfgLine) - 1, "1,%s\n", hex) < 0) {
        DestroyCert(cert);
        FAIL() << "snprintf_s failed.";
        return;
    }
    ASSERT_TRUE(WriteCfgFileChecked("certRevocationPolicy_cloud.cfg", cfgLine));

    HcfX509Certificate *certs[] = { cert };
    HcfX509CertificateArray arr = { certs, 1 };
    int32_t blockedIndex = -1;
    CfResult ret = HcfCertRevocationCheck(&arr, &blockedIndex);
    EXPECT_EQ(ret, CF_ERR_CERT_REVOKED);
    EXPECT_EQ(blockedIndex, 0);
    DestroyCert(cert);
}

HWTEST_F(RevocationTest, Type1NoMatch, testing::ext::TestSize.Level0)
{
    ASSERT_TRUE(WriteCfgFileChecked("certRevocationPolicy_cloud.cfg", REVOCATION_TEST_ZERO_HASH));
    HcfX509Certificate *cert = CreateCertFromPem(TEST_REVOC_LEAF_PEM);
    ASSERT_NE(cert, nullptr);
    HcfX509Certificate *certs[] = { cert };
    HcfX509CertificateArray arr = { certs, 1 };
    int32_t blockedIndex = -1;
    CfResult ret = HcfCertRevocationCheck(&arr, &blockedIndex);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(blockedIndex, -1);
    DestroyCert(cert);
}

HWTEST_F(RevocationTest, Type1UserMatch, testing::ext::TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_REVOC_LEAF_PEM);
    ASSERT_NE(cert, nullptr);
    uint8_t digest[REVOCATION_HASH_LEN];
    ASSERT_TRUE(GetCertSpkiSha256(cert, digest));
    char hex[REVOCATION_HASH_LEN * REVOCATION_TEST_HEX_CHARS_PER_BYTE + 1];
    BytesToHex(digest, REVOCATION_HASH_LEN, hex);
    char cfgLine[REVOCATION_TEST_CFG_LINE_LEN];
    if (snprintf_s(cfgLine, sizeof(cfgLine), sizeof(cfgLine) - 1, "1,%s\n", hex) < 0) {
        DestroyCert(cert);
        FAIL() << "snprintf_s failed.";
        return;
    }
    ASSERT_TRUE(WriteCfgFileChecked("certRevocationPolicy_user.cfg", cfgLine));

    HcfX509Certificate *certs[] = { cert };
    HcfX509CertificateArray arr = { certs, 1 };
    int32_t blockedIndex = -1;
    CfResult ret = HcfCertRevocationCheck(&arr, &blockedIndex);
    EXPECT_EQ(ret, CF_ERR_CERT_REVOKED);
    EXPECT_EQ(blockedIndex, 0);
    DestroyCert(cert);
}

HWTEST_F(RevocationTest, Type1InvalidHashSkipped, testing::ext::TestSize.Level0)
{
    ASSERT_TRUE(WriteCfgFileChecked("certRevocationPolicy_cloud.cfg", "1,abc\n1,1234567890\n"));
    HcfX509Certificate *cert = CreateCertFromPem(TEST_REVOC_LEAF_PEM);
    ASSERT_NE(cert, nullptr);
    HcfX509Certificate *certs[] = { cert };
    HcfX509CertificateArray arr = { certs, 1 };
    int32_t blockedIndex = -1;
    CfResult ret = HcfCertRevocationCheck(&arr, &blockedIndex);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(blockedIndex, -1);
    DestroyCert(cert);
}

HWTEST_F(RevocationTest, UnknownTypeLineSkipped, testing::ext::TestSize.Level0)
{
    ASSERT_TRUE(WriteCfgFileChecked("certRevocationPolicy_cloud.cfg", "3,xxx\nfoo\nbar\n"));
    HcfX509Certificate *cert = CreateCertFromPem(TEST_REVOC_LEAF_PEM);
    ASSERT_NE(cert, nullptr);
    HcfX509Certificate *certs[] = { cert };
    HcfX509CertificateArray arr = { certs, 1 };
    int32_t blockedIndex = -1;
    CfResult ret = HcfCertRevocationCheck(&arr, &blockedIndex);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(blockedIndex, -1);
    DestroyCert(cert);
}

HWTEST_F(RevocationTest, Type1HexCaseInsensitive, testing::ext::TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_REVOC_LEAF_PEM);
    ASSERT_NE(cert, nullptr);
    uint8_t digest[REVOCATION_HASH_LEN];
    ASSERT_TRUE(GetCertSpkiSha256(cert, digest));
    char hex[REVOCATION_HASH_LEN * REVOCATION_TEST_HEX_CHARS_PER_BYTE + 1];
    BytesToHex(digest, REVOCATION_HASH_LEN, hex);
    /* Convert to mixed case to test case-insensitivity */
    int hexLen = REVOCATION_HASH_LEN * REVOCATION_TEST_HEX_CHARS_PER_BYTE;
    for (int i = 0; i < hexLen; i += REVOCATION_TEST_HEX_CHARS_PER_BYTE) {
        if (hex[i] >= 'a' && hex[i] <= 'f') {
            hex[i] -= 'a' - 'A';
        }
    }
    char cfgLine[REVOCATION_TEST_CFG_LINE_LEN];
    if (snprintf_s(cfgLine, sizeof(cfgLine), sizeof(cfgLine) - 1, "1,%s\n", hex) < 0) {
        DestroyCert(cert);
        FAIL() << "snprintf_s failed.";
        return;
    }
    ASSERT_TRUE(WriteCfgFileChecked("certRevocationPolicy_cloud.cfg", cfgLine));

    HcfX509Certificate *certs[] = { cert };
    HcfX509CertificateArray arr = { certs, 1 };
    int32_t blockedIndex = -1;
    CfResult ret = HcfCertRevocationCheck(&arr, &blockedIndex);
    EXPECT_EQ(ret, CF_ERR_CERT_REVOKED);
    EXPECT_EQ(blockedIndex, 0);
    DestroyCert(cert);
}

HWTEST_F(RevocationTest, ClearCacheAndReload, testing::ext::TestSize.Level0)
{
    ASSERT_TRUE(WriteCfgFileChecked("certRevocationPolicy_cloud.cfg", REVOCATION_TEST_ZERO_HASH));
    HcfX509Certificate *cert = CreateCertFromPem(TEST_REVOC_LEAF_PEM);
    ASSERT_NE(cert, nullptr);
    HcfX509Certificate *certs[] = { cert };
    HcfX509CertificateArray arr = { certs, 1 };
    int32_t blockedIndex = -1;
    CfResult ret = HcfCertRevocationCheck(&arr, &blockedIndex);
    EXPECT_EQ(ret, CF_SUCCESS);

    HcfCertRevocationClearCache();

    uint8_t digest[REVOCATION_HASH_LEN];
    ASSERT_TRUE(GetCertSpkiSha256(cert, digest));
    char hex[REVOCATION_HASH_LEN * REVOCATION_TEST_HEX_CHARS_PER_BYTE + 1];
    BytesToHex(digest, REVOCATION_HASH_LEN, hex);
    char cfgLine[REVOCATION_TEST_CFG_LINE_LEN];
    if (snprintf_s(cfgLine, sizeof(cfgLine), sizeof(cfgLine) - 1, "1,%s\n", hex) < 0) {
        DestroyCert(cert);
        FAIL() << "snprintf_s failed.";
        return;
    }
    ASSERT_TRUE(WriteCfgFileChecked("certRevocationPolicy_cloud.cfg", cfgLine));

    ret = HcfCertRevocationCheck(&arr, &blockedIndex);
    EXPECT_EQ(ret, CF_ERR_CERT_REVOKED);
    EXPECT_EQ(blockedIndex, 0);
    DestroyCert(cert);
}

HWTEST_F(RevocationTest, CrLfLineEndings, testing::ext::TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_REVOC_LEAF_PEM);
    ASSERT_NE(cert, nullptr);
    uint8_t digest[REVOCATION_HASH_LEN];
    ASSERT_TRUE(GetCertSpkiSha256(cert, digest));
    char hex[REVOCATION_HASH_LEN * REVOCATION_TEST_HEX_CHARS_PER_BYTE + 1];
    BytesToHex(digest, REVOCATION_HASH_LEN, hex);
    char cfgLine[REVOCATION_TEST_CFG_LINE_LEN];
    if (snprintf_s(cfgLine, sizeof(cfgLine), sizeof(cfgLine) - 1, "1,%s\r\n", hex) < 0) {
        DestroyCert(cert);
        FAIL() << "snprintf_s failed.";
        return;
    }
    ASSERT_TRUE(WriteCfgFileChecked("certRevocationPolicy_cloud.cfg", cfgLine));

    HcfX509Certificate *certs[] = { cert };
    HcfX509CertificateArray arr = { certs, 1 };
    int32_t blockedIndex = -1;
    CfResult ret = HcfCertRevocationCheck(&arr, &blockedIndex);
    EXPECT_EQ(ret, CF_ERR_CERT_REVOKED);
    EXPECT_EQ(blockedIndex, 0);
    DestroyCert(cert);
}

HWTEST_F(RevocationTest, MultiCertChainFirstMatch, testing::ext::TestSize.Level0)
{
    HcfX509Certificate *cert1 = CreateCertFromPem(TEST_REVOC_ROOT_PEM);
    HcfX509Certificate *cert2 = CreateCertFromPem(TEST_REVOC_LEAF_PEM);
    ASSERT_NE(cert1, nullptr);
    ASSERT_NE(cert2, nullptr);
    uint8_t digest[REVOCATION_HASH_LEN];
    ASSERT_TRUE(GetCertSpkiSha256(cert2, digest));
    char hex[REVOCATION_HASH_LEN * REVOCATION_TEST_HEX_CHARS_PER_BYTE + 1];
    BytesToHex(digest, REVOCATION_HASH_LEN, hex);
    char cfgLine[REVOCATION_TEST_CFG_LINE_LEN];
    if (snprintf_s(cfgLine, sizeof(cfgLine), sizeof(cfgLine) - 1, "1,%s\n", hex) < 0) {
        DestroyCert(cert1);
        DestroyCert(cert2);
        FAIL() << "snprintf_s failed.";
        return;
    }
    ASSERT_TRUE(WriteCfgFileChecked("certRevocationPolicy_cloud.cfg", cfgLine));

    HcfX509Certificate *certs[] = { cert1, cert2 };
    HcfX509CertificateArray arr = { certs, REVOCATION_TEST_MULTI_CERT_COUNT };
    int32_t blockedIndex = -1;
    CfResult ret = HcfCertRevocationCheck(&arr, &blockedIndex);
    EXPECT_EQ(ret, CF_ERR_CERT_REVOKED);
    EXPECT_EQ(blockedIndex, 1);
    DestroyCert(cert1);
    DestroyCert(cert2);
}

HWTEST_F(RevocationTest, Type2AkiTimeRangeMatch, testing::ext::TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_REVOC_LEAF_PEM);
    ASSERT_NE(cert, nullptr);
    uint8_t aki[REVOCATION_AKI_LEN];
    ASSERT_TRUE(GetCertAkiKeyId(cert, aki));
    uint32_t notBefore = 0;
    ASSERT_TRUE(GetCertNotBeforeDate(cert, &notBefore));
    char akiHex[REVOCATION_TEST_AKI_HEX_LEN + 1];
    BytesToHex(aki, REVOCATION_AKI_LEN, akiHex);
    uint32_t year = notBefore / REVOCATION_YEAR_MONTH_DIVISOR;
    uint32_t monthDay = notBefore % REVOCATION_YEAR_MONTH_DIVISOR;
    char cfgLine[REVOCATION_TEST_TYPE2_CFG_LEN];
    if (snprintf_s(cfgLine, sizeof(cfgLine), sizeof(cfgLine) - 1,
        "2,%s,%04u%04u-\n", akiHex, year, monthDay) < 0) {
        DestroyCert(cert);
        FAIL() << "snprintf_s failed.";
        return;
    }
    ASSERT_TRUE(WriteCfgFileChecked("certRevocationPolicy_cloud.cfg", cfgLine));

    HcfX509Certificate *certs[] = { cert };
    HcfX509CertificateArray arr = { certs, 1 };
    int32_t blockedIndex = -1;
    CfResult ret = HcfCertRevocationCheck(&arr, &blockedIndex);
    EXPECT_EQ(ret, CF_ERR_CERT_REVOKED);
    EXPECT_EQ(blockedIndex, 0);
    DestroyCert(cert);
}

HWTEST_F(RevocationTest, Type2AkiTimeRangeNoMatch, testing::ext::TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_REVOC_LEAF_PEM);
    ASSERT_NE(cert, nullptr);
    uint8_t aki[REVOCATION_AKI_LEN];
    ASSERT_TRUE(GetCertAkiKeyId(cert, aki));
    char akiHex[REVOCATION_TEST_AKI_HEX_LEN + 1];
    BytesToHex(aki, REVOCATION_AKI_LEN, akiHex);
    char cfgLine[REVOCATION_TEST_TYPE2_CFG_LEN];
    if (snprintf_s(cfgLine, sizeof(cfgLine), sizeof(cfgLine) - 1,
        "2,%s,20990101-\n", akiHex) < 0) {
        DestroyCert(cert);
        FAIL() << "snprintf_s failed.";
        return;
    }
    ASSERT_TRUE(WriteCfgFileChecked("certRevocationPolicy_cloud.cfg", cfgLine));

    HcfX509Certificate *certs[] = { cert };
    HcfX509CertificateArray arr = { certs, 1 };
    int32_t blockedIndex = -1;
    CfResult ret = HcfCertRevocationCheck(&arr, &blockedIndex);
    /* Rule start=20990101, cert notBefore=20261111 < 20990101 → NOT revoked */
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(blockedIndex, -1);
    DestroyCert(cert);
}

/* ===== Multi-thread concurrency tests (rwlock) ===== */

#define REVOCATION_TEST_THREAD_COUNT 8
#define REVOCATION_TEST_THREAD_ITERATIONS 20
#define REVOCATION_TEST_THREAD_DELAY 1000

static void *ThreadQueryWorker(void *arg)
{
    HcfX509CertificateArray *arr = static_cast<HcfX509CertificateArray *>(arg);
    for (int i = 0; i < REVOCATION_TEST_THREAD_ITERATIONS; i++) {
        int32_t blockedIndex = -1;
        CfResult ret = HcfCertRevocationCheck(arr, &blockedIndex);
        if (ret != CF_SUCCESS && ret != CF_ERR_CERT_REVOKED) {
            return reinterpret_cast<void *>(static_cast<intptr_t>(-1));
        }
    }
    return nullptr;
}

typedef struct {
    HcfX509CertificateArray *arr;
    int32_t revokedCount;
} RevocationQueryStats;

/* Query repeatedly and record how many times the cert was reported revoked.
 * Used by the concurrent load+match phase to detect matching regressions. */
static void *ThreadQueryExpectRevokedWorker(void *arg)
{
    RevocationQueryStats *stats = static_cast<RevocationQueryStats *>(arg);
    stats->revokedCount = 0;
    for (int i = 0; i < REVOCATION_TEST_THREAD_ITERATIONS; i++) {
        int32_t blockedIndex = -1;
        CfResult ret = HcfCertRevocationCheck(stats->arr, &blockedIndex);
        if (ret == CF_ERR_CERT_REVOKED) {
            stats->revokedCount++;
            continue;
        }
        if (ret != CF_SUCCESS) {
            return reinterpret_cast<void *>(static_cast<intptr_t>(-1));
        }
    }
    return nullptr;
}

static void *ThreadClearWorker(void *arg)
{
    for (int i = 0; i < REVOCATION_TEST_THREAD_ITERATIONS; i++) {
        HcfCertRevocationClearCache();
        usleep(REVOCATION_TEST_THREAD_DELAY);
    }
    return nullptr;
}

/* Concurrent first-load: multiple threads race to load the cache (DCL path).
 * All threads must get consistent results, no crash, no deadlock. */
HWTEST_F(RevocationTest, ConcurrentFirstQuery, testing::ext::TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_REVOC_LEAF_PEM);
    ASSERT_NE(cert, nullptr);
    HcfX509Certificate *certs[] = { cert };
    HcfX509CertificateArray arr = { certs, 1 };

    /* No policy files: threads race to load an empty cache */
    HcfCertRevocationClearCache();
    pthread_t threads[REVOCATION_TEST_THREAD_COUNT];
    for (int i = 0; i < REVOCATION_TEST_THREAD_COUNT; i++) {
        ASSERT_EQ(pthread_create(&threads[i], nullptr, ThreadQueryWorker, &arr), 0);
    }
    for (int i = 0; i < REVOCATION_TEST_THREAD_COUNT; i++) {
        void *res = nullptr;
        ASSERT_EQ(pthread_join(threads[i], &res), 0);
        EXPECT_EQ(res, nullptr);
    }

    /* With a policy file matching the cert: threads race to load + match */
    uint8_t digest[REVOCATION_HASH_LEN];
    ASSERT_TRUE(GetCertSpkiSha256(cert, digest));
    char hex[REVOCATION_HASH_LEN * REVOCATION_TEST_HEX_CHARS_PER_BYTE + 1];
    BytesToHex(digest, REVOCATION_HASH_LEN, hex);
    char cfgLine[REVOCATION_TEST_CFG_LINE_LEN];
    if (snprintf_s(cfgLine, sizeof(cfgLine), sizeof(cfgLine) - 1, "1,%s\n", hex) < 0) {
        DestroyCert(cert);
        FAIL() << "snprintf_s failed.";
        return;
    }
    ASSERT_TRUE(WriteCfgFileChecked("certRevocationPolicy_cloud.cfg", cfgLine));
    HcfCertRevocationClearCache();

    RevocationQueryStats stats[REVOCATION_TEST_THREAD_COUNT];
    for (int i = 0; i < REVOCATION_TEST_THREAD_COUNT; i++) {
        stats[i].arr = &arr;
        stats[i].revokedCount = 0;
        ASSERT_EQ(pthread_create(&threads[i], nullptr, ThreadQueryExpectRevokedWorker, &stats[i]), 0);
    }
    int32_t hitThreadCount = 0;
    for (int i = 0; i < REVOCATION_TEST_THREAD_COUNT; i++) {
        void *res = nullptr;
        ASSERT_EQ(pthread_join(threads[i], &res), 0);
        EXPECT_EQ(res, nullptr);
        if (stats[i].revokedCount > 0) {
            hitThreadCount++;
        }
    }
    /* Every query should hit the matching rule; at minimum the load+match path
     * must be exercised by some thread, otherwise a matching regression would
     * be indistinguishable from CF_SUCCESS. */
    EXPECT_GT(hitThreadCount, 0);
    DestroyCert(cert);
}

/* Query threads racing with clear thread: ClearAll takes write lock,
 * queries take read locks. Must not deadlock, crash, or return errors. */
HWTEST_F(RevocationTest, ConcurrentQueryAndClear, testing::ext::TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_REVOC_LEAF_PEM);
    ASSERT_NE(cert, nullptr);
    uint8_t digest[REVOCATION_HASH_LEN];
    ASSERT_TRUE(GetCertSpkiSha256(cert, digest));
    char hex[REVOCATION_HASH_LEN * REVOCATION_TEST_HEX_CHARS_PER_BYTE + 1];
    BytesToHex(digest, REVOCATION_HASH_LEN, hex);
    char cfgLine[REVOCATION_TEST_CFG_LINE_LEN];
    if (snprintf_s(cfgLine, sizeof(cfgLine), sizeof(cfgLine) - 1, "1,%s\n", hex) < 0) {
        DestroyCert(cert);
        FAIL() << "snprintf_s failed.";
        return;
    }
    ASSERT_TRUE(WriteCfgFileChecked("certRevocationPolicy_cloud.cfg", cfgLine));

    HcfX509Certificate *certs[] = { cert };
    HcfX509CertificateArray arr = { certs, 1 };
    HcfCertRevocationClearCache();

    pthread_t queryThreads[REVOCATION_TEST_THREAD_COUNT];
    pthread_t clearThread;
    for (int i = 0; i < REVOCATION_TEST_THREAD_COUNT; i++) {
        ASSERT_EQ(pthread_create(&queryThreads[i], nullptr, ThreadQueryWorker, &arr), 0);
    }
    ASSERT_EQ(pthread_create(&clearThread, nullptr, ThreadClearWorker, nullptr), 0);

    for (int i = 0; i < REVOCATION_TEST_THREAD_COUNT; i++) {
        void *res = nullptr;
        ASSERT_EQ(pthread_join(queryThreads[i], &res), 0);
        EXPECT_EQ(res, nullptr);
    }
    void *clearRes = nullptr;
    ASSERT_EQ(pthread_join(clearThread, &clearRes), 0);
    EXPECT_EQ(clearRes, nullptr);
    DestroyCert(cert);
}

/* Mixed hit/miss queries in parallel: threads query the same cert while cache
 * is loaded with a matching rule — all must observe REVOKED (or transient
 * CF_SUCCESS during clear), never an error. */
HWTEST_F(RevocationTest, ConcurrentQueryAfterReload, testing::ext::TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_REVOC_NEW_INTER3_PEM);
    ASSERT_NE(cert, nullptr);
    /* Type-2 rule: AKI matches, time range covers cert notBefore */
    ASSERT_TRUE(WriteCfgFileChecked("certRevocationPolicy_cloud.cfg",
        "2,86ED0851D69D6737389DE94916856696716E3040,-20990101\n"));
    HcfX509Certificate *certs[] = { cert };
    HcfX509CertificateArray arr = { certs, 1 };
    HcfCertRevocationClearCache();

    pthread_t threads[REVOCATION_TEST_THREAD_COUNT];
    for (int i = 0; i < REVOCATION_TEST_THREAD_COUNT; i++) {
        ASSERT_EQ(pthread_create(&threads[i], nullptr, ThreadQueryWorker, &arr), 0);
    }
    for (int i = 0; i < REVOCATION_TEST_THREAD_COUNT; i++) {
        void *res = nullptr;
        ASSERT_EQ(pthread_join(threads[i], &res), 0);
        EXPECT_EQ(res, nullptr);
    }
    DestroyCert(cert);
}

HWTEST_F(RevocationTest, Type2OpenEndRangeMatch, testing::ext::TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_REVOC_LEAF_PEM);
    ASSERT_NE(cert, nullptr);
    uint8_t aki[REVOCATION_AKI_LEN];
    ASSERT_TRUE(GetCertAkiKeyId(cert, aki));
    uint32_t notBefore = 0;
    ASSERT_TRUE(GetCertNotBeforeDate(cert, &notBefore));
    char akiHex[REVOCATION_TEST_AKI_HEX_LEN + 1];
    BytesToHex(aki, REVOCATION_AKI_LEN, akiHex);
    uint32_t year = notBefore / REVOCATION_YEAR_MONTH_DIVISOR;
    uint32_t monthDay = notBefore % REVOCATION_YEAR_MONTH_DIVISOR;
    char cfgLine[REVOCATION_TEST_TYPE2_CFG_LEN];
    if (snprintf_s(cfgLine, sizeof(cfgLine), sizeof(cfgLine) - 1,
        "2,%s,-%04u%04u\n", akiHex, year, monthDay) < 0) {
        DestroyCert(cert);
        FAIL() << "snprintf_s failed.";
        return;
    }
    ASSERT_TRUE(WriteCfgFileChecked("certRevocationPolicy_cloud.cfg", cfgLine));

    HcfX509Certificate *certs[] = { cert };
    HcfX509CertificateArray arr = { certs, 1 };
    int32_t blockedIndex = -1;
    CfResult ret = HcfCertRevocationCheck(&arr, &blockedIndex);
    EXPECT_EQ(ret, CF_ERR_CERT_REVOKED);
    EXPECT_EQ(blockedIndex, 0);
    DestroyCert(cert);
}

HWTEST_F(RevocationTest, Type2MultipleRangesMatch, testing::ext::TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_REVOC_LEAF_PEM);
    ASSERT_NE(cert, nullptr);
    uint8_t aki[REVOCATION_AKI_LEN];
    ASSERT_TRUE(GetCertAkiKeyId(cert, aki));
    uint32_t notBefore = 0;
    ASSERT_TRUE(GetCertNotBeforeDate(cert, &notBefore));
    char akiHex[REVOCATION_TEST_AKI_HEX_LEN + 1];
    BytesToHex(aki, REVOCATION_AKI_LEN, akiHex);
    uint32_t year = notBefore / REVOCATION_YEAR_MONTH_DIVISOR;
    uint32_t monthDay = notBefore % REVOCATION_YEAR_MONTH_DIVISOR;
    char cfgLine[REVOCATION_TEST_TYPE2_DUP_CFG_LEN];
    if (snprintf_s(cfgLine, sizeof(cfgLine), sizeof(cfgLine) - 1,
        "2,%s,20990101-20991212,%04u%04u-\n", akiHex, year, monthDay) < 0) {
        DestroyCert(cert);
        FAIL() << "snprintf_s failed.";
        return;
    }
    ASSERT_TRUE(WriteCfgFileChecked("certRevocationPolicy_cloud.cfg", cfgLine));

    HcfX509Certificate *certs[] = { cert };
    HcfX509CertificateArray arr = { certs, 1 };
    int32_t blockedIndex = -1;
    CfResult ret = HcfCertRevocationCheck(&arr, &blockedIndex);
    EXPECT_EQ(ret, CF_ERR_CERT_REVOKED);
    EXPECT_EQ(blockedIndex, 0);
    DestroyCert(cert);
}

HWTEST_F(RevocationTest, Type2AkiNotFound, testing::ext::TestSize.Level0)
{
    ASSERT_TRUE(WriteCfgFileChecked("certRevocationPolicy_cloud.cfg",
        "2,0000000000000000000000000000000000000000,-20990101\n"));
    HcfX509Certificate *cert = CreateCertFromPem(TEST_REVOC_LEAF_PEM);
    ASSERT_NE(cert, nullptr);
    HcfX509Certificate *certs[] = { cert };
    HcfX509CertificateArray arr = { certs, 1 };
    int32_t blockedIndex = -1;
    CfResult ret = HcfCertRevocationCheck(&arr, &blockedIndex);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(blockedIndex, -1);
    DestroyCert(cert);
}

HWTEST_F(RevocationTest, Type2InvalidAkiSkipped, testing::ext::TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_REVOC_LEAF_PEM);
    ASSERT_NE(cert, nullptr);
    uint8_t aki[REVOCATION_AKI_LEN];
    ASSERT_TRUE(GetCertAkiKeyId(cert, aki));
    char akiHex[REVOCATION_TEST_AKI_HEX_LEN + 1];
    BytesToHex(aki, REVOCATION_AKI_LEN, akiHex);
    char cfgLine[REVOCATION_TEST_TYPE2_DUP_CFG_LEN];
    if (snprintf_s(cfgLine, sizeof(cfgLine), sizeof(cfgLine) - 1,
        "2,short,20990101-\n2,%s,-20990101\n", akiHex) < 0) {
        DestroyCert(cert);
        FAIL() << "snprintf_s failed.";
        return;
    }
    ASSERT_TRUE(WriteCfgFileChecked("certRevocationPolicy_cloud.cfg", cfgLine));

    HcfX509Certificate *certs[] = { cert };
    HcfX509CertificateArray arr = { certs, 1 };
    int32_t blockedIndex = -1;
    CfResult ret = HcfCertRevocationCheck(&arr, &blockedIndex);
    EXPECT_EQ(ret, CF_ERR_CERT_REVOKED);
    EXPECT_EQ(blockedIndex, 0);
    DestroyCert(cert);
}

HWTEST_F(RevocationTest, Type2InvalidTimeSegmentSkipped, testing::ext::TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_REVOC_LEAF_PEM);
    ASSERT_NE(cert, nullptr);
    uint8_t aki[REVOCATION_AKI_LEN];
    ASSERT_TRUE(GetCertAkiKeyId(cert, aki));
    char akiHex[REVOCATION_TEST_AKI_HEX_LEN + 1];
    BytesToHex(aki, REVOCATION_AKI_LEN, akiHex);
    char cfgLine[REVOCATION_TEST_TYPE2_DUP_CFG_LEN];
    if (snprintf_s(cfgLine, sizeof(cfgLine), sizeof(cfgLine) - 1,
        "2,%s,BADSEG,-20990101\n", akiHex) < 0) {
        DestroyCert(cert);
        FAIL() << "snprintf_s failed.";
        return;
    }
    ASSERT_TRUE(WriteCfgFileChecked("certRevocationPolicy_cloud.cfg", cfgLine));

    HcfX509Certificate *certs[] = { cert };
    HcfX509CertificateArray arr = { certs, 1 };
    int32_t blockedIndex = -1;
    CfResult ret = HcfCertRevocationCheck(&arr, &blockedIndex);
    EXPECT_EQ(ret, CF_ERR_CERT_REVOKED);
    EXPECT_EQ(blockedIndex, 0);
    DestroyCert(cert);
}

HWTEST_F(RevocationTest, Type2DuplicateAkiDeduped, testing::ext::TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_REVOC_LEAF_PEM);
    ASSERT_NE(cert, nullptr);
    uint8_t aki[REVOCATION_AKI_LEN];
    ASSERT_TRUE(GetCertAkiKeyId(cert, aki));
    char akiHex[REVOCATION_TEST_AKI_HEX_LEN + 1];
    BytesToHex(aki, REVOCATION_AKI_LEN, akiHex);
    char cfgLine[REVOCATION_TEST_TYPE2_DUP_CFG_LEN];
    if (snprintf_s(cfgLine, sizeof(cfgLine), sizeof(cfgLine) - 1,
        "2,%s,-20990101\n2,%s,-20990101\n", akiHex, akiHex) < 0) {
        DestroyCert(cert);
        FAIL() << "snprintf_s failed.";
        return;
    }
    ASSERT_TRUE(WriteCfgFileChecked("certRevocationPolicy_cloud.cfg", cfgLine));

    HcfX509Certificate *certs[] = { cert };
    HcfX509CertificateArray arr = { certs, 1 };
    int32_t blockedIndex = -1;
    CfResult ret = HcfCertRevocationCheck(&arr, &blockedIndex);
    EXPECT_EQ(ret, CF_ERR_CERT_REVOKED);
    EXPECT_EQ(blockedIndex, 0);
    DestroyCert(cert);
}

HWTEST_F(RevocationTest, Type2UserMatch, testing::ext::TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_REVOC_LEAF_PEM);
    ASSERT_NE(cert, nullptr);
    uint8_t aki[REVOCATION_AKI_LEN];
    ASSERT_TRUE(GetCertAkiKeyId(cert, aki));
    char akiHex[REVOCATION_TEST_AKI_HEX_LEN + 1];
    BytesToHex(aki, REVOCATION_AKI_LEN, akiHex);
    char cfgLine[REVOCATION_TEST_TYPE2_CFG_LEN];
    if (snprintf_s(cfgLine, sizeof(cfgLine), sizeof(cfgLine) - 1,
        "2,%s,-20990101\n", akiHex) < 0) {
        DestroyCert(cert);
        FAIL() << "snprintf_s failed.";
        return;
    }
    ASSERT_TRUE(WriteCfgFileChecked("certRevocationPolicy_user.cfg", cfgLine));

    HcfX509Certificate *certs[] = { cert };
    HcfX509CertificateArray arr = { certs, 1 };
    int32_t blockedIndex = -1;
    CfResult ret = HcfCertRevocationCheck(&arr, &blockedIndex);
    EXPECT_EQ(ret, CF_ERR_CERT_REVOKED);
    EXPECT_EQ(blockedIndex, 0);
    DestroyCert(cert);
}

HWTEST_F(RevocationTest, Type2EndBoundRangeCloudMatch, testing::ext::TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_REVOC_LEAF_PEM);
    ASSERT_NE(cert, nullptr);
    uint8_t aki[REVOCATION_AKI_LEN];
    ASSERT_TRUE(GetCertAkiKeyId(cert, aki));
    char akiHex[REVOCATION_TEST_AKI_HEX_LEN + 1];
    BytesToHex(aki, REVOCATION_AKI_LEN, akiHex);
    char cfgLine[REVOCATION_TEST_TYPE2_CFG_LEN];
    if (snprintf_s(cfgLine, sizeof(cfgLine), sizeof(cfgLine) - 1,
        "2,%s,-20990101\n", akiHex) < 0) {
        DestroyCert(cert);
        FAIL() << "snprintf_s failed.";
        return;
    }
    ASSERT_TRUE(WriteCfgFileChecked("certRevocationPolicy_cloud.cfg", cfgLine));

    HcfX509Certificate *certs[] = { cert };
    HcfX509CertificateArray arr = { certs, 1 };
    int32_t blockedIndex = -1;
    CfResult ret = HcfCertRevocationCheck(&arr, &blockedIndex);
    EXPECT_EQ(ret, CF_ERR_CERT_REVOKED);
    EXPECT_EQ(blockedIndex, 0);
    DestroyCert(cert);
}

HWTEST_F(RevocationTest, Type2CloudAndUserUnion, testing::ext::TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_REVOC_LEAF_PEM);
    ASSERT_NE(cert, nullptr);
    uint8_t aki[REVOCATION_AKI_LEN];
    ASSERT_TRUE(GetCertAkiKeyId(cert, aki));
    char akiHex[REVOCATION_TEST_AKI_HEX_LEN + 1];
    BytesToHex(aki, REVOCATION_AKI_LEN, akiHex);
    ASSERT_TRUE(WriteCfgFileChecked("certRevocationPolicy_cloud.cfg",
        "2,0000000000000000000000000000000000000000,-20990101\n"));
    char cfgLine[REVOCATION_TEST_TYPE2_CFG_LEN];
    if (snprintf_s(cfgLine, sizeof(cfgLine), sizeof(cfgLine) - 1,
        "2,%s,-20990101\n", akiHex) < 0) {
        DestroyCert(cert);
        FAIL() << "snprintf_s failed.";
        return;
    }
    ASSERT_TRUE(WriteCfgFileChecked("certRevocationPolicy_user.cfg", cfgLine));

    HcfX509Certificate *certs[] = { cert };
    HcfX509CertificateArray arr = { certs, 1 };
    int32_t blockedIndex = -1;
    CfResult ret = HcfCertRevocationCheck(&arr, &blockedIndex);
    EXPECT_EQ(ret, CF_ERR_CERT_REVOKED);
    EXPECT_EQ(blockedIndex, 0);
    DestroyCert(cert);
}

HWTEST_F(RevocationTest, Type1AndType2BothPresent, testing::ext::TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_REVOC_LEAF_PEM);
    ASSERT_NE(cert, nullptr);
    uint8_t digest[REVOCATION_HASH_LEN];
    ASSERT_TRUE(GetCertSpkiSha256(cert, digest));
    char hex[REVOCATION_HASH_LEN * REVOCATION_TEST_HEX_CHARS_PER_BYTE + 1];
    BytesToHex(digest, REVOCATION_HASH_LEN, hex);
    uint8_t aki[REVOCATION_AKI_LEN];
    ASSERT_TRUE(GetCertAkiKeyId(cert, aki));
    char akiHex[REVOCATION_TEST_AKI_HEX_LEN + 1];
    BytesToHex(aki, REVOCATION_AKI_LEN, akiHex);
    char cfgLine[REVOCATION_TEST_TYPE2_DUP_CFG_LEN];
    if (snprintf_s(cfgLine, sizeof(cfgLine), sizeof(cfgLine) - 1,
        "1,%s\n2,%s,-20990101\n", hex, akiHex) < 0) {
        DestroyCert(cert);
        FAIL() << "snprintf_s failed.";
        return;
    }
    ASSERT_TRUE(WriteCfgFileChecked("certRevocationPolicy_cloud.cfg", cfgLine));

    HcfX509Certificate *certs[] = { cert };
    HcfX509CertificateArray arr = { certs, 1 };
    int32_t blockedIndex = -1;
    CfResult ret = HcfCertRevocationCheck(&arr, &blockedIndex);
    EXPECT_EQ(ret, CF_ERR_CERT_REVOKED);
    EXPECT_EQ(blockedIndex, 0);
    DestroyCert(cert);
}

HWTEST_F(RevocationTest, Type1MatchType2NoMatch, testing::ext::TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_REVOC_LEAF_PEM);
    ASSERT_NE(cert, nullptr);
    uint8_t digest[REVOCATION_HASH_LEN];
    ASSERT_TRUE(GetCertSpkiSha256(cert, digest));
    char hex[REVOCATION_HASH_LEN * REVOCATION_TEST_HEX_CHARS_PER_BYTE + 1];
    BytesToHex(digest, REVOCATION_HASH_LEN, hex);
    char cfgLine[REVOCATION_TEST_TYPE2_DUP_CFG_LEN];
    if (snprintf_s(cfgLine, sizeof(cfgLine), sizeof(cfgLine) - 1,
        "1,%s\n2,%s,20990101-\n", hex,
        "0000000000000000000000000000000000000000") < 0) {
        DestroyCert(cert);
        FAIL() << "snprintf_s failed.";
        return;
    }
    ASSERT_TRUE(WriteCfgFileChecked("certRevocationPolicy_cloud.cfg", cfgLine));

    HcfX509Certificate *certs[] = { cert };
    HcfX509CertificateArray arr = { certs, 1 };
    int32_t blockedIndex = -1;
    CfResult ret = HcfCertRevocationCheck(&arr, &blockedIndex);
    EXPECT_EQ(ret, CF_ERR_CERT_REVOKED);
    EXPECT_EQ(blockedIndex, 0);
    DestroyCert(cert);
}

HWTEST_F(RevocationTest, Type1NoMatchType2Match, testing::ext::TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_REVOC_LEAF_PEM);
    ASSERT_NE(cert, nullptr);
    uint8_t aki[REVOCATION_AKI_LEN];
    ASSERT_TRUE(GetCertAkiKeyId(cert, aki));
    char akiHex[REVOCATION_TEST_AKI_HEX_LEN + 1];
    BytesToHex(aki, REVOCATION_AKI_LEN, akiHex);
    char cfgLine[REVOCATION_TEST_TYPE2_DUP_CFG_LEN];
    if (snprintf_s(cfgLine, sizeof(cfgLine), sizeof(cfgLine) - 1,
        "1,%s\n2,%s,-20990101\n",
        "0000000000000000000000000000000000000000000000000000000000000000",
        akiHex) < 0) {
        DestroyCert(cert);
        FAIL() << "snprintf_s failed.";
        return;
    }
    ASSERT_TRUE(WriteCfgFileChecked("certRevocationPolicy_cloud.cfg", cfgLine));

    HcfX509Certificate *certs[] = { cert };
    HcfX509CertificateArray arr = { certs, 1 };
    int32_t blockedIndex = -1;
    CfResult ret = HcfCertRevocationCheck(&arr, &blockedIndex);
    EXPECT_EQ(ret, CF_ERR_CERT_REVOKED);
    EXPECT_EQ(blockedIndex, 0);
    DestroyCert(cert);
}

HWTEST_F(RevocationTest, Type1DuplicateHashDeduped, testing::ext::TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_REVOC_LEAF_PEM);
    ASSERT_NE(cert, nullptr);
    uint8_t digest[REVOCATION_HASH_LEN];
    ASSERT_TRUE(GetCertSpkiSha256(cert, digest));
    char hex[REVOCATION_HASH_LEN * REVOCATION_TEST_HEX_CHARS_PER_BYTE + 1];
    BytesToHex(digest, REVOCATION_HASH_LEN, hex);
    char cfgLine[REVOCATION_TEST_CFG_LINE_DUP_LEN];
    if (snprintf_s(cfgLine, sizeof(cfgLine), sizeof(cfgLine) - 1, "1,%s\n1,%s\n", hex, hex) < 0) {
        DestroyCert(cert);
        FAIL() << "snprintf_s failed.";
        return;
    }
    ASSERT_TRUE(WriteCfgFileChecked("certRevocationPolicy_cloud.cfg", cfgLine));

    HcfX509Certificate *certs[] = { cert };
    HcfX509CertificateArray arr = { certs, 1 };
    int32_t blockedIndex = -1;
    CfResult ret = HcfCertRevocationCheck(&arr, &blockedIndex);
    EXPECT_EQ(ret, CF_ERR_CERT_REVOKED);
    EXPECT_EQ(blockedIndex, 0);
    DestroyCert(cert);
}
