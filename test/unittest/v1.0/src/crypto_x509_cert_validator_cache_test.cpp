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


#include <cstring>

#include <openssl/obj_mac.h>

#include "crypto_x509_cert_validator_test_common.h"
#include "revocation_cache_interface.h"
#include "revocation_cache_mock.h"
#include "x509_cert_chain_validator_openssl_private.h"

using namespace testing::ext;
using namespace CFMock;
using ::testing::Mock;
using ::testing::Invoke;
using ::testing::WithoutArgs;
using ::testing::Return;
using ::testing::_;

/* Provided by cf_mock.cpp: the certificate added when loading the system CA directory */
/* (used to make IsTrustAnchorSystemCa return true) */
extern "C" X509 *g_mockSystemCaCert;
/* Provided by cf_mock.cpp: mock switches/counters for covering the BuildSystemCaStore branches */
extern "C" int g_mockX509StoreNewFailAt;
extern "C" int g_mockLoadLocationsFailAt;
extern "C" int g_x509StoreNewCallCount;
extern "C" int g_loadLocationsCallCount;
extern "C" int __real_X509_verify_cert(X509_STORE_CTX *ctx);
extern "C" void *__real_X509_REVOKED_get_ext_d2i(const X509_REVOKED *x, int nid, int *crit, int *idx);

namespace {

/* Number of untrusted certificates (intermediate CA + OCSP signer) used in the OCSP validation cases. */
constexpr uint32_t OCSP_UNTRUSTED_CERT_COUNT = 2;

/* X509_verify_cert call ordinal of the CRL recheck after download / cache hit for the 1st / 2nd validation. */
constexpr int CRL_FIRST_RECHECK_CALL = 3;
constexpr int CRL_SECOND_RECHECK_CALL = 6;

/* Parses a PEM certificate into an OpenSSL X509, used to set the system CA mock certificate */
static X509 *X509FromPem(const char *pem)
{
    if (pem == nullptr) {
        return nullptr;
    }
    BIO *bio = BIO_new_mem_buf(pem, -1);
    if (bio == nullptr) {
        return nullptr;
    }
    X509 *x509 = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return x509;
}

/* Parses a PEM-encoded CRL into an OpenSSL X509_CRL, used to mock the download result */
static X509_CRL *CreateX509CrlFromPemData(const char *pem)
{
    if (pem == nullptr) {
        return nullptr;
    }
    BIO *bio = BIO_new_mem_buf(pem, -1);
    if (bio == nullptr) {
        return nullptr;
    }
    X509_CRL *crl = PEM_read_bio_X509_CRL(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return crl;
}

/* Creates the CDP test cert chain and fills the CRL check params with the revocation cache enabled. */
static void SetupCrlCacheStoreQuery(HcfX509Certificate **cert, HcfX509Certificate **intermediateCert,
    HcfX509Certificate **rootCert, HcfX509CertValidatorParams &params)
{
    *cert = CreateCertFromPem(TEST_END_ENTITY_FOR_CDP);
    *intermediateCert = CreateCertFromPem(TEST_INTERMEDIATE_CA_WITH_CDP);
    *rootCert = CreateCertFromPem(TEST_ROOT_CA_FOR_CDP);

    params.size = sizeof(HcfX509CertValidatorParams);
    params.trustSystemCa = true;
    params.validateDate = false;
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(CfMalloc(sizeof(HcfX509Certificate *), 0));
    params.trustedCerts.data[0] = *rootCert;
    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(CfMalloc(sizeof(HcfX509Certificate *), 0));
    params.untrustedCerts.data[0] = *intermediateCert;

    SetupCrlCheckParams(params, true);
    params.revokedParams->enableRevocationCache = true;
}

/* Mocks the CRL download and the 3rd/6th X509_verify_cert calls (download/cache-hit CRL recheck). */
static void SetupCrlCacheStoreMock(X509_CRL *mockCrl, int *verifyCallCount)
{
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_CRL_load_http(_, _, _, _))
        .WillRepeatedly(WithoutArgs(Invoke([mockCrl]() -> X509_CRL* {
            return X509_CRL_dup(mockCrl);
        })));
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_verify_cert(_))
        .WillRepeatedly(Invoke([verifyCallCount](X509_STORE_CTX *ctx) -> int {
            (*verifyCallCount)++;
            if (*verifyCallCount == CRL_FIRST_RECHECK_CALL || *verifyCallCount == CRL_SECOND_RECHECK_CALL) {
                return 1;
            }
            return __real_X509_verify_cert(ctx);
        }));
}

/* Creates the OCSP test cert chain and fills the online OCSP check params with the revocation cache enabled. */
static void SetupOcspCacheStoreCase(HcfX509Certificate **cert, HcfX509Certificate **caCert,
    HcfX509Certificate **intermediateCert, HcfX509Certificate **signerCert, HcfX509CertValidatorParams &params)
{
    *cert = CreateCertFromPem(OCSP_TEST_EE_VALID_URL);
    *caCert = CreateCertFromPem(OCSP_TEST_ROOT_CA);
    *intermediateCert = CreateCertFromPem(OCSP_TEST_INTERMEDIATE_CA);
    *signerCert = CreateCertFromPem(OCSP_TEST_SIGNER);

    params.size = sizeof(HcfX509CertValidatorParams);
    params.trustSystemCa = true;
    params.validateDate = false;
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(CfMalloc(sizeof(HcfX509Certificate *), 0));
    params.trustedCerts.data[0] = *caCert;
    params.untrustedCerts.count = OCSP_UNTRUSTED_CERT_COUNT;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *) * OCSP_UNTRUSTED_CERT_COUNT, 0));
    params.untrustedCerts.data[0] = *intermediateCert;
    params.untrustedCerts.data[1] = *signerCert;

    SetupOcspCheckParams(params, true);
    params.revokedParams->enableRevocationCache = true;
}

/* Creates the local-CRL revocation test setup: the cert chain, CRL check params, and one local CRL. */
static void SetupLocalCrlRevocationCase(HcfX509Certificate **cert, HcfX509Certificate **intermediateCert,
    HcfX509Certificate **rootCert, HcfX509CertValidatorParams &params)
{
    *cert = CreateCertFromPem(g_testCertChainPemNoRoot);
    *intermediateCert = CreateCertFromPem(g_testCertChainPemMid);
    *rootCert = CreateCertFromPem(g_testCertChainPemRoot);

    params.size = sizeof(HcfX509CertValidatorParams);
    params.trustSystemCa = false;
    params.validateDate = false;
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(CfMalloc(sizeof(HcfX509Certificate *), 0));
    params.trustedCerts.data[0] = *rootCert;
    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(CfMalloc(sizeof(HcfX509Certificate *), 0));
    params.untrustedCerts.data[0] = *intermediateCert;

    SetupCrlCheckParams(params, false);

    HcfX509Crl *crl = nullptr;
    CfEncodingBlob crlStream = { reinterpret_cast<uint8_t *>(const_cast<char *>(g_testCertChainPemMidCRL)),
        sizeof(g_testCertChainPemMidCRL), CF_FORMAT_PEM };
    (void)HcfX509CrlCreate(&crlStream, &crl);
    params.revokedParams->crls.count = 1;
    params.revokedParams->crls.data = static_cast<HcfX509Crl **>(CfMalloc(sizeof(HcfX509Crl *), 0));
    params.revokedParams->crls.data[0] = crl;
}

} // namespace

/**
 * @tc.name: ValidateX509Cert_EnableCache_WithoutSystemCa_001
 * @tc.desc: enableRevocationCache=true but trustSystemCa=false,
 * the three-level condition is not met so the cache is not enabled,
 *           and the original CRL check flow is used (returns CF_ERR_CRL_NOT_FOUND when there is no CRL and no download)
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_EnableCache_WithoutSystemCa_001, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_END_ENTITY_CERT);
    ASSERT_NE(cert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
    params.trustSystemCa = false;
    params.validateDate = false;
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = CreateCertFromPem(TEST_ROOT_CA_CERT);
    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = CreateCertFromPem(TEST_INTERMEDIATE_CA_CERT);

    SetupCrlCheckParams(params, false);
    params.revokedParams->enableRevocationCache = true;

    HcfCertVerifyResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res, CF_ERR_CRL_NOT_FOUND);
    FreeVerifyCertResult(result);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_EnableCache_TrustAnchorNotSystemCa_001
 * @tc.desc: enableRevocationCache=true and trustSystemCa=true,
 * but the trust anchor is not in the system CA (IsTrustAnchorSystemCa returns false),
 * the third-level condition is not met at runtime so the cache degrades,
 * and the original CRL check flow is used (returns CF_ERR_CRL_NOT_FOUND when there is no CRL and no download)
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_EnableCache_TrustAnchorNotSystemCa_001, TestSize.Level0)
{
    /* Do not set g_mockSystemCaCert, so systemCaStore is empty and IsTrustAnchorSystemCa returns false */
    HcfX509Certificate *cert = CreateCertFromPem(TEST_END_ENTITY_CERT);
    HcfX509Certificate *rootCert = CreateCertFromPem(TEST_ROOT_CA_CERT);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(TEST_INTERMEDIATE_CA_CERT);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(rootCert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
    params.trustSystemCa = true;
    params.validateDate = false;
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;
    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    SetupCrlCheckParams(params, false);
    params.revokedParams->enableRevocationCache = true;

    HcfCertVerifyResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res, CF_ERR_CRL_NOT_FOUND);
    FreeVerifyCertResult(result);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}


/**
 * @tc.name: ValidateX509Cert_BuildSystemCaStore_NewFail_001
 * @tc.desc: The X509_STORE_new returns NULL (storeTmp==NULL) branch in BuildSystemCaStore,
 * so the cache degrades and the original CRL check flow is used
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_BuildSystemCaStore_NewFail_001, TestSize.Level0)
{
    g_mockSystemCaCert = nullptr;
    g_x509StoreNewCallCount = 0;
    g_mockX509StoreNewFailAt = 2;  /* The 2nd X509_STORE_new (BuildSystemCaStore) returns NULL */
    g_loadLocationsCallCount = 0;
    g_mockLoadLocationsFailAt = -1;

    HcfX509Certificate *cert = CreateCertFromPem(TEST_END_ENTITY_CERT);
    HcfX509Certificate *rootCert = CreateCertFromPem(TEST_ROOT_CA_CERT);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(TEST_INTERMEDIATE_CA_CERT);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(rootCert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
    params.trustSystemCa = true;
    params.validateDate = false;
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;
    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    SetupCrlCheckParams(params, false);
    params.revokedParams->enableRevocationCache = true;

    HcfCertVerifyResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res, CF_ERR_CRL_NOT_FOUND);
    FreeVerifyCertResult(result);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
    g_mockX509StoreNewFailAt = -1;
}

/**
 * @tc.name: ValidateX509Cert_BuildSystemCaStore_LoadFail_001
 * @tc.desc: The X509_STORE_load_locations load failure (returns non-1) branch in BuildSystemCaStore,
 * so the cache degrades and the original CRL check flow is used
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_BuildSystemCaStore_LoadFail_001, TestSize.Level0)
{
    g_mockSystemCaCert = nullptr;
    g_x509StoreNewCallCount = 0;
    g_mockX509StoreNewFailAt = -1;
    g_loadLocationsCallCount = 0;
    g_mockLoadLocationsFailAt = 3;  /* The 3rd load (CERT_VERIFY_DIR of BuildSystemCaStore) returns 0 */

    HcfX509Certificate *cert = CreateCertFromPem(TEST_END_ENTITY_CERT);
    HcfX509Certificate *rootCert = CreateCertFromPem(TEST_ROOT_CA_CERT);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(TEST_INTERMEDIATE_CA_CERT);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(rootCert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
    params.trustSystemCa = true;
    params.validateDate = false;
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;
    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    SetupCrlCheckParams(params, false);
    params.revokedParams->enableRevocationCache = true;

    HcfCertVerifyResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res, CF_ERR_CRL_NOT_FOUND);
    FreeVerifyCertResult(result);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
    g_mockLoadLocationsFailAt = -1;
}

/**
 * @tc.name: ValidateX509Cert_CrlDownloadCacheStore_001
 * @tc.desc: Writes to the cache after a successful CRL download (covers the cache write branch in HandleCrlNotFound)
 *           Mocks X509_CRL_load_http to return a valid CRL and makes the second CRL check after download succeed
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_CrlDownloadCacheStore_001, TestSize.Level0)
{
    g_mockSystemCaCert = X509FromPem(TEST_ROOT_CA_FOR_CDP);
    ASSERT_NE(g_mockSystemCaCert, nullptr);

    HcfX509Certificate *cert = nullptr;
    HcfX509Certificate *intermediateCert = nullptr;
    HcfX509Certificate *rootCert = nullptr;
    HcfX509CertValidatorParams params = {};
    SetupCrlCacheStoreQuery(&cert, &intermediateCert, &rootCert, params);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);
    ASSERT_NE(rootCert, nullptr);

    X509_CRL *mockCrl = CreateX509CrlFromPemData(g_testCertChainPemMidCRL);
    ASSERT_NE(mockCrl, nullptr);

    /* X509_verify_cert call sequence:
     * 1) Chain verification (real, success)
     * 2) First CRL check (real, no CRL returns UNABLE_TO_GET_CRL, triggering download)
     * 3) CRL check after download (mock returns 1, making VerifyCertByCrl return CF_SUCCESS, triggering cache write) */
    int verifyCallCount = 0;
    HcfCertVerifyResult result = {};

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_CRL_load_http(_, _, _, _))
        .WillRepeatedly(WithoutArgs(Invoke([mockCrl]() -> X509_CRL* {
            return X509_CRL_dup(mockCrl);
        })));
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_verify_cert(_))
        .WillRepeatedly(Invoke([&verifyCallCount](X509_STORE_CTX *ctx) -> int {
            verifyCallCount++;
            if (verifyCallCount >= 3) {
                return 1;
            }
            return __real_X509_verify_cert(ctx);
        }));
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());

    EXPECT_EQ(res, CF_SUCCESS);

    X509_CRL_free(mockCrl);
    CfObjDestroy(cert);
    FreeValidatorParams(params);
    FreeVerifyCertResult(result);
    X509_free(g_mockSystemCaCert);
    g_mockSystemCaCert = nullptr;
}

/**
 * @tc.name: ValidateX509Cert_OcspOnlineCacheStore_001
 * @tc.desc: Writes to the cache after a successful OCSP online check (covers the StoreOcspResponseToCache interface)
 *           Mocks BIO_do_connect_retry and OSSL_HTTP_REQ_CTX_nbio_d2i to return a REVOKED response,
 *           making VerifyOnlineOcspResponse complete signature verification and then call StoreOcspResponseToCache
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_OcspOnlineCacheStore_001, TestSize.Level0)
{
    g_mockSystemCaCert = X509FromPem(OCSP_TEST_ROOT_CA);
    ASSERT_NE(g_mockSystemCaCert, nullptr);

    HcfX509Certificate *cert = nullptr;
    HcfX509Certificate *caCert = nullptr;
    HcfX509Certificate *intermediateCert = nullptr;
    HcfX509Certificate *signerCert = nullptr;
    HcfX509CertValidatorParams params = {};
    SetupOcspCacheStoreCase(&cert, &caCert, &intermediateCert, &signerCert, params);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(caCert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);
    ASSERT_NE(signerCert, nullptr);

    HcfCertVerifyResult result = {};

    X509OpensslMock::SetMockFlag(true);
    /* The request side generates a random nonce via CreateOcspRequest, while the static response carries a fixed nonce;
     * the two are necessarily unequal, causing OCSP_check_nonce to return 0 and fail early,
     * so here it is mocked to return 1 to bypass that. */
    EXPECT_CALL(X509OpensslMock::GetInstance(), OCSP_check_nonce(_, _))
        .WillRepeatedly(Return(1));
    EXPECT_CALL(X509OpensslMock::GetInstance(), BIO_do_connect_retry(_, _, _))
        .WillRepeatedly(Return(1));
    EXPECT_CALL(X509OpensslMock::GetInstance(), OSSL_HTTP_REQ_CTX_nbio_d2i(_, _, _))
        .WillRepeatedly(Invoke([](OSSL_HTTP_REQ_CTX *rctx, ASN1_VALUE **pval, const ASN1_ITEM *it) -> int {
            OCSP_RESPONSE *resp = CreateOcspResponseFromDer(OCSP_TEST_RESP_REVOKED, OCSP_TEST_RESP_REVOKED_SIZE);
            if (resp == nullptr) {
                return 0;
            }
            *pval = (ASN1_VALUE *)resp;
            return 1;
        }));
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());

    EXPECT_EQ(res, CF_ERR_CERT_REVOKED);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
    FreeVerifyCertResult(result);
    X509_free(g_mockSystemCaCert);
    g_mockSystemCaCert = nullptr;
}

/**
 * @tc.name: ValidateX509Cert_OcspCacheQueryMiss_001
 * @tc.desc: OCSP cache query miss (covers the RevocationCacheQuery != CF_SUCCESS || der.data == NULL
 *           branch in TryOcspCache)
 *           No local response and no online check, should return CF_ERR_OCSP_RESPONSE_NOT_FOUND
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_OcspCacheQueryMiss_001, TestSize.Level0)
{
    g_mockSystemCaCert = X509FromPem(OCSP_TEST_ROOT_CA);
    ASSERT_NE(g_mockSystemCaCert, nullptr);

    HcfX509Certificate *cert = CreateCertFromPem(OCSP_TEST_EE_VALID_URL);
    HcfX509Certificate *caCert = CreateCertFromPem(OCSP_TEST_ROOT_CA);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(OCSP_TEST_INTERMEDIATE_CA);
    HcfX509Certificate *signerCert = CreateCertFromPem(OCSP_TEST_SIGNER);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(caCert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);
    ASSERT_NE(signerCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
    params.trustSystemCa = true;
    params.validateDate = false;
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = caCert;
    params.untrustedCerts.count = OCSP_UNTRUSTED_CERT_COUNT;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *) * OCSP_UNTRUSTED_CERT_COUNT, 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;
    params.untrustedCerts.data[1] = signerCert;

    SetupOcspCheckParams(params, false);
    ASSERT_NE(params.revokedParams, nullptr);
    params.revokedParams->enableRevocationCache = true;

    HcfCertVerifyResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res, CF_ERR_OCSP_RESPONSE_NOT_FOUND);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
    FreeVerifyCertResult(result);
    X509_free(g_mockSystemCaCert);
    g_mockSystemCaCert = nullptr;
}

/**
 * @tc.name: ValidateX509Cert_CrlRevokedByLocalCrl_001
 * @tc.desc: The local CRL determines the certificate is revoked,
 * covering the X509_V_ERR_CERT_REVOKED branch in VerifyCertByCrl
 * (usedMethod is set to CRL, revokedCert is set to the certificate being verified,
 * and FillCrlRevocationInfo is called)
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_CrlRevokedByLocalCrl_001, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(g_testCertChainPemNoRoot);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(g_testCertChainPemMid);
    HcfX509Certificate *rootCert = CreateCertFromPem(g_testCertChainPemRoot);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);
    ASSERT_NE(rootCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
    params.trustSystemCa = false;
    params.validateDate = false;
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;
    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    SetupCrlCheckParams(params, false);
    ASSERT_NE(params.revokedParams, nullptr);

    HcfX509Crl *crl = nullptr;
    CfEncodingBlob crlStream = { reinterpret_cast<uint8_t *>(const_cast<char *>(g_testCertChainPemMidCRL)),
        sizeof(g_testCertChainPemMidCRL), CF_FORMAT_PEM };
    ASSERT_EQ(HcfX509CrlCreate(&crlStream, &crl), CF_SUCCESS);
    ASSERT_NE(crl, nullptr);
    params.revokedParams->crls.count = 1;
    params.revokedParams->crls.data = static_cast<HcfX509Crl **>(CfMalloc(sizeof(HcfX509Crl *), 0));
    ASSERT_NE(params.revokedParams->crls.data, nullptr);
    params.revokedParams->crls.data[0] = crl;

    HcfCertVerifyResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res, CF_ERR_CERT_REVOKED);
    ASSERT_NE(result.error, nullptr);
    ASSERT_NE(result.error->revocationInfo, nullptr);
    EXPECT_EQ(result.error->revocationInfo->usedMethod, CERT_REVOKED_METHOD_CRL);
    EXPECT_NE(result.error->revocationInfo->cert, nullptr);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
    FreeVerifyCertResult(result);
}

/**
 * @tc.name: ValidateX509Cert_CrlRevocationReason_001
 * @tc.desc: The local CRL revokes the certificate;
 * mocks X509_REVOKED_get_ext_d2i to return non-NULL for NID_crl_reason,
 * covering the reasonObj != NULL branch in GetCrlRevocationReason (ASN1_ENUMERATED_get/free/return)
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_CrlRevocationReason_001, TestSize.Level0)
{
    HcfX509Certificate *cert = nullptr;
    HcfX509Certificate *intermediateCert = nullptr;
    HcfX509Certificate *rootCert = nullptr;
    HcfX509CertValidatorParams params = {};
    SetupLocalCrlRevocationCase(&cert, &intermediateCert, &rootCert, params);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);
    ASSERT_NE(rootCert, nullptr);
    ASSERT_NE(params.revokedParams, nullptr);
    ASSERT_NE(params.revokedParams->crls.data[0], nullptr);

    HcfCertVerifyResult result = {};

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_REVOKED_get_ext_d2i(_, _, _, _))
        .WillRepeatedly(Invoke([](const X509_REVOKED *x, int nid, int *crit, int *idx) -> void * {
            if (nid == NID_crl_reason) {
                /* ENUMERATED DER encoding value=1 (tag 0x0A),
                 * constructed via d2i to avoid relying on deprecated APIs */
                static const unsigned char enumDer[] = { 0x0a, 0x01, 0x01 };
                const unsigned char *p = enumDer;
                return d2i_ASN1_ENUMERATED(nullptr, &p, sizeof(enumDer));
            }
            return __real_X509_REVOKED_get_ext_d2i(x, nid, crit, idx);
        }));
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());

    EXPECT_EQ(res, CF_ERR_CERT_REVOKED);
    ASSERT_NE(result.error, nullptr);
    ASSERT_NE(result.error->revocationInfo, nullptr);
    EXPECT_EQ(result.error->revocationInfo->revocationReason, 1);  /* keyCompromise */

    CfObjDestroy(cert);
    FreeValidatorParams(params);
    FreeVerifyCertResult(result);
}

/**
 * @tc.name: StoreOcspResponseToCache_EarlyReturn_001
 * @tc.desc: Covers the early-return branches of StoreOcspResponseToCache:
 *           !cacheEnabled / resp == NULL / BuildRevocationCacheIdentifier failure / i2d_OCSP_RESPONSE failure
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, StoreOcspResponseToCache_EarlyReturn_001, TestSize.Level0)
{
    HcfX509CertValidatorOpenSSLParams params = {};
    OCSP_RESPONSE *resp = CreateOcspResponseFromDer(OCSP_TEST_RESP_GOOD, OCSP_TEST_RESP_GOOD_SIZE);
    ASSERT_NE(resp, nullptr);

    /* Branch 1: cacheEnabled is false */
    params.cacheEnabled = false;
    StoreOcspResponseToCache(nullptr, &params, resp, nullptr);

    /* Branch 1: resp is NULL */
    params.cacheEnabled = true;
    StoreOcspResponseToCache(nullptr, &params, nullptr, nullptr);

    /* Branch 2: BuildRevocationCacheIdentifier failure (cert is NULL) */
    StoreOcspResponseToCache(nullptr, &params, resp, nullptr);

    /* Branch 3: i2d_OCSP_RESPONSE failure (empty response cannot be serialized) */
    params.issuer = X509FromPem(OCSP_TEST_INTERMEDIATE_CA);
    ASSERT_NE(params.issuer, nullptr);
    X509 *earlyCert = X509FromPem(OCSP_TEST_EE_VALID_URL);
    ASSERT_NE(earlyCert, nullptr);
    OCSP_RESPONSE *emptyResp = OCSP_RESPONSE_new();
    ASSERT_NE(emptyResp, nullptr);
    StoreOcspResponseToCache(earlyCert, &params, emptyResp, nullptr);
    OCSP_RESPONSE_free(emptyResp);
    X509_free(earlyCert);
    X509_free(params.issuer);

    OCSP_RESPONSE_free(resp);
}

/**
 * @tc.name: StoreOcspResponseToCache_ExpirationFallback_001
 * @tc.desc: When nextUpdate is NULL, Asn1TimeToTimestamp returns 0,
 *           covering the expiration == 0 fallback branch in StoreOcspResponseToCache
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, StoreOcspResponseToCache_ExpirationFallback_001, TestSize.Level0)
{
    HcfX509CertValidatorOpenSSLParams params = {};
    params.cacheEnabled = true;
    params.issuer = X509FromPem(OCSP_TEST_INTERMEDIATE_CA);
    ASSERT_NE(params.issuer, nullptr);
    X509 *expCert = X509FromPem(OCSP_TEST_EE_VALID_URL);
    ASSERT_NE(expCert, nullptr);

    OCSP_RESPONSE *resp = CreateOcspResponseFromDer(OCSP_TEST_RESP_GOOD, OCSP_TEST_RESP_GOOD_SIZE);
    ASSERT_NE(resp, nullptr);

    StoreOcspResponseToCache(expCert, &params, resp, nullptr);  /* nextUpdate == NULL */

    OCSP_RESPONSE_free(resp);
    X509_free(expCert);
    X509_free(params.issuer);
}

/**
 * @tc.name: StoreOcspResponseToCache_StoreFail_001
 * @tc.desc: CmSaveRevocationCache returns failure,
 * covering the storeRet != CF_SUCCESS branch in StoreOcspResponseToCache
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, StoreOcspResponseToCache_StoreFail_001, TestSize.Level0)
{
    HcfX509CertValidatorOpenSSLParams params = {};
    params.cacheEnabled = true;
    params.issuer = X509FromPem(OCSP_TEST_INTERMEDIATE_CA);
    ASSERT_NE(params.issuer, nullptr);
    X509 *failCert = X509FromPem(OCSP_TEST_EE_VALID_URL);
    ASSERT_NE(failCert, nullptr);

    OCSP_RESPONSE *resp = CreateOcspResponseFromDer(OCSP_TEST_RESP_GOOD, OCSP_TEST_RESP_GOOD_SIZE);
    ASSERT_NE(resp, nullptr);

    StoreOcspResponseToCache(failCert, &params, resp, nullptr);

    OCSP_RESPONSE_free(resp);
    X509_free(failCert);
    X509_free(params.issuer);
}

/**
 * @tc.name: IsTrustAnchorSystemCa_Branch_001
 * @tc.desc: Covers the return false / continue / match branches of IsTrustAnchorSystemCa
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, IsTrustAnchorSystemCa_Branch_001, TestSize.Level0)
{
    X509 *anchor = X509FromPem(OCSP_TEST_ROOT_CA);
    ASSERT_NE(anchor, nullptr);
    X509 *otherCert = X509FromPem(OCSP_TEST_INTERMEDIATE_CA);
    ASSERT_NE(otherCert, nullptr);

    /* systemCaStore: contains the matching anchor */
    X509_STORE *store = X509_STORE_new();
    ASSERT_NE(store, nullptr);
    ASSERT_EQ(X509_STORE_add_cert(store, X509_dup(anchor)), 1);

    /* certChain: contains the anchor */
    STACK_OF(X509) *chain = sk_X509_new_null();
    ASSERT_NE(chain, nullptr);
    ASSERT_EQ(sk_X509_push(chain, anchor), 1);

    /* Branch 561: certChain == NULL */
    EXPECT_FALSE(IsTrustAnchorSystemCa(nullptr, store));

    /* Branch 561: systemCaStore == NULL */
    EXPECT_FALSE(IsTrustAnchorSystemCa(chain, nullptr));

    /* Branch 565: empty certChain (num <= 0) */
    STACK_OF(X509) *emptyChain = sk_X509_new_null();
    ASSERT_NE(emptyChain, nullptr);
    EXPECT_FALSE(IsTrustAnchorSystemCa(emptyChain, store));

    /* Branch 569: anchor == NULL (last element of chain is NULL) */
    STACK_OF(X509) *nullAnchorChain = sk_X509_new_null();
    ASSERT_NE(nullAnchorChain, nullptr);
    X509 *tmpX509 = X509FromPem(OCSP_TEST_ROOT_CA);
    ASSERT_NE(tmpX509, nullptr);
    ASSERT_EQ(sk_X509_push(nullAnchorChain, tmpX509), 1);
    (void)sk_X509_set(nullAnchorChain, 0, nullptr);
    X509_free(tmpX509);
    EXPECT_FALSE(IsTrustAnchorSystemCa(nullAnchorChain, store));

    /* Branch 573: empty systemCaStore (objs == NULL) */
    X509_STORE *emptyStore = X509_STORE_new();
    ASSERT_NE(emptyStore, nullptr);
    EXPECT_FALSE(IsTrustAnchorSystemCa(chain, emptyStore));

    /* Branch 579: store contains a CRL (type != X509_LU_X509 → continue) */
    X509_CRL *crl = CreateX509CrlFromPemData(g_testCertChainPemMidCRL);
    ASSERT_NE(crl, nullptr);
    X509_STORE *crlStore = X509_STORE_new();
    ASSERT_NE(crlStore, nullptr);
    ASSERT_EQ(X509_STORE_add_crl(crlStore, crl), 1);
    EXPECT_FALSE(IsTrustAnchorSystemCa(chain, crlStore));

    /* Branch 583: match (X509_cmp == 0 → true) */
    EXPECT_TRUE(IsTrustAnchorSystemCa(chain, store));

    /* Branch 583: no match (X509_cmp != 0 → false) */
    X509_STORE *otherStore = X509_STORE_new();
    ASSERT_NE(otherStore, nullptr);
    ASSERT_EQ(X509_STORE_add_cert(otherStore, X509_dup(otherCert)), 1);
    EXPECT_FALSE(IsTrustAnchorSystemCa(chain, otherStore));

    /* Cleanup */
    sk_X509_pop_free(chain, X509_free);
    sk_X509_free(emptyChain);
    sk_X509_free(nullAnchorChain);
    X509_STORE_free(store);
    X509_STORE_free(emptyStore);
    X509_STORE_free(crlStore);
    X509_STORE_free(otherStore);
    X509_CRL_free(crl);
    X509_free(otherCert);
}

/**
 * @tc.name: FillVerifyCertResult_InvalidChain_001
 * @tc.desc: verifiedChain is NULL or empty,
 * covering the invalid verified chain branch (line 2091) in FillVerifyCertResult
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, FillVerifyCertResult_InvalidChain_001, TestSize.Level0)
{
    HcfCertVerifyResult result = {};

    /* verifiedChain == NULL */
    EXPECT_EQ(FillVerifyCertResult(nullptr, &result), CF_ERR_CRYPTO_OPERATION);
    ASSERT_NE(result.error, nullptr);
    HcfFreeCertVerifyResult(&result);

    /* Empty verifiedChain (sk_X509_num <= 0) */
    result = {};
    STACK_OF(X509) *emptyChain = sk_X509_new_null();
    ASSERT_NE(emptyChain, nullptr);
    EXPECT_EQ(FillVerifyCertResult(emptyChain, &result), CF_ERR_CRYPTO_OPERATION);
    ASSERT_NE(result.error, nullptr);
    HcfFreeCertVerifyResult(&result);
    sk_X509_free(emptyChain);
}

/**
 * @tc.name: ValidateX509Cert_CacheEnabledEmptyChain_001
 * @tc.desc: cacheEnabled=true and certChain is empty (mock X509_STORE_CTX_get1_chain returns an empty chain),
 * covering the branch at line 2185 where IsTrustAnchorSystemCa returns false for an empty chain, degrading cacheEnabled
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_CacheEnabledEmptyChain_001, TestSize.Level0)
{
    g_mockSystemCaCert = X509FromPem(OCSP_TEST_ROOT_CA);
    ASSERT_NE(g_mockSystemCaCert, nullptr);

    HcfX509Certificate *cert = CreateCertFromPem(OCSP_TEST_EE_VALID_URL);
    HcfX509Certificate *caCert = CreateCertFromPem(OCSP_TEST_ROOT_CA);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(OCSP_TEST_INTERMEDIATE_CA);
    HcfX509Certificate *signerCert = CreateCertFromPem(OCSP_TEST_SIGNER);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(caCert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);
    ASSERT_NE(signerCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
    params.trustSystemCa = true;
    params.validateDate = false;
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = caCert;
    params.untrustedCerts.count = OCSP_UNTRUSTED_CERT_COUNT;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *) * OCSP_UNTRUSTED_CERT_COUNT, 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;
    params.untrustedCerts.data[1] = signerCert;

    SetupOcspCheckParams(params, false);
    ASSERT_NE(params.revokedParams, nullptr);
    params.revokedParams->enableRevocationCache = true;

    HcfCertVerifyResult result = {};

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_STORE_CTX_get1_chain(_))
        .WillRepeatedly(Invoke([](X509_STORE_CTX *ctx) -> STACK_OF(X509) * {
            return sk_X509_new_null();  /* Empty chain, making IsTrustAnchorSystemCa return false */
        }));
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());

    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
    FreeVerifyCertResult(result);
    X509_free(g_mockSystemCaCert);
    g_mockSystemCaCert = nullptr;
}

/**
 * @tc.name: ValidateX509Cert_OcspOnlineGood_001
 * @tc.desc: OCSP online check returns GOOD status, covering the status != REVOKED / cfRet == CF_SUCCESS /
 *           status == GOOD branches in VerifyOnlineOcspResponse
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_OcspOnlineGood_001, TestSize.Level0)
{
    g_mockSystemCaCert = X509FromPem(OCSP_TEST_ROOT_CA);
    ASSERT_NE(g_mockSystemCaCert, nullptr);

    HcfX509Certificate *cert = nullptr;
    HcfX509Certificate *caCert = nullptr;
    HcfX509Certificate *intermediateCert = nullptr;
    HcfX509Certificate *signerCert = nullptr;
    HcfX509CertValidatorParams params = {};
    SetupOcspCacheStoreCase(&cert, &caCert, &intermediateCert, &signerCert, params);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(caCert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);
    ASSERT_NE(signerCert, nullptr);

    HcfCertVerifyResult result = {};

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), OCSP_check_nonce(_, _))
        .WillRepeatedly(Return(1));
    EXPECT_CALL(X509OpensslMock::GetInstance(), OCSP_check_validity(_, _, _, _))
        .WillRepeatedly(Return(1));
    EXPECT_CALL(X509OpensslMock::GetInstance(), BIO_do_connect_retry(_, _, _))
        .WillRepeatedly(Return(1));
    EXPECT_CALL(X509OpensslMock::GetInstance(), OSSL_HTTP_REQ_CTX_nbio_d2i(_, _, _))
        .WillRepeatedly(Invoke([](OSSL_HTTP_REQ_CTX *rctx, ASN1_VALUE **pval, const ASN1_ITEM *it) -> int {
            OCSP_RESPONSE *resp = CreateOcspResponseFromDer(OCSP_TEST_RESP_GOOD, OCSP_TEST_RESP_GOOD_SIZE);
            if (resp == nullptr) {
                return 0;
            }
            *pval = (ASN1_VALUE *)resp;
            return 1;
        }));
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());

    EXPECT_EQ(res, CF_SUCCESS);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
    FreeVerifyCertResult(result);
    X509_free(g_mockSystemCaCert);
    g_mockSystemCaCert = nullptr;
}

/**
 * @tc.name: ValidateX509Cert_OcspOnlineUnknown_001
 * @tc.desc: OCSP online check returns UNKNOWN status, covering the status == UNKNOWN branch in VerifyOnlineOcspResponse
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_OcspOnlineUnknown_001, TestSize.Level0)
{
    g_mockSystemCaCert = X509FromPem(OCSP_TEST_ROOT_CA);
    ASSERT_NE(g_mockSystemCaCert, nullptr);

    HcfX509Certificate *cert = nullptr;
    HcfX509Certificate *caCert = nullptr;
    HcfX509Certificate *intermediateCert = nullptr;
    HcfX509Certificate *signerCert = nullptr;
    HcfX509CertValidatorParams params = {};
    SetupOcspCacheStoreCase(&cert, &caCert, &intermediateCert, &signerCert, params);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(caCert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);
    ASSERT_NE(signerCert, nullptr);

    HcfCertVerifyResult result = {};

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), OCSP_check_nonce(_, _))
        .WillRepeatedly(Return(1));
    EXPECT_CALL(X509OpensslMock::GetInstance(), BIO_do_connect_retry(_, _, _))
        .WillRepeatedly(Return(1));
    EXPECT_CALL(X509OpensslMock::GetInstance(), OSSL_HTTP_REQ_CTX_nbio_d2i(_, _, _))
        .WillRepeatedly(Invoke([](OSSL_HTTP_REQ_CTX *rctx, ASN1_VALUE **pval, const ASN1_ITEM *it) -> int {
            OCSP_RESPONSE *resp = CreateOcspResponseFromDer(OCSP_TEST_RESP_UNKNOWN, OCSP_TEST_RESP_UNKNOWN_SIZE);
            if (resp == nullptr) {
                return 0;
            }
            *pval = (ASN1_VALUE *)resp;
            return 1;
        }));
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());

    EXPECT_EQ(res, CF_ERR_OCSP_CERT_STATUS_UNKNOWN);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
    FreeVerifyCertResult(result);
    X509_free(g_mockSystemCaCert);
    g_mockSystemCaCert = nullptr;
}

/**
 * @tc.name: ValidateX509Cert_CrlCacheStoreAndQuery_001
 * @tc.desc: Drives RevocationCacheStore/RevocationCacheQuery through validateX509Cert with the in-memory mock cache:
 *           1st validation downloads the CRL and writes it into the mock cache (store success),
 *           2nd validation reads it back from the mock cache without downloading again (query hit).
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_CrlCacheStoreAndQuery_001, TestSize.Level0)
{
    RevocationCacheMockReset();

    g_mockSystemCaCert = X509FromPem(TEST_ROOT_CA_FOR_CDP);
    ASSERT_NE(g_mockSystemCaCert, nullptr);

    HcfX509Certificate *cert = nullptr;
    HcfX509Certificate *intermediateCert = nullptr;
    HcfX509Certificate *rootCert = nullptr;
    HcfX509CertValidatorParams params = {};
    SetupCrlCacheStoreQuery(&cert, &intermediateCert, &rootCert, params);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);
    ASSERT_NE(rootCert, nullptr);

    X509_CRL *mockCrl = CreateX509CrlFromPemData(g_testCertChainPemMidCRL);
    ASSERT_NE(mockCrl, nullptr);

    int verifyCallCount = 0;
    HcfCertVerifyResult result = {};
    SetupCrlCacheStoreMock(mockCrl, &verifyCallCount);

    /* 1st validation: download CRL -> cache store */
    CfResult res1 = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res1, CF_SUCCESS);
    EXPECT_TRUE(RevocationCacheMockStoreCalled());
    FreeVerifyCertResult(result);
    result = {};

    /* 2nd validation: cache query hit, no download */
    CfResult res2 = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res2, CF_SUCCESS);
    EXPECT_TRUE(RevocationCacheMockQueryHit());

    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());

    X509_CRL_free(mockCrl);
    CfObjDestroy(cert);
    FreeValidatorParams(params);
    FreeVerifyCertResult(result);
    X509_free(g_mockSystemCaCert);
    g_mockSystemCaCert = nullptr;
    RevocationCacheMockReset();
}

/**
 * @tc.name: ValidateX509Cert_OcspCacheStoreAndQuery_001
 * @tc.desc: Drives RevocationCacheStore/RevocationCacheQuery through validateX509Cert with the in-memory mock cache:
 *           1st validation performs an online OCSP check and writes the response into the mock cache,
 *           2nd validation reads the cached response without going online again (query hit).
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_OcspCacheStoreAndQuery_001, TestSize.Level0)
{
    RevocationCacheMockReset();

    g_mockSystemCaCert = X509FromPem(OCSP_TEST_ROOT_CA);
    ASSERT_NE(g_mockSystemCaCert, nullptr);

    HcfX509Certificate *cert = nullptr;
    HcfX509Certificate *caCert = nullptr;
    HcfX509Certificate *intermediateCert = nullptr;
    HcfX509Certificate *signerCert = nullptr;
    HcfX509CertValidatorParams params = {};
    SetupOcspCacheStoreCase(&cert, &caCert, &intermediateCert, &signerCert, params);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(caCert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);
    ASSERT_NE(signerCert, nullptr);

    HcfCertVerifyResult result = {};

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), OCSP_check_nonce(_, _))
        .WillRepeatedly(Return(1));
    EXPECT_CALL(X509OpensslMock::GetInstance(), OCSP_check_validity(_, _, _, _))
        .WillRepeatedly(Return(1));
    EXPECT_CALL(X509OpensslMock::GetInstance(), BIO_do_connect_retry(_, _, _))
        .WillRepeatedly(Return(1));
    EXPECT_CALL(X509OpensslMock::GetInstance(), OSSL_HTTP_REQ_CTX_nbio_d2i(_, _, _))
        .WillRepeatedly(Invoke([](OSSL_HTTP_REQ_CTX *rctx, ASN1_VALUE **pval, const ASN1_ITEM *it) -> int {
            OCSP_RESPONSE *resp = CreateOcspResponseFromDer(OCSP_TEST_RESP_GOOD, OCSP_TEST_RESP_GOOD_SIZE);
            if (resp == nullptr) {
                return 0;
            }
            *pval = (ASN1_VALUE *)resp;
            return 1;
        }));

    /* 1st validation: online OCSP -> cache store */
    CfResult res1 = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res1, CF_SUCCESS);
    EXPECT_TRUE(RevocationCacheMockStoreCalled());
    FreeVerifyCertResult(result);
    result = {};

    /* 2nd validation: cache query hit, no online request */
    CfResult res2 = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res2, CF_SUCCESS);
    EXPECT_TRUE(RevocationCacheMockQueryHit());

    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());

    CfObjDestroy(cert);
    FreeValidatorParams(params);
    FreeVerifyCertResult(result);
    X509_free(g_mockSystemCaCert);
    g_mockSystemCaCert = nullptr;
    RevocationCacheMockReset();
}
