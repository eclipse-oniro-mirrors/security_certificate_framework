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

/* TDD test: validateX509Cert output parameter HcfCertVerifyResult */
/* (compared with the old struct, with new error result and revocation info added) */

#include <cstring>
#include "crypto_x509_cert_validator_test_common.h"

using namespace testing::ext;

/* Provided by cf_mock.cpp: force X509ToHcfX509Certificate to return failure */
extern "C" int g_mockX509ToHcfCertFail;

namespace {
/* Set up a full trust chain: root trust anchor + intermediate untrusted intermediate certificate */
static void SetupFullChain(HcfX509CertValidatorParams &params)
{
    params.trustSystemCa = false;
    params.validateDate = false;
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(CfMalloc(sizeof(HcfX509Certificate *), 0));
    params.trustedCerts.data[0] = CreateCertFromPem(TEST_ROOT_CA_CERT);
    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(CfMalloc(sizeof(HcfX509Certificate *), 0));
    params.untrustedCerts.data[0] = CreateCertFromPem(TEST_INTERMEDIATE_CA_CERT);
}

static void SetupHostname(HcfX509CertValidatorParams &params, const char *hostname)
{
    params.hostnames.count = 1;
    params.hostnames.data = static_cast<char **>(CfMalloc(sizeof(char *), 0));
    if (params.hostnames.data != nullptr) {
        params.hostnames.data[0] = static_cast<char *>(CfMalloc(strlen(hostname) + 1, 0));
        if (params.hostnames.data[0] != nullptr) {
            (void)memcpy_s(params.hostnames.data[0], strlen(hostname) + 1, hostname, strlen(hostname) + 1);
        }
    }
}
} // namespace

/**
 * @tc.name: VerifyResult_Success_001
 * @tc.desc: on successful verification result.error is NULL and certs is non-empty
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, VerifyResult_Success_001, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_END_ENTITY_CERT);
    ASSERT_NE(cert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
    SetupFullChain(params);

    HcfCertVerifyResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_EQ(result.error, nullptr);
    EXPECT_GT(result.certs.count, 0);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
    FreeVerifyCertResult(result);
}

/**
 * @tc.name: VerifyResult_Error_NoRevocationInfo_001
 * @tc.desc: non-revocation error (hostname mismatch) results in non-NULL error,
 * non-NULL errorMsg and NULL revocationInfo
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, VerifyResult_Error_NoRevocationInfo_001, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_END_ENTITY_CERT);
    ASSERT_NE(cert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
    SetupFullChain(params);
    SetupHostname(params, "wrong.example.com");

    HcfCertVerifyResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res, CF_ERR_CERT_HOST_NAME_MISMATCH);
    ASSERT_NE(result.error, nullptr);
    EXPECT_NE(result.error->errorMsg, nullptr);
    EXPECT_EQ(result.error->revocationInfo, nullptr);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
    FreeVerifyCertResult(result);
}

/**
 * @tc.name: VerifyResult_CrlRevoked_001
 * @tc.desc: when CRL determines revocation,
 * result.error->revocationInfo is non-NULL, usedMethod is CRL and cert is non-NULL
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, VerifyResult_CrlRevoked_001, TestSize.Level0)
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
    CfResult ret = HcfX509CrlCreate(&crlStream, &crl);
    ASSERT_EQ(ret, CF_SUCCESS);
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
 * @tc.name: VerifyResult_OcspRevoked_001
 * @tc.desc: when OCSP determines revocation, result.error->revocationInfo is non-NULL,
 * usedMethod is OCSP and cert is non-NULL
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, VerifyResult_OcspRevoked_001, TestSize.Level0)
{
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
    params.trustSystemCa = false;
    params.validateDate = false;
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = caCert;
    params.untrustedCerts.count = 2;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(CfMalloc(sizeof(HcfX509Certificate *) * 2, 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;
    params.untrustedCerts.data[1] = signerCert;

    SetupOcspCheckParams(params, false);
    ASSERT_NE(params.revokedParams, nullptr);
    params.revokedParams->ocspResponses.count = 1;
    params.revokedParams->ocspResponses.data = static_cast<CfBlob *>(CfMalloc(sizeof(CfBlob), 0));
    ASSERT_NE(params.revokedParams->ocspResponses.data, nullptr);
    params.revokedParams->ocspResponses.data[0].data = static_cast<uint8_t *>(CfMalloc(OCSP_TEST_RESP_REVOKED_SIZE, 0));
    ASSERT_NE(params.revokedParams->ocspResponses.data[0].data, nullptr);
    memcpy_s(params.revokedParams->ocspResponses.data[0].data, OCSP_TEST_RESP_REVOKED_SIZE,
        OCSP_TEST_RESP_REVOKED, OCSP_TEST_RESP_REVOKED_SIZE);
    params.revokedParams->ocspResponses.data[0].size = OCSP_TEST_RESP_REVOKED_SIZE;

    HcfCertVerifyResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res, CF_ERR_CERT_REVOKED);
    ASSERT_NE(result.error, nullptr);
    ASSERT_NE(result.error->revocationInfo, nullptr);
    EXPECT_EQ(result.error->revocationInfo->usedMethod, CERT_REVOKED_METHOD_OCSP);
    EXPECT_NE(result.error->revocationInfo->cert, nullptr);

    CfObjDestroy(cert);
    FreeValidatorParamsWithOcspData(params);
    FreeVerifyCertResult(result);
}

/**
 * @tc.name: HcfFreeCertVerifyResult_Null_001
 * @tc.desc: HcfFreeCertVerifyResult returns directly without crashing when the parameter is NULL
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, HcfFreeCertVerifyResult_Null_001, TestSize.Level0)
{
    HcfCertVerifyResult result = {};
    HcfFreeCertVerifyResult(nullptr);
    HcfFreeCertVerifyResult(&result);
    EXPECT_EQ(result.certs.count, 0U);
    EXPECT_EQ(result.certs.data, nullptr);
    EXPECT_EQ(result.error, nullptr);
}

/**
 * @tc.name: HcfFreeCertVerifyResult_CertNull_001
 * @tc.desc: an element of the certs.data array is NULL, covers HcfFreeCertVerifyResult's
 *           result->certs.data[i] == NULL branch (skips destruction, does not crash)
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, HcfFreeCertVerifyResult_CertNull_001, TestSize.Level0)
{
    HcfCertVerifyResult result = {};
    result.certs.count = 2;
    result.certs.data = static_cast<HcfX509Certificate **>(CfMalloc(sizeof(HcfX509Certificate *) * 2, 0));
    ASSERT_NE(result.certs.data, nullptr);
    result.certs.data[0] = CreateCertFromPem(TEST_END_ENTITY_CERT);
    result.certs.data[1] = nullptr;  /* Cover the certs.data[i] == NULL branch */

    HcfFreeCertVerifyResult(&result);

    EXPECT_EQ(result.certs.data, nullptr);
    EXPECT_EQ(result.certs.count, 0u);
}

/**
 * @tc.name: CopyVerifyErrorMsg_X509ToHcfCertFail_001
 * @tc.desc: when CRL determines revocation and X509ToHcfX509Certificate fails,
 * revocationInfo->cert is set to NULL, covers the certificate conversion failure branch of CopyVerifyErrorMsg
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, CopyVerifyErrorMsg_X509ToHcfCertFail_001, TestSize.Level0)
{
    g_mockX509ToHcfCertFail = 1;

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
    CfResult ret = HcfX509CrlCreate(&crlStream, &crl);
    ASSERT_EQ(ret, CF_SUCCESS);
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
    EXPECT_EQ(result.error->revocationInfo->cert, nullptr);  /* X509ToHcfX509Certificate failed, cert set to NULL */

    CfObjDestroy(cert);
    FreeValidatorParams(params);
    FreeVerifyCertResult(result);
    g_mockX509ToHcfCertFail = 0;
}

/* FormatRevocationTime is a private function in the adapter layer (non-static), */
/* forward-declared here to cover its internal branches */
extern "C" void FormatRevocationTime(const ASN1_TIME *time, char *buf, size_t bufLen);

/**
 * @tc.name: FormatRevocationTime_NullParams_001
 * @tc.desc: covers the parameter validation branches of FormatRevocationTime:
 *           the three short-circuit return branches time==NULL / buf==NULL / bufLen==0
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, FormatRevocationTime_NullParams_001, TestSize.Level0)
{
    char buf[64] = { 0 };
    ASN1_TIME *time = ASN1_TIME_new();
    ASSERT_NE(time, nullptr);

    FormatRevocationTime(nullptr, buf, sizeof(buf));   /* time == NULL */
    FormatRevocationTime(time, nullptr, sizeof(buf));  /* buf == NULL */
    FormatRevocationTime(time, buf, 0);                /* bufLen == 0 */

    ASN1_TIME_free(time);
}

/**
 * @tc.name: FormatRevocationTime_InvalidTime_001
 * @tc.desc: covers the ASN1_TIME_to_tm failure branch in FormatRevocationTime
 *           (empty ASN1_TIME cannot be parsed into struct tm)
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, FormatRevocationTime_InvalidTime_001, TestSize.Level0)
{
    char buf[64] = { 0 };
    ASN1_TIME *time = ASN1_TIME_new();
    ASSERT_NE(time, nullptr);

    FormatRevocationTime(time, buf, sizeof(buf));  /* ASN1_TIME_to_tm returns non-1 */

    ASN1_TIME_free(time);
}

/**
 * @tc.name: SetVerifyErrorMsg_ErrorNotNull_001
 * @tc.desc: when result->error is already non-NULL and result->certs is non-empty,
 *           covers the result->error != NULL early return branch in SetVerifyErrorMsg
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, SetVerifyErrorMsg_ErrorNotNull_001, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_END_ENTITY_CERT);
    ASSERT_NE(cert, nullptr);

    HcfCertVerifyResult result = {};
    result.certs.count = 1;
    result.certs.data = static_cast<HcfX509Certificate **>(CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(result.certs.data, nullptr);
    result.certs.data[0] = nullptr;

    HcfCertVerifyErrorResult error = {};
    error.errorMsg = strdup("already has error");
    ASSERT_NE(error.errorMsg, nullptr);
    result.error = &error;

    CfResult res = g_validator->validateX509Cert(g_validator, cert, nullptr, &result);
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);

    CfFree(result.certs.data);
    free(error.errorMsg);
    CfObjDestroy(cert);
}

/**
 * @tc.name: SetVerifyErrorMsg_ErrorMsgMallocFail_001
 * @tc.desc: allocation of error->errorMsg fails (the 2nd CfMallocEx returns NULL),
 *           covers the error->errorMsg == NULL branch in SetVerifyErrorMsg
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, SetVerifyErrorMsg_ErrorMsgMallocFail_001, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_END_ENTITY_CERT);
    ASSERT_NE(cert, nullptr);

    HcfCertVerifyResult result = {};
    result.certs.count = 1;
    result.certs.data = static_cast<HcfX509Certificate **>(CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(result.certs.data, nullptr);
    result.certs.data[0] = nullptr;

    StartRecordMallocNum();
    SetMockMallocIndex(1);  /* The 2nd CfMallocEx (error->errorMsg) inside SetVerifyErrorMsg returns NULL */
    CfResult res = g_validator->validateX509Cert(g_validator, cert, nullptr, &result);
    EndRecordMallocNum();
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);

    CfFree(result.certs.data);
    CfObjDestroy(cert);
}

/**
 * @tc.name: CopyVerifyErrorMsg_InfoMallocFail_001
 * @tc.desc: HcfCertRevocationInfo allocation fails on CRL revocation (the 3rd CfMallocEx returns NULL),
 *           covers the info == NULL early return branch in CopyVerifyErrorMsg
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, CopyVerifyErrorMsg_InfoMallocFail_001, TestSize.Level0)
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

    StartRecordMallocNum();
    SetMockMallocIndex(2);  /* The 3rd CfMallocEx (HcfCertRevocationInfo) returns NULL */
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EndRecordMallocNum();
    EXPECT_EQ(res, CF_ERR_CERT_REVOKED);
    ASSERT_NE(result.error, nullptr);
    EXPECT_EQ(result.error->revocationInfo, nullptr);  /* info allocation failed, revocationInfo not set */

    CfObjDestroy(cert);
    FreeValidatorParams(params);
    FreeVerifyCertResult(result);
}