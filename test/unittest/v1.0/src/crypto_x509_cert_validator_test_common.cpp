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

#include "crypto_x509_cert_validator_test_common.h"
#include "revocation_cache_mock.h"

HcfCertChainValidator *g_validator = nullptr;

void CryptoX509CertValidatorTest::SetUpTestCase()
{
    CfResult res = HcfCertChainValidatorCreate("PKIX", &g_validator);
    ASSERT_EQ(res, CF_SUCCESS);
    ASSERT_NE(g_validator, nullptr);
}

void CryptoX509CertValidatorTest::TearDownTestCase()
{
    if (g_validator != nullptr) {
        CfObjDestroy(g_validator);
        g_validator = nullptr;
    }
}

void CryptoX509CertValidatorTest::SetUp()
{
    RevocationCacheMockReset();
}

void CryptoX509CertValidatorTest::TearDown()
{
    RevocationCacheMockReset();
}

HcfX509Certificate *CreateCertFromPem(const char *pemCert)
{
    CfEncodingBlob inStream = {};
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(pemCert));
    inStream.len = strlen(pemCert);
    inStream.encodingFormat = CF_FORMAT_PEM;

    HcfX509Certificate *cert = nullptr;
    CfResult res = HcfX509CertificateCreate(&inStream, &cert);
    if (res != CF_SUCCESS) {
        return nullptr;
    }
    return cert;
}

void FreeVerifyCertResult(HcfCertVerifyResult &result)
{
    HcfFreeCertVerifyResult(&result);
}

static void FreeCertArray(HcfX509CertificateArray &certs)
{
    if (certs.data != nullptr) {
        for (uint32_t i = 0; i < certs.count; i++) {
            CfObjDestroy(certs.data[i]);
        }
        CfFree(certs.data);
    }
}

static void FreeStringArray(HcfStringArray &arr)
{
    if (arr.data != nullptr) {
        for (uint32_t i = 0; i < arr.count; i++) {
            if (arr.data[i] != nullptr) {
                CfFree(arr.data[i]);
            }
        }
        CfFree(arr.data);
    }
}

static void FreeRevokedParams(HcfX509CertRevokedParams *revokedParams)
{
    if (revokedParams == nullptr) {
        return;
    }
    if (revokedParams->crls.data != nullptr) {
        for (uint32_t i = 0; i < revokedParams->crls.count; i++) {
            CfObjDestroy(revokedParams->crls.data[i]);
        }
        CfFree(revokedParams->crls.data);
    }
    if (revokedParams->revocationFlags.data != nullptr) {
        CfFree(revokedParams->revocationFlags.data);
    }
    if (revokedParams->ocspResponses.data != nullptr) {
        CfFree(revokedParams->ocspResponses.data);
    }
    CfFree(revokedParams);
}

void FreeValidatorParams(HcfX509CertValidatorParams &params)
{
    FreeCertArray(params.trustedCerts);
    FreeCertArray(params.untrustedCerts);
    if (params.date != nullptr) {
        CfFree(params.date);
    }
    FreeStringArray(params.hostnames);
    FreeStringArray(params.emailAddresses);
    FreeStringArray(params.trustCertPath);
    FreeStringArray(params.ipAddresses);
    if (params.keyUsage.data != nullptr) {
        CfFree(params.keyUsage.data);
    }
    if (params.extendedKeyUsage.data != nullptr) {
        CfFree(params.extendedKeyUsage.data);
    }
    if (params.ignoreErrs.data != nullptr) {
        CfFree(params.ignoreErrs.data);
    }
    FreeRevokedParams(params.revokedParams);
}

void FreeValidatorParamsWithOcspData(HcfX509CertValidatorParams &params)
{
    if (params.revokedParams != nullptr && params.revokedParams->ocspResponses.data != nullptr) {
        for (uint32_t i = 0; i < params.revokedParams->ocspResponses.count; i++) {
            if (params.revokedParams->ocspResponses.data[i].data != nullptr) {
                CfFree(params.revokedParams->ocspResponses.data[i].data);
            }
        }
    }
    FreeValidatorParams(params);
}

OCSP_RESPONSE *CreateOcspResponseFromDer(const uint8_t *der, size_t len)
{
    if (der == nullptr || len == 0) {
        return nullptr;
    }
    const unsigned char *p = der;
    return d2i_OCSP_RESPONSE(nullptr, &p, len);
}

HcfX509Certificate *SetupCertWithTrustAnchor(const char *pemCert, HcfX509CertValidatorParams &params)
{
    HcfX509Certificate *cert = CreateCertFromPem(pemCert);
    if (cert == nullptr) {
        return nullptr;
    }
    HcfX509Certificate *trustCert = CreateCertFromPem(pemCert);
    if (trustCert == nullptr) {
        CfObjDestroy(cert);
        return nullptr;
    }
    params.trustSystemCa = false;
    params.validateDate = false;
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(CfMalloc(sizeof(HcfX509Certificate *), 0));
    if (params.trustedCerts.data == nullptr) {
        CfObjDestroy(cert);
        CfObjDestroy(trustCert);
        return nullptr;
    }
    params.trustedCerts.data[0] = trustCert;
    return cert;
}

void SetupKeyUsageParams(HcfX509CertValidatorParams &params, int32_t *values, uint32_t count)
{
    params.keyUsage.count = count;
    params.keyUsage.data = static_cast<int32_t *>(CfMalloc(count * sizeof(int32_t), 0));
    if (params.keyUsage.data != nullptr && values != nullptr) {
        for (uint32_t i = 0; i < count; i++) {
            params.keyUsage.data[i] = values[i];
        }
    }
}

void SetupHostnameParams(HcfX509CertValidatorParams &params, const char *hostname)
{
    params.hostnames.count = 1;
    params.hostnames.data = static_cast<char **>(CfMalloc(sizeof(char *), 0));
    if (params.hostnames.data != nullptr) {
        params.hostnames.data[0] = strdup(hostname);
    }
}

void SetupEmailParams(HcfX509CertValidatorParams &params, const char *email)
{
    params.emailAddresses.count = 1;
    params.emailAddresses.data = static_cast<char **>(CfMalloc(sizeof(char *), 0));
    if (params.emailAddresses.data != nullptr) {
        params.emailAddresses.data[0] = strdup(email);
    }
}

void SetupCrlCheckParams(HcfX509CertValidatorParams &params, bool allowDownload)
{
    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    if (params.revokedParams != nullptr) {
        params.revokedParams->size = sizeof(HcfX509CertRevokedParams);
        params.revokedParams->revocationFlags.count = 1;
        params.revokedParams->revocationFlags.data = static_cast<int32_t *>(CfMalloc(sizeof(int32_t), 0));
        if (params.revokedParams->revocationFlags.data != nullptr) {
            params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_CRL_CHECK;
        }
        params.revokedParams->allowDownloadCrl = allowDownload;
    }
}

void SetupOcspCheckParams(HcfX509CertValidatorParams &params, bool allowOnline)
{
    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    if (params.revokedParams != nullptr) {
        params.revokedParams->size = sizeof(HcfX509CertRevokedParams);
        params.revokedParams->revocationFlags.count = 1;
        params.revokedParams->revocationFlags.data = static_cast<int32_t *>(CfMalloc(sizeof(int32_t), 0));
        if (params.revokedParams->revocationFlags.data != nullptr) {
            params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_OCSP_CHECK;
        }
        params.revokedParams->allowOcspCheckOnline = allowOnline;
    }
}
