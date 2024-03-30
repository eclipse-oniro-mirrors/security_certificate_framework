/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "x509cert_chain_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include "securec.h"

#include "cf_blob.h"
#include "cf_result.h"
#include "x509_cert_chain.h"

namespace OHOS {
    static char g_fuzzCert[] =
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

    static char g_fuzzDate[] = "20231212080000Z";
    static uint8_t g_fuzzPubKey[] = {
        0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
        0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82,
        0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xd0, 0x35, 0x39, 0x92, 0x49, 0xb5,
        0x95, 0x08, 0xef, 0x38, 0xf8, 0xa8, 0x51, 0xd3, 0xef, 0xd8, 0x3e, 0x3a, 0xd9,
        0x2c, 0xe1, 0x31, 0x1f, 0x99, 0x41, 0x03, 0x86, 0xb3, 0x4a, 0x04, 0x41, 0x23,
        0x6f, 0xf8, 0xb6, 0xf4, 0x60, 0x5f, 0x9e, 0x9b, 0xc5, 0x75, 0x3d, 0xfa, 0x6b,
        0x30, 0xa0, 0xd9, 0x53, 0x83, 0x25, 0x14, 0xa3, 0x23, 0x31, 0x67, 0xe2, 0xa0,
        0x03, 0x71, 0xcf, 0x38, 0x12, 0x67, 0xca, 0x88, 0x31, 0x0c, 0xf7, 0xb1, 0xc5,
        0xb1, 0x03, 0xe9, 0xf5, 0x14, 0x64, 0xab, 0x11, 0xf9, 0x70, 0x1e, 0x75, 0x11,
        0x4d, 0x9e, 0x04, 0x4f, 0x54, 0x6b, 0xde, 0x71, 0xfb, 0x04, 0x29, 0xfc, 0xa4,
        0x9d, 0x0a, 0xa2, 0x13, 0x09, 0x0f, 0xef, 0xca, 0xf9, 0xb7, 0x27, 0x85, 0x29,
        0x8e, 0x5d, 0x30, 0x95, 0x6f, 0x30, 0x44, 0x23, 0xc2, 0x59, 0xc6, 0x30, 0xde,
        0x92, 0x82, 0x94, 0x64, 0x64, 0x37, 0x35, 0x6d, 0x23, 0x52, 0x97, 0x9d, 0xfa,
        0x67, 0xed, 0xf1, 0xb7, 0x37, 0xce, 0x27, 0xef, 0x09, 0x41, 0x6f, 0xd2, 0x06,
        0x28, 0x91, 0x5a, 0x73, 0xfe, 0xbe, 0x87, 0x1b, 0xd9, 0xc7, 0x6a, 0xa7, 0x7c,
        0xbb, 0x31, 0x74, 0x82, 0x91, 0xd1, 0x0f, 0xdb, 0x88, 0x6a, 0x14, 0xe9, 0x9f,
        0x08, 0xcb, 0xf4, 0x7f, 0xa7, 0xb1, 0xa8, 0x3c, 0xef, 0x2f, 0x6a, 0x65, 0x74,
        0xf7, 0x4f, 0x90, 0x1c, 0x42, 0xf9, 0x01, 0xd4, 0xb3, 0x2a, 0xd1, 0x21, 0x53,
        0xdb, 0xdd, 0xbd, 0xcb, 0x96, 0x8e, 0x32, 0xf1, 0x56, 0x76, 0x89, 0x2d, 0xf8,
        0xff, 0xe9, 0x6a, 0x06, 0x66, 0x3f, 0x14, 0x5a, 0x7d, 0xf3, 0x15, 0xb1, 0x28,
        0x4d, 0x56, 0x80, 0x7e, 0x9d, 0xb1, 0xa9, 0xdc, 0xd6, 0xef, 0x24, 0x6f, 0x8b,
        0x6a, 0xf5, 0xe3, 0xc9, 0xbd, 0x7a, 0xfe, 0xe5, 0x8c, 0x3a, 0x87, 0xa3, 0xc5,
        0x17, 0xeb, 0xdb, 0x02, 0x03, 0x01, 0x00, 0x01
    };
    static uint8_t g_fuzzSubject[] = {
        0x30, 0x44, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02,
        0x55, 0x53, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x0c,
        0x44, 0x69, 0x67, 0x69, 0x43, 0x65, 0x72, 0x74, 0x20, 0x49, 0x6e, 0x63, 0x31,
        0x1e, 0x30, 0x1c, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x15, 0x47, 0x65, 0x6f,
        0x54, 0x72, 0x75, 0x73, 0x74, 0x20, 0x52, 0x53, 0x41, 0x20, 0x43, 0x4e, 0x20,
        0x43, 0x41, 0x20, 0x47, 0x32
    };
    static char g_fuzzSslHostName[] = "*.163.com";
    constexpr int TEST_DATA_LEN = 1;
    static bool g_testFlag = true;

    static void FreeTrustAnchor(HcfX509TrustAnchor *trustAnchor)
    {
        if (trustAnchor == nullptr) {
            return;
        }
        CfBlobFree(&trustAnchor->CAPubKey);
        CfBlobFree(&trustAnchor->CASubject);
        CfObjDestroy(trustAnchor->CACert);
        trustAnchor->CACert = nullptr;
        free(trustAnchor);
        trustAnchor = nullptr;
    }

    static void FreeValidateResult(HcfX509CertChainValidateResult *result)
    {
        if (result->entityCert != nullptr) {
            CfObjDestroy(result->entityCert);
            result->entityCert = nullptr;
        }

        if (result->trustAnchor != nullptr) {
            FreeTrustAnchor(result->trustAnchor);
        }
    }

    static void TestValidateParam(HcfX509CertChainValidateParams &params, HcfCertChain *x509CertChainObj)
    {
        CfBlob date = { 0 };
        date.data = reinterpret_cast<uint8_t *>(g_fuzzDate);
        date.size = strlen(g_fuzzDate) + 1;
        HcfX509TrustAnchorArray trustAnchors = { 0 };
        HcfX509TrustAnchor anchor = { 0 };
        CfBlob caPubKey = { 0 };
        caPubKey.data = g_fuzzPubKey;
        caPubKey.size = strlen(reinterpret_cast<char *>(g_fuzzPubKey)) + 1;
        anchor.CAPubKey = &caPubKey;
        CfBlob caSubject = { 0 };
        caSubject.data = g_fuzzSubject;
        caSubject.size = strlen(reinterpret_cast<char *>(g_fuzzSubject)) + 1;
        anchor.CASubject = &caSubject;
        trustAnchors.data = static_cast<HcfX509TrustAnchor **>(
            calloc(TEST_DATA_LEN * sizeof(HcfX509TrustAnchor *), 0));
        if (trustAnchors.data == nullptr) {
            return;
        }
        trustAnchors.data[0] = &anchor;
        trustAnchors.count = TEST_DATA_LEN;

        HcfRevocationCheckParam revocationCheckParam = { 0 };
        HcfRevChkOpArray optionData = { 0 };
        HcfRevChkOption option[TEST_DATA_LEN] = { REVOCATION_CHECK_OPTION_ACCESS_NETWORK };
        optionData.data = option;
        optionData.count = TEST_DATA_LEN;
        revocationCheckParam.options = &optionData;

        CfBlob sslHostname = { 0 };
        sslHostname.data = reinterpret_cast<uint8_t *>(g_fuzzSslHostName);
        sslHostname.size = strlen(g_fuzzSslHostName) + 1;
        HcfKuArray keyUsage = { 0 };
        HcfKeyUsageType type[TEST_DATA_LEN] = { KEYUSAGE_DIGITAL_SIGNATURE };
        keyUsage.data = type;
        keyUsage.count = TEST_DATA_LEN;

        params.date = &date;
        params.trustAnchors = &trustAnchors;
        params.sslHostname = &sslHostname;
        params.policy = HcfValPolicyType::VALIDATION_POLICY_TYPE_SSL;
        params.keyUsage = &keyUsage;
        params.revocationCheckParam = &revocationCheckParam;
        HcfX509CertChainValidateResult result = { 0 };
        (void)x509CertChainObj->validate(x509CertChainObj, &params, &result);
        FreeValidateResult(&result);
        free(params.trustAnchors->data);
    }

    static void TestQuery(HcfCertChain *x509CertChainObj)
    {
        HcfX509CertChainValidateParams params = { 0 };
        TestValidateParam(params, x509CertChainObj);

        CfBlob toStringBlob = { 0 };
        (void)x509CertChainObj->toString(x509CertChainObj, &toStringBlob);
        CfBlobDataClearAndFree(&toStringBlob);

        CfBlob hashCodeBlob = { 0 };
        (void)x509CertChainObj->hashCode(x509CertChainObj, &hashCodeBlob);
        CfBlobDataClearAndFree(&hashCodeBlob);
    }

    static void CreateOneCert(void)
    {
        CfEncodingBlob inStream = { 0 };
        inStream.data = reinterpret_cast<uint8_t *>(g_fuzzCert);
        inStream.encodingFormat = CF_FORMAT_PEM;
        inStream.len = strlen(g_fuzzCert) + 1;
        HcfCertChain *x509CertChainObj = nullptr;
        CfResult res = HcfCertChainCreate(&inStream, nullptr, &x509CertChainObj);
        if (res != CF_SUCCESS) {
            return;
        }
        TestQuery(x509CertChainObj);
        CfObjDestroy(x509CertChainObj);
    }

    bool X509CertChainFuzzTest(const uint8_t* data, size_t size)
    {
        if (g_testFlag) {
            CreateOneCert();
            g_testFlag = false;
        }
        if (data == nullptr) {
            return false;
        }
        CfEncodingBlob inStream = { 0 };
        inStream.data = const_cast<uint8_t *>(data);
        inStream.encodingFormat = CF_FORMAT_PEM;
        inStream.len = size;
        HcfCertChain *x509CertChainObj = nullptr;
        CfResult res = HcfCertChainCreate(&inStream, nullptr, &x509CertChainObj);
        if (res != CF_SUCCESS) {
            return false;
        }
        CfObjDestroy(x509CertChainObj);

        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::X509CertChainFuzzTest(data, size);
    return 0;
}
