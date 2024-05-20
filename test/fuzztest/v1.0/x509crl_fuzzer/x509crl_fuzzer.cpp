/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "x509crl_fuzzer.h"

#include <openssl/x509.h>

#include "asy_key_generator.h"
#include "certificate_openssl_class.h"
#include "crypto_x509_test_common.h"
#include "cf_log.h"
#include "cf_blob.h"
#include "cf_memory.h"
#include "cf_result.h"
#include "cipher.h"
#include "key_pair.h"
#include "securec.h"
#include "x509_certificate.h"
#include "x509_crl.h"
#include "x509_crl_entry.h"
#include "cert_crl_collection.h"

namespace OHOS {
    constexpr int TEST_VERSION = 3;
    constexpr int TEST_OFFSET_TIME = 1000;
    constexpr int TEST_SN = 1000;
    constexpr int TEST_TIME = 1986598400;
    constexpr int TEST_OFFSET = 10;
    constexpr int TEST_CRL_LEN = 256;

    HcfKeyPair *g_keyPair = nullptr;
    ASN1_TIME *g_lastUpdate = nullptr;
    ASN1_TIME *g_nextUpdate = nullptr;
    ASN1_TIME *g_rvTime = nullptr;
    static bool g_testFlag = true;

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
    const CfEncodingBlob g_crlDerInStream = { const_cast<uint8_t *>(g_crlDerData),
        sizeof(g_crlDerData), CF_FORMAT_DER };

    static void FreeCrlData()
    {
        if (g_keyPair != nullptr) {
            CfObjDestroy(g_keyPair);
            g_keyPair = nullptr;
        }
        if (g_lastUpdate != nullptr) {
            ASN1_TIME_free(g_lastUpdate);
            g_lastUpdate = nullptr;
        }
        if (g_nextUpdate != nullptr) {
            ASN1_TIME_free(g_nextUpdate);
            g_nextUpdate = nullptr;
        }
        if (g_rvTime != nullptr) {
            ASN1_TIME_free(g_rvTime);
            g_rvTime = nullptr;
        }
    }

    static unsigned char *GetCrlStream()
    {
        unsigned char *buf = nullptr;
        unsigned char *p = nullptr;
        HcfAsyKeyGenerator *generator = nullptr;
        HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_3", &generator);
        generator->generateKeyPair(generator, nullptr, &g_keyPair);
        RSA *rsaPrikey = (reinterpret_cast<HcfOpensslRsaPriKey *>(g_keyPair->priKey))->sk;
        EVP_PKEY *prikey = EVP_PKEY_new();
        EVP_PKEY_assign_RSA(prikey, rsaPrikey);

        X509_CRL *crl = X509_CRL_new();
        (void)X509_CRL_set_version(crl, TEST_VERSION);

        // Set Issuer
        X509_NAME *issuer = X509_NAME_new();
        const char *tmp = "CRL issuer";
        (void)X509_NAME_add_entry_by_NID(issuer, NID_commonName, V_ASN1_PRINTABLESTRING,
            reinterpret_cast<const unsigned char *>(tmp), 10, -1, 0);
        (void)X509_CRL_set_issuer_name(crl, issuer);

        g_lastUpdate = ASN1_TIME_new();
        time_t t = time(nullptr);
        ASN1_TIME_set(g_lastUpdate, t + TEST_OFFSET_TIME);
        (void)X509_CRL_set_lastUpdate(crl, g_lastUpdate);

        g_nextUpdate = ASN1_TIME_new();
        t = TEST_TIME;
        ASN1_TIME_set(g_nextUpdate, t);
        (void)X509_CRL_set_nextUpdate(crl, g_nextUpdate);

        X509_REVOKED *revoked = X509_REVOKED_new();
        ASN1_INTEGER *serial = ASN1_INTEGER_new();
        (void)ASN1_INTEGER_set(serial, TEST_SN);
        (void)X509_REVOKED_set_serialNumber(revoked, serial);

        g_rvTime = ASN1_TIME_new();
        t = TEST_TIME;
        ASN1_TIME_set(g_rvTime, t);
        (void)X509_CRL_set_nextUpdate(crl, g_rvTime);
        (void)X509_REVOKED_set_revocationDate(revoked, g_rvTime);
        (void)X509_CRL_add0_revoked(crl, revoked);

        (void)X509_CRL_sort(crl);
        (void)X509_CRL_sign(crl, prikey, EVP_sha256());
        int len = i2d_X509_CRL(crl, nullptr);
        buf = reinterpret_cast<unsigned char *>(malloc(len + TEST_OFFSET));
        p = buf;
        (void)i2d_X509_CRL(crl, &p);
        return buf;
    }

    static void TestX509CrlPemName(HcfX509Crl *x509CrlPem)
    {
        CfBlob toStringBlob = { 0 };
        (void)x509CrlPem->toString(x509CrlPem, &toStringBlob);
        CfBlobDataClearAndFree(&toStringBlob);

        CfBlob hashCodeBlob = { 0 };
        (void)x509CrlPem->hashCode(x509CrlPem, &hashCodeBlob);
        CfBlobDataClearAndFree(&hashCodeBlob);

        CfBlob extensionsObjectBlob = { 0 };
        (void)x509CrlPem->getExtensionsObject(x509CrlPem, &extensionsObjectBlob);
        CfBlobDataClearAndFree(&extensionsObjectBlob);
    }

    static void TestX509CrlPem(HcfX509Crl *x509CrlPem)
    {
        CfEncodingBlob encodingBlob = { 0 };
        (void)x509CrlPem->getEncoded(x509CrlPem, &encodingBlob);
        if (encodingBlob.data != nullptr) {
            CfFree(encodingBlob.data);
        }
        CfBlob issuerName = { 0 };
        (void)x509CrlPem->getIssuerName(x509CrlPem, &issuerName);
        if (issuerName.data != nullptr) {
            CfFree(issuerName.data);
        }
        CfBlob lastUpdate = { 0 };
        (void)x509CrlPem->getLastUpdate(x509CrlPem, &lastUpdate);
        if (lastUpdate.data != nullptr) {
            CfFree(lastUpdate.data);
        }
        CfBlob nextUpdate = { 0 };
        (void)x509CrlPem->getNextUpdate(x509CrlPem, &nextUpdate);
        if (nextUpdate.data != nullptr) {
            CfFree(nextUpdate.data);
        }
        (void)x509CrlPem->base.getType(&(x509CrlPem->base));
        TestX509CrlPemName(x509CrlPem);
        HcfX509Certificate *x509Cert = nullptr;
        CfEncodingBlob inStreamCert = { 0 };
        inStreamCert.data = reinterpret_cast<uint8_t *>(g_testCert);
        inStreamCert.encodingFormat = CF_FORMAT_PEM;
        inStreamCert.len = strlen(g_testCert) + 1;
        CfResult result = HcfX509CertificateCreate(&inStreamCert, &x509Cert);
        if (result != CF_SUCCESS) {
            return;
        }
        HcfX509CrlEntry *crlEntry = nullptr;
        x509CrlPem->getRevokedCertWithCert(x509CrlPem, x509Cert, &crlEntry);
        if (crlEntry != nullptr) {
            CfObjDestroy(crlEntry);
        }
        (void)x509CrlPem->base.isRevoked(&(x509CrlPem->base), &(x509Cert->base));
        CfObjDestroy(x509Cert);
    }

    static void TestX509CrlEntryName(HcfX509CrlEntry *entry)
    {
        CfBlob toStringBlob = { 0 };
        entry->toString(entry, &toStringBlob);
        CfBlobDataClearAndFree(&toStringBlob);

        CfBlob hashCodeBlob = { 0 };
        entry->hashCode(entry, &hashCodeBlob);
        CfBlobDataClearAndFree(&hashCodeBlob);

        CfBlob extensionsObjectBlob = { 0 };
        entry->getExtensionsObject(entry, &extensionsObjectBlob);
        CfBlobDataClearAndFree(&extensionsObjectBlob);
    }

    static void TestX509CrlEntry(HcfX509Crl *x509CrlDer, const uint8_t *data, size_t size)
    {
        long serialNumber = 1000;
		CfBlob serialBlob = { sizeof(long), reinterpret_cast<uint8_t *>(&serialNumber) };
        HcfX509CrlEntry *entry = nullptr;
        x509CrlDer->getRevokedCert(x509CrlDer, &serialBlob, &entry);
        if (entry != nullptr) {
            CfEncodingBlob entryEncoded = { 0 };
            entry->getEncoded(entry, &entryEncoded);
            if (entryEncoded.data != nullptr) {
                CfFree(entryEncoded.data);
            }
            CfBlob certIssuer = { 0 };
            entry->getCertIssuer(entry, &certIssuer);
            if (certIssuer.data != nullptr) {
                CfFree(certIssuer.data);
            }
            CfBlob revocationDate = { 0 };
            entry->getRevocationDate(entry, &revocationDate);
            if (revocationDate.data != nullptr) {
                CfFree(revocationDate.data);
            }
            CfBlob snBlob = { 0 };
            entry->getSerialNumber(entry, &snBlob);
            if (snBlob.data != nullptr) {
                CfFree(snBlob.data);
            }

            TestX509CrlEntryName(entry);
            CfObjDestroy(entry);
        }
        if (size >= sizeof(long)) {
            entry = nullptr;
            serialBlob.size = sizeof(long);
            serialBlob.data = const_cast<uint8_t *>(data);
            x509CrlDer->getRevokedCert(x509CrlDer, &serialBlob, &entry);
            if (entry != nullptr) {
                CfObjDestroy(entry);
            }
        }
    }

    static void TestX509CrlDer(HcfX509Crl *x509CrlDer)
    {
        CfArray entrys = { 0 };
        x509CrlDer->getRevokedCerts(x509CrlDer, &entrys);
        if (entrys.data != nullptr) {
            HcfX509CrlEntry *crlEntry = reinterpret_cast<HcfX509CrlEntry *>(entrys.data[0].data);
            CfObjDestroy(crlEntry);
        }

        CfBlob signature = { 0 };
        x509CrlDer->getSignature(x509CrlDer, &signature);
        if (signature.data != nullptr) {
            CfFree(signature.data);
        }
        CfBlob signatureAlgName = { 0 };
        x509CrlDer->getSignatureAlgName(x509CrlDer, &signatureAlgName);
        if (signatureAlgName.data != nullptr) {
            CfFree(signatureAlgName.data);
        }
        CfBlob signatureAlgOid = { 0 };
        x509CrlDer->getSignatureAlgOid(x509CrlDer, &signatureAlgOid);
        if (signatureAlgOid.data != nullptr) {
            CfFree(signatureAlgOid.data);
        }
        CfBlob signatureAlgParams = { 0 };
        x509CrlDer->getSignatureAlgParams(x509CrlDer, &signatureAlgParams);
        if (signatureAlgParams.data != nullptr) {
            CfFree(signatureAlgParams.data);
        }
        CfBlob tbsInfo = { 0 };
        x509CrlDer->getTbsInfo(x509CrlDer, &tbsInfo);
        if (tbsInfo.data != nullptr) {
            CfFree(tbsInfo.data);
        }
        (void)x509CrlDer->getVersion(x509CrlDer);
        (void)x509CrlDer->verify(x509CrlDer, g_keyPair->pubKey);
    }

    bool FuzzDoX509CrlTest(const uint8_t *data, size_t size)
    {
        HcfX509Crl *x509CrlDer = nullptr;
        CfEncodingBlob crlDerInStream = { 0 };
        unsigned char *crlStream = GetCrlStream();
        crlDerInStream.data = reinterpret_cast<uint8_t *>(crlStream);
        crlDerInStream.encodingFormat = CF_FORMAT_DER;
        crlDerInStream.len = TEST_CRL_LEN;
        CfResult result = HcfX509CrlCreate(&crlDerInStream, &x509CrlDer);
        CfFree(crlStream);
        if (result != CF_SUCCESS) {
            FreeCrlData();
            return false;
        }
        CfEncodingBlob crlPemInStream = { 0 };
        crlPemInStream.data = reinterpret_cast<uint8_t *>(g_testCrl);
        crlPemInStream.encodingFormat = CF_FORMAT_PEM;
        crlPemInStream.len = strlen(g_testCrl) + 1;
        HcfX509Crl *x509CrlPem = nullptr;
        result = HcfX509CrlCreate(&crlPemInStream, &x509CrlPem);
        if (result != CF_SUCCESS) {
            FreeCrlData();
            CfObjDestroy(x509CrlDer);
            return false;
        }
        TestX509CrlPem(x509CrlPem);
        CfObjDestroy(x509CrlPem);

        TestX509CrlEntry(x509CrlDer, data, size);
        TestX509CrlDer(x509CrlDer);
        FreeCrlData();
        CfObjDestroy(x509CrlDer);

        HcfX509Crl *x509Crl = nullptr;
        CfEncodingBlob crlInStream = { 0 };
        crlInStream.data = const_cast<uint8_t *>(data);
        crlInStream.encodingFormat = CF_FORMAT_PEM;
        crlInStream.len = size;
        result = HcfX509CrlCreate(&crlInStream, &x509Crl);
        if (result == CF_SUCCESS) {
            CfObjDestroy(x509Crl);
        }
        return true;
    }
    void OneCrlCollectionTest()
    {
        CfEncodingBlob inStream = { 0 };
        HcfX509Crl *x509Crl = nullptr;
        HcfCertCrlCollection *x509CertCrlCollection = nullptr;
        HcfX509Certificate *x509CertObj = nullptr;
        HcfX509CertificateArray certArray = { 0 };
        HcfX509CrlArray crlArray = { 0 };
        inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testSelfSignedCaCert));
        inStream.encodingFormat = CF_FORMAT_PEM;
        inStream.len = strlen(g_testSelfSignedCaCert) + 1;
        CfResult ret = HcfX509CertificateCreate(&inStream, &x509CertObj);
        if (ret != CF_SUCCESS || x509CertObj == nullptr) {
            goto Exit;
        }
        ret = HcfX509CrlCreate(&g_crlDerInStream, &x509Crl);
        if (ret != CF_SUCCESS || x509Crl == nullptr) {
            goto Exit;
        }
        certArray.data = static_cast<HcfX509Certificate **>(CfMalloc(1 * sizeof(HcfX509Certificate *), 0));
        if (certArray.data == nullptr) {
            goto Exit;
        }
        certArray.data[0] = x509CertObj;
        certArray.count = 1;

        crlArray.data = static_cast<HcfX509Crl **>(CfMalloc(1 * sizeof(HcfX509Crl *), 0));
        if (crlArray.data == nullptr) {
            goto Exit;
        }
        crlArray.data[0] = x509Crl;
        crlArray.count = 1;

        ret = HcfCertCrlCollectionCreate(&certArray, &crlArray, &x509CertCrlCollection);
        if (ret != CF_SUCCESS || x509CertCrlCollection == nullptr) {
            goto Exit;
        }

    Exit:
        CfObjDestroy(x509CertObj);
        CfObjDestroy(x509Crl);
        CfFree(crlArray.data);
        CfFree(certArray.data);
        CfObjDestroy(x509CertCrlCollection);
    }

    void FuzzDoX509CrlCollectionTest(const uint8_t *data, size_t size, CfEncodingFormat format)
    {
        if (g_testFlag) {
            OneCrlCollectionTest();
            g_testFlag = false;
        }
        
        if (data == nullptr || size < sizeof(HcfX509Certificate) || size < sizeof(HcfX509Crl)) {
            return;
        }

        HcfX509CertificateArray certArray = { 0 };
        HcfX509CrlArray crlArray = { 0 };
        HcfCertCrlCollection *x509CertCrlCollection = nullptr;
        HcfX509Crl *x509Crl = nullptr;
        HcfX509Certificate *x509CertObj = nullptr;

        const CfEncodingBlob inStream = { reinterpret_cast<uint8_t *>(const_cast<char *>(g_testSelfSignedCaCert)),
            sizeof(g_testSelfSignedCaCert) + 1, CF_FORMAT_DER };
        CfResult ret = HcfX509CertificateCreate(&inStream, &x509CertObj);
        if (ret != CF_SUCCESS || x509CertObj == nullptr) {
            return;
        }

        const CfEncodingBlob crlDerInStream = { const_cast<uint8_t *>(data), size, CF_FORMAT_DER };
        ret = HcfX509CrlCreate(&crlDerInStream, &x509Crl);
        if (ret != CF_SUCCESS || x509Crl == nullptr) {
            return;
        }
        certArray.data = static_cast<HcfX509Certificate **>(CfMalloc(1 * sizeof(HcfX509Certificate *), 0));
        if (certArray.data == nullptr) {
            return;
        }
        certArray.data[0] = x509CertObj;
        certArray.count = 1;

        crlArray.data = static_cast<HcfX509Crl **>(CfMalloc(1 * sizeof(HcfX509Crl *), 0));
        if (crlArray.data == nullptr) {
            CfFree(certArray.data);
            return;
        }
        crlArray.data[0] = x509Crl;
        crlArray.count = 1;

        ret = HcfCertCrlCollectionCreate(&certArray, &crlArray, &x509CertCrlCollection);
        if (ret != CF_SUCCESS || x509CertCrlCollection == nullptr) {
            CfFree(certArray.data);
            CfFree(crlArray.data);
            return;
        }

        CfFree(certArray.data);
        CfFree(crlArray.data);
        CfObjDestroy(x509CertCrlCollection);
        return;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::FuzzDoX509CrlTest(data, size);
    OHOS::FuzzDoX509CrlCollectionTest(data, size, CF_FORMAT_DER);
    OHOS::FuzzDoX509CrlCollectionTest(data, size, CF_FORMAT_PEM);
    OHOS::FuzzDoX509CrlCollectionTest(data, size, CF_FORMAT_PKCS7);
    return 0;
}
