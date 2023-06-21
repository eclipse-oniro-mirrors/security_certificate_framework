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
#include "cf_blob.h"
#include "cipher.h"
#include "key_pair.h"
#include "cf_memory.h"
#include "certificate_openssl_class.h"
#include "cf_result.h"
#include "securec.h"
#include "x509_certificate.h"
#include "x509_crl.h"
#include "x509_crl_entry.h"

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

    static char g_testCrl[] =
    "-----BEGIN X509 CRL-----\r\n"
    "MIIB/DCB5QIBATANBgkqhkiG9w0BAQsFADCBjDELMAkGA1UEBhMCQ04xETAPBgNV\r\n"
    "BAgMCHNoYW5naGFpMQ8wDQYDVQQHDAZodWF3ZWkxFTATBgNVBAoMDHd3dy50ZXN0\r\n"
    "LmNvbTENMAsGA1UECwwEdGVzdDEVMBMGA1UEAwwMd3d3LnRlc3QuY29tMRwwGgYJ\r\n"
    "KoZIhvcNAQkBFg10ZXN0QHRlc3QuY29tFw0yMjA4MjkwNzAwMTRaFw0yMjA5Mjgw\r\n"
    "NzAwMTRaMBQwEgIBARcNMjIwODI5MDY1OTUzWqAOMAwwCgYDVR0UBAMCAQAwDQYJ\r\n"
    "KoZIhvcNAQELBQADggEBAHpfFhhUR59OAvOSuKDQUC5tKeLEuPbY8bYdmQVI8EFd\r\n"
    "xDkZTXmT3CX1aDPYKVsG/jH9KPAmCV/ODKEGiJzclb3Z4am7tT+Wy4mpXypNS1od\r\n"
    "wPDcQGsMrjT6iSp6JImiB0dDDSleBTBcYR/hhtFaiGSncyqJ0mhyaXPxIkNOO6nY\r\n"
    "v+rcTEPQWavViDRyNDhnTbN868I3fzFVBcidF13CA0sCJ91ZvsE9h/YmPO2+e0YE\r\n"
    "IUgzn37UOiLGObCVBY12QjGiuvVvCl7ncncsFEJuGfvONOqyFHjyxDHo5W0fqTn2\r\n"
    "eCtiNcgUr9Kz2bwCmvEXhP7PuF4RMLq4vfzi0YjCG98=\r\n"
    "-----END X509 CRL-----\r\n";

    static char g_testCert[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIID/jCCAuagAwIBAgIBATANBgkqhkiG9w0BAQsFADCBjDELMAkGA1UEBhMCQ04x\r\n"
    "ETAPBgNVBAgMCHNoYW5naGFpMQ8wDQYDVQQHDAZodWF3ZWkxFTATBgNVBAoMDHd3\r\n"
    "dy50ZXN0LmNvbTENMAsGA1UECwwEdGVzdDEVMBMGA1UEAwwMd3d3LnRlc3QuY29t\r\n"
    "MRwwGgYJKoZIhvcNAQkBFg10ZXN0QHRlc3QuY29tMB4XDTIyMDgyOTA2NTUwM1oX\r\n"
    "DTIzMDgyOTA2NTUwM1owezELMAkGA1UEBhMCQ04xETAPBgNVBAgMCHNoYW5naGFp\r\n"
    "MRUwEwYDVQQKDAx3d3cudGVzdC5jb20xDTALBgNVBAsMBHRlc3QxFTATBgNVBAMM\r\n"
    "DHd3dy50ZXN0LmNvbTEcMBoGCSqGSIb3DQEJARYNdGVzdEB0ZXN0LmNvbTCCASIw\r\n"
    "DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJmY9T4SzXXwKvfMvnvMWY7TqUJK\r\n"
    "jnWf2Puv0YUQ2fdvyoKQ2LQXdtzoUL53j587oI+IXelOr7dg020zPyun0cmZHZ4y\r\n"
    "l/qAcrWbDjZeEGcbbb5UtQtn1WOEnv8pkXluO355mbZQUKK9L3gFWseXJKGbIXw0\r\n"
    "NRpaJZzqvPor4m3a5pmJKPHOlivUdYfLaKSkNj3DlaFzCWKV82k5ee6gzVyETtG+\r\n"
    "XN+vq8qLybT+fIFsLNMmAHzRxlqz3NiH7yh+1/p/Knvf8bkkRVR2btH51RyX2RSu\r\n"
    "DjPM0/VRL8fxDSDeWBq+Gvn/E6AbOVMmkx63tcyWHhklCSaZtyz7kq39TQMCAwEA\r\n"
    "AaN7MHkwCQYDVR0TBAIwADAsBglghkgBhvhCAQ0EHxYdT3BlblNTTCBHZW5lcmF0\r\n"
    "ZWQgQ2VydGlmaWNhdGUwHQYDVR0OBBYEFFiFDysfADQCzRZCOSPupQxFicwzMB8G\r\n"
    "A1UdIwQYMBaAFNYQRQiPsG8HefOTsmsVhaVjY7IPMA0GCSqGSIb3DQEBCwUAA4IB\r\n"
    "AQAeppxf6sKQJxJQXKPTT3xHKaskidNwDBbOSIvnVvWXicZXDs+1sF6tUaRgvPxL\r\n"
    "OL58+P2Jy0tfSwj2WhqQRGe9MvQ5iFHcdelZc0ciW6EQ0VDHIaDAQc2nQzej/79w\r\n"
    "UE7BJJV3b9n1be2iCsuodKO14pOkMb84WcIxng+8SD+MiFqV5BPO1QyKGdO1PE1b\r\n"
    "+evjyTpFSTgZf2Mw3fGtu5hfEXyHw1lnsFY2MlSwiRlAym/gm4aXy+4H6LyXKd56\r\n"
    "UYQ6fituD0ziaw3RI6liyIe7aENHCkZf6bAvMRhk4QiU4xu6emwX8Qt1bT7RthP0\r\n"
    "1Vsro0IOeXT9WAcqEtQUegsi\r\n"
    "-----END CERTIFICATE-----\r\n";

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

    static void TestX509CrlEntry(HcfX509Crl *x509CrlDer, const uint8_t *data, size_t size)
    {
        long serialNumber = 1000;
        HcfX509CrlEntry *entry = nullptr;
        x509CrlDer->getRevokedCert(x509CrlDer, serialNumber, &entry);
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
            CfObjDestroy(entry);
        }
        if (size >= sizeof(long)) {
            entry = nullptr;
            const long *serialNumberPtr = reinterpret_cast<const long *>(data);
            x509CrlDer->getRevokedCert(x509CrlDer, *serialNumberPtr, &entry);
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

    bool FuzzDoX509CrlTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size < sizeof(long))) {
            return false;
        }
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
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::FuzzDoX509CrlTest(data, size);
    return 0;
}
