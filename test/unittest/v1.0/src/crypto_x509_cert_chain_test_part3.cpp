/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <openssl/pem.h>

#include "cert_crl_common.h"
#include "cf_blob.h"
#include "cf_log.h"
#include "cf_mock.h"
#include "cf_object_base.h"
#include "cf_result.h"
#include "crypto_x509_test_common.h"
#include "memory_mock.h"
#include "securec.h"
#include "string"
#include "x509_cert_chain.h"
#include "x509_cert_chain_openssl.h"
#include "x509_certificate_openssl.h"

using namespace std;
using namespace testing::ext;
using namespace CFMock;

using ::testing::_;
using ::testing::AnyNumber;
using ::testing::Invoke;
using ::testing::Return;

#ifdef __cplusplus
extern "C" {
#endif

int __real_BIO_do_connect_retry(BIO *b, int timeout, int retry);
void *__real_X509_get_ext_d2i(const X509 *x, int nid, int *crit, int *idx);
unsigned long __real_ERR_peek_last_error(void);
X509_CRL *__real_X509_CRL_load_http(const char *url, BIO *bio, BIO *rbio, int timeout);
int __real_OPENSSL_sk_num(const OPENSSL_STACK *st);
void *__real_OPENSSL_sk_value(const OPENSSL_STACK *st, int i);
CfResult __real_CfGetCertIdInfo(STACK_OF(X509) *x509CertChain, const CfBlob *ocspDigest,
    OcspCertIdInfo *certIdInfo, int index);

void ResetMockFunctionPartOne(void)
{
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        BIO_do_connect_retry(_, _, _)).Times(AnyNumber()).WillRepeatedly(Invoke(__real_BIO_do_connect_retry));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        X509_get_ext_d2i(_, _, _, _)).Times(AnyNumber()).WillRepeatedly(Invoke(__real_X509_get_ext_d2i));
}

void ResetMockFunction(void)
{
    ResetMockFunctionPartOne();
}

#ifdef __cplusplus
}
#endif

namespace {
class CryptoX509CertChainTestPart3 : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

static const char g_testRootCertValid[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIIDjjCCAnagAwIBAgIQAzrx5qcRqaC7KGSxHQn65TANBgkqhkiG9w0BAQsFADBh\r\n"
    "MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3\r\n"
    "d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBH\r\n"
    "MjAeFw0xMzA4MDExMjAwMDBaFw0zODAxMTUxMjAwMDBaMGExCzAJBgNVBAYTAlVT\r\n"
    "MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j\r\n"
    "b20xIDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IEcyMIIBIjANBgkqhkiG\r\n"
    "9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuzfNNNx7a8myaJCtSnX/RrohCgiN9RlUyfuI\r\n"
    "2/Ou8jqJkTx65qsGGmvPrC3oXgkkRLpimn7Wo6h+4FR1IAWsULecYxpsMNzaHxmx\r\n"
    "1x7e/dfgy5SDN67sH0NO3Xss0r0upS/kqbitOtSZpLYl6ZtrAGCSYP9PIUkY92eQ\r\n"
    "q2EGnI/yuum06ZIya7XzV+hdG82MHauVBJVJ8zUtluNJbd134/tJS7SsVQepj5Wz\r\n"
    "tCO7TG1F8PapspUwtP1MVYwnSlcUfIKdzXOS0xZKBgyMUNGPHgm+F6HmIcr9g+UQ\r\n"
    "vIOlCsRnKPZzFBQ9RnbDhxSJITRNrw9FDKZJobq7nMWxM4MphQIDAQABo0IwQDAP\r\n"
    "BgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQUTiJUIBiV\r\n"
    "5uNu5g/6+rkS7QYXjzkwDQYJKoZIhvcNAQELBQADggEBAGBnKJRvDkhj6zHd6mcY\r\n"
    "1Yl9PMWLSn/pvtsrF9+wX3N3KjITOYFnQoQj8kVnNeyIv/iPsGEMNKSuIEyExtv4\r\n"
    "NeF22d+mQrvHRAiGfzZ0JFrabA0UWTW98kndth/Jsw1HKj2ZL7tcu7XUIOGZX1NG\r\n"
    "Fdtom/DzMNU+MeKNhJ7jitralj41E6Vf8PlwUHBHQRFXGU7Aj64GxJUTFy8bJZ91\r\n"
    "8rGOmaFvE7FBcf6IKshPECBV1/MUReXgRPTqh5Uykw7+U0b6LJ3/iyK5S9kJRaTe\r\n"
    "pLiaWN0bfVKfjllDiIGknibVb63dDcY3fe0Dkhvld1927jyNxF1WW6LZZm6zNTfl\r\n"
    "MrY=\r\n"
    "-----END CERTIFICATE-----\r\n";

static const char g_testCaChainValid[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIIGIzCCBQugAwIBAgIQD8vHwz7g05mDl1F5X17HGzANBgkqhkiG9w0BAQsFADBg\r\n"
    "MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3\r\n"
    "d3cuZGlnaWNlcnQuY29tMR8wHQYDVQQDExZSYXBpZFNTTCBUTFMgUlNBIENBIEcx\r\n"
    "MB4XDTI1MDMyNDAwMDAwMFoXDTI2MDMyMzIzNTk1OVowFzEVMBMGA1UEAwwMKi5k\r\n"
    "b3ViYW8uY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw6eEA/GD\r\n"
    "ShJ0Rtlet3Lf+uYiYzzFJ6J1iJeT/JyvTwDOTKO2VgMjsFHgUcFJBG6QGZT6PXSv\r\n"
    "vhkdzzIqqXzJwDsqqowwTwMk0YN/JUB0yr/9aFlmQakLZClu1W5og7uxp4ME+ep6\r\n"
    "aJhoQ9MMCCn3/pvDnLoX1hG9z0pgbUsnIrM+1roLpH+D0FwC4jww7+tDr89/kjb4\r\n"
    "/+LMqjAbe1fLtXJRuxH5O+kAQNqLL/0ECvq+4KpC/r/0UxTlRTpGZY2M3MPUEXfp\r\n"
    "RKMmkRoRSKwDMJ5u2DK0qanvV6mu7ORPoDsC/fTAiqonjh8rClm/zpj5GN9BQKfu\r\n"
    "UoaeWIN/XMZSzQIDAQABo4IDIDCCAxwwHwYDVR0jBBgwFoAUDNtsgkkPSmcKuBTu\r\n"
    "esRIUojrVjgwHQYDVR0OBBYEFCseEe+vZQ8BzqzkOju1EhGQwoCYMCMGA1UdEQQc\r\n"
    "MBqCDCouZG91YmFvLmNvbYIKZG91YmFvLmNvbTA+BgNVHSAENzA1MDMGBmeBDAEC\r\n"
    "ATApMCcGCCsGAQUFBwIBFhtodHRwOi8vd3d3LmRpZ2ljZXJ0LmNvbS9DUFMwDgYD\r\n"
    "VR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjA/BgNV\r\n"
    "HR8EODA2MDSgMqAwhi5odHRwOi8vY2RwLnJhcGlkc3NsLmNvbS9SYXBpZFNTTFRM\r\n"
    "U1JTQUNBRzEuY3JsMHYGCCsGAQUFBwEBBGowaDAmBggrBgEFBQcwAYYaaHR0cDov\r\n"
    "L3N0YXR1cy5yYXBpZHNzbC5jb20wPgYIKwYBBQUHMAKGMmh0dHA6Ly9jYWNlcnRz\r\n"
    "LnJhcGlkc3NsLmNvbS9SYXBpZFNTTFRMU1JTQUNBRzEuY3J0MAwGA1UdEwEB/wQC\r\n"
    "MAAwggF9BgorBgEEAdZ5AgQCBIIBbQSCAWkBZwB2AA5XlLzzrqk+MxssmQez95Df\r\n"
    "m8I9cTIl3SGpJaxhxU4hAAABlcjhhZsAAAQDAEcwRQIhAKfZw1gNPE4sWKi3WL0U\r\n"
    "vO4EGn+MD1hScKPMNHex6Ty+AiBv0yYWRuEURh/8ywDMHC+1f3xFaj9kshfv389b\r\n"
    "e09MhAB1AGQRxGykEuyniRyiAi4AvKtPKAfUHjUnq+r+1QPJfc3wAAABlcjhhcUA\r\n"
    "AAQDAEYwRAIgClXL9SnQFh+6HEqsT/3aBM6jK9NmzG+hrmJGowOKVFYCIEsGPJda\r\n"
    "TtsBnc/PrhZSjOHitpzrzKhW02hHOzkrtlR/AHYASZybad4dfOz8Nt7Nh2SmuFuv\r\n"
    "CoeAGdFVUvvp6ynd+MMAAAGVyOGF3gAABAMARzBFAiBExgNNV8q5xfdSU+yL6NAJ\r\n"
    "l1ze5IYXTetQf04caLUhKgIhALvTCHHHdvokmFbRKQvrY50ihwDoHd4pKbzRtyQ0\r\n"
    "H16bMA0GCSqGSIb3DQEBCwUAA4IBAQAsjyQpYDf1JiYBsO4koUcFPeAdvTp9FbRL\r\n"
    "yC0PN34rekPHwcjqsEU7mbuUaZ4EMklHqIqkniStPcKyIDCpSwBu17iezM57fwJA\r\n"
    "tb9XfzjxZH1vWEFHImcvMEwR0BLRmwXUnnRt3qOeetTV/UpIwH4HGfHldtRNqSnj\r\n"
    "xDiM1c2oRjv+4Qs5CTet70NHsaQBjkUWvioCgigE+vuCPnjwVNXJkfSHjC+DWWzf\r\n"
    "Nc+rSFEOvO8Fe4d2rvboT7vXigvTciOeQdig9ySCJQCkWxOvB1AcvZc+kw0YhrpM\r\n"
    "xUBhDd+DaUWOgmmVS3n6k3GfOqm2EU7iCp8KyfRu2DAsnlsO/YpH\r\n"
    "-----END CERTIFICATE----- \r\n"
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIIEszCCA5ugAwIBAgIQCyWUIs7ZgSoVoE6ZUooO+jANBgkqhkiG9w0BAQsFADBh\r\n"
    "MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3\r\n"
    "d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBH\r\n"
    "MjAeFw0xNzExMDIxMjI0MzNaFw0yNzExMDIxMjI0MzNaMGAxCzAJBgNVBAYTAlVT\r\n"
    "MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j\r\n"
    "b20xHzAdBgNVBAMTFlJhcGlkU1NMIFRMUyBSU0EgQ0EgRzEwggEiMA0GCSqGSIb3\r\n"
    "DQEBAQUAA4IBDwAwggEKAoIBAQC/uVklRBI1FuJdUEkFCuDL/I3aJQiaZ6aibRHj\r\n"
    "ap/ap9zy1aYNrphe7YcaNwMoPsZvXDR+hNJOo9gbgOYVTPq8gXc84I75YKOHiVA4\r\n"
    "NrJJQZ6p2sJQyqx60HkEIjzIN+1LQLfXTlpuznToOa1hyTD0yyitFyOYwURM+/CI\r\n"
    "8FNFMpBhw22hpeAQkOOLmsqT5QZJYeik7qlvn8gfD+XdDnk3kkuuu0eG+vuyrSGr\r\n"
    "5uX5LRhFWlv1zFQDch/EKmd163m6z/ycx/qLa9zyvILc7cQpb+k7TLra9WE17YPS\r\n"
    "n9ANjG+ECo9PDW3N9lwhKQCNvw1gGoguyCQu7HE7BnW8eSSFAgMBAAGjggFmMIIB\r\n"
    "YjAdBgNVHQ4EFgQUDNtsgkkPSmcKuBTuesRIUojrVjgwHwYDVR0jBBgwFoAUTiJU\r\n"
    "IBiV5uNu5g/6+rkS7QYXjzkwDgYDVR0PAQH/BAQDAgGGMB0GA1UdJQQWMBQGCCsG\r\n"
    "AQUFBwMBBggrBgEFBQcDAjASBgNVHRMBAf8ECDAGAQH/AgEAMDQGCCsGAQUFBwEB\r\n"
    "BCgwJjAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEIGA1Ud\r\n"
    "HwQ7MDkwN6A1oDOGMWh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEds\r\n"
    "b2JhbFJvb3RHMi5jcmwwYwYDVR0gBFwwWjA3BglghkgBhv1sAQEwKjAoBggrBgEF\r\n"
    "BQcCARYcaHR0cHM6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzALBglghkgBhv1sAQIw\r\n"
    "CAYGZ4EMAQIBMAgGBmeBDAECAjANBgkqhkiG9w0BAQsFAAOCAQEAGUSlOb4K3Wtm\r\n"
    "SlbmE50UYBHXM0SKXPqHMzk6XQUpCheF/4qU8aOhajsyRQFDV1ih/uPIg7YHRtFi\r\n"
    "CTq4G+zb43X1T77nJgSOI9pq/TqCwtukZ7u9VLL3JAq3Wdy2moKLvvC8tVmRzkAe\r\n"
    "0xQCkRKIjbBG80MSyDX/R4uYgj6ZiNT/Zg6GI6RofgqgpDdssLc0XIRQEotxIZcK\r\n"
    "zP3pGJ9FCbMHmMLLyuBd+uCWvVcF2ogYAawufChS/PT61D9rqzPRS5I2uqa3tmIT\r\n"
    "44JhJgWhBnFMb7AGQkvNq9KNS9dd3GWc17H/dXa1enoxzWjE0hBdFjxPhUb0W3wi\r\n"
    "8o34/m8Fxw==\r\n"
    "-----END CERTIFICATE-----\r\n"
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIIDjjCCAnagAwIBAgIQAzrx5qcRqaC7KGSxHQn65TANBgkqhkiG9w0BAQsFADBh\r\n"
    "MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3\r\n"
    "d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBH\r\n"
    "MjAeFw0xMzA4MDExMjAwMDBaFw0zODAxMTUxMjAwMDBaMGExCzAJBgNVBAYTAlVT\r\n"
    "MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j\r\n"
    "b20xIDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IEcyMIIBIjANBgkqhkiG\r\n"
    "9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuzfNNNx7a8myaJCtSnX/RrohCgiN9RlUyfuI\r\n"
    "2/Ou8jqJkTx65qsGGmvPrC3oXgkkRLpimn7Wo6h+4FR1IAWsULecYxpsMNzaHxmx\r\n"
    "1x7e/dfgy5SDN67sH0NO3Xss0r0upS/kqbitOtSZpLYl6ZtrAGCSYP9PIUkY92eQ\r\n"
    "q2EGnI/yuum06ZIya7XzV+hdG82MHauVBJVJ8zUtluNJbd134/tJS7SsVQepj5Wz\r\n"
    "tCO7TG1F8PapspUwtP1MVYwnSlcUfIKdzXOS0xZKBgyMUNGPHgm+F6HmIcr9g+UQ\r\n"
    "vIOlCsRnKPZzFBQ9RnbDhxSJITRNrw9FDKZJobq7nMWxM4MphQIDAQABo0IwQDAP\r\n"
    "BgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQUTiJUIBiV\r\n"
    "5uNu5g/6+rkS7QYXjzkwDQYJKoZIhvcNAQELBQADggEBAGBnKJRvDkhj6zHd6mcY\r\n"
    "1Yl9PMWLSn/pvtsrF9+wX3N3KjITOYFnQoQj8kVnNeyIv/iPsGEMNKSuIEyExtv4\r\n"
    "NeF22d+mQrvHRAiGfzZ0JFrabA0UWTW98kndth/Jsw1HKj2ZL7tcu7XUIOGZX1NG\r\n"
    "Fdtom/DzMNU+MeKNhJ7jitralj41E6Vf8PlwUHBHQRFXGU7Aj64GxJUTFy8bJZ91\r\n"
    "8rGOmaFvE7FBcf6IKshPECBV1/MUReXgRPTqh5Uykw7+U0b6LJ3/iyK5S9kJRaTe\r\n"
    "pLiaWN0bfVKfjllDiIGknibVb63dDcY3fe0Dkhvld1927jyNxF1WW6LZZm6zNTfl\r\n"
    "MrY=\r\n"
    "-----END CERTIFICATE-----\r\n";

static const char g_crlDownloadURI[] =
    "http://crl3.digicert.com/DigiCertGlobalRootG2.crl";

static CfBlob g_blobDownloadURI = { .size = static_cast<uint32_t>(strlen(g_crlDownloadURI) + 1),
    .data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_crlDownloadURI)) };

const int g_testCaChainValidSize = sizeof(g_testCaChainValid) / sizeof(char);
const CfEncodingBlob g_inCaChain = { reinterpret_cast<uint8_t *>(const_cast<char *>(g_testCaChainValid)),
    g_testCaChainValidSize, CF_FORMAT_PEM };

static CfBlob g_ocspDigest = { .size = static_cast<uint32_t>(strlen(g_digest) + 1),
    .data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_digest)) };

static void FreeHcfRevocationCheckParam(HcfRevocationCheckParam *param)
{
    if (param == nullptr) {
        return;
    }

    if (param->options != nullptr) {
        if (param->options->data != nullptr) {
            CfFree(param->options->data);
        }

        CfFree(param->options);
    }

    if (param->ocspResponses != nullptr) {
        CfFree(param->ocspResponses);
    }

    if (param->ocspResponderCert != nullptr) {
        CfObjDestroy(param->ocspResponderCert);
    }

    CfFree(param);
}

static HcfRevocationCheckParam *ConstructHcfRevocationCheckParam(HcfRevChkOption *data, size_t size,
    CfBlob *ocspResponderURI = NULL, CfBlob *crlDownloadURI = NULL,
    const CfEncodingBlob *ocspResponderCertStream = NULL)
{
    HcfRevChkOpArray *revChkOpArray = (HcfRevChkOpArray *)CfMalloc(sizeof(HcfRevChkOpArray), 0);
    if (revChkOpArray == nullptr) {
        return nullptr;
    }

    revChkOpArray->count = size;
    revChkOpArray->data = (HcfRevChkOption *)CfMalloc(revChkOpArray->count * sizeof(HcfRevChkOption), 0);
    if (revChkOpArray->data == nullptr) {
        CfFree(revChkOpArray);
        return nullptr;
    }

    for (size_t i = 0; i < revChkOpArray->count; i++) {
        revChkOpArray->data[i] = data[i];
    }

    CfBlob *resp = (CfBlob *)CfMalloc(sizeof(CfBlob), 0);
    if (resp == nullptr) {
        CfFree(revChkOpArray->data);
        CfFree(revChkOpArray);
        return nullptr;
    }
    resp->data = (uint8_t *)(&g_testOcspResponses[0]);
    resp->size = sizeof(g_testOcspResponses);

    HcfRevocationCheckParam *param = (HcfRevocationCheckParam *)CfMalloc(sizeof(HcfRevocationCheckParam), 0);
    if (param == nullptr) {
        CfFree(revChkOpArray->data);
        CfFree(revChkOpArray);
        return nullptr;
    }

    param->options = revChkOpArray;
    param->ocspResponses = resp;
    param->ocspResponderURI = ocspResponderURI;
    param->crlDownloadURI = crlDownloadURI;
    param->ocspDigest = &g_ocspDigest;

    if (ocspResponderCertStream != NULL) {
        (void)HcfX509CertificateCreate(&g_inStreamOcspResponderCert, &(param->ocspResponderCert));
        if (param->ocspResponderCert == nullptr) {
            FreeHcfRevocationCheckParam(param);
            return nullptr;
        }
    }

    return param;
}

void CryptoX509CertChainTestPart3::SetUpTestCase() {}

void CryptoX509CertChainTestPart3::TearDownTestCase() {}

void CryptoX509CertChainTestPart3::SetUp() {}

void CryptoX509CertChainTestPart3::TearDown() {}


HWTEST_F(CryptoX509CertChainTestPart3, ValidateOnlyCaCertTest001, TestSize.Level0)
{
    CF_LOG_I("ValidateOnlyCaCertTest001");
    HcfX509CertChainSpi *certChainPemOnlyCaCert = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&g_inStreamChainOnlyCenterCaCert, &certChainPemOnlyCaCert);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainPemOnlyCaCert, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainTrustAnchorCaCert, trustAnchorArray);


    HcfX509CertChainValidateParams params = { 0 };
    params.trustAnchors = &trustAnchorArray;

    HcfRevChkOption data[] = { REVOCATION_CHECK_OPTION_ACCESS_NETWORK,
        REVOCATION_CHECK_OPTION_CHECK_INTERMEDIATE_CA_ONLINE };
    params.revocationCheckParam = ConstructHcfRevocationCheckParam(data, sizeof(data) / sizeof(data[0]));
    ASSERT_NE(params.revocationCheckParam, nullptr);

    HcfX509CertChainValidateResult result = { 0 };
    ret = certChainPemOnlyCaCert->engineValidate(certChainPemOnlyCaCert, &params, &result);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    EXPECT_EQ(result.entityCert, nullptr);
    EXPECT_EQ(result.trustAnchor, nullptr);

    FreeValidateResult(result);
    FreeTrustAnchorArr(trustAnchorArray);
    FreeHcfRevocationCheckParam(params.revocationCheckParam);
    CfObjDestroy(certChainPemOnlyCaCert);
}

HWTEST_F(CryptoX509CertChainTestPart3, ValidateOnlyCaCertTest002, TestSize.Level0)
{
    CF_LOG_I("ValidateOnlyCaCertTest002");
    HcfX509CertChainSpi *certChainPemWithOcsp = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&g_inCaChainWithOcsp, &certChainPemWithOcsp);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainPemWithOcsp, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inCaTrustCertWithOcspPem, trustAnchorArray);


    HcfX509CertChainValidateParams params = { 0 };
    params.trustAnchors = &trustAnchorArray;

    HcfRevChkOption data[] = { REVOCATION_CHECK_OPTION_ACCESS_NETWORK, REVOCATION_CHECK_OPTION_PREFER_OCSP,
        REVOCATION_CHECK_OPTION_CHECK_INTERMEDIATE_CA_ONLINE };
    params.revocationCheckParam = ConstructHcfRevocationCheckParam(data, sizeof(data) / sizeof(data[0]));
    ASSERT_NE(params.revocationCheckParam, nullptr);

    HcfX509CertChainValidateResult result = { 0 };

    ret = certChainPemWithOcsp->engineValidate(certChainPemWithOcsp, &params, &result);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    EXPECT_EQ(result.entityCert, nullptr);
    EXPECT_EQ(result.trustAnchor, nullptr);

    FreeValidateResult(result);
    FreeTrustAnchorArr(trustAnchorArray);
    FreeHcfRevocationCheckParam(params.revocationCheckParam);
    CfObjDestroy(certChainPemWithOcsp);
}

HWTEST_F(CryptoX509CertChainTestPart3, ValidateOnlyCaCertTest003, TestSize.Level0)
{
    CF_LOG_I("ValidateOnlyCaCertTest003");
    HcfX509CertChainSpi *certChainPemWithOcsp = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&g_inCaChainWithOcsp, &certChainPemWithOcsp);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainPemWithOcsp, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inCaTrustCertWithOcspPem, trustAnchorArray);


    HcfX509CertChainValidateParams params = { 0 };
    params.trustAnchors = &trustAnchorArray;

    HcfRevChkOption data[] = { REVOCATION_CHECK_OPTION_ACCESS_NETWORK, REVOCATION_CHECK_OPTION_PREFER_OCSP,
        REVOCATION_CHECK_OPTION_CHECK_INTERMEDIATE_CA_ONLINE };
    params.revocationCheckParam = ConstructHcfRevocationCheckParam(data, sizeof(data) / sizeof(data[0]));
    ASSERT_NE(params.revocationCheckParam, nullptr);

    HcfX509CertChainValidateResult result = { 0 };

    ret = certChainPemWithOcsp->engineValidate(certChainPemWithOcsp, &params, &result);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    EXPECT_EQ(result.entityCert, nullptr);
    EXPECT_EQ(result.trustAnchor, nullptr);

    FreeValidateResult(result);
    FreeTrustAnchorArr(trustAnchorArray);
    FreeHcfRevocationCheckParam(params.revocationCheckParam);
    CfObjDestroy(certChainPemWithOcsp);
}

HWTEST_F(CryptoX509CertChainTestPart3, ValidateIgnoreNetworkErrorTest001, TestSize.Level0)
{
    HcfX509CertChainSpi *certChainPemWithOcsp = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&g_inCaChain, &certChainPemWithOcsp);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainPemWithOcsp, nullptr);
    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testRootCertValid));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testRootCertValid) + 1;

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(inStream, trustAnchorArray);

    HcfX509CertChainValidateParams params = { 0 };
    params.trustAnchors = &trustAnchorArray;

    HcfRevChkOption data[] = { REVOCATION_CHECK_OPTION_ACCESS_NETWORK, REVOCATION_CHECK_OPTION_PREFER_OCSP,
        REVOCATION_CHECK_OPTION_CHECK_INTERMEDIATE_CA_ONLINE, REVOCATION_CHECK_OPTION_IGNORE_NETWORK_ERROR };
    params.revocationCheckParam = ConstructHcfRevocationCheckParam(data, sizeof(data) / sizeof(data[0]));
    ASSERT_NE(params.revocationCheckParam, nullptr);

    HcfX509CertChainValidateResult result = { 0 };

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), OPENSSL_sk_num(_))
        .WillRepeatedly(Invoke(__real_OPENSSL_sk_num));
    EXPECT_CALL(X509OpensslMock::GetInstance(), BIO_do_connect_retry(_, _, _))
        .WillRepeatedly(Return(0));
    EXPECT_CALL(X509OpensslMock::GetInstance(), ERR_peek_last_error())
        .WillRepeatedly(Return(268435603));
    ret = certChainPemWithOcsp->engineValidate(certChainPemWithOcsp, &params, &result);
    EXPECT_EQ(ret, CF_SUCCESS);
    X509OpensslMock::SetMockFlag(false);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), BIO_do_connect_retry(_, _, _))
        .WillRepeatedly(Return(0));
    EXPECT_CALL(X509OpensslMock::GetInstance(), ERR_peek_last_error())
        .WillRepeatedly(Return(0));
    ret = certChainPemWithOcsp->engineValidate(certChainPemWithOcsp, &params, &result);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    FreeValidateResult(result);
    FreeTrustAnchorArr(trustAnchorArray);
    FreeHcfRevocationCheckParam(params.revocationCheckParam);
    CfObjDestroy(certChainPemWithOcsp);
}

HWTEST_F(CryptoX509CertChainTestPart3, ValidateIgnoreNetworkErrorTest002, TestSize.Level0)
{
    HcfX509CertChainSpi *certChainPemWithOcsp = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&g_inCaChain, &certChainPemWithOcsp);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainPemWithOcsp, nullptr);
    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testRootCertValid));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testRootCertValid) + 1;

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(inStream, trustAnchorArray);

    HcfX509CertChainValidateParams params = { 0 };
    params.trustAnchors = &trustAnchorArray;

    HcfRevChkOption data[] = { REVOCATION_CHECK_OPTION_ACCESS_NETWORK, REVOCATION_CHECK_OPTION_PREFER_OCSP,
        REVOCATION_CHECK_OPTION_CHECK_INTERMEDIATE_CA_ONLINE };
    params.revocationCheckParam = ConstructHcfRevocationCheckParam(data, sizeof(data) / sizeof(data[0]));
    ASSERT_NE(params.revocationCheckParam, nullptr);

    HcfX509CertChainValidateResult result = { 0 };
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), BIO_do_connect_retry(_, _, _))
        .WillRepeatedly(Return(0));
    EXPECT_CALL(X509OpensslMock::GetInstance(), ERR_peek_last_error())
        .WillRepeatedly(Return(268959746));
    ret = certChainPemWithOcsp->engineValidate(certChainPemWithOcsp, &params, &result);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), BIO_do_connect_retry(_, _, _))
        .WillRepeatedly(Return(0));
    EXPECT_CALL(X509OpensslMock::GetInstance(), ERR_peek_last_error())
        .WillRepeatedly(Return(268435603));
    ret = certChainPemWithOcsp->engineValidate(certChainPemWithOcsp, &params, &result);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    FreeValidateResult(result);
    FreeTrustAnchorArr(trustAnchorArray);
    FreeHcfRevocationCheckParam(params.revocationCheckParam);
    CfObjDestroy(certChainPemWithOcsp);
}

HWTEST_F(CryptoX509CertChainTestPart3, ValidateIgnoreNetworkErrorTest003, TestSize.Level0)
{
    HcfX509CertChainSpi *certChainPem = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&g_inCaChain, &certChainPem);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainPem, nullptr);
    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testRootCertValid));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testRootCertValid) + 1;

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(inStream, trustAnchorArray);

    HcfX509CertChainValidateParams params = { 0 };
    params.trustAnchors = &trustAnchorArray;
    HcfRevChkOption data[] = { REVOCATION_CHECK_OPTION_IGNORE_NETWORK_ERROR, REVOCATION_CHECK_OPTION_PREFER_OCSP,
        REVOCATION_CHECK_OPTION_ACCESS_NETWORK };
    params.revocationCheckParam = ConstructHcfRevocationCheckParam(data, sizeof(data) / sizeof(data[0]));
    ASSERT_NE(params.revocationCheckParam, nullptr);

    HcfX509CertChainValidateResult result = { 0 };
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), BIO_do_connect_retry(_, _, _))
         .WillRepeatedly(Return(-1));
    EXPECT_CALL(X509OpensslMock::GetInstance(), ERR_peek_last_error())
        .WillRepeatedly(Return(268435603));
    ret = certChainPem->engineValidate(certChainPem, &params, &result);
    EXPECT_EQ(ret, CF_SUCCESS);
    X509OpensslMock::SetMockFlag(false);
    FreeValidateResult(result);
    FreeHcfRevocationCheckParam(params.revocationCheckParam);

    HcfRevChkOption data2[] = { REVOCATION_CHECK_OPTION_IGNORE_NETWORK_ERROR,
        REVOCATION_CHECK_OPTION_FALLBACK_NO_PREFER, REVOCATION_CHECK_OPTION_ACCESS_NETWORK };
    params.revocationCheckParam = ConstructHcfRevocationCheckParam(data2, sizeof(data2) / sizeof(data2[0]));
    ASSERT_NE(params.revocationCheckParam, nullptr);
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), BIO_do_connect_retry(_, _, _))
         .WillRepeatedly(Return(-1));
    EXPECT_CALL(X509OpensslMock::GetInstance(), ERR_peek_last_error())
        .WillRepeatedly(Return(268435603));
    ret = certChainPem->engineValidate(certChainPem, &params, &result);
    EXPECT_EQ(ret, CF_SUCCESS);
    X509OpensslMock::SetMockFlag(false);

    FreeValidateResult(result);
    FreeTrustAnchorArr(trustAnchorArray);
    FreeHcfRevocationCheckParam(params.revocationCheckParam);
    CfObjDestroy(certChainPem);
}

HWTEST_F(CryptoX509CertChainTestPart3, ValidateIgnoreNetworkErrorTest004, TestSize.Level0)
{
    HcfX509CertChainSpi *certChainPem = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&g_inCaChain, &certChainPem);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainPem, nullptr);
    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testRootCertValid));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testRootCertValid) + 1;

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(inStream, trustAnchorArray);

    HcfX509CertChainValidateParams params = { 0 };
    params.trustAnchors = &trustAnchorArray;
    HcfRevChkOption data[] = { REVOCATION_CHECK_OPTION_IGNORE_NETWORK_ERROR, REVOCATION_CHECK_OPTION_PREFER_OCSP,
        REVOCATION_CHECK_OPTION_ACCESS_NETWORK, REVOCATION_CHECK_OPTION_CHECK_INTERMEDIATE_CA_ONLINE,
        REVOCATION_CHECK_OPTION_FALLBACK_NO_PREFER};
    params.revocationCheckParam = ConstructHcfRevocationCheckParam(data, sizeof(data) / sizeof(data[0]));
    ASSERT_NE(params.revocationCheckParam, nullptr);

    HcfX509CertChainValidateResult result = { 0 };
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), BIO_do_connect_retry(_, _, _))
         .WillRepeatedly(Return(-1));
    EXPECT_CALL(X509OpensslMock::GetInstance(), ERR_peek_last_error())
        .WillRepeatedly(Return(268435603));
    ret = certChainPem->engineValidate(certChainPem, &params, &result);
    EXPECT_EQ(ret, CF_SUCCESS);
    X509OpensslMock::SetMockFlag(false);
    FreeValidateResult(result);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), BIO_do_connect_retry(_, _, _))
         .WillOnce(Return(-1))
         .WillOnce(Return(1))
         .WillRepeatedly(Invoke(__real_BIO_do_connect_retry));
    ret = certChainPem->engineValidate(certChainPem, &params, &result);
    EXPECT_EQ(ret, CF_SUCCESS);
    X509OpensslMock::SetMockFlag(false);

    FreeValidateResult(result);
    FreeTrustAnchorArr(trustAnchorArray);
    FreeHcfRevocationCheckParam(params.revocationCheckParam);
    CfObjDestroy(certChainPem);
}

HWTEST_F(CryptoX509CertChainTestPart3, ValidateIgnoreNetworkErrorTest005, TestSize.Level0)
{
    HcfX509CertChainSpi *certChainPem = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&g_inCaChain, &certChainPem);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainPem, nullptr);
    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testRootCertValid));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testRootCertValid) + 1;

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(inStream, trustAnchorArray);

    HcfX509CertChainValidateParams params = { 0 };
    params.trustAnchors = &trustAnchorArray;
    HcfRevChkOption data[] = { REVOCATION_CHECK_OPTION_IGNORE_NETWORK_ERROR, REVOCATION_CHECK_OPTION_PREFER_OCSP,
        REVOCATION_CHECK_OPTION_ACCESS_NETWORK, REVOCATION_CHECK_OPTION_CHECK_INTERMEDIATE_CA_ONLINE};
    params.revocationCheckParam = ConstructHcfRevocationCheckParam(data, sizeof(data) / sizeof(data[0]));
    ASSERT_NE(params.revocationCheckParam, nullptr);

    HcfX509CertChainValidateResult result = { 0 };
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), BIO_do_connect_retry(_, _, _))
         .WillRepeatedly(Return(-1));
    EXPECT_CALL(X509OpensslMock::GetInstance(), ERR_peek_last_error())
        .WillOnce(Return(268435603))
        .WillRepeatedly(Return(268959746));
    ret = certChainPem->engineValidate(certChainPem, &params, &result);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    FreeValidateResult(result);
    FreeTrustAnchorArr(trustAnchorArray);
    FreeHcfRevocationCheckParam(params.revocationCheckParam);
    CfObjDestroy(certChainPem);
}

HWTEST_F(CryptoX509CertChainTestPart3, ValidateIgnoreNetworkErrorTest006, TestSize.Level0)
{
    HcfX509CertChainSpi *certChainPem = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&g_inCaChain, &certChainPem);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainPem, nullptr);
    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testRootCertValid));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testRootCertValid) + 1;

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(inStream, trustAnchorArray);

    HcfX509CertChainValidateParams params = { 0 };
    params.trustAnchors = &trustAnchorArray;
    HcfRevChkOption data[] = { REVOCATION_CHECK_OPTION_IGNORE_NETWORK_ERROR, REVOCATION_CHECK_OPTION_PREFER_OCSP,
        REVOCATION_CHECK_OPTION_ACCESS_NETWORK, REVOCATION_CHECK_OPTION_CHECK_INTERMEDIATE_CA_ONLINE};
    params.revocationCheckParam = ConstructHcfRevocationCheckParam(data, sizeof(data) / sizeof(data[0]));
    ASSERT_NE(params.revocationCheckParam, nullptr);

    HcfX509CertChainValidateResult result = { 0 };
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), BIO_do_connect_retry(_, _, _))
         .WillRepeatedly(Return(-1));
    EXPECT_CALL(X509OpensslMock::GetInstance(), ERR_peek_last_error())
        .WillOnce(Return(268435603))
        .WillRepeatedly(Return(268959746));
    EXPECT_CALL(X509OpensslMock::GetInstance(), CfGetCertIdInfo(_, _, _, _))
        .WillOnce(Return(CF_SUCCESS))
        .WillOnce(Return(CF_ERR_CRYPTO_OPERATION))
        .WillRepeatedly(Invoke(__real_CfGetCertIdInfo));
    ret = certChainPem->engineValidate(certChainPem, &params, &result);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    FreeValidateResult(result);
    FreeTrustAnchorArr(trustAnchorArray);
    FreeHcfRevocationCheckParam(params.revocationCheckParam);
    CfObjDestroy(certChainPem);
}

HWTEST_F(CryptoX509CertChainTestPart3, ValidateIgnoreNetworkErrorTest007, TestSize.Level0)
{
    HcfX509CertChainSpi *certChainPem = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&g_inCaChain, &certChainPem);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainPem, nullptr);
    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testRootCertValid));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testRootCertValid) + 1;

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(inStream, trustAnchorArray);

    HcfX509CertChainValidateParams params = { 0 };
    params.trustAnchors = &trustAnchorArray;
    HcfRevChkOption data[] = { REVOCATION_CHECK_OPTION_IGNORE_NETWORK_ERROR, REVOCATION_CHECK_OPTION_ACCESS_NETWORK,
        REVOCATION_CHECK_OPTION_CHECK_INTERMEDIATE_CA_ONLINE };
    params.revocationCheckParam = ConstructHcfRevocationCheckParam(data, sizeof(data) / sizeof(data[0]));
    ASSERT_NE(params.revocationCheckParam, nullptr);

    HcfX509CertChainValidateResult result = { 0 };
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_CRL_load_http(_, _, _, _))
        .WillRepeatedly(Return(nullptr));
    EXPECT_CALL(X509OpensslMock::GetInstance(), ERR_peek_last_error())
        .WillRepeatedly(Return(268435603));
    ret = certChainPem->engineValidate(certChainPem, &params, &result);
    EXPECT_EQ(ret, CF_SUCCESS);
    X509OpensslMock::SetMockFlag(false);
    FreeValidateResult(result);
    FreeTrustAnchorArr(trustAnchorArray);
    FreeHcfRevocationCheckParam(params.revocationCheckParam);
    CfObjDestroy(certChainPem);
}

HWTEST_F(CryptoX509CertChainTestPart3, ValidateIgnoreNetworkErrorTest008, TestSize.Level0)
{
    HcfX509CertChainSpi *certChainPem = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&g_inCaChain, &certChainPem);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainPem, nullptr);
    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testRootCertValid));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testRootCertValid) + 1;

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(inStream, trustAnchorArray);

    HcfX509CertChainValidateParams params = { 0 };
    params.trustAnchors = &trustAnchorArray;
    HcfRevChkOption data[] = { REVOCATION_CHECK_OPTION_IGNORE_NETWORK_ERROR, REVOCATION_CHECK_OPTION_ACCESS_NETWORK,
        REVOCATION_CHECK_OPTION_CHECK_INTERMEDIATE_CA_ONLINE };
    params.revocationCheckParam = ConstructHcfRevocationCheckParam(data, sizeof(data) / sizeof(data[0]));
    ASSERT_NE(params.revocationCheckParam, nullptr);

    HcfX509CertChainValidateResult result = { 0 };
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_CRL_load_http(_, _, _, _))
        .WillRepeatedly(Return(nullptr));
    EXPECT_CALL(X509OpensslMock::GetInstance(), ERR_peek_last_error())
        .WillOnce(Return(268435603))
        .WillRepeatedly(Return(268959746));
    ret = certChainPem->engineValidate(certChainPem, &params, &result);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);
    FreeValidateResult(result);
    FreeTrustAnchorArr(trustAnchorArray);
    FreeHcfRevocationCheckParam(params.revocationCheckParam);
    CfObjDestroy(certChainPem);
}

HWTEST_F(CryptoX509CertChainTestPart3, ValidateIgnoreNetworkErrorTest009, TestSize.Level0)
{
    HcfX509CertChainSpi *certChainPem = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&g_inCaChain, &certChainPem);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainPem, nullptr);
    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testRootCertValid));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testRootCertValid) + 1;

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(inStream, trustAnchorArray);

    HcfX509CertChainValidateParams params = { 0 };
    params.trustAnchors = &trustAnchorArray;
    HcfRevChkOption data[] = { REVOCATION_CHECK_OPTION_IGNORE_NETWORK_ERROR, REVOCATION_CHECK_OPTION_ACCESS_NETWORK,
        REVOCATION_CHECK_OPTION_CHECK_INTERMEDIATE_CA_ONLINE};
    params.revocationCheckParam = ConstructHcfRevocationCheckParam(data, sizeof(data) / sizeof(data[0]));
    ASSERT_NE(params.revocationCheckParam, nullptr);

    HcfX509CertChainValidateResult result = { 0 };
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_CRL_load_http(_, _, _, _))
        .WillRepeatedly(Return(nullptr));
    EXPECT_CALL(X509OpensslMock::GetInstance(), ERR_peek_last_error())
        .WillRepeatedly(Return(268959746));
    ret = certChainPem->engineValidate(certChainPem, &params, &result);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);
    FreeValidateResult(result);
    FreeTrustAnchorArr(trustAnchorArray);
    FreeHcfRevocationCheckParam(params.revocationCheckParam);
    CfObjDestroy(certChainPem);
}

HWTEST_F(CryptoX509CertChainTestPart3, ValidateIgnoreNetworkErrorTest010, TestSize.Level0)
{
    HcfX509CertChainSpi *certChainPem = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&g_inCaChain, &certChainPem);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainPem, nullptr);
    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testRootCertValid));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testRootCertValid) + 1;

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(inStream, trustAnchorArray);

    HcfX509CertChainValidateParams params = { 0 };
    params.trustAnchors = &trustAnchorArray;
    HcfRevChkOption data[] = { REVOCATION_CHECK_OPTION_IGNORE_NETWORK_ERROR, REVOCATION_CHECK_OPTION_ACCESS_NETWORK,
        REVOCATION_CHECK_OPTION_CHECK_INTERMEDIATE_CA_ONLINE };
    params.revocationCheckParam = ConstructHcfRevocationCheckParam(data, sizeof(data) / sizeof(data[0]));
    ASSERT_NE(params.revocationCheckParam, nullptr);
    params.revocationCheckParam->crlDownloadURI = &g_blobDownloadURI;

    HcfX509CertChainValidateResult result = { 0 };
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_CRL_load_http(_, _, _, _))
        .WillRepeatedly(Return(nullptr));
    EXPECT_CALL(X509OpensslMock::GetInstance(), ERR_peek_last_error())
        .WillRepeatedly(Return(268435603));
    ret = certChainPem->engineValidate(certChainPem, &params, &result);
    EXPECT_EQ(ret, CF_SUCCESS);
    X509OpensslMock::SetMockFlag(false);

    FreeValidateResult(result);
    FreeTrustAnchorArr(trustAnchorArray);
    FreeHcfRevocationCheckParam(params.revocationCheckParam);
    CfObjDestroy(certChainPem);
}

HWTEST_F(CryptoX509CertChainTestPart3, ValidateIgnoreNetworkErrorTest011, TestSize.Level0)
{
    HcfX509CertChainSpi *certChainPem = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&g_inCaChain, &certChainPem);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainPem, nullptr);
    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testRootCertValid));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testRootCertValid) + 1;

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(inStream, trustAnchorArray);

    HcfX509CertChainValidateParams params = { 0 };
    params.trustAnchors = &trustAnchorArray;
    HcfRevChkOption data[] = { REVOCATION_CHECK_OPTION_IGNORE_NETWORK_ERROR, REVOCATION_CHECK_OPTION_ACCESS_NETWORK,
        REVOCATION_CHECK_OPTION_CHECK_INTERMEDIATE_CA_ONLINE };
    params.revocationCheckParam = ConstructHcfRevocationCheckParam(data, sizeof(data) / sizeof(data[0]));
    ASSERT_NE(params.revocationCheckParam, nullptr);

    HcfX509CertChainValidateResult result = { 0 };
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_CRL_load_http(_, _, _, _))
        .WillRepeatedly(Return(nullptr));
    EXPECT_CALL(X509OpensslMock::GetInstance(), ERR_peek_last_error())
        .WillRepeatedly(Return(268435603));
    ret = certChainPem->engineValidate(certChainPem, &params, &result);
    EXPECT_EQ(ret, CF_SUCCESS);
    X509OpensslMock::SetMockFlag(false);
    FreeValidateResult(result);

    X509_CRL *crl = X509_CRL_new();
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_CRL_load_http(_, _, _, _))
         .WillOnce(Return(crl))
         .WillRepeatedly(Invoke(__real_X509_CRL_load_http));
    ret = certChainPem->engineValidate(certChainPem, &params, &result);
    EXPECT_EQ(ret, CF_SUCCESS);
    X509OpensslMock::SetMockFlag(false);

    FreeValidateResult(result);
    FreeTrustAnchorArr(trustAnchorArray);
    FreeHcfRevocationCheckParam(params.revocationCheckParam);
    CfObjDestroy(certChainPem);
}

HWTEST_F(CryptoX509CertChainTestPart3, ValidateIgnoreNetworkErrorTest012, TestSize.Level0)
{
    HcfX509CertChainSpi *certChainPem = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&g_inCaChain, &certChainPem);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainPem, nullptr);
    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testRootCertValid));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testRootCertValid) + 1;

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(inStream, trustAnchorArray);

    HcfX509CertChainValidateParams params = { 0 };
    params.trustAnchors = &trustAnchorArray;
    HcfRevChkOption data[] = { REVOCATION_CHECK_OPTION_IGNORE_NETWORK_ERROR, REVOCATION_CHECK_OPTION_ACCESS_NETWORK,
        REVOCATION_CHECK_OPTION_CHECK_INTERMEDIATE_CA_ONLINE };
    params.revocationCheckParam = ConstructHcfRevocationCheckParam(data, sizeof(data) / sizeof(data[0]));
    ASSERT_NE(params.revocationCheckParam, nullptr);
    params.revocationCheckParam->crlDownloadURI = &g_blobDownloadURI;

    HcfX509CertChainValidateResult result = { 0 };
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_CRL_load_http(_, _, _, _))
        .WillRepeatedly(Return(nullptr));
    EXPECT_CALL(X509OpensslMock::GetInstance(), ERR_peek_last_error())
        .WillRepeatedly(Return(268435603));
    ret = certChainPem->engineValidate(certChainPem, &params, &result);
    EXPECT_EQ(ret, CF_SUCCESS);
    X509OpensslMock::SetMockFlag(false);
    FreeValidateResult(result);

    X509_CRL *crl = X509_CRL_new();
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_CRL_load_http(_, _, _, _))
        .WillOnce(Return(nullptr))
        .WillOnce(Return(crl))
        .WillRepeatedly(Invoke(__real_X509_CRL_load_http));
    ret = certChainPem->engineValidate(certChainPem, &params, &result);
    EXPECT_EQ(ret, CF_SUCCESS);
    X509OpensslMock::SetMockFlag(false);

    FreeValidateResult(result);
    FreeTrustAnchorArr(trustAnchorArray);
    FreeHcfRevocationCheckParam(params.revocationCheckParam);
    CfObjDestroy(certChainPem);
}

HWTEST_F(CryptoX509CertChainTestPart3, ContainsOptionTest001, TestSize.Level0)
{
    bool result = ContainsOption(nullptr, REVOCATION_CHECK_OPTION_ACCESS_NETWORK);
    EXPECT_EQ(result, false);

    HcfRevChkOpArray *options = (HcfRevChkOpArray *)CfMalloc(sizeof(HcfRevChkOpArray), 0);
    ASSERT_NE(options, nullptr);
    options->count = 2;
    options->data = nullptr;
    result = ContainsOption(options, REVOCATION_CHECK_OPTION_ACCESS_NETWORK);
    EXPECT_EQ(result, false);
    CfFree(options);

    HcfRevChkOpArray *options2 = (HcfRevChkOpArray *)CfMalloc(sizeof(HcfRevChkOpArray), 0);
    ASSERT_NE(options2, nullptr);
    options2->count = 2;
    options2->data = (HcfRevChkOption *)CfMalloc(options2->count * sizeof(HcfRevChkOption), 0);
    ASSERT_NE(options2->data, nullptr);
    options2->data[0] = REVOCATION_CHECK_OPTION_ACCESS_NETWORK;
    options2->data[1] = REVOCATION_CHECK_OPTION_PREFER_OCSP;
    result = ContainsOption(options2, REVOCATION_CHECK_OPTION_CHECK_INTERMEDIATE_CA_ONLINE);
    EXPECT_EQ(result, false);

    CfFree(options2->data);
    CfFree(options2);
}
} // namespace
