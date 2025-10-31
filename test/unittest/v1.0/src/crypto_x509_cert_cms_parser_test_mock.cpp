/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "string"

#include "cert_cms_generator.h"
#include "cf_blob.h"
#include "cf_mock.h"
#include "memory_mock.h"
#include "cf_object_base.h"
#include "cf_result.h"
#include "cf_memory.h"
#include "x509_cert_cms_generator_openssl.h"

using namespace std;
using namespace testing::ext;
using namespace CFMock;
using ::testing::_;
using ::testing::Invoke;
using ::testing::Return;

#ifdef __cplusplus
extern "C" {
#endif
int __real_CMS_verify(CMS_ContentInfo *cms, STACK_OF(X509) *certs, X509_STORE *store,
    BIO *dcont, BIO *out, unsigned int flags);
int __real_CMS_decrypt(CMS_ContentInfo *cms, EVP_PKEY *pkey, X509 *cert,
    BIO *dcont, BIO *out, unsigned int flags);
CMS_ContentInfo *__real_PEM_read_bio_CMS(BIO *bp, CMS_ContentInfo **x, pem_password_cb *cb, void *u);
CMS_ContentInfo *__real_d2i_CMS_bio(BIO *bp, CMS_ContentInfo **cms);
const ASN1_OBJECT *__real_CMS_get0_type(const CMS_ContentInfo *cms);
ASN1_OCTET_STRING **__real_CMS_get0_content(CMS_ContentInfo *cms);
STACK_OF(X509) *__real_CMS_get1_certs(CMS_ContentInfo *cms);
int __real_BIO_write(BIO *b, const void *data, int dlen);
int __real_OPENSSL_sk_push(OPENSSL_STACK *st, const void *data);
OPENSSL_STACK *__real_OPENSSL_sk_new_null(void);
X509_STORE *__real_X509_STORE_new(void);
int __real_X509_STORE_add_cert(X509_STORE *ctx, X509 *x);
BIO *__real_BIO_new(const BIO_METHOD *type);
BIO *__real_BIO_new_mem_buf(const void *buf, int len);
STACK_OF(CMS_SignerInfo) *__real_CMS_get0_SignerInfos(CMS_ContentInfo *cms);
#ifdef __cplusplus
}
#endif

namespace {
class CryptoX509CertCmsParserTestMock : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

static char g_testleftPem[] =
"-----BEGIN CERTIFICATE-----\r\n"
"MIICejCCAiCgAwIBAgIUGE371/LcCW79mzMm6UiJdyC4khcwCgYIKoZIzj0EAwIw\r\n"
"fjELMAkGA1UEBhMCQ04xEDAOBgNVBAgMB0JlaWppbmcxEDAOBgNVBAcMB0JlaWpp\r\n"
"bmcxHjAcBgNVBAoMFUVDRFNBIEludGVybWVkaWF0ZSBDQTELMAkGA1UECwwCSVQx\r\n"
"HjAcBgNVBAMMFUVDRFNBIEludGVybWVkaWF0ZSBDQTAeFw0yNTA5MjgxMDU0MDVa\r\n"
"Fw0zNTA5MjYxMDU0MDVaMHUxCzAJBgNVBAYTAkNOMRAwDgYDVQQIDAdCZWlqaW5n\r\n"
"MRAwDgYDVQQHDAdCZWlqaW5nMRswGQYDVQQKDBJFQ0RTQSBFeGFtcGxlIENvcnAx\r\n"
"CzAJBgNVBAsMAklUMRgwFgYDVQQDDA93d3cuZXhhbXBsZS5jb20wWTATBgcqhkjO\r\n"
"PQIBBggqhkjOPQMBBwNCAAQNKO5YXAsmdm/ShEU5VyQlQSdnV6hNQIofHhQ/GyeK\r\n"
"1W7t3KnMie4cv/wnA4Qmor2KeBBXUFUnYJqqWOHsivIuo4GEMIGBMAkGA1UdEwQC\r\n"
"MAAwCwYDVR0PBAQDAgK0MCcGA1UdEQQgMB6CD3d3dy5leGFtcGxlLmNvbYILZXhh\r\n"
"bXBsZS5jb20wHQYDVR0OBBYEFD7RUSUimy0SWShmPIus91tDS0u9MB8GA1UdIwQY\r\n"
"MBaAFFjgVG0DwmSwxzJWELNvxGtm3mxUMAoGCCqGSM49BAMCA0gAMEUCIQCTw7sx\r\n"
"X0tt1xiNvIQ9LD4bECzdgzIuBaU97GgYDusIUgIgTkc0wYZ3EUg0COHPly4cVsTj\r\n"
"1Cyy/+qufhBUJw5om7E=\r\n"
"-----END CERTIFICATE-----\r\n";

static char g_interPem[] =
"-----BEGIN CERTIFICATE-----\r\n"
"MIICTDCCAfGgAwIBAgIUc1x0keEiLIcS1oKtSpeEiPoaepkwCgYIKoZIzj0EAwIw\r\n"
"bjELMAkGA1UEBhMCQ04xEDAOBgNVBAgMB0JlaWppbmcxEDAOBgNVBAcMB0JlaWpp\r\n"
"bmcxFjAUBgNVBAoMDUVDRFNBIFJvb3QgQ0ExCzAJBgNVBAsMAklUMRYwFAYDVQQD\r\n"
"DA1FQ0RTQSBSb290IENBMB4XDTI1MDkyODEwNTM0OVoXDTMwMDkyNzEwNTM0OVow\r\n"
"fjELMAkGA1UEBhMCQ04xEDAOBgNVBAgMB0JlaWppbmcxEDAOBgNVBAcMB0JlaWpp\r\n"
"bmcxHjAcBgNVBAoMFUVDRFNBIEludGVybWVkaWF0ZSBDQTELMAkGA1UECwwCSVQx\r\n"
"HjAcBgNVBAMMFUVDRFNBIEludGVybWVkaWF0ZSBDQTBZMBMGByqGSM49AgEGCCqG\r\n"
"SM49AwEHA0IABGoCqpHBV/glJeezsp693/hhflYOKpHvaNszVBLkTurkqrbhbaMo\r\n"
"hw1oO2Zro54rhZ8tom2UAGn1rzNmRVBCxTajXTBbMAwGA1UdEwQFMAMBAf8wCwYD\r\n"
"VR0PBAQDAgEGMB0GA1UdDgQWBBRY4FRtA8JksMcyVhCzb8RrZt5sVDAfBgNVHSME\r\n"
"GDAWgBTmNm24RfPnLf1HMNCocS90CGalJjAKBggqhkjOPQQDAgNJADBGAiEAstMv\r\n"
"puHi/dgAlvycicL3VQ5iITvUSG2fo286LYc01CQCIQCyw4+94ovyRtaT/WWoZh3u\r\n"
"ia4tt478nYeQgMChg+xtSw==\r\n"
"-----END CERTIFICATE-----\r\n";

static char g_verifyRootPem[] =
"-----BEGIN CERTIFICATE-----\r\n"
"MIICUzCCAfqgAwIBAgIUPma0DkC+ck+t/3eykmsKsy5D0egwCgYIKoZIzj0EAwIw\r\n"
"bjELMAkGA1UEBhMCQ04xEDAOBgNVBAgMB0JlaWppbmcxEDAOBgNVBAcMB0JlaWpp\r\n"
"bmcxFjAUBgNVBAoMDUVDRFNBIFJvb3QgQ0ExCzAJBgNVBAsMAklUMRYwFAYDVQQD\r\n"
"DA1FQ0RTQSBSb290IENBMB4XDTI1MDkyODEwNTMyN1oXDTM1MDkyNjEwNTMyN1ow\r\n"
"bjELMAkGA1UEBhMCQ04xEDAOBgNVBAgMB0JlaWppbmcxEDAOBgNVBAcMB0JlaWpp\r\n"
"bmcxFjAUBgNVBAoMDUVDRFNBIFJvb3QgQ0ExCzAJBgNVBAsMAklUMRYwFAYDVQQD\r\n"
"DA1FQ0RTQSBSb290IENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEA3KYWepl\r\n"
"wjHe/Htx2cAhrjaZpWPJOUyL6siUFRayVebaqOQejuUPypbj+u4ZHodsviUe12E1\r\n"
"50Q+R9Uayes+WKN2MHQwHQYDVR0OBBYEFOY2bbhF8+ct/Ucw0KhxL3QIZqUmMB8G\r\n"
"A1UdIwQYMBaAFOY2bbhF8+ct/Ucw0KhxL3QIZqUmMAsGA1UdDwQEAwIBBjAJBgNV\r\n"
"HREEAjAAMAkGA1UdEgQCMAAwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNH\r\n"
"ADBEAiAjo+sFDtGVhyc+NqdwxhepqSXOjRI5As6TSz3OYTvERwIgayLgfBn2uABH\r\n"
"wYQI60CEJkDF9Pn2fxsGuNEyyn0ks28=\r\n"
"-----END CERTIFICATE-----\r\n";

static char g_signedCmsPem[] =
"-----BEGIN CMS-----\r\n"
"MIIEpQYJKoZIhvcNAQcCoIIEljCCBJICAQExDTALBglghkgBZQMEAgQwEwYJKoZI\r\n"
"hvcNAQcBoAYEBAECAwSgggJ+MIICejCCAiCgAwIBAgIUGE371/LcCW79mzMm6UiJ\r\n"
"dyC4khcwCgYIKoZIzj0EAwIwfjELMAkGA1UEBhMCQ04xEDAOBgNVBAgMB0JlaWpp\r\n"
"bmcxEDAOBgNVBAcMB0JlaWppbmcxHjAcBgNVBAoMFUVDRFNBIEludGVybWVkaWF0\r\n"
"ZSBDQTELMAkGA1UECwwCSVQxHjAcBgNVBAMMFUVDRFNBIEludGVybWVkaWF0ZSBD\r\n"
"QTAeFw0yNTA5MjgxMDU0MDVaFw0zNTA5MjYxMDU0MDVaMHUxCzAJBgNVBAYTAkNO\r\n"
"MRAwDgYDVQQIDAdCZWlqaW5nMRAwDgYDVQQHDAdCZWlqaW5nMRswGQYDVQQKDBJF\r\n"
"Q0RTQSBFeGFtcGxlIENvcnAxCzAJBgNVBAsMAklUMRgwFgYDVQQDDA93d3cuZXhh\r\n"
"bXBsZS5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQNKO5YXAsmdm/ShEU5\r\n"
"VyQlQSdnV6hNQIofHhQ/GyeK1W7t3KnMie4cv/wnA4Qmor2KeBBXUFUnYJqqWOHs\r\n"
"ivIuo4GEMIGBMAkGA1UdEwQCMAAwCwYDVR0PBAQDAgK0MCcGA1UdEQQgMB6CD3d3\r\n"
"dy5leGFtcGxlLmNvbYILZXhhbXBsZS5jb20wHQYDVR0OBBYEFD7RUSUimy0SWShm\r\n"
"PIus91tDS0u9MB8GA1UdIwQYMBaAFFjgVG0DwmSwxzJWELNvxGtm3mxUMAoGCCqG\r\n"
"SM49BAMCA0gAMEUCIQCTw7sxX0tt1xiNvIQ9LD4bECzdgzIuBaU97GgYDusIUgIg\r\n"
"Tkc0wYZ3EUg0COHPly4cVsTj1Cyy/+qufhBUJw5om7ExggHlMIIB4QIBATCBljB+\r\n"
"MQswCQYDVQQGEwJDTjEQMA4GA1UECAwHQmVpamluZzEQMA4GA1UEBwwHQmVpamlu\r\n"
"ZzEeMBwGA1UECgwVRUNEU0EgSW50ZXJtZWRpYXRlIENBMQswCQYDVQQLDAJJVDEe\r\n"
"MBwGA1UEAwwVRUNEU0EgSW50ZXJtZWRpYXRlIENBAhQYTfvX8twJbv2bMybpSIl3\r\n"
"ILiSFzALBglghkgBZQMEAgSggeAwGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAc\r\n"
"BgkqhkiG9w0BCQUxDxcNMjUwOTI5MDM1NzM1WjArBgkqhkiG9w0BCQQxHgQc/hln\r\n"
"L6IKzcanlPftaN11Y8J/ZHkgFkuZHxrQNzB5BgkqhkiG9w0BCQ8xbDBqMAsGCWCG\r\n"
"SAFlAwQBKjALBglghkgBZQMEARYwCwYJYIZIAWUDBAECMAoGCCqGSIb3DQMHMA4G\r\n"
"CCqGSIb3DQMCAgIAgDANBggqhkiG9w0DAgIBQDAHBgUrDgMCBzANBggqhkiG9w0D\r\n"
"AgIBKDAKBggqhkjOPQQDAQRHMEUCIAn+mv09rGWttN80CgEdVM5hstWDWZhDXX/x\r\n"
"NcqMlVCnAiEA7ZPsEoe6fvK+YPzyONcWKAeSwEbM2GH1NOXjjsA3+0M=\r\n"
"-----END CMS-----\r\n";

static char g_encryptedCmsPem[] =
"-----BEGIN CMS-----\r\n"
    "MIIEXQYJKoZIhvcNAQcDoIIETjCCBEoCAQIxggQFMIHpAgEAMFIwSDELMAkGA1UE\r\n"
    "BhMCQ04xCzAJBgNVBAgMAlNYMQ4wDAYDVQQHDAV4aSBhbjENMAsGA1UECgwEVGVz\r\n"
    "dDENMAsGA1UEAwwEdGVzdAIGAXKnJjrEMA0GCSqGSIb3DQEBAQUABIGAmj9WNBIB\r\n"
    "uQ9cl7a8YGvKw0sRcRDZtj0ivupGTcHKShj54g3Jxb+WiYvR7YwKjtH/S16z28DQ\r\n"
    "jdAb4Oh7zRkHRsXwiTcTyu9269tib8LwLyvjhNZ1yIy+IjkNGhXD0xGnyb6BjSHx\r\n"
    "gZGuWgAWoyvsPWyuwTo69iiWcq142yjuZ2ChggEDAgEDoFGhTzAJBgcqhkjOPQIB\r\n"
    "A0IABMpGxKtyYoyJNWI/UMjNRnKHBEHtKnZErzYbbh4e6iUtEyCyOg3RGMHCcTKA\r\n"
    "HZGNd28hVI0nNhDs7iIkvA79vyMwGAYJK4EFEIZIPwACMAsGCWCGSAFlAwQBLTCB\r\n"
    "kDCBjTBhMFcxCzAJBgNVBAYTAkNOMQ8wDQYDVQQIDAbpmZXopb8xDzANBgNVBAcM\r\n"
    "Builv+WuiTEPMA0GA1UECgwG5rWL6K+VMRUwEwYDVQQDDAzkuK3mlofmtYvor5UC\r\n"
    "BgFypyY6wAQonc7hNmlgIo6UA/WjKRvjBHy8xEFjOG7yOJ+BWFL/jbtQc2USKFGa\r\n"
    "16GCAb4CAQOgggEYoYIBFDAJBgcqhkjOPgIBA4IBBQACggEAN7IzujspteV8tf8T\r\n"
    "K9zfBa8mKd9mulZt+pylXQhKiKSUXdzP/SLLhwUm7YL8J0kkIeaGQQpzu68bG5Ua\r\n"
    "NNhhsr07FNbM9D0zi6tzJ/5QI7pVFRex7CxSgsJkx4tIuNYm3xPiQsGnT2PmOgE3\r\n"
    "1GYJTQtE7g+Ne5aqUvQ73iTEsTFDtvX4yu++KQg3KQJIrG8dyzkazKafs2mHYyQO\r\n"
    "HVZrfRc7lzV6ef5W0y+9/MdjB2/ERnmS3CBVlf+UkWxUIqUKeZAn6JHt8j2tAzGZ\r\n"
    "9I71ogpP8zo915pXXnftOPmXGj4AJKaMGn7vAUODW0UZpe01xtKuaB7GvjEsFEjK\r\n"
    "7NIiFjAaBgsqhkiG9w0BCRADBTALBglghkgBZQMEAS0wgYAwfjBSMEgxCzAJBgNV\r\n"
    "BAYTAkNOMQswCQYDVQQIDAJTWDEOMAwGA1UEBwwFeGkgYW4xDTALBgNVBAoMBFRl\r\n"
    "c3QxDTALBgNVBAMMBHRlc3QCBgFypyY6xQQoIr8kwhfnKxAkUS89Vgvwr+cirYKu\r\n"
    "ASIOwxaLnE8sY8DbWcKZeASbBaJOAgEEMBIEEDEyMzQ1Njc4OTBhYmNkZWYwCwYJ\r\n"
    "YIZIAWUDBAEtBCh4myONQEamB1ODZIANFV+erQSc87dKLFJCGzhrnFr/oGU2hvNJ\r\n"
    "SiZaMDwGCSqGSIb3DQEHATAdBglghkgBZQMEASoEEJN4M6Q1ywSjw9o3tZr2YrmA\r\n"
    "EAcdXtfS+2vx5JYg2sSklG8=\r\n"
    "-----END CMS-----\r\n";

static char g_privateKey[] =
    "-----BEGIN EC PRIVATE KEY-----\r\n"
    "MHcCAQEEIDmMBMiMN2TSAC+MTqT+nlXEGHKy9rH57erwdM/bSpjJoAoGCCqGSM49\r\n"
    "AwEHoUQDQgAEB06h4SzOryi3d7PW9yN2wACCVxlduBQjVLWZlDKhFKkdZjve8mUy\r\n"
    "ytSSbBj/rrzR2XmzUzofuNkUbAtje3DDJg==\r\n"
    "-----END EC PRIVATE KEY-----\r\n";

static char g_pubKey[] =
"-----BEGIN CERTIFICATE-----\r\n"
"MIICGDCCAb6gAwIBAgIGAXKnJjrAMAoGCCqGSM49BAMCMFcxCzAJBgNVBAYTAkNO\r\n"
"MQ8wDQYDVQQIDAbpmZXopb8xDzANBgNVBAcMBuilv+WuiTEPMA0GA1UECgwG5rWL\r\n"
"6K+VMRUwEwYDVQQDDAzkuK3mlofmtYvor5UwHhcNMjUwOTE2MDY0MTMwWhcNMzUw\r\n"
"OTE0MDY0MTMwWjBXMQswCQYDVQQGEwJDTjEPMA0GA1UECAwG6ZmV6KW/MQ8wDQYD\r\n"
"VQQHDAbopb/lrokxDzANBgNVBAoMBua1i+ivlTEVMBMGA1UEAwwM5Lit5paH5rWL\r\n"
"6K+VMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEB06h4SzOryi3d7PW9yN2wACC\r\n"
"VxlduBQjVLWZlDKhFKkdZjve8mUyytSSbBj/rrzR2XmzUzofuNkUbAtje3DDJqN2\r\n"
"MHQwHQYDVR0OBBYEFNtUldgBESf31bwTnYtApIctaSdtMB8GA1UdIwQYMBaAFNtU\r\n"
"ldgBESf31bwTnYtApIctaSdtMAsGA1UdDwQEAwIBBjAJBgNVHREEAjAAMAkGA1Ud\r\n"
"EgQCMAAwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiEAzxzaG2vR\r\n"
"zUnFFL3X3lRQ0IOJrb6cvkSZuaFd4bW2lgUCIHW6QGGnECDFMbDNz7Og9kjkt+3k\r\n"
"FmEJWqEMYudBH3Ul\r\n"
"-----END CERTIFICATE-----\r\n";

const CfEncodingBlob g_decryptEnvelopedDataPemStream = {
    .data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_privateKey)),
    .len = strlen(g_privateKey) + 1,
    .encodingFormat = CF_FORMAT_PEM
};

static const uint8_t g_inContent[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

static uint8_t g_testRsaKeyNoPasswordDer[] = {
0x30, 0x82, 0x02, 0x5C, 0x02, 0x01, 0x00, 0x02, 0x81, 0x81, 0x00, 0xBE, 0x4F, 0x74, 0xAD, 0x1B,
0x55, 0xEF, 0xF3, 0x61, 0xE5, 0x73, 0xA1, 0xAD, 0x89, 0x59, 0xBD, 0x1E, 0x23, 0x00, 0x75, 0xF7,
0x80, 0x8B, 0x1F, 0xAB, 0x4D, 0x26, 0x21, 0xCF, 0x20, 0x7B, 0xC7, 0x64, 0xAB, 0x92, 0xC2, 0xAC,
0x62, 0xA7, 0x09, 0x22, 0xD0, 0xEB, 0x20, 0x68, 0xDA, 0x7A, 0xCF, 0xC5, 0xF7, 0x39, 0xD3, 0xF9,
0x76, 0x9C, 0xBA, 0x3E, 0x1A, 0x36, 0x06, 0x8A, 0xA8, 0xF6, 0xA8, 0xA4, 0x3A, 0x43, 0x80, 0xF0,
0xF4, 0x3D, 0x2F, 0xA5, 0x23, 0x01, 0x9D, 0x8C, 0xBB, 0x50, 0xCB, 0x4A, 0x20, 0xAA, 0xCE, 0x7D,
0x0F, 0xEF, 0xCA, 0x46, 0x1B, 0x43, 0xFE, 0x9D, 0x51, 0x56, 0xB5, 0x0D, 0xA4, 0xBF, 0xE6, 0xB6,
0x2D, 0x2C, 0xD2, 0x15, 0x82, 0x8D, 0xB6, 0x5C, 0x2E, 0xBF, 0x6A, 0x16, 0x84, 0x3A, 0x7E, 0x28,
0x09, 0x69, 0x7C, 0xF6, 0x4C, 0x82, 0xD3, 0x32, 0x9A, 0x5A, 0xC7, 0x02, 0x03, 0x01, 0x00, 0x01,
0x02, 0x81, 0x80, 0x37, 0x75, 0x3C, 0x10, 0xFD, 0xF8, 0x4B, 0x16, 0x67, 0x9E, 0xCF, 0xD5, 0x7B,
0x96, 0x9C, 0xFA, 0x09, 0x80, 0x35, 0xB0, 0x2A, 0xD1, 0xE0, 0xB8, 0xF7, 0xD8, 0x61, 0x96, 0x54,
0x9F, 0xA8, 0xB2, 0x70, 0x59, 0xB7, 0x48, 0xD7, 0xA7, 0x5F, 0xF9, 0xBF, 0x95, 0x96, 0x0F, 0x39,
0xBF, 0x01, 0x2E, 0xEF, 0x07, 0x9E, 0x68, 0x71, 0x37, 0xE9, 0x70, 0x34, 0x8C, 0xBA, 0xD5, 0xA9,
0x2E, 0x97, 0xC2, 0x07, 0xF2, 0x1B, 0xA6, 0x3F, 0x73, 0x18, 0x78, 0x98, 0x72, 0x56, 0x98, 0xD7,
0x85, 0x61, 0x22, 0xCD, 0x91, 0x96, 0x8B, 0x7C, 0xCC, 0xD9, 0x12, 0xCB, 0xE1, 0xFC, 0x6B, 0x69,
0x77, 0x1A, 0x1B, 0x1D, 0xE9, 0x1C, 0x38, 0xA1, 0x90, 0x28, 0x4B, 0xE5, 0x16, 0x75, 0x37, 0x3C,
0xE2, 0xCF, 0xE7, 0x21, 0x80, 0x14, 0x72, 0xD5, 0x2B, 0x2E, 0x84, 0xBB, 0xBB, 0xEB, 0x3D, 0xD8,
0xD7, 0xF1, 0x31, 0x02, 0x41, 0x00, 0xF2, 0x8F, 0xD4, 0x64, 0x03, 0xCE, 0x60, 0x17, 0x0C, 0x9E,
0xF0, 0xAB, 0x9D, 0xE5, 0x0E, 0x83, 0x76, 0x5D, 0x05, 0xA2, 0xB2, 0x4D, 0xD9, 0x61, 0x29, 0x57,
0x89, 0x1A, 0x4C, 0xF6, 0x4F, 0x38, 0xDE, 0xDB, 0x61, 0x59, 0x41, 0x62, 0xC9, 0x56, 0xB6, 0xC4,
0x30, 0x9E, 0xF5, 0xBC, 0xF8, 0x1F, 0x7A, 0x76, 0x9E, 0x4D, 0x15, 0xD1, 0xCF, 0x33, 0x80, 0xF0,
0x99, 0x2D, 0x66, 0x77, 0x70, 0x73, 0x02, 0x41, 0x00, 0xC8, 0xDA, 0x8F, 0xD0, 0xB8, 0x5E, 0x9E,
0x9B, 0xB4, 0xEB, 0xC6, 0xCD, 0x56, 0x43, 0x71, 0x8A, 0xE4, 0xE3, 0xD7, 0x65, 0x99, 0xE8, 0x51,
0xA9, 0xD7, 0xEF, 0x65, 0xE3, 0x67, 0x67, 0x8E, 0x09, 0x77, 0x68, 0xCD, 0x1D, 0xE1, 0x32, 0x2B,
0x20, 0xE5, 0xCD, 0x96, 0x4E, 0x5B, 0x81, 0x73, 0x83, 0x88, 0x85, 0x19, 0x53, 0x04, 0x3F, 0xDD,
0x34, 0x1D, 0x71, 0x7B, 0x1D, 0xED, 0x84, 0x3B, 0x5D, 0x02, 0x40, 0x10, 0x84, 0xA8, 0xF3, 0x12,
0xAB, 0x48, 0x31, 0xE9, 0xA3, 0x1D, 0x42, 0xA2, 0xA3, 0x09, 0xA4, 0xFC, 0x37, 0x83, 0x7D, 0xBB,
0xE4, 0xBF, 0x4B, 0xF5, 0x93, 0xC7, 0x7B, 0x6A, 0x08, 0x50, 0x06, 0xD0, 0x6E, 0x62, 0x27, 0xC0,
0xE3, 0x28, 0x50, 0xE6, 0x6B, 0x5F, 0xE0, 0x43, 0x5D, 0xD6, 0x0B, 0xD6, 0xBC, 0x23, 0x35, 0x9E,
0xA9, 0xC6, 0x11, 0x7C, 0xD3, 0x65, 0xAB, 0x08, 0xD2, 0x53, 0x6F, 0x02, 0x41, 0x00, 0xA4, 0x91,
0x37, 0x9E, 0x9B, 0x41, 0xA3, 0x91, 0x0E, 0x86, 0xD4, 0x87, 0xAF, 0xB3, 0x68, 0xD7, 0x95, 0xBC,
0xFC, 0xE2, 0x59, 0x5D, 0x59, 0x73, 0xE0, 0xE2, 0x5C, 0xC8, 0x1B, 0x14, 0x64, 0xF3, 0x6A, 0xAC,
0x2A, 0xCB, 0xDD, 0x94, 0xDE, 0x73, 0x80, 0xF6, 0x96, 0xBD, 0xB3, 0x09, 0xF8, 0xDC, 0x7F, 0xC2,
0x16, 0x42, 0xC7, 0xCB, 0x8F, 0xF1, 0xC0, 0x62, 0x17, 0xAF, 0x28, 0xC9, 0xDC, 0x5D, 0x02, 0x40,
0x0D, 0xE2, 0x78, 0x24, 0x66, 0x63, 0x1A, 0xCB, 0x89, 0x84, 0x24, 0xC5, 0x8C, 0xA3, 0x04, 0x4E,
0x2C, 0xF2, 0xF5, 0x79, 0xE4, 0xB7, 0x73, 0xD2, 0xA3, 0x49, 0x4C, 0x6E, 0x0D, 0xBE, 0xD8, 0x12,
0xBA, 0xF6, 0x6E, 0x15, 0xD3, 0xA9, 0x91, 0xEF, 0x0B, 0x9D, 0xF2, 0xF8, 0x94, 0x25, 0x73, 0x4E,
0x2B, 0x55, 0xB2, 0xF1, 0xE1, 0xE1, 0x44, 0xFD, 0x5C, 0x6A, 0xEA, 0x84, 0xF0, 0xC7, 0x23, 0x15
};

static CfResult CreateTrustCertsArray(HcfX509CertificateArray **trustCertsArray,
    const char *rootCertPem, const char *interCertPem)
{
    if (trustCertsArray == nullptr || rootCertPem == nullptr || interCertPem == nullptr) {
        return CF_INVALID_PARAMS;
    }

    uint32_t certNum = 2;
    *trustCertsArray = static_cast<HcfX509CertificateArray *>(CfMalloc(sizeof(HcfX509CertificateArray), 0));
    if (*trustCertsArray == nullptr) {
        return CF_ERR_MALLOC;
    }

    (*trustCertsArray)->data = static_cast<HcfX509Certificate **>(CfMalloc(certNum * sizeof(HcfX509Certificate *), 0));
    if ((*trustCertsArray)->data == nullptr) {
        CfFree(*trustCertsArray);
        *trustCertsArray = nullptr;
        return CF_ERR_MALLOC;
    }
    (*trustCertsArray)->count = certNum;

    CfEncodingBlob rootCertBlob = {0};
    rootCertBlob.data = reinterpret_cast<uint8_t *>(const_cast<char *>(rootCertPem));
    rootCertBlob.encodingFormat = CF_FORMAT_PEM;
    rootCertBlob.len = strlen(rootCertPem) + 1;

    CfResult ret = HcfX509CertificateCreate(&rootCertBlob, &(*trustCertsArray)->data[0]);
    if (ret != CF_SUCCESS) {
        CfFree((*trustCertsArray)->data);
        CfFree(*trustCertsArray);
        *trustCertsArray = nullptr;
        return ret;
    }

    CfEncodingBlob interCertBlob = {0};
    interCertBlob.data = reinterpret_cast<uint8_t *>(const_cast<char *>(interCertPem));
    interCertBlob.encodingFormat = CF_FORMAT_PEM;
    interCertBlob.len = strlen(interCertPem) + 1;

    ret = HcfX509CertificateCreate(&interCertBlob, &(*trustCertsArray)->data[1]);
    if (ret != CF_SUCCESS) {
        CfObjDestroy((*trustCertsArray)->data[0]);
        CfFree((*trustCertsArray)->data);
        CfFree(*trustCertsArray);
        *trustCertsArray = nullptr;
        return ret;
    }

    return CF_SUCCESS;
}

static CfResult CreateSignerCertsArray(HcfX509CertificateArray **signerCertsArray, const char *leafCertPem)
{
    if (signerCertsArray == nullptr || leafCertPem == nullptr) {
        return CF_INVALID_PARAMS;
    }

    uint32_t certNum = 1;
    *signerCertsArray = static_cast<HcfX509CertificateArray *>(CfMalloc(sizeof(HcfX509CertificateArray), 0));
    if (*signerCertsArray == nullptr) {
        return CF_ERR_MALLOC;
    }

    (*signerCertsArray)->data = static_cast<HcfX509Certificate **>(CfMalloc(certNum * sizeof(HcfX509Certificate *), 0));
    if ((*signerCertsArray)->data == nullptr) {
        CfFree(*signerCertsArray);
        *signerCertsArray = nullptr;
        return CF_ERR_MALLOC;
    }
    (*signerCertsArray)->count = certNum;

    CfEncodingBlob leafCertBlob = {0};
    leafCertBlob.data = reinterpret_cast<uint8_t *>(const_cast<char *>(leafCertPem));
    leafCertBlob.encodingFormat = CF_FORMAT_PEM;
    leafCertBlob.len = strlen(leafCertPem) + 1;

    CfResult ret = HcfX509CertificateCreate(&leafCertBlob, &(*signerCertsArray)->data[0]);
    if (ret != CF_SUCCESS) {
        CfFree((*signerCertsArray)->data);
        CfFree(*signerCertsArray);
        *signerCertsArray = nullptr;
        return ret;
    }

    return CF_SUCCESS;
}

static void DestroyCertsArray(HcfX509CertificateArray **certsArray)
{
    if (certsArray == nullptr || *certsArray == nullptr) {
        return;
    }

    if ((*certsArray)->data != nullptr) {
        for (uint32_t i = 0; i < (*certsArray)->count; i++) {
            if ((*certsArray)->data[i] != nullptr) {
                CfObjDestroy((*certsArray)->data[i]);
            }
        }
        CfFree((*certsArray)->data);
    }
    CfFree(*certsArray);
    *certsArray = nullptr;
}

static void FreeCmsOptions(HcfCmsParserSignedDataOptions *cmsOptions)
{
    if (cmsOptions != nullptr) {
        DestroyCertsArray(&cmsOptions->trustCerts);
        DestroyCertsArray(&cmsOptions->signerCerts);
        CfFree(cmsOptions);
    }
}

static CfResult BuildCmsData(HcfCmsParserSignedDataOptions **cmsOptions)
{
    HcfX509CertificateArray *trustCertsArray = nullptr;
    HcfX509CertificateArray *signerCertsArray = nullptr;
    CfResult res = CreateTrustCertsArray(&trustCertsArray, g_verifyRootPem, g_interPem);
    if (res != CF_SUCCESS) {
        return res;
    }

    res = CreateSignerCertsArray(&signerCertsArray, g_testleftPem);
    if (res != CF_SUCCESS) {
        DestroyCertsArray(&trustCertsArray);
        return res;
    }

    HcfCmsParserSignedDataOptions *tmpCmsOptions = static_cast<HcfCmsParserSignedDataOptions *>(
        CfMalloc(sizeof(HcfCmsParserSignedDataOptions), 0));
    if (tmpCmsOptions == nullptr) {
        DestroyCertsArray(&trustCertsArray);
        DestroyCertsArray(&signerCertsArray);
        return CF_ERR_MALLOC;
    }

    CfBlob externalContent;
    externalContent.data = const_cast<uint8_t*>(g_inContent);
    externalContent.size = sizeof(g_inContent);

    tmpCmsOptions->trustCerts = trustCertsArray;
    tmpCmsOptions->signerCerts = signerCertsArray;
    tmpCmsOptions->contentData = &externalContent;
    tmpCmsOptions->contentDataFormat = BINARY;
    *cmsOptions = tmpCmsOptions;
    return CF_SUCCESS;
}

void CryptoX509CertCmsParserTestMock::SetUpTestCase()
{
}

void CryptoX509CertCmsParserTestMock::TearDownTestCase()
{
}

void CryptoX509CertCmsParserTestMock::SetUp()
{
}

void CryptoX509CertCmsParserTestMock::TearDown()
{
}

HWTEST_F(CryptoX509CertCmsParserTestMock, VerifyMockCmsVerifyFail, TestSize.Level0)
{
    HcfCmsParser *cmsParser = nullptr;
    CfBlob cmsData;
    cmsData.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_signedCmsPem));
    cmsData.size = strlen(g_signedCmsPem) + 1;
    CfResult res = HcfCreateCmsParser(&cmsParser);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsParser, nullptr);

    HcfCmsParserSignedDataOptions *cmsOptions = nullptr;
    res = BuildCmsData(&cmsOptions);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsOptions, nullptr);

    res = cmsParser->setRawData(cmsParser, &cmsData, CMS_PEM);
    EXPECT_EQ(res, CF_SUCCESS);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), CMS_verify(_, _, _, _, _, _))
        .WillOnce(Return(0))
        .WillRepeatedly(Invoke(__real_CMS_verify));

    res = cmsParser->verifySignedData(cmsParser, cmsOptions);
    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);

    X509OpensslMock::SetMockFlag(false);
    FreeCmsOptions(cmsOptions);
    CfObjDestroy(cmsParser);
}

HWTEST_F(CryptoX509CertCmsParserTestMock, DecryptMockCmsDecryptFail, TestSize.Level0)
{
    HcfCmsParser *cmsParser = nullptr;
    CfBlob cmsData;
    cmsData.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_encryptedCmsPem));
    cmsData.size = strlen(g_encryptedCmsPem) + 1;

    CfResult res = HcfCreateCmsParser(&cmsParser);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsParser, nullptr);

    res = cmsParser->setRawData(cmsParser, &cmsData, CMS_PEM);
    EXPECT_EQ(res, CF_SUCCESS);

    HcfCmsParserDecryptEnvelopedDataOptions *decryptOptions =
        static_cast<HcfCmsParserDecryptEnvelopedDataOptions *>(
            CfMalloc(sizeof(HcfCmsParserDecryptEnvelopedDataOptions), 0));
    EXPECT_NE(decryptOptions, nullptr);

    PrivateKeyInfo *privateKey = static_cast<PrivateKeyInfo *>(
        CfMalloc(sizeof(PrivateKeyInfo), 0));
    EXPECT_NE(privateKey, nullptr);
    privateKey->privateKey = const_cast<CfEncodingBlob*>(&g_decryptEnvelopedDataPemStream);
    privateKey->privateKeyPassword = nullptr;

    HcfX509Certificate *x509Cert = nullptr;
    CfEncodingBlob certBlob = {0};
    certBlob.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_pubKey));
    certBlob.encodingFormat = CF_FORMAT_PEM;
    certBlob.len = strlen(g_pubKey) + 1;

    res = HcfX509CertificateCreate(&certBlob, &x509Cert);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(x509Cert, nullptr);

    decryptOptions->privateKey = privateKey;
    decryptOptions->cert = x509Cert;
    decryptOptions->encryptedContentData = nullptr;
    decryptOptions->contentDataFormat = BINARY;

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), CMS_decrypt(_, _, _, _, _, _))
        .WillOnce(Return(0))
        .WillRepeatedly(Invoke(__real_CMS_decrypt));

    CfBlob decryptedData = {0, nullptr};
    res = cmsParser->decryptEnvelopedData(cmsParser, decryptOptions, &decryptedData);
    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);

    X509OpensslMock::SetMockFlag(false);
    CfFree(decryptOptions);
    CfFree(privateKey);
    CfObjDestroy(x509Cert);
    CfObjDestroy(cmsParser);
}

HWTEST_F(CryptoX509CertCmsParserTestMock, ParseMockPemReadBioCmsFail, TestSize.Level0)
{
    HcfCmsParser *cmsParser = nullptr;
    CfBlob cmsData;
    cmsData.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_signedCmsPem));
    cmsData.size = strlen(g_signedCmsPem) + 1;

    CfResult res = HcfCreateCmsParser(&cmsParser);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsParser, nullptr);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), PEM_read_bio_CMS(_, _, _, _))
        .WillOnce(Return(nullptr))
        .WillRepeatedly(Invoke(__real_PEM_read_bio_CMS));

    res = cmsParser->setRawData(cmsParser, &cmsData, CMS_PEM);
    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);

    X509OpensslMock::SetMockFlag(false);
    CfObjDestroy(cmsParser);
}

HWTEST_F(CryptoX509CertCmsParserTestMock, ParseMockD2iCmsBioFail, TestSize.Level0)
{
    HcfCmsParser *cmsParser = nullptr;
    CfBlob cmsData;
    cmsData.data = g_testRsaKeyNoPasswordDer;
    cmsData.size = sizeof(g_testRsaKeyNoPasswordDer);

    CfResult res = HcfCreateCmsParser(&cmsParser);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsParser, nullptr);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), d2i_CMS_bio(_, _))
        .WillOnce(Return(nullptr))
        .WillRepeatedly(Invoke(__real_d2i_CMS_bio));

    res = cmsParser->setRawData(cmsParser, &cmsData, CMS_DER);
    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);

    X509OpensslMock::SetMockFlag(false);
    CfObjDestroy(cmsParser);
}

HWTEST_F(CryptoX509CertCmsParserTestMock, GetContentTypeMockCmsGet0TypeFail, TestSize.Level0)
{
    HcfCmsParser *cmsParser = nullptr;
    CfBlob cmsData;
    cmsData.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_signedCmsPem));
    cmsData.size = strlen(g_signedCmsPem) + 1;

    CfResult res = HcfCreateCmsParser(&cmsParser);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsParser, nullptr);

    res = cmsParser->setRawData(cmsParser, &cmsData, CMS_PEM);
    EXPECT_EQ(res, CF_SUCCESS);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), CMS_get0_type(_))
        .WillOnce(Return(nullptr))
        .WillRepeatedly(Invoke(__real_CMS_get0_type));

    HcfCmsContentType contentType;
    res = cmsParser->getContentType(cmsParser, &contentType);
    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);

    X509OpensslMock::SetMockFlag(false);
    CfObjDestroy(cmsParser);
}

HWTEST_F(CryptoX509CertCmsParserTestMock, GetContentDataMockCmsGet0ContentFail, TestSize.Level0)
{
    HcfCmsParser *cmsParser = nullptr;
    CfBlob cmsData;
    cmsData.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_signedCmsPem));
    cmsData.size = strlen(g_signedCmsPem) + 1;

    CfResult res = HcfCreateCmsParser(&cmsParser);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsParser, nullptr);

    res = cmsParser->setRawData(cmsParser, &cmsData, CMS_PEM);
    EXPECT_EQ(res, CF_SUCCESS);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), CMS_get0_content(_))
        .WillOnce(Return(nullptr))
        .WillRepeatedly(Invoke(__real_CMS_get0_content));

    CfBlob contentData = {0, nullptr};
    res = cmsParser->getContentData(cmsParser, &contentData);
    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);

    X509OpensslMock::SetMockFlag(false);
    CfObjDestroy(cmsParser);
}

HWTEST_F(CryptoX509CertCmsParserTestMock, GetContentDataMockBioNewFail, TestSize.Level0)
{
    HcfCmsParser *cmsParser = nullptr;
    CfBlob cmsData;
    cmsData.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_signedCmsPem));
    cmsData.size = strlen(g_signedCmsPem) + 1;

    CfResult res = HcfCreateCmsParser(&cmsParser);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsParser, nullptr);

    res = cmsParser->setRawData(cmsParser, &cmsData, CMS_PEM);
    EXPECT_EQ(res, CF_SUCCESS);

    // Enable mock and set expectation for BIO_new to return nullptr
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), BIO_new(_))
        .WillOnce(Return(nullptr))  // nullptr = failure
        .WillRepeatedly(Invoke(__real_BIO_new));

    CfBlob contentData = {0, nullptr};
    res = cmsParser->getContentData(cmsParser, &contentData);
    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);

    X509OpensslMock::SetMockFlag(false);
    CfObjDestroy(cmsParser);
}

// Mock test case for BIO_write failure
HWTEST_F(CryptoX509CertCmsParserTestMock, GetContentDataMockBioWriteFail, TestSize.Level0)
{
    HcfCmsParser *cmsParser = nullptr;
    CfBlob cmsData;
    cmsData.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_signedCmsPem));
    cmsData.size = strlen(g_signedCmsPem) + 1;

    CfResult res = HcfCreateCmsParser(&cmsParser);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsParser, nullptr);

    res = cmsParser->setRawData(cmsParser, &cmsData, CMS_PEM);
    EXPECT_EQ(res, CF_SUCCESS);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), BIO_write(_, _, _))
        .WillOnce(Return(-1))
        .WillRepeatedly(Invoke(__real_BIO_write));

    CfBlob contentData = {0, nullptr};
    res = cmsParser->getContentData(cmsParser, &contentData);
    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);

    X509OpensslMock::SetMockFlag(false);
    CfObjDestroy(cmsParser);
}

HWTEST_F(CryptoX509CertCmsParserTestMock, GetCmsSignerCertMockSkX509ValueNull, TestSize.Level0)
{
    HcfCmsParser *cmsParser = nullptr;
    CfBlob cmsData;
    cmsData.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_signedCmsPem));
    cmsData.size = strlen(g_signedCmsPem) + 1;

    CfResult res = HcfCreateCmsParser(&cmsParser);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsParser, nullptr);

    res = cmsParser->setRawData(cmsParser, &cmsData, CMS_PEM);
    EXPECT_EQ(res, CF_SUCCESS);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), CMS_get0_SignerInfos(_))
        .WillOnce(Return(nullptr))
        .WillRepeatedly(Invoke(__real_CMS_get0_SignerInfos));

    HcfX509CertificateArray certs = {nullptr, 0};
    res = cmsParser->getCerts(cmsParser, CMS_CERT_SIGNER_CERTS, &certs);
    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);

    X509OpensslMock::SetMockFlag(false);
    CfObjDestroy(cmsParser);
}

HWTEST_F(CryptoX509CertCmsParserTestMock, GetCertsMockCmsGet1CertsFail, TestSize.Level0)
{
    HcfCmsParser *cmsParser = nullptr;
    CfBlob cmsData;
    cmsData.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_signedCmsPem));
    cmsData.size = strlen(g_signedCmsPem) + 1;

    CfResult res = HcfCreateCmsParser(&cmsParser);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsParser, nullptr);

    res = cmsParser->setRawData(cmsParser, &cmsData, CMS_PEM);
    EXPECT_EQ(res, CF_SUCCESS);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), CMS_get1_certs(_))
        .WillOnce(Return(nullptr))
        .WillRepeatedly(Invoke(__real_CMS_get1_certs));

    HcfX509CertificateArray certs = {nullptr, 0};
    res = cmsParser->getCerts(cmsParser, CMS_CERT_ALL_CERTS, &certs);
    EXPECT_EQ(res, CF_SUCCESS);

    X509OpensslMock::SetMockFlag(false);
    CfObjDestroy(cmsParser);
}

HWTEST_F(CryptoX509CertCmsParserTestMock, VerifyMockX509StoreNewFail, TestSize.Level0)
{
    HcfCmsParser *cmsParser = nullptr;
    CfBlob cmsData;
    cmsData.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_signedCmsPem));
    cmsData.size = strlen(g_signedCmsPem) + 1;

    CfResult res = HcfCreateCmsParser(&cmsParser);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsParser, nullptr);

    HcfCmsParserSignedDataOptions *cmsOptions = nullptr;
    res = BuildCmsData(&cmsOptions);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsOptions, nullptr);

    res = cmsParser->setRawData(cmsParser, &cmsData, CMS_PEM);
    EXPECT_EQ(res, CF_SUCCESS);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_STORE_new())
        .WillOnce(Return(nullptr))
        .WillRepeatedly(Invoke(__real_X509_STORE_new));

    res = cmsParser->verifySignedData(cmsParser, cmsOptions);
    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);

    X509OpensslMock::SetMockFlag(false);
    FreeCmsOptions(cmsOptions);
    CfObjDestroy(cmsParser);
}

HWTEST_F(CryptoX509CertCmsParserTestMock, VerifyMockX509StoreAddCertFail, TestSize.Level0)
{
    HcfCmsParser *cmsParser = nullptr;
    CfBlob cmsData;
    cmsData.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_signedCmsPem));
    cmsData.size = strlen(g_signedCmsPem) + 1;

    CfResult res = HcfCreateCmsParser(&cmsParser);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsParser, nullptr);

    HcfCmsParserSignedDataOptions *cmsOptions = nullptr;
    res = BuildCmsData(&cmsOptions);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsOptions, nullptr);

    res = cmsParser->setRawData(cmsParser, &cmsData, CMS_PEM);
    EXPECT_EQ(res, CF_SUCCESS);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_STORE_add_cert(_, _))
        .WillOnce(Return(0))
        .WillRepeatedly(Invoke(__real_X509_STORE_add_cert));

    res = cmsParser->verifySignedData(cmsParser, cmsOptions);
    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);

    X509OpensslMock::SetMockFlag(false);
    FreeCmsOptions(cmsOptions);
    CfObjDestroy(cmsParser);
}

HWTEST_F(CryptoX509CertCmsParserTestMock, VerifyMockSkX509NewNullFail, TestSize.Level0)
{
    HcfCmsParser *cmsParser = nullptr;
    CfBlob cmsData;
    cmsData.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_signedCmsPem));
    cmsData.size = strlen(g_signedCmsPem) + 1;

    CfResult res = HcfCreateCmsParser(&cmsParser);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsParser, nullptr);

    HcfCmsParserSignedDataOptions *cmsOptions = nullptr;
    res = BuildCmsData(&cmsOptions);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsOptions, nullptr);

    res = cmsParser->setRawData(cmsParser, &cmsData, CMS_PEM);
    EXPECT_EQ(res, CF_SUCCESS);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), OPENSSL_sk_new_null())
        .WillOnce(Return(nullptr))
        .WillRepeatedly(Invoke(__real_OPENSSL_sk_new_null));

    res = cmsParser->verifySignedData(cmsParser, cmsOptions);
    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);

    X509OpensslMock::SetMockFlag(false);
    FreeCmsOptions(cmsOptions);
    CfObjDestroy(cmsParser);
}

HWTEST_F(CryptoX509CertCmsParserTestMock, VerifyMockOpensslSkPushFail, TestSize.Level0)
{
    HcfCmsParser *cmsParser = nullptr;
    CfBlob cmsData;
    cmsData.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_signedCmsPem));
    cmsData.size = strlen(g_signedCmsPem) + 1;

    CfResult res = HcfCreateCmsParser(&cmsParser);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsParser, nullptr);

    HcfCmsParserSignedDataOptions *cmsOptions = nullptr;
    res = BuildCmsData(&cmsOptions);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsOptions, nullptr);

    res = cmsParser->setRawData(cmsParser, &cmsData, CMS_PEM);
    EXPECT_EQ(res, CF_SUCCESS);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), OPENSSL_sk_push(_, _))
        .WillOnce(Return(0))
        .WillRepeatedly(Invoke(__real_OPENSSL_sk_push));

    res = cmsParser->verifySignedData(cmsParser, cmsOptions);
    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);

    X509OpensslMock::SetMockFlag(false);
    FreeCmsOptions(cmsOptions);
    CfObjDestroy(cmsParser);
}

HWTEST_F(CryptoX509CertCmsParserTestMock, SetRawDataMockBioNewMemBufFail, TestSize.Level0)
{
    HcfCmsParser *cmsParser = nullptr;
    CfBlob cmsData;
    cmsData.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_signedCmsPem));
    cmsData.size = strlen(g_signedCmsPem) + 1;

    CfResult res = HcfCreateCmsParser(&cmsParser);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsParser, nullptr);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), BIO_new_mem_buf(_, _))
        .WillOnce(Return(nullptr))
        .WillRepeatedly(Invoke(__real_BIO_new_mem_buf));

    res = cmsParser->setRawData(cmsParser, &cmsData, CMS_PEM);
    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);

    X509OpensslMock::SetMockFlag(false);
    CfObjDestroy(cmsParser);
}

HWTEST_F(CryptoX509CertCmsParserTestMock, DecryptMockBioNewFail, TestSize.Level0)
{
    HcfCmsParser *cmsParser = nullptr;
    CfBlob cmsData;
    cmsData.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_encryptedCmsPem));
    cmsData.size = strlen(g_encryptedCmsPem) + 1;

    CfResult res = HcfCreateCmsParser(&cmsParser);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsParser, nullptr);

    res = cmsParser->setRawData(cmsParser, &cmsData, CMS_PEM);
    EXPECT_EQ(res, CF_SUCCESS);

    HcfCmsParserDecryptEnvelopedDataOptions *decryptOptions =
        static_cast<HcfCmsParserDecryptEnvelopedDataOptions *>(
            CfMalloc(sizeof(HcfCmsParserDecryptEnvelopedDataOptions), 0));
    EXPECT_NE(decryptOptions, nullptr);

    PrivateKeyInfo *privateKey = static_cast<PrivateKeyInfo *>(
        CfMalloc(sizeof(PrivateKeyInfo), 0));
    EXPECT_NE(privateKey, nullptr);
    privateKey->privateKey = const_cast<CfEncodingBlob*>(&g_decryptEnvelopedDataPemStream);
    privateKey->privateKeyPassword = nullptr;

    HcfX509Certificate *x509Cert = nullptr;
    CfEncodingBlob certBlob = {0};
    certBlob.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_pubKey));
    certBlob.encodingFormat = CF_FORMAT_PEM;
    certBlob.len = strlen(g_pubKey) + 1;

    res = HcfX509CertificateCreate(&certBlob, &x509Cert);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(x509Cert, nullptr);

    decryptOptions->privateKey = privateKey;
    decryptOptions->cert = x509Cert;
    decryptOptions->encryptedContentData = nullptr;
    decryptOptions->contentDataFormat = BINARY;

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), BIO_new(_))
        .WillOnce(Return(nullptr))
        .WillRepeatedly(Invoke(__real_BIO_new));

    CfBlob decryptedData = {0, nullptr};
    res = cmsParser->decryptEnvelopedData(cmsParser, decryptOptions, &decryptedData);
    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);

    X509OpensslMock::SetMockFlag(false);
    CfFree(decryptOptions);
    CfFree(privateKey);
    CfObjDestroy(x509Cert);
    CfObjDestroy(cmsParser);
}

HWTEST_F(CryptoX509CertCmsParserTestMock, CreateParserMockCfMallocFail, TestSize.Level0)
{
    SetMockFlag(true);
    HcfCmsParser *cmsParser = nullptr;
    CfResult res = HcfCreateCmsParser(&cmsParser);
    EXPECT_EQ(res, CF_ERR_MALLOC);
    EXPECT_EQ(cmsParser, nullptr);
    SetMockFlag(false);
}

HWTEST_F(CryptoX509CertCmsParserTestMock, SetRawDataInvalidFormat, TestSize.Level0)
{
    HcfCmsParser *cmsParser = nullptr;
    CfBlob cmsData;
    cmsData.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_signedCmsPem));
    cmsData.size = strlen(g_signedCmsPem) + 1;

    CfResult res = HcfCreateCmsParser(&cmsParser);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsParser, nullptr);

    res = cmsParser->setRawData(cmsParser, &cmsData, static_cast<HcfCmsFormat>(999));
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);

    CfObjDestroy(cmsParser);
}

HWTEST_F(CryptoX509CertCmsParserTestMock, GetContentDataMockCfMallocFail, TestSize.Level0)
{
    HcfCmsParser *cmsParser = nullptr;
    CfBlob cmsData;
    cmsData.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_signedCmsPem));
    cmsData.size = strlen(g_signedCmsPem) + 1;

    CfResult res = HcfCreateCmsParser(&cmsParser);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsParser, nullptr);

    res = cmsParser->setRawData(cmsParser, &cmsData, CMS_PEM);
    EXPECT_EQ(res, CF_SUCCESS);

    SetMockFlag(true);
    CfBlob contentData = {0, nullptr};
    res = cmsParser->getContentData(cmsParser, &contentData);
    EXPECT_EQ(res, CF_ERR_MALLOC);
    SetMockFlag(false);

    CfObjDestroy(cmsParser);
}

HWTEST_F(CryptoX509CertCmsParserTestMock, GetCertsMockCfMallocFailAllCerts, TestSize.Level0)
{
    HcfCmsParser *cmsParser = nullptr;
    CfBlob cmsData;
    cmsData.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_signedCmsPem));
    cmsData.size = strlen(g_signedCmsPem) + 1;

    CfResult res = HcfCreateCmsParser(&cmsParser);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsParser, nullptr);

    res = cmsParser->setRawData(cmsParser, &cmsData, CMS_PEM);
    EXPECT_EQ(res, CF_SUCCESS);

    SetMockFlag(true);
    HcfX509CertificateArray certs = {nullptr, 0};
    res = cmsParser->getCerts(cmsParser, CMS_CERT_ALL_CERTS, &certs);
    EXPECT_EQ(res, CF_ERR_MALLOC);
    SetMockFlag(false);

    CfObjDestroy(cmsParser);
}

HWTEST_F(CryptoX509CertCmsParserTestMock, GetCertsMockCfMallocFailSignerCerts, TestSize.Level0)
{
    HcfCmsParser *cmsParser = nullptr;
    CfBlob cmsData;
    cmsData.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_signedCmsPem));
    cmsData.size = strlen(g_signedCmsPem) + 1;

    CfResult res = HcfCreateCmsParser(&cmsParser);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsParser, nullptr);

    res = cmsParser->setRawData(cmsParser, &cmsData, CMS_PEM);
    EXPECT_EQ(res, CF_SUCCESS);

    SetMockFlag(true);
    HcfX509CertificateArray certs = {nullptr, 0};
    res = cmsParser->getCerts(cmsParser, CMS_CERT_SIGNER_CERTS, &certs);
    EXPECT_EQ(res, CF_ERR_MALLOC);
    SetMockFlag(false);

    CfObjDestroy(cmsParser);
}

HWTEST_F(CryptoX509CertCmsParserTestMock, DecryptMockCfMallocFail, TestSize.Level0)
{
    HcfCmsParser *cmsParser = nullptr;
    CfBlob cmsData;
    cmsData.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_encryptedCmsPem));
    cmsData.size = strlen(g_encryptedCmsPem) + 1;

    CfResult res = HcfCreateCmsParser(&cmsParser);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsParser, nullptr);

    res = cmsParser->setRawData(cmsParser, &cmsData, CMS_PEM);
    EXPECT_EQ(res, CF_SUCCESS);

    HcfCmsParserDecryptEnvelopedDataOptions *decryptOptions =
        static_cast<HcfCmsParserDecryptEnvelopedDataOptions *>(
            CfMalloc(sizeof(HcfCmsParserDecryptEnvelopedDataOptions), 0));
    EXPECT_NE(decryptOptions, nullptr);

    PrivateKeyInfo *privateKey = static_cast<PrivateKeyInfo *>(
        CfMalloc(sizeof(PrivateKeyInfo), 0));
    EXPECT_NE(privateKey, nullptr);
    privateKey->privateKey = const_cast<CfEncodingBlob*>(&g_decryptEnvelopedDataPemStream);
    privateKey->privateKeyPassword = nullptr;

    HcfX509Certificate *x509Cert = nullptr;
    CfEncodingBlob certBlob = {0};
    certBlob.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_pubKey));
    certBlob.encodingFormat = CF_FORMAT_PEM;
    certBlob.len = strlen(g_pubKey) + 1;

    res = HcfX509CertificateCreate(&certBlob, &x509Cert);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(x509Cert, nullptr);

    decryptOptions->privateKey = privateKey;
    decryptOptions->cert = x509Cert;
    decryptOptions->encryptedContentData = nullptr;
    decryptOptions->contentDataFormat = BINARY;

    SetMockFlag(true);
    CfBlob decryptedData = {0, nullptr};
    res = cmsParser->decryptEnvelopedData(cmsParser, decryptOptions, &decryptedData);
    EXPECT_EQ(res, CF_ERR_MALLOC);
    SetMockFlag(false);

    CfFree(decryptOptions);
    CfFree(privateKey);
    CfObjDestroy(x509Cert);
    CfObjDestroy(cmsParser);
}

HWTEST_F(CryptoX509CertCmsParserTestMock, InvalidParamsTest, TestSize.Level0)
{
    HcfCmsParser *cmsParser = nullptr;
    CfBlob cmsData;
    cmsData.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_signedCmsPem));
    cmsData.size = strlen(g_signedCmsPem) + 1;

    CfResult res = HcfCreateCmsParser(&cmsParser);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsParser, nullptr);

    res = cmsParser->setRawData(nullptr, &cmsData, CMS_PEM);
    EXPECT_EQ(res, CF_INVALID_PARAMS);

    res = cmsParser->setRawData(cmsParser, nullptr, CMS_PEM);
    EXPECT_EQ(res, CF_INVALID_PARAMS);

    HcfCmsContentType contentType;
    res = cmsParser->getContentType(nullptr, &contentType);
    EXPECT_EQ(res, CF_INVALID_PARAMS);

    res = cmsParser->getContentType(cmsParser, nullptr);
    EXPECT_EQ(res, CF_INVALID_PARAMS);

    CfBlob contentData = {0, nullptr};
    res = cmsParser->getContentData(nullptr, &contentData);
    EXPECT_EQ(res, CF_INVALID_PARAMS);

    res = cmsParser->getContentData(cmsParser, nullptr);
    EXPECT_EQ(res, CF_INVALID_PARAMS);

    HcfX509CertificateArray certs = {nullptr, 0};
    res = cmsParser->getCerts(nullptr, CMS_CERT_ALL_CERTS, &certs);
    EXPECT_EQ(res, CF_INVALID_PARAMS);

    res = cmsParser->getCerts(cmsParser, CMS_CERT_ALL_CERTS, nullptr);
    EXPECT_EQ(res, CF_INVALID_PARAMS);

    res = cmsParser->verifySignedData(nullptr, nullptr);
    EXPECT_EQ(res, CF_INVALID_PARAMS);

    res = cmsParser->verifySignedData(cmsParser, nullptr);
    EXPECT_EQ(res, CF_INVALID_PARAMS);

    res = cmsParser->decryptEnvelopedData(nullptr, nullptr, nullptr);
    EXPECT_EQ(res, CF_INVALID_PARAMS);

    res = cmsParser->decryptEnvelopedData(cmsParser, nullptr, nullptr);
    EXPECT_EQ(res, CF_INVALID_PARAMS);

    CfObjDestroy(cmsParser);
}

HWTEST_F(CryptoX509CertCmsParserTestMock, OperationsBeforeSetRawData, TestSize.Level0)
{
    HcfCmsParser *cmsParser = nullptr;
    CfResult res = HcfCreateCmsParser(&cmsParser);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsParser, nullptr);

    HcfCmsContentType contentType;
    res = cmsParser->getContentType(cmsParser, &contentType);
    EXPECT_EQ(res, CF_ERR_SHOULD_NOT_CALL);

    CfBlob contentData = {0, nullptr};
    res = cmsParser->getContentData(cmsParser, &contentData);
    EXPECT_EQ(res, CF_ERR_SHOULD_NOT_CALL);

    HcfX509CertificateArray certs = {nullptr, 0};
    res = cmsParser->getCerts(cmsParser, CMS_CERT_ALL_CERTS, &certs);
    EXPECT_EQ(res, CF_ERR_SHOULD_NOT_CALL);

    CfObjDestroy(cmsParser);
}

HWTEST_F(CryptoX509CertCmsParserTestMock, GetCertsInvalidCertType, TestSize.Level0)
{
    HcfCmsParser *cmsParser = nullptr;
    CfBlob cmsData;
    cmsData.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_signedCmsPem));
    cmsData.size = strlen(g_signedCmsPem) + 1;

    CfResult res = HcfCreateCmsParser(&cmsParser);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsParser, nullptr);

    res = cmsParser->setRawData(cmsParser, &cmsData, CMS_PEM);
    EXPECT_EQ(res, CF_SUCCESS);

    HcfX509CertificateArray certs = {nullptr, 0};
    res = cmsParser->getCerts(cmsParser, static_cast<HcfCmsCertType>(999), &certs);
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);

    CfObjDestroy(cmsParser);
}

HWTEST_F(CryptoX509CertCmsParserTestMock, GetCmsSignerCertMockCmsGet1CertsFail, TestSize.Level0)
{
    HcfCmsParser *cmsParser = nullptr;
    CfBlob cmsData;
    cmsData.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_signedCmsPem));
    cmsData.size = strlen(g_signedCmsPem) + 1;

    CfResult res = HcfCreateCmsParser(&cmsParser);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsParser, nullptr);

    res = cmsParser->setRawData(cmsParser, &cmsData, CMS_PEM);
    EXPECT_EQ(res, CF_SUCCESS);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), CMS_get1_certs(_))
        .WillOnce(Return(nullptr))
        .WillRepeatedly(Invoke(__real_CMS_get1_certs));

    HcfX509CertificateArray certs = {nullptr, 0};
    res = cmsParser->getCerts(cmsParser, CMS_CERT_SIGNER_CERTS, &certs);
    EXPECT_NE(res, CF_ERR_CRYPTO_OPERATION);

    X509OpensslMock::SetMockFlag(false);
    CfObjDestroy(cmsParser);
}

HWTEST_F(CryptoX509CertCmsParserTestMock, GetCmsSignerCertsMockCmsGet0SignerInfosFail, TestSize.Level0)
{
    HcfCmsParser *cmsParser = nullptr;
    CfBlob cmsData;
    cmsData.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_signedCmsPem));
    cmsData.size = strlen(g_signedCmsPem) + 1;

    CfResult res = HcfCreateCmsParser(&cmsParser);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsParser, nullptr);

    res = cmsParser->setRawData(cmsParser, &cmsData, CMS_PEM);
    EXPECT_EQ(res, CF_SUCCESS);

    HcfX509CertificateArray certs = {nullptr, 0};
    res = cmsParser->getCerts(cmsParser, CMS_CERT_SIGNER_CERTS, &certs);
    EXPECT_EQ(res, CF_SUCCESS);

    if (certs.data != NULL) {
        for (uint32_t i = 0; i < certs.count; i++) {
            if (certs.data[i] != NULL) {
                CfObjDestroy(certs.data[i]);
            }
        }
        CfFree(certs.data);
    }

    CfObjDestroy(cmsParser);
}
}
