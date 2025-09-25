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
#include "vector"

#include "cert_cms_generator.h"
#include "cf_blob.h"
#include "memory_mock.h"
#include "cf_object_base.h"
#include "cf_result.h"
#include "cf_memory.h"
#include "x509_cert_cms_generator_openssl.h"
#include "cf_mock.h"

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
EVP_PKEY_CTX *__real_CMS_SignerInfo_get0_pkey_ctx(CMS_SignerInfo *si);
int __real_EVP_PKEY_CTX_set_rsa_padding(EVP_PKEY_CTX *ctx, int pad_mode);
const ASN1_OBJECT *__real_CMS_get0_type(const CMS_ContentInfo *cms);
CMS_RecipientInfo *__real_CMS_add1_recipient_cert(CMS_ContentInfo *cms, X509 *recip,
                                                  unsigned int flags);
EVP_PKEY_CTX *__real_CMS_RecipientInfo_get0_pkey_ctx(CMS_RecipientInfo *ri);
int __real_EVP_PKEY_CTX_set_ecdh_kdf_md(EVP_PKEY_CTX *ctx, const EVP_MD *md);
STACK_OF(CMS_SignerInfo) *__real_CMS_get0_SignerInfos(CMS_ContentInfo *cms);
int __real_OBJ_obj2nid(const ASN1_OBJECT *o);
BIO *__real_BIO_new(const BIO_METHOD *type);
CMS_ContentInfo *__real_CMS_AuthEnvelopedData_create(const EVP_CIPHER *cipher);
CMS_ContentInfo *__real_CMS_EnvelopedData_create(const EVP_CIPHER *cipher);
bool __real_CfIsClassMatch(const CfObjectBase *obj, const char *className);
EVP_PKEY *__real_X509_get0_pubkey(X509 *x);
int __real_CMS_set_detached(CMS_ContentInfo *cms, int detached);
#ifdef __cplusplus
}
#endif
namespace {
class CryptoX509CertCmsGeneratorTestPart2 : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

static char g_testEccKeyP1Pem[] =
"-----BEGIN EC PARAMETERS-----\r\n"
"BggqhkjOPQMBBw==\r\n"
"-----END EC PARAMETERS-----\r\n"
"-----BEGIN EC PRIVATE KEY-----\r\n"
"MHcCAQEEIODRxm2YjHqVMx8ilrOH/dT7RsPWzjsJKuFr0+xYBWkCoAoGCCqGSM49\r\n"
"AwEHoUQDQgAEc4Neg+rbDR2Wu8NLSxxaa14OZFEIF7/779yiDNtYWPlg2DM9Tkk+\r\n"
"LZk3kFkBfJAEbY42xwcbTj7n1sTH8X+dVg==\r\n"
"-----END EC PRIVATE KEY-----\r\n";

static char g_testEccCertP1Pem[] =
"-----BEGIN CERTIFICATE-----\r\n"
"MIICOjCCAd+gAwIBAgIGAXKnJjrAMAoGCCqGSM49BAMCMHkxCzAJBgNVBAYTAmNo\r\n"
"MQ8wDQYDVQQIDAZodWF3ZWkxDTALBgNVBAcMBHhpYW4xDzANBgNVBAoMBmh1YXdl\r\n"
"aTENMAsGA1UECwwEdGVzdDENMAsGA1UEAwwEYW5uZTEbMBkGCSqGSIb3DQEJARYM\r\n"
"dGVzdEAxMjMuY29tMB4XDTI0MTEyNzAzMjQ1MFoXDTM0MTEyNTAzMjQ1MFoweTEL\r\n"
"MAkGA1UEBhMCY2gxDzANBgNVBAgMBmh1YXdlaTENMAsGA1UEBwwEeGlhbjEPMA0G\r\n"
"A1UECgwGaHVhd2VpMQ0wCwYDVQQLDAR0ZXN0MQ0wCwYDVQQDDARhbm5lMRswGQYJ\r\n"
"KoZIhvcNAQkBFgx0ZXN0QDEyMy5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC\r\n"
"AARzg16D6tsNHZa7w0tLHFprXg5kUQgXv/vv3KIM21hY+WDYMz1OST4tmTeQWQF8\r\n"
"kARtjjbHBxtOPufWxMfxf51Wo1MwUTAdBgNVHQ4EFgQUU/P31GCBwyrj3yXkoNaX\r\n"
"xvPp8uIwHwYDVR0jBBgwFoAUU/P31GCBwyrj3yXkoNaXxvPp8uIwDwYDVR0TAQH/\r\n"
"BAUwAwEB/zAKBggqhkjOPQQDAgNJADBGAiEA/wCfbTorAWEEZcgd0CgfXI+EzXu2\r\n"
"Y88BmDD5LFlj3N0CIQDB34h77Li0CSpYpS4+7Mug237zbkFjHR3Q4/VWOT1G1A==\r\n"
"-----END CERTIFICATE-----\r\n";

static char g_testEccKeyP8Pem[] =
"-----BEGIN ENCRYPTED PRIVATE KEY-----\r\n"
"MIHsMFcGCSqGSIb3DQEFDTBKMCkGCSqGSIb3DQEFDDAcBAgVOv5c1oJSswICCAAw\r\n"
"DAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEEL+/YBmKLeXLWMPI2njbNh8EgZDY\r\n"
"/vhzIgh/CBsRqB9kxqV6hGVVU8Mv0M8vnIOvKqcTO6bEGj9X/BLMUJs4J3ayFcNL\r\n"
"1z6VDhNWgAk7asj1dDlYLK7IUtgx9e6X0kch7JIj2OnGTLc+3pCK+E/O0tPzEenB\r\n"
"N42bhM5M0Hx/PrWkRDXqRrsA8g8PsTPmcn6Z5f3zqI+4mtbkAr1bZKItQyHJbYI=\r\n"
"-----END ENCRYPTED PRIVATE KEY-----\r\n";

static char g_testEccCertP8Pem[] =
"-----BEGIN CERTIFICATE-----\r\n"
"MIICKDCCAc+gAwIBAgIGAXKnJjrAMAoGCCqGSM49BAMCMHExCzAJBgNVBAYTAnpo\r\n"
"MQ0wCwYDVQQIDAR4aWFuMQ0wCwYDVQQHDAR4aWFuMQ8wDQYDVQQKDAZodWF3ZWkx\r\n"
"DTALBgNVBAsMBHhpYW4xDTALBgNVBAMMBHhpYW4xFTATBgkqhkiG9w0BCQEWBmh1\r\n"
"YXdlaTAeFw0yNTA5MTMwMjM2NDBaFw0zNTA5MTEwMjM2NDBaMHExCzAJBgNVBAYT\r\n"
"AnpoMQ0wCwYDVQQIDAR4aWFuMQ0wCwYDVQQHDAR4aWFuMQ8wDQYDVQQKDAZodWF3\r\n"
"ZWkxDTALBgNVBAsMBHhpYW4xDTALBgNVBAMMBHhpYW4xFTATBgkqhkiG9w0BCQEW\r\n"
"Bmh1YXdlaTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHDl8gqIBjyXGf+jGohb\r\n"
"8LBqtvQuXBhI1+PaAvwjVlwqG4B6GPwBZ1U4kUUR/pe5GhCkfxb+SnOnOTFd5tJv\r\n"
"ieyjUzBRMB0GA1UdDgQWBBQMyWTwmXRIK151j6AODBlnXyfmsjAfBgNVHSMEGDAW\r\n"
"gBQMyWTwmXRIK151j6AODBlnXyfmsjAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49\r\n"
"BAMCA0cAMEQCIAKT+kxDqR+gaNrasFGIZclM5UFVcILmLc8kgxmOsK6pAiAu8J3Z\r\n"
"XevpzOPaF/NKfF6ZWt8kZIQtSWXa/Zl0sCm/3g==\r\n"
"-----END CERTIFICATE-----\r\n";

static char g_testRsaCertP1Pem[] =
"-----BEGIN CERTIFICATE-----\r\n"
"MIICXjCCAcegAwIBAgIGAXKnJjrAMA0GCSqGSIb3DQEBCwUAMEgxCzAJBgNVBAYT\r\n"
"AkNOMQwwCgYDVQQIDANzaGExDTALBgNVBAcMBHhpYW4xDTALBgNVBAoMBHRlc3Qx\r\n"
"DTALBgNVBAMMBHRlc3QwHhcNMjQxMTIyMDkwNTIyWhcNMzQxMTIwMDkwNTIyWjBI\r\n"
"MQswCQYDVQQGEwJDTjEMMAoGA1UECAwDc2hhMQ0wCwYDVQQHDAR4aWFuMQ0wCwYD\r\n"
"VQQKDAR0ZXN0MQ0wCwYDVQQDDAR0ZXN0MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCB\r\n"
"iQKBgQC6nCZTM16Rk2c4P/hwfVm++jqe6GCA/PXXGe4YL218q1dTKMHBGEw8kXi0\r\n"
"XLDcyyC2yUn8ywN2QSyly6ke9EE6PGfZywStLp4g2PTTWB04sS3aXT2y+fToiTXQ\r\n"
"3AxfFYRpB+EgSdSCkJs6jKXVwbzu54kEtQTfs8UdBQ9nVKaJLwIDAQABo1MwUTAd\r\n"
"BgNVHQ4EFgQU6QXnt1smb2HRSO/2zuRQnz/SDxowHwYDVR0jBBgwFoAU6QXnt1sm\r\n"
"b2HRSO/2zuRQnz/SDxowDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOB\r\n"
"gQBPR/+5xzFG1XlTdgwWVvqVxvhGUkbMTGW0IviJ+jbKsi57vnVsOtFzEA6y+bYx\r\n"
"xG/kEOcwLtzeVHOQA+ZU5SVcc+qc0dfFiWjL2PSAG4bpqSTjujpuUk+g8ugixbG1\r\n"
"a26pkDJhNeB/E3eBIbeydSY0A/dIGb6vbGo6BSq2KvnWAA==\r\n"
"-----END CERTIFICATE-----\r\n";

static char g_testRsaKeyP1Pem[] =
"-----BEGIN RSA PRIVATE KEY-----\r\n"
"Proc-Type: 4,ENCRYPTED\r\n"
"DEK-Info: DES-EDE3-CBC,DB0AC6E3BEE16420\r\n\r\n"
"1N5xykdckthZnswMV7blxXm2RCqe/OByBfMwFI7JoXR8STtMiStd4xA3W405k1Ma\r\n"
"ExpsHgWwZaS23x+sQ1sL1dsqIPMrw1Vr+KrL20vQcCVjXPpGKauafVbtcWQ1r2PZ\r\n"
"QJ4KWP6FhUp+sGt2ItODW3dK+1GdqL22ZtANrgFzS42Wh8FSn0UMCf6RG62DK62J\r\n"
"z2jtf4XaorrGSjdTeY+fyyGfSyKidIMMBe+IXwlhCgAe7aHSaqXtMsv+BibB7PJ3\r\n"
"XmEp1D/0ptL3r46txyYcuy8jSNCkW8er93KKnlRN6KbuYZPvPNncWkzZBzV17t5d\r\n"
"QgtvVh32AKgqk5jm8YVnspOFiPrbrK9UN3IW15juFkfnhriM3IrKap4/kW+tfawZ\r\n"
"DmHkSyl8xqFK413Rv0UvYBTjOcGbs2BSJYEvp8CIjtA17SvLmNw70K2nXWuQYutY\r\n"
"+HyucPtHfEqUPQRzWTAMMntTru77u7dxo2WMMMxOtMJO5h7MAnZH9bAFiuO3ewcY\r\n"
"eEePg10d8Owcfh9G6kc0HIGT9MMLMi0mTXhpoQTuWPYuSx6uUZL1fsp1x2fuM0qn\r\n"
"bdf3+UnATYUu4tgvBHrMV7405Y6Y3PnqOFxVMeAHeOTo6UThtJ10mfeCPXGcUaHo\r\n"
"P5enw7h4145cha3+S4hNrUwj3skrtavld7tY74p4DvgZSlCMF3JAm3DhpnEMVcYP\r\n"
"Y6TkSevvxOpBvEHE41Y4VBCBwd9clcixI6cSBJKPUU4A/sc/kkNdGFcbzLQCg/zR\r\n"
"1m7YmBROb2qy4w3lv/uwVnPGLg/YV465irRaN3hgz7/1lm8STKQhmQ==\r\n"
"-----END RSA PRIVATE KEY-----\r\n";

static char g_testDsaCertP1Pem[] =
"-----BEGIN CERTIFICATE-----\r\n"
"MIIFIDCCBMagAwIBAgIUQeaBW8rU+pjNWSuEL1FPg60h+pwwCwYJYIZIAWUDBAMC\r\n"
"MG0xCzAJBgNVBAYTAkFVMQ0wCwYDVQQIDARURVNUMQ0wCwYDVQQHDARYSUFOMQ0w\r\n"
"CwYDVQQKDARURVNUMQ0wCwYDVQQLDARURVNUMQ0wCwYDVQQDDARURVNUMRMwEQYJ\r\n"
"KoZIhvcNAQkBFgRURVNUMB4XDTI1MDkyMjA3Mzg1NVoXDTI2MDkyMjA3Mzg1NVow\r\n"
"bTELMAkGA1UEBhMCQVUxDTALBgNVBAgMBFRFU1QxDTALBgNVBAcMBFhJQU4xDTAL\r\n"
"BgNVBAoMBFRFU1QxDTALBgNVBAsMBFRFU1QxDTALBgNVBAMMBFRFU1QxEzARBgkq\r\n"
"hkiG9w0BCQEWBFRFU1QwggNHMIICOQYHKoZIzjgEATCCAiwCggEBAP9I0Kczsy1C\r\n"
"DWl2IrP66jPzlsnBZZfJApQRpueJ5IgoPFa5FwMZleoGnYHujyT14FaZq0vhJEtP\r\n"
"4737dg+8glno7StM5DESkflYvPNvxcQ1qgA9dAiwPFxEASDryeUz9t4BGxYPUc4x\r\n"
"hECRWC/KZsU7kfkywoRN7ofHffo9BAlMV2vcfTbTAVmyPSzlHnBl/d0xcK5q1XbQ\r\n"
"5lGdrMbLXlKEiXUTDvNqBiwbRfDhcy62RPElwSDTP18QTT8TMvutNR8dJUZotB+v\r\n"
"OTt+3hAblga+2f+pWc2yURb5bH0CE/HPOL4AuXrpuWs3ABCiFTl3KJ9SNUfGCY9t\r\n"
"CXJxcX8r/vsCIQCp4fsN0LNLjizL3LjjTzw5OJd9SnhqBEU3IWVp5IWZQQKCAQAd\r\n"
"3VzgU/T3Lnj2LwpccSD/1DS61Ozr6E9RSVfDFXN/UxvntUDepEj46zy3sfXtjUNZ\r\n"
"tSTZeCikR0IiXD6IYs22bjwbdKwyunXfRkXxdDgsAN0hW2bdOsyuXGmR/odUX6ep\r\n"
"mrycGj8wpABdquh8hGGbtJOq5cs580GLy6Gvj43/UJAuuDy3gbsmXSkDeGc9rdBm\r\n"
"g+BUH8D+UPI932DqyNBORlpsXsqbtA9AYiYyup2PBvIspkTXkm6wOApdl7gZZ6V8\r\n"
"1f7CZikSydZUT5E+Lya/06OxxdlqTN9Mb60InNCQJbWfBeRYOIElGuDFJ4lr0s9G\r\n"
"0c1Sh8mazcKks1JR6/BpA4IBBgACggEBALmr83ZAPmoPTRRuGFAob5rmUArQw6vc\r\n"
"pjEv9HhKRhxsrvpU9Z3fEZtDAYUJrq/ylxONPdF8PLul8rC6BaFK/mT+gRp0t9av\r\n"
"nqg+mUDL2X9IWLXWE+LjEoxMccS10B3Mz53HdAY7VGtbYpuEcUuQsesSXnOHMvr+\r\n"
"KgBRvTkCvM2tjkN8x3Wx9jVfeZFj2z1kYEk9FGcpYb+xoteApsltmKOsS240bUDO\r\n"
"0R8y57BPOuIseD/12YWJRYquxAI8PJZdbfMspI+k2XzffZkOb674RuF0t3mr44Us\r\n"
"YBtve9AWf5gH/xT7xDVirWK1Ig02km5jlxIMvjS/z/o7buZ2AZs1wz6jUzBRMB0G\r\n"
"A1UdDgQWBBSD2emkqWY6i0A1QjPARxAAkhRESTAfBgNVHSMEGDAWgBSD2emkqWY6\r\n"
"i0A1QjPARxAAkhRESTAPBgNVHRMBAf8EBTADAQH/MAsGCWCGSAFlAwQDAgNHADBE\r\n"
" AiB01Xwvvg1Qj3cYgdCRIPtPiRgDFAwbI3Rwv+8o22H87AIgOGgkFpaGDTrirZG5\r\n"
"lFa6g/oQZwfyPYc+H58OKp4oWcg=\r\n"
"-----END CERTIFICATE-----\r\n";

static char g_testDsaKeyP1Pem[] =
"-----BEGIN DSA PRIVATE KEY-----\r\n"
"MIIDVgIBAAKCAQEA/0jQpzOzLUINaXYis/rqM/OWycFll8kClBGm54nkiCg8VrkX\r\n"
"AxmV6gadge6PJPXgVpmrS+EkS0/jvft2D7yCWejtK0zkMRKR+Vi882/FxDWqAD10\r\n"
"CLA8XEQBIOvJ5TP23gEbFg9RzjGEQJFYL8pmxTuR+TLChE3uh8d9+j0ECUxXa9x9\r\n"
"NtMBWbI9LOUecGX93TFwrmrVdtDmUZ2sxsteUoSJdRMO82oGLBtF8OFzLrZE8SXB\r\n"
"INM/XxBNPxMy+601Hx0lRmi0H685O37eEBuWBr7Z/6lZzbJRFvlsfQIT8c84vgC5\r\n"
"eum5azcAEKIVOXcon1I1R8YJj20JcnFxfyv++wIhAKnh+w3Qs0uOLMvcuONPPDk4\r\n"
"l31KeGoERTchZWnkhZlBAoIBAB3dXOBT9PcuePYvClxxIP/UNLrU7OvoT1FJV8MV\r\n"
"c39TG+e1QN6kSPjrPLex9e2NQ1m1JNl4KKRHQiJcPohizbZuPBt0rDK6dd9GRfF0\r\n"
"OCwA3SFbZt06zK5caZH+h1Rfp6mavJwaPzCkAF2q6HyEYZu0k6rlyznzQYvLoa+P\r\n"
"jf9QkC64PLeBuyZdKQN4Zz2t0GaD4FQfwP5Q8j3fYOrI0E5GWmxeypu0D0BiJjK6\r\n"
"nY8G8iymRNeSbrA4Cl2XuBlnpXzV/sJmKRLJ1lRPkT4vJr/To7HF2WpM30xvrQic\r\n"
"0JAltZ8F5Fg4gSUa4MUniWvSz0bRzVKHyZrNwqSzUlHr8GkCggEBALmr83ZAPmoP\r\n"
"TRRuGFAob5rmUArQw6vcpjEv9HhKRhxsrvpU9Z3fEZtDAYUJrq/ylxONPdF8PLul\r\n"
"8rC6BaFK/mT+gRp0t9avnqg+mUDL2X9IWLXWE+LjEoxMccS10B3Mz53HdAY7VGtb\r\n"
"YpuEcUuQsesSXnOHMvr+KgBRvTkCvM2tjkN8x3Wx9jVfeZFj2z1kYEk9FGcpYb+x\r\n"
"oteApsltmKOsS240bUDO0R8y57BPOuIseD/12YWJRYquxAI8PJZdbfMspI+k2Xzf\r\n"
"fZkOb674RuF0t3mr44UsYBtve9AWf5gH/xT7xDVirWK1Ig02km5jlxIMvjS/z/o7\r\n"
"buZ2AZs1wz4CIG9wUSfBVNYErIymDGNRiDTraBqb1qZoY9LEPObzrT7Y\r\n"
"-----END DSA PRIVATE KEY-----\r\n";

const CfEncodingBlob g_inCertEccP1PemStream = {
    .data = reinterpret_cast<uint8_t *>(g_testEccCertP1Pem),
    .len = strlen(g_testEccCertP1Pem) + 1,
    .encodingFormat = CF_FORMAT_PEM
};

const CfEncodingBlob g_inKeyEccP1PemStream = {
    .data = reinterpret_cast<uint8_t *>(g_testEccKeyP1Pem),
    .len = strlen(g_testEccKeyP1Pem) + 1,
    .encodingFormat = CF_FORMAT_PEM
};

const CfEncodingBlob g_inCertEccP8PemStream = {
    .data = reinterpret_cast<uint8_t *>(g_testEccCertP8Pem),
    .len = strlen(g_testEccCertP8Pem) + 1,
    .encodingFormat = CF_FORMAT_PEM
};

const CfEncodingBlob g_inKeyEccP8PemStream = {
    .data = reinterpret_cast<uint8_t *>(g_testEccKeyP8Pem),
    .len = strlen(g_testEccKeyP8Pem) + 1,
    .encodingFormat = CF_FORMAT_PEM
};

const CfEncodingBlob g_inCertRsaP1PemStream = {
    .data = reinterpret_cast<uint8_t *>(g_testRsaCertP1Pem),
    .len = strlen(g_testRsaCertP1Pem) + 1,
    .encodingFormat = CF_FORMAT_PEM
};

const CfEncodingBlob g_inKeyRsaP1PemStream = {
    .data = reinterpret_cast<uint8_t *>(g_testRsaKeyP1Pem),
    .len = strlen(g_testRsaKeyP1Pem) + 1,
    .encodingFormat = CF_FORMAT_PEM
};

const CfEncodingBlob g_inCertDsaP1PemStream = {
    .data = reinterpret_cast<uint8_t *>(g_testDsaCertP1Pem),
    .len = strlen(g_testDsaCertP1Pem) + 1,
    .encodingFormat = CF_FORMAT_PEM
};

const CfEncodingBlob g_inKeyDsaP1PemStream = {
    .data = reinterpret_cast<uint8_t *>(g_testDsaKeyP1Pem),
    .len = strlen(g_testDsaKeyP1Pem) + 1,
    .encodingFormat = CF_FORMAT_PEM
};

static const uint8_t g_inContent[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
static const char g_testPwd[] = "123456";
static const char g_digestSHA1[] = "SHA1";
static const char g_digestSHA256[] = "SHA256";
static const char g_digestSHA384[] = "SHA384";
static const char g_digestSHA512[] = "SHA512";

void CryptoX509CertCmsGeneratorTestPart2::SetUpTestCase()
{
}
void CryptoX509CertCmsGeneratorTestPart2::TearDownTestCase()
{
}

void CryptoX509CertCmsGeneratorTestPart2::SetUp()
{
}

void CryptoX509CertCmsGeneratorTestPart2::TearDown()
{
}

HWTEST_F(CryptoX509CertCmsGeneratorTestPart2, CreateCmsGenerator001, TestSize.Level0)
{
    HcfCmsGenerator *cmsGenerator = nullptr;
    CfResult res = HcfCreateCmsGenerator(ENVELOPED_DATA, &cmsGenerator);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsGenerator, nullptr);
    CfObjDestroy(cmsGenerator);
}

HWTEST_F(CryptoX509CertCmsGeneratorTestPart2, CreateCmsGenerator002, TestSize.Level0)
{
    HcfCmsGenerator *cmsGenerator = nullptr;
    CfResult res = HcfCreateCmsGenerator(static_cast<HcfCmsContentType>(-1), &cmsGenerator);
    EXPECT_EQ(res, CF_INVALID_PARAMS);
    EXPECT_EQ(cmsGenerator, nullptr);

    res = HcfCreateCmsGenerator(static_cast<HcfCmsContentType>(2), &cmsGenerator);
    EXPECT_EQ(res, CF_INVALID_PARAMS);
    EXPECT_EQ(cmsGenerator, nullptr);
}

HWTEST_F(CryptoX509CertCmsGeneratorTestPart2, AddSigner001, TestSize.Level0)
{
    HcfCmsGenerator *cmsGenerator = nullptr;
    PrivateKeyInfo *privateKey = nullptr;
    HcfCmsSignerOptions *options = nullptr;
    HcfX509Certificate *x509Cert = nullptr;

    CfResult res = HcfCreateCmsGenerator(SIGNED_DATA, &cmsGenerator);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsGenerator, nullptr);

    res = HcfX509CertificateCreate(&g_inCertRsaP1PemStream, &x509Cert);
    EXPECT_EQ(res, CF_SUCCESS);
    ASSERT_NE(x509Cert, nullptr);

    privateKey = (PrivateKeyInfo *)CfMalloc(sizeof(PrivateKeyInfo), 0);
    privateKey->privateKey = const_cast<CfEncodingBlob*>(&g_inKeyRsaP1PemStream);
    privateKey->privateKeyPassword = const_cast<char*>(g_testPwd);

    options = (HcfCmsSignerOptions *)CfMalloc(sizeof(HcfCmsSignerOptions), 0);
    options->mdName = const_cast<char*>(g_digestSHA1);
    options->padding = PKCS1_PSS_PADDING;
    res = cmsGenerator->addSigner(cmsGenerator, &(x509Cert->base), privateKey, options);
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);

    options->mdName = const_cast<char*>(g_digestSHA256);
    options->padding = PKCS1_PSS_PADDING;
    options->addCert = true;
    options->addAttr = true;
    options->addSmimeCapAttr = true;
    res = cmsGenerator->addSigner(cmsGenerator, &(x509Cert->base), privateKey, options);
    EXPECT_EQ(res, CF_SUCCESS);

    options->mdName = const_cast<char*>(g_digestSHA384);
    options->padding = PKCS1_PSS_PADDING;
    options->addCert = false;
    options->addAttr = false;
    options->addSmimeCapAttr = false;
    res = cmsGenerator->addSigner(cmsGenerator, &(x509Cert->base), privateKey, options);
    EXPECT_EQ(res, CF_SUCCESS);

    options->mdName = const_cast<char*>(g_digestSHA512);
    options->padding = PKCS1_PSS_PADDING;
    options->addCert = false;
    options->addAttr = false;
    options->addSmimeCapAttr = true;
    res = cmsGenerator->addSigner(cmsGenerator, &(x509Cert->base), privateKey, options);
    EXPECT_EQ(res, CF_SUCCESS);

    CfFree(privateKey);
    CfFree(options);
    CfObjDestroy(x509Cert);
    CfObjDestroy(cmsGenerator);
}

HWTEST_F(CryptoX509CertCmsGeneratorTestPart2, AddSigner002, TestSize.Level0)
{
    HcfCmsGenerator *cmsGenerator = nullptr;
    PrivateKeyInfo *privateKey = nullptr;
    HcfCmsSignerOptions *options = nullptr;
    HcfX509Certificate *x509Cert = nullptr;

    CfResult res = HcfCreateCmsGenerator(SIGNED_DATA, &cmsGenerator);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsGenerator, nullptr);

    res = HcfX509CertificateCreate(&g_inCertRsaP1PemStream, &x509Cert);
    EXPECT_EQ(res, CF_SUCCESS);
    ASSERT_NE(x509Cert, nullptr);

    privateKey = (PrivateKeyInfo *)CfMalloc(sizeof(PrivateKeyInfo), 0);
    privateKey->privateKey = const_cast<CfEncodingBlob*>(&g_inKeyRsaP1PemStream);
    privateKey->privateKeyPassword = const_cast<char*>(g_testPwd);

    options = (HcfCmsSignerOptions *)CfMalloc(sizeof(HcfCmsSignerOptions), 0);
    options->mdName = const_cast<char*>(g_digestSHA1);
    options->padding = PKCS1_PADDING;
    res = cmsGenerator->addSigner(cmsGenerator, &(x509Cert->base), privateKey, options);
    EXPECT_EQ(res, CF_SUCCESS);

    options->mdName = const_cast<char*>(g_digestSHA256);
    options->padding = PKCS1_PADDING;
    options->addCert = false;
    options->addAttr = true;
    options->addSmimeCapAttr = true;
    res = cmsGenerator->addSigner(cmsGenerator, &(x509Cert->base), privateKey, options);
    EXPECT_EQ(res, CF_SUCCESS);

    options->mdName = const_cast<char*>(g_digestSHA384);
    options->padding = PKCS1_PADDING;
    options->addCert = false;
    options->addAttr = true;
    options->addSmimeCapAttr = false;
    res = cmsGenerator->addSigner(cmsGenerator, &(x509Cert->base), privateKey, options);
    EXPECT_EQ(res, CF_SUCCESS);

    options->mdName = const_cast<char*>(g_digestSHA512);
    options->padding = PKCS1_PADDING;
    options->addCert = true;
    options->addAttr = false;
    options->addSmimeCapAttr = true;
    res = cmsGenerator->addSigner(cmsGenerator, &(x509Cert->base), privateKey, options);
    EXPECT_EQ(res, CF_SUCCESS);

    CfFree(privateKey);
    CfFree(options);
    CfObjDestroy(x509Cert);
    CfObjDestroy(cmsGenerator);
}

HWTEST_F(CryptoX509CertCmsGeneratorTestPart2, AddSigner003, TestSize.Level0)
{
    HcfCmsGenerator *cmsGenerator = nullptr;
    PrivateKeyInfo *privateKey = nullptr;
    HcfCmsSignerOptions *options = nullptr;
    HcfX509Certificate *x509Cert = nullptr;

    CfResult res = HcfCreateCmsGenerator(SIGNED_DATA, &cmsGenerator);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsGenerator, nullptr);

    res = HcfX509CertificateCreate(&g_inCertEccP1PemStream, &x509Cert);
    EXPECT_EQ(res, CF_SUCCESS);
    ASSERT_NE(x509Cert, nullptr);

    privateKey = (PrivateKeyInfo *)CfMalloc(sizeof(PrivateKeyInfo), 0);
    privateKey->privateKey = const_cast<CfEncodingBlob*>(&g_inKeyEccP1PemStream);
    privateKey->privateKeyPassword = const_cast<char*>(g_testPwd);

    options = (HcfCmsSignerOptions *)CfMalloc(sizeof(HcfCmsSignerOptions), 0);
    options->mdName = const_cast<char*>(g_digestSHA1);
    res = cmsGenerator->addSigner(cmsGenerator, &(x509Cert->base), privateKey, options);
    EXPECT_EQ(res, CF_SUCCESS);

    options->mdName = const_cast<char*>(g_digestSHA256);
    options->addCert = false;
    options->addAttr = true;
    options->addSmimeCapAttr = true;
    res = cmsGenerator->addSigner(cmsGenerator, &(x509Cert->base), privateKey, options);
    EXPECT_EQ(res, CF_SUCCESS);

    options->mdName = const_cast<char*>(g_digestSHA384);
    options->addCert = false;
    options->addAttr = true;
    options->addSmimeCapAttr = false;
    res = cmsGenerator->addSigner(cmsGenerator, &(x509Cert->base), privateKey, options);
    EXPECT_EQ(res, CF_SUCCESS);

    options->mdName = const_cast<char*>(g_digestSHA512);
    options->addCert = true;
    options->addAttr = false;
    options->addSmimeCapAttr = true;
    res = cmsGenerator->addSigner(cmsGenerator, &(x509Cert->base), privateKey, options);
    EXPECT_EQ(res, CF_SUCCESS);

    CfFree(privateKey);
    CfFree(options);
    CfObjDestroy(x509Cert);
    CfObjDestroy(cmsGenerator);
}

HWTEST_F(CryptoX509CertCmsGeneratorTestPart2, AddSigner004, TestSize.Level0)
{
    HcfCmsGenerator *cmsGenerator = nullptr;
    PrivateKeyInfo *privateKey = nullptr;
    HcfCmsSignerOptions *options = nullptr;
    HcfX509Certificate *x509Cert = nullptr;

    CfResult res = HcfCreateCmsGenerator(SIGNED_DATA, &cmsGenerator);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsGenerator, nullptr);

    res = HcfX509CertificateCreate(&g_inCertEccP8PemStream, &x509Cert);
    EXPECT_EQ(res, CF_SUCCESS);
    ASSERT_NE(x509Cert, nullptr);

    privateKey = (PrivateKeyInfo *)CfMalloc(sizeof(PrivateKeyInfo), 0);
    privateKey->privateKey = const_cast<CfEncodingBlob*>(&g_inKeyEccP8PemStream);
    privateKey->privateKeyPassword = const_cast<char*>(g_testPwd);

    options = (HcfCmsSignerOptions *)CfMalloc(sizeof(HcfCmsSignerOptions), 0);
    options->mdName = const_cast<char*>(g_digestSHA1);
    res = cmsGenerator->addSigner(cmsGenerator, &(x509Cert->base), privateKey, options);
    EXPECT_EQ(res, CF_SUCCESS);

    options->mdName = const_cast<char*>(g_digestSHA256);
    options->addCert = false;
    options->addAttr = false;
    options->addSmimeCapAttr = false;
    res = cmsGenerator->addSigner(cmsGenerator, &(x509Cert->base), privateKey, options);
    EXPECT_EQ(res, CF_SUCCESS);

    options->mdName = const_cast<char*>(g_digestSHA384);
    options->addCert = true;
    options->addAttr = false;
    options->addSmimeCapAttr = true;
    res = cmsGenerator->addSigner(cmsGenerator, &(x509Cert->base), privateKey, options);
    EXPECT_EQ(res, CF_SUCCESS);

    options->mdName = const_cast<char*>(g_digestSHA512);
    options->addCert = false;
    options->addAttr = true;
    options->addSmimeCapAttr = false;
    res = cmsGenerator->addSigner(cmsGenerator, &(x509Cert->base), privateKey, options);
    EXPECT_EQ(res, CF_SUCCESS);

    CfFree(privateKey);
    CfFree(options);
    CfObjDestroy(x509Cert);
    CfObjDestroy(cmsGenerator);
}

HWTEST_F(CryptoX509CertCmsGeneratorTestPart2, AddSigner005, TestSize.Level0)
{
    HcfCmsGenerator *cmsGenerator = nullptr;
    PrivateKeyInfo *privateKey = nullptr;
    HcfCmsSignerOptions *options = nullptr;
    HcfX509Certificate *x509Cert = nullptr;

    CfResult res = HcfCreateCmsGenerator(SIGNED_DATA, &cmsGenerator);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsGenerator, nullptr);

    res = HcfX509CertificateCreate(&g_inCertEccP8PemStream, &x509Cert);
    EXPECT_EQ(res, CF_SUCCESS);
    ASSERT_NE(x509Cert, nullptr);

    privateKey = (PrivateKeyInfo *)CfMalloc(sizeof(PrivateKeyInfo), 0);
    privateKey->privateKey = const_cast<CfEncodingBlob*>(&g_inKeyEccP8PemStream);
    privateKey->privateKeyPassword = const_cast<char*>(g_testPwd);
    options = (HcfCmsSignerOptions *)CfMalloc(sizeof(HcfCmsSignerOptions), 0);
    options->mdName = const_cast<char*>(g_digestSHA256);
    options->addCert = true;
    options->padding = PKCS1_PSS_PADDING;
    options->addAttr = false;
    options->addSmimeCapAttr = false;
    res = cmsGenerator->addSigner(cmsGenerator, &(x509Cert->base), privateKey, options);
    EXPECT_EQ(res, CF_SUCCESS);
    options->mdName = const_cast<char*>(g_digestSHA384);
    options->padding = PKCS1_PADDING;
    options->addCert = false;
    options->addAttr = false;
    options->addSmimeCapAttr = true;
    res = cmsGenerator->addSigner(cmsGenerator, &(x509Cert->base), privateKey, options);
    EXPECT_EQ(res, CF_SUCCESS);
    options->mdName = const_cast<char*>(g_digestSHA512);
    options->padding = static_cast<CfCmsRsaSignaturePadding>(2);
    options->addCert = false;
    options->addAttr = true;
    options->addSmimeCapAttr = false;
    res = cmsGenerator->addSigner(cmsGenerator, &(x509Cert->base), privateKey, options);
    EXPECT_EQ(res, CF_SUCCESS);
    CfFree(privateKey);
    CfFree(options);
    CfObjDestroy(x509Cert);
    CfObjDestroy(cmsGenerator);
}

HWTEST_F(CryptoX509CertCmsGeneratorTestPart2, DoFinal001, TestSize.Level0)
{
    HcfCmsGenerator *cmsGenerator = nullptr;
    HcfX509Certificate *x509Cert = nullptr;
    CfBlob out = {0, nullptr};
    CfBlob content;
    content.data = const_cast<uint8_t*>(g_inContent);
    content.size = sizeof(g_inContent);
    HcfCmsGeneratorOptions *cmsOptions = nullptr;

    CfResult res = HcfCreateCmsGenerator(SIGNED_DATA, &cmsGenerator);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsGenerator, nullptr);

    CfResult ret = HcfX509CertificateCreate(&g_inCertRsaP1PemStream, &x509Cert);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(x509Cert, nullptr);

    res = cmsGenerator->addCert(cmsGenerator, &(x509Cert->base));
    EXPECT_EQ(res, CF_SUCCESS);

    cmsOptions = (HcfCmsGeneratorOptions *)CfMalloc(sizeof(HcfCmsGeneratorOptions), 0);
    cmsOptions->dataFormat = BINARY;
    cmsOptions->outFormat = CMS_DER;
    cmsOptions->isDetachedContent = false;
    res = cmsGenerator->doFinal(cmsGenerator, &content, cmsOptions, &out);
    EXPECT_EQ(res, CF_SUCCESS);

    CfFree(cmsOptions);
    CfObjDestroy(x509Cert);
    CfBlobDataClearAndFree(&out);
    CfObjDestroy(cmsGenerator);
}

HWTEST_F(CryptoX509CertCmsGeneratorTestPart2, DoFinal002, TestSize.Level0)
{
    HcfCmsGenerator *cmsGenerator = nullptr;
    HcfX509Certificate *x509Cert = nullptr;
    CfBlob out = {0, nullptr};
    CfBlob content;
    content.data = const_cast<uint8_t*>(g_inContent);
    content.size = sizeof(g_inContent);
    HcfCmsGeneratorOptions *cmsOptions = nullptr;

    CfResult res = HcfCreateCmsGenerator(SIGNED_DATA, &cmsGenerator);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsGenerator, nullptr);

    CfResult ret = HcfX509CertificateCreate(&g_inCertEccP1PemStream, &x509Cert);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(x509Cert, nullptr);

    res = cmsGenerator->addCert(cmsGenerator, &(x509Cert->base));
    EXPECT_EQ(res, CF_SUCCESS);

    cmsOptions = (HcfCmsGeneratorOptions *)CfMalloc(sizeof(HcfCmsGeneratorOptions), 0);
    cmsOptions->dataFormat = BINARY;
    cmsOptions->outFormat = CMS_DER;
    cmsOptions->isDetachedContent = false;
    res = cmsGenerator->doFinal(cmsGenerator, &content, cmsOptions, &out);
    EXPECT_EQ(res, CF_SUCCESS);

    CfFree(cmsOptions);
    CfObjDestroy(x509Cert);
    CfBlobDataClearAndFree(&out);
    CfObjDestroy(cmsGenerator);
}

static void FreeTestRecipientInfo(CmsRecipientInfo *recipientInfo)
{
    if (recipientInfo == nullptr) {
        return;
    }
    if (recipientInfo->keyTransInfo != nullptr) {
        CfFree(recipientInfo->keyTransInfo);
    }
    if (recipientInfo->keyAgreeInfo != nullptr) {
        CfFree(recipientInfo->keyAgreeInfo);
    }
    CfFree(recipientInfo);
}

HWTEST_F(CryptoX509CertCmsGeneratorTestPart2, addRecipientInfo001, TestSize.Level0)
{
    HcfCmsGenerator *cmsGenerator = nullptr;
    HcfX509Certificate *x509Cert = nullptr;
    CfBlob out = {0, nullptr};
    CfBlob content;
    content.data = const_cast<uint8_t*>(g_inContent);
    content.size = sizeof(g_inContent);
    HcfCmsGeneratorOptions *cmsOptions = nullptr;

    CfResult res = HcfCreateCmsGenerator(ENVELOPED_DATA, &cmsGenerator);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsGenerator, nullptr);

    CfResult ret = HcfX509CertificateCreate(&g_inCertEccP1PemStream, &x509Cert);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(x509Cert, nullptr);

    CmsRecipientInfo *recipientInfo = nullptr;
    recipientInfo = (CmsRecipientInfo *)CfMalloc(sizeof(CmsRecipientInfo), 0);
    EXPECT_NE(recipientInfo, nullptr);

    recipientInfo->keyAgreeInfo = nullptr;
    recipientInfo->keyAgreeInfo = (KeyAgreeRecipientInfo *)CfMalloc(sizeof(KeyAgreeRecipientInfo), 0);
    EXPECT_NE(recipientInfo->keyAgreeInfo, nullptr);
    recipientInfo->keyAgreeInfo->recipientCert = &(x509Cert->base);
    recipientInfo->keyAgreeInfo->digestAlgorithm = CMS_SHA256;
    res = cmsGenerator->addRecipientInfo(cmsGenerator, recipientInfo);
    EXPECT_EQ(res, CF_SUCCESS);

    recipientInfo->keyAgreeInfo->digestAlgorithm = CMS_SHA384;
    res = cmsGenerator->addRecipientInfo(cmsGenerator, recipientInfo);
    EXPECT_EQ(res, CF_SUCCESS);

    recipientInfo->keyAgreeInfo->digestAlgorithm = CMS_SHA512;
    res = cmsGenerator->addRecipientInfo(cmsGenerator, recipientInfo);
    EXPECT_EQ(res, CF_SUCCESS);

    recipientInfo->keyAgreeInfo->digestAlgorithm = static_cast<CfCmsKeyAgreeRecipientDigestAlgorithm>(3);
    res = cmsGenerator->addRecipientInfo(cmsGenerator, recipientInfo);
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);

    cmsOptions = (HcfCmsGeneratorOptions *)CfMalloc(sizeof(HcfCmsGeneratorOptions), 0);
    cmsOptions->dataFormat = BINARY;
    cmsOptions->outFormat = CMS_DER;
    cmsOptions->isDetachedContent = false;
    res = cmsGenerator->doFinal(cmsGenerator, &content, cmsOptions, &out);
    EXPECT_EQ(res, CF_SUCCESS);

    FreeTestRecipientInfo(recipientInfo);
    CfFree(cmsOptions);
    CfObjDestroy(x509Cert);
    CfBlobDataClearAndFree(&out);
    CfObjDestroy(cmsGenerator);
}

HWTEST_F(CryptoX509CertCmsGeneratorTestPart2, addRecipientInfo002, TestSize.Level0)
{
    HcfCmsGenerator *cmsGenerator = nullptr;
    HcfX509Certificate *x509Cert = nullptr;
    CfBlob out = {0, nullptr};
    CfBlob content;
    content.data = const_cast<uint8_t*>(g_inContent);
    content.size = sizeof(g_inContent);
    HcfCmsGeneratorOptions *cmsOptions = nullptr;

    CfResult res = HcfCreateCmsGenerator(ENVELOPED_DATA, &cmsGenerator);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsGenerator, nullptr);

    CfResult ret = HcfX509CertificateCreate(&g_inCertRsaP1PemStream, &x509Cert);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(x509Cert, nullptr);

    CmsRecipientInfo *recipientInfo = nullptr;
    recipientInfo = (CmsRecipientInfo *)CfMalloc(sizeof(CmsRecipientInfo), 0);
    EXPECT_NE(recipientInfo, nullptr);

    recipientInfo->keyTransInfo = nullptr;
    recipientInfo->keyTransInfo = (KeyTransRecipientInfo *)CfMalloc(sizeof(KeyTransRecipientInfo), 0);
    EXPECT_NE(recipientInfo->keyTransInfo, nullptr);
    recipientInfo->keyTransInfo->recipientCert = &(x509Cert->base);

    res = cmsGenerator->addRecipientInfo(cmsGenerator, recipientInfo);
    EXPECT_EQ(res, CF_SUCCESS);

    cmsOptions = (HcfCmsGeneratorOptions *)CfMalloc(sizeof(HcfCmsGeneratorOptions), 0);
    cmsOptions->dataFormat = BINARY;
    cmsOptions->outFormat = CMS_DER;
    cmsOptions->isDetachedContent = false;
    res = cmsGenerator->doFinal(cmsGenerator, &content, cmsOptions, &out);
    EXPECT_EQ(res, CF_SUCCESS);

    FreeTestRecipientInfo(recipientInfo);
    CfFree(cmsOptions);
    CfObjDestroy(x509Cert);
    CfBlobDataClearAndFree(&out);
    CfObjDestroy(cmsGenerator);
}

HWTEST_F(CryptoX509CertCmsGeneratorTestPart2, addRecipientInfo003, TestSize.Level0)
{
    HcfCmsGenerator *cmsGenerator = nullptr;
    HcfX509Certificate *x509CertRsa = nullptr;
    HcfX509Certificate *x509CertEcc = nullptr;
    CfBlob out = {0, nullptr};
    CfBlob content;
    content.data = const_cast<uint8_t*>(g_inContent);
    content.size = sizeof(g_inContent);
    HcfCmsGeneratorOptions *cmsOptions = nullptr;

    CfResult res = HcfCreateCmsGenerator(ENVELOPED_DATA, &cmsGenerator);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsGenerator, nullptr);

    CfResult ret = HcfX509CertificateCreate(&g_inCertRsaP1PemStream, &x509CertRsa);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(x509CertRsa, nullptr);

    CfResult ret2 = HcfX509CertificateCreate(&g_inCertEccP1PemStream, &x509CertEcc);
    EXPECT_EQ(ret2, CF_SUCCESS);
    ASSERT_NE(x509CertEcc, nullptr);

    CmsRecipientInfo *recipientInfo = nullptr;
    recipientInfo = (CmsRecipientInfo *)CfMalloc(sizeof(CmsRecipientInfo), 0);
    EXPECT_NE(recipientInfo, nullptr);

    recipientInfo->keyTransInfo = nullptr;
    recipientInfo->keyTransInfo = (KeyTransRecipientInfo *)CfMalloc(sizeof(KeyTransRecipientInfo), 0);
    EXPECT_NE(recipientInfo->keyTransInfo, nullptr);
    recipientInfo->keyTransInfo->recipientCert = &(x509CertRsa->base);

    recipientInfo->keyAgreeInfo = nullptr;
    recipientInfo->keyAgreeInfo = (KeyAgreeRecipientInfo *)CfMalloc(sizeof(KeyAgreeRecipientInfo), 0);
    EXPECT_NE(recipientInfo->keyAgreeInfo, nullptr);
    recipientInfo->keyAgreeInfo->recipientCert = &(x509CertEcc->base);
    recipientInfo->keyAgreeInfo->digestAlgorithm = CMS_SHA256;

    res = cmsGenerator->addRecipientInfo(cmsGenerator, recipientInfo);
    EXPECT_EQ(res, CF_SUCCESS);

    cmsOptions = (HcfCmsGeneratorOptions *)CfMalloc(sizeof(HcfCmsGeneratorOptions), 0);
    cmsOptions->dataFormat = BINARY;
    cmsOptions->outFormat = CMS_DER;
    cmsOptions->isDetachedContent = false;
    res = cmsGenerator->doFinal(cmsGenerator, &content, cmsOptions, &out);
    EXPECT_EQ(res, CF_SUCCESS);

    FreeTestRecipientInfo(recipientInfo);
    CfFree(cmsOptions);
    CfObjDestroy(x509CertRsa);
    CfObjDestroy(x509CertEcc);
    CfBlobDataClearAndFree(&out);
    CfObjDestroy(cmsGenerator);
}

HWTEST_F(CryptoX509CertCmsGeneratorTestPart2, addRecipientInfo004, TestSize.Level0)
{
    HcfCmsGenerator *cmsGenerator = nullptr;
    CfBlob out = {0, nullptr};
    CfBlob content;
    content.data = const_cast<uint8_t*>(g_inContent);
    content.size = sizeof(g_inContent);
    HcfCmsGeneratorOptions *cmsOptions = nullptr;

    CfResult res = HcfCreateCmsGenerator(ENVELOPED_DATA, &cmsGenerator);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsGenerator, nullptr);

    CmsRecipientInfo *recipientInfo = nullptr;
    recipientInfo = (CmsRecipientInfo *)CfMalloc(sizeof(CmsRecipientInfo), 0);
    EXPECT_NE(recipientInfo, nullptr);

    recipientInfo->keyTransInfo = nullptr;
    recipientInfo->keyAgreeInfo = nullptr;
    
    res = cmsGenerator->addRecipientInfo(cmsGenerator, recipientInfo);
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);

    cmsOptions = (HcfCmsGeneratorOptions *)CfMalloc(sizeof(HcfCmsGeneratorOptions), 0);
    cmsOptions->dataFormat = BINARY;
    cmsOptions->outFormat = CMS_DER;
    cmsOptions->isDetachedContent = false;
    res = cmsGenerator->doFinal(cmsGenerator, &content, cmsOptions, &out);
    EXPECT_EQ(res, CF_SUCCESS);

    FreeTestRecipientInfo(recipientInfo);
    CfFree(cmsOptions);
    CfBlobDataClearAndFree(&out);
    CfObjDestroy(cmsGenerator);
}

HWTEST_F(CryptoX509CertCmsGeneratorTestPart2, addRecipientInfo005, TestSize.Level0)
{
    HcfCmsGenerator *cmsGenerator = nullptr;
    HcfX509Certificate *x509CertRsa = nullptr;
    HcfX509Certificate *x509CertEcc = nullptr;
    CfBlob out = {0, nullptr};
    CfBlob content;
    content.data = const_cast<uint8_t*>(g_inContent);
    content.size = sizeof(g_inContent);
    HcfCmsGeneratorOptions *cmsOptions = nullptr;

    CfResult res = HcfCreateCmsGenerator(ENVELOPED_DATA, &cmsGenerator);
    EXPECT_EQ(res, CF_SUCCESS);

    CfResult ret = HcfX509CertificateCreate(&g_inCertRsaP1PemStream, &x509CertRsa);
    EXPECT_EQ(ret, CF_SUCCESS);

    CfResult ret2 = HcfX509CertificateCreate(&g_inCertEccP1PemStream, &x509CertEcc);
    EXPECT_EQ(ret2, CF_SUCCESS);

    CmsRecipientInfo *recipientInfo = nullptr;
    recipientInfo = (CmsRecipientInfo *)CfMalloc(sizeof(CmsRecipientInfo), 0);
    EXPECT_NE(recipientInfo, nullptr);

    recipientInfo->keyTransInfo = nullptr;
    recipientInfo->keyTransInfo = (KeyTransRecipientInfo *)CfMalloc(sizeof(KeyTransRecipientInfo), 0);
    EXPECT_NE(recipientInfo->keyTransInfo, nullptr);
    recipientInfo->keyTransInfo->recipientCert = &(x509CertRsa->base);

    recipientInfo->keyAgreeInfo = nullptr;
    recipientInfo->keyAgreeInfo = (KeyAgreeRecipientInfo *)CfMalloc(sizeof(KeyAgreeRecipientInfo), 0);
    EXPECT_NE(recipientInfo->keyAgreeInfo, nullptr);
    recipientInfo->keyAgreeInfo->recipientCert = &(x509CertEcc->base);
    recipientInfo->keyAgreeInfo->digestAlgorithm = CMS_SHA256;

    for (int i = 0; i < 11; i++) {
        res = cmsGenerator->addRecipientInfo(cmsGenerator, recipientInfo);
        if (i < 10) {
            EXPECT_EQ(res, CF_SUCCESS);
        } else {
            EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);
        }
    }

    cmsOptions = (HcfCmsGeneratorOptions *)CfMalloc(sizeof(HcfCmsGeneratorOptions), 0);
    cmsOptions->dataFormat = BINARY;
    cmsOptions->outFormat = CMS_DER;
    cmsOptions->isDetachedContent = false;
    res = cmsGenerator->doFinal(cmsGenerator, &content, cmsOptions, &out);
    EXPECT_EQ(res, CF_SUCCESS);

    FreeTestRecipientInfo(recipientInfo);
    CfFree(cmsOptions);
    CfObjDestroy(x509CertRsa);
    CfObjDestroy(x509CertEcc);
    CfBlobDataClearAndFree(&out);
    CfObjDestroy(cmsGenerator);
}
 
HWTEST_F(CryptoX509CertCmsGeneratorTestPart2, addRecipientInfo006, TestSize.Level0)
{
    HcfCmsGenerator *cmsGenerator = nullptr;
    HcfX509Certificate *x509Cert = nullptr;
    CfBlob out = {0, nullptr};

    CfResult res = HcfCreateCmsGenerator(ENVELOPED_DATA, &cmsGenerator);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsGenerator, nullptr);

    CfResult ret = HcfX509CertificateCreate(&g_inCertEccP1PemStream, &x509Cert);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(x509Cert, nullptr);

    CmsRecipientInfo *recipientInfo = nullptr;
    recipientInfo = (CmsRecipientInfo *)CfMalloc(sizeof(CmsRecipientInfo), 0);
    EXPECT_NE(recipientInfo, nullptr);

    recipientInfo->keyTransInfo = nullptr;
    recipientInfo->keyTransInfo = (KeyTransRecipientInfo *)CfMalloc(sizeof(KeyTransRecipientInfo), 0);
    EXPECT_NE(recipientInfo->keyTransInfo, nullptr);
    recipientInfo->keyTransInfo->recipientCert = &(x509Cert->base);

    res = cmsGenerator->addRecipientInfo(cmsGenerator, recipientInfo);
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);

    FreeTestRecipientInfo(recipientInfo);
    CfObjDestroy(x509Cert);
    CfBlobDataClearAndFree(&out);
    CfObjDestroy(cmsGenerator);
}

HWTEST_F(CryptoX509CertCmsGeneratorTestPart2, addRecipientInfo007, TestSize.Level0)
{
    HcfCmsGenerator *cmsGenerator = nullptr;
    HcfX509Certificate *x509CertRsa = nullptr;
    CfBlob out = {0, nullptr};

    CfResult res = HcfCreateCmsGenerator(ENVELOPED_DATA, &cmsGenerator);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsGenerator, nullptr);

    CfResult ret = HcfX509CertificateCreate(&g_inCertRsaP1PemStream, &x509CertRsa);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(x509CertRsa, nullptr);

    CmsRecipientInfo *recipientInfo = nullptr;
    recipientInfo = (CmsRecipientInfo *)CfMalloc(sizeof(CmsRecipientInfo), 0);
    EXPECT_NE(recipientInfo, nullptr);

    recipientInfo->keyAgreeInfo = nullptr;
    recipientInfo->keyAgreeInfo = (KeyAgreeRecipientInfo *)CfMalloc(sizeof(KeyAgreeRecipientInfo), 0);
    EXPECT_NE(recipientInfo->keyAgreeInfo, nullptr);
    recipientInfo->keyAgreeInfo->recipientCert = &(x509CertRsa->base);
    recipientInfo->keyAgreeInfo->digestAlgorithm = CMS_SHA256;

    res = cmsGenerator->addRecipientInfo(cmsGenerator, recipientInfo);
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);

    FreeTestRecipientInfo(recipientInfo);
    CfObjDestroy(x509CertRsa);
    CfBlobDataClearAndFree(&out);
    CfObjDestroy(cmsGenerator);
}

HWTEST_F(CryptoX509CertCmsGeneratorTestPart2, setRecipientEncryptionAlgorithm001, TestSize.Level0)
{
    HcfCmsGenerator *cmsGenerator = nullptr;

    CfResult res = HcfCreateCmsGenerator(ENVELOPED_DATA, &cmsGenerator);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsGenerator, nullptr);

    res = cmsGenerator->setRecipientEncryptionAlgorithm(cmsGenerator, CMS_AES_128_CBC);
    EXPECT_EQ(res, CF_SUCCESS);

    res = cmsGenerator->setRecipientEncryptionAlgorithm(cmsGenerator, CMS_AES_192_CBC);
    EXPECT_EQ(res, CF_SUCCESS);

    res = cmsGenerator->setRecipientEncryptionAlgorithm(cmsGenerator, CMS_AES_256_CBC);
    EXPECT_EQ(res, CF_SUCCESS);

    res = cmsGenerator->setRecipientEncryptionAlgorithm(cmsGenerator, CMS_AES_128_GCM);
    EXPECT_EQ(res, CF_SUCCESS);

    res = cmsGenerator->setRecipientEncryptionAlgorithm(cmsGenerator, CMS_AES_192_GCM);
    EXPECT_EQ(res, CF_SUCCESS);

    res = cmsGenerator->setRecipientEncryptionAlgorithm(cmsGenerator, CMS_AES_256_GCM);
    EXPECT_EQ(res, CF_SUCCESS);

    res = cmsGenerator->setRecipientEncryptionAlgorithm(cmsGenerator,
        static_cast<CfCmsRecipientEncryptionAlgorithm>(-1));
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);

    res = cmsGenerator->setRecipientEncryptionAlgorithm(cmsGenerator,
        static_cast<CfCmsRecipientEncryptionAlgorithm>(6));
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);

    res = HcfCreateCmsGenerator(SIGNED_DATA, &cmsGenerator);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsGenerator, nullptr);

    res = cmsGenerator->setRecipientEncryptionAlgorithm(cmsGenerator, CMS_AES_128_CBC);
    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);
    CfObjDestroy(cmsGenerator);
}

HWTEST_F(CryptoX509CertCmsGeneratorTestPart2, getEncryptedContentData001, TestSize.Level0)
{
    HcfCmsGenerator *cmsGenerator = nullptr;
    HcfX509Certificate *x509Cert = nullptr;
    CfBlob out = {0, nullptr};
    CfBlob content;
    content.data = const_cast<uint8_t*>(g_inContent);
    content.size = sizeof(g_inContent);
    HcfCmsGeneratorOptions *cmsOptions = nullptr;
    CfResult res = HcfCreateCmsGenerator(ENVELOPED_DATA, &cmsGenerator);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsGenerator, nullptr);
    CfResult ret = HcfX509CertificateCreate(&g_inCertRsaP1PemStream, &x509Cert);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(x509Cert, nullptr);
    CmsRecipientInfo *recipientInfo = nullptr;
    recipientInfo = (CmsRecipientInfo *)CfMalloc(sizeof(CmsRecipientInfo), 0);
    EXPECT_NE(recipientInfo, nullptr);
    recipientInfo->keyTransInfo = nullptr;
    recipientInfo->keyTransInfo = (KeyTransRecipientInfo *)CfMalloc(sizeof(KeyTransRecipientInfo), 0);
    EXPECT_NE(recipientInfo->keyTransInfo, nullptr);
    recipientInfo->keyTransInfo->recipientCert = &(x509Cert->base);
    res = cmsGenerator->addRecipientInfo(cmsGenerator, recipientInfo);
    EXPECT_EQ(res, CF_SUCCESS);
    cmsOptions = (HcfCmsGeneratorOptions *)CfMalloc(sizeof(HcfCmsGeneratorOptions), 0);
    cmsOptions->dataFormat = BINARY;
    cmsOptions->outFormat = CMS_DER;
    cmsOptions->isDetachedContent = false;
    res = cmsGenerator->doFinal(cmsGenerator, &content, cmsOptions, &out);
    EXPECT_EQ(res, CF_SUCCESS);
    res = cmsGenerator->getEncryptedContentData(cmsGenerator, &out);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(out.data, nullptr);
    EXPECT_GT(out.size, 0);

    FreeTestRecipientInfo(recipientInfo);
    CfFree(cmsOptions);
    CfObjDestroy(x509Cert);
    CfBlobDataClearAndFree(&out);
    CfObjDestroy(cmsGenerator);
}

HWTEST_F(CryptoX509CertCmsGeneratorTestPart2, getEncryptedContentData002, TestSize.Level0)
{
    HcfCmsGenerator *cmsGenerator = nullptr;
    CfBlob out = {0, nullptr};

    CfResult res = HcfCreateCmsGenerator(SIGNED_DATA, &cmsGenerator);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsGenerator, nullptr);

    res = cmsGenerator->getEncryptedContentData(cmsGenerator, &out);
    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);

    res = HcfCreateCmsGenerator(ENVELOPED_DATA, &cmsGenerator);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsGenerator, nullptr);

    res = cmsGenerator->getEncryptedContentData(cmsGenerator, &out);
    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);

    CfBlobDataClearAndFree(&out);
    CfObjDestroy(cmsGenerator);
}

HWTEST_F(CryptoX509CertCmsGeneratorTestPart2, Invalid001, TestSize.Level0)
{
    HcfCmsGenerator *cmsGenerator = nullptr;
    HcfX509Certificate *x509Cert = nullptr;
    CfBlob out = {0, nullptr};

    CfResult res = HcfCreateCmsGenerator(ENVELOPED_DATA, &cmsGenerator);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsGenerator, nullptr);

    res = HcfX509CertificateCreate(&g_inCertEccP1PemStream, &x509Cert);
    EXPECT_EQ(res, CF_SUCCESS);
    ASSERT_NE(x509Cert, nullptr);

    CmsRecipientInfo *recipientInfo = nullptr;
    recipientInfo = (CmsRecipientInfo *)CfMalloc(sizeof(CmsRecipientInfo), 0);
    EXPECT_NE(recipientInfo, nullptr);

    recipientInfo->keyAgreeInfo = nullptr;
    recipientInfo->keyAgreeInfo = (KeyAgreeRecipientInfo *)CfMalloc(sizeof(KeyAgreeRecipientInfo), 0);
    EXPECT_NE(recipientInfo->keyAgreeInfo, nullptr);
    recipientInfo->keyAgreeInfo->recipientCert = &(x509Cert->base);
    recipientInfo->keyAgreeInfo->digestAlgorithm = CMS_SHA256;
    res = cmsGenerator->addRecipientInfo(nullptr, recipientInfo);
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);

    res = cmsGenerator->addRecipientInfo(cmsGenerator, nullptr);
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);

    res = cmsGenerator->setRecipientEncryptionAlgorithm(nullptr, CMS_AES_256_GCM);
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);

    res = cmsGenerator->getEncryptedContentData(nullptr, &out);
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);

    res = cmsGenerator->getEncryptedContentData(cmsGenerator, nullptr);
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);

    FreeTestRecipientInfo(recipientInfo);
    CfObjDestroy(x509Cert);
    CfObjDestroy(cmsGenerator);
}

HWTEST_F(CryptoX509CertCmsGeneratorTestPart2, Invalid002, TestSize.Level0)
{
    HcfCmsGeneratorSpi *cmsGenerator = nullptr;
    HcfX509Certificate *x509Cert = nullptr;
    CfBlob out = {0, nullptr};

    CfResult res = HcfCmsGeneratorSpiCreate(ENVELOPED_DATA, &cmsGenerator);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsGenerator, nullptr);

    res = HcfX509CertificateCreate(&g_inCertEccP1PemStream, &x509Cert);
    EXPECT_EQ(res, CF_SUCCESS);
    ASSERT_NE(x509Cert, nullptr);

    CmsRecipientInfo *recipientInfo = nullptr;
    recipientInfo = (CmsRecipientInfo *)CfMalloc(sizeof(CmsRecipientInfo), 0);
    EXPECT_NE(recipientInfo, nullptr);

    recipientInfo->keyAgreeInfo = nullptr;
    recipientInfo->keyAgreeInfo = (KeyAgreeRecipientInfo *)CfMalloc(sizeof(KeyAgreeRecipientInfo), 0);
    EXPECT_NE(recipientInfo->keyAgreeInfo, nullptr);
    recipientInfo->keyAgreeInfo->recipientCert = &(x509Cert->base);
    recipientInfo->keyAgreeInfo->digestAlgorithm = CMS_SHA256;
    res = cmsGenerator->engineAddRecipientInfo(nullptr, recipientInfo);
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);

    res = cmsGenerator->engineAddRecipientInfo(cmsGenerator, nullptr);
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);

    res = cmsGenerator->engineSetRecipientEncryptionAlgorithm(nullptr, CMS_AES_256_GCM);
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);

    res = cmsGenerator->engineGetEncryptedContentData(nullptr, &out);
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);

    res = cmsGenerator->engineGetEncryptedContentData(cmsGenerator, nullptr);
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);

    FreeTestRecipientInfo(recipientInfo);
    CfObjDestroy(x509Cert);
    CfObjDestroy(cmsGenerator);
}

HWTEST_F(CryptoX509CertCmsGeneratorTestPart2, Invalid003, TestSize.Level0)
{
    HcfCmsGenerator *cmsGenerator = nullptr;
    PrivateKeyInfo *privateKey = nullptr;
    HcfCmsSignerOptions *options = nullptr;
    HcfX509Certificate *x509Cert = nullptr;

    CfResult res = HcfCreateCmsGenerator(ENVELOPED_DATA, &cmsGenerator);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsGenerator, nullptr);

    res = HcfX509CertificateCreate(&g_inCertRsaP1PemStream, &x509Cert);
    EXPECT_EQ(res, CF_SUCCESS);
    ASSERT_NE(x509Cert, nullptr);

    privateKey = (PrivateKeyInfo *)CfMalloc(sizeof(PrivateKeyInfo), 0);
    privateKey->privateKey = const_cast<CfEncodingBlob*>(&g_inKeyRsaP1PemStream);
    privateKey->privateKeyPassword = const_cast<char*>(g_testPwd);

    options = (HcfCmsSignerOptions *)CfMalloc(sizeof(HcfCmsSignerOptions), 0);
    options->mdName = const_cast<char*>(g_digestSHA256);
    options->padding = PKCS1_PSS_PADDING;
    res = cmsGenerator->addSigner(cmsGenerator, &(x509Cert->base), privateKey, options);
    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);
    res = cmsGenerator->addCert(cmsGenerator, &(x509Cert->base));
    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);
    
    CfFree(privateKey);
    CfFree(options);
    CfObjDestroy(x509Cert);
    CfObjDestroy(cmsGenerator);
}

HWTEST_F(CryptoX509CertCmsGeneratorTestPart2, Invalid004, TestSize.Level0)
{
    HcfCmsGenerator *cmsGenerator = nullptr;
    HcfX509Certificate *x509Cert = nullptr;
    CfBlob out = {0, nullptr};

    CfResult res = HcfCreateCmsGenerator(SIGNED_DATA, &cmsGenerator);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsGenerator, nullptr);

    res = HcfX509CertificateCreate(&g_inCertEccP1PemStream, &x509Cert);
    EXPECT_EQ(res, CF_SUCCESS);
    ASSERT_NE(x509Cert, nullptr);

    CmsRecipientInfo *recipientInfo = nullptr;
    recipientInfo = (CmsRecipientInfo *)CfMalloc(sizeof(CmsRecipientInfo), 0);
    EXPECT_NE(recipientInfo, nullptr);

    recipientInfo->keyAgreeInfo = nullptr;
    recipientInfo->keyAgreeInfo = (KeyAgreeRecipientInfo *)CfMalloc(sizeof(KeyAgreeRecipientInfo), 0);
    EXPECT_NE(recipientInfo->keyAgreeInfo, nullptr);
    recipientInfo->keyAgreeInfo->recipientCert = &(x509Cert->base);
    recipientInfo->keyAgreeInfo->digestAlgorithm = CMS_SHA256;
    res = cmsGenerator->addRecipientInfo(cmsGenerator, recipientInfo);
    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);

    res = cmsGenerator->setRecipientEncryptionAlgorithm(cmsGenerator, CMS_AES_256_GCM);
    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);

    res = cmsGenerator->getEncryptedContentData(cmsGenerator, &out);
    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);

    FreeTestRecipientInfo(recipientInfo);
    CfObjDestroy(x509Cert);
    CfObjDestroy(cmsGenerator);
}

HWTEST_F(CryptoX509CertCmsGeneratorTestPart2, Invalid005, TestSize.Level0)
{
    HcfCmsGenerator *cmsGenerator = nullptr;
    PrivateKeyInfo *privateKey = nullptr;
    HcfCmsSignerOptions *options = nullptr;
    HcfX509Certificate *x509Cert = nullptr;

    CfResult res = HcfCreateCmsGenerator(SIGNED_DATA, &cmsGenerator);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsGenerator, nullptr);

    res = HcfX509CertificateCreate(&g_inCertRsaP1PemStream, &x509Cert);
    EXPECT_EQ(res, CF_SUCCESS);
    ASSERT_NE(x509Cert, nullptr);

    privateKey = (PrivateKeyInfo *)CfMalloc(sizeof(PrivateKeyInfo), 0);
    privateKey->privateKey = const_cast<CfEncodingBlob*>(&g_inKeyRsaP1PemStream);
    privateKey->privateKeyPassword = const_cast<char*>(g_testPwd);

    options = (HcfCmsSignerOptions *)CfMalloc(sizeof(HcfCmsSignerOptions), 0);
    options->mdName = const_cast<char*>(g_digestSHA256);
    options->padding = PKCS1_PSS_PADDING;
    options->addCert = true;
    options->addAttr = true;
    options->addSmimeCapAttr = true;

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), CMS_SignerInfo_get0_pkey_ctx(_))
        .WillOnce(Return(nullptr))
        .WillRepeatedly(Invoke(__real_CMS_SignerInfo_get0_pkey_ctx));
    res = cmsGenerator->addSigner(cmsGenerator, &(x509Cert->base), privateKey, options);
    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    CfFree(privateKey);
    CfFree(options);
    CfObjDestroy(x509Cert);
    CfObjDestroy(cmsGenerator);
}

HWTEST_F(CryptoX509CertCmsGeneratorTestPart2, Invalid006, TestSize.Level0)
{
    HcfCmsGenerator *cmsGenerator = nullptr;
    PrivateKeyInfo *privateKey = nullptr;
    HcfCmsSignerOptions *options = nullptr;
    HcfX509Certificate *x509Cert = nullptr;

    CfResult res = HcfCreateCmsGenerator(SIGNED_DATA, &cmsGenerator);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsGenerator, nullptr);

    res = HcfX509CertificateCreate(&g_inCertRsaP1PemStream, &x509Cert);
    EXPECT_EQ(res, CF_SUCCESS);
    ASSERT_NE(x509Cert, nullptr);

    privateKey = (PrivateKeyInfo *)CfMalloc(sizeof(PrivateKeyInfo), 0);
    privateKey->privateKey = const_cast<CfEncodingBlob*>(&g_inKeyRsaP1PemStream);
    privateKey->privateKeyPassword = const_cast<char*>(g_testPwd);

    options = (HcfCmsSignerOptions *)CfMalloc(sizeof(HcfCmsSignerOptions), 0);
    options->mdName = const_cast<char*>(g_digestSHA256);
    options->padding = PKCS1_PSS_PADDING;
    options->addCert = true;
    options->addAttr = true;
    options->addSmimeCapAttr = true;

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), EVP_PKEY_CTX_set_rsa_padding(_, _))
        .WillOnce(Return(0))
        .WillRepeatedly(Invoke(__real_EVP_PKEY_CTX_set_rsa_padding));
    res = cmsGenerator->addSigner(cmsGenerator, &(x509Cert->base), privateKey, options);
    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    CfFree(privateKey);
    CfFree(options);
    CfObjDestroy(x509Cert);
    CfObjDestroy(cmsGenerator);
}

HWTEST_F(CryptoX509CertCmsGeneratorTestPart2, Invalid007, TestSize.Level0)
{
    HcfCmsGenerator *cmsGenerator = nullptr;
    HcfX509Certificate *x509Cert = nullptr;
    PrivateKeyInfo *privateKey = nullptr;
    HcfCmsSignerOptions *options = nullptr;

    CfResult res = HcfCreateCmsGenerator(SIGNED_DATA, &cmsGenerator);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsGenerator, nullptr);

    res = HcfX509CertificateCreate(&g_inCertEccP1PemStream, &x509Cert);
    EXPECT_EQ(res, CF_SUCCESS);
    ASSERT_NE(x509Cert, nullptr);

    privateKey = (PrivateKeyInfo *)CfMalloc(sizeof(PrivateKeyInfo), 0);
    privateKey->privateKey = const_cast<CfEncodingBlob*>(&g_inKeyRsaP1PemStream);
    privateKey->privateKeyPassword = const_cast<char*>(g_testPwd);

    options = (HcfCmsSignerOptions *)CfMalloc(sizeof(HcfCmsSignerOptions), 0);
    options->mdName = const_cast<char*>(g_digestSHA256);
    options->padding = PKCS1_PSS_PADDING;
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), CMS_get0_type(_))
        .WillOnce(Return(nullptr))
        .WillRepeatedly(Invoke(__real_CMS_get0_type));
    res = cmsGenerator->addSigner(cmsGenerator, &(x509Cert->base), privateKey, options);
    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), CMS_get0_type(_))
        .WillOnce(Return(nullptr))
        .WillRepeatedly(Invoke(__real_CMS_get0_type));
    res = cmsGenerator->addCert(cmsGenerator, &(x509Cert->base));
    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    CfFree(privateKey);
    CfFree(options);
    CfObjDestroy(x509Cert);
    CfObjDestroy(cmsGenerator);
}

HWTEST_F(CryptoX509CertCmsGeneratorTestPart2, Invalid008, TestSize.Level0)
{
    HcfCmsGenerator *cmsGenerator = nullptr;
    HcfX509Certificate *x509Cert = nullptr;
    CfBlob out = {0, nullptr};

    CfResult res = HcfCreateCmsGenerator(SIGNED_DATA, &cmsGenerator);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsGenerator, nullptr);

    res = HcfX509CertificateCreate(&g_inCertEccP1PemStream, &x509Cert);
    EXPECT_EQ(res, CF_SUCCESS);
    ASSERT_NE(x509Cert, nullptr);

    CmsRecipientInfo *recipientInfo = nullptr;
    recipientInfo = (CmsRecipientInfo *)CfMalloc(sizeof(CmsRecipientInfo), 0);
    EXPECT_NE(recipientInfo, nullptr);

    recipientInfo->keyAgreeInfo = nullptr;
    recipientInfo->keyAgreeInfo = (KeyAgreeRecipientInfo *)CfMalloc(sizeof(KeyAgreeRecipientInfo), 0);
    EXPECT_NE(recipientInfo->keyAgreeInfo, nullptr);
    recipientInfo->keyAgreeInfo->recipientCert = &(x509Cert->base);
    recipientInfo->keyAgreeInfo->digestAlgorithm = CMS_SHA256;

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), CMS_get0_type(_))
        .WillOnce(Return(nullptr))
        .WillRepeatedly(Invoke(__real_CMS_get0_type));
    res = cmsGenerator->addRecipientInfo(cmsGenerator, recipientInfo);
    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), CMS_get0_type(_))
        .WillOnce(Return(nullptr))
        .WillRepeatedly(Invoke(__real_CMS_get0_type));
    res = cmsGenerator->setRecipientEncryptionAlgorithm(cmsGenerator, CMS_AES_256_GCM);
    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), CMS_get0_type(_))
        .WillOnce(Return(nullptr))
        .WillRepeatedly(Invoke(__real_CMS_get0_type));
    res = cmsGenerator->getEncryptedContentData(cmsGenerator, &out);
    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    FreeTestRecipientInfo(recipientInfo);
    CfObjDestroy(x509Cert);
    CfObjDestroy(cmsGenerator);
}

HWTEST_F(CryptoX509CertCmsGeneratorTestPart2, Invalid009, TestSize.Level0)
{
    HcfCmsGenerator *cmsGenerator = nullptr;
    HcfX509Certificate *x509Cert = nullptr;

    CfResult res = HcfCreateCmsGenerator(ENVELOPED_DATA, &cmsGenerator);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsGenerator, nullptr);

    CfResult ret = HcfX509CertificateCreate(&g_inCertEccP1PemStream, &x509Cert);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(x509Cert, nullptr);

    CmsRecipientInfo *recipientInfo = nullptr;
    recipientInfo = (CmsRecipientInfo *)CfMalloc(sizeof(CmsRecipientInfo), 0);
    EXPECT_NE(recipientInfo, nullptr);

    recipientInfo->keyAgreeInfo = nullptr;
    recipientInfo->keyAgreeInfo = (KeyAgreeRecipientInfo *)CfMalloc(sizeof(KeyAgreeRecipientInfo), 0);
    EXPECT_NE(recipientInfo->keyAgreeInfo, nullptr);
    recipientInfo->keyAgreeInfo->recipientCert = &(x509Cert->base);
    recipientInfo->keyAgreeInfo->digestAlgorithm = CMS_SHA256;

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), CMS_add1_recipient_cert(_, _, _))
        .WillOnce(Return(nullptr))
        .WillRepeatedly(Invoke(__real_CMS_add1_recipient_cert));
    res = cmsGenerator->addRecipientInfo(cmsGenerator, recipientInfo);
    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), CMS_RecipientInfo_get0_pkey_ctx(_))
        .WillOnce(Return(nullptr))
        .WillRepeatedly(Invoke(__real_CMS_RecipientInfo_get0_pkey_ctx));
    res = cmsGenerator->addRecipientInfo(cmsGenerator, recipientInfo);
    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), EVP_PKEY_CTX_set_ecdh_kdf_md(_, _))
        .WillOnce(Return(0))
        .WillRepeatedly(Invoke(__real_EVP_PKEY_CTX_set_ecdh_kdf_md));
    res = cmsGenerator->addRecipientInfo(cmsGenerator, recipientInfo);
    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    FreeTestRecipientInfo(recipientInfo);
    CfObjDestroy(x509Cert);
    CfObjDestroy(cmsGenerator);
}

HWTEST_F(CryptoX509CertCmsGeneratorTestPart2, Invalid010, TestSize.Level0)
{
    HcfCmsGenerator *cmsGenerator = nullptr;
    HcfX509Certificate *x509Cert = nullptr;

    CfResult res = HcfCreateCmsGenerator(ENVELOPED_DATA, &cmsGenerator);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsGenerator, nullptr);

    CfResult ret = HcfX509CertificateCreate(&g_inCertRsaP1PemStream, &x509Cert);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(x509Cert, nullptr);

    CmsRecipientInfo *recipientInfo = nullptr;
    recipientInfo = (CmsRecipientInfo *)CfMalloc(sizeof(CmsRecipientInfo), 0);
    EXPECT_NE(recipientInfo, nullptr);

    recipientInfo->keyTransInfo = nullptr;
    recipientInfo->keyTransInfo = (KeyTransRecipientInfo *)CfMalloc(sizeof(KeyTransRecipientInfo), 0);
    EXPECT_NE(recipientInfo->keyTransInfo, nullptr);
    recipientInfo->keyTransInfo->recipientCert = &(x509Cert->base);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), CMS_add1_recipient_cert(_, _, _))
        .WillOnce(Return(nullptr))
        .WillRepeatedly(Invoke(__real_CMS_add1_recipient_cert));
    res = cmsGenerator->addRecipientInfo(cmsGenerator, recipientInfo);
    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    FreeTestRecipientInfo(recipientInfo);
    CfObjDestroy(x509Cert);
    CfObjDestroy(cmsGenerator);
}

HWTEST_F(CryptoX509CertCmsGeneratorTestPart2, Invalid011, TestSize.Level0)
{
    HcfCmsGenerator *cmsGenerator = nullptr;
    HcfX509Certificate *x509Cert = nullptr;
    CfBlob out = {0, nullptr};
    CfBlob content;
    content.data = const_cast<uint8_t*>(g_inContent);
    content.size = sizeof(g_inContent);
    HcfCmsGeneratorOptions *cmsOptions = nullptr;

    CfResult res = HcfCreateCmsGenerator(ENVELOPED_DATA, &cmsGenerator);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsGenerator, nullptr);

    CfResult ret = HcfX509CertificateCreate(&g_inCertRsaP1PemStream, &x509Cert);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(x509Cert, nullptr);

    CmsRecipientInfo *recipientInfo = nullptr;
    recipientInfo = (CmsRecipientInfo *)CfMalloc(sizeof(CmsRecipientInfo), 0);
    EXPECT_NE(recipientInfo, nullptr);

    recipientInfo->keyTransInfo = nullptr;
    recipientInfo->keyTransInfo = (KeyTransRecipientInfo *)CfMalloc(sizeof(KeyTransRecipientInfo), 0);
    EXPECT_NE(recipientInfo->keyTransInfo, nullptr);
    recipientInfo->keyTransInfo->recipientCert = &(x509Cert->base);

    res = cmsGenerator->addRecipientInfo(cmsGenerator, recipientInfo);
    EXPECT_EQ(res, CF_SUCCESS);

    cmsOptions = (HcfCmsGeneratorOptions *)CfMalloc(sizeof(HcfCmsGeneratorOptions), 0);
    cmsOptions->dataFormat = BINARY;
    cmsOptions->outFormat = CMS_DER;
    cmsOptions->isDetachedContent = false;

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), CMS_get0_type(_))
        .WillOnce(Return(nullptr))
        .WillRepeatedly(Invoke(__real_CMS_get0_type));
    res = cmsGenerator->doFinal(cmsGenerator, &content, cmsOptions, &out);
    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), OBJ_obj2nid(_))
        .WillOnce(Return(0))
        .WillRepeatedly(Invoke(__real_OBJ_obj2nid));
    res = cmsGenerator->doFinal(cmsGenerator, &content, cmsOptions, &out);
    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    FreeTestRecipientInfo(recipientInfo);
    CfFree(cmsOptions);
    CfObjDestroy(x509Cert);
    CfBlobDataClearAndFree(&out);
    CfObjDestroy(cmsGenerator);
}

HWTEST_F(CryptoX509CertCmsGeneratorTestPart2, Invalid012, TestSize.Level0)
{
    HcfCmsGenerator *cmsGenerator = nullptr;
    HcfX509Certificate *x509Cert = nullptr;
    CfBlob out = {0, nullptr};
    CfBlob content;
    content.data = const_cast<uint8_t*>(g_inContent);
    content.size = sizeof(g_inContent);
    HcfCmsGeneratorOptions *cmsOptions = nullptr;

    CfResult res = HcfCreateCmsGenerator(ENVELOPED_DATA, &cmsGenerator);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsGenerator, nullptr);

    CfResult ret = HcfX509CertificateCreate(&g_inCertRsaP1PemStream, &x509Cert);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(x509Cert, nullptr);

    CmsRecipientInfo *recipientInfo = nullptr;
    recipientInfo = (CmsRecipientInfo *)CfMalloc(sizeof(CmsRecipientInfo), 0);
    EXPECT_NE(recipientInfo, nullptr);

    recipientInfo->keyTransInfo = nullptr;
    recipientInfo->keyTransInfo = (KeyTransRecipientInfo *)CfMalloc(sizeof(KeyTransRecipientInfo), 0);
    EXPECT_NE(recipientInfo->keyTransInfo, nullptr);
    recipientInfo->keyTransInfo->recipientCert = &(x509Cert->base);

    res = cmsGenerator->addRecipientInfo(cmsGenerator, recipientInfo);
    EXPECT_EQ(res, CF_SUCCESS);

    cmsOptions = (HcfCmsGeneratorOptions *)CfMalloc(sizeof(HcfCmsGeneratorOptions), 0);
    cmsOptions->dataFormat = BINARY;
    cmsOptions->outFormat = CMS_DER;
    cmsOptions->isDetachedContent = false;

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), OBJ_obj2nid(_))
        .WillOnce(Return(0))
        .WillRepeatedly(Invoke(__real_OBJ_obj2nid));
    res = cmsGenerator->doFinal(cmsGenerator, &content, cmsOptions, &out);
    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), BIO_new(_))
        .WillOnce(Return(nullptr))
        .WillRepeatedly(Invoke(__real_BIO_new));
    res = cmsGenerator->doFinal(cmsGenerator, &content, cmsOptions, &out);
    EXPECT_EQ(res, CF_ERR_MALLOC);
    X509OpensslMock::SetMockFlag(false);

    FreeTestRecipientInfo(recipientInfo);
    CfFree(cmsOptions);
    CfObjDestroy(x509Cert);
    CfBlobDataClearAndFree(&out);
    CfObjDestroy(cmsGenerator);
}

HWTEST_F(CryptoX509CertCmsGeneratorTestPart2, Invalid013, TestSize.Level0)
{
    HcfCmsGenerator *cmsGenerator = nullptr;
    PrivateKeyInfo *privateKey = nullptr;
    HcfCmsSignerOptions *options = nullptr;
    HcfX509Certificate *x509Cert = nullptr;
    HcfCmsGeneratorOptions *cmsOptions = nullptr;
    CfBlob out = {0, nullptr};
    CfBlob content;
    content.data = const_cast<uint8_t*>(g_inContent);
    content.size = sizeof(g_inContent);

    CfResult res = HcfCreateCmsGenerator(SIGNED_DATA, &cmsGenerator);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsGenerator, nullptr);

    res = HcfX509CertificateCreate(&g_inCertRsaP1PemStream, &x509Cert);
    EXPECT_EQ(res, CF_SUCCESS);
    ASSERT_NE(x509Cert, nullptr);

    privateKey = (PrivateKeyInfo *)CfMalloc(sizeof(PrivateKeyInfo), 0);
    privateKey->privateKey = const_cast<CfEncodingBlob*>(&g_inKeyRsaP1PemStream);
    privateKey->privateKeyPassword = const_cast<char*>(g_testPwd);

    options = (HcfCmsSignerOptions *)CfMalloc(sizeof(HcfCmsSignerOptions), 0);
    options->mdName = const_cast<char*>(g_digestSHA256);
    options->padding = PKCS1_PSS_PADDING;
    options->addCert = true;
    options->addAttr = true;
    options->addSmimeCapAttr = true;
    res = cmsGenerator->addSigner(cmsGenerator, &(x509Cert->base), privateKey, options);
    EXPECT_EQ(res, CF_SUCCESS);

    cmsOptions = (HcfCmsGeneratorOptions *)CfMalloc(sizeof(HcfCmsGeneratorOptions), 0);
    cmsOptions->dataFormat = BINARY;
    cmsOptions->outFormat = CMS_DER;
    cmsOptions->isDetachedContent = false;

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), CMS_get0_SignerInfos(_))
        .WillOnce(Return(nullptr))
        .WillRepeatedly(Invoke(__real_CMS_get0_SignerInfos));
    res = cmsGenerator->doFinal(cmsGenerator, &content, cmsOptions, &out);
    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    CfFree(privateKey);
    CfFree(options);
    CfObjDestroy(x509Cert);
    CfObjDestroy(cmsGenerator);
    CfFree(cmsOptions);
    CfBlobDataClearAndFree(&out);
}

HWTEST_F(CryptoX509CertCmsGeneratorTestPart2, Invalid014, TestSize.Level0)
{
    HcfCmsGenerator *cmsGenerator = nullptr;
    HcfX509Certificate *x509Cert = nullptr;
    CfBlob out = {0, nullptr};
    CfBlob content;
    content.data = const_cast<uint8_t*>(g_inContent);
    content.size = sizeof(g_inContent);
    HcfCmsGeneratorOptions *cmsOptions = nullptr;

    CfResult res = HcfCreateCmsGenerator(SIGNED_DATA, &cmsGenerator);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsGenerator, nullptr);

    CfResult ret = HcfX509CertificateCreate(&g_inCertRsaP1PemStream, &x509Cert);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(x509Cert, nullptr);

    res = cmsGenerator->addCert(cmsGenerator, &(x509Cert->base));
    EXPECT_EQ(res, CF_SUCCESS);

    cmsOptions = (HcfCmsGeneratorOptions *)CfMalloc(sizeof(HcfCmsGeneratorOptions), 0);
    cmsOptions->dataFormat = BINARY;
    cmsOptions->outFormat = CMS_DER;
    cmsOptions->isDetachedContent = false;
    res = cmsGenerator->doFinal(nullptr, &content, cmsOptions, &out);
    EXPECT_EQ(res, CF_INVALID_PARAMS);
    res = cmsGenerator->doFinal(cmsGenerator, nullptr, cmsOptions, &out);
    EXPECT_EQ(res, CF_INVALID_PARAMS);
    res = cmsGenerator->doFinal(cmsGenerator, &content, nullptr, &out);
    EXPECT_EQ(res, CF_INVALID_PARAMS);
    res = cmsGenerator->doFinal(cmsGenerator, &content, cmsOptions, nullptr);
    EXPECT_EQ(res, CF_INVALID_PARAMS);

    CfFree(cmsOptions);
    CfObjDestroy(x509Cert);
    CfObjDestroy(cmsGenerator);
}

HWTEST_F(CryptoX509CertCmsGeneratorTestPart2, Invalid015, TestSize.Level0)
{
    HcfCmsGenerator *cmsGenerator = nullptr;
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), CMS_AuthEnvelopedData_create(_))
        .WillOnce(Return(nullptr))
        .WillRepeatedly(Invoke(__real_CMS_AuthEnvelopedData_create));
    CfResult res = HcfCreateCmsGenerator(ENVELOPED_DATA, &cmsGenerator);
    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);
}

HWTEST_F(CryptoX509CertCmsGeneratorTestPart2, Invalid016, TestSize.Level0)
{
    HcfCmsGenerator *cmsGenerator = nullptr;

    CfResult res = HcfCreateCmsGenerator(ENVELOPED_DATA, &cmsGenerator);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsGenerator, nullptr);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), CMS_AuthEnvelopedData_create(_))
        .WillOnce(Return(nullptr))
        .WillRepeatedly(Invoke(__real_CMS_AuthEnvelopedData_create));
    res = cmsGenerator->setRecipientEncryptionAlgorithm(cmsGenerator, CMS_AES_256_GCM);
    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), CMS_EnvelopedData_create(_))
        .WillOnce(Return(nullptr))
        .WillRepeatedly(Invoke(__real_CMS_EnvelopedData_create));
    res = cmsGenerator->setRecipientEncryptionAlgorithm(cmsGenerator, CMS_AES_128_CBC);
    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    CfObjDestroy(cmsGenerator);
}

HWTEST_F(CryptoX509CertCmsGeneratorTestPart2, Invalid017, TestSize.Level0)
{
    HcfCmsGenerator *cmsGenerator = nullptr;
    HcfX509Certificate *x509Cert = nullptr;
    CfBlob out = {0, nullptr};

    CfResult res = HcfCreateCmsGenerator(ENVELOPED_DATA, &cmsGenerator);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsGenerator, nullptr);

    res = HcfX509CertificateCreate(&g_inCertEccP1PemStream, &x509Cert);
    EXPECT_EQ(res, CF_SUCCESS);
    ASSERT_NE(x509Cert, nullptr);

    CmsRecipientInfo *recipientInfo = nullptr;
    recipientInfo = (CmsRecipientInfo *)CfMalloc(sizeof(CmsRecipientInfo), 0);
    EXPECT_NE(recipientInfo, nullptr);

    recipientInfo->keyAgreeInfo = nullptr;
    recipientInfo->keyAgreeInfo = (KeyAgreeRecipientInfo *)CfMalloc(sizeof(KeyAgreeRecipientInfo), 0);
    EXPECT_NE(recipientInfo->keyAgreeInfo, nullptr);
    recipientInfo->keyAgreeInfo->recipientCert = &(x509Cert->base);
    recipientInfo->keyAgreeInfo->digestAlgorithm = CMS_SHA256;

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), CfIsClassMatch(_, _))
        .WillOnce(Return(false))
        .WillRepeatedly(Invoke(__real_CfIsClassMatch));
    res = cmsGenerator->addRecipientInfo(cmsGenerator, recipientInfo);
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);
    X509OpensslMock::SetMockFlag(false);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), CfIsClassMatch(_, _))
        .WillOnce(Return(false))
        .WillRepeatedly(Invoke(__real_CfIsClassMatch));
    res = cmsGenerator->setRecipientEncryptionAlgorithm(cmsGenerator, CMS_AES_256_GCM);
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);
    X509OpensslMock::SetMockFlag(false);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), CfIsClassMatch(_, _))
        .WillOnce(Return(false))
        .WillRepeatedly(Invoke(__real_CfIsClassMatch));
    res = cmsGenerator->getEncryptedContentData(cmsGenerator, &out);
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);
    X509OpensslMock::SetMockFlag(false);

    FreeTestRecipientInfo(recipientInfo);
    CfObjDestroy(x509Cert);
    CfObjDestroy(cmsGenerator);
}

HWTEST_F(CryptoX509CertCmsGeneratorTestPart2, Invalid018, TestSize.Level0)
{
    HcfCmsGenerator *cmsGenerator = nullptr;
    PrivateKeyInfo *privateKey = nullptr;
    HcfCmsSignerOptions *options = nullptr;
    HcfX509Certificate *x509Cert = nullptr;

    CfResult res = HcfCreateCmsGenerator(SIGNED_DATA, &cmsGenerator);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsGenerator, nullptr);

    res = HcfX509CertificateCreate(&g_inCertDsaP1PemStream, &x509Cert);
    EXPECT_EQ(res, CF_SUCCESS);
    ASSERT_NE(x509Cert, nullptr);

    privateKey = (PrivateKeyInfo *)CfMalloc(sizeof(PrivateKeyInfo), 0);
    privateKey->privateKey = const_cast<CfEncodingBlob*>(&g_inKeyDsaP1PemStream);
    privateKey->privateKeyPassword = const_cast<char*>(g_testPwd);

    options = (HcfCmsSignerOptions *)CfMalloc(sizeof(HcfCmsSignerOptions), 0);

    options->mdName = const_cast<char*>(g_digestSHA256);
    options->padding = PKCS1_PSS_PADDING;
    options->addCert = true;
    options->addAttr = true;
    options->addSmimeCapAttr = true;
    res = cmsGenerator->addSigner(cmsGenerator, &(x509Cert->base), privateKey, options);
    EXPECT_EQ(res, CF_NOT_SUPPORT);

    CfFree(privateKey);
    CfFree(options);
    CfObjDestroy(x509Cert);
    CfObjDestroy(cmsGenerator);
}

HWTEST_F(CryptoX509CertCmsGeneratorTestPart2, Invalid019, TestSize.Level0)
{
    HcfCmsGenerator *cmsGenerator = nullptr;
    HcfX509Certificate *x509Cert = nullptr;

    CfResult res = HcfCreateCmsGenerator(ENVELOPED_DATA, &cmsGenerator);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsGenerator, nullptr);

    CfResult ret = HcfX509CertificateCreate(&g_inCertEccP1PemStream, &x509Cert);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(x509Cert, nullptr);

    CmsRecipientInfo *recipientInfo = nullptr;
    recipientInfo = (CmsRecipientInfo *)CfMalloc(sizeof(CmsRecipientInfo), 0);
    EXPECT_NE(recipientInfo, nullptr);

    recipientInfo->keyAgreeInfo = nullptr;
    recipientInfo->keyAgreeInfo = (KeyAgreeRecipientInfo *)CfMalloc(sizeof(KeyAgreeRecipientInfo), 0);
    EXPECT_NE(recipientInfo->keyAgreeInfo, nullptr);
    recipientInfo->keyAgreeInfo->recipientCert = &(x509Cert->base);
    recipientInfo->keyAgreeInfo->digestAlgorithm = CMS_SHA256;

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_get0_pubkey(_))
        .WillOnce(Return(nullptr))
        .WillRepeatedly(Invoke(__real_X509_get0_pubkey));
    res = cmsGenerator->addRecipientInfo(cmsGenerator, recipientInfo);
    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    FreeTestRecipientInfo(recipientInfo);
    CfObjDestroy(x509Cert);
    CfObjDestroy(cmsGenerator);
}

HWTEST_F(CryptoX509CertCmsGeneratorTestPart2, Invalid020, TestSize.Level0)
{
    HcfCmsGenerator *cmsGenerator = nullptr;
    HcfX509Certificate *x509Cert = nullptr;

    CfResult res = HcfCreateCmsGenerator(ENVELOPED_DATA, &cmsGenerator);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsGenerator, nullptr);

    CfResult ret = HcfX509CertificateCreate(&g_inCertRsaP1PemStream, &x509Cert);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(x509Cert, nullptr);

    CmsRecipientInfo *recipientInfo = nullptr;
    recipientInfo = (CmsRecipientInfo *)CfMalloc(sizeof(CmsRecipientInfo), 0);
    EXPECT_NE(recipientInfo, nullptr);

    recipientInfo->keyTransInfo = nullptr;
    recipientInfo->keyTransInfo = (KeyTransRecipientInfo *)CfMalloc(sizeof(KeyTransRecipientInfo), 0);
    EXPECT_NE(recipientInfo->keyTransInfo, nullptr);
    recipientInfo->keyTransInfo->recipientCert = &(x509Cert->base);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_get0_pubkey(_))
        .WillOnce(Return(nullptr))
        .WillRepeatedly(Invoke(__real_X509_get0_pubkey));
    res = cmsGenerator->addRecipientInfo(cmsGenerator, recipientInfo);
    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    FreeTestRecipientInfo(recipientInfo);
    CfObjDestroy(x509Cert);
    CfObjDestroy(cmsGenerator);
}

HWTEST_F(CryptoX509CertCmsGeneratorTestPart2, Invalid021, TestSize.Level0)
{
    HcfCmsGenerator *cmsGenerator = nullptr;
    PrivateKeyInfo *privateKey = nullptr;
    HcfCmsSignerOptions *options = nullptr;
    HcfX509Certificate *x509Cert = nullptr;

    CfResult res = HcfCreateCmsGenerator(SIGNED_DATA, &cmsGenerator);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsGenerator, nullptr);

    res = HcfX509CertificateCreate(&g_inCertRsaP1PemStream, &x509Cert);
    EXPECT_EQ(res, CF_SUCCESS);
    ASSERT_NE(x509Cert, nullptr);

    privateKey = (PrivateKeyInfo *)CfMallocEx(sizeof(PrivateKeyInfo));
    privateKey->privateKey = const_cast<CfEncodingBlob*>(&g_inKeyRsaP1PemStream);
    privateKey->privateKeyPassword = const_cast<char*>(g_testPwd);

    options = (HcfCmsSignerOptions *)CfMallocEx(sizeof(HcfCmsSignerOptions));
    options->mdName = const_cast<char*>(g_digestSHA256);
    options->padding = static_cast<CfCmsRsaSignaturePadding>(-1);
    res = cmsGenerator->addSigner(cmsGenerator, &(x509Cert->base), privateKey, options);
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);

    CfFree(privateKey);
    CfFree(options);
    CfObjDestroy(x509Cert);
    CfObjDestroy(cmsGenerator);
}

HWTEST_F(CryptoX509CertCmsGeneratorTestPart2, Invalid022, TestSize.Level0)
{
    HcfCmsGenerator *cmsGenerator = nullptr;
    HcfX509Certificate *x509Cert = nullptr;
    CfBlob out = {0, nullptr};
    CfBlob content;
    content.data = const_cast<uint8_t*>(g_inContent);
    content.size = sizeof(g_inContent);
    HcfCmsGeneratorOptions *cmsOptions = nullptr;

    CfResult res = HcfCreateCmsGenerator(ENVELOPED_DATA, &cmsGenerator);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsGenerator, nullptr);

    CfResult ret = HcfX509CertificateCreate(&g_inCertRsaP1PemStream, &x509Cert);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(x509Cert, nullptr);

    CmsRecipientInfo *recipientInfo = nullptr;
    recipientInfo = (CmsRecipientInfo *)CfMallocEx(sizeof(CmsRecipientInfo));
    EXPECT_NE(recipientInfo, nullptr);

    recipientInfo->keyTransInfo = nullptr;
    recipientInfo->keyTransInfo = (KeyTransRecipientInfo *)CfMallocEx(sizeof(KeyTransRecipientInfo));
    EXPECT_NE(recipientInfo->keyTransInfo, nullptr);
    recipientInfo->keyTransInfo->recipientCert = &(x509Cert->base);

    res = cmsGenerator->addRecipientInfo(cmsGenerator, recipientInfo);
    EXPECT_EQ(res, CF_SUCCESS);

    cmsOptions = (HcfCmsGeneratorOptions *)CfMallocEx(sizeof(HcfCmsGeneratorOptions));
    cmsOptions->dataFormat = TEXT;
    cmsOptions->outFormat = CMS_PEM;
    cmsOptions->isDetachedContent = false;

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), CMS_set_detached(_, _))
        .WillOnce(Return(0))
        .WillRepeatedly(Invoke(__real_CMS_set_detached));
    res = cmsGenerator->doFinal(cmsGenerator, &content, cmsOptions, &out);
    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    FreeTestRecipientInfo(recipientInfo);
    CfFree(cmsOptions);
    CfObjDestroy(x509Cert);
    CfBlobDataClearAndFree(&out);
    CfObjDestroy(cmsGenerator);
}

HWTEST_F(CryptoX509CertCmsGeneratorTestPart2, Invalid023, TestSize.Level0)
{
    HcfCmsGeneratorSpi *cmsGenerator = nullptr;
    HcfX509Certificate *x509Cert = nullptr;
    CfBlob out = {0, nullptr};

    CfResult res = HcfCmsGeneratorSpiCreate(ENVELOPED_DATA, &cmsGenerator);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsGenerator, nullptr);

    res = HcfX509CertificateCreate(&g_inCertEccP1PemStream, &x509Cert);
    EXPECT_EQ(res, CF_SUCCESS);
    ASSERT_NE(x509Cert, nullptr);

    CmsRecipientInfo *recipientInfo = nullptr;
    recipientInfo = (CmsRecipientInfo *)CfMallocEx(sizeof(CmsRecipientInfo));
    EXPECT_NE(recipientInfo, nullptr);

    recipientInfo->keyAgreeInfo = nullptr;
    recipientInfo->keyAgreeInfo = (KeyAgreeRecipientInfo *)CfMallocEx(sizeof(KeyAgreeRecipientInfo));
    EXPECT_NE(recipientInfo->keyAgreeInfo, nullptr);
    recipientInfo->keyAgreeInfo->recipientCert = &(x509Cert->base);
    recipientInfo->keyAgreeInfo->digestAlgorithm = CMS_SHA256;
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), CfIsClassMatch(_, _))
        .WillOnce(Return(false))
        .WillRepeatedly(Invoke(__real_CfIsClassMatch));
    res = cmsGenerator->engineAddRecipientInfo(cmsGenerator, recipientInfo);
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);
    X509OpensslMock::SetMockFlag(false);
    
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), CfIsClassMatch(_, _))
        .WillOnce(Return(false))
        .WillRepeatedly(Invoke(__real_CfIsClassMatch));
    res = cmsGenerator->engineSetRecipientEncryptionAlgorithm(cmsGenerator, CMS_AES_256_GCM);
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);
    X509OpensslMock::SetMockFlag(false);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), CfIsClassMatch(_, _))
        .WillOnce(Return(false))
        .WillRepeatedly(Invoke(__real_CfIsClassMatch));
    res = cmsGenerator->engineGetEncryptedContentData(cmsGenerator, &out);
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);
    X509OpensslMock::SetMockFlag(false);

    FreeTestRecipientInfo(recipientInfo);
    CfObjDestroy(x509Cert);
    CfObjDestroy(cmsGenerator);
}
}