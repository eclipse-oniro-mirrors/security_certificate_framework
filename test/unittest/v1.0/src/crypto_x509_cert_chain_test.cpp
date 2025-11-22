/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "certificate_openssl_common.h"
#include "cf_blob.h"
#include "cf_log.h"
#include "cf_mock.h"
#include "cf_object_base.h"
#include "cf_result.h"
#include "crypto_x509_test_common.h"
#include "memory_mock.h"
#include "securec.h"
#include "string"
#include "x509_trust_anchor.h"
#include "x509_cert_chain.h"
#include "x509_cert_chain_openssl.h"
#include "x509_certificate_openssl.h"
#include "crypto_x509_cert_chain_data_pem.h"
#include "crypto_x509_cert_chain_data_pem_added.h"
#include "cert_crl_common.h"
#include "fwk_class.h"

#define OID_STR_MAX_LEN 128
#define MAX_CERT_NUM 256
#define DEMO_CERT_ARRAY_SIZE 2

using namespace std;
using namespace testing::ext;
using namespace CFMock;

using ::testing::_;
using ::testing::AnyNumber;
using ::testing::Invoke;
using ::testing::Return;

namespace {
class CryptoX509CertChainTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

static HcfCertChain *g_certChainP7b = nullptr;
static HcfX509Certificate *g_x509CertObj = nullptr;
static HcfX509CertChainSpi *g_certChainP7bSpi = nullptr;
static HcfX509CertChainSpi *g_certChainPemSpi = nullptr;
static HcfX509CertChainSpi *g_certChainDerSpi = nullptr;
constexpr uint32_t TEST_MAX_CERT_NUM = 257; /* max certs number of a certchain */

#define CERT_VERIFY_DIR "/etc/security/certificates"

static const char TEST_CERT_CHAIN_PEM[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIIJ7DCCCNSgAwIBAgIMTkADpl62gfh/S9jrMA0GCSqGSIb3DQEBCwUAMFAxCzAJ\r\n"
    "BgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSYwJAYDVQQDEx1H\r\n"
    "bG9iYWxTaWduIFJTQSBPViBTU0wgQ0EgMjAxODAeFw0yNDA3MDgwMTQxMDJaFw0y\r\n"
    "NTA4MDkwMTQxMDFaMIGAMQswCQYDVQQGEwJDTjEQMA4GA1UECBMHYmVpamluZzEQ\r\n"
    "MA4GA1UEBxMHYmVpamluZzE5MDcGA1UEChMwQmVpamluZyBCYWlkdSBOZXRjb20g\r\n"
    "U2NpZW5jZSBUZWNobm9sb2d5IENvLiwgTHRkMRIwEAYDVQQDEwliYWlkdS5jb20w\r\n"
    "ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC1wFMskJ2dseOqoHptNwot\r\n"
    "FOhdBERsZ4VQnRNKXEEXMQEfgbNtScQ+C/Z+IpRAt1EObhYlifn74kt2nTsCQLng\r\n"
    "jfQkRVBuO/6PNGKdlCYGBeGqAL7xR+LOyHnpH9mwCBJc+WVt2zYM9I1clpXCJa+I\r\n"
    "tsq6qpb1AGoQxRDZ2n4K8Gd61wgNCPHDHc/Lk9NPJoUBMvYWvEe5lKhHsJtWtHe4\r\n"
    "QC3y58Vi+r5R0PWn2hyTBr9fCo58p/stDiRqp9Irtmi95YhwkNkmgwpMB8RhcGoN\r\n"
    "h+Uw5TkPZVj4AVaoPT1ED/GMKZev0+ypmp0+nmjVg2x7yUfLUfp3X7oBdI4TS2hv\r\n"
    "AgMBAAGjggaTMIIGjzAOBgNVHQ8BAf8EBAMCBaAwDAYDVR0TAQH/BAIwADCBjgYI\r\n"
    "KwYBBQUHAQEEgYEwfzBEBggrBgEFBQcwAoY4aHR0cDovL3NlY3VyZS5nbG9iYWxz\r\n"
    "aWduLmNvbS9jYWNlcnQvZ3Nyc2FvdnNzbGNhMjAxOC5jcnQwNwYIKwYBBQUHMAGG\r\n"
    "K2h0dHA6Ly9vY3NwLmdsb2JhbHNpZ24uY29tL2dzcnNhb3Zzc2xjYTIwMTgwVgYD\r\n"
    "VR0gBE8wTTBBBgkrBgEEAaAyARQwNDAyBggrBgEFBQcCARYmaHR0cHM6Ly93d3cu\r\n"
    "Z2xvYmFsc2lnbi5jb20vcmVwb3NpdG9yeS8wCAYGZ4EMAQICMD8GA1UdHwQ4MDYw\r\n"
    "NKAyoDCGLmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3Nyc2FvdnNzbGNhMjAx\r\n"
    "OC5jcmwwggNhBgNVHREEggNYMIIDVIIJYmFpZHUuY29tggxiYWlmdWJhby5jb22C\r\n"
    "DHd3dy5iYWlkdS5jboIQd3d3LmJhaWR1LmNvbS5jboIPbWN0LnkubnVvbWkuY29t\r\n"
    "ggthcG9sbG8uYXV0b4IGZHd6LmNuggsqLmJhaWR1LmNvbYIOKi5iYWlmdWJhby5j\r\n"
    "b22CESouYmFpZHVzdGF0aWMuY29tgg4qLmJkc3RhdGljLmNvbYILKi5iZGltZy5j\r\n"
    "b22CDCouaGFvMTIzLmNvbYILKi5udW9taS5jb22CDSouY2h1YW5rZS5jb22CDSou\r\n"
    "dHJ1c3Rnby5jb22CDyouYmNlLmJhaWR1LmNvbYIQKi5leXVuLmJhaWR1LmNvbYIP\r\n"
    "Ki5tYXAuYmFpZHUuY29tgg8qLm1iZC5iYWlkdS5jb22CESouZmFueWkuYmFpZHUu\r\n"
    "Y29tgg4qLmJhaWR1YmNlLmNvbYIMKi5taXBjZG4uY29tghAqLm5ld3MuYmFpZHUu\r\n"
    "Y29tgg4qLmJhaWR1cGNzLmNvbYIMKi5haXBhZ2UuY29tggsqLmFpcGFnZS5jboIN\r\n"
    "Ki5iY2Vob3N0LmNvbYIQKi5zYWZlLmJhaWR1LmNvbYIOKi5pbS5iYWlkdS5jb22C\r\n"
    "EiouYmFpZHVjb250ZW50LmNvbYILKi5kbG5lbC5jb22CCyouZGxuZWwub3JnghIq\r\n"
    "LmR1ZXJvcy5iYWlkdS5jb22CDiouc3UuYmFpZHUuY29tgggqLjkxLmNvbYISKi5o\r\n"
    "YW8xMjMuYmFpZHUuY29tgg0qLmFwb2xsby5hdXRvghIqLnh1ZXNodS5iYWlkdS5j\r\n"
    "b22CESouYmouYmFpZHViY2UuY29tghEqLmd6LmJhaWR1YmNlLmNvbYIOKi5zbWFy\r\n"
    "dGFwcHMuY26CDSouYmR0anJjdi5jb22CDCouaGFvMjIyLmNvbYIMKi5oYW9rYW4u\r\n"
    "Y29tgg8qLnBhZS5iYWlkdS5jb22CESoudmQuYmRzdGF0aWMuY29tghEqLmNsb3Vk\r\n"
    "LmJhaWR1LmNvbYISY2xpY2suaG0uYmFpZHUuY29tghBsb2cuaG0uYmFpZHUuY29t\r\n"
    "ghBjbS5wb3MuYmFpZHUuY29tghB3bi5wb3MuYmFpZHUuY29tghR1cGRhdGUucGFu\r\n"
    "LmJhaWR1LmNvbTAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwHwYDVR0j\r\n"
    "BBgwFoAU+O9/8s14Z6jeb48kjYjxhwMCs+swHQYDVR0OBBYEFK3KAFTK2OWUto+D\r\n"
    "2ieAKE5ZJDsYMIIBfwYKKwYBBAHWeQIEAgSCAW8EggFrAWkAdgCvGBoo1oyj4KmK\r\n"
    "TJxnqwn4u7wiuq68sTijoZ3T+bYDDQAAAZCQAGzzAAAEAwBHMEUCIFwF5Jc+zyIF\r\n"
    "Gnpxchz9fY1qzlqg/oVrs2nnuxcpBuuIAiEAu3scD6u51VOP/9aMSqR2yKHZLbHw\r\n"
    "Fos9U7AzSdLIZa8AdgAS8U40vVNyTIQGGcOPP3oT+Oe1YoeInG0wBYTr5YYmOgAA\r\n"
    "AZCQAG3iAAAEAwBHMEUCIBBYQ6NP7VUDgfktWRg5QxT23QAbTqYovtV2D9O8Qc0T\r\n"
    "AiEA2P7+44EvQ5adwL1y56oyxv/m+Gujeia7wpo7+Xbhv6MAdwAN4fIwK9MNwUBi\r\n"
    "EgnqVS78R3R8sdfpMO8OQh60fk6qNAAAAZCQAGy+AAAEAwBIMEYCIQDU7Hxtx4c9\r\n"
    "p9Jd+cr+DCMtyRYSc0b8cktCcbMmtDE9ygIhAIpJd4yb7jtxnaEC8oLWDushbK1v\r\n"
    "0BIuZu6YrQvsf1nQMA0GCSqGSIb3DQEBCwUAA4IBAQCh9DfewC012/+fHZpmSpCn\r\n"
    "y+h3/+ClAZ8cJVO+LCmYz9r6bkyhcFquJ5qUpyoW8AYtU0oUFlqH6zLIyujW+7lq\r\n"
    "wFxB6NsXKKdwBKmMbmnZr2Fca5f+TtwD/GDJgG/egr7fI1u8194j9KEl8cK8Fujm\r\n"
    "+UsoWklEzd1It9xkLazJR/6SwbhSR4k610pvj8rQrS4wAewuYFDaDOfqsHtDIsx1\r\n"
    "tZfIfoB/O1wGWZQJU2M9wC8uYq0jQ2Q0MQJXuyJz04MFiGrPAS1Uk8mWd8M+3p65\r\n"
    "Xy4iAf8uWzs1M+fcwBE8BNBghkQgE+FSUsldm+5ZBCazU0joJswzldWisXMLTagI\r\n"
    "-----END CERTIFICATE-----\r\n"
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIIETjCCAzagAwIBAgINAe5fIh38YjvUMzqFVzANBgkqhkiG9w0BAQsFADBMMSAw\r\n"
    "HgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMzETMBEGA1UEChMKR2xvYmFs\r\n"
    "U2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0xODExMjEwMDAwMDBaFw0yODEx\r\n"
    "MjEwMDAwMDBaMFAxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52\r\n"
    "LXNhMSYwJAYDVQQDEx1HbG9iYWxTaWduIFJTQSBPViBTU0wgQ0EgMjAxODCCASIw\r\n"
    "DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKdaydUMGCEAI9WXD+uu3Vxoa2uP\r\n"
    "UGATeoHLl+6OimGUSyZ59gSnKvuk2la77qCk8HuKf1UfR5NhDW5xUTolJAgvjOH3\r\n"
    "idaSz6+zpz8w7bXfIa7+9UQX/dhj2S/TgVprX9NHsKzyqzskeU8fxy7quRU6fBhM\r\n"
    "abO1IFkJXinDY+YuRluqlJBJDrnw9UqhCS98NE3QvADFBlV5Bs6i0BDxSEPouVq1\r\n"
    "lVW9MdIbPYa+oewNEtssmSStR8JvA+Z6cLVwzM0nLKWMjsIYPJLJLnNvBhBWk0Cq\r\n"
    "o8VS++XFBdZpaFwGue5RieGKDkFNm5KQConpFmvv73W+eka440eKHRwup08CAwEA\r\n"
    "AaOCASkwggElMA4GA1UdDwEB/wQEAwIBhjASBgNVHRMBAf8ECDAGAQH/AgEAMB0G\r\n"
    "A1UdDgQWBBT473/yzXhnqN5vjySNiPGHAwKz6zAfBgNVHSMEGDAWgBSP8Et/qC5F\r\n"
    "JK5NUPpjmove4t0bvDA+BggrBgEFBQcBAQQyMDAwLgYIKwYBBQUHMAGGImh0dHA6\r\n"
    "Ly9vY3NwMi5nbG9iYWxzaWduLmNvbS9yb290cjMwNgYDVR0fBC8wLTAroCmgJ4Yl\r\n"
    "aHR0cDovL2NybC5nbG9iYWxzaWduLmNvbS9yb290LXIzLmNybDBHBgNVHSAEQDA+\r\n"
    "MDwGBFUdIAAwNDAyBggrBgEFBQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFsc2lnbi5j\r\n"
    "b20vcmVwb3NpdG9yeS8wDQYJKoZIhvcNAQELBQADggEBAJmQyC1fQorUC2bbmANz\r\n"
    "EdSIhlIoU4r7rd/9c446ZwTbw1MUcBQJfMPg+NccmBqixD7b6QDjynCy8SIwIVbb\r\n"
    "0615XoFYC20UgDX1b10d65pHBf9ZjQCxQNqQmJYaumxtf4z1s4DfjGRzNpZ5eWl0\r\n"
    "6r/4ngGPoJVpjemEuunl1Ig423g7mNA2eymw0lIYkN5SQwCuaifIFJ6GlazhgDEw\r\n"
    "fpolu4usBCOmmQDo8dIm7A9+O4orkjgTHY+GzYZSR+Y0fFukAj6KYXwidlNalFMz\r\n"
    "hriSqHKvoflShx8xpfywgVcvzfTO3PYkz6fiNJBonf6q8amaEsybwMbDqKWwIX7e\r\n"
    "SPY=\r\n"
    "-----END CERTIFICATE-----\r\n"
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIIDXzCCAkegAwIBAgILBAAAAAABIVhTCKIwDQYJKoZIhvcNAQELBQAwTDEgMB4G\r\n"
    "A1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjMxEzARBgNVBAoTCkdsb2JhbFNp\r\n"
    "Z24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMDkwMzE4MTAwMDAwWhcNMjkwMzE4\r\n"
    "MTAwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMzETMBEG\r\n"
    "A1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZI\r\n"
    "hvcNAQEBBQADggEPADCCAQoCggEBAMwldpB5BngiFvXAg7aEyiie/QV2EcWtiHL8\r\n"
    "RgJDx7KKnQRfJMsuS+FggkbhUqsMgUdwbN1k0ev1LKMPgj0MK66X17YUhhB5uzsT\r\n"
    "gHeMCOFJ0mpiLx9e+pZo34knlTifBtc+ycsmWQ1z3rDI6SYOgxXG71uL0gRgykmm\r\n"
    "KPZpO/bLyCiR5Z2KYVc3rHQU3HTgOu5yLy6c+9C7v/U9AOEGM+iCK65TpjoWc4zd\r\n"
    "QQ4gOsC0p6Hpsk+QLjJg6VfLuQSSaGjlOCZgdbKfd/+RFO+uIEn8rUAVSNECMWEZ\r\n"
    "XriX7613t2Saer9fwRPvm2L7DWzgVGkWqQPabumDk3F2xmmFghcCAwEAAaNCMEAw\r\n"
    "DgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFI/wS3+o\r\n"
    "LkUkrk1Q+mOai97i3Ru8MA0GCSqGSIb3DQEBCwUAA4IBAQBLQNvAUKr+yAzv95ZU\r\n"
    "RUm7lgAJQayzE4aGKAczymvmdLm6AC2upArT9fHxD4q/c2dKg8dEe3jgr25sbwMp\r\n"
    "jjM5RcOO5LlXbKr8EpbsU8Yt5CRsuZRj+9xTaGdWPoO4zzUhw8lo/s7awlOqzJCK\r\n"
    "6fBdRoyV3XpYKBovHd7NADdBj+1EbddTKJd+82cEHhXXipa0095MJ6RMG3NzdvQX\r\n"
    "mcIfeg7jLQitChws/zyrVQ4PkX4268NXSb7hLi18YIvDQVETI53O9zJrlAGomecs\r\n"
    "Mx86OyXShkDOOyyGeMlhLxS67ttVb9+E7gUJTb0o2HLO02JQZR7rkpeDMdmztcpH\r\n"
    "WD9f\r\n"
    "-----END CERTIFICATE-----\r\n";

static const char TEST_CERT_CHAIN_PEM_NOT_ROOT[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIIJ7DCCCNSgAwIBAgIMTkADpl62gfh/S9jrMA0GCSqGSIb3DQEBCwUAMFAxCzAJ\r\n"
    "BgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSYwJAYDVQQDEx1H\r\n"
    "bG9iYWxTaWduIFJTQSBPViBTU0wgQ0EgMjAxODAeFw0yNDA3MDgwMTQxMDJaFw0y\r\n"
    "NTA4MDkwMTQxMDFaMIGAMQswCQYDVQQGEwJDTjEQMA4GA1UECBMHYmVpamluZzEQ\r\n"
    "MA4GA1UEBxMHYmVpamluZzE5MDcGA1UEChMwQmVpamluZyBCYWlkdSBOZXRjb20g\r\n"
    "U2NpZW5jZSBUZWNobm9sb2d5IENvLiwgTHRkMRIwEAYDVQQDEwliYWlkdS5jb20w\r\n"
    "ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC1wFMskJ2dseOqoHptNwot\r\n"
    "FOhdBERsZ4VQnRNKXEEXMQEfgbNtScQ+C/Z+IpRAt1EObhYlifn74kt2nTsCQLng\r\n"
    "jfQkRVBuO/6PNGKdlCYGBeGqAL7xR+LOyHnpH9mwCBJc+WVt2zYM9I1clpXCJa+I\r\n"
    "tsq6qpb1AGoQxRDZ2n4K8Gd61wgNCPHDHc/Lk9NPJoUBMvYWvEe5lKhHsJtWtHe4\r\n"
    "QC3y58Vi+r5R0PWn2hyTBr9fCo58p/stDiRqp9Irtmi95YhwkNkmgwpMB8RhcGoN\r\n"
    "h+Uw5TkPZVj4AVaoPT1ED/GMKZev0+ypmp0+nmjVg2x7yUfLUfp3X7oBdI4TS2hv\r\n"
    "AgMBAAGjggaTMIIGjzAOBgNVHQ8BAf8EBAMCBaAwDAYDVR0TAQH/BAIwADCBjgYI\r\n"
    "KwYBBQUHAQEEgYEwfzBEBggrBgEFBQcwAoY4aHR0cDovL3NlY3VyZS5nbG9iYWxz\r\n"
    "aWduLmNvbS9jYWNlcnQvZ3Nyc2FvdnNzbGNhMjAxOC5jcnQwNwYIKwYBBQUHMAGG\r\n"
    "K2h0dHA6Ly9vY3NwLmdsb2JhbHNpZ24uY29tL2dzcnNhb3Zzc2xjYTIwMTgwVgYD\r\n"
    "VR0gBE8wTTBBBgkrBgEEAaAyARQwNDAyBggrBgEFBQcCARYmaHR0cHM6Ly93d3cu\r\n"
    "Z2xvYmFsc2lnbi5jb20vcmVwb3NpdG9yeS8wCAYGZ4EMAQICMD8GA1UdHwQ4MDYw\r\n"
    "NKAyoDCGLmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3Nyc2FvdnNzbGNhMjAx\r\n"
    "OC5jcmwwggNhBgNVHREEggNYMIIDVIIJYmFpZHUuY29tggxiYWlmdWJhby5jb22C\r\n"
    "DHd3dy5iYWlkdS5jboIQd3d3LmJhaWR1LmNvbS5jboIPbWN0LnkubnVvbWkuY29t\r\n"
    "ggthcG9sbG8uYXV0b4IGZHd6LmNuggsqLmJhaWR1LmNvbYIOKi5iYWlmdWJhby5j\r\n"
    "b22CESouYmFpZHVzdGF0aWMuY29tgg4qLmJkc3RhdGljLmNvbYILKi5iZGltZy5j\r\n"
    "b22CDCouaGFvMTIzLmNvbYILKi5udW9taS5jb22CDSouY2h1YW5rZS5jb22CDSou\r\n"
    "dHJ1c3Rnby5jb22CDyouYmNlLmJhaWR1LmNvbYIQKi5leXVuLmJhaWR1LmNvbYIP\r\n"
    "Ki5tYXAuYmFpZHUuY29tgg8qLm1iZC5iYWlkdS5jb22CESouZmFueWkuYmFpZHUu\r\n"
    "Y29tgg4qLmJhaWR1YmNlLmNvbYIMKi5taXBjZG4uY29tghAqLm5ld3MuYmFpZHUu\r\n"
    "Y29tgg4qLmJhaWR1cGNzLmNvbYIMKi5haXBhZ2UuY29tggsqLmFpcGFnZS5jboIN\r\n"
    "Ki5iY2Vob3N0LmNvbYIQKi5zYWZlLmJhaWR1LmNvbYIOKi5pbS5iYWlkdS5jb22C\r\n"
    "EiouYmFpZHVjb250ZW50LmNvbYILKi5kbG5lbC5jb22CCyouZGxuZWwub3JnghIq\r\n"
    "LmR1ZXJvcy5iYWlkdS5jb22CDiouc3UuYmFpZHUuY29tgggqLjkxLmNvbYISKi5o\r\n"
    "YW8xMjMuYmFpZHUuY29tgg0qLmFwb2xsby5hdXRvghIqLnh1ZXNodS5iYWlkdS5j\r\n"
    "b22CESouYmouYmFpZHViY2UuY29tghEqLmd6LmJhaWR1YmNlLmNvbYIOKi5zbWFy\r\n"
    "dGFwcHMuY26CDSouYmR0anJjdi5jb22CDCouaGFvMjIyLmNvbYIMKi5oYW9rYW4u\r\n"
    "Y29tgg8qLnBhZS5iYWlkdS5jb22CESoudmQuYmRzdGF0aWMuY29tghEqLmNsb3Vk\r\n"
    "LmJhaWR1LmNvbYISY2xpY2suaG0uYmFpZHUuY29tghBsb2cuaG0uYmFpZHUuY29t\r\n"
    "ghBjbS5wb3MuYmFpZHUuY29tghB3bi5wb3MuYmFpZHUuY29tghR1cGRhdGUucGFu\r\n"
    "LmJhaWR1LmNvbTAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwHwYDVR0j\r\n"
    "BBgwFoAU+O9/8s14Z6jeb48kjYjxhwMCs+swHQYDVR0OBBYEFK3KAFTK2OWUto+D\r\n"
    "2ieAKE5ZJDsYMIIBfwYKKwYBBAHWeQIEAgSCAW8EggFrAWkAdgCvGBoo1oyj4KmK\r\n"
    "TJxnqwn4u7wiuq68sTijoZ3T+bYDDQAAAZCQAGzzAAAEAwBHMEUCIFwF5Jc+zyIF\r\n"
    "Gnpxchz9fY1qzlqg/oVrs2nnuxcpBuuIAiEAu3scD6u51VOP/9aMSqR2yKHZLbHw\r\n"
    "Fos9U7AzSdLIZa8AdgAS8U40vVNyTIQGGcOPP3oT+Oe1YoeInG0wBYTr5YYmOgAA\r\n"
    "AZCQAG3iAAAEAwBHMEUCIBBYQ6NP7VUDgfktWRg5QxT23QAbTqYovtV2D9O8Qc0T\r\n"
    "AiEA2P7+44EvQ5adwL1y56oyxv/m+Gujeia7wpo7+Xbhv6MAdwAN4fIwK9MNwUBi\r\n"
    "EgnqVS78R3R8sdfpMO8OQh60fk6qNAAAAZCQAGy+AAAEAwBIMEYCIQDU7Hxtx4c9\r\n"
    "p9Jd+cr+DCMtyRYSc0b8cktCcbMmtDE9ygIhAIpJd4yb7jtxnaEC8oLWDushbK1v\r\n"
    "0BIuZu6YrQvsf1nQMA0GCSqGSIb3DQEBCwUAA4IBAQCh9DfewC012/+fHZpmSpCn\r\n"
    "y+h3/+ClAZ8cJVO+LCmYz9r6bkyhcFquJ5qUpyoW8AYtU0oUFlqH6zLIyujW+7lq\r\n"
    "wFxB6NsXKKdwBKmMbmnZr2Fca5f+TtwD/GDJgG/egr7fI1u8194j9KEl8cK8Fujm\r\n"
    "+UsoWklEzd1It9xkLazJR/6SwbhSR4k610pvj8rQrS4wAewuYFDaDOfqsHtDIsx1\r\n"
    "tZfIfoB/O1wGWZQJU2M9wC8uYq0jQ2Q0MQJXuyJz04MFiGrPAS1Uk8mWd8M+3p65\r\n"
    "Xy4iAf8uWzs1M+fcwBE8BNBghkQgE+FSUsldm+5ZBCazU0joJswzldWisXMLTagI\r\n"
    "-----END CERTIFICATE-----\r\n"
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIIETjCCAzagAwIBAgINAe5fIh38YjvUMzqFVzANBgkqhkiG9w0BAQsFADBMMSAw\r\n"
    "HgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMzETMBEGA1UEChMKR2xvYmFs\r\n"
    "U2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0xODExMjEwMDAwMDBaFw0yODEx\r\n"
    "MjEwMDAwMDBaMFAxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52\r\n"
    "LXNhMSYwJAYDVQQDEx1HbG9iYWxTaWduIFJTQSBPViBTU0wgQ0EgMjAxODCCASIw\r\n"
    "DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKdaydUMGCEAI9WXD+uu3Vxoa2uP\r\n"
    "UGATeoHLl+6OimGUSyZ59gSnKvuk2la77qCk8HuKf1UfR5NhDW5xUTolJAgvjOH3\r\n"
    "idaSz6+zpz8w7bXfIa7+9UQX/dhj2S/TgVprX9NHsKzyqzskeU8fxy7quRU6fBhM\r\n"
    "abO1IFkJXinDY+YuRluqlJBJDrnw9UqhCS98NE3QvADFBlV5Bs6i0BDxSEPouVq1\r\n"
    "lVW9MdIbPYa+oewNEtssmSStR8JvA+Z6cLVwzM0nLKWMjsIYPJLJLnNvBhBWk0Cq\r\n"
    "o8VS++XFBdZpaFwGue5RieGKDkFNm5KQConpFmvv73W+eka440eKHRwup08CAwEA\r\n"
    "AaOCASkwggElMA4GA1UdDwEB/wQEAwIBhjASBgNVHRMBAf8ECDAGAQH/AgEAMB0G\r\n"
    "A1UdDgQWBBT473/yzXhnqN5vjySNiPGHAwKz6zAfBgNVHSMEGDAWgBSP8Et/qC5F\r\n"
    "JK5NUPpjmove4t0bvDA+BggrBgEFBQcBAQQyMDAwLgYIKwYBBQUHMAGGImh0dHA6\r\n"
    "Ly9vY3NwMi5nbG9iYWxzaWduLmNvbS9yb290cjMwNgYDVR0fBC8wLTAroCmgJ4Yl\r\n"
    "aHR0cDovL2NybC5nbG9iYWxzaWduLmNvbS9yb290LXIzLmNybDBHBgNVHSAEQDA+\r\n"
    "MDwGBFUdIAAwNDAyBggrBgEFBQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFsc2lnbi5j\r\n"
    "b20vcmVwb3NpdG9yeS8wDQYJKoZIhvcNAQELBQADggEBAJmQyC1fQorUC2bbmANz\r\n"
    "EdSIhlIoU4r7rd/9c446ZwTbw1MUcBQJfMPg+NccmBqixD7b6QDjynCy8SIwIVbb\r\n"
    "0615XoFYC20UgDX1b10d65pHBf9ZjQCxQNqQmJYaumxtf4z1s4DfjGRzNpZ5eWl0\r\n"
    "6r/4ngGPoJVpjemEuunl1Ig423g7mNA2eymw0lIYkN5SQwCuaifIFJ6GlazhgDEw\r\n"
    "fpolu4usBCOmmQDo8dIm7A9+O4orkjgTHY+GzYZSR+Y0fFukAj6KYXwidlNalFMz\r\n"
    "hriSqHKvoflShx8xpfywgVcvzfTO3PYkz6fiNJBonf6q8amaEsybwMbDqKWwIX7e\r\n"
    "SPY=\r\n"
    "-----END CERTIFICATE-----\r\n";

static const char TEST_CERT_CHAIN_PEM_ROOT[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIIDXzCCAkegAwIBAgILBAAAAAABIVhTCKIwDQYJKoZIhvcNAQELBQAwTDEgMB4G\r\n"
    "A1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjMxEzARBgNVBAoTCkdsb2JhbFNp\r\n"
    "Z24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMDkwMzE4MTAwMDAwWhcNMjkwMzE4\r\n"
    "MTAwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMzETMBEG\r\n"
    "A1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZI\r\n"
    "hvcNAQEBBQADggEPADCCAQoCggEBAMwldpB5BngiFvXAg7aEyiie/QV2EcWtiHL8\r\n"
    "RgJDx7KKnQRfJMsuS+FggkbhUqsMgUdwbN1k0ev1LKMPgj0MK66X17YUhhB5uzsT\r\n"
    "gHeMCOFJ0mpiLx9e+pZo34knlTifBtc+ycsmWQ1z3rDI6SYOgxXG71uL0gRgykmm\r\n"
    "KPZpO/bLyCiR5Z2KYVc3rHQU3HTgOu5yLy6c+9C7v/U9AOEGM+iCK65TpjoWc4zd\r\n"
    "QQ4gOsC0p6Hpsk+QLjJg6VfLuQSSaGjlOCZgdbKfd/+RFO+uIEn8rUAVSNECMWEZ\r\n"
    "XriX7613t2Saer9fwRPvm2L7DWzgVGkWqQPabumDk3F2xmmFghcCAwEAAaNCMEAw\r\n"
    "DgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFI/wS3+o\r\n"
    "LkUkrk1Q+mOai97i3Ru8MA0GCSqGSIb3DQEBCwUAA4IBAQBLQNvAUKr+yAzv95ZU\r\n"
    "RUm7lgAJQayzE4aGKAczymvmdLm6AC2upArT9fHxD4q/c2dKg8dEe3jgr25sbwMp\r\n"
    "jjM5RcOO5LlXbKr8EpbsU8Yt5CRsuZRj+9xTaGdWPoO4zzUhw8lo/s7awlOqzJCK\r\n"
    "6fBdRoyV3XpYKBovHd7NADdBj+1EbddTKJd+82cEHhXXipa0095MJ6RMG3NzdvQX\r\n"
    "mcIfeg7jLQitChws/zyrVQ4PkX4268NXSb7hLi18YIvDQVETI53O9zJrlAGomecs\r\n"
    "Mx86OyXShkDOOyyGeMlhLxS67ttVb9+E7gUJTb0o2HLO02JQZR7rkpeDMdmztcpH\r\n"
    "WD9f\r\n"
    "-----END CERTIFICATE-----\r\n";

static const char *GetInvalidCertChainClass(void)
{
    return "HcfInvalidCertChain";
}

void CryptoX509CertChainTest::SetUpTestCase()
{
    CfResult ret = HcfCertChainCreate(&g_inStreamChainDataP7b, nullptr, &g_certChainP7b);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(g_certChainP7b, nullptr);

    HcfX509Certificate *x509CertObj = nullptr;
    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testSelfSignedCaCert));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testSelfSignedCaCert) + 1;
    (void)HcfX509CertificateCreate(&inStream, &x509CertObj);
    ASSERT_NE(x509CertObj, nullptr);
    g_x509CertObj = x509CertObj;

    HcfX509CertChainSpi *certChainSpi = nullptr;
    ret = HcfX509CertChainByEncSpiCreate(&g_inStreamChainDataP7b, &certChainSpi);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainSpi, nullptr);
    g_certChainP7bSpi = certChainSpi;
    certChainSpi = nullptr;
    ret = HcfX509CertChainByEncSpiCreate(&g_inStreamChainDataPem, &certChainSpi);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainSpi, nullptr);
    g_certChainPemSpi = certChainSpi;
    certChainSpi = nullptr;
    ret = HcfX509CertChainByEncSpiCreate(&g_inStreamChainDataDer, &certChainSpi);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainSpi, nullptr);
    g_certChainDerSpi = certChainSpi;
}

void CryptoX509CertChainTest::TearDownTestCase()
{
    CfObjDestroy(g_x509CertObj);
    CfObjDestroy(g_certChainP7b);
    CfObjDestroy(g_certChainP7bSpi);
    CfObjDestroy(g_certChainPemSpi);
    CfObjDestroy(g_certChainDerSpi);
}

void CryptoX509CertChainTest::SetUp() {}

void CryptoX509CertChainTest::TearDown() {}

/* invalid encodingBlob. */
HWTEST_F(CryptoX509CertChainTest, CertChainByEncSpiCreateTest001, TestSize.Level0)
{
    HcfX509CertChainSpi *certChainSpi = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(nullptr, &certChainSpi);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);
}

/* invalid certChainSpi. */
HWTEST_F(CryptoX509CertChainTest, CertChainByEncSpiCreateTest002, TestSize.Level0)
{
    CfResult ret = HcfX509CertChainByEncSpiCreate(&g_inStreamChainDataP7b, nullptr);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);
}

/* The encoding format is CF_FORMAT_PKCS7 */
HWTEST_F(CryptoX509CertChainTest, CertChainByEncSpiCreateTest003, TestSize.Level0)
{
    HcfX509CertChainSpi *certChainSpi = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&g_inStreamChainDataP7b, &certChainSpi);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainSpi, nullptr);

    CfObjDestroy(certChainSpi);
}

HWTEST_F(CryptoX509CertChainTest, CertChainByEncSpiCreateTest004, TestSize.Level0)
{
    HcfX509CertChainSpi *certChainSpi = nullptr;
    CfEncodingBlob inStream = { nullptr, 0, CF_FORMAT_PKCS7 };
    inStream.data = static_cast<uint8_t *>(CfMalloc(g_inStreamChainDataP7b.len, 0));
    ASSERT_NE(inStream.data, nullptr);
    memcpy_s(inStream.data, g_inStreamChainDataP7b.len, g_inStreamChainDataP7b.data, g_inStreamChainDataP7b.len);
    inStream.len = g_inStreamChainDataP7b.len;
    inStream.encodingFormat = g_inStreamChainDataP7b.encodingFormat;
    inStream.data[0] = 0x77; // magic code 0x77

    CfResult ret = HcfX509CertChainByEncSpiCreate(&inStream, &certChainSpi);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);

    CfFree(inStream.data);
}

HWTEST_F(CryptoX509CertChainTest, CertChainByEncSpiCreateTest005, TestSize.Level0)
{
    HcfX509CertChainSpi *certChainSpi = nullptr;
    CfEncodingBlob inStream = { nullptr, 0, CF_FORMAT_PKCS7 };
    inStream.data = static_cast<uint8_t *>(CfMalloc(g_inStreamChainDataDer.len, 0));
    ASSERT_NE(inStream.data, nullptr);
    memcpy_s(inStream.data, g_inStreamChainDataDer.len, g_inStreamChainDataDer.data, g_inStreamChainDataDer.len);
    inStream.len = g_inStreamChainDataDer.len;

    CfResult ret = HcfX509CertChainByEncSpiCreate(&inStream, &certChainSpi);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);

    CfFree(inStream.data);
}

HWTEST_F(CryptoX509CertChainTest, CertChainByEncSpiCreateTest006, TestSize.Level0)
{
    HcfX509CertChainSpi *certChainSpi = nullptr;
    CfEncodingBlob inStream = { nullptr, 0, CF_FORMAT_PKCS7 };

    CfResult ret = HcfX509CertChainByEncSpiCreate(&inStream, &certChainSpi);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);
}

/* The encoding format is CF_FORMAT_DER */
HWTEST_F(CryptoX509CertChainTest, CertChainByEncSpiCreateTest007, TestSize.Level0)
{
    HcfX509CertChainSpi *certChainSpi = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&g_inStreamChainDataDer, &certChainSpi);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainSpi, nullptr);

    CfObjDestroy(certChainSpi);
}

/* Invalid encoding format. */
HWTEST_F(CryptoX509CertChainTest, CertChainByEncSpiCreateTest008, TestSize.Level0)
{
    HcfX509CertChainSpi *certChainSpi = nullptr;
    CfEncodingBlob inStream = { nullptr, 0, (CfEncodingFormat)(CF_FORMAT_PKCS7 + 1) };
    inStream.data = static_cast<uint8_t *>(CfMalloc(g_inStreamChainDataDer.len, 0));
    memcpy_s(inStream.data, g_inStreamChainDataDer.len, g_inStreamChainDataDer.data, g_inStreamChainDataDer.len);
    inStream.len = g_inStreamChainDataDer.len;

    CfResult ret = HcfX509CertChainByEncSpiCreate(&inStream, &certChainSpi);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);

    CfFree(inStream.data);
}

HWTEST_F(CryptoX509CertChainTest, CertChainByEncSpiCreateTest009, TestSize.Level0)
{
    HcfX509CertChainSpi *certChainSpi = nullptr;
    CfEncodingBlob inStream = { nullptr, 0, CF_FORMAT_PEM };
    inStream.data = static_cast<uint8_t *>(CfMalloc(g_inStreamChainDataPem.len, 0));
    memcpy_s(inStream.data, g_inStreamChainDataDer.len, g_inStreamChainDataPem.data, g_inStreamChainDataPem.len);
    inStream.len = g_inStreamChainDataPem.len;

    CfResult ret = HcfX509CertChainByEncSpiCreate(&inStream, &certChainSpi);
    ASSERT_EQ(ret, CF_SUCCESS);

    CfFree(inStream.data);
    CfObjDestroy(certChainSpi);
}

HWTEST_F(CryptoX509CertChainTest, CertChainByEncSpiCreateTest010, TestSize.Level0)
{
    HcfX509CertChainSpi *certChainSpi = nullptr;
    CfEncodingBlob inStream = { nullptr, 0, CF_FORMAT_PKCS7 };
    inStream.data = static_cast<uint8_t *>(CfMalloc(g_inStreamChainDataDer.len, 0));
    memcpy_s(inStream.data, g_inStreamChainDataDer.len, g_inStreamChainDataDer.data, g_inStreamChainDataDer.len);
    inStream.len = ~0;

    CfResult ret = HcfX509CertChainByEncSpiCreate(&inStream, &certChainSpi);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);

    CfFree(inStream.data);
}

HWTEST_F(CryptoX509CertChainTest, CertChainByEncSpiCreateTest011, TestSize.Level0)
{
    HcfX509CertChainSpi *certChainSpi = nullptr;
    CfEncodingBlob inStream = { nullptr, 0, CF_FORMAT_PEM };

    CfResult ret = HcfX509CertChainByEncSpiCreate(&inStream, &certChainSpi);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);
}

HWTEST_F(CryptoX509CertChainTest, CertChainByEncSpiCreateTest012, TestSize.Level0)
{
    HcfX509CertChainSpi *certChainSpi = nullptr;
    CfEncodingBlob inStream = { nullptr, 0, CF_FORMAT_DER };
    inStream.data = static_cast<uint8_t *>(CfMalloc(g_inStreamChainDataDer.len, 0));
    memcpy_s(inStream.data, g_inStreamChainDataDer.len, g_inStreamChainDataDer.data, g_inStreamChainDataDer.len);
    inStream.len = g_inStreamChainDataDer.len;
    inStream.encodingFormat = g_inStreamChainDataDer.encodingFormat;
    inStream.data[0] = 0x77; // magic code 0x77

    CfResult ret = HcfX509CertChainByEncSpiCreate(&inStream, &certChainSpi);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);

    CfFree(inStream.data);
}

HWTEST_F(CryptoX509CertChainTest, CertChainByEncSpiCreateTest013, TestSize.Level0)
{
    HcfX509CertChainSpi *certChainSpi = nullptr;
    SetMockFlag(true);
    CfResult ret = HcfX509CertChainByEncSpiCreate(&g_inStreamChainDataP7b, &certChainSpi);
    ASSERT_EQ(ret, CF_ERR_MALLOC);
    SetMockFlag(false);
}

HWTEST_F(CryptoX509CertChainTest, CertChainByArrSpiCreateTest001, TestSize.Level0)
{
    HcfX509CertChainSpi *certChainSpi;
    CfResult ret = HcfX509CertChainByArrSpiCreate(nullptr, &certChainSpi);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);
}

HWTEST_F(CryptoX509CertChainTest, CertChainByArrSpiCreateTest002, TestSize.Level0)
{
    HcfX509CertificateArray certArray;
    CfResult ret = HcfX509CertChainByArrSpiCreate(&certArray, nullptr);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);
}

HWTEST_F(CryptoX509CertChainTest, CertChainByArrSpiCreateTest003, TestSize.Level0)
{
    HcfX509CertChainSpi *certChainSpi = nullptr;
    HcfX509CertificateArray certArray;

    HcfX509Certificate *x509CertObj = nullptr;
    (void)HcfX509CertificateCreate(&g_inStreamSelfSignedCaCert, &x509CertObj);

    certArray.data = static_cast<HcfX509Certificate **>(CfMalloc(1 * sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(certArray.data, nullptr);
    certArray.data[0] = x509CertObj;
    certArray.count = 1;

    CfResult ret = HcfX509CertChainByArrSpiCreate(&certArray, &certChainSpi);
    ASSERT_EQ(ret, CF_SUCCESS);

    // free memory
    CfFree(certArray.data);
    CfObjDestroy(x509CertObj);
    CfObjDestroy(certChainSpi);
}

HWTEST_F(CryptoX509CertChainTest, CertChainByArrSpiCreateTest004, TestSize.Level0)
{
    HcfX509CertChainSpi *certChainSpi = nullptr;
    HcfX509CertificateArray certArray;

    HcfX509Certificate *x509CertObj = nullptr;
    CfEncodingBlob inStream = { 0 };
    inStream.data = (uint8_t *)g_testSelfSignedCaCert;
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testSelfSignedCaCert) + 1;
    (void)HcfX509CertificateCreate(&inStream, &x509CertObj);

    certArray.data = static_cast<HcfX509Certificate **>(CfMalloc(1 * sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(certArray.data, nullptr);
    certArray.data[0] = x509CertObj;
    certArray.count = 0;

    CfResult ret = HcfX509CertChainByArrSpiCreate(&certArray, &certChainSpi);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);

    // free memory
    CfFree(certArray.data);
    CfObjDestroy(x509CertObj);
    CfObjDestroy(certChainSpi);
}

HWTEST_F(CryptoX509CertChainTest, CertChainByArrSpiCreateTest005, TestSize.Level0)
{
    HcfX509CertChainSpi *certChainSpi = nullptr;
    HcfX509CertificateArray certArray;

    HcfX509Certificate *x509CertObj = nullptr;
    (void)HcfX509CertificateCreate(&g_inStreamSelfSignedCaCert, &x509CertObj);

    certArray.data = static_cast<HcfX509Certificate **>(CfMalloc(1 * sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(certArray.data, nullptr);
    certArray.data[0] = x509CertObj;
    certArray.count = TEST_MAX_CERT_NUM;

    CfResult ret = HcfX509CertChainByArrSpiCreate(&certArray, &certChainSpi);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);

    // free memory
    CfFree(certArray.data);
    CfObjDestroy(x509CertObj);
    CfObjDestroy(certChainSpi);
}

HWTEST_F(CryptoX509CertChainTest, CertChainByArrSpiCreateTest006, TestSize.Level0)
{
    ASSERT_NE(g_x509CertObj, nullptr);
    HcfX509CertChainSpi *certChainSpi = nullptr;
    HcfX509CertificateArray certArray;

    HcfX509Certificate *x509CertObj = nullptr;
    (void)HcfX509CertificateCreate(&g_inStreamSelfSignedCaCert, &x509CertObj);

    certArray.data = static_cast<HcfX509Certificate **>(CfMalloc(1 * sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(certArray.data, nullptr);
    certArray.data[0] = x509CertObj;
    certArray.count = 1;

    x509CertObj->base.base.getClass = GetInvalidCertClass;
    CfResult ret = HcfX509CertChainByArrSpiCreate(&certArray, &certChainSpi);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);

    x509CertObj->base.base.getClass = g_x509CertObj->base.base.getClass;

    CfFree(certArray.data);
    CfObjDestroy(x509CertObj);
}

HWTEST_F(CryptoX509CertChainTest, CertChainByArrSpiCreateTest007, TestSize.Level0)
{
    HcfX509CertificateArray certArray;
    HcfX509Certificate *x509CertObj = nullptr;
    (void)HcfX509CertificateCreate(&g_inStreamSelfSignedCaCert, &x509CertObj);

    certArray.data = static_cast<HcfX509Certificate **>(CfMalloc(1 * sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(certArray.data, nullptr);
    certArray.data[0] = x509CertObj;
    certArray.count = 1;

    SetMockFlag(true);
    HcfX509CertChainSpi *certChainSpi = nullptr;
    CfResult ret = HcfX509CertChainByArrSpiCreate(&certArray, &certChainSpi);
    ASSERT_EQ(ret, CF_ERR_MALLOC);
    SetMockFlag(false);

    CfFree(certArray.data);
    CfObjDestroy(x509CertObj);
}

HWTEST_F(CryptoX509CertChainTest, CertChainCreateTest001, TestSize.Level0)
{
    HcfX509CertificateArray certArray;
    CfResult ret = HcfCertChainCreate(&g_inStreamChainDataP7b, &certArray, nullptr);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);
}

HWTEST_F(CryptoX509CertChainTest, CertChainCreateTest002, TestSize.Level0)
{
    HcfCertChain *pCertChain = nullptr;
    CfResult ret = HcfCertChainCreate(nullptr, nullptr, &pCertChain);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);
}

HWTEST_F(CryptoX509CertChainTest, CertChainCreateTest003, TestSize.Level0)
{
    HcfCertChain *pCertChain = nullptr;
    HcfX509CertificateArray certArray;
    CfResult ret = HcfCertChainCreate(&g_inStreamChainDataP7b, &certArray, &pCertChain);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);
}

HWTEST_F(CryptoX509CertChainTest, CertChainCreateTest004, TestSize.Level0)
{
    HcfCertChain *pCertChain = nullptr;
    CfResult ret = HcfCertChainCreate(&g_inStreamChainDataP7b, nullptr, &pCertChain);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(pCertChain, nullptr);

    CfObjDestroy(pCertChain);
}

HWTEST_F(CryptoX509CertChainTest, CertChainCreateTest005, TestSize.Level0)
{
    HcfCertChain *pCertChain = nullptr;
    CfEncodingBlob inStream = { nullptr, 0, (CfEncodingFormat)(CF_FORMAT_PKCS7 + 1) };
    inStream.data = static_cast<uint8_t *>(CfMalloc(g_inStreamChainDataDer.len, 0));
    memcpy_s(inStream.data, g_inStreamChainDataDer.len, g_inStreamChainDataDer.data, g_inStreamChainDataDer.len);
    inStream.len = g_inStreamChainDataDer.len;

    CfResult ret = HcfCertChainCreate(&inStream, nullptr, &pCertChain);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);

    CfFree(inStream.data);
}

HWTEST_F(CryptoX509CertChainTest, GetCertlistOpensslTest001, TestSize.Level0)
{
    ASSERT_NE(g_certChainP7bSpi, nullptr);
    HcfX509CertificateArray certsList;
    CfResult ret = g_certChainP7bSpi->engineGetCertList(nullptr, &certsList);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);
}

HWTEST_F(CryptoX509CertChainTest, GetCertlistOpensslTest002, TestSize.Level0)
{
    ASSERT_NE(g_certChainP7bSpi, nullptr);
    CfResult ret = g_certChainP7bSpi->engineGetCertList(g_certChainP7bSpi, nullptr);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);
}

HWTEST_F(CryptoX509CertChainTest, GetCertlistOpensslTest003, TestSize.Level0)
{
    ASSERT_NE(g_certChainP7bSpi, nullptr);
    HcfX509CertChainSpi *certChainSpi = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&g_inStreamChainDataP7b, &certChainSpi);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainSpi, nullptr);

    certChainSpi->base.getClass = GetInvalidCertClass;
    ret = certChainSpi->engineGetCertList(certChainSpi, nullptr);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);

    certChainSpi->base.getClass = g_certChainP7bSpi->base.getClass;

    CfObjDestroy(certChainSpi);
}

HWTEST_F(CryptoX509CertChainTest, GetCertlistOpensslTest004, TestSize.Level0)
{
    ASSERT_NE(g_certChainP7bSpi, nullptr);

    HcfX509CertificateArray certsList = { nullptr, 0 };
    CfResult ret = g_certChainP7bSpi->engineGetCertList(g_certChainP7bSpi, &certsList);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_EQ(certsList.count > 0, true);
    ASSERT_NE(certsList.data, nullptr);

    FreeCertArrayData(&certsList);
}

HWTEST_F(CryptoX509CertChainTest, GetCertlistOpensslTest005, TestSize.Level0)
{
    ASSERT_NE(g_certChainP7bSpi, nullptr);
    HcfX509CertChainSpi *certChainSpi = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&g_inStreamChainDataP7b, &certChainSpi);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainSpi, nullptr);
    certChainSpi->base.getClass = GetInvalidCertChainClass;

    HcfX509CertificateArray certsList = { nullptr, 0 };
    ret = certChainSpi->engineGetCertList(certChainSpi, &certsList);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);

    certChainSpi->base.getClass = g_certChainP7bSpi->base.getClass;
    CfObjDestroy(certChainSpi);
}

HWTEST_F(CryptoX509CertChainTest, GetCertListCoreTest001, TestSize.Level0)
{
    ASSERT_NE(g_certChainP7b, nullptr);
    HcfX509CertificateArray certsArray = { 0 };
    CfResult ret = g_certChainP7b->getCertList(nullptr, &certsArray);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);
}

HWTEST_F(CryptoX509CertChainTest, GetCertListCoreTest002, TestSize.Level0)
{
    ASSERT_NE(g_certChainP7b, nullptr);
    CfResult ret = g_certChainP7b->getCertList(g_certChainP7b, nullptr);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);
}

HWTEST_F(CryptoX509CertChainTest, GetCertListCoreTest003, TestSize.Level0)
{
    ASSERT_NE(g_certChainP7b, nullptr);
    HcfCertChain *pCertChain = nullptr;
    CfResult ret = HcfCertChainCreate(&g_inStreamChainDataP7b, nullptr, &pCertChain);
    ASSERT_EQ(ret, CF_SUCCESS);

    pCertChain->base.getClass = GetInvalidCertChainClass;
    ret = g_certChainP7b->getCertList(pCertChain, nullptr);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);

    pCertChain->base.getClass = g_certChainP7b->base.getClass;
    CfObjDestroy(pCertChain);
}

HWTEST_F(CryptoX509CertChainTest, GetCertListCoreTest004, TestSize.Level0)
{
    ASSERT_NE(g_certChainP7b, nullptr);
    HcfX509CertificateArray out = { nullptr, 0 };
    CfResult ret = g_certChainP7b->getCertList(g_certChainP7b, &out);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_EQ(out.count > 0, true);

    FreeCertArrayData(&out);
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest001, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslTest001");
    HcfX509CertChainSpi *certChainSpi = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&g_inStreamChainDataP7b, &certChainSpi);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainSpi, nullptr);

    ret = certChainSpi->engineValidate(nullptr, nullptr, nullptr);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);

    CfObjDestroy(certChainSpi);
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest002, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslTest002");
    ASSERT_NE(g_certChainP7bSpi, nullptr);
    CfResult ret = g_certChainP7bSpi->engineValidate(g_certChainP7bSpi, nullptr, nullptr);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest003, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslTest003");
    ASSERT_NE(g_certChainP7bSpi, nullptr);
    HcfX509TrustAnchor anchor = { 0 };
    CfEncodingBlob inStream = { 0 };
    inStream.data = (uint8_t *)g_testSelfSignedCaCert;
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testSelfSignedCaCert) + 1;
    (void)HcfX509CertificateCreate(&inStream, &anchor.CACert);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    trustAnchorArray.data = static_cast<HcfX509TrustAnchor **>(CfMalloc(1 * sizeof(HcfX509TrustAnchor *), 0));
    ASSERT_NE(trustAnchorArray.data, nullptr);
    trustAnchorArray.data[0] = &anchor;
    trustAnchorArray.count = 1;

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    ASSERT_EQ(pCertChainValidateParams.date, nullptr);               // test
    ASSERT_EQ(pCertChainValidateParams.certCRLCollections, nullptr); // test
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;

    CfResult ret = g_certChainP7bSpi->engineValidate(g_certChainP7bSpi, &pCertChainValidateParams, nullptr);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);

    CfFree(trustAnchorArray.data);
    CfObjDestroy(anchor.CACert);
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest004, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslTest004");
    ASSERT_NE(g_certChainP7bSpi, nullptr);

    HcfX509CertChainSpi *certChainSpi = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&g_inStreamChainDataP7b, &certChainSpi);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainSpi, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainDataPemRoot, trustAnchorArray);

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;

    certChainSpi->base.getClass = GetInvalidCertChainClass;
    HcfX509CertChainValidateResult result = { 0 };
    ret = certChainSpi->engineValidate(certChainSpi, &pCertChainValidateParams, &result);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);

    certChainSpi->base.getClass = g_certChainP7bSpi->base.getClass;
    FreeTrustAnchorArr(trustAnchorArray);
    CfObjDestroy(certChainSpi);
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest005, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslTest005");
    ASSERT_NE(g_certChainPemSpi, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainDataPemRoot, trustAnchorArray);

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;

    HcfX509CertChainValidateResult result = { 0 };
    CfResult ret = g_certChainPemSpi->engineValidate(g_certChainPemSpi, &pCertChainValidateParams, &result);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(result.entityCert, nullptr);
    ASSERT_NE(result.trustAnchor, nullptr);

    FreeTrustAnchorArr(trustAnchorArray);
    FreeValidateResult(result);
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest006, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslTest006");
    ASSERT_NE(g_certChainPemSpi, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamSelfSignedCaCert, trustAnchorArray);

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;

    HcfX509CertChainValidateResult result = { 0 };
    CfResult ret = g_certChainPemSpi->engineValidate(g_certChainPemSpi, &pCertChainValidateParams, &result);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);

    FreeTrustAnchorArr(trustAnchorArray);
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest007, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslTest007");
    ASSERT_NE(g_certChainPemSpi, nullptr);

    HcfX509TrustAnchor anchor = { 0 };

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    trustAnchorArray.data = static_cast<HcfX509TrustAnchor **>(CfMalloc(1 * sizeof(HcfX509TrustAnchor *), 0));
    ASSERT_NE(trustAnchorArray.data, nullptr);
    trustAnchorArray.data[0] = &anchor;
    trustAnchorArray.count = 1;

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;

    HcfX509CertChainValidateResult result = { 0 };
    CfResult ret = g_certChainPemSpi->engineValidate(g_certChainPemSpi, &pCertChainValidateParams, &result);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);

    CfFree(trustAnchorArray.data);
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest008, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslTest008");
    ASSERT_NE(g_certChainPemSpi, nullptr);

    CfBlob pubkey = { 0, nullptr };
    pubkey.data = (uint8_t *)(&g_testChainPubkeyPemRootData[0]);
    pubkey.size = g_testChainPubkeyPemRootDataSize;

    HcfX509TrustAnchor anchor = { 0 };

    anchor.CAPubKey = &pubkey;

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    trustAnchorArray.data = static_cast<HcfX509TrustAnchor **>(CfMalloc(1 * sizeof(HcfX509TrustAnchor *), 0));
    ASSERT_NE(trustAnchorArray.data, nullptr);
    trustAnchorArray.data[0] = &anchor;
    trustAnchorArray.count = 1;

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;

    HcfX509CertChainValidateResult result = { 0 };
    CfResult ret = g_certChainPemSpi->engineValidate(g_certChainPemSpi, &pCertChainValidateParams, &result);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(result.entityCert, nullptr);
    ASSERT_NE(result.trustAnchor, nullptr);

    CfFree(trustAnchorArray.data);
    FreeValidateResult(result);
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest009, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslTest009");
    ASSERT_NE(g_certChainPemSpi, nullptr);

    CfBlob pubkey = { 0, nullptr };
    pubkey.data = (uint8_t *)(&g_testCrlSubAndIssNameDerData[0]);
    pubkey.size = g_testCrlSubAndIssNameDerDataSize;

    HcfX509TrustAnchor anchor = { 0 };
    anchor.CAPubKey = &pubkey;

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    trustAnchorArray.data = static_cast<HcfX509TrustAnchor **>(CfMalloc(1 * sizeof(HcfX509TrustAnchor *), 0));
    ASSERT_NE(trustAnchorArray.data, nullptr);
    trustAnchorArray.data[0] = &anchor;
    trustAnchorArray.count = 1;

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;

    HcfX509CertChainValidateResult result = { 0 };
    CfResult ret = g_certChainPemSpi->engineValidate(g_certChainPemSpi, &pCertChainValidateParams, &result);
    ASSERT_EQ(ret, CF_ERR_CRYPTO_OPERATION);

    CfFree(trustAnchorArray.data);
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest010, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslTest010");
    ASSERT_NE(g_certChainPemSpi, nullptr);

    CfBlob pubkey = { 0, nullptr };
    pubkey.data = (uint8_t *)(&g_testChainPubkeyPemRootData[0]);
    pubkey.size = g_testChainPubkeyPemRootDataSize;

    CfBlob subject = { 0, nullptr };
    subject.data = (uint8_t *)(&g_testChainSubjectPemRootData[0]);
    subject.size = g_testChainSubjectPemRootDataSize;

    HcfX509TrustAnchor anchor = { 0 };
    anchor.CAPubKey = &pubkey;
    anchor.CASubject = &subject;

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    trustAnchorArray.data = static_cast<HcfX509TrustAnchor **>(CfMalloc(1 * sizeof(HcfX509TrustAnchor *), 0));
    ASSERT_NE(trustAnchorArray.data, nullptr);
    trustAnchorArray.data[0] = &anchor;
    trustAnchorArray.count = 1;

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;

    HcfX509CertChainValidateResult result = { 0 };
    CfResult ret = g_certChainPemSpi->engineValidate(g_certChainPemSpi, &pCertChainValidateParams, &result);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(result.entityCert, nullptr);
    ASSERT_NE(result.trustAnchor, nullptr);

    CfFree(trustAnchorArray.data);
    FreeValidateResult(result);
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest011, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslTest011");
    ASSERT_NE(g_certChainPemSpi, nullptr);

    CfBlob pubkey = { 0, nullptr };
    pubkey.data = (uint8_t *)(&g_testChainPubkeyPemRootData[0]);
    pubkey.size = g_testChainPubkeyPemRootDataSize;

    CfBlob subject = { 0, nullptr };
    subject.data = (uint8_t *)(&g_testChainSubjectPemOtherSubjectData[0]);
    subject.size = g_testChainSubjectPemOtherSubjectDataSize;

    HcfX509TrustAnchor anchor = { 0 };
    anchor.CAPubKey = &pubkey;
    anchor.CASubject = &subject;

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    trustAnchorArray.data = static_cast<HcfX509TrustAnchor **>(CfMalloc(1 * sizeof(HcfX509TrustAnchor *), 0));
    ASSERT_NE(trustAnchorArray.data, nullptr);
    trustAnchorArray.data[0] = &anchor;
    trustAnchorArray.count = 1;

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;

    HcfX509CertChainValidateResult result = { 0 };
    CfResult ret = g_certChainPemSpi->engineValidate(g_certChainPemSpi, &pCertChainValidateParams, &result);

    ASSERT_EQ(ret, CF_INVALID_PARAMS);

    CfFree(trustAnchorArray.data);
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest012, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslTest012");
    ASSERT_NE(g_certChainPemSpi, nullptr);

    CfBlob pubkey = { 0, nullptr };
    pubkey.data = (uint8_t *)(&g_testChainPubkeyPemRootData[0]);
    pubkey.size = g_testChainPubkeyPemRootDataSize;

    HcfX509TrustAnchor anchor = { 0 };
    anchor.CAPubKey = &pubkey;
    anchor.CASubject = &pubkey;

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    trustAnchorArray.data = static_cast<HcfX509TrustAnchor **>(CfMalloc(1 * sizeof(HcfX509TrustAnchor *), 0));
    ASSERT_NE(trustAnchorArray.data, nullptr);
    trustAnchorArray.data[0] = &anchor;
    trustAnchorArray.count = 1;

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;

    HcfX509CertChainValidateResult result = { 0 };
    CfResult ret = g_certChainPemSpi->engineValidate(g_certChainPemSpi, &pCertChainValidateParams, &result);
    ASSERT_EQ(ret, CF_ERR_CRYPTO_OPERATION);

    CfFree(trustAnchorArray.data);
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest013, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslTest013");
    ASSERT_NE(g_certChainPemSpi, nullptr);

    CfBlob pubkey = { 0, nullptr };
    pubkey.data = (uint8_t *)(&g_testCrlSubAndIssNameDerData[0]);
    pubkey.size = g_testCrlSubAndIssNameDerDataSize;

    HcfX509TrustAnchor anchor = { 0 };

    anchor.CAPubKey = &pubkey;
    anchor.CASubject = &pubkey;

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    trustAnchorArray.data = static_cast<HcfX509TrustAnchor **>(CfMalloc(1 * sizeof(HcfX509TrustAnchor *), 0));
    ASSERT_NE(trustAnchorArray.data, nullptr);
    trustAnchorArray.data[0] = &anchor;
    trustAnchorArray.count = 1;

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;

    HcfX509CertChainValidateResult result = { 0 };
    CfResult ret = g_certChainPemSpi->engineValidate(g_certChainPemSpi, &pCertChainValidateParams, &result);
    ASSERT_EQ(ret, CF_ERR_CRYPTO_OPERATION);

    CfFree(trustAnchorArray.data);
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest014, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslTest014");
    HcfX509CertChainSpi *certChainSpi = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&g_inStreamChainDataPemNoRoot, &certChainSpi);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainSpi, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainDataPemRoot, trustAnchorArray);

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;

    HcfX509CertChainValidateResult result = { 0 };
    ret = certChainSpi->engineValidate(certChainSpi, &pCertChainValidateParams, &result);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(result.entityCert, nullptr);
    ASSERT_NE(result.trustAnchor, nullptr);

    FreeTrustAnchorArr(trustAnchorArray);
    FreeValidateResult(result);
    CfObjDestroy(certChainSpi);
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest015, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslTest015");
    HcfX509CertChainSpi *certChainSpi = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&g_inStreamChainPemNoRootHasPubKey, &certChainSpi);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainSpi, nullptr);

    CfBlob pubkey = { 0, nullptr };
    pubkey.data = (uint8_t *)(&g_testChainPubkeyPemRootHasPubKey[0]);
    pubkey.size = g_testChainPubkeyPemRootHasPubKeySize;

    HcfX509TrustAnchor anchor = { 0 };
    anchor.CAPubKey = &pubkey;

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    trustAnchorArray.data = static_cast<HcfX509TrustAnchor **>(CfMalloc(1 * sizeof(HcfX509TrustAnchor *), 0));
    ASSERT_NE(trustAnchorArray.data, nullptr);
    trustAnchorArray.data[0] = &anchor;
    trustAnchorArray.count = 1;

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;

    HcfX509CertChainValidateResult result = { 0 };
    ret = certChainSpi->engineValidate(certChainSpi, &pCertChainValidateParams, &result);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(result.entityCert, nullptr);
    ASSERT_NE(result.trustAnchor, nullptr);

    CfFree(trustAnchorArray.data);
    CfObjDestroy(certChainSpi);
    FreeValidateResult(result);
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest016, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslTest016");
    ASSERT_NE(g_certChainPemSpi, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainDataPemMid, trustAnchorArray);

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;

    HcfX509CertChainValidateResult result = { 0 };
    CfResult ret = g_certChainPemSpi->engineValidate(g_certChainPemSpi, &pCertChainValidateParams, &result);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);

    FreeTrustAnchorArr(trustAnchorArray);
    FreeValidateResult(result);
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest017, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslTest017");
    HcfX509CertChainSpi *certChainSpi = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&g_inStreamChainDataPemRoot, &certChainSpi);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainSpi, nullptr);

    CfBlob pubkey = { 0, nullptr };
    pubkey.data = (uint8_t *)(&g_testCrlSubAndIssNameDerData[0]);
    pubkey.size = g_testCrlSubAndIssNameDerDataSize;

    HcfX509TrustAnchor anchor = { 0 };
    (void)HcfX509CertificateCreate(&g_inStreamChainDataPemRoot, &anchor.CACert);
    anchor.CAPubKey = &pubkey;

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    trustAnchorArray.data = static_cast<HcfX509TrustAnchor **>(CfMalloc(1 * sizeof(HcfX509TrustAnchor *), 0));
    ASSERT_NE(trustAnchorArray.data, nullptr);
    trustAnchorArray.data[0] = &anchor;
    trustAnchorArray.count = 1;

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;

    HcfX509CertChainValidateResult result = { 0 };
    ret = certChainSpi->engineValidate(certChainSpi, &pCertChainValidateParams, &result);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(result.entityCert, nullptr);
    ASSERT_NE(result.trustAnchor, nullptr);

    FreeValidateResult(result);
    CfFree(trustAnchorArray.data);
    CfObjDestroy(anchor.CACert);
    CfObjDestroy(certChainSpi);
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest018, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslTest018");
    ASSERT_NE(g_certChainPemSpi, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainDataPemRoot, trustAnchorArray);

    const char *date = "20231205073900Z";
    CfBlob validDate = { 0 };
    validDate.data = reinterpret_cast<uint8_t *>(const_cast<char *>(date));
    validDate.size = strlen(date) + 1;
    // validatetime :notBeforeDate: 2023-12-05 07:39:00 UTC , notAfterDate: 2024-09-01 23:59:00 UTC

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;
    pCertChainValidateParams.date = &validDate;

    HcfX509CertChainValidateResult result = { 0 };
    CfResult ret = g_certChainPemSpi->engineValidate(g_certChainPemSpi, &pCertChainValidateParams, &result);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(result.entityCert, nullptr);
    ASSERT_NE(result.trustAnchor, nullptr);

    FreeTrustAnchorArr(trustAnchorArray);
    FreeValidateResult(result);
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest019, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslTest019");
    ASSERT_NE(g_certChainPemSpi, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainDataPemRoot, trustAnchorArray);

    const char *date = "20240901235900Z";
    CfBlob validDate = { 0 };
    validDate.data = reinterpret_cast<uint8_t *>(const_cast<char *>(date));
    validDate.size = strlen(date) + 1;
    // validatetime :notBeforeDate: 2023-12-05 07:39:00 UTC , notAfterDate: 2024-09-01 23:59:00 UTC

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;
    pCertChainValidateParams.date = &validDate;

    HcfX509CertChainValidateResult result = { 0 };
    CfResult ret = g_certChainPemSpi->engineValidate(g_certChainPemSpi, &pCertChainValidateParams, &result);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(result.entityCert, nullptr);
    ASSERT_NE(result.trustAnchor, nullptr);

    FreeTrustAnchorArr(trustAnchorArray);
    FreeValidateResult(result);
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest020, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslTest020");
    ASSERT_NE(g_certChainPemSpi, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainDataPemRoot, trustAnchorArray);

    const char *date = "231205073900Z";
    CfBlob validDate = { 0 };
    validDate.data = reinterpret_cast<uint8_t *>(const_cast<char *>(date));
    validDate.size = strlen(date) + 1;
    // validatetime :notBeforeDate: 2023-12-05 07:39:00 UTC , notAfterDate: 2024-09-01 23:59:00 UTC

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;
    pCertChainValidateParams.date = &validDate;

    HcfX509CertChainValidateResult result = { 0 };
    CfResult ret = g_certChainPemSpi->engineValidate(g_certChainPemSpi, &pCertChainValidateParams, &result);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(result.entityCert, nullptr);
    ASSERT_NE(result.trustAnchor, nullptr);

    FreeTrustAnchorArr(trustAnchorArray);
    FreeValidateResult(result);
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest021, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslTest021");
    ASSERT_NE(g_certChainPemSpi, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainDataPemRoot, trustAnchorArray);

    const char *date = "231206090000";
    CfBlob validDate = { 0 };
    validDate.data = reinterpret_cast<uint8_t *>(const_cast<char *>(date));
    validDate.size = strlen(date); // len is wrong.
    // validatetime :notBeforeDate: 2023-12-05 07:39:00 UTC , notAfterDate: 2024-09-01 23:59:00 UTC

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;
    pCertChainValidateParams.date = &validDate;

    HcfX509CertChainValidateResult result = { 0 };
    CfResult ret = g_certChainPemSpi->engineValidate(g_certChainPemSpi, &pCertChainValidateParams, &result);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);

    FreeTrustAnchorArr(trustAnchorArray);
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest022, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslTest022");
    ASSERT_NE(g_certChainPemSpi, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainDataPemRoot, trustAnchorArray);

    const char *date = "abc"; // format is not correct.
    CfBlob validDate = { 0 };
    validDate.data = reinterpret_cast<uint8_t *>(const_cast<char *>(date));
    validDate.size = strlen(date) + 1;
    // validatetime :notBeforeDate: 2023-12-05 07:39:00 UTC , notAfterDate: 2024-09-01 23:59:00 UTC

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;
    pCertChainValidateParams.date = &validDate;

    HcfX509CertChainValidateResult result = { 0 };
    CfResult ret = g_certChainPemSpi->engineValidate(g_certChainPemSpi, &pCertChainValidateParams, &result);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);

    FreeTrustAnchorArr(trustAnchorArray);
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest023, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslTest023");
    ASSERT_NE(g_certChainPemSpi, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainDataPemRoot, trustAnchorArray);

    const char *date = "20231205073500Z";
    CfBlob validDate = { 0 };
    validDate.data = reinterpret_cast<uint8_t *>(const_cast<char *>(date));
    validDate.size = strlen(date) + 1;
    // validatetime :notBeforeDate: 2023-12-05 07:39:00 UTC , notAfterDate: 2024-09-01 23:59:00 UTC

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;
    pCertChainValidateParams.date = &validDate;

    HcfX509CertChainValidateResult result = { 0 };
    CfResult ret = g_certChainPemSpi->engineValidate(g_certChainPemSpi, &pCertChainValidateParams, &result);
    ASSERT_EQ(ret, CF_ERR_CERT_NOT_YET_VALID);

    FreeTrustAnchorArr(trustAnchorArray);
    FreeValidateResult(result);
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest024, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslTest024");
    ASSERT_NE(g_certChainPemSpi, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainDataPemRoot, trustAnchorArray);

    const char *date = "20240901235901Z";
    CfBlob validDate = { 0 };
    validDate.data = reinterpret_cast<uint8_t *>(const_cast<char *>(date));
    validDate.size = strlen(date) + 1;
    // validatetime :notBeforeDate: 2023-12-05 07:39:00 UTC , notAfterDate: 2024-09-01 23:59:00 UTC

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;
    pCertChainValidateParams.date = &validDate;

    HcfX509CertChainValidateResult result = { 0 };
    CfResult ret = g_certChainPemSpi->engineValidate(g_certChainPemSpi, &pCertChainValidateParams, &result);
    ASSERT_EQ(ret, CF_ERR_CERT_HAS_EXPIRED);

    FreeTrustAnchorArr(trustAnchorArray);
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest025, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslTest025");
    ASSERT_NE(g_certChainPemSpi, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainDataPemRoot, trustAnchorArray);

    HcfCertCRLCollectionArray certCRLCollections = { 0 };
    BuildCollectionArr(&g_inStreamChainDataPemRoot, &g_crlDerInStream, certCRLCollections);

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;
    pCertChainValidateParams.certCRLCollections = &certCRLCollections;

    HcfX509CertChainValidateResult result = { 0 };
    CfResult ret = g_certChainPemSpi->engineValidate(g_certChainPemSpi, &pCertChainValidateParams, &result);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(result.entityCert, nullptr);
    ASSERT_NE(result.trustAnchor, nullptr);

    FreeTrustAnchorArr(trustAnchorArray);
    FreeCertCrlCollectionArr(certCRLCollections);
    FreeValidateResult(result);
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest026, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslTest026");
    ASSERT_NE(g_certChainPemSpi, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainDataPemRoot, trustAnchorArray);

    HcfCertCRLCollectionArray certCRLCollections = { 0 };
    BuildCollectionArr(&g_inStreamChainDataPemMid, &g_inStreamChainDataPemMidCRL, certCRLCollections);

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;
    pCertChainValidateParams.certCRLCollections = &certCRLCollections;

    HcfX509CertChainValidateResult result = { 0 };
    CfResult ret = g_certChainPemSpi->engineValidate(g_certChainPemSpi, &pCertChainValidateParams, &result);
    ASSERT_EQ(ret, CF_ERR_CRYPTO_OPERATION);

    FreeTrustAnchorArr(trustAnchorArray);
    FreeCertCrlCollectionArr(certCRLCollections);
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest027, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslTest027");
    ASSERT_NE(g_certChainPemSpi, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainDataPemRoot, trustAnchorArray);

    HcfCertCRLCollectionArray certCRLCollections = { 0 };
    BuildCollectionArr(&g_inStreamChainDataPemRoot, &g_crlDerInStream, certCRLCollections);

    const char *date = "20231212080000Z";
    CfBlob validDate = { 0 };
    validDate.data = reinterpret_cast<uint8_t *>(const_cast<char *>(date));
    validDate.size = strlen(date) + 1;
    // validatetime :notBeforeDate: 20231205080000, notAfterDate: 20241205075959

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;
    pCertChainValidateParams.date = &validDate;
    pCertChainValidateParams.certCRLCollections = &certCRLCollections;

    HcfX509CertChainValidateResult result = { 0 };
    CfResult ret = g_certChainPemSpi->engineValidate(g_certChainPemSpi, &pCertChainValidateParams, &result);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(result.entityCert, nullptr);
    ASSERT_NE(result.trustAnchor, nullptr);

    FreeTrustAnchorArr(trustAnchorArray);
    FreeCertCrlCollectionArr(certCRLCollections);
    FreeValidateResult(result);
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest028, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslTest028");
    for (unsigned int i = 0; i < 1000; i++) {
        HcfX509TrustAnchorArray trustAnchorArray = { 0 };
        BuildAnchorArr(g_inStreamChainDataPemRoot, trustAnchorArray);

        HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
        pCertChainValidateParams.trustAnchors = &trustAnchorArray;

        HcfX509CertChainValidateResult result = { 0 };
        CfResult ret = g_certChainPemSpi->engineValidate(g_certChainPemSpi, &pCertChainValidateParams, &result);
        ASSERT_EQ(ret, CF_SUCCESS);
        ASSERT_NE(result.entityCert, nullptr);
        ASSERT_NE(result.trustAnchor, nullptr);

        FreeTrustAnchorArr(trustAnchorArray);
        FreeValidateResult(result);
    }
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest029, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslTest029");
    HcfX509CertChainSpi *certChainSpi = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&g_inStreamChainPemNoRootHasPubKey, &certChainSpi);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainSpi, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainPemNoRootLast, trustAnchorArray);

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;

    HcfX509CertChainValidateResult result = { 0 };
    ret = certChainSpi->engineValidate(certChainSpi, &pCertChainValidateParams, &result);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(result.entityCert, nullptr);
    ASSERT_NE(result.trustAnchor, nullptr);

    FreeTrustAnchorArr(trustAnchorArray);
    FreeValidateResult(result);
    CfObjDestroy(certChainSpi);
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest030, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslTest030");
    ASSERT_NE(g_certChainPemSpi, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainDataPemRoot, trustAnchorArray);

    HcfCertCRLCollectionArray certCRLCollections = { 0 };
    BuildCollectionArr(&g_inStreamChainDataPemRoot, nullptr, certCRLCollections);

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;
    pCertChainValidateParams.certCRLCollections = &certCRLCollections;

    HcfX509CertChainValidateResult result = { 0 };
    CfResult ret = g_certChainPemSpi->engineValidate(g_certChainPemSpi, &pCertChainValidateParams, &result);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(result.entityCert, nullptr);
    ASSERT_NE(result.trustAnchor, nullptr);

    FreeTrustAnchorArr(trustAnchorArray);
    FreeCertCrlCollectionArr(certCRLCollections);
    FreeValidateResult(result);
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest031, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslTest031");
    HcfX509CertChainSpi *certChainSpi = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&g_inStreamChainDataPemDisorder, &certChainSpi);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainSpi, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainDataPemRoot, trustAnchorArray);

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;

    HcfX509CertChainValidateResult result = { 0 };
    ret = certChainSpi->engineValidate(certChainSpi, &pCertChainValidateParams, &result);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);

    FreeTrustAnchorArr(trustAnchorArray);
    CfObjDestroy(certChainSpi);
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest032, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslTest032");
    HcfX509CertChainSpi *certChainSpi = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&g_inStreamChainPemNoRootHasPubKey, &certChainSpi);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainSpi, nullptr);

    CfBlob pubkey = { 0, nullptr };
    pubkey.data = (uint8_t *)(&g_testChainPubkeyPemNoRootLast[0]);
    pubkey.size = g_testChainPubkeyPemNoRootLastSize;

    HcfX509TrustAnchor anchor = { 0 };
    anchor.CAPubKey = &pubkey;

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    trustAnchorArray.data = static_cast<HcfX509TrustAnchor **>(CfMalloc(1 * sizeof(HcfX509TrustAnchor *), 0));
    ASSERT_NE(trustAnchorArray.data, nullptr);
    trustAnchorArray.data[0] = &anchor;
    trustAnchorArray.count = 1;

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;

    HcfX509CertChainValidateResult result = { 0 };
    ret = certChainSpi->engineValidate(certChainSpi, &pCertChainValidateParams, &result);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(result.entityCert, nullptr);
    ASSERT_NE(result.trustAnchor, nullptr);

    CfFree(trustAnchorArray.data);
    CfObjDestroy(certChainSpi);
    FreeValidateResult(result);
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest033, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslTest033");
    HcfX509CertChainSpi *certChainSpi = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&g_inStreamChainPemNoRootHasPubKey, &certChainSpi);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainSpi, nullptr);

    CfBlob pubkey = { 0, nullptr };
    pubkey.data = (uint8_t *)(&g_testChainPubkeyPemNoRootLast[0]);
    pubkey.size = g_testChainPubkeyPemNoRootLastSize;

    CfBlob subject = { 0, nullptr };
    subject.data = (uint8_t *)(&g_testChainSubjectPemNoRootLastUp[0]);
    subject.size = g_testChainSubjectPemNoRootLastUpSize;

    HcfX509TrustAnchor anchor = { 0 };
    anchor.CAPubKey = &pubkey;
    anchor.CASubject = &subject;

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    trustAnchorArray.data = static_cast<HcfX509TrustAnchor **>(CfMalloc(1 * sizeof(HcfX509TrustAnchor *), 0));
    ASSERT_NE(trustAnchorArray.data, nullptr);
    trustAnchorArray.data[0] = &anchor;
    trustAnchorArray.count = 1;

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;

    HcfX509CertChainValidateResult result = { 0 };
    ret = certChainSpi->engineValidate(certChainSpi, &pCertChainValidateParams, &result);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);

    CfFree(trustAnchorArray.data);
    CfObjDestroy(certChainSpi);
}

HWTEST_F(CryptoX509CertChainTest, ValidateOpensslTest034, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslTest034");
    HcfX509CertChainSpi *certChainSpi = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&g_inStreamChainPemNoRootHasPubKey, &certChainSpi);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainSpi, nullptr);

    CfBlob pubkey = { 0, nullptr };
    pubkey.data = (uint8_t *)(&g_testChainPubkeyPemNoRootLastUp[0]);
    pubkey.size = g_testChainPubkeyPemNoRootLastUpSize;

    CfBlob subject = { 0, nullptr };
    subject.data = (uint8_t *)(&g_testChainSubjectPemNoRootLast[0]);
    subject.size = g_testChainSubjectPemNoRootLastSize;

    HcfX509TrustAnchor anchor = { 0 };
    anchor.CAPubKey = &pubkey;
    anchor.CASubject = &subject;

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    trustAnchorArray.data = static_cast<HcfX509TrustAnchor **>(CfMalloc(1 * sizeof(HcfX509TrustAnchor *), 0));
    ASSERT_NE(trustAnchorArray.data, nullptr);
    trustAnchorArray.data[0] = &anchor;
    trustAnchorArray.count = 1;

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;

    HcfX509CertChainValidateResult result = { 0 };
    ret = certChainSpi->engineValidate(certChainSpi, &pCertChainValidateParams, &result);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);

    CfFree(trustAnchorArray.data);
    CfObjDestroy(certChainSpi);
}

HWTEST_F(CryptoX509CertChainTest, ValidateCoreTest001, TestSize.Level0)
{
    CF_LOG_I("ValidateCoreTest001");
    HcfCertChain *pCertChain = nullptr;
    CfResult ret = HcfCertChainCreate(&g_inStreamChainDataP7b, nullptr, &pCertChain);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(pCertChain, nullptr);

    ret = pCertChain->validate(nullptr, nullptr, nullptr);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);

    CfObjDestroy(pCertChain);
}

HWTEST_F(CryptoX509CertChainTest, ValidateCoreTest002, TestSize.Level0)
{
    CF_LOG_I("ValidateCoreTest002");
    HcfCertChain *pCertChain = nullptr;
    CfResult ret = HcfCertChainCreate(&g_inStreamChainDataP7b, nullptr, &pCertChain);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(pCertChain, nullptr);

    ret = pCertChain->validate(pCertChain, nullptr, nullptr);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);

    CfObjDestroy(pCertChain);
}

HWTEST_F(CryptoX509CertChainTest, ValidateCoreTest003, TestSize.Level0)
{
    CF_LOG_I("ValidateCoreTest003");
    ASSERT_NE(g_certChainP7b, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamSelfSignedCaCert, trustAnchorArray);

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;

    CfResult ret = g_certChainP7b->validate(g_certChainP7b, &pCertChainValidateParams, nullptr);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);

    FreeTrustAnchorArr(trustAnchorArray);
}

HWTEST_F(CryptoX509CertChainTest, ValidateCoreTest004, TestSize.Level0)
{
    CF_LOG_I("ValidateCoreTest004");
    HcfCertChain *pCertChain = nullptr;
    CfResult ret = HcfCertChainCreate(&g_inStreamChainDataPem, nullptr, &pCertChain);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(pCertChain, nullptr);
    pCertChain->base.getClass = GetInvalidCertChainClass;

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };

    HcfX509CertChainValidateResult result = { 0 };
    ret = pCertChain->validate(pCertChain, &pCertChainValidateParams, &result);
    ASSERT_EQ(ret, CF_INVALID_PARAMS);

    pCertChain->base.getClass = g_certChainP7b->base.getClass;
    CfObjDestroy(pCertChain);
}

HWTEST_F(CryptoX509CertChainTest, ValidateCoreTest005, TestSize.Level0)
{
    ASSERT_NE(g_certChainPemSpi, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainDataPemRoot, trustAnchorArray);

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;

    HcfX509CertChainValidateResult result = { 0 };
    CfResult ret = g_certChainPemSpi->engineValidate(g_certChainPemSpi, &pCertChainValidateParams, &result);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(result.entityCert, nullptr);
    ASSERT_NE(result.trustAnchor, nullptr);

    FreeTrustAnchorArr(trustAnchorArray);
    FreeValidateResult(result);
}

HWTEST_F(CryptoX509CertChainTest, ValidateCoreTest006, TestSize.Level0)
{
    ASSERT_NE(g_certChainPemSpi, nullptr);

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    pCertChainValidateParams.trustAnchors = nullptr;
    pCertChainValidateParams.trustSystemCa = true;

    HcfX509CertChainValidateResult result = { 0 };
    CfResult ret = g_certChainPemSpi->engineValidate(g_certChainPemSpi, &pCertChainValidateParams, &result);
    ASSERT_NE(ret, CF_SUCCESS);

    FreeValidateResult(result);
}

HWTEST_F(CryptoX509CertChainTest, ValidateCoreTest007, TestSize.Level0)
{
    const CfEncodingBlob inStreamChainDataPem = {
        reinterpret_cast<uint8_t *>(const_cast<char *>(TEST_CERT_CHAIN_PEM)),
        sizeof(TEST_CERT_CHAIN_PEM) / sizeof(char),
        CF_FORMAT_PEM
    };
    HcfX509CertChainSpi *certChainSpi = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&inStreamChainDataPem, &certChainSpi);
    ASSERT_EQ(ret, CF_SUCCESS);

    const CfEncodingBlob inStreamChainDataPemRoot = {
        reinterpret_cast<uint8_t *>(const_cast<char *>(TEST_CERT_CHAIN_PEM_ROOT)),
        sizeof(TEST_CERT_CHAIN_PEM_ROOT) / sizeof(char),
        CF_FORMAT_PEM
    };
    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    if (access(CERT_VERIFY_DIR, F_OK) == -1) {
        BuildAnchorArr(inStreamChainDataPemRoot, trustAnchorArray);
    }

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;
    pCertChainValidateParams.trustSystemCa = true;
    HcfX509CertChainValidateResult result = { 0 };
    ret = certChainSpi->engineValidate(certChainSpi, &pCertChainValidateParams, &result);
    ASSERT_EQ(ret, CF_SUCCESS);

    FreeValidateResult(result);
    FreeTrustAnchorArr(trustAnchorArray);
    CfObjDestroy(certChainSpi);
}

HWTEST_F(CryptoX509CertChainTest, ValidateCoreTest008, TestSize.Level0)
{
    const CfEncodingBlob inStreamChainDataPem = {
        reinterpret_cast<uint8_t *>(const_cast<char *>(TEST_CERT_CHAIN_PEM_NOT_ROOT)),
        sizeof(TEST_CERT_CHAIN_PEM_NOT_ROOT) / sizeof(char),
        CF_FORMAT_PEM
    };
    HcfX509CertChainSpi *certChainSpi = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&inStreamChainDataPem, &certChainSpi);
    ASSERT_EQ(ret, CF_SUCCESS);

    const CfEncodingBlob inStreamChainDataPemRoot = {
        reinterpret_cast<uint8_t *>(const_cast<char *>(TEST_CERT_CHAIN_PEM_ROOT)),
        sizeof(TEST_CERT_CHAIN_PEM_ROOT) / sizeof(char),
        CF_FORMAT_PEM
    };
    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    if (access(CERT_VERIFY_DIR, F_OK) == -1) {
        BuildAnchorArr(inStreamChainDataPemRoot, trustAnchorArray);
    }

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    pCertChainValidateParams.trustAnchors = &trustAnchorArray;
    pCertChainValidateParams.trustSystemCa = true;
    HcfX509CertChainValidateResult result = { 0 };
    ret = certChainSpi->engineValidate(certChainSpi, &pCertChainValidateParams, &result);
    ASSERT_EQ(ret, CF_SUCCESS);

    FreeValidateResult(result);
    FreeTrustAnchorArr(trustAnchorArray);
    CfObjDestroy(certChainSpi);
}
} // namespace
