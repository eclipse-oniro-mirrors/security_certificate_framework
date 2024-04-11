/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "memory_mock.h"
#include "securec.h"
#include "x509_certificate.h"
#include "x509_certificate_openssl.h"

using namespace std;
using namespace testing::ext;

namespace {
HcfX509CertificateSpi *g_x509CertSpiObj = nullptr;

class CryptoX509CertificateTestPart2 : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

static char g_certWithCrlDp1[] =
"-----BEGIN CERTIFICATE-----\r\n"
"MIIB/jCCAaSgAwIBAgICA+gwCgYIKoZIzj0EAwIwLDELMAkGA1UEBhMCQ04xDTAL\r\n"
"BgNVBAoMBHRlc3QxDjAMBgNVBAMMBXN1YmNhMB4XDTIzMTAwNzA0MDEwOFoXDTMz\r\n"
"MTAwNDA0MDEwOFowLDELMAkGA1UEBhMCQ04xDTALBgNVBAoMBHRlc3QxDjAMBgNV\r\n"
"BAMMBWxvY2FsMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZDPvdlJI6Yv4fiaR\r\n"
"nQHcusXVbukk90mQ0rBGOYRikFvgvm5cjTdaUGcQKEtwYIKDQl5n6Pf7ElCJ7GRz\r\n"
"raWZ+qOBtTCBsjAJBgNVHRMEAjAAMCwGCWCGSAGG+EIBDQQfFh1PcGVuU1NMIEdl\r\n"
"bmVyYXRlZCBDZXJ0aWZpY2F0ZTAdBgNVHQ4EFgQU63Gbl8gIsUn0VyZ4rya3PCjm\r\n"
"sfEwHwYDVR0jBBgwFoAU77mynM0rz1SD43DQjleWM7bF+MEwNwYDVR0fBDAwLjAs\r\n"
"oCqgKIYmaHR0cDovL3Rlc3QudGVzdENSTGRwLmNvbS9DUkxfRFBfMS5jcmwwCgYI\r\n"
"KoZIzj0EAwIDSAAwRQIhAISKHH9u221mBgdDWfll3loLvEHJ3or9NUO5Zn6SrX6L\r\n"
"AiAtRlOa6/mTD68faQTdhsAaQP955QfW34B4yFqU2Bq72A==\r\n"
"-----END CERTIFICATE-----\r\n";

static char g_certWithCrlDp2[] =
"-----BEGIN CERTIFICATE-----\r\n"
"MIICLTCCAdKgAwIBAgICA+gwCgYIKoZIzj0EAwIwLDELMAkGA1UEBhMCQ04xDTAL\r\n"
"BgNVBAoMBHRlc3QxDjAMBgNVBAMMBXN1YmNhMB4XDTIzMTAwNzAzNTgwNloXDTMz\r\n"
"MTAwNDAzNTgwNlowLDELMAkGA1UEBhMCQ04xDTALBgNVBAoMBHRlc3QxDjAMBgNV\r\n"
"BAMMBWxvY2FsMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZDPvdlJI6Yv4fiaR\r\n"
"nQHcusXVbukk90mQ0rBGOYRikFvgvm5cjTdaUGcQKEtwYIKDQl5n6Pf7ElCJ7GRz\r\n"
"raWZ+qOB4zCB4DAJBgNVHRMEAjAAMCwGCWCGSAGG+EIBDQQfFh1PcGVuU1NMIEdl\r\n"
"bmVyYXRlZCBDZXJ0aWZpY2F0ZTAdBgNVHQ4EFgQU63Gbl8gIsUn0VyZ4rya3PCjm\r\n"
"sfEwHwYDVR0jBBgwFoAU77mynM0rz1SD43DQjleWM7bF+MEwZQYDVR0fBF4wXDAs\r\n"
"oCqgKIYmaHR0cDovL3Rlc3QudGVzdENSTGRwLmNvbS9DUkxfRFBfMS5jcmwwLKAq\r\n"
"oCiGJmh0dHA6Ly90ZXN0LnRlc3RDUkxkcC5jb20vQ1JMX0RQXzIuY3JsMAoGCCqG\r\n"
"SM49BAMCA0kAMEYCIQCt3yL3X3ecFWS2+wkzTKZSV9zyLoAsYEvD+OjGNZbSmwIh\r\n"
"AOyFskTB0ZiSBn7EYMZ3gs6T0C0kmFjrNi+clJeynBEp\r\n"
"-----END CERTIFICATE-----\r\n";

static char g_certWithCrlDp8[] =
"-----BEGIN CERTIFICATE-----\n"
"MIIDSDCCAu6gAwIBAgICA+gwCgYIKoZIzj0EAwIwLDELMAkGA1UEBhMCQ04xDTAL\n"
"BgNVBAoMBHRlc3QxDjAMBgNVBAMMBXN1YmNhMB4XDTIzMTAxMDA3NDIyOFoXDTMz\n"
"MTAwNzA3NDIyOFowLDELMAkGA1UEBhMCQ04xDTALBgNVBAoMBHRlc3QxDjAMBgNV\n"
"BAMMBWxvY2FsMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETaBOoRxQun7uhAkm\n"
"5A8x484nBrohN0i9eouxES6Zw3uDCu3nxdwqqReB/teuHipgsrKiVwxGNHdKVFxE\n"
"yKIQzaOCAf4wggH6MAkGA1UdEwQCMAAwLAYJYIZIAYb4QgENBB8WHU9wZW5TU0wg\n"
"R2VuZXJhdGVkIENlcnRpZmljYXRlMB0GA1UdDgQWBBSpaV4I7K72Jxu+PWYHOyFP\n"
"4eWhXDAfBgNVHSMEGDAWgBSE1UBYzjXlk0cCk3CDPN9sENNP7jCCAX0GA1UdHwSC\n"
"AXQwggFwMCygKqAohiZodHRwOi8vdGVzdC50ZXN0Q1JMZHAuY29tL0NSTF9EUF8x\n"
"LmNybDAsoCqgKIYmaHR0cDovL3Rlc3QudGVzdENSTGRwLmNvbS9DUkxfRFBfMi5j\n"
"cmwwLKAqoCiGJmh0dHA6Ly90ZXN0LnRlc3RDUkxkcC5jb20vQ1JMX0RQXzMuY3Js\n"
"MCygKqAohiZodHRwOi8vdGVzdC50ZXN0Q1JMZHAuY29tL0NSTF9EUF80LmNybDAs\n"
"oCqgKIYmaHR0cDovL3Rlc3QudGVzdENSTGRwLmNvbS9DUkxfRFBfNS5jcmwwLKAq\n"
"oCiGJmh0dHA6Ly90ZXN0LnRlc3RDUkxkcC5jb20vQ1JMX0RQXzYuY3JsMCygKqAo\n"
"hiZodHRwOi8vdGVzdC50ZXN0Q1JMZHAuY29tL0NSTF9EUF83LmNybDAsoCqgKIYm\n"
"aHR0cDovL3Rlc3QudGVzdENSTGRwLmNvbS9DUkxfRFBfOC5jcmwwCgYIKoZIzj0E\n"
"AwIDSAAwRQIgV1rwM5Yk0U8SM0MEI3L5rstpiB58ydrjvubSF+Wgbk0CIQCkRDuS\n"
"LgDV2OXx7wXaPQME7nFafzqXk6NdgifDQWMqkw==\n"
"-----END CERTIFICATE-----\n";

static char g_certWithoutCrlDp[] =
"-----BEGIN CERTIFICATE-----\r\n"
"MIIBnDCCAUKgAwIBAgICA+gwCgYIKoZIzj0EAwIwLTELMAkGA1UEBhMCQ04xDTAL\r\n"
"BgNVBAoMBHRlc3QxDzANBgNVBAMMBnJvb3RjYTAeFw0yMzEwMDcwMzU4MDZaFw0z\r\n"
"MzEwMDQwMzU4MDZaMCwxCzAJBgNVBAYTAkNOMQ0wCwYDVQQKDAR0ZXN0MQ4wDAYD\r\n"
"VQQDDAVzdWJjYTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJqIo1VhLtAnIgNJ\r\n"
"0TkfNpqevo92EcCYFL+Wm0wq/Gfm3l0PTWyFngNm6uRfemBsAmGczlONSVRx9v2w\r\n"
"Awk+sS+jUzBRMB0GA1UdDgQWBBTvubKczSvPVIPjcNCOV5YztsX4wTAfBgNVHSME\r\n"
"GDAWgBSRIhaqS/s2+0ZLFfxS6b7L/cy4wjAPBgNVHRMBAf8EBTADAQH/MAoGCCqG\r\n"
"SM49BAMCA0gAMEUCIENRICDJNFiguuJ+g3aAl3qe/RKiPaGwSPv03yJ25u+RAiEA\r\n"
"xf55dBUEyMEoOaTb/hhPXrBUUA5XZw8UT6wYujR/AS0=\r\n"
"-----END CERTIFICATE-----\r\n";

static char g_certWithCrlDpNoURI[] =
"-----BEGIN CERTIFICATE-----\n"
"MIIB3TCCAYKgAwIBAgICA+gwCgYIKoZIzj0EAwIwLDELMAkGA1UEBhMCQ04xDTAL\n"
"BgNVBAoMBHRlc3QxDjAMBgNVBAMMBXN1YmNhMB4XDTIzMTAxMDEzMDgxOVoXDTMz\n"
"MTAwNzEzMDgxOVowLDELMAkGA1UEBhMCQ04xDTALBgNVBAoMBHRlc3QxDjAMBgNV\n"
"BAMMBWxvY2FsMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETaBOoRxQun7uhAkm\n"
"5A8x484nBrohN0i9eouxES6Zw3uDCu3nxdwqqReB/teuHipgsrKiVwxGNHdKVFxE\n"
"yKIQzaOBkzCBkDAJBgNVHRMEAjAAMCwGCWCGSAGG+EIBDQQfFh1PcGVuU1NMIEdl\n"
"bmVyYXRlZCBDZXJ0aWZpY2F0ZTAdBgNVHQ4EFgQUqWleCOyu9icbvj1mBzshT+Hl\n"
"oVwwHwYDVR0jBBgwFoAUhNVAWM415ZNHApNwgzzfbBDTT+4wFQYDVR0fBA4wDDAK\n"
"oAigBocECgEBATAKBggqhkjOPQQDAgNJADBGAiEA3Qe/oPfqrwlGfjErqDHyeZb1\n"
"iCYjVEYEoZupg6Ue80ACIQCXtjsGqRyZAm43yHdGhW8j0gE6L3Bv5Vm4UZOJPZRy\n"
"Ww==\n"
"-----END CERTIFICATE-----\n";

static char g_certWithCrlDpIssuer[] =
"-----BEGIN CERTIFICATE-----\n"
"MIICDDCCAbGgAwIBAgICA+gwCgYIKoZIzj0EAwIwLDELMAkGA1UEBhMCQ04xDTAL\n"
"BgNVBAoMBHRlc3QxDjAMBgNVBAMMBXN1YmNhMB4XDTIzMTAxOTEyMTc0NloXDTMz\n"
"MTAxNjEyMTc0NlowLDELMAkGA1UEBhMCQ04xDTALBgNVBAoMBHRlc3QxDjAMBgNV\n"
"BAMMBWxvY2FsMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEINihyk+dLPlaRvHb\n"
"rbUEp/xtWBt7/eNePaccrS7QkBlNFuRrv+Ea9eg62a41bw8EoYU/hDYRJHoqqXti\n"
"OU97bqOBwjCBvzAJBgNVHRMEAjAAMCwGCWCGSAGG+EIBDQQfFh1PcGVuU1NMIEdl\n"
"bmVyYXRlZCBDZXJ0aWZpY2F0ZTAdBgNVHQ4EFgQUsiyVH5fLNzjOZBKDgWERDTCK\n"
"6f0wHwYDVR0jBBgwFoAUjLWOfDZrafbczKOUrx5/NdooOIUwRAYDVR0fBD0wOzA5\n"
"gQIFYKIzpDEwLzELMAkGA1UEBhMCQ04xDTALBgNVBAoMBFRlc3QxETAPBgNVBAMM\n"
"CFNvbWVOYW1lMAoGCCqGSM49BAMCA0kAMEYCIQCLzL7zNmkakBNDGNTggvbb00qg\n"
"7SAMdyynm9BlLGGTAQIhAKGmqy8v0p2QlGM68iYugxo2dq20FxK4aK5Cr3rnMmYE\n"
"-----END CERTIFICATE-----\n";

static char g_certWithCrlDpURILenTooLong[] =
"-----BEGIN CERTIFICATE-----\n"
"MIIGbzCCBhagAwIBAgICA+gwCgYIKoZIzj0EAwIwLDELMAkGA1UEBhMCQ04xDTAL\n"
"BgNVBAoMBHRlc3QxDjAMBgNVBAMMBXN1YmNhMB4XDTIzMTAxOTEyNDEwOFoXDTMz\n"
"MTAxNjEyNDEwOFowLDELMAkGA1UEBhMCQ04xDTALBgNVBAoMBHRlc3QxDjAMBgNV\n"
"BAMMBWxvY2FsMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEINihyk+dLPlaRvHb\n"
"rbUEp/xtWBt7/eNePaccrS7QkBlNFuRrv+Ea9eg62a41bw8EoYU/hDYRJHoqqXti\n"
"OU97bqOCBSYwggUiMAkGA1UdEwQCMAAwLAYJYIZIAYb4QgENBB8WHU9wZW5TU0wg\n"
"R2VuZXJhdGVkIENlcnRpZmljYXRlMB0GA1UdDgQWBBSyLJUfl8s3OM5kEoOBYREN\n"
"MIrp/TAfBgNVHSMEGDAWgBSMtY58Nmtp9tzMo5SvHn812ig4hTCCBKUGA1UdHwSC\n"
"BJwwggSYMIIElKCCBJCgggSMhoIEiGh0dHA6Ly90ZXN0LnRlc3RDUkxkcC5jb20v\n"
"Y3JsRGlzdHJpYnV0aW9uUG9pbnRzY3JsRGlzdHJpYnV0aW9uUG9pbnRzY3JsRGlz\n"
"dHJpYnV0aW9uUG9pbnRzY3JsRGlzdHJpYnV0aW9uUG9pbnRzY3JsRGlzdHJpYnV0\n"
"aW9uUG9pbnRzY3JsRGlzdHJpYnV0aW9uUG9pbnRzY3JsRGlzdHJpYnV0aW9uUG9p\n"
"bnRzY3JsRGlzdHJpYnV0aW9uUG9pbnRzY3JsRGlzdHJpYnV0aW9uUG9pbnRzY3Js\n"
"RGlzdHJpYnV0aW9uUG9pbnRzY3JsRGlzdHJpYnV0aW9uUG9pbnRzY3JsRGlzdHJp\n"
"YnV0aW9uUG9pbnRzY3JsRGlzdHJpYnV0aW9uUG9pbnRzY3JsRGlzdHJpYnV0aW9u\n"
"UG9pbnRzY3JsRGlzdHJpYnV0aW9uUG9pbnRzY3JsRGlzdHJpYnV0aW9uUG9pbnRz\n"
"Y3JsRGlzdHJpYnV0aW9uUG9pbnRzY3JsRGlzdHJpYnV0aW9uUG9pbnRzY3JsRGlz\n"
"dHJpYnV0aW9uUG9pbnRzY3JsRGlzdHJpYnV0aW9uUG9pbnRzY3JsRGlzdHJpYnV0\n"
"aW9uUG9pbnRzY3JsRGlzdHJpYnV0aW9uUG9pbnRzY3JsRGlzdHJpYnV0aW9uUG9p\n"
"bnRzY3JsRGlzdHJpYnV0aW9uUG9pbnRzY3JsRGlzdHJpYnV0aW9uUG9pbnRzY3Js\n"
"RGlzdHJpYnV0aW9uUG9pbnRzY3JsRGlzdHJpYnV0aW9uUG9pbnRzY3JsRGlzdHJp\n"
"YnV0aW9uUG9pbnRzY3JsRGlzdHJpYnV0aW9uUG9pbnRzY3JsRGlzdHJpYnV0aW9u\n"
"UG9pbnRzY3JsRGlzdHJpYnV0aW9uUG9pbnRzY3JsRGlzdHJpYnV0aW9uUG9pbnRz\n"
"Y3JsRGlzdHJpYnV0aW9uUG9pbnRzY3JsRGlzdHJpYnV0aW9uUG9pbnRzY3JsRGlz\n"
"dHJpYnV0aW9uUG9pbnRzY3JsRGlzdHJpYnV0aW9uUG9pbnRzY3JsRGlzdHJpYnV0\n"
"aW9uUG9pbnRzY3JsRGlzdHJpYnV0aW9uUG9pbnRzY3JsRGlzdHJpYnV0aW9uUG9p\n"
"bnRzY3JsRGlzdHJpYnV0aW9uUG9pbnRzY3JsRGlzdHJpYnV0aW9uUG9pbnRzY3Js\n"
"RGlzdHJpYnV0aW9uUG9pbnRzY3JsRGlzdHJpYnV0aW9uUG9pbnRzY3JsRGlzdHJp\n"
"YnV0aW9uUG9pbnRzY3JsRGlzdHJpYnV0aW9uUG9pbnRzY3JsRGlzdHJpYnV0aW9u\n"
"UG9pbnRzY3JsRGlzdHJpYnV0aW9uUG9pbnRzY3JsRGlzdHJpYnV0aW9uUG9pbnRz\n"
"Y3JsRGlzdHJpYnV0aW9uUG9pbnRzY3JsRGlzdHJpYnV0aW9uUG9pbnRzY3JsRGlz\n"
"dHJpYnV0aW9uUG9pbnRzY3JsRGlzdHJpYnV0aW9uUG9pbnRzY3JsRGlzdHJpYnV0\n"
"aW9uUG9pbnRzY3JsRGlzdHJpYnV0aW9uUG9pbnRzMAoGCCqGSM49BAMCA0cAMEQC\n"
"ID7BfeTjZ/iEm3ae8FcqWw02wh5resqP1sAQHXhzovMxAiA/5jb7DT5F7i8C35dS\n"
"pmYqrumevQAng4kYKpD3VDOD6A==\n"
"-----END CERTIFICATE-----\n";

static char g_certWithCrlDp100[] =
"-----BEGIN CERTIFICATE-----\n"
"MIIUKzCCE9KgAwIBAgICA+gwCgYIKoZIzj0EAwIwLDELMAkGA1UEBhMCQ04xDTAL\n"
"BgNVBAoMBHRlc3QxDjAMBgNVBAMMBXN1YmNhMB4XDTIzMTAyMDAxNDYwOFoXDTMz\n"
"MTAxNzAxNDYwOFowLDELMAkGA1UEBhMCQ04xDTALBgNVBAoMBHRlc3QxDjAMBgNV\n"
"BAMMBWxvY2FsMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEINihyk+dLPlaRvHb\n"
"rbUEp/xtWBt7/eNePaccrS7QkBlNFuRrv+Ea9eg62a41bw8EoYU/hDYRJHoqqXti\n"
"OU97bqOCEuIwghLeMAkGA1UdEwQCMAAwLAYJYIZIAYb4QgENBB8WHU9wZW5TU0wg\n"
"R2VuZXJhdGVkIENlcnRpZmljYXRlMB0GA1UdDgQWBBSyLJUfl8s3OM5kEoOBYREN\n"
"MIrp/TAfBgNVHSMEGDAWgBSMtY58Nmtp9tzMo5SvHn812ig4hTCCEmEGA1UdHwSC\n"
"ElgwghJUMCygKqAohiZodHRwOi8vdGVzdC50ZXN0Q1JMZHAuY29tL0NSTF9EUF8x\n"
"LmNybDAsoCqgKIYmaHR0cDovL3Rlc3QudGVzdENSTGRwLmNvbS9DUkxfRFBfMi5j\n"
"cmwwLKAqoCiGJmh0dHA6Ly90ZXN0LnRlc3RDUkxkcC5jb20vQ1JMX0RQXzMuY3Js\n"
"MCygKqAohiZodHRwOi8vdGVzdC50ZXN0Q1JMZHAuY29tL0NSTF9EUF80LmNybDAs\n"
"oCqgKIYmaHR0cDovL3Rlc3QudGVzdENSTGRwLmNvbS9DUkxfRFBfNS5jcmwwLKAq\n"
"oCiGJmh0dHA6Ly90ZXN0LnRlc3RDUkxkcC5jb20vQ1JMX0RQXzYuY3JsMCygKqAo\n"
"hiZodHRwOi8vdGVzdC50ZXN0Q1JMZHAuY29tL0NSTF9EUF83LmNybDAsoCqgKIYm\n"
"aHR0cDovL3Rlc3QudGVzdENSTGRwLmNvbS9DUkxfRFBfOC5jcmwwLKAqoCiGJmh0\n"
"dHA6Ly90ZXN0LnRlc3RDUkxkcC5jb20vQ1JMX0RQXzkuY3JsMC2gK6AphidodHRw\n"
"Oi8vdGVzdC50ZXN0Q1JMZHAuY29tL0NSTF9EUF8xMC5jcmwwLaAroCmGJ2h0dHA6\n"
"Ly90ZXN0LnRlc3RDUkxkcC5jb20vQ1JMX0RQXzExLmNybDAtoCugKYYnaHR0cDov\n"
"L3Rlc3QudGVzdENSTGRwLmNvbS9DUkxfRFBfMTIuY3JsMC2gK6AphidodHRwOi8v\n"
"dGVzdC50ZXN0Q1JMZHAuY29tL0NSTF9EUF8xMy5jcmwwLaAroCmGJ2h0dHA6Ly90\n"
"ZXN0LnRlc3RDUkxkcC5jb20vQ1JMX0RQXzE0LmNybDAtoCugKYYnaHR0cDovL3Rl\n"
"c3QudGVzdENSTGRwLmNvbS9DUkxfRFBfMTUuY3JsMC2gK6AphidodHRwOi8vdGVz\n"
"dC50ZXN0Q1JMZHAuY29tL0NSTF9EUF8xNi5jcmwwLaAroCmGJ2h0dHA6Ly90ZXN0\n"
"LnRlc3RDUkxkcC5jb20vQ1JMX0RQXzE3LmNybDAtoCugKYYnaHR0cDovL3Rlc3Qu\n"
"dGVzdENSTGRwLmNvbS9DUkxfRFBfMTguY3JsMC2gK6AphidodHRwOi8vdGVzdC50\n"
"ZXN0Q1JMZHAuY29tL0NSTF9EUF8xOS5jcmwwLaAroCmGJ2h0dHA6Ly90ZXN0LnRl\n"
"c3RDUkxkcC5jb20vQ1JMX0RQXzIwLmNybDAtoCugKYYnaHR0cDovL3Rlc3QudGVz\n"
"dENSTGRwLmNvbS9DUkxfRFBfMjEuY3JsMC2gK6AphidodHRwOi8vdGVzdC50ZXN0\n"
"Q1JMZHAuY29tL0NSTF9EUF8yMi5jcmwwLaAroCmGJ2h0dHA6Ly90ZXN0LnRlc3RD\n"
"UkxkcC5jb20vQ1JMX0RQXzIzLmNybDAtoCugKYYnaHR0cDovL3Rlc3QudGVzdENS\n"
"TGRwLmNvbS9DUkxfRFBfMjQuY3JsMC2gK6AphidodHRwOi8vdGVzdC50ZXN0Q1JM\n"
"ZHAuY29tL0NSTF9EUF8yNS5jcmwwLaAroCmGJ2h0dHA6Ly90ZXN0LnRlc3RDUkxk\n"
"cC5jb20vQ1JMX0RQXzI2LmNybDAtoCugKYYnaHR0cDovL3Rlc3QudGVzdENSTGRw\n"
"LmNvbS9DUkxfRFBfMjcuY3JsMC2gK6AphidodHRwOi8vdGVzdC50ZXN0Q1JMZHAu\n"
"Y29tL0NSTF9EUF8yOC5jcmwwLaAroCmGJ2h0dHA6Ly90ZXN0LnRlc3RDUkxkcC5j\n"
"b20vQ1JMX0RQXzI5LmNybDAtoCugKYYnaHR0cDovL3Rlc3QudGVzdENSTGRwLmNv\n"
"bS9DUkxfRFBfMzAuY3JsMC2gK6AphidodHRwOi8vdGVzdC50ZXN0Q1JMZHAuY29t\n"
"L0NSTF9EUF8zMS5jcmwwLaAroCmGJ2h0dHA6Ly90ZXN0LnRlc3RDUkxkcC5jb20v\n"
"Q1JMX0RQXzMyLmNybDAtoCugKYYnaHR0cDovL3Rlc3QudGVzdENSTGRwLmNvbS9D\n"
"UkxfRFBfMzMuY3JsMC2gK6AphidodHRwOi8vdGVzdC50ZXN0Q1JMZHAuY29tL0NS\n"
"TF9EUF8zNC5jcmwwLaAroCmGJ2h0dHA6Ly90ZXN0LnRlc3RDUkxkcC5jb20vQ1JM\n"
"X0RQXzM1LmNybDAtoCugKYYnaHR0cDovL3Rlc3QudGVzdENSTGRwLmNvbS9DUkxf\n"
"RFBfMzYuY3JsMC2gK6AphidodHRwOi8vdGVzdC50ZXN0Q1JMZHAuY29tL0NSTF9E\n"
"UF8zNy5jcmwwLaAroCmGJ2h0dHA6Ly90ZXN0LnRlc3RDUkxkcC5jb20vQ1JMX0RQ\n"
"XzM4LmNybDAtoCugKYYnaHR0cDovL3Rlc3QudGVzdENSTGRwLmNvbS9DUkxfRFBf\n"
"MzkuY3JsMC2gK6AphidodHRwOi8vdGVzdC50ZXN0Q1JMZHAuY29tL0NSTF9EUF80\n"
"MC5jcmwwLaAroCmGJ2h0dHA6Ly90ZXN0LnRlc3RDUkxkcC5jb20vQ1JMX0RQXzQx\n"
"LmNybDAtoCugKYYnaHR0cDovL3Rlc3QudGVzdENSTGRwLmNvbS9DUkxfRFBfNDIu\n"
"Y3JsMC2gK6AphidodHRwOi8vdGVzdC50ZXN0Q1JMZHAuY29tL0NSTF9EUF80My5j\n"
"cmwwLaAroCmGJ2h0dHA6Ly90ZXN0LnRlc3RDUkxkcC5jb20vQ1JMX0RQXzQ0LmNy\n"
"bDAtoCugKYYnaHR0cDovL3Rlc3QudGVzdENSTGRwLmNvbS9DUkxfRFBfNDUuY3Js\n"
"MC2gK6AphidodHRwOi8vdGVzdC50ZXN0Q1JMZHAuY29tL0NSTF9EUF80Ni5jcmww\n"
"LaAroCmGJ2h0dHA6Ly90ZXN0LnRlc3RDUkxkcC5jb20vQ1JMX0RQXzQ3LmNybDAt\n"
"oCugKYYnaHR0cDovL3Rlc3QudGVzdENSTGRwLmNvbS9DUkxfRFBfNDguY3JsMC2g\n"
"K6AphidodHRwOi8vdGVzdC50ZXN0Q1JMZHAuY29tL0NSTF9EUF80OS5jcmwwLaAr\n"
"oCmGJ2h0dHA6Ly90ZXN0LnRlc3RDUkxkcC5jb20vQ1JMX0RQXzUwLmNybDAtoCug\n"
"KYYnaHR0cDovL3Rlc3QudGVzdENSTGRwLmNvbS9DUkxfRFBfNTEuY3JsMC2gK6Ap\n"
"hidodHRwOi8vdGVzdC50ZXN0Q1JMZHAuY29tL0NSTF9EUF81Mi5jcmwwLaAroCmG\n"
"J2h0dHA6Ly90ZXN0LnRlc3RDUkxkcC5jb20vQ1JMX0RQXzUzLmNybDAtoCugKYYn\n"
"aHR0cDovL3Rlc3QudGVzdENSTGRwLmNvbS9DUkxfRFBfNTQuY3JsMC2gK6Aphido\n"
"dHRwOi8vdGVzdC50ZXN0Q1JMZHAuY29tL0NSTF9EUF81NS5jcmwwLaAroCmGJ2h0\n"
"dHA6Ly90ZXN0LnRlc3RDUkxkcC5jb20vQ1JMX0RQXzU2LmNybDAtoCugKYYnaHR0\n"
"cDovL3Rlc3QudGVzdENSTGRwLmNvbS9DUkxfRFBfNTcuY3JsMC2gK6AphidodHRw\n"
"Oi8vdGVzdC50ZXN0Q1JMZHAuY29tL0NSTF9EUF81OC5jcmwwLaAroCmGJ2h0dHA6\n"
"Ly90ZXN0LnRlc3RDUkxkcC5jb20vQ1JMX0RQXzU5LmNybDAtoCugKYYnaHR0cDov\n"
"L3Rlc3QudGVzdENSTGRwLmNvbS9DUkxfRFBfNjAuY3JsMC2gK6AphidodHRwOi8v\n"
"dGVzdC50ZXN0Q1JMZHAuY29tL0NSTF9EUF82MS5jcmwwLaAroCmGJ2h0dHA6Ly90\n"
"ZXN0LnRlc3RDUkxkcC5jb20vQ1JMX0RQXzYyLmNybDAtoCugKYYnaHR0cDovL3Rl\n"
"c3QudGVzdENSTGRwLmNvbS9DUkxfRFBfNjMuY3JsMC2gK6AphidodHRwOi8vdGVz\n"
"dC50ZXN0Q1JMZHAuY29tL0NSTF9EUF82NC5jcmwwLaAroCmGJ2h0dHA6Ly90ZXN0\n"
"LnRlc3RDUkxkcC5jb20vQ1JMX0RQXzY1LmNybDAtoCugKYYnaHR0cDovL3Rlc3Qu\n"
"dGVzdENSTGRwLmNvbS9DUkxfRFBfNjYuY3JsMC2gK6AphidodHRwOi8vdGVzdC50\n"
"ZXN0Q1JMZHAuY29tL0NSTF9EUF82Ny5jcmwwLaAroCmGJ2h0dHA6Ly90ZXN0LnRl\n"
"c3RDUkxkcC5jb20vQ1JMX0RQXzY4LmNybDAtoCugKYYnaHR0cDovL3Rlc3QudGVz\n"
"dENSTGRwLmNvbS9DUkxfRFBfNjkuY3JsMC2gK6AphidodHRwOi8vdGVzdC50ZXN0\n"
"Q1JMZHAuY29tL0NSTF9EUF83MC5jcmwwLaAroCmGJ2h0dHA6Ly90ZXN0LnRlc3RD\n"
"UkxkcC5jb20vQ1JMX0RQXzcxLmNybDAtoCugKYYnaHR0cDovL3Rlc3QudGVzdENS\n"
"TGRwLmNvbS9DUkxfRFBfNzIuY3JsMC2gK6AphidodHRwOi8vdGVzdC50ZXN0Q1JM\n"
"ZHAuY29tL0NSTF9EUF83My5jcmwwLaAroCmGJ2h0dHA6Ly90ZXN0LnRlc3RDUkxk\n"
"cC5jb20vQ1JMX0RQXzc0LmNybDAtoCugKYYnaHR0cDovL3Rlc3QudGVzdENSTGRw\n"
"LmNvbS9DUkxfRFBfNzUuY3JsMC2gK6AphidodHRwOi8vdGVzdC50ZXN0Q1JMZHAu\n"
"Y29tL0NSTF9EUF83Ni5jcmwwLaAroCmGJ2h0dHA6Ly90ZXN0LnRlc3RDUkxkcC5j\n"
"b20vQ1JMX0RQXzc3LmNybDAtoCugKYYnaHR0cDovL3Rlc3QudGVzdENSTGRwLmNv\n"
"bS9DUkxfRFBfNzguY3JsMC2gK6AphidodHRwOi8vdGVzdC50ZXN0Q1JMZHAuY29t\n"
"L0NSTF9EUF83OS5jcmwwLaAroCmGJ2h0dHA6Ly90ZXN0LnRlc3RDUkxkcC5jb20v\n"
"Q1JMX0RQXzgwLmNybDAtoCugKYYnaHR0cDovL3Rlc3QudGVzdENSTGRwLmNvbS9D\n"
"UkxfRFBfODEuY3JsMC2gK6AphidodHRwOi8vdGVzdC50ZXN0Q1JMZHAuY29tL0NS\n"
"TF9EUF84Mi5jcmwwLaAroCmGJ2h0dHA6Ly90ZXN0LnRlc3RDUkxkcC5jb20vQ1JM\n"
"X0RQXzgzLmNybDAtoCugKYYnaHR0cDovL3Rlc3QudGVzdENSTGRwLmNvbS9DUkxf\n"
"RFBfODQuY3JsMC2gK6AphidodHRwOi8vdGVzdC50ZXN0Q1JMZHAuY29tL0NSTF9E\n"
"UF84NS5jcmwwLaAroCmGJ2h0dHA6Ly90ZXN0LnRlc3RDUkxkcC5jb20vQ1JMX0RQ\n"
"Xzg2LmNybDAtoCugKYYnaHR0cDovL3Rlc3QudGVzdENSTGRwLmNvbS9DUkxfRFBf\n"
"ODcuY3JsMC2gK6AphidodHRwOi8vdGVzdC50ZXN0Q1JMZHAuY29tL0NSTF9EUF84\n"
"OC5jcmwwLaAroCmGJ2h0dHA6Ly90ZXN0LnRlc3RDUkxkcC5jb20vQ1JMX0RQXzg5\n"
"LmNybDAtoCugKYYnaHR0cDovL3Rlc3QudGVzdENSTGRwLmNvbS9DUkxfRFBfOTAu\n"
"Y3JsMC2gK6AphidodHRwOi8vdGVzdC50ZXN0Q1JMZHAuY29tL0NSTF9EUF85MS5j\n"
"cmwwLaAroCmGJ2h0dHA6Ly90ZXN0LnRlc3RDUkxkcC5jb20vQ1JMX0RQXzkyLmNy\n"
"bDAtoCugKYYnaHR0cDovL3Rlc3QudGVzdENSTGRwLmNvbS9DUkxfRFBfOTMuY3Js\n"
"MC2gK6AphidodHRwOi8vdGVzdC50ZXN0Q1JMZHAuY29tL0NSTF9EUF85NC5jcmww\n"
"LaAroCmGJ2h0dHA6Ly90ZXN0LnRlc3RDUkxkcC5jb20vQ1JMX0RQXzk1LmNybDAt\n"
"oCugKYYnaHR0cDovL3Rlc3QudGVzdENSTGRwLmNvbS9DUkxfRFBfOTYuY3JsMC2g\n"
"K6AphidodHRwOi8vdGVzdC50ZXN0Q1JMZHAuY29tL0NSTF9EUF85Ny5jcmwwLaAr\n"
"oCmGJ2h0dHA6Ly90ZXN0LnRlc3RDUkxkcC5jb20vQ1JMX0RQXzk4LmNybDAtoCug\n"
"KYYnaHR0cDovL3Rlc3QudGVzdENSTGRwLmNvbS9DUkxfRFBfOTkuY3JsMC6gLKAq\n"
"hihodHRwOi8vdGVzdC50ZXN0Q1JMZHAuY29tL0NSTF9EUF8xMDAuY3JsMAoGCCqG\n"
"SM49BAMCA0cAMEQCIDG3YVjrRZauRV49iX4KtoDgNVBqz/Q5nphRfMisG6sEAiAI\n"
"WcZaLh0N/XYlkfx6Z88stuyr3uPVQjonrzlSVn5fAQ==\n"
"-----END CERTIFICATE-----\n";

static char g_certWithCrlDp101[] =
"-----BEGIN CERTIFICATE-----\n"
"MIIXHzCCFsWgAwIBAgICA+gwCgYIKoZIzj0EAwIwLDELMAkGA1UEBhMCQ04xDTAL\n"
"BgNVBAoMBHRlc3QxDjAMBgNVBAMMBXN1YmNhMB4XDTIzMTAyMDAxNTExMVoXDTMz\n"
"MTAxNzAxNTExMVowLDELMAkGA1UEBhMCQ04xDTALBgNVBAoMBHRlc3QxDjAMBgNV\n"
"BAMMBWxvY2FsMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEINihyk+dLPlaRvHb\n"
"rbUEp/xtWBt7/eNePaccrS7QkBlNFuRrv+Ea9eg62a41bw8EoYU/hDYRJHoqqXti\n"
"OU97bqOCFdUwghXRMAkGA1UdEwQCMAAwLAYJYIZIAYb4QgENBB8WHU9wZW5TU0wg\n"
"R2VuZXJhdGVkIENlcnRpZmljYXRlMB0GA1UdDgQWBBSyLJUfl8s3OM5kEoOBYREN\n"
"MIrp/TAfBgNVHSMEGDAWgBSMtY58Nmtp9tzMo5SvHn812ig4hTCCFVQGA1UdHwSC\n"
"FUswghVHMDOgMaAvhi1odHRwOi8vdGVzdDEudGVzdDFDUkxkcC5jb20vdGVzdF9j\n"
"cmxfY3BfMS5jcmwwM6AxoC+GLWh0dHA6Ly90ZXN0MS50ZXN0MUNSTGRwLmNvbS90\n"
"ZXN0X2NybF9jcF8yLmNybDAzoDGgL4YtaHR0cDovL3Rlc3QxLnRlc3QxQ1JMZHAu\n"
"Y29tL3Rlc3RfY3JsX2NwXzMuY3JsMDOgMaAvhi1odHRwOi8vdGVzdDEudGVzdDFD\n"
"UkxkcC5jb20vdGVzdF9jcmxfY3BfNC5jcmwwM6AxoC+GLWh0dHA6Ly90ZXN0MS50\n"
"ZXN0MUNSTGRwLmNvbS90ZXN0X2NybF9jcF81LmNybDAzoDGgL4YtaHR0cDovL3Rl\n"
"c3QxLnRlc3QxQ1JMZHAuY29tL3Rlc3RfY3JsX2NwXzYuY3JsMDOgMaAvhi1odHRw\n"
"Oi8vdGVzdDEudGVzdDFDUkxkcC5jb20vdGVzdF9jcmxfY3BfNy5jcmwwM6AxoC+G\n"
"LWh0dHA6Ly90ZXN0MS50ZXN0MUNSTGRwLmNvbS90ZXN0X2NybF9jcF84LmNybDAz\n"
"oDGgL4YtaHR0cDovL3Rlc3QxLnRlc3QxQ1JMZHAuY29tL3Rlc3RfY3JsX2NwXzku\n"
"Y3JsMDSgMqAwhi5odHRwOi8vdGVzdDEudGVzdDFDUkxkcC5jb20vdGVzdF9jcmxf\n"
"Y3BfMTAuY3JsMDSgMqAwhi5odHRwOi8vdGVzdDEudGVzdDFDUkxkcC5jb20vdGVz\n"
"dF9jcmxfY3BfMTEuY3JsMDSgMqAwhi5odHRwOi8vdGVzdDEudGVzdDFDUkxkcC5j\n"
"b20vdGVzdF9jcmxfY3BfMTIuY3JsMDSgMqAwhi5odHRwOi8vdGVzdDEudGVzdDFD\n"
"UkxkcC5jb20vdGVzdF9jcmxfY3BfMTMuY3JsMDSgMqAwhi5odHRwOi8vdGVzdDEu\n"
"dGVzdDFDUkxkcC5jb20vdGVzdF9jcmxfY3BfMTQuY3JsMDSgMqAwhi5odHRwOi8v\n"
"dGVzdDEudGVzdDFDUkxkcC5jb20vdGVzdF9jcmxfY3BfMTUuY3JsMDSgMqAwhi5o\n"
"dHRwOi8vdGVzdDEudGVzdDFDUkxkcC5jb20vdGVzdF9jcmxfY3BfMTYuY3JsMDSg\n"
"MqAwhi5odHRwOi8vdGVzdDEudGVzdDFDUkxkcC5jb20vdGVzdF9jcmxfY3BfMTcu\n"
"Y3JsMDSgMqAwhi5odHRwOi8vdGVzdDEudGVzdDFDUkxkcC5jb20vdGVzdF9jcmxf\n"
"Y3BfMTguY3JsMDSgMqAwhi5odHRwOi8vdGVzdDEudGVzdDFDUkxkcC5jb20vdGVz\n"
"dF9jcmxfY3BfMTkuY3JsMDSgMqAwhi5odHRwOi8vdGVzdDEudGVzdDFDUkxkcC5j\n"
"b20vdGVzdF9jcmxfY3BfMjAuY3JsMDSgMqAwhi5odHRwOi8vdGVzdDEudGVzdDFD\n"
"UkxkcC5jb20vdGVzdF9jcmxfY3BfMjEuY3JsMDSgMqAwhi5odHRwOi8vdGVzdDEu\n"
"dGVzdDFDUkxkcC5jb20vdGVzdF9jcmxfY3BfMjIuY3JsMDSgMqAwhi5odHRwOi8v\n"
"dGVzdDEudGVzdDFDUkxkcC5jb20vdGVzdF9jcmxfY3BfMjMuY3JsMDSgMqAwhi5o\n"
"dHRwOi8vdGVzdDEudGVzdDFDUkxkcC5jb20vdGVzdF9jcmxfY3BfMjQuY3JsMDSg\n"
"MqAwhi5odHRwOi8vdGVzdDEudGVzdDFDUkxkcC5jb20vdGVzdF9jcmxfY3BfMjUu\n"
"Y3JsMDSgMqAwhi5odHRwOi8vdGVzdDEudGVzdDFDUkxkcC5jb20vdGVzdF9jcmxf\n"
"Y3BfMjYuY3JsMDSgMqAwhi5odHRwOi8vdGVzdDEudGVzdDFDUkxkcC5jb20vdGVz\n"
"dF9jcmxfY3BfMjcuY3JsMDSgMqAwhi5odHRwOi8vdGVzdDEudGVzdDFDUkxkcC5j\n"
"b20vdGVzdF9jcmxfY3BfMjguY3JsMDSgMqAwhi5odHRwOi8vdGVzdDEudGVzdDFD\n"
"UkxkcC5jb20vdGVzdF9jcmxfY3BfMjkuY3JsMDSgMqAwhi5odHRwOi8vdGVzdDEu\n"
"dGVzdDFDUkxkcC5jb20vdGVzdF9jcmxfY3BfMzAuY3JsMDSgMqAwhi5odHRwOi8v\n"
"dGVzdDEudGVzdDFDUkxkcC5jb20vdGVzdF9jcmxfY3BfMzEuY3JsMDSgMqAwhi5o\n"
"dHRwOi8vdGVzdDEudGVzdDFDUkxkcC5jb20vdGVzdF9jcmxfY3BfMzIuY3JsMDSg\n"
"MqAwhi5odHRwOi8vdGVzdDEudGVzdDFDUkxkcC5jb20vdGVzdF9jcmxfY3BfMzMu\n"
"Y3JsMDSgMqAwhi5odHRwOi8vdGVzdDEudGVzdDFDUkxkcC5jb20vdGVzdF9jcmxf\n"
"Y3BfMzQuY3JsMDSgMqAwhi5odHRwOi8vdGVzdDEudGVzdDFDUkxkcC5jb20vdGVz\n"
"dF9jcmxfY3BfMzUuY3JsMDSgMqAwhi5odHRwOi8vdGVzdDEudGVzdDFDUkxkcC5j\n"
"b20vdGVzdF9jcmxfY3BfMzYuY3JsMDSgMqAwhi5odHRwOi8vdGVzdDEudGVzdDFD\n"
"UkxkcC5jb20vdGVzdF9jcmxfY3BfMzcuY3JsMDSgMqAwhi5odHRwOi8vdGVzdDEu\n"
"dGVzdDFDUkxkcC5jb20vdGVzdF9jcmxfY3BfMzguY3JsMDSgMqAwhi5odHRwOi8v\n"
"dGVzdDEudGVzdDFDUkxkcC5jb20vdGVzdF9jcmxfY3BfMzkuY3JsMDSgMqAwhi5o\n"
"dHRwOi8vdGVzdDEudGVzdDFDUkxkcC5jb20vdGVzdF9jcmxfY3BfNDAuY3JsMDSg\n"
"MqAwhi5odHRwOi8vdGVzdDEudGVzdDFDUkxkcC5jb20vdGVzdF9jcmxfY3BfNDEu\n"
"Y3JsMDSgMqAwhi5odHRwOi8vdGVzdDEudGVzdDFDUkxkcC5jb20vdGVzdF9jcmxf\n"
"Y3BfNDIuY3JsMDSgMqAwhi5odHRwOi8vdGVzdDEudGVzdDFDUkxkcC5jb20vdGVz\n"
"dF9jcmxfY3BfNDMuY3JsMDSgMqAwhi5odHRwOi8vdGVzdDEudGVzdDFDUkxkcC5j\n"
"b20vdGVzdF9jcmxfY3BfNDQuY3JsMDSgMqAwhi5odHRwOi8vdGVzdDEudGVzdDFD\n"
"UkxkcC5jb20vdGVzdF9jcmxfY3BfNDUuY3JsMDSgMqAwhi5odHRwOi8vdGVzdDEu\n"
"dGVzdDFDUkxkcC5jb20vdGVzdF9jcmxfY3BfNDYuY3JsMDSgMqAwhi5odHRwOi8v\n"
"dGVzdDEudGVzdDFDUkxkcC5jb20vdGVzdF9jcmxfY3BfNDcuY3JsMDSgMqAwhi5o\n"
"dHRwOi8vdGVzdDEudGVzdDFDUkxkcC5jb20vdGVzdF9jcmxfY3BfNDguY3JsMDSg\n"
"MqAwhi5odHRwOi8vdGVzdDEudGVzdDFDUkxkcC5jb20vdGVzdF9jcmxfY3BfNDku\n"
"Y3JsMDSgMqAwhi5odHRwOi8vdGVzdDEudGVzdDFDUkxkcC5jb20vdGVzdF9jcmxf\n"
"Y3BfNTAuY3JsMDSgMqAwhi5odHRwOi8vdGVzdDEudGVzdDFDUkxkcC5jb20vdGVz\n"
"dF9jcmxfY3BfNTEuY3JsMDSgMqAwhi5odHRwOi8vdGVzdDEudGVzdDFDUkxkcC5j\n"
"b20vdGVzdF9jcmxfY3BfNTIuY3JsMDSgMqAwhi5odHRwOi8vdGVzdDEudGVzdDFD\n"
"UkxkcC5jb20vdGVzdF9jcmxfY3BfNTMuY3JsMDSgMqAwhi5odHRwOi8vdGVzdDEu\n"
"dGVzdDFDUkxkcC5jb20vdGVzdF9jcmxfY3BfNTQuY3JsMDSgMqAwhi5odHRwOi8v\n"
"dGVzdDEudGVzdDFDUkxkcC5jb20vdGVzdF9jcmxfY3BfNTUuY3JsMDSgMqAwhi5o\n"
"dHRwOi8vdGVzdDEudGVzdDFDUkxkcC5jb20vdGVzdF9jcmxfY3BfNTYuY3JsMDSg\n"
"MqAwhi5odHRwOi8vdGVzdDEudGVzdDFDUkxkcC5jb20vdGVzdF9jcmxfY3BfNTcu\n"
"Y3JsMDSgMqAwhi5odHRwOi8vdGVzdDEudGVzdDFDUkxkcC5jb20vdGVzdF9jcmxf\n"
"Y3BfNTguY3JsMDSgMqAwhi5odHRwOi8vdGVzdDEudGVzdDFDUkxkcC5jb20vdGVz\n"
"dF9jcmxfY3BfNTkuY3JsMDSgMqAwhi5odHRwOi8vdGVzdDEudGVzdDFDUkxkcC5j\n"
"b20vdGVzdF9jcmxfY3BfNjAuY3JsMDSgMqAwhi5odHRwOi8vdGVzdDEudGVzdDFD\n"
"UkxkcC5jb20vdGVzdF9jcmxfY3BfNjEuY3JsMDSgMqAwhi5odHRwOi8vdGVzdDEu\n"
"dGVzdDFDUkxkcC5jb20vdGVzdF9jcmxfY3BfNjIuY3JsMDSgMqAwhi5odHRwOi8v\n"
"dGVzdDEudGVzdDFDUkxkcC5jb20vdGVzdF9jcmxfY3BfNjMuY3JsMDSgMqAwhi5o\n"
"dHRwOi8vdGVzdDEudGVzdDFDUkxkcC5jb20vdGVzdF9jcmxfY3BfNjQuY3JsMDSg\n"
"MqAwhi5odHRwOi8vdGVzdDEudGVzdDFDUkxkcC5jb20vdGVzdF9jcmxfY3BfNjUu\n"
"Y3JsMDSgMqAwhi5odHRwOi8vdGVzdDEudGVzdDFDUkxkcC5jb20vdGVzdF9jcmxf\n"
"Y3BfNjYuY3JsMDSgMqAwhi5odHRwOi8vdGVzdDEudGVzdDFDUkxkcC5jb20vdGVz\n"
"dF9jcmxfY3BfNjcuY3JsMDSgMqAwhi5odHRwOi8vdGVzdDEudGVzdDFDUkxkcC5j\n"
"b20vdGVzdF9jcmxfY3BfNjguY3JsMDSgMqAwhi5odHRwOi8vdGVzdDEudGVzdDFD\n"
"UkxkcC5jb20vdGVzdF9jcmxfY3BfNjkuY3JsMDSgMqAwhi5odHRwOi8vdGVzdDEu\n"
"dGVzdDFDUkxkcC5jb20vdGVzdF9jcmxfY3BfNzAuY3JsMDSgMqAwhi5odHRwOi8v\n"
"dGVzdDEudGVzdDFDUkxkcC5jb20vdGVzdF9jcmxfY3BfNzEuY3JsMDSgMqAwhi5o\n"
"dHRwOi8vdGVzdDEudGVzdDFDUkxkcC5jb20vdGVzdF9jcmxfY3BfNzIuY3JsMDSg\n"
"MqAwhi5odHRwOi8vdGVzdDEudGVzdDFDUkxkcC5jb20vdGVzdF9jcmxfY3BfNzMu\n"
"Y3JsMDSgMqAwhi5odHRwOi8vdGVzdDEudGVzdDFDUkxkcC5jb20vdGVzdF9jcmxf\n"
"Y3BfNzQuY3JsMDSgMqAwhi5odHRwOi8vdGVzdDEudGVzdDFDUkxkcC5jb20vdGVz\n"
"dF9jcmxfY3BfNzUuY3JsMDSgMqAwhi5odHRwOi8vdGVzdDEudGVzdDFDUkxkcC5j\n"
"b20vdGVzdF9jcmxfY3BfNzYuY3JsMDSgMqAwhi5odHRwOi8vdGVzdDEudGVzdDFD\n"
"UkxkcC5jb20vdGVzdF9jcmxfY3BfNzcuY3JsMDSgMqAwhi5odHRwOi8vdGVzdDEu\n"
"dGVzdDFDUkxkcC5jb20vdGVzdF9jcmxfY3BfNzguY3JsMDSgMqAwhi5odHRwOi8v\n"
"dGVzdDEudGVzdDFDUkxkcC5jb20vdGVzdF9jcmxfY3BfNzkuY3JsMDSgMqAwhi5o\n"
"dHRwOi8vdGVzdDEudGVzdDFDUkxkcC5jb20vdGVzdF9jcmxfY3BfODAuY3JsMDSg\n"
"MqAwhi5odHRwOi8vdGVzdDEudGVzdDFDUkxkcC5jb20vdGVzdF9jcmxfY3BfODEu\n"
"Y3JsMDSgMqAwhi5odHRwOi8vdGVzdDEudGVzdDFDUkxkcC5jb20vdGVzdF9jcmxf\n"
"Y3BfODIuY3JsMDSgMqAwhi5odHRwOi8vdGVzdDEudGVzdDFDUkxkcC5jb20vdGVz\n"
"dF9jcmxfY3BfODMuY3JsMDSgMqAwhi5odHRwOi8vdGVzdDEudGVzdDFDUkxkcC5j\n"
"b20vdGVzdF9jcmxfY3BfODQuY3JsMDSgMqAwhi5odHRwOi8vdGVzdDEudGVzdDFD\n"
"UkxkcC5jb20vdGVzdF9jcmxfY3BfODUuY3JsMDSgMqAwhi5odHRwOi8vdGVzdDEu\n"
"dGVzdDFDUkxkcC5jb20vdGVzdF9jcmxfY3BfODYuY3JsMDSgMqAwhi5odHRwOi8v\n"
"dGVzdDEudGVzdDFDUkxkcC5jb20vdGVzdF9jcmxfY3BfODcuY3JsMDSgMqAwhi5o\n"
"dHRwOi8vdGVzdDEudGVzdDFDUkxkcC5jb20vdGVzdF9jcmxfY3BfODguY3JsMDSg\n"
"MqAwhi5odHRwOi8vdGVzdDEudGVzdDFDUkxkcC5jb20vdGVzdF9jcmxfY3BfODku\n"
"Y3JsMDSgMqAwhi5odHRwOi8vdGVzdDEudGVzdDFDUkxkcC5jb20vdGVzdF9jcmxf\n"
"Y3BfOTAuY3JsMDSgMqAwhi5odHRwOi8vdGVzdDEudGVzdDFDUkxkcC5jb20vdGVz\n"
"dF9jcmxfY3BfOTEuY3JsMDSgMqAwhi5odHRwOi8vdGVzdDEudGVzdDFDUkxkcC5j\n"
"b20vdGVzdF9jcmxfY3BfOTIuY3JsMDSgMqAwhi5odHRwOi8vdGVzdDEudGVzdDFD\n"
"UkxkcC5jb20vdGVzdF9jcmxfY3BfOTMuY3JsMDSgMqAwhi5odHRwOi8vdGVzdDEu\n"
"dGVzdDFDUkxkcC5jb20vdGVzdF9jcmxfY3BfOTQuY3JsMDSgMqAwhi5odHRwOi8v\n"
"dGVzdDEudGVzdDFDUkxkcC5jb20vdGVzdF9jcmxfY3BfOTUuY3JsMDSgMqAwhi5o\n"
"dHRwOi8vdGVzdDEudGVzdDFDUkxkcC5jb20vdGVzdF9jcmxfY3BfOTYuY3JsMDSg\n"
"MqAwhi5odHRwOi8vdGVzdDEudGVzdDFDUkxkcC5jb20vdGVzdF9jcmxfY3BfOTcu\n"
"Y3JsMDSgMqAwhi5odHRwOi8vdGVzdDEudGVzdDFDUkxkcC5jb20vdGVzdF9jcmxf\n"
"Y3BfOTguY3JsMDSgMqAwhi5odHRwOi8vdGVzdDEudGVzdDFDUkxkcC5jb20vdGVz\n"
"dF9jcmxfY3BfOTkuY3JsMDWgM6Axhi9odHRwOi8vdGVzdDEudGVzdDFDUkxkcC5j\n"
"b20vdGVzdF9jcmxfY3BfMTAwLmNybDA1oDOgMYYvaHR0cDovL3Rlc3QxLnRlc3Qx\n"
"Q1JMZHAuY29tL3Rlc3RfY3JsX2NwXzEwMS5jcmwwCgYIKoZIzj0EAwIDSAAwRQIh\n"
"AK7dZQaO+HAOfH3AnOEJ83tB/9xeMA2Z+K4ptR880auOAiA2pR5bHiVERvqUKQix\n"
"neDdISIVTtOvIqTB//4hVKu0IQ==\n"
"-----END CERTIFICATE-----\n";

const CfEncodingBlob g_inStream = {
    .data = reinterpret_cast<uint8_t *>(g_certWithCrlDp1),
    .len = strlen(g_certWithCrlDp1) + 1,
    .encodingFormat = CF_FORMAT_PEM
};

void CryptoX509CertificateTestPart2::SetUpTestCase()
{
    CfResult ret = OpensslX509CertSpiCreate(&g_inStream, &g_x509CertSpiObj);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(g_x509CertSpiObj, nullptr);
}

void CryptoX509CertificateTestPart2::TearDownTestCase()
{
    CfObjDestroy(g_x509CertSpiObj);
}

void CryptoX509CertificateTestPart2::SetUp()
{
}

void CryptoX509CertificateTestPart2::TearDown()
{
}

/**
 * @tc.name: CryptoX509CertificateTestPart2.CfCRLDpURITest001
 * @tc.desc: Generate certificate with 1 CRL DP URI, get URI return success.
 * @tc.type: FUNC
 * @tc.require: I86VWA
 */
HWTEST_F(CryptoX509CertificateTestPart2, CfCRLDpURITest001, TestSize.Level0)
{
    HcfX509Certificate *x509Cert = nullptr;
    CfResult ret = HcfX509CertificateCreate(&g_inStream, &x509Cert);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(x509Cert, nullptr);

    CfArray outURI = { nullptr, CF_FORMAT_DER, 0 };
    ret = x509Cert->getCRLDistributionPointsURI(x509Cert, &outURI);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(outURI.count, 1); /* CRL DP URI count is 1 */

    CfObjDestroy(x509Cert);
    CfArrayDataClearAndFree(&outURI);
}

/**
 * @tc.name: CryptoX509CertificateTestPart2.CfCRLDpURITest002
 * @tc.desc: Generate certificate with 2 CRL DP URI, get URI return success.
 * @tc.type: FUNC
 * @tc.require: I86VWA
 */
HWTEST_F(CryptoX509CertificateTestPart2, CfCRLDpURITest002, TestSize.Level0)
{
    HcfX509Certificate *x509Cert = nullptr;
    CfEncodingBlob inStream = {
        .data = reinterpret_cast<uint8_t *>(g_certWithCrlDp2),
        .len = strlen(g_certWithCrlDp2) + 1,
        .encodingFormat = CF_FORMAT_PEM
    };
    CfResult ret = HcfX509CertificateCreate(&inStream, &x509Cert);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(x509Cert, nullptr);

    CfArray outURI = { nullptr, CF_FORMAT_DER, 0 };
    ret = x509Cert->getCRLDistributionPointsURI(x509Cert, &outURI);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(outURI.count, 2); /* CRL DP URI count is 2 */

    CfObjDestroy(x509Cert);
    CfArrayDataClearAndFree(&outURI);
}

/**
 * @tc.name: CryptoX509CertificateTestPart2.CfCRLDpURITest003
 * @tc.desc: Generate certificate with 8 CRL DP URI, get URI return success.
 * @tc.type: FUNC
 * @tc.require: I86VWA
 */
HWTEST_F(CryptoX509CertificateTestPart2, CfCRLDpURITest003, TestSize.Level0)
{
    HcfX509Certificate *x509Cert = nullptr;
    CfEncodingBlob inStream = {
        .data = reinterpret_cast<uint8_t *>(g_certWithCrlDp8),
        .len = strlen(g_certWithCrlDp8) + 1,
        .encodingFormat = CF_FORMAT_PEM
    };
    CfResult ret = HcfX509CertificateCreate(&inStream, &x509Cert);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(x509Cert, nullptr);

    CfArray outURI = { nullptr, CF_FORMAT_DER, 0 };
    ret = x509Cert->getCRLDistributionPointsURI(x509Cert, &outURI);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(outURI.count, 8); /* CRL DP URI count is 8 */

    CfObjDestroy(x509Cert);
    CfArrayDataClearAndFree(&outURI);
}

/**
 * @tc.name: CryptoX509CertificateTestPart2.CfCRLDpURITest004
 * @tc.desc: Generate certificate without CRL DP URI, get URI return CF_NOT_EXIST.
 * @tc.type: FUNC
 * @tc.require: I86VWA
 */
HWTEST_F(CryptoX509CertificateTestPart2, CfCRLDpURITest004, TestSize.Level0)
{
    HcfX509Certificate *x509Cert = nullptr;
    CfEncodingBlob inStream = {
        .data = reinterpret_cast<uint8_t *>(g_certWithoutCrlDp),
        .len = strlen(g_certWithoutCrlDp) + 1,
        .encodingFormat = CF_FORMAT_PEM
    };
    CfResult ret = HcfX509CertificateCreate(&inStream, &x509Cert);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(x509Cert, nullptr);

    CfArray outURI = { nullptr, CF_FORMAT_DER, 0 };
    ret = x509Cert->getCRLDistributionPointsURI(x509Cert, &outURI);
    EXPECT_EQ(ret, CF_NOT_EXIST);

    CfObjDestroy(x509Cert);
    CfArrayDataClearAndFree(&outURI);
}

/**
 * @tc.name: CryptoX509CertificateTestPart2.CfCRLDpURITest005
 * @tc.desc: Generate certificate without CRL DP URI, outURI param is nullptr, get URI return CF_INVALID_PARAMS.
 * @tc.type: FUNC
 * @tc.require: I86VWA
 */
HWTEST_F(CryptoX509CertificateTestPart2, CfCRLDpURITest005, TestSize.Level0)
{
    HcfX509Certificate *x509Cert005 = nullptr;
    CfResult ret = HcfX509CertificateCreate(&g_inStream, &x509Cert005);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(x509Cert005, nullptr);

    ret = x509Cert005->getCRLDistributionPointsURI(x509Cert005, nullptr);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    CfObjDestroy(x509Cert005);
}

/**
 * @tc.name: CryptoX509CertificateTestPart2.CfCRLDpURITest006
 * @tc.desc: self is nullptr, outURI is not nullptr, get URI return CF_INVALID_PARAMS.
 * @tc.type: FUNC
 * @tc.require: I86VWA
 */
HWTEST_F(CryptoX509CertificateTestPart2, CfCRLDpURITest006, TestSize.Level0)
{
    HcfX509Certificate *x509Cert006 = nullptr;
    CfResult ret = HcfX509CertificateCreate(&g_inStream, &x509Cert006);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(x509Cert006, nullptr);

    CfArray outURI = { nullptr, CF_FORMAT_DER, 0 };
    ret = x509Cert006->getCRLDistributionPointsURI(nullptr, &outURI);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    CfObjDestroy(x509Cert006);
}

static const char *InvalidX509CertClass(void)
{
    return "INVALID_CERT_CLASS";
}

static const char *ValidX509CertClass(void)
{
    return "HcfX509Certificate";
}

/**
 * @tc.name: CryptoX509CertificateTestPart2.CfCRLDpURITest007
 * @tc.desc: invalid HcfX509Certificate class, get URI return CF_INVALID_PARAMS.
 * @tc.type: FUNC
 * @tc.require: I86VWA
 */
HWTEST_F(CryptoX509CertificateTestPart2, CfCRLDpURITest007, TestSize.Level0)
{
    HcfX509Certificate *x509Cert007 = nullptr;
    CfResult ret = HcfX509CertificateCreate(&g_inStream, &x509Cert007);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(x509Cert007, nullptr);
    x509Cert007->base.base.getClass = InvalidX509CertClass;

    CfArray outURI = { nullptr, CF_FORMAT_DER, 0 };
    ret = x509Cert007->getCRLDistributionPointsURI(x509Cert007, &outURI);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    x509Cert007->base.base.getClass = ValidX509CertClass;
    CfObjDestroy(x509Cert007);
}

/**
 * @tc.name: CryptoX509CertificateTestPart2.CfCRLDpURITest008
 * @tc.desc: cert with CRL DP fullNames, but not has URI, get URI return CF_NOT_EXIST.
 * @tc.type: FUNC
 * @tc.require: I86VWA
 */
HWTEST_F(CryptoX509CertificateTestPart2, CfCRLDpURITest008, TestSize.Level0)
{
    HcfX509Certificate *x509Cert = nullptr;
    CfEncodingBlob inStream = {
        .data = reinterpret_cast<uint8_t *>(g_certWithCrlDpNoURI),
        .len = strlen(g_certWithCrlDpNoURI) + 1,
        .encodingFormat = CF_FORMAT_PEM
    };
    CfResult ret = HcfX509CertificateCreate(&inStream, &x509Cert);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(x509Cert, nullptr);

    CfArray outURI = { nullptr, CF_FORMAT_DER, 0 };
    ret = x509Cert->getCRLDistributionPointsURI(x509Cert, &outURI);
    EXPECT_EQ(ret, CF_NOT_EXIST);

    CfObjDestroy(x509Cert);
    CfArrayDataClearAndFree(&outURI);
}

/**
 * @tc.name: CryptoX509CertificateTestPart2.CfCRLDpURITest009
 * @tc.desc: cert with CRL DP nameRelativeToCRLIssuer, get URI return CF_NOT_EXIST.
 * @tc.type: FUNC
 * @tc.require: I86VWA
 */
HWTEST_F(CryptoX509CertificateTestPart2, CfCRLDpURITest009, TestSize.Level0)
{
    HcfX509Certificate *x509Cert009 = nullptr;
    CfEncodingBlob inStream = {
        .data = reinterpret_cast<uint8_t *>(g_certWithCrlDpIssuer),
        .len = strlen(g_certWithCrlDpIssuer) + 1,
        .encodingFormat = CF_FORMAT_PEM
    };
    CfResult ret = HcfX509CertificateCreate(&inStream, &x509Cert009);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(x509Cert009, nullptr);

    CfArray outURI = { nullptr, CF_FORMAT_DER, 0 };
    ret = x509Cert009->getCRLDistributionPointsURI(x509Cert009, &outURI);
    EXPECT_EQ(ret, CF_NOT_EXIST);

    CfObjDestroy(x509Cert009);
    CfArrayDataClearAndFree(&outURI);
}

/**
 * @tc.name: CryptoX509CertificateTestPart2.CfCRLDpURITest010
 * @tc.desc: cert with CRL DP URI length too long return CF_ERR_CRYPTO_OPERATION.
 * @tc.type: FUNC
 * @tc.require: I86VWA
 */
HWTEST_F(CryptoX509CertificateTestPart2, CfCRLDpURITest010, TestSize.Level0)
{
    HcfX509Certificate *x509Cert010 = nullptr;
    CfEncodingBlob inStream = {
        .data = reinterpret_cast<uint8_t *>(g_certWithCrlDpURILenTooLong),
        .len = strlen(g_certWithCrlDpURILenTooLong) + 1,
        .encodingFormat = CF_FORMAT_PEM
    };
    CfResult ret = HcfX509CertificateCreate(&inStream, &x509Cert010);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(x509Cert010, nullptr);

    CfArray outURI = { nullptr, CF_FORMAT_DER, 0 };
    ret = x509Cert010->getCRLDistributionPointsURI(x509Cert010, &outURI);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);

    CfObjDestroy(x509Cert010);
    CfArrayDataClearAndFree(&outURI);
}

/**
 * @tc.name: CryptoX509CertificateTestPart2.CfCRLDpURITest011
 * @tc.desc: cert with CRL DP URI 100 count, return success.
 * @tc.type: FUNC
 * @tc.require: I86VWA
 */
HWTEST_F(CryptoX509CertificateTestPart2, CfCRLDpURITest011, TestSize.Level0)
{
    HcfX509Certificate *x509Cert011 = nullptr;
    CfEncodingBlob inStream = {
        .data = reinterpret_cast<uint8_t *>(g_certWithCrlDp100),
        .len = strlen(g_certWithCrlDp100) + 1,
        .encodingFormat = CF_FORMAT_PEM
    };
    CfResult ret = HcfX509CertificateCreate(&inStream, &x509Cert011);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(x509Cert011, nullptr);

    CfArray outURI = { nullptr, CF_FORMAT_DER, 0 };
    ret = x509Cert011->getCRLDistributionPointsURI(x509Cert011, &outURI);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(outURI.count, 100); /* CRL DP URI count is 100 */

    CfObjDestroy(x509Cert011);
    CfArrayDataClearAndFree(&outURI);
}

/**
 * @tc.name: CryptoX509CertificateTestPart2.CfCRLDpURITest012
 * @tc.desc: cert with CRL DP URI exceed max 100 count, return CF_ERR_CRYPTO_OPERATION
 * @tc.type: FUNC
 * @tc.require: I86VWA
 */
HWTEST_F(CryptoX509CertificateTestPart2, CfCRLDpURITest012, TestSize.Level0)
{
    HcfX509Certificate *x509Cert012= nullptr;
    CfEncodingBlob inStream = {
        .data = reinterpret_cast<uint8_t *>(g_certWithCrlDp101),
        .len = strlen(g_certWithCrlDp101) + 1,
        .encodingFormat = CF_FORMAT_PEM
    };
    CfResult ret = HcfX509CertificateCreate(&inStream, &x509Cert012);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(x509Cert012, nullptr);

    CfArray outURI = { nullptr, CF_FORMAT_DER, 0 };
    ret = x509Cert012->getCRLDistributionPointsURI(x509Cert012, &outURI);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);

    CfObjDestroy(x509Cert012);
    CfArrayDataClearAndFree(&outURI);
}

/**
 * @tc.name: CryptoX509CertificateTestPart2.CfCRLDpURIEngineTest001
 * @tc.desc: generate engine cert obj with CRL DP URI, get URI return CF_INVALID_PARAMS.
 * @tc.type: FUNC
 * @tc.require: I86VWA
 */
HWTEST_F(CryptoX509CertificateTestPart2, CfCRLDpURIEngineTest001, TestSize.Level0)
{
    HcfX509CertificateSpi *x509CertObj = nullptr;
    CfResult ret = OpensslX509CertSpiCreate(&g_inStream, &x509CertObj);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(x509CertObj, nullptr);

    CfArray outURI = { nullptr, CF_FORMAT_DER, 0 };
    ret = x509CertObj->engineGetCRLDistributionPointsURI(x509CertObj, &outURI);
    EXPECT_EQ(ret, CF_SUCCESS);

    CfArrayDataClearAndFree(&outURI);
    CfObjDestroy(x509CertObj);
}

/**
 * @tc.name: CryptoX509CertificateTestPart2.CfCRLDpURIEngineTest002
 * @tc.desc: generate engine cert obj with CRL DP URI, outURI is null, get URI return CF_INVALID_PARAMS.
 * @tc.type: FUNC
 * @tc.require: I86VWA
 */
HWTEST_F(CryptoX509CertificateTestPart2, CfCRLDpURIEngineTest002, TestSize.Level0)
{
    HcfX509CertificateSpi *x509CertObj = nullptr;
    CfResult ret = OpensslX509CertSpiCreate(&g_inStream, &x509CertObj);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(x509CertObj, nullptr);

    ret = x509CertObj->engineGetCRLDistributionPointsURI(x509CertObj, nullptr);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    CfObjDestroy(x509CertObj);
}

/**
 * @tc.name: CryptoX509CertificateTestPart2.CfCRLDpURIEngineTest003
 * @tc.desc: generate engine cert obj with CRL DP URI, outURI is null, get URI return CF_INVALID_PARAMS.
 * @tc.type: FUNC
 * @tc.require: I86VWA
 */
HWTEST_F(CryptoX509CertificateTestPart2, CfCRLDpURIEngineTest003, TestSize.Level0)
{
    HcfX509CertificateSpi *x509CertObj = nullptr;
    CfResult ret = OpensslX509CertSpiCreate(&g_inStream, &x509CertObj);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(x509CertObj, nullptr);

    CfArray outURI = { nullptr, CF_FORMAT_DER, 0 };
    ret = x509CertObj->engineGetCRLDistributionPointsURI(nullptr, &outURI);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    CfObjDestroy(x509CertObj);
}

static const char *InvalidX509EngineCertClass(void)
{
    return "INVALID_CERT_ENGINE_CLASS";
}

static const char *ValidX509EngineCertClass(void)
{
    return "X509CertOpensslClass";
}

/**
 * @tc.name: CryptoX509CertificateTestPart2.CfCRLDpURIEngineTest004
 * @tc.desc: engine obj class invalid, get URI return CF_INVALID_PARAMS.
 * @tc.type: FUNC
 * @tc.require: I86VWA
 */
HWTEST_F(CryptoX509CertificateTestPart2, CfCRLDpURIEngineTest004, TestSize.Level0)
{
    HcfX509CertificateSpi *x509CertObj = nullptr;
    CfResult ret = OpensslX509CertSpiCreate(&g_inStream, &x509CertObj);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(x509CertObj, nullptr);

    x509CertObj->base.getClass = InvalidX509EngineCertClass;

    CfArray outURI = { nullptr, CF_FORMAT_DER, 0 };
    ret = x509CertObj->engineGetCRLDistributionPointsURI(x509CertObj, &outURI);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    x509CertObj->base.getClass = ValidX509EngineCertClass;
    CfObjDestroy(x509CertObj);
}

/**
 * @tc.name: CryptoX509CertificateTestPart2.CfCRLDpURIEngineTest005
 * @tc.desc: generate engine cert obj with CRL DP URI, malloc failed.
 * @tc.type: FUNC
 * @tc.require: I86VWA
 */
HWTEST_F(CryptoX509CertificateTestPart2, CfCRLDpURIEngineTest005, TestSize.Level0)
{
    HcfX509CertificateSpi *x509CertObj = nullptr;
    CfResult ret = OpensslX509CertSpiCreate(&g_inStream, &x509CertObj);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(x509CertObj, nullptr);

    SetMockFlag(true);
    CfArray outURI = { nullptr, CF_FORMAT_DER, 0 };
    ret = x509CertObj->engineGetCRLDistributionPointsURI(x509CertObj, &outURI);
    EXPECT_NE(ret, CF_SUCCESS);
    SetMockFlag(false);

    CfArrayDataClearAndFree(&outURI);
    CfObjDestroy(x509CertObj);
}

HWTEST_F(CryptoX509CertificateTestPart2, HcfX509CertificateSpiEngineToStringTest001, TestSize.Level0)
{
    CF_LOG_I("HcfX509CertificateSpiEngineToStringTest001");
    ASSERT_NE(g_x509CertSpiObj, nullptr);

    CfBlob blob = { 0, nullptr };
    CfResult ret = g_x509CertSpiObj->engineToString(g_x509CertSpiObj, &blob);
    EXPECT_EQ(ret, CF_SUCCESS);
    CfBlobDataFree(&blob);

    HcfX509CertificateSpi invalidCertSpi;
    invalidCertSpi.base.getClass = InvalidX509CertClass;

    ret = g_x509CertSpiObj->engineToString(&invalidCertSpi, &blob);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_x509CertSpiObj->engineToString(NULL, &blob);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_x509CertSpiObj->engineToString(g_x509CertSpiObj, NULL);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_x509CertSpiObj->engineToString(NULL, NULL);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);
}

HWTEST_F(CryptoX509CertificateTestPart2, HcfX509CertificateSpiEngineHashCodeTest001, TestSize.Level0)
{
    CF_LOG_I("HcfX509CertificateSpiEngineHashCodeTest001");
    ASSERT_NE(g_x509CertSpiObj, nullptr);

    CfBlob blob = { 0, nullptr };
    CfResult ret = g_x509CertSpiObj->engineHashCode(g_x509CertSpiObj, &blob);
    EXPECT_EQ(ret, CF_SUCCESS);
    CfBlobDataFree(&blob);

    HcfX509CertificateSpi invalidCertSpi;
    invalidCertSpi.base.getClass = InvalidX509CertClass;

    ret = g_x509CertSpiObj->engineHashCode(&invalidCertSpi, &blob);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_x509CertSpiObj->engineHashCode(NULL, &blob);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_x509CertSpiObj->engineHashCode(g_x509CertSpiObj, NULL);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_x509CertSpiObj->engineHashCode(NULL, NULL);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);
}

HWTEST_F(CryptoX509CertificateTestPart2, HcfX509CertificateSpiEngineGetExtensionsObjectTest001, TestSize.Level0)
{
    CF_LOG_I("HcfX509CertificateSpiEngineGetExtensionsObjectTest001");
    ASSERT_NE(g_x509CertSpiObj, nullptr);

    CfBlob blob = { 0, nullptr };
    CfResult ret = g_x509CertSpiObj->engineGetExtensionsObject(g_x509CertSpiObj, &blob);
    EXPECT_EQ(ret, CF_SUCCESS);
    CfBlobDataFree(&blob);

    HcfX509CertificateSpi invalidCertSpi;
    invalidCertSpi.base.getClass = InvalidX509CertClass;

    ret = g_x509CertSpiObj->engineGetExtensionsObject(&invalidCertSpi, &blob);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_x509CertSpiObj->engineGetExtensionsObject(NULL, &blob);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_x509CertSpiObj->engineGetExtensionsObject(g_x509CertSpiObj, NULL);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_x509CertSpiObj->engineGetExtensionsObject(NULL, NULL);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);
}
}