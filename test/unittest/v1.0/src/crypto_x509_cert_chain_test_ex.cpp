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

#include "cert_crl_common.h"
#include "certificate_openssl_common.h"
#include "cf_blob.h"
#include "cf_log.h"
#include "cf_mock.h"
#include "cf_object_base.h"
#include "cf_result.h"
#include "crypto_x509_test_common.h"
#include "fwk_class.h"
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

static const char g_pkcs12testPrikey[] =
    "-----BEGIN PRIVATE KEY-----\r\n"
    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC9kBV6Cqd3vSi5\r\n"
    "RuRAWjXEvsfD20ekCYyeJvnnSrHwnKodbF8VWFSv4sqYzMnxObpDLyQw0Uu08tbn\r\n"
    "EQvxv0lOwnWkZR+Oc3M9Ow1uhDkm3eFbY5858mAmtY7Sqzhd0LS9k8Q57FRqOrQm\r\n"
    "7ngHb0O+yjCIn/zmjyEuw51/cPDTM4h3P3di9nhbIg+UOMfkDbuSKRD7UvVV/JZi\r\n"
    "BklF5ZrjFYgzYnWKv7N7XkYMGkaOx8+tue24eK06SapQWDLRnRPCVePV6xtoCmbN\r\n"
    "A3ib/Uvr0qvRwPDCzGGOW9JvQdrI6Z/GD9nt5hqHB15iJVNxkDQtugv14qeDsFPS\r\n"
    "IU8CtkCbAgMBAAECggEBAKbMmMlJhLCM5r+ZDJE/j55ujRLe6XwC1xP2keEeTdK9\r\n"
    "18aKLGR41BPsSH8JfAxh0m75lSvLjoVLRSQPUOZIfjXqUF/2hzzug5F2W8xKVovH\r\n"
    "o1uqHlp71nVZPrJK7Q9H7TH/SyP4uxK6UvkKzt0j34WLHgeqV3t8qCMhB34zIAWG\r\n"
    "BcAuKJNRZGvMvjK99OSOh0SyvGQ5Yb5vyj1/znx3gM4z4deYXxDSyCO0m5I16jmM\r\n"
    "gBEUG0UDUp8Xr2xs/EkhhWYRT1bkDlYZ9IuCbH/vB1YJJFdaO2tDivDUF6IObvNt\r\n"
    "GaVuLlA/rSOJmJFBetrm7n+O2vNJxvoQmBYDKm3+qYkCgYEA9p5C1ZY5XfwwOcqi\r\n"
    "KQ+Asd2NWLG2blhsII5wB8uPhFapjV0S9xTabScUD35AfxHgctafpZeQk4x5niRP\r\n"
    "BHq7hpitaDdYs6A/jhZ7fdVYKb1KRTDt1LXmcg0qVmi/ANNvjhqjvyZM+pEj8yxM\r\n"
    "aOl4isbBfUbzSsEbda3LcHi6+w8CgYEAxMYtkl3gbXJcgbAEdW+nMMQGoFDLkgyu\r\n"
    "n0ZYuRRrWLnnUzZUyqNBwQUaZpwxHaAqi0OAEGSRSZBKRHz9IA2iP9YzcaJ0WtpB\r\n"
    "CPqwBZjrCaVEpHldo2pIdujysXgiXRUiE+VR9ViDmftoVbdL6kttGS08jBBDVIV/\r\n"
    "uQgC/q29UbUCgYAJHirMaMRwNB24VUSPjhItAUrzh4Z+J+i/f2Sm9SC2PNoB7vn/\r\n"
    "hpbYyEQWmo1Z5VhOBp9aaPMgcWYhsaf2O29pd4WZv8oYwgj3gN9J9LRQvr3bNwbk\r\n"
    "AWGmv9Pb4/2D001hjJyXOZxI+0q/99hPXKpnPxfyQMhH8EHKpQVLgDsxgwKBgEiH\r\n"
    "+DJUci5Fkj2ngO08u7bo+rxLK85o6FEDYB7QnQT2eYMdqsGKzej1FZcvCZeu+x+c\r\n"
    "QO9J8pfYHNgD7lXLULwRG6NOS29VtdU2en2FsVU72wJ5Tf+3ZICYOyUZcCk5afdF\r\n"
    "dyFlgBTZK8s0pkH1jYBTQVcrg3X7Q2oTvu7bYcZlAoGAUwQI11mMR8oqfgWMoI/1\r\n"
    "smOoq9qSMlutuWBjoPkbtJEGHEXAvjW1kgdBlPjUCwn6j+oIDLYu8DbfQRdiFQeP\r\n"
    "rVCbbgOgayVpr+8Tv2DqB370GwBpOpuq0yiiN+c39Y0u03Yfve3icyl8+lN1t4h6\r\n"
    "a20rj9HG4sb8tUIHPBv0dgY=\r\n"
    "-----END PRIVATE KEY-----\r\n";

static const char g_pkcs12testCert[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIIDZzCCAk8CFCwQ5cxuFI+fsf/2fkG4gy8UT1gmMA0GCSqGSIb3DQEBCwUAMG8x\r\n"
    "CzAJBgNVBAYTAkVOMQ0wCwYDVQQIDARURVNUMQ0wCwYDVQQHDAR4aWFuMQ8wDQYD\r\n"
    "VQQKDAZodWF3ZWkxDTALBgNVBAsMBHhpYW4xDTALBgNVBAMMBHhpYW4xEzARBgkq\r\n"
    "hkiG9w0BCQEWBHhpYW4wHhcNMjUwODE0MTE1NTQ1WhcNMjYwODE0MTE1NTQ1WjBx\r\n"
    "MQswCQYDVQQGEwJHVDEPMA0GA1UECAwGaHVhd2VpMQ0wCwYDVQQHDAR4aWFuMQ8w\r\n"
    "DQYDVQQKDAZodWF3ZWkxDTALBgNVBAsMBHhpYW4xDTALBgNVBAMMBHhpYW4xEzAR\r\n"
    "BgkqhkiG9w0BCQEWBHhpYW4wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB\r\n"
    "AQC9kBV6Cqd3vSi5RuRAWjXEvsfD20ekCYyeJvnnSrHwnKodbF8VWFSv4sqYzMnx\r\n"
    "ObpDLyQw0Uu08tbnEQvxv0lOwnWkZR+Oc3M9Ow1uhDkm3eFbY5858mAmtY7Sqzhd\r\n"
    "0LS9k8Q57FRqOrQm7ngHb0O+yjCIn/zmjyEuw51/cPDTM4h3P3di9nhbIg+UOMfk\r\n"
    "DbuSKRD7UvVV/JZiBklF5ZrjFYgzYnWKv7N7XkYMGkaOx8+tue24eK06SapQWDLR\r\n"
    "nRPCVePV6xtoCmbNA3ib/Uvr0qvRwPDCzGGOW9JvQdrI6Z/GD9nt5hqHB15iJVNx\r\n"
    "kDQtugv14qeDsFPSIU8CtkCbAgMBAAEwDQYJKoZIhvcNAQELBQADggEBALuqlvql\r\n"
    "q/5SVghmtdzVNlsif9JofSgJhmww3r8HblZ7zD7ALfR6JcxxbBJYdBIn6mf2eNx/\r\n"
    "kTzwYs94D12PhyAP63AcDxS/4Sh7QhmnNIx2SGi/rbFdPm8cmkaFfwr5gQP+ouNB\r\n"
    "1e7vVyNpSjr4F8YcfjOHPofoCdWaOaBPrM760h711y/BTVMjuYkdzn0D1bHZIBc+\r\n"
    "tljIMWXKsTwR6wCIpnFRJbEATTBwV843Q071d62jYueLgdS2wT39Syqb3ao3aHAS\r\n"
    "ZI8k9GgNNKD4qBAZUbQVCs6diTBbeUMaqJ2N+tcQfmGfnNZK+/olEF6Ue/H0LZzY\r\n"
    "nZSOvPxc0c2O34k=\r\n"
    "-----END CERTIFICATE-----\r\n";

static const char g_pkcs12testCaCert[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIIDZTCCAk0CFAoqA7Irtoo7/3+sfOHy0s91pKkiMA0GCSqGSIb3DQEBCwUAMG8x\r\n"
    "CzAJBgNVBAYTAkVOMQ0wCwYDVQQIDARURVNUMQ0wCwYDVQQHDAR4aWFuMQ8wDQYD\r\n"
    "VQQKDAZodWF3ZWkxDTALBgNVBAsMBHhpYW4xDTALBgNVBAMMBHhpYW4xEzARBgkq\r\n"
    "hkiG9w0BCQEWBHhpYW4wHhcNMjUwODE0MTE1NDM0WhcNMjYwODE0MTE1NDM0WjBv\r\n"
    "MQswCQYDVQQGEwJFTjENMAsGA1UECAwEVEVTVDENMAsGA1UEBwwEeGlhbjEPMA0G\r\n"
    "A1UECgwGaHVhd2VpMQ0wCwYDVQQLDAR4aWFuMQ0wCwYDVQQDDAR4aWFuMRMwEQYJ\r\n"
    "KoZIhvcNAQkBFgR4aWFuMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\r\n"
    "wk4aByV5nOw+zIh/1agaN7rQyk+NFuXlYSwINrONRZt8zePSxhxz6gMq0XAb8ld0\r\n"
    "DFC5onGQEI4ED8iP3v7C7yHqIAybTmIy22RWWk8c6h9S40Azp/YHujTTRs2XMe9G\r\n"
    "A/iKed9DwLclbv6+m+WPmIvgFFAJlebtFI6X0E/zBxs/TknR8tJ2uk2G/CGCBlo5\r\n"
    "bbSz5RIPfEmz93rR7prMxQLOsvfdNewNlhe82jxMKfzGEPXYXUj+Xwp8ep+aaUTr\r\n"
    "Kb6Thvx7+uOBxgMM1crREepTKJM/4bsOpb2yIXXcOqclUPAZBvtzIjgs/DdKtCZo\r\n"
    "0Jzr3gUbDJeE2xd+DcADxQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQA5RyDOMYJV\r\n"
    "AsdBUihPvnnakKfAY9CYN9I1tR0b9DaboeL+bONeIKzXyFdDrAj6eZLKZLUblFlH\r\n"
    "BZnbP4lNwfYjmNgp4j7cqSIFVwd2Y+6T29pK6T6XYRsFGOaSp7wFzXplfbP8Ou1b\r\n"
    "o2zTZWWWHbiExuXot4RfQkgH3Zhk5zjJGWvaOksvEhJUaufkWAXbRY2KHmH64dDB\r\n"
    "Bgp50CPObTuc2a+5PAi7W5nj1se2OqKvepoeYLl8pfF/GFRqrvcII9kCm0oyMqBx\r\n"
    "25R7aCNtSnENZnvRBspdYcX8zu6fR1qf0JmpLqLw5pPxJ2Puvq7g+33GWJ3Gq45f\r\n"
    "ZcLXS+9LpW3a\r\n"
    "-----END CERTIFICATE-----\r\n";

const uint8_t g_pkcs12testPrikeyDer[] = {
    0x30, 0x82, 0x04, 0xa3, 0x02, 0x01, 0x00, 0x02, 0x82, 0x01, 0x01, 0x00, 0xbd, 0x90, 0x15, 0x7a,
    0x0a, 0xa7, 0x77, 0xbd, 0x28, 0xb9, 0x46, 0xe4, 0x40, 0x5a, 0x35, 0xc4, 0xbe, 0xc7, 0xc3, 0xdb,
    0x47, 0xa4, 0x09, 0x8c, 0x9e, 0x26, 0xf9, 0xe7, 0x4a, 0xb1, 0xf0, 0x9c, 0xaa, 0x1d, 0x6c, 0x5f,
    0x15, 0x58, 0x54, 0xaf, 0xe2, 0xca, 0x98, 0xcc, 0xc9, 0xf1, 0x39, 0xba, 0x43, 0x2f, 0x24, 0x30,
    0xd1, 0x4b, 0xb4, 0xf2, 0xd6, 0xe7, 0x11, 0x0b, 0xf1, 0xbf, 0x49, 0x4e, 0xc2, 0x75, 0xa4, 0x65,
    0x1f, 0x8e, 0x73, 0x73, 0x3d, 0x3b, 0x0d, 0x6e, 0x84, 0x39, 0x26, 0xdd, 0xe1, 0x5b, 0x63, 0x9f,
    0x39, 0xf2, 0x60, 0x26, 0xb5, 0x8e, 0xd2, 0xab, 0x38, 0x5d, 0xd0, 0xb4, 0xbd, 0x93, 0xc4, 0x39,
    0xec, 0x54, 0x6a, 0x3a, 0xb4, 0x26, 0xee, 0x78, 0x07, 0x6f, 0x43, 0xbe, 0xca, 0x30, 0x88, 0x9f,
    0xfc, 0xe6, 0x8f, 0x21, 0x2e, 0xc3, 0x9d, 0x7f, 0x70, 0xf0, 0xd3, 0x33, 0x88, 0x77, 0x3f, 0x77,
    0x62, 0xf6, 0x78, 0x5b, 0x22, 0x0f, 0x94, 0x38, 0xc7, 0xe4, 0x0d, 0xbb, 0x92, 0x29, 0x10, 0xfb,
    0x52, 0xf5, 0x55, 0xfc, 0x96, 0x62, 0x06, 0x49, 0x45, 0xe5, 0x9a, 0xe3, 0x15, 0x88, 0x33, 0x62,
    0x75, 0x8a, 0xbf, 0xb3, 0x7b, 0x5e, 0x46, 0x0c, 0x1a, 0x46, 0x8e, 0xc7, 0xcf, 0xad, 0xb9, 0xed,
    0xb8, 0x78, 0xad, 0x3a, 0x49, 0xaa, 0x50, 0x58, 0x32, 0xd1, 0x9d, 0x13, 0xc2, 0x55, 0xe3, 0xd5,
    0xeb, 0x1b, 0x68, 0x0a, 0x66, 0xcd, 0x03, 0x78, 0x9b, 0xfd, 0x4b, 0xeb, 0xd2, 0xab, 0xd1, 0xc0,
    0xf0, 0xc2, 0xcc, 0x61, 0x8e, 0x5b, 0xd2, 0x6f, 0x41, 0xda, 0xc8, 0xe9, 0x9f, 0xc6, 0x0f, 0xd9,
    0xed, 0xe6, 0x1a, 0x87, 0x07, 0x5e, 0x62, 0x25, 0x53, 0x71, 0x90, 0x34, 0x2d, 0xba, 0x0b, 0xf5,
    0xe2, 0xa7, 0x83, 0xb0, 0x53, 0xd2, 0x21, 0x4f, 0x02, 0xb6, 0x40, 0x9b, 0x02, 0x03, 0x01, 0x00,
    0x01, 0x02, 0x82, 0x01, 0x01, 0x00, 0xa6, 0xcc, 0x98, 0xc9, 0x49, 0x84, 0xb0, 0x8c, 0xe6, 0xbf,
    0x99, 0x0c, 0x91, 0x3f, 0x8f, 0x9e, 0x6e, 0x8d, 0x12, 0xde, 0xe9, 0x7c, 0x02, 0xd7, 0x13, 0xf6,
    0x91, 0xe1, 0x1e, 0x4d, 0xd2, 0xbd, 0xd7, 0xc6, 0x8a, 0x2c, 0x64, 0x78, 0xd4, 0x13, 0xec, 0x48,
    0x7f, 0x09, 0x7c, 0x0c, 0x61, 0xd2, 0x6e, 0xf9, 0x95, 0x2b, 0xcb, 0x8e, 0x85, 0x4b, 0x45, 0x24,
    0x0f, 0x50, 0xe6, 0x48, 0x7e, 0x35, 0xea, 0x50, 0x5f, 0xf6, 0x87, 0x3c, 0xee, 0x83, 0x91, 0x76,
    0x5b, 0xcc, 0x4a, 0x56, 0x8b, 0xc7, 0xa3, 0x5b, 0xaa, 0x1e, 0x5a, 0x7b, 0xd6, 0x75, 0x59, 0x3e,
    0xb2, 0x4a, 0xed, 0x0f, 0x47, 0xed, 0x31, 0xff, 0x4b, 0x23, 0xf8, 0xbb, 0x12, 0xba, 0x52, 0xf9,
    0x0a, 0xce, 0xdd, 0x23, 0xdf, 0x85, 0x8b, 0x1e, 0x07, 0xaa, 0x57, 0x7b, 0x7c, 0xa8, 0x23, 0x21,
    0x07, 0x7e, 0x33, 0x20, 0x05, 0x86, 0x05, 0xc0, 0x2e, 0x28, 0x93, 0x51, 0x64, 0x6b, 0xcc, 0xbe,
    0x32, 0xbd, 0xf4, 0xe4, 0x8e, 0x87, 0x44, 0xb2, 0xbc, 0x64, 0x39, 0x61, 0xbe, 0x6f, 0xca, 0x3d,
    0x7f, 0xce, 0x7c, 0x77, 0x80, 0xce, 0x33, 0xe1, 0xd7, 0x98, 0x5f, 0x10, 0xd2, 0xc8, 0x23, 0xb4,
    0x9b, 0x92, 0x35, 0xea, 0x39, 0x8c, 0x80, 0x11, 0x14, 0x1b, 0x45, 0x03, 0x52, 0x9f, 0x17, 0xaf,
    0x6c, 0x6c, 0xfc, 0x49, 0x21, 0x85, 0x66, 0x11, 0x4f, 0x56, 0xe4, 0x0e, 0x56, 0x19, 0xf4, 0x8b,
    0x82, 0x6c, 0x7f, 0xef, 0x07, 0x56, 0x09, 0x24, 0x57, 0x5a, 0x3b, 0x6b, 0x43, 0x8a, 0xf0, 0xd4,
    0x17, 0xa2, 0x0e, 0x6e, 0xf3, 0x6d, 0x19, 0xa5, 0x6e, 0x2e, 0x50, 0x3f, 0xad, 0x23, 0x89, 0x98,
    0x91, 0x41, 0x7a, 0xda, 0xe6, 0xee, 0x7f, 0x8e, 0xda, 0xf3, 0x49, 0xc6, 0xfa, 0x10, 0x98, 0x16,
    0x03, 0x2a, 0x6d, 0xfe, 0xa9, 0x89, 0x02, 0x81, 0x81, 0x00, 0xf6, 0x9e, 0x42, 0xd5, 0x96, 0x39,
    0x5d, 0xfc, 0x30, 0x39, 0xca, 0xa2, 0x29, 0x0f, 0x80, 0xb1, 0xdd, 0x8d, 0x58, 0xb1, 0xb6, 0x6e,
    0x58, 0x6c, 0x20, 0x8e, 0x70, 0x07, 0xcb, 0x8f, 0x84, 0x56, 0xa9, 0x8d, 0x5d, 0x12, 0xf7, 0x14,
    0xda, 0x6d, 0x27, 0x14, 0x0f, 0x7e, 0x40, 0x7f, 0x11, 0xe0, 0x72, 0xd6, 0x9f, 0xa5, 0x97, 0x90,
    0x93, 0x8c, 0x79, 0x9e, 0x24, 0x4f, 0x04, 0x7a, 0xbb, 0x86, 0x98, 0xad, 0x68, 0x37, 0x58, 0xb3,
    0xa0, 0x3f, 0x8e, 0x16, 0x7b, 0x7d, 0xd5, 0x58, 0x29, 0xbd, 0x4a, 0x45, 0x30, 0xed, 0xd4, 0xb5,
    0xe6, 0x72, 0x0d, 0x2a, 0x56, 0x68, 0xbf, 0x00, 0xd3, 0x6f, 0x8e, 0x1a, 0xa3, 0xbf, 0x26, 0x4c,
    0xfa, 0x91, 0x23, 0xf3, 0x2c, 0x4c, 0x68, 0xe9, 0x78, 0x8a, 0xc6, 0xc1, 0x7d, 0x46, 0xf3, 0x4a,
    0xc1, 0x1b, 0x75, 0xad, 0xcb, 0x70, 0x78, 0xba, 0xfb, 0x0f, 0x02, 0x81, 0x81, 0x00, 0xc4, 0xc6,
    0x2d, 0x92, 0x5d, 0xe0, 0x6d, 0x72, 0x5c, 0x81, 0xb0, 0x04, 0x75, 0x6f, 0xa7, 0x30, 0xc4, 0x06,
    0xa0, 0x50, 0xcb, 0x92, 0x0c, 0xae, 0x9f, 0x46, 0x58, 0xb9, 0x14, 0x6b, 0x58, 0xb9, 0xe7, 0x53,
    0x36, 0x54, 0xca, 0xa3, 0x41, 0xc1, 0x05, 0x1a, 0x66, 0x9c, 0x31, 0x1d, 0xa0, 0x2a, 0x8b, 0x43,
    0x80, 0x10, 0x64, 0x91, 0x49, 0x90, 0x4a, 0x44, 0x7c, 0xfd, 0x20, 0x0d, 0xa2, 0x3f, 0xd6, 0x33,
    0x71, 0xa2, 0x74, 0x5a, 0xda, 0x41, 0x08, 0xfa, 0xb0, 0x05, 0x98, 0xeb, 0x09, 0xa5, 0x44, 0xa4,
    0x79, 0x5d, 0xa3, 0x6a, 0x48, 0x76, 0xe8, 0xf2, 0xb1, 0x78, 0x22, 0x5d, 0x15, 0x22, 0x13, 0xe5,
    0x51, 0xf5, 0x58, 0x83, 0x99, 0xfb, 0x68, 0x55, 0xb7, 0x4b, 0xea, 0x4b, 0x6d, 0x19, 0x2d, 0x3c,
    0x8c, 0x10, 0x43, 0x54, 0x85, 0x7f, 0xb9, 0x08, 0x02, 0xfe, 0xad, 0xbd, 0x51, 0xb5, 0x02, 0x81,
    0x80, 0x09, 0x1e, 0x2a, 0xcc, 0x68, 0xc4, 0x70, 0x34, 0x1d, 0xb8, 0x55, 0x44, 0x8f, 0x8e, 0x12,
    0x2d, 0x01, 0x4a, 0xf3, 0x87, 0x86, 0x7e, 0x27, 0xe8, 0xbf, 0x7f, 0x64, 0xa6, 0xf5, 0x20, 0xb6,
    0x3c, 0xda, 0x01, 0xee, 0xf9, 0xff, 0x86, 0x96, 0xd8, 0xc8, 0x44, 0x16, 0x9a, 0x8d, 0x59, 0xe5,
    0x58, 0x4e, 0x06, 0x9f, 0x5a, 0x68, 0xf3, 0x20, 0x71, 0x66, 0x21, 0xb1, 0xa7, 0xf6, 0x3b, 0x6f,
    0x69, 0x77, 0x85, 0x99, 0xbf, 0xca, 0x18, 0xc2, 0x08, 0xf7, 0x80, 0xdf, 0x49, 0xf4, 0xb4, 0x50,
    0xbe, 0xbd, 0xdb, 0x37, 0x06, 0xe4, 0x01, 0x61, 0xa6, 0xbf, 0xd3, 0xdb, 0xe3, 0xfd, 0x83, 0xd3,
    0x4d, 0x61, 0x8c, 0x9c, 0x97, 0x39, 0x9c, 0x48, 0xfb, 0x4a, 0xbf, 0xf7, 0xd8, 0x4f, 0x5c, 0xaa,
    0x67, 0x3f, 0x17, 0xf2, 0x40, 0xc8, 0x47, 0xf0, 0x41, 0xca, 0xa5, 0x05, 0x4b, 0x80, 0x3b, 0x31,
    0x83, 0x02, 0x81, 0x80, 0x48, 0x87, 0xf8, 0x32, 0x54, 0x72, 0x2e, 0x45, 0x92, 0x3d, 0xa7, 0x80,
    0xed, 0x3c, 0xbb, 0xb6, 0xe8, 0xfa, 0xbc, 0x4b, 0x2b, 0xce, 0x68, 0xe8, 0x51, 0x03, 0x60, 0x1e,
    0xd0, 0x9d, 0x04, 0xf6, 0x79, 0x83, 0x1d, 0xaa, 0xc1, 0x8a, 0xcd, 0xe8, 0xf5, 0x15, 0x97, 0x2f,
    0x09, 0x97, 0xae, 0xfb, 0x1f, 0x9c, 0x40, 0xef, 0x49, 0xf2, 0x97, 0xd8, 0x1c, 0xd8, 0x03, 0xee,
    0x55, 0xcb, 0x50, 0xbc, 0x11, 0x1b, 0xa3, 0x4e, 0x4b, 0x6f, 0x55, 0xb5, 0xd5, 0x36, 0x7a, 0x7d,
    0x85, 0xb1, 0x55, 0x3b, 0xdb, 0x02, 0x79, 0x4d, 0xff, 0xb7, 0x64, 0x80, 0x98, 0x3b, 0x25, 0x19,
    0x70, 0x29, 0x39, 0x69, 0xf7, 0x45, 0x77, 0x21, 0x65, 0x80, 0x14, 0xd9, 0x2b, 0xcb, 0x34, 0xa6,
    0x41, 0xf5, 0x8d, 0x80, 0x53, 0x41, 0x57, 0x2b, 0x83, 0x75, 0xfb, 0x43, 0x6a, 0x13, 0xbe, 0xee,
    0xdb, 0x61, 0xc6, 0x65, 0x02, 0x81, 0x80, 0x53, 0x04, 0x08, 0xd7, 0x59, 0x8c, 0x47, 0xca, 0x2a,
    0x7e, 0x05, 0x8c, 0xa0, 0x8f, 0xf5, 0xb2, 0x63, 0xa8, 0xab, 0xda, 0x92, 0x32, 0x5b, 0xad, 0xb9,
    0x60, 0x63, 0xa0, 0xf9, 0x1b, 0xb4, 0x91, 0x06, 0x1c, 0x45, 0xc0, 0xbe, 0x35, 0xb5, 0x92, 0x07,
    0x41, 0x94, 0xf8, 0xd4, 0x0b, 0x09, 0xfa, 0x8f, 0xea, 0x08, 0x0c, 0xb6, 0x2e, 0xf0, 0x36, 0xdf,
    0x41, 0x17, 0x62, 0x15, 0x07, 0x8f, 0xad, 0x50, 0x9b, 0x6e, 0x03, 0xa0, 0x6b, 0x25, 0x69, 0xaf,
    0xef, 0x13, 0xbf, 0x60, 0xea, 0x07, 0x7e, 0xf4, 0x1b, 0x00, 0x69, 0x3a, 0x9b, 0xaa, 0xd3, 0x28,
    0xa2, 0x37, 0xe7, 0x37, 0xf5, 0x8d, 0x2e, 0xd3, 0x76, 0x1f, 0xbd, 0xed, 0xe2, 0x73, 0x29, 0x7c,
    0xfa, 0x53, 0x75, 0xb7, 0x88, 0x7a, 0x6b, 0x6d, 0x2b, 0x8f, 0xd1, 0xc6, 0xe2, 0xc6, 0xfc, 0xb5,
    0x42, 0x07, 0x3c, 0x1b, 0xf4, 0x76, 0x06 };

const uint8_t g_pkcs12testCertDer[] = {
    0x30, 0x82, 0x03, 0x67, 0x30, 0x82, 0x02, 0x4f, 0x02, 0x14, 0x2c, 0x10, 0xe5, 0xcc, 0x6e, 0x14,
    0x8f, 0x9f, 0xb1, 0xff, 0xf6, 0x7e, 0x41, 0xb8, 0x83, 0x2f, 0x14, 0x4f, 0x58, 0x26, 0x30, 0x0d,
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30, 0x6f, 0x31,
    0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x45, 0x4e, 0x31, 0x0d, 0x30, 0x0b,
    0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x04, 0x54, 0x45, 0x53, 0x54, 0x31, 0x0d, 0x30, 0x0b, 0x06,
    0x03, 0x55, 0x04, 0x07, 0x0c, 0x04, 0x78, 0x69, 0x61, 0x6e, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03,
    0x55, 0x04, 0x0a, 0x0c, 0x06, 0x68, 0x75, 0x61, 0x77, 0x65, 0x69, 0x31, 0x0d, 0x30, 0x0b, 0x06,
    0x03, 0x55, 0x04, 0x0b, 0x0c, 0x04, 0x78, 0x69, 0x61, 0x6e, 0x31, 0x0d, 0x30, 0x0b, 0x06, 0x03,
    0x55, 0x04, 0x03, 0x0c, 0x04, 0x78, 0x69, 0x61, 0x6e, 0x31, 0x13, 0x30, 0x11, 0x06, 0x09, 0x2a,
    0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01, 0x16, 0x04, 0x78, 0x69, 0x61, 0x6e, 0x30, 0x1e,
    0x17, 0x0d, 0x32, 0x35, 0x30, 0x38, 0x31, 0x34, 0x31, 0x31, 0x35, 0x35, 0x34, 0x35, 0x5a, 0x17,
    0x0d, 0x32, 0x36, 0x30, 0x38, 0x31, 0x34, 0x31, 0x31, 0x35, 0x35, 0x34, 0x35, 0x5a, 0x30, 0x71,
    0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x47, 0x54, 0x31, 0x0f, 0x30,
    0x0d, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x06, 0x68, 0x75, 0x61, 0x77, 0x65, 0x69, 0x31, 0x0d,
    0x30, 0x0b, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0c, 0x04, 0x78, 0x69, 0x61, 0x6e, 0x31, 0x0f, 0x30,
    0x0d, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x06, 0x68, 0x75, 0x61, 0x77, 0x65, 0x69, 0x31, 0x0d,
    0x30, 0x0b, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c, 0x04, 0x78, 0x69, 0x61, 0x6e, 0x31, 0x0d, 0x30,
    0x0b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x04, 0x78, 0x69, 0x61, 0x6e, 0x31, 0x13, 0x30, 0x11,
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01, 0x16, 0x04, 0x78, 0x69, 0x61,
    0x6e, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
    0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01,
    0x01, 0x00, 0xbd, 0x90, 0x15, 0x7a, 0x0a, 0xa7, 0x77, 0xbd, 0x28, 0xb9, 0x46, 0xe4, 0x40, 0x5a,
    0x35, 0xc4, 0xbe, 0xc7, 0xc3, 0xdb, 0x47, 0xa4, 0x09, 0x8c, 0x9e, 0x26, 0xf9, 0xe7, 0x4a, 0xb1,
    0xf0, 0x9c, 0xaa, 0x1d, 0x6c, 0x5f, 0x15, 0x58, 0x54, 0xaf, 0xe2, 0xca, 0x98, 0xcc, 0xc9, 0xf1,
    0x39, 0xba, 0x43, 0x2f, 0x24, 0x30, 0xd1, 0x4b, 0xb4, 0xf2, 0xd6, 0xe7, 0x11, 0x0b, 0xf1, 0xbf,
    0x49, 0x4e, 0xc2, 0x75, 0xa4, 0x65, 0x1f, 0x8e, 0x73, 0x73, 0x3d, 0x3b, 0x0d, 0x6e, 0x84, 0x39,
    0x26, 0xdd, 0xe1, 0x5b, 0x63, 0x9f, 0x39, 0xf2, 0x60, 0x26, 0xb5, 0x8e, 0xd2, 0xab, 0x38, 0x5d,
    0xd0, 0xb4, 0xbd, 0x93, 0xc4, 0x39, 0xec, 0x54, 0x6a, 0x3a, 0xb4, 0x26, 0xee, 0x78, 0x07, 0x6f,
    0x43, 0xbe, 0xca, 0x30, 0x88, 0x9f, 0xfc, 0xe6, 0x8f, 0x21, 0x2e, 0xc3, 0x9d, 0x7f, 0x70, 0xf0,
    0xd3, 0x33, 0x88, 0x77, 0x3f, 0x77, 0x62, 0xf6, 0x78, 0x5b, 0x22, 0x0f, 0x94, 0x38, 0xc7, 0xe4,
    0x0d, 0xbb, 0x92, 0x29, 0x10, 0xfb, 0x52, 0xf5, 0x55, 0xfc, 0x96, 0x62, 0x06, 0x49, 0x45, 0xe5,
    0x9a, 0xe3, 0x15, 0x88, 0x33, 0x62, 0x75, 0x8a, 0xbf, 0xb3, 0x7b, 0x5e, 0x46, 0x0c, 0x1a, 0x46,
    0x8e, 0xc7, 0xcf, 0xad, 0xb9, 0xed, 0xb8, 0x78, 0xad, 0x3a, 0x49, 0xaa, 0x50, 0x58, 0x32, 0xd1,
    0x9d, 0x13, 0xc2, 0x55, 0xe3, 0xd5, 0xeb, 0x1b, 0x68, 0x0a, 0x66, 0xcd, 0x03, 0x78, 0x9b, 0xfd,
    0x4b, 0xeb, 0xd2, 0xab, 0xd1, 0xc0, 0xf0, 0xc2, 0xcc, 0x61, 0x8e, 0x5b, 0xd2, 0x6f, 0x41, 0xda,
    0xc8, 0xe9, 0x9f, 0xc6, 0x0f, 0xd9, 0xed, 0xe6, 0x1a, 0x87, 0x07, 0x5e, 0x62, 0x25, 0x53, 0x71,
    0x90, 0x34, 0x2d, 0xba, 0x0b, 0xf5, 0xe2, 0xa7, 0x83, 0xb0, 0x53, 0xd2, 0x21, 0x4f, 0x02, 0xb6,
    0x40, 0x9b, 0x02, 0x03, 0x01, 0x00, 0x01, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
    0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0xbb, 0xaa, 0x96, 0xfa, 0xa5,
    0xab, 0xfe, 0x52, 0x56, 0x08, 0x66, 0xb5, 0xdc, 0xd5, 0x36, 0x5b, 0x22, 0x7f, 0xd2, 0x68, 0x7d,
    0x28, 0x09, 0x86, 0x6c, 0x30, 0xde, 0xbf, 0x07, 0x6e, 0x56, 0x7b, 0xcc, 0x3e, 0xc0, 0x2d, 0xf4,
    0x7a, 0x25, 0xcc, 0x71, 0x6c, 0x12, 0x58, 0x74, 0x12, 0x27, 0xea, 0x67, 0xf6, 0x78, 0xdc, 0x7f,
    0x91, 0x3c, 0xf0, 0x62, 0xcf, 0x78, 0x0f, 0x5d, 0x8f, 0x87, 0x20, 0x0f, 0xeb, 0x70, 0x1c, 0x0f,
    0x14, 0xbf, 0xe1, 0x28, 0x7b, 0x42, 0x19, 0xa7, 0x34, 0x8c, 0x76, 0x48, 0x68, 0xbf, 0xad, 0xb1,
    0x5d, 0x3e, 0x6f, 0x1c, 0x9a, 0x46, 0x85, 0x7f, 0x0a, 0xf9, 0x81, 0x03, 0xfe, 0xa2, 0xe3, 0x41,
    0xd5, 0xee, 0xef, 0x57, 0x23, 0x69, 0x4a, 0x3a, 0xf8, 0x17, 0xc6, 0x1c, 0x7e, 0x33, 0x87, 0x3e,
    0x87, 0xe8, 0x09, 0xd5, 0x9a, 0x39, 0xa0, 0x4f, 0xac, 0xce, 0xfa, 0xd2, 0x1e, 0xf5, 0xd7, 0x2f,
    0xc1, 0x4d, 0x53, 0x23, 0xb9, 0x89, 0x1d, 0xce, 0x7d, 0x03, 0xd5, 0xb1, 0xd9, 0x20, 0x17, 0x3e,
    0xb6, 0x58, 0xc8, 0x31, 0x65, 0xca, 0xb1, 0x3c, 0x11, 0xeb, 0x00, 0x88, 0xa6, 0x71, 0x51, 0x25,
    0xb1, 0x00, 0x4d, 0x30, 0x70, 0x57, 0xce, 0x37, 0x43, 0x4e, 0xf5, 0x77, 0xad, 0xa3, 0x62, 0xe7,
    0x8b, 0x81, 0xd4, 0xb6, 0xc1, 0x3d, 0xfd, 0x4b, 0x2a, 0x9b, 0xdd, 0xaa, 0x37, 0x68, 0x70, 0x12,
    0x64, 0x8f, 0x24, 0xf4, 0x68, 0x0d, 0x34, 0xa0, 0xf8, 0xa8, 0x10, 0x19, 0x51, 0xb4, 0x15, 0x0a,
    0xce, 0x9d, 0x89, 0x30, 0x5b, 0x79, 0x43, 0x1a, 0xa8, 0x9d, 0x8d, 0xfa, 0xd7, 0x10, 0x7e, 0x61,
    0x9f, 0x9c, 0xd6, 0x4a, 0xfb, 0xfa, 0x25, 0x10, 0x5e, 0x94, 0x7b, 0xf1, 0xf4, 0x2d, 0x9c, 0xd8,
    0x9d, 0x94, 0x8e, 0xbc, 0xfc, 0x5c, 0xd1, 0xcd, 0x8e, 0xdf, 0x89 };

const uint8_t g_pkcs12testCaCertDer[] = {
    0x30, 0x82, 0x03, 0x65, 0x30, 0x82, 0x02, 0x4d, 0x02, 0x14, 0x0a, 0x2a, 0x03, 0xb2, 0x2b, 0xb6,
    0x8a, 0x3b, 0xff, 0x7f, 0xac, 0x7c, 0xe1, 0xf2, 0xd2, 0xcf, 0x75, 0xa4, 0xa9, 0x22, 0x30, 0x0d,
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30, 0x6f, 0x31,
    0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x45, 0x4e, 0x31, 0x0d, 0x30, 0x0b,
    0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x04, 0x54, 0x45, 0x53, 0x54, 0x31, 0x0d, 0x30, 0x0b, 0x06,
    0x03, 0x55, 0x04, 0x07, 0x0c, 0x04, 0x78, 0x69, 0x61, 0x6e, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03,
    0x55, 0x04, 0x0a, 0x0c, 0x06, 0x68, 0x75, 0x61, 0x77, 0x65, 0x69, 0x31, 0x0d, 0x30, 0x0b, 0x06,
    0x03, 0x55, 0x04, 0x0b, 0x0c, 0x04, 0x78, 0x69, 0x61, 0x6e, 0x31, 0x0d, 0x30, 0x0b, 0x06, 0x03,
    0x55, 0x04, 0x03, 0x0c, 0x04, 0x78, 0x69, 0x61, 0x6e, 0x31, 0x13, 0x30, 0x11, 0x06, 0x09, 0x2a,
    0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01, 0x16, 0x04, 0x78, 0x69, 0x61, 0x6e, 0x30, 0x1e,
    0x17, 0x0d, 0x32, 0x35, 0x30, 0x38, 0x31, 0x34, 0x31, 0x31, 0x35, 0x34, 0x33, 0x34, 0x5a, 0x17,
    0x0d, 0x32, 0x36, 0x30, 0x38, 0x31, 0x34, 0x31, 0x31, 0x35, 0x34, 0x33, 0x34, 0x5a, 0x30, 0x6f,
    0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x45, 0x4e, 0x31, 0x0d, 0x30,
    0x0b, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x04, 0x54, 0x45, 0x53, 0x54, 0x31, 0x0d, 0x30, 0x0b,
    0x06, 0x03, 0x55, 0x04, 0x07, 0x0c, 0x04, 0x78, 0x69, 0x61, 0x6e, 0x31, 0x0f, 0x30, 0x0d, 0x06,
    0x03, 0x55, 0x04, 0x0a, 0x0c, 0x06, 0x68, 0x75, 0x61, 0x77, 0x65, 0x69, 0x31, 0x0d, 0x30, 0x0b,
    0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c, 0x04, 0x78, 0x69, 0x61, 0x6e, 0x31, 0x0d, 0x30, 0x0b, 0x06,
    0x03, 0x55, 0x04, 0x03, 0x0c, 0x04, 0x78, 0x69, 0x61, 0x6e, 0x31, 0x13, 0x30, 0x11, 0x06, 0x09,
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01, 0x16, 0x04, 0x78, 0x69, 0x61, 0x6e, 0x30,
    0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
    0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00,
    0xc2, 0x4e, 0x1a, 0x07, 0x25, 0x79, 0x9c, 0xec, 0x3e, 0xcc, 0x88, 0x7f, 0xd5, 0xa8, 0x1a, 0x37,
    0xba, 0xd0, 0xca, 0x4f, 0x8d, 0x16, 0xe5, 0xe5, 0x61, 0x2c, 0x08, 0x36, 0xb3, 0x8d, 0x45, 0x9b,
    0x7c, 0xcd, 0xe3, 0xd2, 0xc6, 0x1c, 0x73, 0xea, 0x03, 0x2a, 0xd1, 0x70, 0x1b, 0xf2, 0x57, 0x74,
    0x0c, 0x50, 0xb9, 0xa2, 0x71, 0x90, 0x10, 0x8e, 0x04, 0x0f, 0xc8, 0x8f, 0xde, 0xfe, 0xc2, 0xef,
    0x21, 0xea, 0x20, 0x0c, 0x9b, 0x4e, 0x62, 0x32, 0xdb, 0x64, 0x56, 0x5a, 0x4f, 0x1c, 0xea, 0x1f,
    0x52, 0xe3, 0x40, 0x33, 0xa7, 0xf6, 0x07, 0xba, 0x34, 0xd3, 0x46, 0xcd, 0x97, 0x31, 0xef, 0x46,
    0x03, 0xf8, 0x8a, 0x79, 0xdf, 0x43, 0xc0, 0xb7, 0x25, 0x6e, 0xfe, 0xbe, 0x9b, 0xe5, 0x8f, 0x98,
    0x8b, 0xe0, 0x14, 0x50, 0x09, 0x95, 0xe6, 0xed, 0x14, 0x8e, 0x97, 0xd0, 0x4f, 0xf3, 0x07, 0x1b,
    0x3f, 0x4e, 0x49, 0xd1, 0xf2, 0xd2, 0x76, 0xba, 0x4d, 0x86, 0xfc, 0x21, 0x82, 0x06, 0x5a, 0x39,
    0x6d, 0xb4, 0xb3, 0xe5, 0x12, 0x0f, 0x7c, 0x49, 0xb3, 0xf7, 0x7a, 0xd1, 0xee, 0x9a, 0xcc, 0xc5,
    0x02, 0xce, 0xb2, 0xf7, 0xdd, 0x35, 0xec, 0x0d, 0x96, 0x17, 0xbc, 0xda, 0x3c, 0x4c, 0x29, 0xfc,
    0xc6, 0x10, 0xf5, 0xd8, 0x5d, 0x48, 0xfe, 0x5f, 0x0a, 0x7c, 0x7a, 0x9f, 0x9a, 0x69, 0x44, 0xeb,
    0x29, 0xbe, 0x93, 0x86, 0xfc, 0x7b, 0xfa, 0xe3, 0x81, 0xc6, 0x03, 0x0c, 0xd5, 0xca, 0xd1, 0x11,
    0xea, 0x53, 0x28, 0x93, 0x3f, 0xe1, 0xbb, 0x0e, 0xa5, 0xbd, 0xb2, 0x21, 0x75, 0xdc, 0x3a, 0xa7,
    0x25, 0x50, 0xf0, 0x19, 0x06, 0xfb, 0x73, 0x22, 0x38, 0x2c, 0xfc, 0x37, 0x4a, 0xb4, 0x26, 0x68,
    0xd0, 0x9c, 0xeb, 0xde, 0x05, 0x1b, 0x0c, 0x97, 0x84, 0xdb, 0x17, 0x7e, 0x0d, 0xc0, 0x03, 0xc5,
    0x02, 0x03, 0x01, 0x00, 0x01, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
    0x01, 0x0b, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x39, 0x47, 0x20, 0xce, 0x31, 0x82, 0x55,
    0x02, 0xc7, 0x41, 0x52, 0x28, 0x4f, 0xbe, 0x79, 0xda, 0x90, 0xa7, 0xc0, 0x63, 0xd0, 0x98, 0x37,
    0xd2, 0x35, 0xb5, 0x1d, 0x1b, 0xf4, 0x36, 0x9b, 0xa1, 0xe2, 0xfe, 0x6c, 0xe3, 0x5e, 0x20, 0xac,
    0xd7, 0xc8, 0x57, 0x43, 0xac, 0x08, 0xfa, 0x79, 0x92, 0xca, 0x64, 0xb5, 0x1b, 0x94, 0x59, 0x47,
    0x05, 0x99, 0xdb, 0x3f, 0x89, 0x4d, 0xc1, 0xf6, 0x23, 0x98, 0xd8, 0x29, 0xe2, 0x3e, 0xdc, 0xa9,
    0x22, 0x05, 0x57, 0x07, 0x76, 0x63, 0xee, 0x93, 0xdb, 0xda, 0x4a, 0xe9, 0x3e, 0x97, 0x61, 0x1b,
    0x05, 0x18, 0xe6, 0x92, 0xa7, 0xbc, 0x05, 0xcd, 0x7a, 0x65, 0x7d, 0xb3, 0xfc, 0x3a, 0xed, 0x5b,
    0xa3, 0x6c, 0xd3, 0x65, 0x65, 0x96, 0x1d, 0xb8, 0x84, 0xc6, 0xe5, 0xe8, 0xb7, 0x84, 0x5f, 0x42,
    0x48, 0x07, 0xdd, 0x98, 0x64, 0xe7, 0x38, 0xc9, 0x19, 0x6b, 0xda, 0x3a, 0x4b, 0x2f, 0x12, 0x12,
    0x54, 0x6a, 0xe7, 0xe4, 0x58, 0x05, 0xdb, 0x45, 0x8d, 0x8a, 0x1e, 0x61, 0xfa, 0xe1, 0xd0, 0xc1,
    0x06, 0x0a, 0x79, 0xd0, 0x23, 0xce, 0x6d, 0x3b, 0x9c, 0xd9, 0xaf, 0xb9, 0x3c, 0x08, 0xbb, 0x5b,
    0x99, 0xe3, 0xd6, 0xc7, 0xb6, 0x3a, 0xa2, 0xaf, 0x7a, 0x9a, 0x1e, 0x60, 0xb9, 0x7c, 0xa5, 0xf1,
    0x7f, 0x18, 0x54, 0x6a, 0xae, 0xf7, 0x08, 0x23, 0xd9, 0x02, 0x9b, 0x4a, 0x32, 0x32, 0xa0, 0x71,
    0xdb, 0x94, 0x7b, 0x68, 0x23, 0x6d, 0x4a, 0x71, 0x0d, 0x66, 0x7b, 0xd1, 0x06, 0xca, 0x5d, 0x61,
    0xc5, 0xfc, 0xce, 0xee, 0x9f, 0x47, 0x5a, 0x9f, 0xd0, 0x99, 0xa9, 0x2e, 0xa2, 0xf0, 0xe6, 0x93,
    0xf1, 0x27, 0x63, 0xee, 0xbe, 0xae, 0xe0, 0xfb, 0x7d, 0xc6, 0x58, 0x9d, 0xc6, 0xab, 0x8e, 0x5f,
    0x65, 0xc2, 0xd7, 0x4b, 0xef, 0x4b, 0xa5, 0x6d, 0xda };

const CfEncodingBlob certPem = {
    .data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_pkcs12testCert)),
    .len = strlen(g_pkcs12testCert) + 1,
    .encodingFormat = CF_FORMAT_PEM
};

const CfEncodingBlob certDer = {
    .data = const_cast<uint8_t *>(g_pkcs12testCertDer),
    .len = sizeof(g_pkcs12testCertDer) + 1,
    .encodingFormat = CF_FORMAT_DER
};

const CfEncodingBlob caCertPem = {
    .data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_pkcs12testCaCert)),
    .len = strlen(g_pkcs12testCaCert) + 1,
    .encodingFormat = CF_FORMAT_PEM
};

const CfEncodingBlob caCertDer = {
    .data = const_cast<uint8_t *>(g_pkcs12testCaCertDer),
    .len = sizeof(g_pkcs12testCaCertDer) + 1,
    .encodingFormat = CF_FORMAT_DER
};

static const char g_testPkcs12Pwd[] = "123456";
static const char g_testPkcs12PwdBad[] = "12";

int __real_X509_print(BIO *bp, X509 *x);
BIO *__real_BIO_new(const BIO_METHOD *type);
int __real_i2d_X509_bio(BIO *bp, X509 *x509);
int __real_X509_check_private_key(const X509 *x, const EVP_PKEY *k);
int __real_X509_digest(const X509 *cert, const EVP_MD *md, unsigned char *data, unsigned int *len);
PKCS12_SAFEBAG *__real_PKCS12_add_cert(STACK_OF(PKCS12_SAFEBAG) **pbags, X509 *cert);
int __real_PKCS12_add_localkeyid(PKCS12_SAFEBAG *bag, unsigned char *name, int namelen);
PKCS7 *__real_PKCS12_pack_p7encdata_ex(int pbe_nid, const char *pass, int passlen, unsigned char *salt, int saltlen,
    int iter, STACK_OF(PKCS12_SAFEBAG) *bags, OSSL_LIB_CTX *ctx, const char *propq);
PKCS7 *__real_PKCS12_pack_p7data(STACK_OF(PKCS12_SAFEBAG) *sk);
PKCS12 *__real_PKCS12_add_safes_ex(STACK_OF(PKCS7) *safes, int nid_p7, OSSL_LIB_CTX *ctx, const char *propq);
int __real_PKCS12_set_mac(PKCS12 *p12, const char *pass, int passlen, unsigned char *salt, int saltlen,
    int iter, const EVP_MD *md_type);
PKCS12_SAFEBAG *__real_PKCS12_SAFEBAG_create_pkcs8_encrypt_ex(int pbe_nid, const char *pass, int passlen,
    unsigned char *salt, int saltlen, int iter, PKCS8_PRIV_KEY_INFO *p8inf, OSSL_LIB_CTX *ctx, const char *propq);
int __real_i2d_PKCS12(PKCS12 *a, unsigned char **pp);
int __real_PKCS12_add_safe(STACK_OF(PKCS7) **psafes, STACK_OF(PKCS12_SAFEBAG) *bags,
    int nid_safe, int iter, const char *pass);
BIO *__real_BIO_new_mem_buf(const void *buf, int len);
#ifdef __cplusplus
}
#endif

namespace {
class CryptoX509CertChainTestEx : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

static HcfCertChain *g_certChainP7b = nullptr;
static HcfX509CertChainSpi *g_certChainP7bSpi = nullptr;

static const char *GetInvalidCertChainClass(void)
{
    return "HcfInvalidCertChain";
}

void CryptoX509CertChainTestEx::SetUpTestCase()
{
    CfResult ret = HcfCertChainCreate(&g_inStreamChainDataP7b, nullptr, &g_certChainP7b);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(g_certChainP7b, nullptr);

    HcfX509CertChainSpi *certChainSpi = nullptr;
    ret = HcfX509CertChainByEncSpiCreate(&g_inStreamChainDataP7b, &certChainSpi);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainSpi, nullptr);
    g_certChainP7bSpi = certChainSpi;
}

void CryptoX509CertChainTestEx::TearDownTestCase()
{
    CfObjDestroy(g_certChainP7b);
    CfObjDestroy(g_certChainP7bSpi);
}

void CryptoX509CertChainTestEx::SetUp() {}

void CryptoX509CertChainTestEx::TearDown() {}

HWTEST_F(CryptoX509CertChainTestEx, ToStringTest001, TestSize.Level0)
{
    CF_LOG_I("CryptoX509CertChainTestEx - ToStringTest001");
    ASSERT_NE(g_certChainP7b, nullptr);

    CfBlob blob = { 0, nullptr };
    CfResult ret = g_certChainP7b->toString(g_certChainP7b, &blob);
    EXPECT_EQ(ret, CF_SUCCESS);
    CfBlobDataFree(&blob);

    HcfCertChain certChain;
    certChain.base.getClass = GetInvalidCertChainClass;

    ret = g_certChainP7b->toString(&certChain, &blob);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_certChainP7b->toString(NULL, &blob);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_certChainP7b->toString(g_certChainP7b, NULL);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_certChainP7b->toString(NULL, NULL);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), BIO_new(_))
        .WillOnce(Return(nullptr))
        .WillRepeatedly(Invoke(__real_BIO_new));
    ret = g_certChainP7b->toString(g_certChainP7b, &blob);
    EXPECT_EQ(ret, CF_ERR_MALLOC);
    X509OpensslMock::SetMockFlag(false);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), BIO_ctrl(_, _, _, _)).WillRepeatedly(Return(0));
    ret = g_certChainP7b->toString(g_certChainP7b, &blob);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);
}

HWTEST_F(CryptoX509CertChainTestEx, HashCodeTest001, TestSize.Level0)
{
    CF_LOG_I("CryptoX509CertChainTestEx - HashCodeTest001");
    ASSERT_NE(g_certChainP7b, nullptr);

    CfBlob blob = { 0, nullptr };
    CfResult ret = g_certChainP7b->hashCode(g_certChainP7b, &blob);
    EXPECT_EQ(ret, CF_SUCCESS);
    CfBlobDataFree(&blob);

    SetMockFlag(true);
    ret = g_certChainP7b->hashCode(g_certChainP7b, &blob);
    EXPECT_EQ(ret, CF_ERR_MALLOC);
    SetMockFlag(false);

    HcfCertChain certChain;
    certChain.base.getClass = GetInvalidCertChainClass;

    ret = g_certChainP7b->hashCode(&certChain, &blob);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_certChainP7b->hashCode(NULL, &blob);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_certChainP7b->hashCode(g_certChainP7b, NULL);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_certChainP7b->hashCode(NULL, NULL);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), BIO_new(_))
        .WillOnce(Return(nullptr))
        .WillRepeatedly(Invoke(__real_BIO_new));
    ret = g_certChainP7b->hashCode(g_certChainP7b, &blob);
    EXPECT_EQ(ret, CF_ERR_MALLOC);
    X509OpensslMock::SetMockFlag(false);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), i2d_X509_bio(_, _))
        .WillOnce(Return(-1))
        .WillRepeatedly(Invoke(__real_i2d_X509_bio));
    ret = g_certChainP7b->hashCode(g_certChainP7b, &blob);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), BIO_ctrl(_, _, _, _)).WillRepeatedly(Return(0));
    ret = g_certChainP7b->hashCode(g_certChainP7b, &blob);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);
}

HWTEST_F(CryptoX509CertChainTestEx, HcfX509CertChainSpiEngineToStringTest001, TestSize.Level0)
{
    CF_LOG_I("HcfX509CertChainSpiEngineToStringTest001");
    ASSERT_NE(g_certChainP7bSpi, nullptr);

    CfBlob blob = { 0, nullptr };
    CfResult ret = g_certChainP7bSpi->engineToString(g_certChainP7bSpi, &blob);
    EXPECT_EQ(ret, CF_SUCCESS);
    CfBlobDataFree(&blob);

    HcfX509CertChainSpi InvalidCertChainSpi;
    InvalidCertChainSpi.base.getClass = GetInvalidCertChainClass;

    ret = g_certChainP7bSpi->engineToString(&InvalidCertChainSpi, &blob);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_certChainP7bSpi->engineToString(NULL, &blob);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_certChainP7bSpi->engineToString(g_certChainP7bSpi, NULL);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_certChainP7bSpi->engineToString(NULL, NULL);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);
}

HWTEST_F(CryptoX509CertChainTestEx, HcfX509CertChainSpiEngineHashCodeTest001, TestSize.Level0)
{
    CF_LOG_I("HcfX509CertChainSpiEngineHashCodeTest001");
    ASSERT_NE(g_certChainP7bSpi, nullptr);

    CfBlob blob = { 0, nullptr };
    CfResult ret = g_certChainP7bSpi->engineHashCode(g_certChainP7bSpi, &blob);
    EXPECT_EQ(ret, CF_SUCCESS);
    CfBlobDataFree(&blob);

    HcfX509CertChainSpi InvalidCertChainSpi;
    InvalidCertChainSpi.base.getClass = GetInvalidCertChainClass;

    ret = g_certChainP7bSpi->engineHashCode(&InvalidCertChainSpi, &blob);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_certChainP7bSpi->engineHashCode(NULL, &blob);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_certChainP7bSpi->engineHashCode(g_certChainP7bSpi, NULL);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_certChainP7bSpi->engineHashCode(NULL, NULL);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);
}

HWTEST_F(CryptoX509CertChainTestEx, HcfCreatePkcs12Test001, TestSize.Level0)
{
    HcfX509P12Collection *p12Collection =
        static_cast<HcfX509P12Collection *>(CfMalloc(sizeof(HcfX509P12Collection), 0));
    ASSERT_NE(p12Collection, nullptr);

    CfBlob prikey;
    prikey.size = sizeof(g_pkcs12testPrikeyDer);
    prikey.data = const_cast<uint8_t *>(g_pkcs12testPrikeyDer);
    p12Collection->prikey = &prikey;
    p12Collection->isPem = false;

    HcfX509Certificate *mainCert = nullptr;
    CfResult ret = HcfX509CertificateCreate(&certDer, &mainCert);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(mainCert, nullptr);
    p12Collection->cert = mainCert;

    HcfX509Certificate *caCert = nullptr;
    ret = HcfX509CertificateCreate(&caCertDer, &caCert);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(caCert, nullptr);
    p12Collection->otherCertsCount = 1;
    p12Collection->otherCerts = static_cast<HcfX509Certificate **>(CfMalloc(sizeof(HcfX509Certificate *), 0));
    p12Collection->otherCerts[0] = caCert;

    HcfPkcs12CreatingConfig conf = { 0 };
    CfBlob pwd;
    pwd.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testPkcs12Pwd));
    pwd.size = strlen(g_testPkcs12Pwd) + 1;
    conf.pwd = &pwd;
    conf.keyEncParams.saltLen = 16;
    conf.keyEncParams.iteration = 1000;
    conf.keyEncParams.alg = AES_128_CBC;
    conf.encryptCert = true;
    conf.certEncParams.saltLen = 16;
    conf.certEncParams.iteration = 1000;
    conf.certEncParams.alg = AES_128_CBC;
    conf.macSaltLen = 16;
    conf.macIteration = 1000;
    conf.macAlg = CF_MAC_SHA256;

    CfBlob blob = { 0, nullptr };

    ret = HcfCreatePkcs12(p12Collection, &conf, &blob);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_GT(blob.size, 0);

    CfBlobDataFree(&blob);
    CfObjDestroy(mainCert);
    CfObjDestroy(caCert);
    CfFree(p12Collection->otherCerts);
    p12Collection->otherCerts = nullptr;
    p12Collection->otherCertsCount = 0;
    CfFree(p12Collection);
    p12Collection = nullptr;
}

HWTEST_F(CryptoX509CertChainTestEx, HcfCreatePkcs12Test002, TestSize.Level0)
{
    HcfX509P12Collection *p12Collection =
        static_cast<HcfX509P12Collection *>(CfMalloc(sizeof(HcfX509P12Collection), 0));
    ASSERT_NE(p12Collection, nullptr);

    CfBlob prikey;
    prikey.size = strlen(g_pkcs12testPrikey);
    prikey.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_pkcs12testPrikey));
    p12Collection->prikey = &prikey;
    p12Collection->isPem = true;

    HcfX509Certificate *mainCert = nullptr;
    CfResult ret = HcfX509CertificateCreate(&certPem, &mainCert);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(mainCert, nullptr);
    p12Collection->cert = mainCert;

    HcfX509Certificate *caCert = nullptr;
    ret = HcfX509CertificateCreate(&caCertPem, &caCert);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(caCert, nullptr);

    p12Collection->otherCertsCount = 1;
    p12Collection->otherCerts = static_cast<HcfX509Certificate **>(CfMalloc(sizeof(HcfX509Certificate *), 0));
    p12Collection->otherCerts[0] = caCert;

    HcfPkcs12CreatingConfig conf = { 0 };
    CfBlob pwd;
    pwd.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testPkcs12Pwd));
    pwd.size = strlen(g_testPkcs12Pwd) + 1;
    conf.pwd = &pwd;
    conf.keyEncParams.saltLen = 16;
    conf.keyEncParams.iteration = 1000;
    conf.keyEncParams.alg = AES_128_CBC;
    conf.encryptCert = true;
    conf.certEncParams.saltLen = 16;
    conf.certEncParams.iteration = 1000;
    conf.certEncParams.alg = AES_128_CBC;
    conf.macSaltLen = 16;
    conf.macIteration = 1000;
    conf.macAlg = CF_MAC_SHA256;

    CfBlob blob = { 0, nullptr };

    ret = HcfCreatePkcs12(p12Collection, &conf, &blob);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_GT(blob.size, 0);

    CfBlobDataFree(&blob);
    CfObjDestroy(mainCert);
    CfObjDestroy(caCert);
    CfFree(p12Collection->otherCerts);
    p12Collection->otherCerts = nullptr;
    p12Collection->otherCertsCount = 0;
    CfFree(p12Collection);
    p12Collection = nullptr;
}

HWTEST_F(CryptoX509CertChainTestEx, HcfCreatePkcs12Test003, TestSize.Level0)
{
    HcfX509P12Collection *p12Collection = nullptr;
    CfBlob blob = { 0, nullptr };

    CfResult ret = HcfCreatePkcs12(p12Collection, nullptr, &blob);
    EXPECT_EQ(ret, CF_ERR_PARAMETER_CHECK);
    EXPECT_EQ(blob.data, nullptr);
    EXPECT_EQ(blob.size, 0);

    HcfPkcs12CreatingConfig conf = { 0 };
    CfBlob pwd;
    pwd.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testPkcs12Pwd));
    pwd.size = strlen(g_testPkcs12Pwd) + 1;
    conf.pwd = &pwd;
    conf.keyEncParams.saltLen = 16;
    conf.keyEncParams.iteration = 1000;
    conf.keyEncParams.alg = AES_128_CBC;
    conf.encryptCert = true;
    conf.certEncParams.saltLen = 16;
    conf.certEncParams.iteration = 1000;
    conf.certEncParams.alg = AES_128_CBC;
    conf.macSaltLen = 16;
    conf.macIteration = 1000;
    conf.macAlg = CF_MAC_SHA256;

    ret = HcfCreatePkcs12(p12Collection, &conf, &blob);
    EXPECT_EQ(ret, CF_ERR_PARAMETER_CHECK);
    EXPECT_EQ(blob.data, nullptr);
    EXPECT_EQ(blob.size, 0);
}

HWTEST_F(CryptoX509CertChainTestEx, HcfCreatePkcs12Test004, TestSize.Level0)
{
    CfBlob blob = { 0, nullptr };

    HcfX509P12Collection *p12Collection =
        static_cast<HcfX509P12Collection *>(CfMalloc(sizeof(HcfX509P12Collection), 0));
    ASSERT_NE(p12Collection, nullptr);

    CfBlob prikey;
    prikey.size = sizeof(g_pkcs12testPrikey);
    prikey.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_pkcs12testPrikey));
    p12Collection->prikey = &prikey;
    p12Collection->isPem = true;

    HcfX509Certificate *mainCert = nullptr;
    CfResult ret = HcfX509CertificateCreate(&certPem, &mainCert);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(mainCert, nullptr);
    p12Collection->cert = mainCert;

    HcfX509Certificate *caCert = nullptr;
    ret = HcfX509CertificateCreate(&caCertPem, &caCert);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(caCert, nullptr);

    p12Collection->otherCertsCount = 1;
    p12Collection->otherCerts = static_cast<HcfX509Certificate **>(CfMalloc(sizeof(HcfX509Certificate *), 0));
    p12Collection->otherCerts[0] = caCert;

    ret = HcfCreatePkcs12(p12Collection, nullptr, &blob);
    EXPECT_EQ(ret, CF_ERR_PARAMETER_CHECK);
    EXPECT_EQ(blob.data, nullptr);
    EXPECT_EQ(blob.size, 0);

    CfObjDestroy(mainCert);
    CfObjDestroy(caCert);
    CfFree(p12Collection->otherCerts);
    p12Collection->otherCerts = nullptr;
    p12Collection->otherCertsCount = 0;
    CfFree(p12Collection);
    p12Collection = nullptr;
}

HWTEST_F(CryptoX509CertChainTestEx, HcfCreatePkcs12Test005, TestSize.Level0)
{
    HcfX509P12Collection *p12Collection =
        static_cast<HcfX509P12Collection *>(CfMalloc(sizeof(HcfX509P12Collection), 0));
    ASSERT_NE(p12Collection, nullptr);

    HcfPkcs12CreatingConfig conf = { 0 };
    CfBlob pwd;
    pwd.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testPkcs12Pwd));
    pwd.size = strlen(g_testPkcs12Pwd) + 1;
    conf.pwd = &pwd;
    conf.keyEncParams.saltLen = 16;
    conf.keyEncParams.iteration = 1000;
    conf.keyEncParams.alg = AES_128_CBC;
    conf.encryptCert = true;
    conf.certEncParams.saltLen = 16;
    conf.certEncParams.iteration = 1000;
    conf.certEncParams.alg = AES_128_CBC;
    conf.macSaltLen = 16;
    conf.macIteration = 1000;
    conf.macAlg = CF_MAC_SHA256;

    CfBlob blob = { 0, nullptr };

    CfResult ret = HcfCreatePkcs12(p12Collection, &conf, &blob);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    EXPECT_EQ(blob.data, nullptr);
    EXPECT_EQ(blob.size, 0);

    CfBlob pwdNull = { 0, nullptr };
    conf.pwd = &pwdNull;
    ret = HcfCreatePkcs12(p12Collection, &conf, &blob);
    EXPECT_EQ(ret, CF_ERR_PARAMETER_CHECK);
    EXPECT_EQ(blob.data, nullptr);
    EXPECT_EQ(blob.size, 0);

    CfFree(p12Collection->otherCerts);
    p12Collection->otherCerts = nullptr;
    p12Collection->otherCertsCount = 0;
    CfFree(p12Collection);
    p12Collection = nullptr;
}

HWTEST_F(CryptoX509CertChainTestEx, HcfCreatePkcs12Test006, TestSize.Level0)
{
    HcfX509P12Collection *p12Collection =
        static_cast<HcfX509P12Collection *>(CfMalloc(sizeof(HcfX509P12Collection), 0));
    ASSERT_NE(p12Collection, nullptr);

    CfBlob prikey;
    prikey.size = strlen(g_pkcs12testPrikey);
    prikey.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_pkcs12testPrikey));
    p12Collection->prikey = &prikey;
    p12Collection->isPem = true;

    HcfX509Certificate *mainCert = nullptr;
    CfResult ret = HcfX509CertificateCreate(&certPem, &mainCert);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(mainCert, nullptr);
    p12Collection->cert = mainCert;

    HcfX509Certificate *caCert = nullptr;
    ret = HcfX509CertificateCreate(&caCertPem, &caCert);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(caCert, nullptr);

    p12Collection->otherCertsCount = 1;
    p12Collection->otherCerts = static_cast<HcfX509Certificate **>(CfMalloc(sizeof(HcfX509Certificate *), 0));
    p12Collection->otherCerts[0] = caCert;

    HcfPkcs12CreatingConfig conf = { 0 };
    CfBlob pwd;
    pwd.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testPkcs12PwdBad));
    pwd.size = strlen(g_testPkcs12PwdBad) + 1;
    conf.pwd = &pwd;

    CfBlob blob = { 0, nullptr };

    ret = HcfCreatePkcs12(p12Collection, &conf, &blob);
    EXPECT_EQ(ret, CF_ERR_PARAMETER_CHECK);
    EXPECT_EQ(blob.data, nullptr);
    EXPECT_EQ(blob.size, 0);

    CfObjDestroy(mainCert);
    CfObjDestroy(caCert);
    CfFree(p12Collection->otherCerts);
    p12Collection->otherCerts = nullptr;
    p12Collection->otherCertsCount = 0;
    CfFree(p12Collection);
    p12Collection = nullptr;
}

HWTEST_F(CryptoX509CertChainTestEx, HcfCreatePkcs12Test007, TestSize.Level0)
{
    HcfX509P12Collection *p12Collection =
        static_cast<HcfX509P12Collection *>(CfMalloc(sizeof(HcfX509P12Collection), 0));
    ASSERT_NE(p12Collection, nullptr);

    CfBlob prikey;
    prikey.size = strlen(g_pkcs12testPrikey);
    prikey.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_pkcs12testPrikey));
    p12Collection->prikey = &prikey;
    p12Collection->isPem = true;

    HcfX509Certificate *mainCert = nullptr;
    CfResult ret = HcfX509CertificateCreate(&certPem, &mainCert);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(mainCert, nullptr);
    p12Collection->cert = mainCert;

    HcfX509Certificate *caCert = nullptr;
    ret = HcfX509CertificateCreate(&caCertPem, &caCert);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(caCert, nullptr);

    p12Collection->otherCertsCount = 1;
    p12Collection->otherCerts = static_cast<HcfX509Certificate **>(CfMalloc(sizeof(HcfX509Certificate *), 0));
    p12Collection->otherCerts[0] = caCert;

    HcfPkcs12CreatingConfig conf = { 0 };
    CfBlob pwd;
    pwd.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testPkcs12Pwd));
    pwd.size = strlen(g_testPkcs12Pwd) + 1;
    conf.pwd = &pwd;
    conf.keyEncParams.saltLen = 16;
    conf.keyEncParams.iteration = -1;
    conf.keyEncParams.alg = AES_128_CBC;
    conf.encryptCert = true;
    conf.certEncParams.saltLen = 16;
    conf.certEncParams.iteration = -1;
    conf.certEncParams.alg = AES_128_CBC;
    conf.macSaltLen = 16;
    conf.macIteration = -1;
    conf.macAlg = CF_MAC_SHA256;

    CfBlob blob = { 0, nullptr };

    ret = HcfCreatePkcs12(p12Collection, &conf, &blob);
    EXPECT_EQ(ret, CF_ERR_PARAMETER_CHECK);
    EXPECT_EQ(blob.data, nullptr);
    EXPECT_EQ(blob.size, 0);

    CfObjDestroy(mainCert);
    CfObjDestroy(caCert);
    CfFree(p12Collection->otherCerts);
    p12Collection->otherCerts = nullptr;
    p12Collection->otherCertsCount = 0;
    CfFree(p12Collection);
    p12Collection = nullptr;
}

HWTEST_F(CryptoX509CertChainTestEx, HcfCreatePkcs12Test008, TestSize.Level0)
{
    HcfX509P12Collection *p12Collection =
        static_cast<HcfX509P12Collection *>(CfMalloc(sizeof(HcfX509P12Collection), 0));
    ASSERT_NE(p12Collection, nullptr);

    CfBlob prikey;
    prikey.size = strlen(g_pkcs12testPrikey);
    prikey.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_pkcs12testPrikey));
    p12Collection->prikey = &prikey;
    p12Collection->isPem = true;

    HcfX509Certificate *mainCert = nullptr;
    CfResult ret = HcfX509CertificateCreate(&certPem, &mainCert);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(mainCert, nullptr);
    p12Collection->cert = mainCert;

    HcfX509Certificate *caCert = nullptr;
    ret = HcfX509CertificateCreate(&caCertPem, &caCert);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(caCert, nullptr);

    p12Collection->otherCertsCount = 1;
    p12Collection->otherCerts = static_cast<HcfX509Certificate **>(CfMalloc(sizeof(HcfX509Certificate *), 0));
    p12Collection->otherCerts[0] = caCert;

    HcfPkcs12CreatingConfig conf = { 0 };
    CfBlob pwd;
    pwd.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testPkcs12Pwd));
    pwd.size = strlen(g_testPkcs12Pwd) + 1;
    conf.pwd = &pwd;
    conf.keyEncParams.saltLen = 6;
    conf.keyEncParams.iteration = 1000;
    conf.keyEncParams.alg = AES_128_CBC;
    conf.encryptCert = true;
    conf.certEncParams.saltLen = 0;
    conf.certEncParams.iteration = 1000;
    conf.certEncParams.alg = AES_128_CBC;
    conf.macSaltLen = -1;
    conf.macIteration = 1000;
    conf.macAlg = CF_MAC_SHA256;

    CfBlob blob = { 0, nullptr };

    ret = HcfCreatePkcs12(p12Collection, &conf, &blob);
    EXPECT_EQ(ret, CF_ERR_PARAMETER_CHECK);
    EXPECT_EQ(blob.data, nullptr);
    EXPECT_EQ(blob.size, 0);

    CfBlobDataFree(&blob);
    CfObjDestroy(mainCert);
    CfObjDestroy(caCert);
    CfFree(p12Collection->otherCerts);
    p12Collection->otherCerts = nullptr;
    p12Collection->otherCertsCount = 0;
    CfFree(p12Collection);
    p12Collection = nullptr;
}

HWTEST_F(CryptoX509CertChainTestEx, HcfCreatePkcs12Test009, TestSize.Level0)
{
    HcfX509P12Collection *p12Collection =
        static_cast<HcfX509P12Collection *>(CfMalloc(sizeof(HcfX509P12Collection), 0));
    ASSERT_NE(p12Collection, nullptr);

    CfBlob prikey;
    prikey.size = strlen(g_pkcs12testPrikey);
    prikey.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_pkcs12testPrikey));
    p12Collection->prikey = &prikey;
    p12Collection->isPem = true;

    HcfX509Certificate *mainCert = nullptr;
    CfResult ret = HcfX509CertificateCreate(&certPem, &mainCert);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(mainCert, nullptr);
    p12Collection->cert = mainCert;

    HcfX509Certificate *caCert = nullptr;
    ret = HcfX509CertificateCreate(&caCertPem, &caCert);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(caCert, nullptr);

    p12Collection->otherCertsCount = 1;
    p12Collection->otherCerts = static_cast<HcfX509Certificate **>(CfMalloc(sizeof(HcfX509Certificate *), 0));
    p12Collection->otherCerts[0] = caCert;

    HcfPkcs12CreatingConfig conf = { 0 };
    CfBlob pwd;
    pwd.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testPkcs12Pwd));
    pwd.size = strlen(g_testPkcs12Pwd) + 1;
    conf.pwd = &pwd;
    conf.keyEncParams.saltLen = 16;
    conf.keyEncParams.iteration = 1000;
    conf.keyEncParams.alg = (CfPbesEncryptionAlgorithm)(-1);
    conf.encryptCert = true;
    conf.certEncParams.saltLen = 16;
    conf.certEncParams.iteration = 1000;
    conf.certEncParams.alg = (CfPbesEncryptionAlgorithm)3;
    conf.macSaltLen = 16;
    conf.macIteration = 1000;
    conf.macAlg = CfPkcs12MacDigestAlgorithm(-2);

    CfBlob blob = { 0, nullptr };

    ret = HcfCreatePkcs12(p12Collection, &conf, &blob);
    EXPECT_EQ(ret, CF_ERR_PARAMETER_CHECK);
    EXPECT_EQ(blob.data, nullptr);
    EXPECT_EQ(blob.size, 0);

    CfObjDestroy(mainCert);
    CfObjDestroy(caCert);
    CfFree(p12Collection->otherCerts);
    p12Collection->otherCerts = nullptr;
    p12Collection->otherCertsCount = 0;
    CfFree(p12Collection);
    p12Collection = nullptr;
}

HWTEST_F(CryptoX509CertChainTestEx, HcfCreatePkcs12Test010, TestSize.Level0)
{
    HcfX509P12Collection *p12Collection =
        static_cast<HcfX509P12Collection *>(CfMalloc(sizeof(HcfX509P12Collection), 0));
    ASSERT_NE(p12Collection, nullptr);

    CfBlob prikey;
    prikey.size = strlen(g_pkcs12testPrikey);
    prikey.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_pkcs12testPrikey));
    p12Collection->prikey = &prikey;
    p12Collection->isPem = true;

    HcfPkcs12CreatingConfig conf = { 0 };
    CfBlob pwd;
    pwd.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testPkcs12Pwd));
    pwd.size = strlen(g_testPkcs12Pwd) + 1;
    conf.pwd = &pwd;
    conf.keyEncParams.saltLen = 16;
    conf.keyEncParams.iteration = 1000;
    conf.keyEncParams.alg = AES_192_CBC;
    conf.encryptCert = false;
    conf.certEncParams.saltLen = 16;
    conf.certEncParams.iteration = 1000;
    conf.certEncParams.alg = AES_256_CBC;
    conf.macSaltLen = 16;
    conf.macIteration = 1000;
    conf.macAlg = CF_MAC_SHA384;

    CfBlob blob = { 0, nullptr };
    CfResult ret = HcfCreatePkcs12Func(p12Collection, &conf, &blob);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_GT(blob.size, 0);
    CfBlobDataFree(&blob);

    conf.macAlg = CF_MAC_SHA512;
    ret = HcfCreatePkcs12Func(p12Collection, &conf, &blob);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_GT(blob.size, 0);
    CfBlobDataFree(&blob);

    CfFree(p12Collection);
    p12Collection = nullptr;
}

HWTEST_F(CryptoX509CertChainTestEx, HcfCreatePkcs12Test011, TestSize.Level0)
{
    HcfX509P12Collection *p12Collection =
        static_cast<HcfX509P12Collection *>(CfMalloc(sizeof(HcfX509P12Collection), 0));
    ASSERT_NE(p12Collection, nullptr);

    CfBlob prikey;
    prikey.size = strlen(g_pkcs12testPrikey);
    prikey.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_pkcs12testPrikey));
    p12Collection->prikey = &prikey;
    p12Collection->isPem = true;

    HcfPkcs12CreatingConfig conf = { 0 };
    CfBlob *pwd = static_cast<CfBlob *>(CfMalloc(sizeof(CfBlob), 0));
    pwd->data = static_cast<uint8_t *>(CfMalloc(strlen(g_testPkcs12Pwd) + 1, 0));
    (void)memcpy_s(pwd->data, strlen(g_testPkcs12Pwd) + 1, g_testPkcs12Pwd, strlen(g_testPkcs12Pwd) + 1);
    pwd->size = strlen(g_testPkcs12Pwd) + 1;
    conf.pwd = pwd;

    CfBlob blob = { 0, nullptr };
    CfResult ret = HcfCreatePkcs12Func(p12Collection, nullptr, &blob);
    EXPECT_EQ(ret, CF_ERR_PARAMETER_CHECK);
    EXPECT_EQ(blob.data, nullptr);
    EXPECT_EQ(blob.size, 0);
    CfBlobClearAndFree(&pwd);

    pwd = static_cast<CfBlob *>(CfMalloc(sizeof(CfBlob), 0));
    pwd->data = static_cast<uint8_t *>(CfMalloc(strlen(g_testPkcs12PwdBad) + 1, 0));
    (void)memcpy_s(pwd->data, strlen(g_testPkcs12PwdBad) + 1, g_testPkcs12PwdBad, strlen(g_testPkcs12PwdBad) + 1);
    pwd->size = strlen(g_testPkcs12PwdBad) + 1;
    conf.pwd = pwd;
    conf.keyEncParams.saltLen = 16;
    conf.keyEncParams.iteration = 1000;
    conf.keyEncParams.alg = AES_128_CBC;
    conf.encryptCert = true;
    conf.certEncParams.saltLen = 16;
    conf.certEncParams.iteration = 1000;
    conf.certEncParams.alg = AES_128_CBC;
    conf.macSaltLen = 16;
    conf.macIteration = 1000;
    conf.macAlg = CF_MAC_SHA256;
    ret = HcfCreatePkcs12Func(p12Collection, &conf, &blob);
    EXPECT_EQ(ret, CF_ERR_PARAMETER_CHECK);
    EXPECT_EQ(blob.data, nullptr);
    EXPECT_EQ(blob.size, 0);

    CfBlobClearAndFree(&pwd);
    CfBlobClearAndFree(nullptr);

    CfFree(p12Collection);
    p12Collection = nullptr;
}

HWTEST_F(CryptoX509CertChainTestEx, HcfCreatePkcs12Test012, TestSize.Level0)
{
    HcfX509P12Collection *p12Collection =
        static_cast<HcfX509P12Collection *>(CfMalloc(sizeof(HcfX509P12Collection), 0));
    ASSERT_NE(p12Collection, nullptr);

    CfBlob prikey;
    prikey.size = strlen(g_pkcs12testPrikey);
    prikey.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_pkcs12testPrikey));
    p12Collection->prikey = &prikey;
    p12Collection->isPem = true;

    HcfX509Certificate *mainCert = nullptr;
    CfResult ret = HcfX509CertificateCreate(&certPem, &mainCert);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(mainCert, nullptr);
    p12Collection->cert = mainCert;

    HcfPkcs12CreatingConfig conf = { 0 };
    CfBlob pwd;
    pwd.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testPkcs12Pwd));
    pwd.size = strlen(g_testPkcs12Pwd) + 1;
    conf.pwd = &pwd;
    conf.keyEncParams.saltLen = 16;
    conf.keyEncParams.iteration = 1000;
    conf.keyEncParams.alg = AES_128_CBC;
    conf.encryptCert = true;
    conf.certEncParams.saltLen = 16;
    conf.certEncParams.iteration = 1000;
    conf.certEncParams.alg = AES_128_CBC;
    conf.macSaltLen = 16;
    conf.macIteration = 1000;
    conf.macAlg = CF_MAC_SHA256;

    CfBlob blob = { 0, nullptr };

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_check_private_key(_, _))
        .WillOnce(Return(0))
        .WillRepeatedly(Invoke(__real_X509_check_private_key));
    ret = HcfCreatePkcs12(p12Collection, &conf, &blob);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_digest(_, _, _, _))
        .WillOnce(Return(0))
        .WillRepeatedly(Invoke(__real_X509_digest));
    ret = HcfCreatePkcs12(p12Collection, &conf, &blob);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    CfObjDestroy(mainCert);
    CfFree(p12Collection);
    p12Collection = nullptr;
}

HWTEST_F(CryptoX509CertChainTestEx, HcfCreatePkcs12Test013, TestSize.Level0)
{
    HcfX509P12Collection *p12Collection =
        static_cast<HcfX509P12Collection *>(CfMalloc(sizeof(HcfX509P12Collection), 0));
    ASSERT_NE(p12Collection, nullptr);

    CfBlob prikey;
    prikey.size = strlen(g_pkcs12testPrikey);
    prikey.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_pkcs12testPrikey));
    p12Collection->prikey = &prikey;
    p12Collection->isPem = true;

    HcfX509Certificate *mainCert = nullptr;
    CfResult ret = HcfX509CertificateCreate(&certPem, &mainCert);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(mainCert, nullptr);
    p12Collection->cert = mainCert;

    HcfPkcs12CreatingConfig conf = { 0 };
    CfBlob pwd;
    pwd.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testPkcs12Pwd));
    pwd.size = strlen(g_testPkcs12Pwd) + 1;
    conf.pwd = &pwd;
    conf.keyEncParams.saltLen = 16;
    conf.keyEncParams.iteration = 1000;
    conf.keyEncParams.alg = AES_128_CBC;
    conf.encryptCert = false;
    conf.certEncParams.saltLen = 16;
    conf.certEncParams.iteration = 1000;
    conf.certEncParams.alg = AES_128_CBC;
    conf.macSaltLen = 16;
    conf.macIteration = 1000;
    conf.macAlg = CF_MAC_SHA256;

    CfBlob blob = { 0, nullptr };

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), PKCS12_add_cert(_, _))
        .WillOnce(Return(nullptr))
        .WillRepeatedly(Invoke(__real_PKCS12_add_cert));
    ret = HcfCreatePkcs12(p12Collection, &conf, &blob);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), PKCS12_add_localkeyid(_, _, _))
        .WillOnce(Return(0))
        .WillRepeatedly(Invoke(__real_PKCS12_add_localkeyid));
    ret = HcfCreatePkcs12(p12Collection, &conf, &blob);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    CfObjDestroy(mainCert);
    CfFree(p12Collection);
    p12Collection = nullptr;
}

HWTEST_F(CryptoX509CertChainTestEx, HcfCreatePkcs12Test014, TestSize.Level0)
{
    HcfX509P12Collection *p12Collection =
        static_cast<HcfX509P12Collection *>(CfMalloc(sizeof(HcfX509P12Collection), 0));
    ASSERT_NE(p12Collection, nullptr);

    CfBlob prikey;
    prikey.size = strlen(g_pkcs12testPrikey);
    prikey.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_pkcs12testPrikey));
    p12Collection->prikey = &prikey;
    p12Collection->isPem = true;

    HcfX509Certificate *caCert = nullptr;
    CfResult ret = HcfX509CertificateCreate(&caCertPem, &caCert);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(caCert, nullptr);

    p12Collection->otherCertsCount = 1;
    p12Collection->otherCerts = static_cast<HcfX509Certificate **>(CfMalloc(sizeof(HcfX509Certificate *), 0));
    p12Collection->otherCerts[0] = caCert;

    HcfPkcs12CreatingConfig conf = { 0 };
    CfBlob pwd;
    pwd.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testPkcs12Pwd));
    pwd.size = strlen(g_testPkcs12Pwd) + 1;
    conf.pwd = &pwd;
    conf.keyEncParams.saltLen = 16;
    conf.keyEncParams.iteration = 1000;
    conf.keyEncParams.alg = AES_128_CBC;
    conf.encryptCert = true;
    conf.certEncParams.saltLen = 16;
    conf.certEncParams.iteration = 1000;
    conf.certEncParams.alg = AES_128_CBC;
    conf.macSaltLen = 16;
    conf.macIteration = 1000;
    conf.macAlg = CF_MAC_SHA256;

    CfBlob blob = { 0, nullptr };

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), PKCS12_add_cert(_, _))
        .WillOnce(Return(nullptr))
        .WillRepeatedly(Invoke(__real_PKCS12_add_cert));
    ret = HcfCreatePkcs12(p12Collection, &conf, &blob);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    CfObjDestroy(caCert);
    CfFree(p12Collection->otherCerts);
    p12Collection->otherCerts = nullptr;
    p12Collection->otherCertsCount = 0;
    CfFree(p12Collection);
    p12Collection = nullptr;
}

HWTEST_F(CryptoX509CertChainTestEx, HcfCreatePkcs12Test015, TestSize.Level0)
{
    HcfX509P12Collection *p12Collection =
        static_cast<HcfX509P12Collection *>(CfMalloc(sizeof(HcfX509P12Collection), 0));
    ASSERT_NE(p12Collection, nullptr);

    CfBlob prikey;
    prikey.size = strlen(g_pkcs12testPrikey);
    prikey.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_pkcs12testPrikey));
    p12Collection->prikey = &prikey;
    p12Collection->isPem = true;

    HcfX509Certificate *caCert = nullptr;
    CfResult ret = HcfX509CertificateCreate(&caCertPem, &caCert);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(caCert, nullptr);

    p12Collection->otherCertsCount = 1;
    p12Collection->otherCerts = static_cast<HcfX509Certificate **>(CfMalloc(sizeof(HcfX509Certificate *), 0));
    p12Collection->otherCerts[0] = caCert;

    HcfPkcs12CreatingConfig conf = { 0 };
    CfBlob pwd;
    pwd.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testPkcs12Pwd));
    pwd.size = strlen(g_testPkcs12Pwd) + 1;
    conf.pwd = &pwd;
    conf.keyEncParams.saltLen = 16;
    conf.keyEncParams.iteration = 1000;
    conf.keyEncParams.alg = AES_128_CBC;
    conf.encryptCert = true;
    conf.certEncParams.saltLen = 16;
    conf.certEncParams.iteration = 1000;
    conf.certEncParams.alg = AES_128_CBC;
    conf.macSaltLen = 16;
    conf.macIteration = 1000;
    conf.macAlg = CF_MAC_SHA256;

    CfBlob blob = { 0, nullptr };

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), PKCS12_pack_p7encdata_ex(_, _, _, _, _, _, _, _, _))
        .WillOnce(Return(nullptr))
        .WillRepeatedly(Invoke(__real_PKCS12_pack_p7encdata_ex));
    ret = HcfCreatePkcs12(p12Collection, &conf, &blob);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    CfObjDestroy(caCert);
    CfFree(p12Collection->otherCerts);
    p12Collection->otherCerts = nullptr;
    p12Collection->otherCertsCount = 0;
    CfFree(p12Collection);
    p12Collection = nullptr;
}

HWTEST_F(CryptoX509CertChainTestEx, HcfCreatePkcs12Test016, TestSize.Level0)
{
    HcfX509P12Collection *p12Collection =
        static_cast<HcfX509P12Collection *>(CfMalloc(sizeof(HcfX509P12Collection), 0));
    ASSERT_NE(p12Collection, nullptr);

    CfBlob prikey;
    prikey.size = strlen(g_pkcs12testPrikey);
    prikey.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_pkcs12testPrikey));
    p12Collection->prikey = &prikey;
    p12Collection->isPem = true;

    HcfX509Certificate *caCert = nullptr;
    CfResult ret = HcfX509CertificateCreate(&caCertPem, &caCert);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(caCert, nullptr);

    p12Collection->otherCertsCount = 1;
    p12Collection->otherCerts = static_cast<HcfX509Certificate **>(CfMalloc(sizeof(HcfX509Certificate *), 0));
    p12Collection->otherCerts[0] = caCert;

    HcfPkcs12CreatingConfig conf = { 0 };
    CfBlob pwd;
    pwd.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testPkcs12Pwd));
    pwd.size = strlen(g_testPkcs12Pwd) + 1;
    conf.pwd = &pwd;
    conf.keyEncParams.saltLen = 16;
    conf.keyEncParams.iteration = 1000;
    conf.keyEncParams.alg = AES_128_CBC;
    conf.encryptCert = false;
    conf.certEncParams.saltLen = 16;
    conf.certEncParams.iteration = 1000;
    conf.certEncParams.alg = AES_128_CBC;
    conf.macSaltLen = 16;
    conf.macIteration = 1000;
    conf.macAlg = CF_MAC_SHA256;

    CfBlob blob = { 0, nullptr };

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), PKCS12_pack_p7data(_))
        .WillOnce(Return(nullptr))
        .WillRepeatedly(Invoke(__real_PKCS12_pack_p7data));
    ret = HcfCreatePkcs12(p12Collection, &conf, &blob);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    CfObjDestroy(caCert);
    CfFree(p12Collection->otherCerts);
    p12Collection->otherCerts = nullptr;
    p12Collection->otherCertsCount = 0;
    CfFree(p12Collection);
    p12Collection = nullptr;
}

HWTEST_F(CryptoX509CertChainTestEx, HcfCreatePkcs12Test017, TestSize.Level0)
{
    HcfX509P12Collection *p12Collection =
        static_cast<HcfX509P12Collection *>(CfMalloc(sizeof(HcfX509P12Collection), 0));
    ASSERT_NE(p12Collection, nullptr);

    CfBlob prikey;
    prikey.size = strlen(g_pkcs12testPrikey);
    prikey.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_pkcs12testPrikey));
    p12Collection->prikey = &prikey;
    p12Collection->isPem = true;

    HcfX509Certificate *mainCert = nullptr;
    CfResult ret = HcfX509CertificateCreate(&certPem, &mainCert);
    EXPECT_EQ(ret, CF_SUCCESS);
    p12Collection->cert = mainCert;

    HcfX509Certificate *caCert = nullptr;
    ret = HcfX509CertificateCreate(&caCertPem, &caCert);
    EXPECT_EQ(ret, CF_SUCCESS);

    p12Collection->otherCertsCount = 1;
    p12Collection->otherCerts = static_cast<HcfX509Certificate **>(CfMalloc(sizeof(HcfX509Certificate *), 0));
    p12Collection->otherCerts[0] = caCert;

    HcfPkcs12CreatingConfig conf = { 0 };
    CfBlob pwd;
    pwd.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testPkcs12Pwd));
    pwd.size = strlen(g_testPkcs12Pwd) + 1;
    conf.pwd = &pwd;
    conf.keyEncParams.saltLen = 16;
    conf.keyEncParams.iteration = 1000;
    conf.keyEncParams.alg = AES_128_CBC;
    conf.encryptCert = true;
    conf.certEncParams.saltLen = 16;
    conf.certEncParams.iteration = 1000;
    conf.certEncParams.alg = AES_128_CBC;
    conf.macSaltLen = 16;
    conf.macIteration = 1000;
    conf.macAlg = CF_MAC_SHA256;

    CfBlob blob = { 0, nullptr };

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), PKCS12_add_safes_ex(_, _, _, _))
        .WillOnce(Return(nullptr))
        .WillRepeatedly(Invoke(__real_PKCS12_add_safes_ex));
    ret = HcfCreatePkcs12(p12Collection, &conf, &blob);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    CfObjDestroy(mainCert);
    CfObjDestroy(caCert);
    CfFree(p12Collection->otherCerts);
    p12Collection->otherCerts = nullptr;
    p12Collection->otherCertsCount = 0;
    CfFree(p12Collection);
    p12Collection = nullptr;
}

HWTEST_F(CryptoX509CertChainTestEx, HcfCreatePkcs12Test018, TestSize.Level0)
{
    HcfX509P12Collection *p12Collection =
        static_cast<HcfX509P12Collection *>(CfMalloc(sizeof(HcfX509P12Collection), 0));
    ASSERT_NE(p12Collection, nullptr);

    CfBlob prikey;
    prikey.size = strlen(g_pkcs12testPrikey);
    prikey.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_pkcs12testPrikey));
    p12Collection->prikey = &prikey;
    p12Collection->isPem = true;

    HcfX509Certificate *mainCert = nullptr;
    CfResult ret = HcfX509CertificateCreate(&certPem, &mainCert);
    EXPECT_EQ(ret, CF_SUCCESS);
    p12Collection->cert = mainCert;

    HcfX509Certificate *caCert = nullptr;
    ret = HcfX509CertificateCreate(&caCertPem, &caCert);
    EXPECT_EQ(ret, CF_SUCCESS);

    p12Collection->otherCertsCount = 1;
    p12Collection->otherCerts = static_cast<HcfX509Certificate **>(CfMalloc(sizeof(HcfX509Certificate *), 0));
    p12Collection->otherCerts[0] = caCert;

    HcfPkcs12CreatingConfig conf = { 0 };
    CfBlob pwd;
    pwd.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testPkcs12Pwd));
    pwd.size = strlen(g_testPkcs12Pwd) + 1;
    conf.pwd = &pwd;
    conf.keyEncParams.saltLen = 16;
    conf.keyEncParams.iteration = 1000;
    conf.keyEncParams.alg = AES_128_CBC;
    conf.encryptCert = true;
    conf.certEncParams.saltLen = 16;
    conf.certEncParams.iteration = 1000;
    conf.certEncParams.alg = AES_128_CBC;
    conf.macSaltLen = 16;
    conf.macIteration = 1000;
    conf.macAlg = CF_MAC_SHA256;

    CfBlob blob = { 0, nullptr };

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), PKCS12_set_mac(_, _, _, _, _, _, _))
        .WillOnce(Return(0))
        .WillRepeatedly(Invoke(__real_PKCS12_set_mac));
    ret = HcfCreatePkcs12(p12Collection, &conf, &blob);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    CfObjDestroy(mainCert);
    CfObjDestroy(caCert);
    CfFree(p12Collection->otherCerts);
    p12Collection->otherCerts = nullptr;
    p12Collection->otherCertsCount = 0;
    CfFree(p12Collection);
    p12Collection = nullptr;
}

HWTEST_F(CryptoX509CertChainTestEx, HcfCreatePkcs12Test019, TestSize.Level0)
{
    HcfX509P12Collection *p12Collection =
        static_cast<HcfX509P12Collection *>(CfMalloc(sizeof(HcfX509P12Collection), 0));
    ASSERT_NE(p12Collection, nullptr);

    CfBlob prikey;
    prikey.size = strlen(g_pkcs12testPrikey);
    prikey.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_pkcs12testPrikey));
    p12Collection->prikey = &prikey;
    p12Collection->isPem = true;

    HcfX509Certificate *mainCert = nullptr;
    CfResult ret = HcfX509CertificateCreate(&certPem, &mainCert);
    EXPECT_EQ(ret, CF_SUCCESS);
    p12Collection->cert = mainCert;

    HcfX509Certificate *caCert = nullptr;
    ret = HcfX509CertificateCreate(&caCertPem, &caCert);
    EXPECT_EQ(ret, CF_SUCCESS);

    p12Collection->otherCertsCount = 1;
    p12Collection->otherCerts = static_cast<HcfX509Certificate **>(CfMalloc(sizeof(HcfX509Certificate *), 0));
    p12Collection->otherCerts[0] = caCert;

    HcfPkcs12CreatingConfig conf = { 0 };
    CfBlob pwd;
    pwd.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testPkcs12Pwd));
    pwd.size = strlen(g_testPkcs12Pwd) + 1;
    conf.pwd = &pwd;
    conf.keyEncParams.saltLen = 16;
    conf.keyEncParams.iteration = 1000;
    conf.keyEncParams.alg = AES_128_CBC;
    conf.encryptCert = true;
    conf.certEncParams.saltLen = 16;
    conf.certEncParams.iteration = 1000;
    conf.certEncParams.alg = AES_128_CBC;
    conf.macSaltLen = 16;
    conf.macIteration = 1000;
    conf.macAlg = CF_MAC_SHA256;

    CfBlob blob = { 0, nullptr };

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), PKCS12_SAFEBAG_create_pkcs8_encrypt_ex(_, _, _, _, _, _, _, _, _))
        .WillOnce(Return(nullptr))
        .WillRepeatedly(Invoke(__real_PKCS12_SAFEBAG_create_pkcs8_encrypt_ex));
    ret = HcfCreatePkcs12(p12Collection, &conf, &blob);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    CfObjDestroy(mainCert);
    CfObjDestroy(caCert);
    CfFree(p12Collection->otherCerts);
    p12Collection->otherCerts = nullptr;
    p12Collection->otherCertsCount = 0;
    CfFree(p12Collection);
    p12Collection = nullptr;
}

HWTEST_F(CryptoX509CertChainTestEx, HcfCreatePkcs12Test020, TestSize.Level0)
{
    HcfX509P12Collection *p12Collection =
        static_cast<HcfX509P12Collection *>(CfMalloc(sizeof(HcfX509P12Collection), 0));
    ASSERT_NE(p12Collection, nullptr);

    CfBlob prikey;
    prikey.size = strlen(g_pkcs12testPrikey);
    prikey.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_pkcs12testPrikey));
    p12Collection->prikey = &prikey;
    p12Collection->isPem = true;

    HcfX509Certificate *mainCert = nullptr;
    CfResult ret = HcfX509CertificateCreate(&certPem, &mainCert);
    EXPECT_EQ(ret, CF_SUCCESS);
    p12Collection->cert = mainCert;

    HcfX509Certificate *caCert = nullptr;
    ret = HcfX509CertificateCreate(&caCertPem, &caCert);
    EXPECT_EQ(ret, CF_SUCCESS);

    p12Collection->otherCertsCount = 1;
    p12Collection->otherCerts = static_cast<HcfX509Certificate **>(CfMalloc(sizeof(HcfX509Certificate *), 0));
    p12Collection->otherCerts[0] = caCert;

    HcfPkcs12CreatingConfig conf = { 0 };
    CfBlob pwd;
    pwd.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testPkcs12Pwd));
    pwd.size = strlen(g_testPkcs12Pwd) + 1;
    conf.pwd = &pwd;
    conf.keyEncParams.saltLen = 16;
    conf.keyEncParams.iteration = 1000;
    conf.keyEncParams.alg = AES_128_CBC;
    conf.encryptCert = true;
    conf.certEncParams.saltLen = 16;
    conf.certEncParams.iteration = 1000;
    conf.certEncParams.alg = AES_128_CBC;
    conf.macSaltLen = 16;
    conf.macIteration = 1000;
    conf.macAlg = CF_MAC_SHA256;

    CfBlob blob = { 0, nullptr };

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), i2d_PKCS12(_, _))
        .WillOnce(Return(0))
        .WillRepeatedly(Invoke(__real_i2d_PKCS12));
    ret = HcfCreatePkcs12(p12Collection, &conf, &blob);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    CfObjDestroy(mainCert);
    CfObjDestroy(caCert);
    CfFree(p12Collection->otherCerts);
    p12Collection->otherCerts = nullptr;
    p12Collection->otherCertsCount = 0;
    CfFree(p12Collection);
    p12Collection = nullptr;
}

HWTEST_F(CryptoX509CertChainTestEx, HcfCreatePkcs12Test021, TestSize.Level0)
{
    HcfX509P12Collection *p12Collection =
        static_cast<HcfX509P12Collection *>(CfMalloc(sizeof(HcfX509P12Collection), 0));
    ASSERT_NE(p12Collection, nullptr);

    CfBlob prikey;
    prikey.size = strlen(g_pkcs12testPrikey);
    prikey.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_pkcs12testPrikey));
    p12Collection->prikey = &prikey;
    p12Collection->isPem = true;

    HcfX509Certificate *mainCert = nullptr;
    CfResult ret = HcfX509CertificateCreate(&certPem, &mainCert);
    EXPECT_EQ(ret, CF_SUCCESS);
    p12Collection->cert = mainCert;

    HcfX509Certificate *caCert = nullptr;
    ret = HcfX509CertificateCreate(&caCertPem, &caCert);
    EXPECT_EQ(ret, CF_SUCCESS);

    p12Collection->otherCertsCount = 1;
    p12Collection->otherCerts = static_cast<HcfX509Certificate **>(CfMalloc(sizeof(HcfX509Certificate *), 0));
    p12Collection->otherCerts[0] = caCert;

    HcfPkcs12CreatingConfig conf = { 0 };
    CfBlob pwd;
    pwd.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testPkcs12Pwd));
    pwd.size = strlen(g_testPkcs12Pwd) + 1;
    conf.pwd = &pwd;
    conf.keyEncParams.saltLen = 16;
    conf.keyEncParams.iteration = 1000;
    conf.keyEncParams.alg = AES_128_CBC;
    conf.encryptCert = true;
    conf.certEncParams.saltLen = 16;
    conf.certEncParams.iteration = 1000;
    conf.certEncParams.alg = AES_128_CBC;
    conf.macSaltLen = 16;
    conf.macIteration = 1000;
    conf.macAlg = CF_MAC_SHA256;

    CfBlob blob = { 0, nullptr };

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), PKCS12_add_safe(_, _, _, _, _))
        .WillOnce(Return(0))
        .WillRepeatedly(Invoke(__real_PKCS12_add_safe));
    ret = HcfCreatePkcs12(p12Collection, &conf, &blob);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    CfObjDestroy(mainCert);
    CfObjDestroy(caCert);
    CfFree(p12Collection->otherCerts);
    p12Collection->otherCerts = nullptr;
    p12Collection->otherCertsCount = 0;
    CfFree(p12Collection);
    p12Collection = nullptr;
}

HWTEST_F(CryptoX509CertChainTestEx, HcfCreatePkcs12Test022, TestSize.Level0)
{
    HcfX509P12Collection *p12Collection =
        static_cast<HcfX509P12Collection *>(CfMalloc(sizeof(HcfX509P12Collection), 0));
    ASSERT_NE(p12Collection, nullptr);

    CfBlob prikey;
    prikey.size = strlen(g_pkcs12testPrikey);
    prikey.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_pkcs12testPrikey));
    p12Collection->prikey = &prikey;
    p12Collection->isPem = true;

    HcfX509Certificate *caCert = nullptr;
    CfResult ret = HcfX509CertificateCreate(&caCertPem, &caCert);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(caCert, nullptr);

    p12Collection->otherCertsCount = 1;
    p12Collection->otherCerts = static_cast<HcfX509Certificate **>(CfMalloc(sizeof(HcfX509Certificate *), 0));
    p12Collection->otherCerts[0] = caCert;

    HcfPkcs12CreatingConfig conf = { 0 };
    CfBlob pwd;
    pwd.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testPkcs12Pwd));
    pwd.size = strlen(g_testPkcs12Pwd) + 1;
    conf.pwd = &pwd;
    conf.keyEncParams.saltLen = 16;
    conf.keyEncParams.iteration = 1000;
    conf.keyEncParams.alg = AES_128_CBC;
    conf.encryptCert = true;
    conf.certEncParams.saltLen = 16;
    conf.certEncParams.iteration = 1000;
    conf.certEncParams.alg = AES_128_CBC;
    conf.macSaltLen = 16;
    conf.macIteration = 1000;
    conf.macAlg = CF_MAC_SHA256;

    CfBlob blob = { 0, nullptr };

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), BIO_new_mem_buf(_, _))
        .WillOnce(Return(nullptr))
        .WillRepeatedly(Invoke(__real_BIO_new_mem_buf));
    ret = HcfCreatePkcs12(p12Collection, &conf, &blob);
    EXPECT_EQ(ret, CF_ERR_MALLOC);
    X509OpensslMock::SetMockFlag(false);

    CfObjDestroy(caCert);
    CfFree(p12Collection->otherCerts);
    p12Collection->otherCerts = nullptr;
    p12Collection->otherCertsCount = 0;
    CfFree(p12Collection);
    p12Collection = nullptr;
}
} // namespace
