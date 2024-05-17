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

#ifndef CRYPTO_X509_TEST_COMMON_H
#define CRYPTO_X509_TEST_COMMON_H

#include <stdbool.h>

#include "asy_key_generator.h"
#include "cf_memory.h"
#include "cipher.h"
#include "crypto_x509_cert_chain_data_der.h"
#include "crypto_x509_cert_chain_data_p7b.h"
#include "crypto_x509_cert_chain_data_pem.h"
#include "crypto_x509_cert_chain_data_pem_added.h"
#include "crypto_x509_cert_chain_data_pem_ex.h"
#include "key_pair.h"
#include "memory_mock.h"
#include "securec.h"
#include "x509_cert_chain.h"
#include "x509_crl.h"

#ifdef __cplusplus
extern "C" {
#endif

static const char g_deviceTestCert[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIIBLzCB1QIUO/QDVJwZLIpeJyPjyTvE43xvE5cwCgYIKoZIzj0EAwIwGjEYMBYG\r\n"
    "A1UEAwwPRXhhbXBsZSBSb290IENBMB4XDTIzMDkwNDExMjAxOVoXDTI2MDUzMDEx\r\n"
    "MjAxOVowGjEYMBYGA1UEAwwPRXhhbXBsZSBSb290IENBMFkwEwYHKoZIzj0CAQYI\r\n"
    "KoZIzj0DAQcDQgAEHjG74yMIueO7z3T+dyuEIrhxTg2fqgeNB3SGfsIXlsiUfLTa\r\n"
    "tUsU0i/sePnrKglj2H8Abbx9PK0tsW/VgqwDIDAKBggqhkjOPQQDAgNJADBGAiEA\r\n"
    "0ce/fvA4tckNZeB865aOApKXKlBjiRlaiuq5mEEqvNACIQDPD9WyC21MXqPBuRUf\r\n"
    "BetUokslUfjT6+s/X4ByaxycAA==\r\n"
    "-----END CERTIFICATE-----";
extern const int g_deviceTestCertSize;
static const char g_rootCert[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIIGQDCCBCigAwIBAgIUKNQFxqguJbKjFXanBmC2ZwUv9dkwDQYJKoZIhvcNAQEL\r\n"
    "BQAwejELMAkGA1UEBhMCQ04xETAPBgNVBAgMCFNIQU5HSEFJMREwDwYDVQQHDAhT\r\n"
    "SEFOR0hBSTELMAkGA1UECgwCQUExCzAJBgNVBAsMAkJCMQswCQYDVQQDDAJDQzEe\r\n"
    "MBwGCSqGSIb3DQEJARYPZmlyc3RAaGVsbG8uY29tMCAXDTIyMDgyMzExMjk0MVoY\r\n"
    "DzIwNjIwODIzMTEyOTQxWjB6MQswCQYDVQQGEwJDTjERMA8GA1UECAwIU0hBTkdI\r\n"
    "QUkxETAPBgNVBAcMCFNIQU5HSEFJMQswCQYDVQQKDAJBQTELMAkGA1UECwwCQkIx\r\n"
    "CzAJBgNVBAMMAkNDMR4wHAYJKoZIhvcNAQkBFg9maXJzdEBoZWxsby5jb20wggIi\r\n"
    "MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCr4nXrmskgHytDYcp8/BRORk71\r\n"
    "f2idSs6cxxSOycILA3fbhbCB3qA8Bj4k1bT592j99MsKm+djMFvUOW/mS6iEWcoS\r\n"
    "sK1HvYX2d7y0GMDnltT9I/KlcYDHiwcq0UgHX4OSbB70EUt9vUmq/opYeUJFIbfq\r\n"
    "QJvGu57PJw+lxdsq3mZvx8n04fIMxqJdQSXu2foh0fSIePthNIV5JNtO9tTmmKn9\r\n"
    "b+L9Eb1IfhKnvxNVuq046+eUwRA3Qva4HQOkCplamfU+b2dQGXnpha/NzXfCVuZK\r\n"
    "R13xhUXjuXADGAIoRl9BgxgONTVpy209xQ7W1UvVEbSVDf8r9OlPDf3olRoavTAv\r\n"
    "+EaYyqrFoEtTzIRZDiLIhqjoqtpbrl5oVggfH/qn8qDyZ+a6puwa81+9Mad8CLwh\r\n"
    "Q9sa0uT+AET86gCGgpOBPF31+xYgnznQjd2wRs5a2rrYjy5wqAYyGPNUy9lm2EaU\r\n"
    "03jMv+JzgeSdyqly8g3oCxBhRENgtGWlMUzzqZoM+Z6/NUn+pebRr53z4lzQWFFV\r\n"
    "M1M81OHIKnleuud5CTnuRNfX7jVX9O+iu/bHjU2YKKrB3L1+ZY0cf6RXUDsBFSxg\r\n"
    "dRZXBVvjJ8Ag+PDYOGG4Cbh9NByhvNvoKa7eBDpWXkOcP6VqnlIL33AUNKk9NEZc\r\n"
    "KpyN1Dbk3eN/c9pIBQIDAQABo4G7MIG4MB0GA1UdDgQWBBRn2V1KId/KpzEztYbH\r\n"
    "PHbCFqIioTAfBgNVHSMEGDAWgBRn2V1KId/KpzEztYbHPHbCFqIioTASBgNVHRMB\r\n"
    "Af8ECDAGAQH/AgEDMAsGA1UdDwQEAwIBBjAdBgNVHSUEFjAUBggrBgEFBQcDAQYI\r\n"
    "KwYBBQUHAwIwGgYDVR0RBBMwEYEPZmlyc3RAaGVsbG8uY29tMBoGA1UdEgQTMBGB\r\n"
    "D2ZpcnN0QGhlbGxvLmNvbTANBgkqhkiG9w0BAQsFAAOCAgEAqbo9c3pEMfk4pmTL\r\n"
    "Oays4RGZy9kZtZMOgdNvZ1gLbRow85x3mSOQ7ew8trt4PbjEp48EQzTFy4AxsBj/\r\n"
    "Kw7p6Y9RAu/fBQMOMwIKzBUW9gayehpOyRTgnt27jDUBBXcq21HDy+WK9FTreqTG\r\n"
    "R2CH/Yt75pfsHLWulq7Ou3s5sWvLyuYxohVDsIJfJHwgUSGPB33bFGqSxzN4qOMJ\r\n"
    "4+M1OO0+hHVWzqESmYBaroX7XYoFeVOJsEDdjU9lccIZpfupbZ4ljjdBk3v45WSt\r\n"
    "gbTS2NYauczjl3wT/p5EU7iGf1a8rSOjUqZS6cmDP7Tq0PL4+1iMCZlF1ZXLvPb4\r\n"
    "dCAebIPMF7Pn1BLjANsQ94iKWHmPWdl8m6QmdCtSGgt7zNx3W0N6kF/7tRdshUQD\r\n"
    "mPXFZed3U3vVVCOGPPY/KYnNvU2umJ4EsDSThlRPPafZ8GDuj1cF4OGdxfNx6bSQ\r\n"
    "E6Zuj4oYR1k5+vAWbVS6F25KV0C6mXkrmL/pl2JQt+fyWIjGxP3pkBcxBYyP+OgQ\r\n"
    "hX9yv+cUIkDPNa9yytVn2Z+9CFJbz3l/AxIxTqR5a3m9Qlls4otQKco0E9ArA3ce\r\n"
    "v9YYMHEDo61jQYTd2rz7BvIdvQ+ds4V+GjmgDFa21tMvpNxC6LMy4gS4PmOSAbMu\r\n"
    "jI6AaoTlr5I7zPhFbR8/XEs7DzI=\r\n"
    "-----END CERTIFICATE-----\r\n";
extern const int g_rootCertSize;
static const char g_secondCert[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "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\r\n"
    "-----END CERTIFICATE-----\r\n";
extern const int g_secondCertSize;
static const char g_testInvalidCert[] =
    "-----xxxx CERTIFICATE-----\r\n"
    "MIIDpzCCAo+gAwIBAgICAQAwDQYJKoZIhvcNAQELBQAwbDELMAkGA1UEBhMCQ04x\r\n"
    "CzAJBgNVBAgMAkJKMQswCQYDVQQHDAJCSjELMAkGA1UECgwCSEQxDDAKBgNVBAsM\r\n"
    "A2RldjELMAkGA1UEAwwCY2ExGzAZBgkqhkiG9w0BCQEWDGNhQHdvcmxkLmNvbTAe\r\n"
    "Fw0yMjA4MTkwNTE2MTVaFw0yMzA4MTkwNTE2MTVaMGwxCzAJBgNVBAYTAkNOMQsw\r\n"
    "CQYDVQQIDAJCSjELMAkGA1UEBwwCQkoxCzAJBgNVBAoMAkhEMQwwCgYDVQQLDANk\r\n"
    "ZXYxCzAJBgNVBAMMAmNhMRswGQYJKoZIhvcNAQkBFgxjYUB3b3JsZC5jb20wggEi\r\n"
    "MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCuvLoVT5em7ApBma8xtgpcFcaU\r\n"
    "CbXBJSUl2NpFW2sriucbEOvKRdw9KvLa/tSP6CupPZVKIzHAP2oeW88aFBr23miG\r\n"
    "iR49M52c73Iw3H3EG2ckK8M1mxEzXSqynivqiNZDKG+bA5cFzcfmk6Th1bJan9w9\r\n"
    "Ci8HPSBvgg7Rc6pqNM4HjTHl3Bb6cf4Xh3/GgpjypTd9jAAEyq+l/+1pnTYVlIJA\r\n"
    "WGh0Z26RosXfzwfFKH77ysTjoj9ambvGmFsMXvNXEyYmBCeYND6xGj4pa2lylsra\r\n"
    "kfYmGxcFQ45Lj5oWdNQQVdvrQiYWu3SJOC/WqB5UIAq92PPrq1apznxfjqABAgMB\r\n"
    "AAGjUzBRMB0GA1UdDgQWBBRI5iWwjBMAOCcgcUjUCYJdsvwEMjAfBgNVHSMEGDAW\r\n"
    "gBRI5iWwjBMAOCcgcUjUCYJdsvwEMjAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3\r\n"
    "DQEBCwUAA4IBAQABop7EJgS2czHKWVzdEwjbi9m5ZUPy6aOV9paV1e/5IyFNHwun\r\n"
    "B64iwcg03+FmIWNuynb1mglHHrUoXygXu9GIR8cWfOI3W+Pnn8fDi8MxQMn/e/Jj\r\n"
    "BuGcnRwKynRhyLdkyWYn1YwqenMuFJu9yzkhfAPltGFEuPYCWDatdhm6zhFdu1PE\r\n"
    "EMErHpQOT45z5cgC4XqgKlE+n8L4/5RfZnbuUJ3bV+FuI+VApLGXJQlJQAOTqBDg\r\n"
    "k7DMSgPUUxYYa6AGMFy6vqQ6hcgCMK08ko8LdjVd1MobKzM9Oh480GFZA/ubR3QW\r\n"
    "lv3OuOhmnIxNGcPUiqpSiWKqR5tf1KUImIR9\r\n"
    "-----END CERTIFICATE-----\r\n";
extern const int g_testInvalidCertSize;
static const char g_testSelfSignedCaCert[] =
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

extern const int g_testSelfSignedCaCertSize;
static const uint8_t g_testSubjectAndIssuerNameDerData[] = {
    0x30, 0x76, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x43, 0x4E, 0x31, 0x0B, 0x30,
    0x09, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0C, 0x02, 0x42, 0x4A, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04,
    0x07, 0x0C, 0x02, 0x42, 0x4A, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x02, 0x48, 0x44,
    0x31, 0x0C, 0x30, 0x0A, 0x06, 0x03, 0x55, 0x04, 0x0B, 0x0C, 0x03, 0x64, 0x65, 0x76, 0x31, 0x0B, 0x30, 0x09,
    0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x02, 0x63, 0x61, 0x31, 0x25, 0x30, 0x23, 0x06, 0x09, 0x2A, 0x86, 0x48,
    0x86, 0xF7, 0x0D, 0x01, 0x09, 0x01, 0x16, 0x16, 0x63, 0x61, 0x40, 0x63, 0x72, 0x79, 0x70, 0x74, 0x6F, 0x66,
    0x72, 0x61, 0x6D, 0x65, 0x77, 0x6F, 0x72, 0x6B, 0x2E, 0x63, 0x6F, 0x6D
};
extern const int g_testSubjectAndIssuerNameDerDataSize;
static const uint8_t g_testCrlSubAndIssNameDerData[] = {
    0x30, 0x2C, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x43, 0x4E, 0x31, 0x0D, 0x30,
    0x0B, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x04, 0x74, 0x65, 0x73, 0x74, 0x31, 0x0E, 0x30, 0x0C, 0x06, 0x03,
    0x55, 0x04, 0x03, 0x0C, 0x05, 0x73, 0x75, 0x62, 0x63, 0x61
};
extern const int g_testCrlSubAndIssNameDerDataSize;
static const uint8_t g_testPublicKeyDerData[] = {
    0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05,
    0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0x9f, 0x29, 0xd0,
    0x85, 0x84, 0xed, 0x6c, 0x30, 0x6e, 0xd0, 0x13, 0x83, 0xe0, 0x1b, 0x61, 0x08, 0xf7, 0xdd, 0x63, 0x41, 0x06,
    0x4b, 0x54, 0xfb, 0xf0, 0x15, 0x7f, 0xe4, 0xe5, 0xd5, 0xa0, 0x1a, 0xe1, 0x33, 0x9e, 0x5b, 0x6f, 0xd9, 0x01,
    0x17, 0x38, 0xb1, 0xdc, 0x0b, 0x55, 0x3c, 0x5d, 0x5c, 0x28, 0xa9, 0x16, 0xc7, 0xae, 0x88, 0x63, 0x77, 0xd2,
    0x1c, 0x17, 0xad, 0x71, 0x54, 0x1e, 0xb7, 0x0c, 0x7f, 0x4c, 0x36, 0xb0, 0x29, 0x33, 0x9c, 0x95, 0x59, 0xfe,
    0xb4, 0x1c, 0x7c, 0x43, 0xb9, 0x29, 0xbd, 0x6f, 0x07, 0x3e, 0x83, 0x10, 0x47, 0x20, 0x21, 0x26, 0x04, 0x86,
    0x1a, 0x8e, 0x05, 0xf6, 0x01, 0x8a, 0xde, 0x6a, 0x7e, 0x9a, 0xb9, 0x47, 0x6f, 0xb6, 0x47, 0xf4, 0xe1, 0xff,
    0x26, 0xd5, 0xfa, 0x40, 0x6b, 0x52, 0x5f, 0x86, 0xb2, 0xc5, 0xdb, 0x0c, 0x07, 0xba, 0xa1, 0x90, 0xb2, 0xe7,
    0xa9, 0x46, 0xa6, 0x10, 0xef, 0x98, 0x73, 0x14, 0x3b, 0xb6, 0xb5, 0xde, 0x3f, 0x92, 0x16, 0x64, 0xe1, 0x31,
    0xb2, 0x36, 0xc9, 0xec, 0xae, 0x6b, 0x52, 0xda, 0x81, 0x2a, 0x1a, 0x04, 0x97, 0xd8, 0xd4, 0x9f, 0xa2, 0xee,
    0x35, 0x8f, 0x9a, 0x61, 0x05, 0x47, 0x47, 0x50, 0xda, 0x9d, 0x04, 0x1a, 0x31, 0xd3, 0x81, 0x01, 0xa1, 0x46,
    0x8e, 0x55, 0xbb, 0x00, 0xc7, 0x8a, 0x93, 0x52, 0xbf, 0x45, 0xcf, 0xf0, 0xe5, 0x00, 0xfc, 0xf6, 0x1b, 0x2f,
    0xf4, 0x81, 0x8f, 0x51, 0x6a, 0xe0, 0x2d, 0xe0, 0xb5, 0xfb, 0xe3, 0x7a, 0xcc, 0x14, 0x6f, 0x35, 0x5a, 0x32,
    0x8a, 0xbf, 0xc0, 0x2b, 0xb2, 0xd6, 0xa7, 0x17, 0x23, 0xcd, 0x19, 0x2d, 0xed, 0xf0, 0x85, 0x1d, 0xb8, 0x73,
    0x47, 0x17, 0x60, 0x53, 0xb4, 0xb8, 0x68, 0xbd, 0x7a, 0x03, 0xe9, 0xdb, 0x87, 0xf0, 0xef, 0x26, 0x06, 0xaa,
    0x01, 0x02, 0x03, 0x01, 0x00, 0x01
};
extern const int g_testPublicKeyDerDataSize;

static const char g_testErrorCert[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIIBLzCB1QIUO/QDVJwZLIpeJyPjyTvE43xvE5cwCgYIKoZIzj0EAwIwGjEYMBYG\r\n"
    "A1UEAwwPRXhhbXBsZSBSb290IENBMB4XDTIzMDkwNDExMjAxOVoXDTI2MDUzMDEx\r\n"
    "MjAxOVowGjEYMBYGA1UEAwwPRXhhbXBsZSBSb290IENBMFkwEwYHKoZIzj0CAQYI\r\n"
    "KoZIzj0DAQcDQgAEHjG74yMIueO7z3T+dyuEIrhxTg2fqgeNB3SGfsIXlsiUfLTa\r\n"
    "tUsU0i/sePnrKglj2H8Abbx9PK0tsW/VgqwDIDAKBggqhkjOPQQDAgNJADBGAiEA\r\n"
    "0ce/fvA4tckNZeB865aOApKXKlBjiRlaiuq5mEEqvNACIQDPD9WyC21MXqPBuRUf\r\n"
    "BetUokslUfjT6+s/X4ByaxycAA==\r\n"
    "-----END CERTIFICATE-----";
extern const int g_testErrorCertSize;
static const char g_testCert[] =
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
extern const int g_testCertSize;
static const char g_testCrl[] =
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
extern const int g_testCrlSize;
static const char g_testCrlWithoutExts[] =
    "-----BEGIN X509 CRL-----\r\n"
    "MIHzMF4CAQMwDQYJKoZIhvcNAQEEBQAwFTETMBEGA1UEAxMKQ1JMIGlzc3VlchcN\r\n"
    "MTcwODA3MTExOTU1WhcNMzIxMjE0MDA1MzIwWjAVMBMCAgPoFw0zMjEyMTQwMDUz\r\n"
    "MjBaMA0GCSqGSIb3DQEBBAUAA4GBACEPHhlaCTWA42ykeaOyR0SGQIHIOUR3gcDH\r\n"
    "J1LaNwiL+gDxI9rMQmlhsUGJmPIPdRs9uYyI+f854lsWYisD2PUEpn3DbEvzwYeQ\r\n"
    "5SqQoPDoM+YfZZa23hoTLsu52toXobP74sf/9K501p/+8hm4ROMLBoRT86GQKY6g\r\n"
    "eavsH0Q3\r\n"
    "-----END X509 CRL-----\r\n";
extern const int g_testCrlWithoutExtsSize;
static const char g_testCrlWithBignumSerial[] =
    "-----BEGIN X509 CRL-----\r\n"
    "MIICEzCB/AIBATANBgkqhkiG9w0BAQsFADB0MQswCQYDVQQGEwJDTjEQMA4GA1UE\r\n"
    "CAwHSmlhbmdTdTEQMA4GA1UEBwwHTmFuSmluZzEKMAgGA1UECgwBdDEKMAgGA1UE\r\n"
    "CwwBdDEMMAoGA1UEAwwDemhiMRswGQYJKoZIhvcNAQkBFgx0ZXN0QDEyMy5jb20X\r\n"
    "DTIzMTEwNzAyNTIwN1oXDTIzMTIwNzAyNTIwN1owLDAqAhkA/wH/Af8B/wH/////\r\n"
    "//////////////8BFw0yMzExMDcwMjUxMDNaoCYwJDAiBgNVHRQEGwIZAP8B/wH/\r\n"
    "Af8B////////////////////ATANBgkqhkiG9w0BAQsFAAOCAQEAcB23lkrRYo48\r\n"
    "YT5RiTxIyjSK1kTT+Zxc3oJ6gXcPoS1j7/Td+fDmFfjLOUeKWYrrx/T7NyfjFxjn\r\n"
    "On37RKmQCHlVJtqAxIstnXCwoSzq68kqK9uczZCaYzWr+aPz/obQRxFWRs0aJy2x\r\n"
    "KvXp6iBObXlAQVSHXkI5ikjkxR5Xpfi+VH0ojTi5NjpPssLJMN4b7qCZ/334qkZ7\r\n"
    "eH6O355R2z0XM4vxQJDAJBoF5X9EFYFJc/uwdZPITnSKaG5IBMt1k5ei5jOLsMDa\r\n"
    "tQSBrPschBRBmg2kBAz8Zq6jgW2j5UaQZ6e0/oKOiiXB/uAPwkpBLAGewinkeZKJ\r\n"
    "VBgXORYAFg==\r\n"
    "-----END X509 CRL-----\r\n";
extern const int g_testCrlWithBignumSerialSize;
static const char g_testCrlWhichEntryWithExt[] =
    "-----BEGIN X509 CRL-----\r\n"
    "MIIBDjB5AgEDMA0GCSqGSIb3DQEBBAUAMBUxEzARBgNVBAMTCkNSTCBpc3N1ZXIX\r\n"
    "DTIzMTExMzExMTYxM1oXDTIzMTExMzExNDkzM1owMDAuAgMAq80XDTIzMTExMzEx\r\n"
    "NDkzM1owGDAWBglghkgBhvhCAQ0BAf8EBhYEdGVzdDANBgkqhkiG9w0BAQQFAAOB\r\n"
    "gQAJlecMe4ImV/IKP2LvT+vO1Os8Z2/tUERk9aleJB9mRpWXfk6hYbUr8RAw3nSu\r\n"
    "4aYnlhdRxS8tkthv2FFxp4Ms/Oto+biyby8zFyzgbjWocPlOx/kL65+itylJGXzN\r\n"
    "28Vgfm9pJFiUQWI34lohYeHyyvT0IlOkhUc8/fdzCZdATA==\r\n"
    "-----END X509 CRL-----\r\n";
extern const int g_testCrlWhichEntryWithExtSize;
static const char g_testIssuerCert[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIIDKDCCAhCgAwIBAgICA+gwDQYJKoZIhvcNAQELBQAwLTELMAkGA1UEBhMCQ04x\r\n"
    "DTALBgNVBAoMBHRlc3QxDzANBgNVBAMMBnJvb3RjYTAeFw0yMzA5MTIwNjQ3NDla\r\n"
    "Fw0zMzA5MDkwNjQ3NDlaMCwxCzAJBgNVBAYTAkNOMQ0wCwYDVQQKDAR0ZXN0MQ4w\r\n"
    "DAYDVQQDDAVzdWJjYTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALpr\r\n"
    "uLwlJjJ9uowa0N6aEmIIdf6YxR5+q6yDYg4it2cLJmkU/0P1Lt2Yl/MiBvW0t3DW\r\n"
    "I6cKFv8rZ+GdwRIfIrTmINJhKjPwvrUqXJctFEkxEgtux4/+C8n06vZJypy5p6Vy\r\n"
    "LFWbLIM1FGkPuBtwjnIQdyUxo+R+oBSVXyvA5w9CX0Ak08jRvsBWc1Oh2Avcm6nF\r\n"
    "0T+ac4Kf0NzVkkMjKoYwUdoPMppjpYGDX0jdRzJhdFUFjGMLR3YQJtlqLeUqVGnO\r\n"
    "mws5K7picMM/Z7tO3tIT6BBPljGzsLheu2tM5yuXBRt4A6D7j9qW+ufNnL7Lklvu\r\n"
    "X6TWn5BKoA/h7cIgc5UCAwEAAaNTMFEwHQYDVR0OBBYEFCIrGN6E2TBO9j3f1/QC\r\n"
    "7UQihCDoMB8GA1UdIwQYMBaAFP+lNpyMpRzNOeVYvU7ecYdvfIhSMA8GA1UdEwEB\r\n"
    "/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBALKHwCrQWu3fHRrCO2usfxNdI2S7\r\n"
    "SkkYDKHiuf4P5VMypSwCewCrEDZwkzLcMlFZ+RMnz1a14viBUvqb3CMbR9Hg52EF\r\n"
    "aFjOeZOGEuJF6hCVi0gJ9AddS8hGaUAzo82BlNCGsM8SGHCP5GsOSyKbvRrWc3jR\r\n"
    "0qDOnHzAbesV6lw2g3MoeXCXIw/HBtv7k9SlJZyAREtmMAkYRm0X4tekqFq/6Mwk\r\n"
    "g9WNnnzPNI1tBp1Nvv3JD3jVHLVXQUp9iOej7KX/OC0NETjn8sXLsjc0ZS1Ub2Nw\r\n"
    "wWFdrSrSmjNbibrOHqQaoP/cpcqNP2EA5lFWSYVjJVkpv2YojGjLhjwqxP0=\r\n"
    "-----END CERTIFICATE-----\r\n";
extern const int g_testIssuerCertSize;
extern const int g_testChainDataP7bSize;
extern const int g_testChainDataDerSize;
extern const int g_testCertChainPemSize;
extern const int g_testCertChainPemMidSize;
extern const int g_testCertChainPemRootSize;
extern const int g_testCertChainPemMidCRLSize;
extern const int g_testCertChainPemNoRootSize;

static const uint8_t g_crlDerData[] = {
    0x30, 0x82, 0x01, 0xE3, 0x30, 0x81, 0xCC, 0x02, 0x01, 0x01, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86,
    0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00, 0x30, 0x2C, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06,
    0x13, 0x02, 0x43, 0x4E, 0x31, 0x0D, 0x30, 0x0B, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x04, 0x74, 0x65, 0x73,
    0x74, 0x31, 0x0E, 0x30, 0x0C, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x05, 0x73, 0x75, 0x62, 0x63, 0x61, 0x17,
    0x0D, 0x32, 0x33, 0x30, 0x39, 0x31, 0x32, 0x30, 0x36, 0x34, 0x37, 0x35, 0x30, 0x5A, 0x17, 0x0D, 0x32, 0x33,
    0x31, 0x30, 0x31, 0x32, 0x30, 0x36, 0x34, 0x37, 0x35, 0x30, 0x5A, 0x30, 0x3B, 0x30, 0x13, 0x02, 0x02, 0x03,
    0xE8, 0x17, 0x0D, 0x32, 0x33, 0x30, 0x39, 0x31, 0x32, 0x30, 0x36, 0x34, 0x37, 0x34, 0x39, 0x5A, 0x30, 0x24,
    0x02, 0x13, 0x17, 0x5D, 0x6A, 0x9F, 0xEC, 0xA9, 0x09, 0xD7, 0x12, 0xB2, 0x48, 0x52, 0xA6, 0x3E, 0x48, 0xF6,
    0x12, 0x93, 0xA9, 0x17, 0x0D, 0x32, 0x33, 0x30, 0x39, 0x31, 0x32, 0x30, 0x36, 0x34, 0x32, 0x35, 0x34, 0x5A,
    0xA0, 0x2F, 0x30, 0x2D, 0x30, 0x1F, 0x06, 0x03, 0x55, 0x1D, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x22,
    0x2B, 0x18, 0xDE, 0x84, 0xD9, 0x30, 0x4E, 0xF6, 0x3D, 0xDF, 0xD7, 0xF4, 0x02, 0xED, 0x44, 0x22, 0x84, 0x20,
    0xE8, 0x30, 0x0A, 0x06, 0x03, 0x55, 0x1D, 0x14, 0x04, 0x03, 0x02, 0x01, 0x02, 0x30, 0x0D, 0x06, 0x09, 0x2A,
    0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x40, 0xA1, 0x82,
    0x5E, 0xCE, 0x5A, 0x5D, 0x8E, 0x7A, 0xD3, 0xA0, 0x3F, 0xD0, 0x7C, 0xA7, 0x2E, 0x6A, 0xBE, 0x7E, 0xB2, 0x7B,
    0xA7, 0x95, 0x23, 0xF5, 0xC0, 0xF6, 0xBF, 0x06, 0xD9, 0x57, 0x8C, 0x5A, 0x3F, 0x61, 0x39, 0x8D, 0x7A, 0x20,
    0x07, 0x3E, 0xD8, 0x0A, 0x39, 0xB1, 0xA7, 0x43, 0xC1, 0xF7, 0xDE, 0x57, 0x0B, 0xDA, 0x22, 0xDD, 0x02, 0x90,
    0x80, 0xB5, 0x4A, 0x63, 0x83, 0x73, 0xDB, 0x55, 0x90, 0x45, 0xE7, 0x26, 0x99, 0x99, 0xB5, 0x70, 0x3C, 0x1E,
    0x0C, 0x33, 0xF0, 0x18, 0x9F, 0x3F, 0x23, 0x47, 0x76, 0x0B, 0x03, 0x13, 0x25, 0xF3, 0xFB, 0xAC, 0x48, 0x2C,
    0xBA, 0x18, 0x08, 0x06, 0xAF, 0x89, 0x52, 0x31, 0x5C, 0x34, 0xD6, 0x96, 0x76, 0x26, 0xB6, 0x1A, 0xEF, 0xDA,
    0x02, 0xE2, 0x23, 0x95, 0xA2, 0x79, 0x03, 0x85, 0xBB, 0xBE, 0xF8, 0x46, 0x55, 0x4C, 0x7D, 0x08, 0x35, 0x1D,
    0x37, 0xC6, 0x05, 0xE6, 0x49, 0xC0, 0xDC, 0x1A, 0x10, 0xD6, 0xE1, 0x5C, 0xD7, 0x3E, 0xE0, 0x35, 0xC9, 0x24,
    0x22, 0x94, 0xD3, 0x71, 0xC4, 0x0B, 0xCE, 0x81, 0x0B, 0x14, 0x31, 0xBC, 0xFF, 0x3F, 0x9B, 0x3A, 0x70, 0x2E,
    0x4A, 0x0D, 0x65, 0x64, 0x2C, 0xAF, 0xF5, 0xF3, 0xB3, 0xF6, 0x55, 0x5A, 0x7C, 0x2F, 0xAA, 0x68, 0x7A, 0x3E,
    0x35, 0x6F, 0x6B, 0x74, 0x28, 0x71, 0x57, 0x5A, 0x02, 0xE5, 0x2E, 0xA3, 0x1D, 0x3B, 0xBC, 0xEF, 0xD0, 0x8E,
    0x31, 0x09, 0xCB, 0xAF, 0x78, 0xC4, 0x04, 0x2B, 0x33, 0x37, 0x30, 0xE3, 0x14, 0x8E, 0xB8, 0x97, 0xA7, 0xF7,
    0x25, 0x59, 0xCB, 0x65, 0xEA, 0x69, 0xE8, 0xD5, 0x35, 0x81, 0xDB, 0xA7, 0x8D, 0x02, 0xF8, 0x82, 0xD5, 0x90,
    0x5D, 0x91, 0x65, 0x15, 0x5E, 0xF9, 0xC5, 0x1F, 0x1A, 0x6A, 0x17, 0x7C, 0xB1, 0xE0, 0x79, 0xA0, 0x34, 0xCF,
    0x42
};
extern const int g_crlDerDataSize;
extern const int g_testChainPubkeyPemRootDataSize;
extern const int g_testChainSubjectPemRootDataSize;
extern const int g_testChainSubjectPemOtherSubjectDataSize;
extern const int g_testChainPubkeyPemRootHasPubKeySize;
extern const int g_testChainPubkeyPemNoRootLastSize;
extern const int g_testChainSubjectPemNoRootLastUpSize;
extern const int g_testChainPubkeyPemNoRootLastUpSize;
extern const int g_testChainSubjectPemNoRootLastSize;

static const char g_testCertChainPemMid[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIIC0zCCAoWgAwIBAgIIXpLoPpQVWnkwBQYDK2VwMFoxCzAJBgNVBAYTAkVOMRAw\r\n"
    "DgYDVQQIEwdFbmdsYW5kMQ8wDQYDVQQHEwZMb25kb24xDDAKBgNVBAoTA3RzMTEM\r\n"
    "MAoGA1UECxMDdHMxMQwwCgYDVQQDEwN0czEwHhcNMjMxMjA1MDczNzAwWhcNMjQw\r\n"
    "OTAxMjM1OTAwWjBaMQswCQYDVQQGEwJFTjEQMA4GA1UECBMHRW5nbGFuZDEPMA0G\r\n"
    "A1UEBxMGTG9uZG9uMQwwCgYDVQQKEwN0czIxDDAKBgNVBAsTA3RzMjEMMAoGA1UE\r\n"
    "AxMDdHMyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtt+2QxUevbol\r\n"
    "YLp51QGcUpageI4fwGLIqv4fj4aoVnHFOOBqVOVpfCLRp26LFV/F8ebwPyo8YEBK\r\n"
    "SwXzMD1573rMSbaH9BalscH5lZYAbetXoio6YRvzlcmcrVvLBNMeVnxY86xHpo0M\r\n"
    "TNyP7W024rZsxWO98xFQVdoiaBC+7+midlisx2Y+7u0jzT9GjeUP6JLdLFUZJKUP\r\n"
    "STK3jVzw9v1eZQZKYoNfU6vFMd6ndtwW6qEnwpzmmX/UT+p5ThAMH593zszlz330\r\n"
    "nTSXBjIsGkyvOz9gSB0Z0LAuJj06XUNhGL5xKJYKbdI38MFQFJKvRHfgTAvVsvAv\r\n"
    "pBUM2DuBKwIDAQABo28wbTAMBgNVHRMEBTADAQH/MB0GA1UdDgQWBBQ37B0zGcKA\r\n"
    "OnmgxZQVMg6ZGvrGLTALBgNVHQ8EBAMCAQYwEQYJYIZIAYb4QgEBBAQDAgAHMB4G\r\n"
    "CWCGSAGG+EIBDQQRFg94Y2EgY2VydGlmaWNhdGUwBQYDK2VwA0EAuasLBe55YgvF\r\n"
    "b4wmHeohylc9r8cFGS1LNQ5UcSn3sGqMYf6ehnef16NLuCW6upHCs8Sui4iAMvsP\r\n"
    "uKPWR9dKBA==\r\n"
    "-----END CERTIFICATE-----\r\n";

static const char g_testCertChainPemMidCRL[] =
    "-----BEGIN X509 CRL-----\r\n"
    "MIICDTCB9gIBATANBgkqhkiG9w0BAQsFADBaMQswCQYDVQQGEwJFTjEQMA4GA1UE\r\n"
    "CBMHRW5nbGFuZDEPMA0GA1UEBxMGTG9uZG9uMQwwCgYDVQQKEwN0czIxDDAKBgNV\r\n"
    "BAsTA3RzMjEMMAoGA1UEAxMDdHMyFw0yMzEyMTUwMjMyMDBaFw0yNDAxMTQwMjMy\r\n"
    "MDBaMDcwNQIIIM2q/TmRoLcXDTIzMTIxNTAyMzA1M1owGjAYBgNVHRgEERgPMjAy\r\n"
    "MzEyMTQwMjMwMDBaoC8wLTAfBgNVHSMEGDAWgBQ37B0zGcKAOnmgxZQVMg6ZGvrG\r\n"
    "LTAKBgNVHRQEAwIBATANBgkqhkiG9w0BAQsFAAOCAQEAomTBBa9igM3xigouO6uh\r\n"
    "A2P4ws3xr53KYVmpM9nBsuzzzlVBbKh4SbJXboLxFA7NL+FK00lm4is6gQylyPf1\r\n"
    "rcjgKJx8Ol9n2BfrfH9Jlig4EYD7U/NDFB1S7fTbCbYqztZr0oVEfCwKRfCTTPiT\r\n"
    "v2a0S4LZylcAdIKzcDUi9bET5d4/NQBVLz1P3gtEQMZAQlh+VNlk80lcSGdCgejz\r\n"
    "YYbmQ6Lh+AE9QbZMAnCvYD5lT2oU4hUwZcY2ZGhktFnoyFTw80ZjOP/dOwqdkuYi\r\n"
    "SQhs90WaiBhEGmnau0BcJa6FFShTU0CrxFlx5Q0OvqCDtQuxvoYLLosf021Aw5kp\r\n"
    "hg==\r\n"
    "-----END X509 CRL-----\r\n";

static const char g_testCertChainPemRoot[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIIB3zCCAZGgAwIBAgIIWQvOEDl+ya4wBQYDK2VwMFoxCzAJBgNVBAYTAkVOMRAw\r\n"
    "DgYDVQQIEwdFbmdsYW5kMQ8wDQYDVQQHEwZMb25kb24xDDAKBgNVBAoTA3RzMTEM\r\n"
    "MAoGA1UECxMDdHMxMQwwCgYDVQQDEwN0czEwHhcNMjMxMjA1MDAwMDAwWhcNMjQx\r\n"
    "MjA0MjM1OTU5WjBaMQswCQYDVQQGEwJFTjEQMA4GA1UECBMHRW5nbGFuZDEPMA0G\r\n"
    "A1UEBxMGTG9uZG9uMQwwCgYDVQQKEwN0czExDDAKBgNVBAsTA3RzMTEMMAoGA1UE\r\n"
    "AxMDdHMxMCowBQYDK2VwAyEAuxadj1ww0LqPN24zr28jcSOlSWAe0QdLyRF+ZgG6\r\n"
    "klKjdTBzMBIGA1UdEwEB/wQIMAYBAf8CARQwHQYDVR0OBBYEFNSgpoQvfxR8A1Y4\r\n"
    "St8NjOHkRpm4MAsGA1UdDwQEAwIBBjARBglghkgBhvhCAQEEBAMCAAcwHgYJYIZI\r\n"
    "AYb4QgENBBEWD3hjYSBjZXJ0aWZpY2F0ZTAFBgMrZXADQQAblBgoa72X/K13WOvc\r\n"
    "KW0fqBgFKvLy85hWD6Ufi61k4ProQiZzMK+0+y9jReKelPx/zRdCCgSbQroAR2mV\r\n"
    "xjoE\r\n"
    "-----END CERTIFICATE-----\r\n";

static const char g_testExtAttrCert[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIIGujCCBaKgAwIBAgISESG8vx4IzALnkqQG05AvM+2bMA0GCSqGSIb3DQEBBQUA\r\n"
    "MFkxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMS8wLQYD\r\n"
    "VQQDEyZHbG9iYWxTaWduIEV4dGVuZGVkIFZhbGlkYXRpb24gQ0EgLSBHMjAeFw0x\r\n"
    "MjA4MTQxMjM1MDJaFw0xMzA4MTUxMDMxMjlaMIIBCjEdMBsGA1UEDwwUUHJpdmF0\r\n"
    "ZSBPcmdhbml6YXRpb24xDzANBgNVBAUTBjU3ODYxMTETMBEGCysGAQQBgjc8AgED\r\n"
    "EwJVUzEeMBwGCysGAQQBgjc8AgECEw1OZXcgSGFtcHNoaXJlMQswCQYDVQQGEwJV\r\n"
    "UzEWMBQGA1UECAwNTmV3IEhhbXBzaGlyZTETMBEGA1UEBwwKUG9ydHNtb3V0aDEg\r\n"
    "MB4GA1UECRMXVHdvIEludGVybmF0aW9uYWwgRHJpdmUxDTALBgNVBAsMBC5DT00x\r\n"
    "GzAZBgNVBAoMEkdNTyBHbG9iYWxTaWduIEluYzEbMBkGA1UEAwwSd3d3Lmdsb2Jh\r\n"
    "bHNpZ24uY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqx/nHBP4\r\n"
    "6s5KKMDlfZS4qFDiAWsoPSRn6WO4nrUF/G2S3I/AdJ0IcSDOHb48/3APj5alqbgo\r\n"
    "o4IzdG6KLAbENpHMl0L3pHBq/5tJPTi02SbiYUHfp2fhueMauRo8spfEk6fNRnDn\r\n"
    "QpyMFRkYd7Jz+KMerTO1xAcOH+xp0KkcP0i2jFTEuM3LwR0yTms1rry+RryjDDt5\r\n"
    "7W0DLnNFWhyGd6YymzNkCPeL6weV8uk2uYRKKf2XOAzgIpNo3zU6iakZOzlQB9h9\r\n"
    "qRuIks2AU/cZ89cBkDjHua0ezX5rG3/Url33jAT9cR5zCXHWtj7VzlOjDXXnn16b\r\n"
    "L9/AWsvGMNkYHQIDAQABo4ICxzCCAsMwDgYDVR0PAQH/BAQDAgWgMEwGA1UdIARF\r\n"
    "MEMwQQYJKwYBBAGgMgEBMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2Jh\r\n"
    "bHNpZ24uY29tL3JlcG9zaXRvcnkvMIIBKwYDVR0RBIIBIjCCAR6CEnd3dy5nbG9i\r\n"
    "YWxzaWduLmNvbYIVc3RhdHVzLmdsb2JhbHNpZ24uY29tghF0aC5nbG9iYWxzaWdu\r\n"
    "LmNvbYISZGV2Lmdsb2JhbHNpZ24uY29tghNpbmZvLmdsb2JhbHNpZ24uY29tghZh\r\n"
    "cmNoaXZlLmdsb2JhbHNpZ24uY29tghZzdGF0aWMxLmdsb2JhbHNpZ24uY29tghZz\r\n"
    "dGF0aWMyLmdsb2JhbHNpZ24uY29tghNibG9nLmdsb2JhbHNpZ24uY29tghdzc2xj\r\n"
    "aGVjay5nbG9iYWxzaWduLmNvbYIVc3lzdGVtLmdsb2JhbHNpZ24uY29tghhvcGVy\r\n"
    "YXRpb24uZ2xvYmFsc2lnbi5jb22CDmdsb2JhbHNpZ24uY29tMAkGA1UdEwQCMAAw\r\n"
    "HQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMD8GA1UdHwQ4MDYwNKAyoDCG\r\n"
    "Lmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3MvZ3NleHRlbmR2YWxnMi5jcmww\r\n"
    "gYgGCCsGAQUFBwEBBHwwejBBBggrBgEFBQcwAoY1aHR0cDovL3NlY3VyZS5nbG9i\r\n"
    "YWxzaWduLmNvbS9jYWNlcnQvZ3NleHRlbmR2YWxnMi5jcnQwNQYIKwYBBQUHMAGG\r\n"
    "KWh0dHA6Ly9vY3NwMi5nbG9iYWxzaWduLmNvbS9nc2V4dGVuZHZhbGcyMB0GA1Ud\r\n"
    "DgQWBBSvMoTDlFB0aVgVrNkkS1QSmYfx1zAfBgNVHSMEGDAWgBSwsEr9HHUo+Bxh\r\n"
    "qhP2+sGQPWsWozANBgkqhkiG9w0BAQUFAAOCAQEAgnohm8IRw1ukfc0GmArK3ZLC\r\n"
    "DLGpsefwWMvNrclqwrgtVrBx4pfe5xGAjqyQ2QI8V8a8a1ytVMCSC1AMWiWxawvW\r\n"
    "fw48fHunqtpTYNDyEe1Q+7tTGZ0SQ3HljYY9toVEjAMDhiM0Szl6ERRO5S7BTCen\r\n"
    "mDpWZF8w3ScRRY2UJc8xwWFiYyGWDNzNL1O8R2Y95QIkHUgQpSD3cjl4YvF/Xx/o\r\n"
    "hBEzl884uNAggIyQRu0ImLEetEtHWB2w0pZG3nTAqjOAAAyH2Q8IHoJtjQzvg6fy\r\n"
    "IQEO1C5GoQ7isiKIjKBXVYOm+gKSQXlzwj1BlU/OW6kEe24IiERhAN9ILA24wA==\r\n"
    "-----END CERTIFICATE-----\r\n";

static const char g_testCertWithPrivateKeyValid[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIIE0DCCA7igAwIBAgIIAziWeqd+Il8wDQYJKoZIhvcNAQELBQAwZDELMAkGA1UE\r\n"
    "BhMCQ04xEDAOBgNVBAgTB0ppYW5nc3UxEDAOBgNVBAcTB05hbmppbmcxDzANBgNV\r\n"
    "BAoTBnRlc3RDYTEPMA0GA1UECxMGdGVzdENhMQ8wDQYDVQQDEwZ0ZXN0Q2EwHhcN\r\n"
    "MjMxMTIxMDkwNzAwWhcNMjQxMTIxMDkwNzAwWjBsMQswCQYDVQQGEwJDTjEOMAwG\r\n"
    "A1UECBMFdGVzdDExDjAMBgNVBAcTBXRlc3QyMRMwEQYDVQQKEwp0ZXN0RW50aXR5\r\n"
    "MRMwEQYDVQQLEwp0ZXN0RW50aXR5MRMwEQYDVQQDEwp0ZXN0RW50aXR5MIIBIjAN\r\n"
    "BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtlJYIV6tGD9ud/5oIKEU675s9bC4\r\n"
    "u8T5QFz5/lBji9Msm8yIKw0A0f3ObUSnTiHK7N6HW8mifOR7Ol0qqyySsAAXOHaS\r\n"
    "75uhLsGe33RUDudVqRRperdCtWoTKOAJ57bAf+a0YtSggoXbFD501FpD+PyAmJPd\r\n"
    "8X2IpHVhlsKlclaG75uva8jmM8yGSprF/U7eNqQRC/AC+/chCWnU4EOhWwKGtNbv\r\n"
    "83QiC5Bdkzg0XU86XSkSl5a1DBOlFKNaok96auEBUUqT2aqn7n+51CFIo+7gURrW\r\n"
    "7lQA4CJrgVQ5E5067jn5gcCBTQ/769S1tyef7t0d3Ch7EbBlkCdk6GDr0QIDAQAB\r\n"
    "o4IBfDCCAXgwHwYDVR0jBBgwFoAUEuUlpeu7/V4AKWsn3soGdQI5VW0wKwYDVR0Q\r\n"
    "BCQwIoAPMjAyMzExMjEwMDAwMDBagQ8yMDI4MTEyMTAwMDAwMFowDAYDVR0TAQH/\r\n"
    "BAIwADAdBgNVHQ4EFgQUEuUlpeu7/V4AKWsn3soGdQI5VW0wDAYDVR0PBAUDAwcD\r\n"
    "gDApBgNVHSUEIjAgBggrBgEFBQcDBAYIKwYBBQUHAwgGCisGAQQBgjcCARUwGQYD\r\n"
    "VR0RBBIwEIEOdGVzdDFAdGVzdC5jb20wFwYDVR0gBBAwDjAFBgMqAwQwBQYDKgIC\r\n"
    "MFsGA1UdHgRUMFKgHjANggtleGFtcGxlLmNvbTANggtleGFtcGxlLm9yZ6EwMAqH\r\n"
    "CAAAAAAAAAAAMCKHIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMBEG\r\n"
    "CWCGSAGG+EIBAQQEAwIGQDAeBglghkgBhvhCAQ0EERYPeGNhIGNlcnRpZmljYXRl\r\n"
    "MA0GCSqGSIb3DQEBCwUAA4IBAQCmPFuLoIcOOkTaSiuPEu9XuNXkMAzNI3u92xhp\r\n"
    "S4/LXPb9ruFBChYMsW6+1obSfDTx7553LhkH7X6Mt7AXKWmnSMY0yQJ/lPoGIIyB\r\n"
    "Ir7D32aDPrZNBg5WxSzUkddbgEId8iILt9jAWAfvGHNJLiDtHh5bfTx1ZtSPvmON\r\n"
    "+kG4XvRCn+KnP+ZWSsURXfLqNbs9pRSFk42S5FP4dUy3Ohij+U0/tnr0C6Kfakd8\r\n"
    "pZ31DXtKBoID52qpVFziQkpLZSqXAUvO5v4X5RSZvN3PnCzBEng0NqS2SoaS0mMV\r\n"
    "fAk3kUyZVj3fRpxEXYleD96l3gP4pP3mrS8pxPoqGzuIQoEU\r\n"
    "-----END CERTIFICATE-----\r\n";

extern const CfEncodingBlob g_crlDerInStream;
extern const CfEncodingBlob g_invalidCrlDerInStream;
extern const CfEncodingBlob g_inStreamCrl;
extern const CfEncodingBlob g_inStreamSelfSignedCaCert;
extern const CfEncodingBlob g_crlWithoutExtPemInStream;
extern const CfEncodingBlob g_crlWithBignumSerialInStream;
extern const CfEncodingBlob g_crlWhichEntryWithExtInStream;
extern const CfEncodingBlob g_inStreamCert;
extern const CfEncodingBlob g_inStreamIssuerCert;
extern const CfEncodingBlob g_inStreamChainDataP7b;
extern const CfEncodingBlob g_inStreamChainDataDer;
extern const CfEncodingBlob g_inStreamChainDataPem;
extern const CfEncodingBlob g_inStreamChainDataPemMid;
extern const CfEncodingBlob g_inStreamChainDataPemRoot;
extern const CfEncodingBlob g_inStreamChainDataPemNoRoot;
extern const CfEncodingBlob g_inStreamChainDataPemMidCRL;
extern const CfEncodingBlob g_inStreamChainPemNoRootHasPubKey;
extern const CfEncodingBlob g_inStreamChainPemNoRootLast;
extern const CfEncodingBlob g_inStreamChainDataPemDisorder;
extern const CfEncodingBlob g_inStreamChainDataPem163;
extern const CfEncodingBlob g_inStreamChainDataPemRoot163;
extern const CfEncodingBlob g_inStreamOcspResponderCert;

const char *GetInvalidCertClass(void);
const char *GetInvalidCrlClass(void);
SubAltNameArray *ConstructSubAltNameArrayData();
CfArray *ConstructCertPolicyData();
const char *GetValidCrlClass(void);
const char *GetValidX509CertificateClass(void);
void FreeTrustAnchor(HcfX509TrustAnchor *&trustAnchor);
void BuildAnchorArr(const CfEncodingBlob &certInStream, HcfX509TrustAnchorArray &trustAnchorArray);
void FreeTrustAnchorArr(HcfX509TrustAnchorArray &trustAnchorArray);
void BuildCollectionArr(const CfEncodingBlob *certInStream, const CfEncodingBlob *crlInStream,
    HcfCertCRLCollectionArray &certCRLCollections);
void FreeCertCrlCollectionArr(HcfCertCRLCollectionArray &certCRLCollections);
void FreeValidateResult(HcfX509CertChainValidateResult &result);

#ifdef __cplusplus
}
#endif
#endif
