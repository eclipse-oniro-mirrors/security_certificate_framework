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

#ifndef CF_CERTIFICATE_OEPNSSL_CLASS_H
#define CF_CERTIFICATE_OEPNSSL_CLASS_H

#include "pub_key.h"
#include "pri_key.h"
#include "x509_certificate_spi.h"
#include "x509_crl_entry.h"
#include "x509_crl.h"
#include "x509_crl_spi.h"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

typedef struct {
    HcfPubKey base;

    uint32_t bits;

    RSA *pk;
} HcfOpensslRsaPubKey;
#define OPENSSL_RSA_PUBKEY_CLASS "OPENSSL.RSA.PUB_KEY"

typedef struct {
    HcfPriKey base;

    uint32_t bits;

    RSA *sk;
} HcfOpensslRsaPriKey;
#define OPENSSL_RSA_PRIKEY_CLASS "OPENSSL.RSA.PRI_KEY"

typedef struct {
    HcfX509CertificateSpi base;
    X509 *x509;
} HcfOpensslX509Cert;
#define X509_CERT_OPENSSL_CLASS "X509CertOpensslClass"

typedef struct {
    HcfX509CrlEntry base;
    X509_REVOKED *rev;
    CfBlob *certIssuer;
} HcfX509CRLEntryOpensslImpl;
#define X509_CRL_ENTRY_OPENSSL_CLASS "X509CrlEntryOpensslClass"

typedef struct {
    HcfX509Crl base;
    HcfX509CrlSpi *spiObj;
    const char *certType;
} HcfX509CrlImpl;
#define X509_CRL_OPENSSL_CLASS "X509CrlOpensslClass"

#endif
