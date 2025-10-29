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

#ifndef X509_TRUST_ANCHOR_H
#define X509_TRUST_ANCHOR_H

#include <stddef.h>
#include <stdint.h>

#include "cf_blob.h"
#include "x509_certificate.h"

typedef struct HcfX509TrustAnchor HcfX509TrustAnchor;
struct HcfX509TrustAnchor {
    CfBlob *CAPubKey;           // CAPubKey : Uint8Array DER format
    HcfX509Certificate *CACert; // CACert : X509Cert
    CfBlob *CASubject;          // CASubject : Uint8Array DER format
    CfBlob *nameConstraints;
};

typedef struct {
    HcfX509TrustAnchor **data;
    uint32_t count;
} HcfX509TrustAnchorArray;

typedef struct {
    bool isPem;                         // format of prikey : PEM format is true, DER is false
    CfBlob *pwd;                        // pwd : string
    bool isGetPriKey;                   // isGetPriKey : true is get prikey, false is not get prikey
    bool isGetCert;                     // isGetCert : true is get Cert, false is not get Cert
    bool isGetOtherCerts;               // isGetOtherCerts : true is get otherCerts, false is not get otherCerts
} HcfParsePKCS12Conf;

typedef struct {
    bool isPem;                         // format of prikey : PEM format is true, DER is false
    CfBlob *prikey;                     // prikey : Uint8Array
    HcfX509Certificate *cert;           // cert : X509Cert
    HcfX509Certificate **otherCerts;    // otherCerts : X509Cert[]
    uint32_t otherCertsCount;           // otherCertsCount : count of otherCerts
} HcfX509P12Collection;

#define CERT_PKCS12_DEFAULT_SALT_LEN 16
#define CERT_PKCS12_DEFAULT_ITERATION 2048

typedef struct {
    int32_t saltLen;       // saltLen : int
    int32_t iteration;  // iteration : int
    CfPbesEncryptionAlgorithm alg;         // alg : AES_128_CBC = 0, AES_192_CBC = 1, AES_256_CBC = 2,
} HcfPbesParams;

typedef struct {
    CfBlob *pwd;                        // pwd : string
    HcfPbesParams keyEncParams;         // keyEncParams : PbesParams
    bool encryptCert;        // encryptCert : boolean default is true
    HcfPbesParams certEncParams;        // certEncParams : PbesParams
    int32_t macSaltLen;     // macSalt : int
    int32_t macIteration; // macIteration : int
    CfPkcs12MacDigestAlgorithm macAlg;      // macAlg : SHA256 = 0, SHA384 = 1, SHA512 = 2,
} HcfPkcs12CreatingConfig;
#endif // X509_TRUST_ANCHOR_H
