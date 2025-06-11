/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#ifndef ANI_X509_CRL_H
#define ANI_X509_CRL_H

#include "ani_common.h"
#include "x509_crl.h"

namespace ANI::CertFramework {
class X509CRLImpl {
public:
    X509CRLImpl();
    explicit X509CRLImpl(HcfX509Crl *x509Crl);
    ~X509CRLImpl();

    bool IsRevoked(weak::X509Cert cert);
    string GetType();
    EncodingBlob GetEncodedSync();
    void VerifySync(cryptoFramework::weak::PubKey key);
    int32_t GetVersion();
    DataBlob GetIssuerName();
    string GetIssuerNameEx(EncodingType encodingType);
    string GetLastUpdate();
    string GetNextUpdate();
    X509CRLEntry GetRevokedCert(array_view<uint8_t> serialNumber);
    X509CRLEntry GetRevokedCertWithCert(weak::X509Cert cert);
    array<X509CRLEntry> GetRevokedCertsSync();
    DataBlob GetTBSInfo();
    DataBlob GetSignature();
    string GetSignatureAlgName();
    string GetSignatureAlgOid();
    DataBlob GetSignatureAlgParams();
    DataBlob GetExtensions();
    bool Match(X509CRLMatchParameters const& param);
    X500DistinguishedName GetIssuerX500DistinguishedName();
    string ToString();
    string ToStringEx(EncodingType encodingType);
    array<uint8_t> HashCode();
    CertExtension GetExtensionsObject();

private:
    HcfX509Crl *x509Crl_ = nullptr;
};
} // namespace ANI::CertFramework

#endif // ANI_X509_CRL_H
