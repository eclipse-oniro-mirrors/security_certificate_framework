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

#ifndef ANI_X509_CERT_H
#define ANI_X509_CERT_H

#include "ani_common.h"
#include "x509_certificate.h"

namespace ANI::CertFramework {
class X509CertImpl {
public:
    X509CertImpl();
    explicit X509CertImpl(HcfX509Certificate *cert, bool owner = true);
    ~X509CertImpl();

    int64_t GetX509CertObj();
    void VerifySync(cryptoFramework::weak::PubKey key);
    EncodingBlob GetEncodedSync();
    cryptoFramework::PubKey GetPublicKey();
    void CheckValidityWithDate(string_view date);
    int32_t GetVersion();
    array<uint8_t> GetCertSerialNumber();
    DataBlob GetIssuerName();
    string GetIssuerNameEx(EncodingType encodingType);
    DataBlob GetSubjectName(optional_view<EncodingType> encodingType);
    string GetNotBeforeTime();
    string GetNotAfterTime();
    DataBlob GetSignature();
    string GetSignatureAlgName();
    string GetSignatureAlgOid();
    DataBlob GetSignatureAlgParams();
    DataBlob GetKeyUsage();
    DataArray GetExtKeyUsage();
    int32_t GetBasicConstraints();
    DataArray GetSubjectAltNames();
    DataArray GetIssuerAltNames();
    DataBlob GetItem(CertItemType itemType);
    bool Match(X509CertMatchParameters const& param);
    DataArray GetCRLDistributionPoint();
    X500DistinguishedName GetIssuerX500DistinguishedName();
    X500DistinguishedName GetSubjectX500DistinguishedName();
    string ToString();
    string ToStringEx(EncodingType encodingType);
    array<uint8_t> HashCode();
    CertExtension GetExtensionsObject();

private:
    HcfX509Certificate *cert_ = nullptr;
    CfObject *object_ = nullptr;
    bool owner_ = true;
};
} // namespace ANI::CertFramework

#endif // ANI_X509_CERT_H
