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
#include "ani_pub_key.h"
#include "x509_certificate.h"

namespace ANI::CertFramework {
class X509CertImpl {
public:
    X509CertImpl();
    explicit X509CertImpl(HcfX509Certificate *cert);
    ~X509CertImpl();

    void VerifySync(cryptoFramework::weak::PubKey key);
    EncodingBlob GetEncodedSync();
    cryptoFramework::PubKey GetPublicKey();

private:
    HcfX509Certificate *cert_ = nullptr;
};
} // namespace ANI::CertFramework

#endif // ANI_X509_CERT_H
