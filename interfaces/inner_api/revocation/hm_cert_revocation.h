/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef HM_CERT_REVOCATION_H
#define HM_CERT_REVOCATION_H

#include <stddef.h>
#include <stdint.h>
#include "cf_result.h"
#include "x509_certificate.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Check whether any certificate in the chain is revoked or disabled
 * by the system revocation policy.
 *
 * @param [in] certs The certificate chain array. data is HcfX509Certificate**, count is the number.
 *                   Must be non-NULL; when count > 0, data must be non-NULL.
 *                   count == 0 is treated as an empty chain and returns CF_SUCCESS.
 * @param [out] blockedIndex The index of the first matched certificate, or -1 if none matched.
 *                          Can be NULL if the caller does not need the index.
 * @return CF_SUCCESS if no certificate is revoked, including an empty chain
 *         (count == 0) and an unavailable policy (both cloud and user policy
 *         files missing or unreadable, treated as empty rules);
 *         CF_ERR_CERT_REVOKED(-30015) if any certificate is revoked;
 *         CF_ERR_PARAMETER_CHECK(-20005) if certs is NULL, or data is NULL while count > 0;
 *         CF_ERR_MALLOC(-20001) if memory allocation fails.
 *
 * @note Per-certificate fail-open: a certificate is treated as NOT revoked
 *       (skipped) when it cannot be matched, including: missing AKI
 *       keyIdentifier, AKI keyIdentifier length != 20 bytes, unsupported
 *       notBefore format (e.g. 11-byte UTCTime without seconds), or
 *       unparseable certificate DER. Policy-level unavailability is fail-open
 *       (treated as empty rules) and returns CF_SUCCESS.
 */
CfResult HcfCertRevocationCheck(const HcfX509CertificateArray *certs, int32_t *blockedIndex);

/*
 * Clear the revocation cache. The next call to HcfCertRevocationCheck
 * will reload the policy files lazily. Thread-safe; safe to call
 * concurrently with HcfCertRevocationCheck.
 */
void HcfCertRevocationClearCache(void);

#ifdef __cplusplus
}
#endif

#endif // HM_CERT_REVOCATION_H
