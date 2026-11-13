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

#ifndef REVOCATION_CHECK_H
#define REVOCATION_CHECK_H

#include <stdint.h>
#include "cf_result.h"
#include "x509_certificate.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque forward declaration of the OpenSSL X509 type. Callers that already
 * include <openssl/x509.h> can pass X509* directly (same underlying type);
 * this keeps OpenSSL includes out of non-OpenSSL consumers of this header. */
struct x509_st;

/* Opaque forward declaration of an OpenSSL X509 stack (STACK_OF(X509)). */
struct stack_st_X509;

/* Accessor used by RevocationCheckX509View to expose the i-th certificate from
 * a caller-owned container. The returned X509 is borrowed: the callee never
 * frees it and the container must stay valid for the whole call. */
typedef struct x509_st *(*RevocationCertGetter)(const void *ctx, uint32_t index);

/* Check cert chain for revoked certs. blockedIndex initialized to -1 (may be NULL).
 * count==0 returns CF_SUCCESS. Returns CF_SUCCESS/CF_ERR_CERT_REVOKED/
 * CF_ERR_PARAMETER_CHECK/CF_ERR_MALLOC. When both policy files are missing or
 * unavailable the policy is treated as empty and CF_SUCCESS is returned. */
CfResult RevocationCheck(const HcfX509CertificateArray *certs, int32_t *blockedIndex);

/* Check an already-parsed X509 array. Avoids the DER re-encode/re-parse cost of the
 * Hcf-based entry point; intended for callers that already hold X509 objects
 * (chain validator, CMS). Does not take ownership of the X509 objects.
 * Semantics match RevocationCheck: user cache first, then cloud; blockedIndex
 * receives the first matched cert index, or -1 when not revoked. */
CfResult RevocationCheckX509(struct x509_st **x509s, uint32_t count, int32_t *blockedIndex);

/* Generic, zero-copy entry point: checks the certificates exposed by
 * getter(ctx, i). The caller keeps ownership of ctx and every X509 object.
 * Useful for callers whose certificates live in a non-array container
 * (e.g. CertsInfo[]) without building a temporary X509** array.
 * count==0 returns CF_SUCCESS; blockedIndex receives the first matched index
 * or -1. Semantics otherwise match RevocationCheckX509. */
CfResult RevocationCheckX509View(const void *ctx, uint32_t count,
    RevocationCertGetter getter, int32_t *blockedIndex);

/* Convenience wrapper over an OpenSSL X509 stack (STACK_OF(X509)).
 * Zero-copy and does not take ownership of the stack or its elements.
 * Semantics match RevocationCheckX509. */
CfResult RevocationCheckX509Stack(struct stack_st_X509 *chain, int32_t *blockedIndex);

/* Convert an Hcf certificate to an X509 object (DER round-trip).
 * On success *x509Out is owned by the caller and must be freed with X509_free. */
CfResult RevocationHcfCertToX509(HcfX509Certificate *cert, struct x509_st **x509Out);

/* Clear cloud+user caches, next query lazily reloads. Thread-safe via write lock. */
void RevocationClearCache(void);

/* Called when user.cfg is externally updated to clear the user cache.
 * Invoked by the CA cert status change event subscriber
 * (revocation_event_subscriber.cpp) on cert manager notifications. */
void RevocationNotifyUserCfgUpdate(void);

#ifdef __cplusplus
}
#endif

#endif // REVOCATION_CHECK_H
