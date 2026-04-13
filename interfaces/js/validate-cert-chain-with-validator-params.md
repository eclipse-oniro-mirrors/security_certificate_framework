# 证书链校验（带校验参数）

<!--Kit: Device Certificate Kit-->
<!--Subsystem: Security-->
<!--Owner: @zxz--3-->
<!--Designer: @lanming-->
<!--Tester: @PAFT-->
<!--Adviser: @zengyawen-->

证书链校验器提供证书链构建和校验能力，支持通过[X509CertValidatorParams](../../reference/apis-device-certificate-kit/js-apis-cert.md#x509certvalidatorparams)参数配置校验行为，包括信任锚设置、证书吊销检查、日期校验、主机名匹配等。

相较于基础的[validate](../../reference/apis-device-certificate-kit/js-apis-cert.md#validate-1)方法，新增的[validate(cert: X509Cert, params: X509CertValidatorParams)](../../reference/apis-device-certificate-kit/js-apis-cert.md#validate)方法提供更灵活的证书链校验配置能力。

## 开发步骤

1. 导入[证书算法库框架模块](../../reference/apis-device-certificate-kit/js-apis-cert.md)。
   ```ts
   import { cert } from '@kit.DeviceCertificateKit';
   ```

2. [cert.createCertChainValidator](../../reference/apis-device-certificate-kit/js-apis-cert.md#certcreatecertchainvalidator)创建证书链校验器对象。

3. 基于已有的证书数据，创建[X509Cert](../../reference/apis-device-certificate-kit/js-apis-cert.md#x509cert)证书对象。

4. 创建[X509CertValidatorParams](../../reference/apis-device-certificate-kit/js-apis-cert.md#x509certvalidatorparams)校验参数对象。

5. 调用[CertChainValidator.validate(cert: X509Cert, params: X509CertValidatorParams)](../../reference/apis-device-certificate-kit/js-apis-cert.md#validate)校验证书，返回校验结果[VerifyCertResult](../../reference/apis-device-certificate-kit/js-apis-cert.md#verifycertresult)。

## 参数详解

### X509CertValidatorParams 参数说明

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| untrustedCerts | Array\<X509Cert\> | 否 | - | **非信任证书列表**。提供辅助构建证书链的中间证书。这些证书仅用于构建链，不作为信任锚点。适用于服务器未发送完整证书链的场景。最大数量：100。 |
| trustedCerts | Array\<X509Cert\> | 否 | - | **信任证书列表**。指定信任的根证书或中间CA证书，作为验证的信任锚点。验证时，证书链必须能追溯到这些信任证书。必须设置此参数或将trustSystemCa设为true。最大数量：100。 |
| trustSystemCa | boolean | 否 | false | **是否信任系统CA**。设为true时，使用操作系统预置的CA证书库作为信任锚。适用于验证公共网站证书，无需手动配置根证书。 |
| partialChain | boolean | 否 | false | **是否允许部分链验证**。设为true时，允许信任链中的任意证书作为信任锚，而非必须追溯到根证书。 |
| allowDownloadIntermediateCa | boolean | 否 | false | **是否允许从网络下载中间CA证书**。设为true时，当证书链缺失中间证书时，自动从证书的AIA扩展下载颁发者证书，解决证书链不完整的问题。下载超时：3秒，最大下载次数：5次。 |
| date | string | 否 | 当前时间 | **验证日期**。格式为YYMMDDHHMMSSZ或YYYYMMDDHHMMSSZ。支持自定义验证时间，适用于离线验证历史签名等场景。详见下方date参数格式说明。 |
| validateDate | boolean | 否 | true | **是否验证日期**。设为false时跳过证书有效期验证。 |
| ignoreErrs | Array\<CertResult\> | 否 | - | **忽略指定错误**。允许忽略特定的验证错误。最大数量：8。支持的错误码见下表。 |
| hostnames | Array\<string\> | 否 | - | **主机名列表**。验证证书的主题备用名（SAN）或通用名（CN）是否包含指定的主机名。用于HTTPS等场景。最大数量：100，每个主机名最大长度：128。 |
| emailAddresses | Array\<string\> | 否 | - | **邮箱地址列表**。验证证书是否包含指定的邮箱地址。目前仅支持1个邮箱。最大长度：128。 |
| keyUsage | Array\<KeyUsageType\> | 否 | - | **密钥用途列表**。验证证书的密钥用途扩展是否包含指定的用途。最大数量：9。 |
| userId | Uint8Array | 否 | - | **SM2用户ID**。用于验证国密SM2证书时设置签名验证所需的用户标识符。最大长度：128。userId参数与吊销检查不能同时使用。 |
| revokedParams | X509CertRevokedParams | 否 | - | **吊销检查参数**。用于检查证书是否被吊销。包含CRL列表、OCSP响应数据、是否允许在线检查等配置。 |

### date参数格式说明

date参数用于指定证书有效期验证的时间点，采用UTCTime或GeneralizedTime格式：

**格式一：YYMMDDHHMMSSZ（长度13）**
- 采用UTCTime格式，年份用2位数字表示
- 示例：`250101000000Z` 表示2025年1月1日0时0分0秒UTC时间
- 年份范围：00-99，其中00-49表示2000-2049年，50-99表示1950-1999年

**格式二：YYYYMMDDHHMMSSZ（长度15）**
- 采用GeneralizedTime格式，年份用4位数字表示
- 示例：`20250101000000Z` 表示2025年1月1日0时0分0秒UTC时间
- 年份范围：可表示任意年份，无限制

**格式组成**：
| 组成部分 | 长度 | 说明 |
|----------|------|------|
| YY或YYYY | 2或4 | 年份 |
| MM | 2 | 月份（01-12） |
| DD | 2 | 日期（01-31） |
| HH | 2 | 小时（00-23） |
| MM | 2 | 分钟（00-59） |
| SS | 2 | 秒（00-59） |
| Z | 1 | UTC时间标识符 |

**说明**：
- 末尾的`Z`表示UTC（协调世界时），必须包含。
- 时间字段采用24小时制。
- 默认使用当前系统时间进行验证。

### ignoreErrs 支持忽略的错误码

| 错误码 | 常量名 | 说明 |
|--------|--------|------|
| 19030003 | ERR_CERT_NOT_YET_VALID | 证书未生效 |
| 19030004 | ERR_CERT_HAS_EXPIRED | 证书已过期 |
| 19030011 | ERR_UNKNOWN_CRITICAL_EXTENSION | 未知的关键扩展 |
| 19030015 | ERR_CRL_NOT_FOUND | 未找到CRL |
| 19030016 | ERR_CRL_NOT_YET_VALID | CRL未生效 |
| 19030017 | ERR_CRL_HAS_EXPIRED | CRL已过期 |
| 19030020 | ERR_OCSP_RESPONSE_NOT_FOUND | 未找到OCSP响应 |
| 19030024 | ERR_NETWORK_TIMEOUT | 网络超时 |

**说明**：以上8种错误码可以通过ignoreErrs参数指定忽略，其他错误码不支持忽略。忽略错误后验证将继续进行后续校验。

### X509CertRevokedParams 吊销检查参数说明

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| revocationFlags | Array\<CertRevocationFlag\> | 是 | - | **吊销检查标志**。数量范围：[1, 4]。必须设置CERT_REVOCATION_CRL_CHECK或CERT_REVOCATION_OCSP_CHECK。 |
| crls | Array\<X509CRL\> | 否 | - | **CRL列表**。提供用于验证的证书吊销列表。最大数量：100。 |
| allowDownloadCrl | boolean | 否 | false | **是否允许下载CRL**。设为true时，从证书的CRL分发点扩展下载CRL。下载超时：3秒。 |
| ocspResponses | Array\<Uint8Array\> | 否 | - | **OCSP响应数据**。预置的OCSP响应数据。最大数量：100。 |
| allowOcspCheckOnline | boolean | 否 | false | **是否允许在线OCSP检查**。设为true时，从证书的AIA扩展获取OCSP URL并发送请求。超时：4秒。 |
| ocspDigest | OcspDigest | 否 | SHA256 | **OCSP摘要算法**。设置OCSP请求使用的摘要算法（SHA1/SHA224/SHA256/SHA384/SHA512）。 |

### CertRevocationFlag 吊销检查标志说明

| 标志值 | 常量名 | 作用说明 |
|--------|--------|----------|
| 0 | CERT_REVOCATION_PREFER_OCSP | **优先OCSP**。仅当同时启用CRL_CHECK和OCSP_CHECK时有效。设置后先执行OCSP检查，未找到响应或超时时回退CRL；不设置则先执行CRL检查，未找到CRL或超时时回退OCSP。 |
| 1 | CERT_REVOCATION_CRL_CHECK | **启用CRL检查**。使用证书吊销列表检查证书状态。首先使用预置的crls参数，未匹配时若allowDownloadCrl=true则从CDP扩展下载CRL。 |
| 2 | CERT_REVOCATION_OCSP_CHECK | **启用OCSP检查**。使用在线证书状态协议检查证书状态。首先使用预置的ocspResponses参数，未匹配时若allowOcspCheckOnline=true则从AIA扩展获取OCSP URL并发送请求。 |
| 3 | CERT_REVOCATION_CHECK_ALL_CERT | **检查所有证书**。设置后对证书链中所有证书执行吊销检查（跳过自签名证书）；不设置则仅检查终端证书（证书链第一个证书）。 |

**参数校验规则**：
- revocationFlags数量范围：[1, 4]，必须设置至少一个标志
- 必须设置CRL_CHECK或OCSP_CHECK（不能仅设置PREFER_OCSP或CHECK_ALL_CERT）
- userId参数与吊销检查不能同时使用（互斥）

**组合使用示例**：

| revocationFlags组合 | 执行逻辑 |
|---------------------|----------|
| `[CRL_CHECK]` | 仅CRL检查，无回退机制 |
| `[OCSP_CHECK]` | 仅OCSP检查，无回退机制 |
| `[CRL_CHECK, OCSP_CHECK]` | 先CRL检查，未找到CRL或网络超时时回退OCSP；若CRL校验发现证书被吊销则直接返回错误不回退 |
| `[PREFER_OCSP, CRL_CHECK, OCSP_CHECK]` | 先OCSP检查，未找到OCSP响应或网络超时时回退CRL；若OCSP校验发现证书被吊销则直接返回错误不回退 |
| `[CRL_CHECK, CHECK_ALL_CERT]` | 对证书链所有证书执行CRL检查（跳过自签名证书） |
| `[PREFER_OCSP, CRL_CHECK, OCSP_CHECK, CHECK_ALL_CERT]` | 对所有证书优先OCSP检查，未找到响应或超时时回退CRL |

**回退机制说明**：

回退仅发生在资源获取失败（未找到CRL/OCSP响应或网络超时），校验失败（如证书被吊销）不会回退。

| 优先方式 | 回退条件（资源获取失败） | 不回退条件（校验失败） | 回退目标 |
|----------|--------------------------|------------------------|----------|
| OCSP优先（PREFER_OCSP） | OCSP_RESPONSE_NOT_FOUND 或 NETWORK_TIMEOUT | CERT_REVOKED、OCSP_SIGNATURE_FAILURE等 | CRL检查 |
| CRL优先（无PREFER_OCSP） | CRL_NOT_FOUND 或 NETWORK_TIMEOUT | CERT_REVOKED、CRL_SIGNATURE_FAILURE等 | OCSP检查 |

### KeyUsageType 密钥用途枚举

| 值 | 常量名 | 说明 |
|------|--------|------|
| 0 | KEYUSAGE_DIGITAL_SIGNATURE | 数字签名 |
| 1 | KEYUSAGE_NON_REPUDIATION | 不可否认 |
| 2 | KEYUSAGE_KEY_ENCIPHERMENT | 密钥加密 |
| 3 | KEYUSAGE_DATA_ENCIPHERMENT | 数据加密 |
| 4 | KEYUSAGE_KEY_AGREEMENT | 密钥协商 |
| 5 | KEYUSAGE_KEY_CERT_SIGN | 证书签名 |
| 6 | KEYUSAGE_CRL_SIGN | CRL签名 |
| 7 | KEYUSAGE_ENCIPHER_ONLY | 仅加密 |
| 8 | KEYUSAGE_DECIPHER_ONLY | 仅解密 |

### OcspDigest OCSP摘要算法枚举

| 值 | 常量名 | 说明 |
|------|--------|------|
| 0 | SHA1 | SHA1摘要算法 |
| 1 | SHA224 | SHA224摘要算法 |
| 2 | SHA256 | SHA256摘要算法（默认） |
| 3 | SHA384 | SHA384摘要算法 |
| 4 | SHA512 | SHA512摘要算法 |

### VerifyCertResult 返回结果说明

| 参数 | 类型 | 说明 |
|------|------|------|
| certChain | Array\<X509Cert\> | **验证后的证书链**。验证成功时返回完整的证书链，从终端证书到信任锚点。可用于后续的证书信息查询或其他验证操作。 |

## 场景一：基础场景，信任证书由使用者提供

当应用有自定义的信任锚证书时，可以通过`trustedCerts`参数指定信任的CA证书列表。

<!-- @[certificate_chain_validation_with_custom_trust_anchor](https://gitcode.com/openharmony/applications_app_samples/blob/master/code/DocsSample/Security/DeviceCertificateKit/CertificateAlgorithmLibrary/entry/src/main/ets/pages/ValidateCertChainWithCustomTrustAnchor.ets) -->

``` TypeScript
import { cert } from '@kit.DeviceCertificateKit';

// 待校验的终端实体证书（PEM格式）
let endEntityCertData = '-----BEGIN CERTIFICATE-----\r\n' +
  'MIIDUjCCAjqgAwIBAgIBZjANBgkqhkiG9w0BAQsFADA/MQswCQYDVQQGEwJVUzER\r\n' +
  'MA8GA1UECgwIVGVzdCBPcmcxHTAbBgNVBAMMFFRlc3QgSW50ZXJtZWRpYXRlIENB\r\n' +
  'MB4XDTI1MDEwMTAwMDAwMFoXDTI2MDEwMTAwMDAwMFowOzELMAkGA1UEBhMCVVMx\r\n' +
  'ETAPBgNVBAoMCFRlc3QgT3JnMRkwFwYDVQQDDBB0ZXN0LmV4YW1wbGUuY29tMIIB\r\n' +
  'IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvuupEHodA9hCgM0C2Zy1dIBH\r\n' +
  'S6CK8rPR1ygUr8/q8+1HiFTneBhSUZIK8YcFOKPstZ3MdHNLSJWS0FyEgUdDLrIf\r\n' +
  'DFZAHDdWFs/nmGBdXFbJiKeffKojAnaVgLIC2OzfMtgMmscPEPLvWrj5X4nhxFZc\r\n' +
  '/yVNHiqQYay+kypKO3qRJwna/KaMcm/BAvrLUpjOgri3B0nf16OyAP52csxUokaf\r\n' +
  '/6r5KXAkBXThF/64RA37+RTQf+nkQ6AF2Q9VlfF76RhnpqqUy0m3joGTkXy7DYXO\r\n' +
  'gHfgKNI2Cplf6i1/16rG3CbLLXy58qlNRBmSgvvynl4w+kHSnafabdOtnJKnWQID\r\n' +
  'AQABo10wWzAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIFoDATBgNVHSUEDDAK\r\n' +
  'BggrBgEFBQcDATAmBgNVHREEHzAdghB0ZXN0LmV4YW1wbGUuY29tgglsb2NhbGhv\r\n' +
  'c3QwDQYJKoZIhvcNAQELBQADggEBAEzAFIzQnZaxXdbFfpIhErm9WQOrMeaTGSMU\r\n' +
  'Hz7cjcV+Hii+1ZvU+cKYFXnQ2pIhNz4Lf4Tk1JFpT4pNZAqxLKIWnvZ4LvwBk54J\r\n' +
  'g99Ilhc9xtPKeIFvuQrXevPp+2XjTxlCejtVPV1TZ+4l8nWkrU0n/gBZCZ2cL8Kw\r\n' +
  'k9562UbM4tb8BZt7s7NROLI2KFd8M06/cKvUIR/TpNNjVpcSi9ozvti82GUS6b3z\r\n' +
  'QGaLNQbjXBnPDpJwEa6B2xQCOyVnnV3rENq6qpPbQWE+B/tXeg0uPYQdU8Mbka6H\r\n' +
  'zYoFmR8AEtSYi1QSHZMiYoAExq4O1fM0+bI9IeKsmVtk0u/Nkt0=\r\n' +
  '-----END CERTIFICATE-----\r\n';

// 中间CA证书（PEM格式）
let intermediateCaCertData = '-----BEGIN CERTIFICATE-----\r\n' +
  'MIIEFzCCAf+gAwIBAgIBZTANBgkqhkiG9w0BAQsFADA/MQswCQYDVQQGEwJVUzER\r\n' +
  'MA8GA1UECgwIVGVzdCBPcmcxHTAbBgNVBAMMFFRlc3QgSW50ZXJtZWRpYXRlIENB\r\n' +
  'MB4XDTI1MDEwMTAwMDAwMFoXDTMwMDEwMTAwMDAwMFowTzELMAkGA1UEBhMCVVMx\r\n' +
  'ETAPBgNVBAoMCFRlc3QgT3JnMR0wGwYDVQQDDBRUZXN0IEludGVybWVkaWF0ZSBD\r\n' +
  'QTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJnt2JFi/ylZvv9tBp0n\r\n' +
  'BZgAYu5zUyUmiXjlM9WWzAlHMC/u8dr6zYP7vyPMUyGtDsUajvLzVHSDNm9/BfaM\r\n' +
  'TU8fDDPwdId0KNCqNudBKyt9dNCxRSGmxdC0t8KbVvkg160dVVqFNjZ4Grbnrbu\r\n' +
  'av86CQeDesymBNE5jBbfL2qEeif04Q6coAGBNIH3HuG59aJxiO41llvQvh4/Dnc\r\n' +
  '79CNrBCCPaEHD6lQQX+TW2GL4R1ai7jcQTTTAXG+7crye6pYi2s/B9X8peXnOE0\r\n' +
  'tn5LKEV9Y2QpG5xP4A3QQwh6JkACkLHF1pAfKXSxkpAwejImhTNFcDZdTTSA4lT\r\n' +
  'mWaySaP0CAwEAAaOmTDAmMBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQ\r\n' +
  'DAgGGMA0GCSqGSIb3DQEBCwUAA4ICAQBTcIuCCX1vBsIehHxPN/Oqu7upFqpOAYP\r\n' +
  '++S9oSA0lVLnOnwccNPvCFP5dRCZY1A1rJsf0OVeFUjAfmOHCbpcyEn26y3lsNwp\r\n' +
  '0tAV7dJdkiaS00vStgopGJjPwJBT6LTh936/rWGHFUcv0O8lqPQiPddLnwxKFvZ/\r\n' +
  '4Is4yCwFaAVvIQ5uCS6ZIhMgtX+ECxsT5xtRK7CJJCa2BB48vhBA3/VF04XvJLd9\r\n' +
  'frgU/oSvWYKh3KauYrgsbrtUZ5vHYyVHa9T+qBnHP10iEi0q8pjyyjxP6DrX/UHK\r\n' +
  'z+A4/iZdeNdSKuvk0mdbY+08axFWsWQfPqXz6lur9VgZyPdbzrLdAIsSuyA4g+4s\r\n' +
  '/8WnbJDBT7OWCR1Z1JDstuqfw2/BeSgeS/hMiF2URF0GIBMSSm3qxmgX2NfLUlLx\r\n' +
  'irgbKguxXshCcOyBQRfsF3lR7op+gKw2LzmttJbbaM47gsX/rOOq89AMN9Rv8G3E\r\n' +
  'b2Wal9wbux47oPy+cHd0fkv5I7yrxeWf9ixdgcVctS52KsgqzWME1OR0tCKQYbnp\r\n' +
  'bHCuj8CBTy6BJh7L84djXTgFyDpgSBMKlv52nFdKvcdeiZwASOgAC+69GRPGjFvO\r\n' +
  'xrFT05K/lwWpB09gvazZqC+RdlBtDUQI7ONML1zAihz+xGJYWHomOwuIkX1m++so\r\n' +
  'DY0/8FBIOhw==\r\n' +
  '-----END CERTIFICATE-----\r\n';

// 根CA证书（PEM格式），作为信任锚
let rootCaCertData = '-----BEGIN CERTIFICATE-----\r\n' +
  'MIIFDDCCAvSgAwIBAgILBAAAAAABIVhTCKIwDQYJKoZIhvcNAQELBQAwTDEgMB4G\r\n' +
  'A1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjMxEzARBgNVBAoTCkdsb2JhbFNp\r\n' +
  'Z24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMDkwMzE4MTAwMDAwWhcNMjkwMzE4\r\n' +
  'MTAwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMzETMBEG\r\n' +
  'A1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZI\r\n' +
  'hvcNAQEBBQADggEPADCCAQoCggEBAMwldpB5BngiFvXAg7aEyiie/QV2EcWtiHL8\r\n' +
  'RgJDx7KKnQRfJMsuS+FggkbhUqsMgUdwbN1k0ev1LKMPgj0MK66X17YUhhB5uzsT\r\n' +
  'gHeMCOFJ0mpiLx9e+pZo34knlTifBtc+ycsmWQ1z3rDI6SYOgxXG71uL0gRgykmm\r\n' +
  'KPZpO/bLyCiR5Z2KYVc3rHQU3HTgOu5yLy6c+9C7v/U9AOEGM+iCK65TpjoWc4zd\r\n' +
  'QQ4gOsC0p6Hpsk+QLjJg6VfLuQSSaGjlOCZgdbKfd/+RFO+uIEn8rUAVSNECMWEZ\r\n' +
  'XriX7613t2Saer9fwRPvm2L7DWzgVGkWqQPabumDk3F2xmmFghcCAwEAAaNCMEAw\r\n' +
  'DgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFI/wS3+o\r\n' +
  'LkUkrk1Q+mOai97i3Ru8MA0GCSqGSIb3DQEBCwUAA4IBAQBLQNvAUKr+yAzv95ZU\r\n' +
  'RUm7lgAJQayzE4aGKAczymvmdLm6AC2upArT9fHxD4q/c2dKg8dEe3jgr25sbwMp\r\n' +
  'jjM5RcOO5LlXbKr8EpbsU8Yt5CRsuZRj+9xTaGdWPoO4zzUhw8lo/s7awlOqzJCK\r\n' +
  '6fBdRoyV3XpYKBovHd7NADdBj+1EbddTKJd+82cEHhXXipa0095MJ6RMG3NzdvQX\r\n' +
  'mcIfeg7jLQitChws/zyrVQ4PkX4268NXSb7hLi18YIvDQVETI53O9zJrlAGomecs\r\n' +
  'Mx86OyXShkDOOyyGeMlhLxS67ttVb9+E7gUJTb0o2HLO02JQZR7rkpeDMdmztcpH\r\n' +
  'WD9f\r\n' +
  '-----END CERTIFICATE-----\r\n';

async function validateCertChainWithCustomTrustAnchor(): Promise<void> {
  // 创建证书链校验器实例
  let validator = cert.createCertChainValidator('PKIX');

  // 创建终端实体证书对象
  let endEntityCert = await cert.createX509Cert({
    data: endEntityCertData,
    encodingFormat: cert.EncodingFormat.FORMAT_PEM
  });

  // 创建中间CA证书对象
  let intermediateCaCert = await cert.createX509Cert({
    data: intermediateCaCertData,
    encodingFormat: cert.EncodingFormat.FORMAT_PEM
  });

  // 创建根CA证书对象
  let rootCaCert = await cert.createX509Cert({
    data: rootCaCertData,
    encodingFormat: cert.EncodingFormat.FORMAT_PEM
  });

  // 构建校验参数
  let params: cert.X509CertValidatorParams = {
    // 不信任的中间证书，用于构建证书链
    untrustedCerts: [intermediateCaCert],
    // 信任锚证书，用于验证证书链
    trustedCerts: [rootCaCert],
    // 不信任系统预置CA证书
    trustSystemCa: false,
    // 不校验证书有效期（仅用于示例，实际场景建议开启）
    validateDate: false
  };

  try {
    // 校验证书链
    let result: cert.VerifyCertResult = await validator.validate(endEntityCert, params);
    // 校验成功，获取已校验的证书链
    console.info('validate success, certChain length: ' + result.certChain.length);
    for (let i = 0; i < result.certChain.length; i++) {
      let certSubject = result.certChain[i].getSubjectName();
      console.info('cert[' + i + '] subject: ' + certSubject);
    }
  } catch (err) {
    // 校验失败
    let error = err as BusinessError;
    console.error('validate failed, errCode: ' + error.code + ', errMsg: ' + error.message);
  }
}
```

## 场景二：信任系统预置CA证书

当应用需要验证互联网公开证书（如HTTPS网站证书）时，可以使用系统预置的CA证书作为信任锚。通过设置`trustSystemCa`为`true`，校验器会使用系统预置的CA证书库。

<!-- @[certificate_chain_validation_with_system_ca](https://gitcode.com/openharmony/applications_app_samples/blob/master/code/DocsSample/Security/DeviceCertificateKit/CertificateAlgorithmLibrary/entry/src/main/ets/pages/ValidateCertChainWithSystemCa.ets) -->

``` TypeScript
import { cert } from '@kit.DeviceCertificateKit';

// 待校验的终端实体证书（真实世界证书，PEM格式）
let endEntityCertData = '-----BEGIN CERTIFICATE-----\r\n' +
  'MIIIBDCCBuygAwIBAgIMIQ6D5jWg1xsz8IC1MA0GCSqGSIb3DQEBCwUAMFAxCzAJ\r\n' +
  'BgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSYwJAYDVQQDEx1H\r\n' +
  'bG9iYWxTaWduIFJTQSBPViBTU0wgQ0EgMjAxODAeFw0yNTA3MDIwNjM2MDNaFw0y\r\n' +
  'NjA4MDMwNjM2MDJaMIGGMQswCQYDVQQGEwJDTjEQMA4GA1UECBMHSmlhbmdzdTEQ\r\n' +
  'MA4GA1UEBxMHTmFuamluZzEvMC0GA1UEChMmSHVhd2VpIFNvZnR3YXJlIFRlY2hu\r\n' +
  'b2xvZ2llcyBDby4sIEx0ZC4xIjAgBgNVBAMTGWxvZ3NlcnZpY2UxLmRiYW5rY2xv\r\n' +
  'dWQuY24wggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQCOkSeHSJaUHsAh\r\n' +
  '9jHzar5MQnA6mKYJw7ho8Q9yrcx1K7qj49wl+a2zQ9v+CpXHnX7UfO2SiGvbS0w0\r\n' +
  '9zeckFwxj7NZJNH2+qFzutkNIaDq4k71e9VhrniISYA+a9Ej9LCacTf2p+J75Ks7\r\n' +
  'KyC7OynlFCrx9J6UmIkOiJBGMxxFbtuwyrmTxNS4l/RZQ3GWO1a/OL0sIEQIcnHj\r\n' +
  'd0mGIVUOpeJsx7kI100/W/Jy2n2WYbe/FSBOqhDvNhLtMe8wIzu71Ljo9QSCfVry\r\n' +
  'lucfI1TC60QTLP9smPqqKNnxZn7pDwp0DSMTECa/Qmxwui36+U2fwCSuBfbfAeOK\r\n' +
  'bhd+1Eq52Ki+eWRPeI6ACc6ai+C+RuYJgFysBphT+uOXCCL300zmUbzDkghicSsG\r\n' +
  'iRng24/MAokEMdi8PdIchax5wDWR9Ox3W8+RUACqAoC3wecDDJ+E/tYw/ro9QTWP\r\n' +
  'V9dXA6r3R7QaxB9fYqm7p3bbnlOrhBYmb0Jv+KPQ+qUePgOPDhMCAwEAAaOCBCUw\r\n' +
  'ggQhMA4GA1UdDwEB/wQEAwIFoDAMBgNVHRMBAf8EAjAAMIGOBggrBgEFBQcBAQSB\r\n' +
  'gTB/MEQGCCsGAQUFBzAChjhodHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24uY29tL2Nh\r\n' +
  'Y2VydC9nc3JzYW92c3NsY2EyMDE4LmNydDA3BggrBgEFBQcwAYYraHR0cDovL29j\r\n' +
  'c3AuZ2xvYmFsc2lnbi5jb20vZ3Nyc2FvdnNzbGNhMjAxODBWBgNVHSAETzBNMEEG\r\n' +
  'CSsGAQQBoDIBFDA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9iYWxzaWdu\r\n' +
  'LmNvbS9yZXBvc2l0b3J5LzAIBgZngQwBAgIwPwYDVR0fBDgwNjA0oDKgMIYuaHR0\r\n' +
  'cDovL2NybC5nbG9iYWxzaWduLmNvbS9nc3JzYW92c3NsY2EyMDE4LmNybDCB9QYD\r\n' +
  'VR0RBIHtMIHqghlsb2dzZXJ2aWNlMS5kYmFua2Nsb3VkLmNugg8qLmRiYW5rY2xv\r\n' +
  'dWQuY26CECouZGJhbmtjbG91ZC5jb22CDSouaGljbG91ZC5jb22CECouZHQuaGlj\r\n' +
  'bG91ZC5jb22CEiouY2xvdWQuaHVhd2VpLmNvbYIUKi50aGluZ3MuaGljbG91ZC5j\r\n' +
  'b22CFiouYnVnYm91bnR5Lmh1YXdlaS5jb22CDCouaHVhd2VpLmNvbYIWKi5kZXZl\r\n' +
  'bG9wZXIuaHVhd2VpLmNvbYIQKi5vcC5oaWNsb3VkLmNvbYIPKi5oYXJtb255b3Mu\r\n' +
  'Y29tMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAfBgNVHSMEGDAWgBT4\r\n' +
  '73/yzXhnqN5vjySNiPGHAwKz6zAdBgNVHQ4EFgQU/1F8htpS+aPKi25LCdrPMcDJ\r\n' +
  'vWAwggF+BgorBgEEAdZ5AgQCBIIBbgSCAWoBaAB1AMs49xWJfIShRF9bwd37yW7y\r\n' +
  'mlnNRwppBYWwyxTDFFjnAAABl8nZj5cAAAQDAEYwRAIgfPQurIKPP9QFyk+FvuM8\r\n' +
  'EDULQ0Y/+aswyXm1njl2+4gCIAmpcyQUItRca4DYe4NwlnflJeDP2OGuBfb4dtvN\r\n' +
  'OcgkAHcA2AlVO5RPev/IFhlvlE+Fq7D4/F6HVSYPFdEucrtFSxQAAAGXydmPoQAA\r\n' +
  'BAMASDBGAiEAwlFW3u9G/UnSV6zPgRDfOF95ty+PUmRwVfL6Gl7KQ5ICIQDlCJ5f\r\n' +
  '7luAEkbhT8T3VWTtOlzXY5OzJwMF3v4VcE1SGQB2AMIxfldFGaNF7n843rKQQevH\r\n' +
  'wiFaIr9/1bWtdprZDlLNAAABl8nZkQ4AAAQDAEcwRQIgcM0rZSzfxkxPeGlaepYP\r\n' +
  'vXxIe77WcKJOuX0BLVVsgrcCIQCgKvdD3zJ5ettx6eVkeKftShLwNa1jBzEoZRv4\r\n' +
  'aIGMmzANBgkqhkiG9w0BAQsFAAOCAQEAGj6foM35o54ujB2UUzQ4ZrGIeVtlYgYJ\r\n' +
  'oUDlWaiXzLwCEVdUsgIMQ81y6UXshMUbJoH2eNZXiEHYQDd1qcgui++GLIAID31+\r\n' +
  'iG0/gOhikhmNiGEfvTAsnaLVxwtb05W0IaBvG69xCTAHJuNfYNaPP7J1IzHYnDUk\r\n' +
  'mg72KkvF7kMXEzYgJ6EPiP7L+FJ1fIggu3fJVW9f3HjAEtMail9W7Ekn/kIzwjNs\r\n' +
  '8somwVMAvOSSc3nXejQieufpQlMZZB8YlMYMQalwoRea4h9CSvUBYz3CMxa9lyh0\r\n' +
  'RLvFpzNoUuYm6lZoStoySmr4hdk5QDMEVy+L5m24sqN7kHOgPnomSg==\r\n' +
  '-----END CERTIFICATE-----\r\n';

// 中间CA证书（PEM格式）- GlobalSign RSA OV SSL CA 2018
let intermediateCaCertData = '-----BEGIN CERTIFICATE-----\r\n' +
  'MIIETjCCAzagAwIBAgINAe5fIh38YjvUMzqFVzANBgkqhkiG9w0BAQsFADBMMSAw\r\n' +
  'HgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMzETMBEGA1UEChMKR2xvYmFs\r\n' +
  'U2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0xODExMjEwMDAwMDBaFw0yODEx\r\n' +
  'MjEwMDAwMDBaMFAxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52\r\n' +
  'LXNhMSYwJAYDVQQDEx1HbG9iYWxTaWduIFJTQSBPViBTU0wgQ0EgMjAxODCCASIw\r\n' +
  'DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKdaydUMGCEAI9WXD+uu3Vxoa2uP\r\n' +
  'UGATeoHLl+6OimGUSyZ59gSnKvuk2la77qCk8HuKf1UfR5NhDW5xUTolJAgvjOH3\r\n' +
  'idaSz6+zpz8w7bXfIa7+9UQX/dhj2S/TgVprX9NHsKzyqzskeU8fxy7quRU6fBhM\r\n' +
  'abO1IFkJXinDY+YuRluqlJBJDrnw9UqhCS98NE3QvADFBlV5Bs6i0BDxSEPouVq1\r\n' +
  'lVW9MdIbPYa+oewNEtssmSStR8JvA+Z6cLVwzM0nLKWMjsIYPJLJLnNvBhBWk0Cq\r\n' +
  'o8VS++XFBdZpaFwGue5RieGKDkFNm5KQConpFmvv73W+eka440eKHRwup08CAwEA\r\n' +
  'AaOCASkwggElMA4GA1UdDwEB/wQEAwIBhjASBgNVHRMBAf8ECDAGAQH/AgEAMB0G\r\n' +
  'A1UdDgQWBBT473/yzXhnqN5vjySNiPGHAwKz6zAfBgNVHSMEGDAWgBSP8Et/qC5F\r\n' +
  'JK5NUPpjmove4t0bvDA+BggrBgEFBQcBAQQyMDAwLgYIKwYBBQUHMAGGImh0dHA6\r\n' +
  'Ly9vY3NwMi5nbG9iYWxzaWduLmNvbS9yb290cjMwNgYDVR0fBC8wLTAroCmgJ4Yl\r\n' +
  'aHR0cDovL2NybC5nbG9iYWxzaWduLmNvbS9yb290LXIzLmNybDBHBgNVHSAEQDA+\r\n' +
  'MDwGBFUdIAAwNDAyBggrBgEFBQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFsc2lnbi5j\r\n' +
  'b20vcmVwb3NpdG9yeS8wDQYJKoZIhvcNAQELBQADggEBAJmQyC1fQorUC2bbmANz\r\n' +
  'EdSIhlIoU4r7rd/9c446ZwTbw1MUcBQJfMPg+NccmBqixD7b6QDjynCy8SIwIVbb\r\n' +
  '0615XoFYC20UgDX1b10d65pHBf9ZjQCxQNqQmJYaumxtf4z1s4DfjGRzNpZ5eWl0\r\n' +
  '6r/4ngGPoJVpjemEuunl1Ig423g7mNA2eymw0lIYkN5SQwCuaifIFJ6GlazhgDEw\r\n' +
  'fpolu4usBCOmmQDo8dIm7A9+O4orkjgTHY+GzYZSR+Y0fFukAj6KYXwidlNalFMz\r\n' +
  'hriSqHKvoflShx8xpfywgVcvzfTO3PYkz6fiNJBonf6q8amaEsybwMbDqKWwIX7e\r\n' +
  'SPY=\r\n' +
  '-----END CERTIFICATE-----\r\n';

async function validateCertChainWithSystemCa(): Promise<void> {
  // 创建证书链校验器实例
  let validator = cert.createCertChainValidator('PKIX');

  // 创建终端实体证书对象
  let endEntityCert = await cert.createX509Cert({
    data: endEntityCertData,
    encodingFormat: cert.EncodingFormat.FORMAT_PEM
  });

  // 创建中间CA证书对象
  let intermediateCaCert = await cert.createX509Cert({
    data: intermediateCaCertData,
    encodingFormat: cert.EncodingFormat.FORMAT_PEM
  });

  // 构建校验参数
  let params: cert.X509CertValidatorParams = {
    // 不信任的中间证书，用于构建证书链
    untrustedCerts: [intermediateCaCert],
    // 信任系统预置CA证书
    trustSystemCa: true,
    // 校验证书有效期
    validateDate: true
  };

  try {
    // 校验证书链
    let result: cert.VerifyCertResult = await validator.validate(endEntityCert, params);
    console.info('validate success, certChain length: ' + result.certChain.length);
  } catch (err) {
    let error = err as BusinessError;
    console.error('validate failed, errCode: ' + error.code + ', errMsg: ' + error.message);
  }
}
```

**说明**：
- `trustSystemCa`默认值为`false`，需要显式设置为`true`才能使用系统预置CA证书。
- 系统预置CA证书包括常见的根CA证书，如GlobalSign、DigiCert、Let's Encrypt等。

## 场景三：证书吊销校验

证书吊销校验用于验证证书是否被CA吊销。支持通过CRL（证书吊销列表）或OCSP（在线证书状态协议）进行吊销检查。

### 使用CRL进行吊销校验

<!-- @[certificate_chain_validation_with_crl](https://gitcode.com/openharmony/applications_app_samples/blob/master/code/DocsSample/Security/DeviceCertificateKit/CertificateAlgorithmLibrary/entry/src/main/ets/pages/ValidateCertChainWithCrl.ets) -->

``` TypeScript
import { cert } from '@kit.DeviceCertificateKit';

// 待校验的终端实体证书（OCSP测试证书链）
let endEntityCertData = '-----BEGIN CERTIFICATE-----\r\n' +
  'MIIDsDCCApigAwIBAgICEAIwDQYJKoZIhvcNAQELBQAwRDELMAkGA1UEBhMCVVMx\r\n' +
  'ETAPBgNVBAoMCFRlc3QgT3JnMSIwIAYDVQQDDBlPQ1NQIFRlc3QgSW50ZXJtZWRp\r\n' +
  'YXRlIENBMB4XDTI2MDMyNDA5MDIzMFoXDTQ2MDMxOTA5MDIzMFowNzELMAkGA1UE\r\n' +
  'BhMCVVMxETAPBgNVBAoMCFRlc3QgT3JnMRUwEwYDVQQDDAxPQ1NQIFRlc3QgRUUw\r\n' +
  'ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDA0Saa3vE7D/wpos+EwVuK\r\n' +
  'VQ6iW0h5xmFwBZqH+79JUxprHBXjH/jKXG8+czWV9hx480u7zpmK1qI7b3aGhsc1\r\n' +
  '7mpQ2AdUgN3645vz/XiZJ3ZNkTfSeE9PsWXNGS8sayAZZMr+vh4t2+/SsHP+JlDC\r\n' +
  'nHzLuc0VqJbeqIaEqI4+4J2KxMVPDdI+VRCXly3tIXRnaoSbppvOlKpRjybMD6DA\r\n' +
  '2mKaD/rI5jERE8hugeGGGLEATr0c7avd29dW0ol99mJqwSpqcFXW3ygwUrHRCu2R\r\n' +
  'gI/7yHZkoylJWK3IVcfmEn7J5eTYNq4F8kAUheR1kjmOAgSB1C4sVhy5s3+rkeYj\r\n' +
  'AgMBAAGjgbgwgbUwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0l\r\n' +
  'BBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMB0GA1UdDgQWBBQjy/R6QNihViaXf5u9\r\n' +
  'hQffQVcivDAfBgNVHSMEGDAWgBRrGWswj5l+jz+a55vU4zwiNgINZjA2BggrBgEF\r\n' +
  'BQcBAQQqMCgwJgYIKwYBBQUHMAGGGmh0dHA6Ly9sb2NhbGhvc3Q6OTk5OS9vY3Nw\r\n' +
  'MA0GCSqGSIb3DQEBCwUAA4IBAQCLigBe1flMn3EinNdHGh1V48pJ66SgGJeDDx2R\r\n' +
  '7uAZqM0ptx9XWTg2IAOX77R84bNWX0aFs2GRO3QkQPXdNJz5SB4VpW00WzMQuqOk\r\n' +
  'JkvDmpylmfV4q8mvjnppMBrFqqt0YtyLB7eloQ5gzlXHKZVSkkgr2A7c/XmlUt2v\r\n' +
  'uK+G7G6oyWwJh2lA6dKVTZ4gYMwukTmrddYD0mT7hGMZC2Oinxcl8YW7VtqvRclv\r\n' +
  'NWmXBEZrlN+Njv0V8RigrORT730J2ItaOX/9KBJqoakWB9vQ/Fmt/twJoiqeulVP\r\n' +
  'i8vPC6j4huKyYwvaw2qYqsBETmWUlHn/pzXdWEA2C55M6P0E\r\n' +
  '-----END CERTIFICATE-----\r\n';

// 中间CA证书（OCSP测试证书链）
let intermediateCaCertData = '-----BEGIN CERTIFICATE-----\r\n' +
  'MIIDYTCCAkmgAwIBAgIBAjANBgkqhkiG9w0BAQsFADA8MQswCQYDVQQGEwJVUzER\r\n' +
  'MA8GA1UECgwIVGVzdCBPcmcxGjAYBgNVBAMMEU9DU1AgVGVzdCBSb290IENBMB4X\r\n' +
  'DTI2MDMyNDA5MDIyOVoXDTQ2MDMxOTA5MDIyOVowRDELMAkGA1UEBhMCVVMxETAP\r\n' +
  'BgNVBAoMCFRlc3QgT3JnMSIwIAYDVQQDDBlPQ1NQIFRlc3QgSW50ZXJtZWRpYXRl\r\n' +
  'IENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlkEzThKS+GZqZaEW\r\n' +
  'G4rQ23hh1zatQnjUorKvT0J20EJCeuUrYLOLYFM5kjBdMcJJCr8/Q9vGa580h74+\r\n' +
  '0XfKQSFLzgSC53Lq1cPOtcixWkcj+PDCilXcoWiuq6C2gcj8onnWlv2v/d/g5CVb\r\n' +
  '1NZVmxabJP76WrcMVSy9wkrgruxLQlK6Kvaj7rFOAwiJqfUab6fVAGPtGhP20HvR\r\n' +
  'IFjL3SP5+gg1LaysrzhEn7MwNqKglzq3NvZweepqs/X910BaCo4cf32Xlf7NLxcn\r\n' +
  '6kzAM159IFxi7a4K0JatrzHtkFnRcPni+hQOPaK/69VpmkbWm+ZbsX7E9IOEpnFy\r\n' +
  'zX/T1wIDAQABo2YwZDASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIB\r\n' +
  'BjAdBgNVHQ4EFgQUaxlrMI+Zfo8/mueb1OM8IjYCDWYwHwYDVR0jBBgwFoAUfnnj\r\n' +
  'Z8meT6+b9DzYmmH9GjKwuBEwDQYJKoZIhvcNAQELBQADggEBAFkpBWKCGCumsavn\r\n' +
  'rB+QHDRvMjadsVkbATfIfJaagBGL7OyKzydr351us21K8pWfK2yN6mbxHXxt34SF\r\n' +
  'h/Ujke+PlRHFQELHTGwNWxbMQkNEpmFNNFr4tM9TgtQrtWFIDnPImtNc68EREgMe\r\n' +
  'cXm+ttgPbAGY/55XQss7BfWcqzn5iYz4kDtdMIdbanVdVzwq+hVPxF8I4BX7KBdA\r\n' +
  'ScmZzQt1N02IgMZmoRp0NKTHoXpWXAn/1q6lKQPzJoUD+D3RTpzKRNTsWy0Zayqr\r\n' +
  'TNPPfYkeNkd+usSWnOTJkS1qMMS0v0Hul2WoqMRQzX2EQrkCeGwMSjWrIhrZLm2s\r\n' +
  'YCUkPVM=\r\n' +
  '-----END CERTIFICATE-----\r\n';

// 根CA证书（OCSP测试证书链）
let rootCaCertData = '-----BEGIN CERTIFICATE-----\r\n' +
  'MIIDRjCCAi6gAwIBAgIBATANBgkqhkiG9w0BAQsFADA8MQswCQYDVQQGEwJVUzER\r\n' +
  'MA8GA1UECgwIVGVzdCBPcmcxGjAYBgNVBAMMEU9DU1AgVGVzdCBSb290IENBMB4X\r\n' +
  'DTI2MDMyNDA5MDIyOVoXDTQ2MDMxOTA5MDIyOVowPDELMAkGA1UEBhMCVVMxETAP\r\n' +
  'BgNVBAoMCFRlc3QgT3JnMRowGAYDVQQDDBFPQ1NQIFRlc3QgUm9vdCBDQTCCASIw\r\n' +
  'DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJfQ+HiqrZArX11Ey6/wR1tRjG8Y\r\n' +
  'XCOQoty2mKhU8s76Ue9PfTMW+vXsMjU7snS+kULL5DvTszd3HjAaH5FZ8z9rklOl\r\n' +
  '2hE1C2sM7IQXYQuvRbfu1TqWgzWu1daRKHvfCeedd11Vr1/DdJY29U69wqXCUwAw\r\n' +
  'Fg/+nmKwWyE3GjEtTTbKpHgNJoSA2q07VTx8MTbgQUHGCEecGo+wNjA9Jks3aPZY\r\n' +
  'zesK75HceXbpY7Yl4fWM8o93VBayDFocbq6dLBGb8+X03S+e02lQNms65fkFPLrB\r\n' +
  'ehxdZxzu7mOpp3PKj7rTB5JJzYFF8XeCBLdIGrE0ZoG/RA4IfXD0ACDdxIUCAwEA\r\n' +
  'AaNTMFEwHQYDVR0OBBYEFH5542fJnk+vm/Q82Jph/RoysLgRMB8GA1UdIwQYMBaA\r\n' +
  'FH5542fJnk+vm/Q82Jph/RoysLgRMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcN\r\n' +
  'AQELBQADggEBAD24n5P7M+ZqYvF3H46/nJq9NOBF5JEdPnsO9S52B8WvxhjuVEZM\r\n' +
  'M6ebQchw5uhvbi30KoFnLLMQuDbgvXzWJCbOh8pLKo2HcVA12PnwdzyVUKOnVVo/\r\n' +
  '47t9ByCvRxBIS80nOkGuOoyjo4tMY2Sml0zH4mGO6n5geYYixg4w5GgdJcPs+Xz/\r\n' +
  'U7qlB6SLtB5ZamvQU0wZWI1g8ic6OrWxQOCM6pY4x38tgfEVIO8Jh4e6M7db6c9o\r\n' +
  'hOBR9EBXT9bBT+kXIQvTQLS33GMcjb/pnX8M0SRlcDDqlViovDm3sRlAkpSPYdF2\r\n' +
  '2a+m5c7rZ/HZSfvbHvgBw5j+t7mOcwPmSnw=\r\n' +
  '-----END CERTIFICATE-----\r\n';

// CRL数据（PEM格式）- 示例格式，实际CRL需从CA获取
let crlData = '-----BEGIN X509 CRL-----\r\n' +
  'MIIBXzCCAkegAwIBAgILBAAAAAABIVhTCKIwDQYJKoZIhvcNAQELBQAwTDEgMB4G\r\n' +
  'A1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjMxEzARBgNVBAoTCkdsb2JhbFNp\r\n' +
  'Z24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMDkwMzE4MTAwMDAwWhcNMjkwMzE4\r\n' +
  'MTAwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMzETMBEG\r\n' +
  'A1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZI\r\n' +
  'hvcNAQEBBQADggEPADCCAQoCggEBAMwldpB5BngiFvXAg7aEyiie/QV2EcWtiHL8\r\n' +
  'RgJDx7KKnQRfJMsuS+FggkbhUqsMgUdwbN1k0ev1LKMPgj0MK66X17YUhhB5uzsT\r\n' +
  '-----END X509 CRL-----\r\n';

async function validateCertChainWithCrl(): Promise<void> {
  // 创建证书链校验器实例
  let validator = cert.createCertChainValidator('PKIX');

  // 创建证书对象
  let endEntityCert = await cert.createX509Cert({
    data: endEntityCertData,
    encodingFormat: cert.EncodingFormat.FORMAT_PEM
  });
  let intermediateCaCert = await cert.createX509Cert({
    data: intermediateCaCertData,
    encodingFormat: cert.EncodingFormat.FORMAT_PEM
  });
  let rootCaCert = await cert.createX509Cert({
    data: rootCaCertData,
    encodingFormat: cert.EncodingFormat.FORMAT_PEM
  });

  // 创建CRL对象
  let crl = await cert.createX509CRL({
    data: crlData,
    encodingFormat: cert.EncodingFormat.FORMAT_PEM
  });

  // 构建吊销校验参数
  let revokedParams: cert.X509CertRevokedParams = {
    // 启用CRL检查
    revocationFlags: [cert.CertRevocationFlag.CERT_REVOCATION_CRL_CHECK],
    // 提供CRL列表
    crls: [crl]
  };

  // 构建校验参数
  let params: cert.X509CertValidatorParams = {
    untrustedCerts: [intermediateCaCert],
    trustedCerts: [rootCaCert],
    trustSystemCa: false,
    validateDate: true,
    // 设置吊销校验参数
    revokedParams: revokedParams
  };

  try {
    let result: cert.VerifyCertResult = await validator.validate(endEntityCert, params);
    console.info('validate success, certChain length: ' + result.certChain.length);
  } catch (err) {
    let error = err as BusinessError;
    if (error.code === cert.CertResult.ERR_CERT_HAS_REVOKED) {
      console.error('certificate has been revoked');
    } else {
      console.error('validate failed, errCode: ' + error.code + ', errMsg: ' + error.message);
    }
  }
}
```

### 使用OCSP进行吊销校验

``` TypeScript
import { cert } from '@kit.DeviceCertificateKit';

// OCSP测试终端实体证书（PEM格式）
let endEntityCertData = '-----BEGIN CERTIFICATE-----\r\n' +
  'MIIDsDCCApigAwIBAgICEAIwDQYJKoZIhvcNAQELBQAwRDELMAkGA1UEBhMCVVMx\r\n' +
  'ETAPBgNVBAoMCFRlc3QgT3JnMSIwIAYDVQQDDBlPQ1NQIFRlc3QgSW50ZXJtZWRp\r\n' +
  'YXRlIENBMB4XDTI2MDMyNDA5MDIzMFoXDTQ2MDMxOTA5MDIzMFowNzELMAkGA1UE\r\n' +
  'BhMCVVMxETAPBgNVBAoMCFRlc3QgT3JnMRUwEwYDVQQDDAxPQ1NQIFRlc3QgRUUw\r\n' +
  'ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDA0Saa3vE7D/wpos+EwVuK\r\n' +
  'VQ6iW0h5xmFwBZqH+79JUxprHBXjH/jKXG8+czWV9hx480u7zpmK1qI7b3aGhsc1\r\n' +
  '7mpQ2AdUgN3645vz/XiZJ3ZNkTfSeE9PsWXNGS8sayAZZMr+vh4t2+/SsHP+JlDC\r\n' +
  'nHzLuc0VqJbeqIaEqI4+4J2KxMVPDdI+VRCXly3tIXRnaoSbppvOlKpRjybMD6DA\r\n' +
  '2mKaD/rI5jERE8hugeGGGLEATr0c7avd29dW0ol99mJqwSpqcFXW3ygwUrHRCu2R\r\n' +
  'gI/7yHZkoylJWK3IVcfmEn7J5eTYNq4F8kAUheR1kjmOAgSB1C4sVhy5s3+rkeYj\r\n' +
  'AgMBAAGjgbgwgbUwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0l\r\n' +
  'BBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMB0GA1UdDgQWBBQjy/R6QNihViaXf5u9\r\n' +
  'hQffQVcivDAfBgNVHSMEGDAWgBRrGWswj5l+jz+a55vU4zwiNgINZjA2BggrBgEF\r\n' +
  'BQcBAQQqMCgwJgYIKwYBBQUHMAGGGmh0dHA6Ly9sb2NhbGhvc3Q6OTk5OS9vY3Nw\r\n' +
  'MA0GCSqGSIb3DQEBCwUAA4IBAQCLigBe1flMn3EinNdHGh1V48pJ66SgGJeDDx2R\r\n' +
  '7uAZqM0ptx9XWTg2IAOX77R84bNWX0aFs2GRO3QkQPXdNJz5SB4VpW00WzMQuqOk\r\n' +
  'JkvDmpylmfV4q8mvjnppMBrFqqt0YtyLB7eloQ5gzlXHKZVSkkgr2A7c/XmlUt2v\r\n' +
  'uK+G7G6oyWwJh2lA6dKVTZ4gYMwukTmrddYD0mT7hGMZC2Oinxcl8YW7VtqvRclv\r\n' +
  'NWmXBEZrlN+Njv0V8RigrORT730J2ItaOX/9KBJqoakWB9vQ/Fmt/twJoiqeulVP\r\n' +
  'i8vPC6j4huKyYwvaw2qYqsBETmWUlHn/pzXdWEA2C55M6P0E\r\n' +
  '-----END CERTIFICATE-----\r\n';

// OCSP测试中间CA证书（PEM格式）
let intermediateCaCertData = '-----BEGIN CERTIFICATE-----\r\n' +
  'MIIDYTCCAkmgAwIBAgIBAjANBgkqhkiG9w0BAQsFADA8MQswCQYDVQQGEwJVUzER\r\n' +
  'MA8GA1UECgwIVGVzdCBPcmcxGjAYBgNVBAMMEU9DU1AgVGVzdCBSb290IENBMB4X\r\n' +
  'DTI2MDMyNDA5MDIyOVoXDTQ2MDMxOTA5MDIyOVowRDELMAkGA1UEBhMCVVMxETAP\r\n' +
  'BgNVBAoMCFRlc3QgT3JnMSIwIAYDVQQDDBlPQ1NQIFRlc3QgSW50ZXJtZWRpYXRl\r\n' +
  'IENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlkEzThKS+GZqZaEW\r\n' +
  'G4rQ23hh1zatQnjUorKvT0J20EJCeuUrYLOLYFM5kjBdMcJJCr8/Q9vGa580h74+\r\n' +
  '0XfKQSFLzgSC53Lq1cPOtcixWkcj+PDCilXcoWiuq6C2gcj8onnWlv2v/d/g5CVb\r\n' +
  '1NZVmxabJP76WrcMVSy9wkrgruxLQlK6Kvaj7rFOAwiJqfUab6fVAGPtGhP20HvR\r\n' +
  'IFjL3SP5+gg1LaysrzhEn7MwNqKglzq3NvZweepqs/X910BaCo4cf32Xlf7NLxcn\r\n' +
  '6kzAM159IFxi7a4K0JatrzHtkFnRcPni+hQOPaK/69VpmkbWm+ZbsX7E9IOEpnFy\r\n' +
  'zX/T1wIDAQABo2YwZDASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIB\r\n' +
  'BjAdBgNVHQ4EFgQUaxlrMI+Zfo8/mueb1OM8IjYCDWYwHwYDVR0jBBgwFoAUfnnj\r\n' +
  'Z8meT6+b9DzYmmH9GjKwuBEwDQYJKoZIhvcNAQELBQADggEBAFkpBWKCGCumsavn\r\n' +
  'rB+QHDRvMjadsVkbATfIfJaagBGL7OyKzydr351us21K8pWfK2yN6mbxHXxt34SF\r\n' +
  'h/Ujke+PlRHFQELHTGwNWxbMQkNEpmFNNFr4tM9TgtQrtWFIDnPImtNc68EREgMe\r\n' +
  'cXm+ttgPbAGY/55XQss7BfWcqzn5iYz4kDtdMIdbanVdVzwq+hVPxF8I4BX7KBdA\r\n' +
  'ScmZzQt1N02IgMZmoRp0NKTHoXpWXAn/1q6lKQPzJoUD+D3RTpzKRNTsWy0Zayqr\r\n' +
  'TNPPfYkeNkd+usSWnOTJkS1qMMS0v0Hul2WoqMRQzX2EQrkCeGwMSjWrIhrZLm2s\r\n' +
  'YCUkPVM=\r\n' +
  '-----END CERTIFICATE-----\r\n';

// OCSP测试根CA证书（PEM格式）
let rootCaCertData = '-----BEGIN CERTIFICATE-----\r\n' +
  'MIIDRjCCAi6gAwIBAgIBATANBgkqhkiG9w0BAQsFADA8MQswCQYDVQQGEwJVUzER\r\n' +
  'MA8GA1UECgwIVGVzdCBPcmcxGjAYBgNVBAMMEU9DU1AgVGVzdCBSb290IENBMB4X\r\n' +
  'DTI2MDMyNDA5MDIyOVoXDTQ2MDMxOTA5MDIyOVowPDELMAkGA1UEBhMCVVMxETAP\r\n' +
  'BgNVBAoMCFRlc3QgT3JnMRowGAYDVQQDDBFPQ1NQIFRlc3QgUm9vdCBDQTCCASIw\r\n' +
  'DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJfQ+HiqrZArX11Ey6/wR1tRjG8Y\r\n' +
  'XCOQoty2mKhU8s76Ue9PfTMW+vXsMjU7snS+kULL5DvTszd3HjAaH5FZ8z9rklOl\r\n' +
  '2hE1C2sM7IQXYQuvRbfu1TqWgzWu1daRKHvfCeedd11Vr1/DdJY29U69wqXCUwAw\r\n' +
  'Fg/+nmKwWyE3GjEtTTbKpHgNJoSA2q07VTx8MTbgQUHGCEecGo+wNjA9Jks3aPZY\r\n' +
  'zesK75HceXbpY7Yl4fWM8o93VBayDFocbq6dLBGb8+X03S+e02lQNms65fkFPLrB\r\n' +
  'ehxdZxzu7mOpp3PKj7rTB5JJzYFF8XeCBLdIGrE0ZoG/RA4IfXD0ACDdxIUCAwEA\r\n' +
  'AaNTMFEwHQYDVR0OBBYEFH5542fJnk+vm/Q82Jph/RoysLgRMB8GA1UdIwQYMBaA\r\n' +
  'FH5542fJnk+vm/Q82Jph/RoysLgRMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcN\r\n' +
  'AQELBQADggEBAD24n5P7M+ZqYvF3H46/nJq9NOBF5JEdPnsO9S52B8WvxhjuVEZM\r\n' +
  'M6ebQchw5uhvbi30KoFnLLMQuDbgvXzWJCbOh8pLKo2HcVA12PnwdzyVUKOnVVo/\r\n' +
  '47t9ByCvRxBIS80nOkGuOoyjo4tMY2Sml0zH4mGO6n5geYYixg4w5GgdJcPs+Xz/\r\n' +
  'U7qlB6SLtB5ZamvQU0wZWI1g8ic6OrWxQOCM6pY4x38tgfEVIO8Jh4e6M7db6c9o\r\n' +
  'hOBR9EBXT9bBT+kXIQvTQLS33GMcjb/pnX8M0SRlcDDqlViovDm3sRlAkpSPYdF2\r\n' +
  '2a+m5c7rZ/HZSfvbHvgBw5j+t7mOcwPmSnw=\r\n' +
  '-----END CERTIFICATE-----\r\n';

async function validateCertChainWithOcsp(): Promise<void> {
  let validator = cert.createCertChainValidator('PKIX');

  // 创建证书对象
  let endEntityCert = await cert.createX509Cert({
    data: endEntityCertData,
    encodingFormat: cert.EncodingFormat.FORMAT_PEM
  });
  let intermediateCaCert = await cert.createX509Cert({
    data: intermediateCaCertData,
    encodingFormat: cert.EncodingFormat.FORMAT_PEM
  });
  let rootCaCert = await cert.createX509Cert({
    data: rootCaCertData,
    encodingFormat: cert.EncodingFormat.FORMAT_PEM
  });

  // 构建吊销校验参数
  let revokedParams: cert.X509CertRevokedParams = {
    // 启用OCSP检查
    revocationFlags: [cert.CertRevocationFlag.CERT_REVOCATION_OCSP_CHECK],
    // 允许在线OCSP检查
    allowOcspCheckOnline: true
  };

  let params: cert.X509CertValidatorParams = {
    untrustedCerts: [intermediateCaCert],
    trustedCerts: [rootCaCert],
    trustSystemCa: false,
    validateDate: true,
    revokedParams: revokedParams
  };

  try {
    let result: cert.VerifyCertResult = await validator.validate(endEntityCert, params);
    console.info('validate success');
  } catch (err) {
    let error = err as BusinessError;
    console.error('validate failed, errCode: ' + error.code);
  }
}
```

### CRL和OCSP组合校验

当需要更可靠的吊销检查时，可以同时启用CRL和OCSP，并配置回退策略：

``` TypeScript
import { cert } from '@kit.DeviceCertificateKit';

// OCSP测试终端实体证书（PEM格式）
let endEntityCertData = '-----BEGIN CERTIFICATE-----\r\n' +
  'MIIDsDCCApigAwIBAgICEAIwDQYJKoZIhvcNAQELBQAwRDELMAkGA1UEBhMCVVMx\r\n' +
  'ETAPBgNVBAoMCFRlc3QgT3JnMSIwIAYDVQQDDBlPQ1NQIFRlc3QgSW50ZXJtZWRp\r\n' +
  'YXRlIENBMB4XDTI2MDMyNDA5MDIzMFoXDTQ2MDMxOTA5MDIzMFowNzELMAkGA1UE\r\n' +
  'BhMCVVMxETAPBgNVBAoMCFRlc3QgT3JnMRUwEwYDVQQDDAxPQ1NQIFRlc3QgRUUw\r\n' +
  'ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDA0Saa3vE7D/wpos+EwVuK\r\n' +
  'VQ6iW0h5xmFwBZqH+79JUxprHBXjH/jKXG8+czWV9hx480u7zpmK1qI7b3aGhsc1\r\n' +
  '7mpQ2AdUgN3645vz/XiZJ3ZNkTfSeE9PsWXNGS8sayAZZMr+vh4t2+/SsHP+JlDC\r\n' +
  'nHzLuc0VqJbeqIaEqI4+4J2KxMVPDdI+VRCXly3tIXRnaoSbppvOlKpRjybMD6DA\r\n' +
  '2mKaD/rI5jERE8hugeGGGLEATr0c7avd29dW0ol99mJqwSpqcFXW3ygwUrHRCu2R\r\n' +
  'gI/7yHZkoylJWK3IVcfmEn7J5eTYNq4F8kAUheR1kjmOAgSB1C4sVhy5s3+rkeYj\r\n' +
  'AgMBAAGjgbgwgbUwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0l\r\n' +
  'BBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMB0GA1UdDgQWBBQjy/R6QNihViaXf5u9\r\n' +
  'hQffQVcivDAfBgNVHSMEGDAWgBRrGWswj5l+jz+a55vU4zwiNgINZjA2BggrBgEF\r\n' +
  'BQcBAQQqMCgwJgYIKwYBBQUHMAGGGmh0dHA6Ly9sb2NhbGhvc3Q6OTk5OS9vY3Nw\r\n' +
  'MA0GCSqGSIb3DQEBCwUAA4IBAQCLigBe1flMn3EinNdHGh1V48pJ66SgGJeDDx2R\r\n' +
  '7uAZqM0ptx9XWTg2IAOX77R84bNWX0aFs2GRO3QkQPXdNJz5SB4VpW00WzMQuqOk\r\n' +
  'JkvDmpylmfV4q8mvjnppMBrFqqt0YtyLB7eloQ5gzlXHKZVSkkgr2A7c/XmlUt2v\r\n' +
  'uK+G7G6oyWwJh2lA6dKVTZ4gYMwukTmrddYD0mT7hGMZC2Oinxcl8YW7VtqvRclv\r\n' +
  'NWmXBEZrlN+Njv0V8RigrORT730J2ItaOX/9KBJqoakWB9vQ/Fmt/twJoiqeulVP\r\n' +
  'i8vPC6j4huKyYwvaw2qYqsBETmWUlHn/pzXdWEA2C55M6P0E\r\n' +
  '-----END CERTIFICATE-----\r\n';

// OCSP测试中间CA证书（PEM格式）
let intermediateCaCertData = '-----BEGIN CERTIFICATE-----\r\n' +
  'MIIDYTCCAkmgAwIBAgIBAjANBgkqhkiG9w0BAQsFADA8MQswCQYDVQQGEwJVUzER\r\n' +
  'MA8GA1UECgwIVGVzdCBPcmcxGjAYBgNVBAMMEU9DU1AgVGVzdCBSb290IENBMB4X\r\n' +
  'DTI2MDMyNDA5MDIyOVoXDTQ2MDMxOTA5MDIyOVowRDELMAkGA1UEBhMCVVMxETAP\r\n' +
  'BgNVBAoMCFRlc3QgT3JnMSIwIAYDVQQDDBlPQ1NQIFRlc3QgSW50ZXJtZWRpYXRl\r\n' +
  'IENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlkEzThKS+GZqZaEW\r\n' +
  'G4rQ23hh1zatQnjUorKvT0J20EJCeuUrYLOLYFM5kjBdMcJJCr8/Q9vGa580h74+\r\n' +
  '0XfKQSFLzgSC53Lq1cPOtcixWkcj+PDCilXcoWiuq6C2gcj8onnWlv2v/d/g5CVb\r\n' +
  '1NZVmxabJP76WrcMVSy9wkrgruxLQlK6Kvaj7rFOAwiJqfUab6fVAGPtGhP20HvR\r\n' +
  'IFjL3SP5+gg1LaysrzhEn7MwNqKglzq3NvZweepqs/X910BaCo4cf32Xlf7NLxcn\r\n' +
  '6kzAM159IFxi7a4K0JatrzHtkFnRcPni+hQOPaK/69VpmkbWm+ZbsX7E9IOEpnFy\r\n' +
  'zX/T1wIDAQABo2YwZDASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIB\r\n' +
  'BjAdBgNVHQ4EFgQUaxlrMI+Zfo8/mueb1OM8IjYCDWYwHwYDVR0jBBgwFoAUfnnj\r\n' +
  'Z8meT6+b9DzYmmH9GjKwuBEwDQYJKoZIhvcNAQELBQADggEBAFkpBWKCGCumsavn\r\n' +
  'rB+QHDRvMjadsVkbATfIfJaagBGL7OyKzydr351us21K8pWfK2yN6mbxHXxt34SF\r\n' +
  'h/Ujke+PlRHFQELHTGwNWxbMQkNEpmFNNFr4tM9TgtQrtWFIDnPImtNc68EREgMe\r\n' +
  'cXm+ttgPbAGY/55XQss7BfWcqzn5iYz4kDtdMIdbanVdVzwq+hVPxF8I4BX7KBdA\r\n' +
  'ScmZzQt1N02IgMZmoRp0NKTHoXpWXAn/1q6lKQPzJoUD+D3RTpzKRNTsWy0Zayqr\r\n' +
  'TNPPfYkeNkd+usSWnOTJkS1qMMS0v0Hul2WoqMRQzX2EQrkCeGwMSjWrIhrZLm2s\r\n' +
  'YCUkPVM=\r\n' +
  '-----END CERTIFICATE-----\r\n';

// OCSP测试根CA证书（PEM格式）
let rootCaCertData = '-----BEGIN CERTIFICATE-----\r\n' +
  'MIIDRjCCAi6gAwIBAgIBATANBgkqhkiG9w0BAQsFADA8MQswCQYDVQQGEwJVUzER\r\n' +
  'MA8GA1UECgwIVGVzdCBPcmcxGjAYBgNVBAMMEU9DU1AgVGVzdCBSb290IENBMB4X\r\n' +
  'DTI2MDMyNDA5MDIyOVoXDTQ2MDMxOTA5MDIyOVowPDELMAkGA1UEBhMCVVMxETAP\r\n' +
  'BgNVBAoMCFRlc3QgT3JnMRowGAYDVQQDDBFPQ1NQIFRlc3QgUm9vdCBDQTCCASIw\r\n' +
  'DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJfQ+HiqrZArX11Ey6/wR1tRjG8Y\r\n' +
  'XCOQoty2mKhU8s76Ue9PfTMW+vXsMjU7snS+kULL5DvTszd3HjAaH5FZ8z9rklOl\r\n' +
  '2hE1C2sM7IQXYQuvRbfu1TqWgzWu1daRKHvfCeedd11Vr1/DdJY29U69wqXCUwAw\r\n' +
  'Fg/+nmKwWyE3GjEtTTbKpHgNJoSA2q07VTx8MTbgQUHGCEecGo+wNjA9Jks3aPZY\r\n' +
  'zesK75HceXbpY7Yl4fWM8o93VBayDFocbq6dLBGb8+X03S+e02lQNms65fkFPLrB\r\n' +
  'ehxdZxzu7mOpp3PKj7rTB5JJzYFF8XeCBLdIGrE0ZoG/RA4IfXD0ACDdxIUCAwEA\r\n' +
  'AaNTMFEwHQYDVR0OBBYEFH5542fJnk+vm/Q82Jph/RoysLgRMB8GA1UdIwQYMBaA\r\n' +
  'FH5542fJnk+vm/Q82Jph/RoysLgRMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcN\r\n' +
  'AQELBQADggEBAD24n5P7M+ZqYvF3H46/nJq9NOBF5JEdPnsO9S52B8WvxhjuVEZM\r\n' +
  'M6ebQchw5uhvbi30KoFnLLMQuDbgvXzWJCbOh8pLKo2HcVA12PnwdzyVUKOnVVo/\r\n' +
  '47t9ByCvRxBIS80nOkGuOoyjo4tMY2Sml0zH4mGO6n5geYYixg4w5GgdJcPs+Xz/\r\n' +
  'U7qlB6SLtB5ZamvQU0wZWI1g8ic6OrWxQOCM6pY4x38tgfEVIO8Jh4e6M7db6c9o\r\n' +
  'hOBR9EBXT9bBT+kXIQvTQLS33GMcjb/pnX8M0SRlcDDqlViovDm3sRlAkpSPYdF2\r\n' +
  '2a+m5c7rZ/HZSfvbHvgBw5j+t7mOcwPmSnw=\r\n' +
  '-----END CERTIFICATE-----\r\n';

async function validateCertChainWithCrlAndOcsp(): Promise<void> {
  let validator = cert.createCertChainValidator('PKIX');

  // 创建证书对象
  let endEntityCert = await cert.createX509Cert({
    data: endEntityCertData,
    encodingFormat: cert.EncodingFormat.FORMAT_PEM
  });
  let intermediateCaCert = await cert.createX509Cert({
    data: intermediateCaCertData,
    encodingFormat: cert.EncodingFormat.FORMAT_PEM
  });
  let rootCaCert = await cert.createX509Cert({
    data: rootCaCertData,
    encodingFormat: cert.EncodingFormat.FORMAT_PEM
  });

  // 构建吊销校验参数：同时启用CRL和OCSP，优先OCSP
  let revokedParams: cert.X509CertRevokedParams = {
    revocationFlags: [
      cert.CertRevocationFlag.CERT_REVOCATION_PREFER_OCSP,  // 优先OCSP
      cert.CertRevocationFlag.CERT_REVOCATION_CRL_CHECK,    // 启用CRL
      cert.CertRevocationFlag.CERT_REVOCATION_OCSP_CHECK,   // 启用OCSP
      cert.CertRevocationFlag.CERT_REVOCATION_CHECK_ALL_CERT // 检查所有证书
    ],
    allowDownloadCrl: true,        // 允许下载CRL
    allowOcspCheckOnline: true     // 允许在线OCSP检查
  };

  let params: cert.X509CertValidatorParams = {
    untrustedCerts: [intermediateCaCert],
    trustedCerts: [rootCaCert],
    trustSystemCa: false,
    validateDate: true,
    revokedParams: revokedParams
  };

  try {
    let result: cert.VerifyCertResult = await validator.validate(endEntityCert, params);
    console.info('validate success');
  } catch (err) {
    let error = err as BusinessError;
    console.error('validate failed, errCode: ' + error.code);
  }
}
```

**说明**：
- 同时启用CRL和OCSP时，设置PREFER_OCSP可优先使用OCSP检查。
- 未找到OCSP响应或网络超时时，会自动回退到CRL检查。
- 证书确实被吊销时，不会回退，直接返回错误。

## 场景四：国密证书链校验

国密（SM2/SM3/SM4）算法是中国自主研发的密码算法体系。校验SM2证书时，需要设置`userId`参数。

<!-- @[certificate_chain_validation_for_sm2](https://gitcode.com/openharmony/applications_app_samples/blob/master/code/DocsSample/Security/DeviceCertificateKit/CertificateAlgorithmLibrary/entry/src/main/ets/pages/ValidateSm2CertChain.ets) -->

``` TypeScript
import { cert } from '@kit.DeviceCertificateKit';

// SM2终端实体证书（PEM格式）
let sm2EndEntityCertData = '-----BEGIN CERTIFICATE-----\r\n' +
  'MIICETCCAbegAwIBAgIBAjAKBggqgRzPVQGDdTBiMQswCQYDVQQGEwJYWDELMAkG\r\n' +
  'A1UECAwCWFgxFDASBgNVBAoMC2NlcnRpZmljYXRlMQ8wDQYDVQQLDAZ0ZXN0aW4x\r\n' +
  'HzAdBgNVBAMMFmNlcnRpZmljYXRlLnRlc3Rpbi5jb20wHhcNMjQwNTIyMDcwMDA2\r\n' +
  'WhcNMzQwNTIwMDcwMDA2WjBmMQswCQYDVQQGEwJYWDELMAkGA1UECAwCWFgxFDAS\r\n' +
  'BgNVBAoMC2NlcnRpZmljYXRlMREwDwYDVQQLDAh0ZXN0c2lnbjEhMB8GA1UEAwwY\r\n' +
  'Y2VydGlmaWNhdGUudGVzdHNpZ24uY29tMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0D\r\n' +
  'QgAEyp/bWrol7RGQaQfSaMgRQGgSBNV8Pu6M6Jl7jYLNlXMQ3Nbc3rU36f7teirK\r\n' +
  'y22ymVlhWnTQOC73AP+uMZp3rqNaMFgwCQYDVR0TBAIwADALBgNVHQ8EBAMCBsAw\r\n' +
  'HQYDVR0OBBYEFA7RZ1QXVll8KuvBR6hmNnldJgAPMB8GA1UdIwQYMBaAFLF6vKQB\r\n' +
  '1DF442gd6o7bN6Yv9u06MAoGCCqBHM9VAYN1A0gAMEUCIQCh+dr3D4bWWZP8M3nJ\r\n' +
  'eqzfKKt2YIsE7YhO3/PVTAhhPwIgarpo3xJ9OlGLgzH/Xl094Jc9rpOtJ/a2fgbw\r\n' +
  'QM9Qpfg=\r\n' +
  '-----END CERTIFICATE-----\r\n';

// SM2中间CA证书（PEM格式）
let sm2IntermediateCaCertData = '-----BEGIN CERTIFICATE-----\r\n' +
  'MIICHjCCAcOgAwIBAgIBATAKBggqgRzPVQGDdTBvMQswCQYDVQQGEwJYWDELMAkG\r\n' +
  'A1UECAwCWFgxCzAJBgNVBAcMAlhYMRQwEgYDVQQKDAtjZXJ0aWZpY2F0ZTEPMA0G\r\n' +
  'A1UECwwGdGVzdGNhMR8wHQYDVQQDDBZjZXJ0aWZpY2F0ZS50ZXN0Y2EuY29tMB4X\r\n' +
  'DTI0MDUyMjA3MDAwNloXDTM0MDUyMDA3MDAwNlowYjELMAkGA1UEBhMCWFgxCzAJ\r\n' +
  'BgNVBAgMAlhYMRQwEgYDVQQKDAtjZXJ0aWZpY2F0ZTEPMA0GA1UECwwGdGVzdGlu\r\n' +
  'MR8wHQYDVQQDDBZjZXJ0aWZpY2F0ZS50ZXN0aW4uY29tMFkwEwYHKoZIzj0CAQYI\r\n' +
  'KoEcz1UBgi0DQgAEN7ryctUk9ISQTs+qQzvk3hTZLj4f90pCfFEC3e8O/au8RTs0\r\n' +
  '3f6fuwGWX0zH297CI80eaAYidzK25FkJZA7PnqNdMFswDAYDVR0TBAUwAwEB/zAL\r\n' +
  'BgNVHQ8EBAMCAQYwHQYDVR0OBBYEFLF6vKQB1DF442gd6o7bN6Yv9u06MB8GA1Ud\r\n' +
  'IwQYMBaAFB+u42AfwCBbDWuMyrC+6RNVkQPWMAoGCCqBHM9VAYN1A0kAMEYCIQDY\r\n' +
  'DSufjGI1nxynGaD+SZR/s4TlPfxgOJ9J4hcT9xpweAIhAMqOe3N5nZVKlZrM71WC\r\n' +
  'lvFqnJkmAkkZ8lJlmp4v79BQ\r\n' +
  '-----END CERTIFICATE-----\r\n';

// SM2根CA证书（PEM格式）
let sm2RootCaCertData = '-----BEGIN CERTIFICATE-----\r\n' +
  'MIICQjCCAemgAwIBAgIUVH0RkiQvN0SqTKy1sdDzhXHtkggwCgYIKoEcz1UBg3Uw\r\n' +
  'bzELMAkGA1UEBhMCWFgxCzAJBgNVBAgMAlhYMQswCQYDVQQHDAJYWDEUMBIGA1UE\r\n' +
  'CgwLY2VydGlmaWNhdGUxDzANBgNVBAsMBnRlc3RjYTEfMB0GA1UEAwwWY2VydGlm\r\n' +
  'aWNhdGUudGVzdGNhLmNvbTAeFw0yNDA1MjIwNzAwMDZaFw0zNDA1MjAwNzAwMDZa\r\n' +
  'MG8xCzAJBgNVBAYTAlhYMQswCQYDVQQIDAJYWDELMAkGA1UEBwwCWFgxFDASBgNV\r\n' +
  'BAoMC2NlcnRpZmljYXRlMQ8wDQYDVQQLDAZ0ZXN0Y2ExHzAdBgNVBAMMFmNlcnRp\r\n' +
  'ZmljYXRlLnRlc3RjYS5jb20wWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAAQDpkiQ\r\n' +
  'sEW8nDG9uNqk08YZXOoAoIsNcOXNg+sm2HDraIjY2bLRo4gzfDqxgxAeth871qvR\r\n' +
  'fmHyP5p4l/iqiAnwo2MwYTAdBgNVHQ4EFgQUH67jYB/AIFsNa4zKsL7pE1WRA9Yw\r\n' +
  'HwYDVR0jBBgwFoAUH67jYB/AIFsNa4zKsL7pE1WRA9YwEgYDVR0TAQH/BAgwBgEB\r\n' +
  '/wIBHjALBgNVHQ8EBAMCAQYwCgYIKoEcz1UBg3UDRwAwRAIgDii62EqXUtA7rFTH\r\n' +
  'dFDboGzPHqV9EtZCc4jO1QfQLFoCIFVIa/Sc3G+gRCQsBr6LEwU4d1Dc0o071NSs\r\n' +
  'yjVOeyi/\r\n' +
  '-----END CERTIFICATE-----\r\n';

async function validateSm2CertChain(): Promise<void> {
  // 创建证书链校验器实例
  let validator = cert.createCertChainValidator('PKIX');

  // 创建SM2证书对象
  let sm2EndEntityCert = await cert.createX509Cert({
    data: sm2EndEntityCertData,
    encodingFormat: cert.EncodingFormat.FORMAT_PEM
  });
  let sm2IntermediateCaCert = await cert.createX509Cert({
    data: sm2IntermediateCaCertData,
    encodingFormat: cert.EncodingFormat.FORMAT_PEM
  });
  let sm2RootCaCert = await cert.createX509Cert({
    data: sm2RootCaCertData,
    encodingFormat: cert.EncodingFormat.FORMAT_PEM
  });

  // SM2用户ID，最常用的ID为"1234567812345678"
  let userId = new Uint8Array([
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38
  ]);

  // 构建校验参数
  let params: cert.X509CertValidatorParams = {
    untrustedCerts: [sm2IntermediateCaCert],
    trustedCerts: [sm2RootCaCert],
    trustSystemCa: false,
    validateDate: true,
    // 设置SM2用户ID
    userId: userId
  };

  try {
    let result: cert.VerifyCertResult = await validator.validate(sm2EndEntityCert, params);
    console.info('SM2 cert chain validate success, certChain length: ' + result.certChain.length);
  } catch (err) {
    let error = err as BusinessError;
    console.error('validate failed, errCode: ' + error.code + ', errMsg: ' + error.message);
  }
}
```

**说明**：
- SM2证书校验时，`userId`参数用于SM2签名验证。
- 常用的SM2用户ID为ASCII编码的"1234567812345678"（16字节）。
- `userId`参数与吊销检查参数（revokedParams）不能同时使用。

## 更多用法示例

### 忽略过期证书错误

某些场景下需要忽略证书过期错误继续使用证书：

``` TypeScript
let params: cert.X509CertValidatorParams = {
  trustedCerts: [rootCaCert],
  trustSystemCa: false,
  // 忽略证书过期错误和证书未生效错误
  ignoreErrs: [
    cert.CertResult.ERR_CERT_HAS_EXPIRED,
    cert.CertResult.ERR_CERT_NOT_YET_VALID
  ]
};
```

### 主机名和邮箱验证

证书校验时可验证证书中的SAN（Subject Alternative Name）扩展：

``` TypeScript
let params: cert.X509CertValidatorParams = {
  trustedCerts: [rootCaCert],
  trustSystemCa: false,
  // 校验主机名是否匹配
  hostnames: ['www.example.com', 'api.example.com'],
  // 校验邮箱地址是否匹配
  emailAddresses: ['user@example.com']
};
```

### 密钥用途验证

验证证书密钥用途是否符合预期：

``` TypeScript
let params: cert.X509CertValidatorParams = {
  trustedCerts: [rootCaCert],
  trustSystemCa: false,
  // 要求证书包含数字签名密钥用途
  keyUsage: [cert.KeyUsageType.KEYUSAGE_DIGITAL_SIGNATURE]
};
```

### 自动下载中间CA证书

当证书链不完整时，可通过AIA（Authority Information Access）扩展自动下载中间CA证书：

``` TypeScript
let params: cert.X509CertValidatorParams = {
  trustSystemCa: true,
  validateDate: true,
  // 允许从网络下载中间CA证书
  allowDownloadIntermediateCa: true
};
```

**说明**：
- 下载中间CA证书需要证书包含AIA扩展，且扩展中指定了CA Issuers URL。
- 下载操作会发起网络请求，可能影响校验性能。下载超时：3秒，最大下载次数：5次。

### 部分证书链校验

部分证书链校验允许在没有完整链到根CA的情况下，只要能链接到任意信任锚就通过校验：

``` TypeScript
let params: cert.X509CertValidatorParams = {
  trustedCerts: [intermediateCaCert], // 仅信任中间CA
  trustSystemCa: false,
  // 允许部分链校验
  partialChain: true
};
```

### 自定义验证日期

适用于离线验证历史签名等场景：

``` TypeScript
let params: cert.X509CertValidatorParams = {
  trustedCerts: [rootCaCert],
  trustSystemCa: false,
  validateDate: true,
  // 设置验证日期为2024年12月31日23时59分59秒
  date: '20241231235959Z'
};
```

## 错误处理

证书链校验可能返回以下错误：

| 错误码 | 常量名 | 错误说明 |
|--------|--------|----------|
| 401 | INVALID_PARAMS | 参数校验失败 |
| 19020001 | ERR_OUT_OF_MEMORY | 内存分配失败 |
| 19020002 | ERR_RUNTIME_ERROR | 运行时错误 |
| 19020003 | ERR_PARAMETER_CHECK_FAILED | 参数校验失败 |
| 19030001 | ERR_CRYPTO_OPERATION | 密码学操作错误 |
| 19030002 | ERR_CERT_SIGNATURE_FAILURE | 证书签名验证失败 |
| 19030003 | ERR_CERT_NOT_YET_VALID | 证书未生效 |
| 19030004 | ERR_CERT_HAS_EXPIRED | 证书已过期 |
| 19030005 | ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY | 无法获取颁发者证书 |
| 19030006 | ERR_KEYUSAGE_NO_CERTSIGN | 密钥不能用于证书签名 |
| 19030007 | ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE | 密钥不能用于数字签名 |
| 19030009 | ERR_CERT_UNTRUSTED | 证书不受信任 |
| 19030010 | ERR_CERT_HAS_REVOKED | 证书已被吊销 |
| 19030011 | ERR_UNKNOWN_CRITICAL_EXTENSION | 不支持的关键扩展 |
| 19030012 | ERR_CERT_HOSTNAME_MISMATCH | 主机名不匹配 |
| 19030013 | ERR_CERT_EMAIL_ADDRESS_MISMATCH | 邮箱地址不匹配 |
| 19030014 | ERR_CERT_KEYUSAGE_MISMATCH | 密钥用法不匹配 |
| 19030015 | ERR_CRL_NOT_FOUND | 未找到CRL |
| 19030016 | ERR_CRL_NOT_YET_VALID | CRL未生效 |
| 19030017 | ERR_CRL_HAS_EXPIRED | CRL已过期 |
| 19030018 | ERR_CRL_SIGNATURE_FAILURE | CRL签名验证失败 |
| 19030019 | ERR_CRL_ISSUER_NOT_FOUND | 未找到CRL颁发者 |
| 19030020 | ERR_OCSP_RESPONSE_NOT_FOUND | 未找到OCSP响应 |
| 19030021 | ERR_OCSP_RESPONSE_INVALID | 无效的OCSP响应 |
| 19030022 | ERR_OCSP_SIGNATURE_FAILURE | OCSP签名验证失败 |
| 19030023 | ERR_OCSP_CERT_STATUS_UNKNOWN | 未知的OCSP证书状态 |
| 19030024 | ERR_NETWORK_TIMEOUT | 网络连接超时 |