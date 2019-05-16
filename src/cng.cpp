/*
 * Copyright 2018-2019 Yubico AB
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <windows.h>
#include <bcrypt.h>
#include <wincrypt.h>

#include <stdexcept>

#include "format.hpp"
#include "unique.hpp"
#include "cng.hpp"

using namespace std;
using namespace y;
using namespace y::win;
using namespace y::string;

#define CHECK_STATUS(_f, ...) \
  if (!BCRYPT_SUCCESS(status = _f(__VA_ARGS__))) { \
    throw runtime_error(formatString("Error 0x%08x in " #_f ".", status)); \
  }

#define CHECK_BOOL(_f, ...) \
  if (!_f(__VA_ARGS__)) { \
    throw runtime_error(formatString("Error 0x%08x in " #_f ".", ::GetLastError())); \
  }


struct NCryptProvDeleter {
  typedef NCRYPT_PROV_HANDLE pointer;
  void operator()(NCRYPT_PROV_HANDLE h) {
    if (h != 0) {
      ::NCryptFreeObject(h);
    }
  }
};

using unique_ncryptprov = unique_ptr<NCRYPT_PROV_HANDLE, NCryptProvDeleter>;

struct NCryptKeyDeleter {
  typedef NCRYPT_KEY_HANDLE pointer;
  void operator() (NCRYPT_KEY_HANDLE h) {
    if (h != 0) {
      ::NCryptFreeObject(h);
    }
  }
};

using unique_ncryptkey = unique_ptr<NCRYPT_KEY_HANDLE, NCryptKeyDeleter>;

struct CertContextDeleter {
  void operator()(PCCERT_CONTEXT ctx) {
    if (ctx) {
      CertFreeCertificateContext(ctx);
    }
  }
};

using unique_cert_context = unique_ptr<const CERT_CONTEXT, CertContextDeleter>;

void CNG::createSelfSignedCertificate(const wchar_t *name) {
  NTSTATUS status = 0;
  const wchar_t wszProviderName[] = L"Microsoft Smart Card Key Storage Provider";
  const wchar_t wszKeyNamePrefix[] = L"ykmdtool-";
  DWORD dwBitLen = 2048;
  DWORD dwUsage = NCRYPT_ALLOW_ALL_USAGES;
  DWORD cbTemp = 0;
  unique_ptr<uint8_t[]> rgbTemp;
  unique_ncryptprov hProv;
  unique_ncryptkey hKey;

  // Open the KSP

  CHECK_STATUS(NCryptOpenStorageProvider,
    outparam(hProv),
    wszProviderName,
    0);

  // Create a new key

  wstring strKeyName = wszKeyNamePrefix;
  strKeyName += name;

  CHECK_STATUS(NCryptCreatePersistedKey,
    hProv.get(),
    outparam(hKey),
    BCRYPT_RSA_ALGORITHM,
    strKeyName.c_str(),
    AT_KEYEXCHANGE,
    0);

  CHECK_STATUS(NCryptSetProperty, hKey.get(), NCRYPT_LENGTH_PROPERTY, (PBYTE)&dwBitLen, sizeof(dwBitLen), 0);
  CHECK_STATUS(NCryptSetProperty, hKey.get(), NCRYPT_KEY_USAGE_PROPERTY, (PBYTE)&dwUsage, sizeof(dwUsage), 0);
  CHECK_STATUS(NCryptFinalizeKey, hKey.get(), 0);

  wstring strDN = L"CN=";
  strDN += name;

  cbTemp = 0;

  CHECK_BOOL(CertStrToName, X509_ASN_ENCODING, strDN.c_str(), CERT_X500_NAME_STR, NULL, NULL, &cbTemp, NULL);

  rgbTemp.reset(new uint8_t[cbTemp]);

  CHECK_BOOL(CertStrToName, X509_ASN_ENCODING, strDN.c_str(), CERT_X500_NAME_STR, NULL, rgbTemp.get(), &cbTemp, NULL);

  CERT_NAME_BLOB SubjectIssuerBlob;

  memset(&SubjectIssuerBlob, 0, sizeof(SubjectIssuerBlob));
  SubjectIssuerBlob.cbData = cbTemp;
  SubjectIssuerBlob.pbData = rgbTemp.get();
  
  CRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm;

  memset(&SignatureAlgorithm, 0, sizeof(SignatureAlgorithm));
  SignatureAlgorithm.pszObjId = szOID_RSA_SHA256RSA;
  
  unique_cert_context pcc(CertCreateSelfSignCertificate(
    hKey.get(),
    &SubjectIssuerBlob,
    0,
    NULL,
    &SignatureAlgorithm,
    NULL,
    NULL,
    NULL
  ));

  if (!pcc) {
    throw runtime_error(formatString("Error 0x%08x in CertCreateSelfSignCertificate", GetLastError()));
  }

  CHECK_STATUS(NCryptSetProperty, hKey.get(), NCRYPT_CERTIFICATE_PROPERTY, pcc->pbCertEncoded, pcc->cbCertEncoded, 0);
}

