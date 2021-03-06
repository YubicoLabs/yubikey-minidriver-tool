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

#include <stdio.h>
#include <wchar.h>

#include <stdexcept>
#include <unordered_map>
#include <memory>
#include <fstream>

#include "cardmod.h"
#include "format.hpp"
#include "md.hpp"
#include "unique.hpp"
#include "cng.hpp"

using namespace std;
using namespace y;
using namespace y::win;
using namespace y::string;

enum Command {
  Init,
  UnblockPin,
  Clear,
  VerifyPin,
  Attest,
  SetAdminKey,
  SelfSignCert
};

enum Parameter {
  CurPin,
  NewPin,
  CurKey,
  NewKey,
  PUK,
  ContainerIndex,
  OutFile,
  Name
};

Command g_command;
unordered_map<Parameter, wstring> g_parameters;

void showUsage() {
  wprintf(
    L"\nykmdtool.exe\n"
    L"\nThis program comes with ABSOLUTELY NO WARRANTY and is unsupported example software."
    L"\n"
    L"\nsyntax: ykmdtool.exe unblockpin          <adminkey>  <newpin>\n"
    L"                     changepin             <oldpin>    <newpin>\n"
    L"                     changeadminkey        <adminkey>  <newadminkey>\n"
    L"                     calculateresponse     <adminkey>  <challange>\n"
    L"                     generaterandomkey\n"
    L"                     attest                <container index> <out file>\n"
    L"                     self-sign-certificate <name>\n "
    L"\n"
    L"  <adminkey> is one the the following alternatives:\n"
    L"    - 48 hexadecimal characters\n"
    L"    - \"default\", representing 48 zeroes\n"
    L"    - \"random\", representing 48 random hexadecimal characters\n"
    L"\n"
    L"  <pin> is variable-length string composed of alphanumerical characters\n"
    L"\n");
}

void parseCli(int argc, wchar_t *argv[]) {
  if (argc < 2) {
    throw exception("operation not supplied");
  }
  else if (!_wcsicmp(L"unblockpin", argv[1])) {
    g_command = Command::UnblockPin;
    if (argc < 4) throw runtime_error("unblockpin requires <puk> and <pin> arguments");

    g_parameters[Parameter::PUK] = argv[2];
    g_parameters[Parameter::NewPin] = argv[3];
  }
  else if (!_wcsicmp(L"verifypin", argv[1])) {
    g_command = Command::VerifyPin;
    if (argc != 3) throw runtime_error("verifypin requires <pin> argument");

    g_parameters[Parameter::CurPin] = argv[2];
  }
  else if (!_wcsicmp(L"attest", argv[1])) {
    g_command = Command::Attest;
    if (argc != 4) throw runtime_error("attest requires <container index> and <out file> arguments");

    g_parameters[Parameter::ContainerIndex] = argv[2];
    g_parameters[Parameter::OutFile] = argv[3];
  }
  else if (!_wcsicmp(L"setadminkey", argv[1])) {
    g_command = Command::SetAdminKey;

    if (argc != 4) throw runtime_error("setadminkey requires <current key> and <new key> arguments");

    g_parameters[Parameter::CurKey] = argv[2];
    g_parameters[Parameter::NewKey] = argv[3];
  }
  else if (!_wcsicmp(L"self-sign-certificate", argv[1])) {
    g_command = Command::SelfSignCert;

    if (argc != 3) throw runtime_error("self-sign-certificate requires <name> argument");

    g_parameters[Parameter::Name] = argv[2];
  }
  else {
    throw runtime_error("invalid operation specified");
  }
}

struct CertContextDeleter {
  void operator()(PCCERT_CONTEXT ctx) {
    if (ctx) {
      CertFreeCertificateContext(ctx);
    }
  }
};

struct LocalAllocDeleter {
  void operator()(void *p) {
    if (p) {
      LocalFree(p);
    }
  }
};

#define szOID_YK_FIRMWARE_VER "1.3.6.1.4.1.41482.3.3"
#define szOID_YK_SERIAL       "1.3.6.1.4.1.41482.3.7"
#define szOID_YK_POLICY       "1.3.6.1.4.1.41482.3.8"

void printCertificate(vector<unsigned char>& data) {
  DWORD dwEncoding = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
  DWORD dwErr = 0;

  using unique_cert_context = unique_ptr<const CERT_CONTEXT, CertContextDeleter>;
  using unique_cert_name = unique_ptr<CERT_NAME_INFO, LocalAllocDeleter>;

  unique_cert_context pCert(
    CertCreateCertificateContext(
      dwEncoding,
      data.data(),
      static_cast<DWORD>(data.size()))
  );

  if (pCert == nullptr) {
    dwErr = GetLastError();
    throw runtime_error(formatString("Error 0x%08x in CertCreateCertificateContext", dwErr));
  }

  wprintf(L"Version: V%d\n", pCert->pCertInfo->dwVersion + 1);

  unique_cert_name pDecoded;
  DWORD cbDecoded = 0;

  if (CryptDecodeObjectEx(
    dwEncoding,
    X509_NAME,
    pCert->pCertInfo->Issuer.pbData,
    pCert->pCertInfo->Issuer.cbData,
    CRYPT_DECODE_ALLOC_FLAG | CRYPT_DECODE_NOCOPY_FLAG,
    NULL,
    outparam(pDecoded),
    &cbDecoded)) {
    wprintf(L"Issuer: %s\n", reinterpret_cast<wchar_t*>(pDecoded->rgRDN[0].rgRDNAttr[0].Value.pbData));
  }
  else {
    throw runtime_error(formatString("Error 0x%08x in CryptDecodeObjectEx", GetLastError()));
  }

  if (CryptDecodeObjectEx(
    dwEncoding,
    X509_NAME,
    pCert->pCertInfo->Subject.pbData,
    pCert->pCertInfo->Subject.cbData,
    CRYPT_DECODE_ALLOC_FLAG | CRYPT_DECODE_NOCOPY_FLAG,
    NULL,
    outparam(pDecoded),
    &cbDecoded)) {
    wprintf(L"Subject: %s\n", reinterpret_cast<wchar_t*>(pDecoded->rgRDN[0].rgRDNAttr[0].Value.pbData));
  }
  else {
    throw runtime_error(formatString("Error 0x%08x in CryptDecodeObjectEx", GetLastError()));
  }

  // basic cert attributes

  if (pCert->pCertInfo->SerialNumber.cbData > 0) {
    DWORD cbSerial = pCert->pCertInfo->SerialNumber.cbData;
    BYTE* pbSerial = pCert->pCertInfo->SerialNumber.pbData;

    // serial number is arbitrary bytes, but encoded in little endian
    // by the cert api, so they should be treated as a byte sequence in reverse order

    wprintf(L"Serial Number: ");

    for (DWORD j = cbSerial - 1; j < cbSerial; j--) {
      wprintf(L"%02x", pbSerial[j]);
    }

    wprintf(L"\n");
  }

  // extensions

  wprintf(L"Extensions:\n");

  for (DWORD i = 0; i < pCert->pCertInfo->cExtension; i++) {
    PCERT_EXTENSION pExt = &(pCert->pCertInfo->rgExtension[i]);

    wprintf(L"  %S ", pExt->pszObjId);

    if (!strcmp(szOID_YK_FIRMWARE_VER, pExt->pszObjId)) {
      wprintf(L"(YubiKey Firmware Version): ");

      for (DWORD j = 0; j < pExt->Value.cbData; j++) {
        wprintf(L"%s%d", j == 0 ? L"" : L".", pExt->Value.pbData[i]);
      }
    }
    else if (!strcmp(szOID_YK_POLICY, pExt->pszObjId)) {
      wprintf(L"(YubiKey Policy): ");

      if (pExt->Value.cbData != 2) {
        wprintf(L"<Unable to decode>");
      }
      else {
        wprintf(L"Pin - ");
        switch (*(pExt->Value.pbData)) {
        case 1:
          wprintf(L"never");
          break;
        case 2:
          wprintf(L"once");
          break;
        case 3:
          wprintf(L"always");
          break;
        default:
          wprintf(L"<unknown>");
          break;
        }

        wprintf(L", Touch - ");
        switch (*(pExt->Value.pbData + 1)) {
        case 1:
          wprintf(L"never");
          break;
        case 2:
          wprintf(L"always");
          break;
        case 3:
          wprintf(L"cached");
          break;
        default:
          wprintf(L"unknown");
          break;
        }
      }
    }
    else if (!strcmp(szOID_YK_SERIAL, pExt->pszObjId)) {
      using up_int = unique_ptr<int, LocalAllocDeleter>;
      up_int pInt;
      cbDecoded = 0;

      wprintf(L"(YubiKey Serial Number): ");

      if (CryptDecodeObjectEx(
        dwEncoding,
        X509_INTEGER,
        pExt->Value.pbData,
        pExt->Value.cbData,
        CRYPT_DECODE_ALLOC_FLAG | CRYPT_DECODE_NOCOPY_FLAG,
        NULL,
        outparam(pInt),
        &cbDecoded)) {
        wprintf(L"%d", *pInt);
      }
      else {
        wprintf(L"<unable to parse>");
      }
    }

    wprintf(L"\n");
  }

  PCCRYPT_OID_INFO pOIDInfo = NULL;

  pOIDInfo = CryptFindOIDInfo(CRYPT_OID_INFO_OID_KEY, pCert->pCertInfo->SignatureAlgorithm.pszObjId, 0);
  wprintf(L"Signature Algorithm: %s\n", pOIDInfo ? pOIDInfo->pwszName : L"<unknown>");

  wprintf(L"  Parameters: ");

  for (DWORD i = 0; i < pCert->pCertInfo->SignatureAlgorithm.Parameters.cbData; i++) {
    wprintf(L"%s%02x", i == 0 ? L"" : L" ", pCert->pCertInfo->SignatureAlgorithm.Parameters.pbData[i]);
  }

  wprintf(L"\n");

  wprintf(L"Public Key:\n");

  pOIDInfo = CryptFindOIDInfo(CRYPT_OID_INFO_OID_KEY, pCert->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId, 0);
  wprintf(L"  Algorithm: %s", pOIDInfo ? pOIDInfo->pwszName : L"<unknown>");

  using unique_byte_ptr = unique_ptr<BYTE, LocalAllocDeleter>;

  unique_byte_ptr pPubKey;
  cbDecoded = 0;

  if (CryptDecodeObjectEx(
    dwEncoding,
    RSA_CSP_PUBLICKEYBLOB,
    pCert->pCertInfo->SubjectPublicKeyInfo.PublicKey.pbData,
    pCert->pCertInfo->SubjectPublicKeyInfo.PublicKey.cbData,
    CRYPT_DECODE_ALLOC_FLAG,
    NULL,
    outparam(pPubKey),
    &cbDecoded
  )) {
    
    PUBLICKEYSTRUC *pPKS = reinterpret_cast<PUBLICKEYSTRUC*>(pPubKey.get());
    
    switch (pPKS->aiKeyAlg) {
    case CALG_RSA_KEYX:
    case CALG_RSA_SIGN:
      RSAPUBKEY * pRSA = reinterpret_cast<RSAPUBKEY*>(pPubKey.get() + sizeof(PUBLICKEYSTRUC));
      wprintf(L"%d\n", pRSA->bitlen);
      wprintf(L"  Public Exponent: %d\n", pRSA->pubexp);

      BYTE* pKey = reinterpret_cast<BYTE*>(pRSA) + sizeof(RSAPUBKEY);

      // like most all CryptoAPI objects, the modulus is represented as
      // a little-endian byte sequence, so it's reversed in memory

      size_t cbKey = pRSA->bitlen / 8;

      reverse(pKey, pKey + cbKey);

      wprintf(L"  Modulus:\n");
      for (DWORD i = 0; i < cbKey; i+=16) {
        wprintf(L"    ");
        for (DWORD j = 0; (j < 16) && ((j + i) < cbKey); j++) {
          wprintf(L"%s%02x", j == 0 ? L"" : L" ", pKey[i+j]);
        }
        wprintf(L"\n");
      }
    }
  }
  else {
    throw runtime_error(formatString("Error 0x%08x in CryptDecodeObjectEx", GetLastError()));
  }
}

int wmain(int argc, wchar_t *argv[]) {
  int res = 0;

  try {
    Minidriver md;

    parseCli(argc, argv);

    if (g_command != Command::SelfSignCert) {
      md.Open();
    }

    switch (g_command) {
    case Command::VerifyPin:
      md.VerifyPin(string2bytevec(g_parameters[Parameter::CurPin]));
      break;

    case Command::UnblockPin:
      md.UnblockPin(string2bytevec(g_parameters[Parameter::PUK]), string2bytevec(g_parameters[Parameter::NewPin]));
      break;

    case Command::Attest: {
      int index = stoi(g_parameters[Parameter::ContainerIndex]);

      if ((index < 0) || (index > 0xFF)) {
        throw runtime_error("Container index out of range");
      }

      vector<unsigned char> result = md.Attest((BYTE)index);

      // make this optional? 
      fstream fs(g_parameters[Parameter::OutFile], fstream::out | fstream::binary | fstream::trunc);
      fs.write((const char*)result.data(), result.size());
      fs.close();

      printCertificate(result);
      break;
    }

    case Command::SetAdminKey: {
      vector<BYTE> curKey = hexDecode(g_parameters[Parameter::CurKey]);
      vector<BYTE> newKey = hexDecode(g_parameters[Parameter::NewKey]);

      if (curKey.size() != 24) {
        throw runtime_error("Parameter <current key> must be 48 hex characters");
      }

      if (newKey.size() != 24) {
        throw runtime_error("Parameter <current key> must be 48 hex characters");
      }

      md.ChangeAdminKey(curKey, newKey); }
      break;

    case Command::SelfSignCert:
      CNG::createSelfSignedCertificate(g_parameters[Parameter::Name].c_str());
      break;
    }


    md.Close();
  }
  catch (const exception& e) {
    wprintf(L"Operation failed: %S\n", e.what());
    showUsage();
    res = -1;
  }
  catch (...) {
    wprintf(L"An unhandled exception occurred\n");
    res = -2;
  }

  return res;
}

