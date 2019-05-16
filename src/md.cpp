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

#include "md.hpp"
#include "unique.hpp"

using namespace std;
using namespace y;
using namespace y::win;
using namespace y::string;

#define ROLE_PUK 7
#define CB_YK_CHALLENGE 8
#define CB_YK_ADMINKEY  24

static void * __stdcall _alloc(SIZE_T cb) {
  return malloc(cb);
}

static void * __stdcall _realloc(LPVOID p, SIZE_T cb) {
  return realloc(p, cb);
}

static void   __stdcall _free(LPVOID p) {
  free(p);
}

struct CryptProvDeleter {
  typedef HCRYPTPROV pointer;
  void operator()(HCRYPTPROV h) {
    if (h != 0) {
      ::CryptReleaseContext(h, 0);
    }
  }
};

using unique_cryptprov = unique_ptr<HCRYPTPROV, CryptProvDeleter>;

struct MDDeleter {
  typedef LPBYTE pointer;
  void operator()(LPBYTE p) {
    _free(p);
  }
};

using unique_mdblob_ptr = unique_ptr<BYTE, MDDeleter>;

// Functions

static vector<BYTE> computeResponse(const vector<BYTE>& key, const vector<BYTE>& challenge) {
  HRESULT hr = 0;

#pragma pack(push, 1)
  struct TripleDESKey {
    BLOBHEADER hdr = { PLAINTEXTKEYBLOB, CUR_BLOB_VERSION, 0, CALG_3DES };
    DWORD dwKeySize = CB_YK_ADMINKEY;
    BYTE rgbKeyData[CB_YK_ADMINKEY] = { 0 };
  };
#pragma pack(pop)

  throw runtime_error("compute response is not yet implemented");

  TripleDESKey tdk = TripleDESKey();

  if (challenge.size() != CB_YK_CHALLENGE) {
    throw runtime_error("challenge does not meet length requirements");
  }

  vector<BYTE> response(challenge);

  unique_cryptprov hProv;

  if (!CryptAcquireContext(
    outparam(hProv),
    NULL,
    NULL,
    PROV_RSA_FULL,
    0)) {
    throw runtime_error(formatString("Error 0x%08x in CryptAcquireContext", GetLastError()));
  }


  return response;
} 

Minidriver::Minidriver() :
  _fTransactionOpen(false),
  _ctx(NULL),
  _data{ 0 },
  _szReader{ 0 },
  _szCard{ 0 },
  _rgbAtr{ 0 },
  _cbAtr(sizeof(_rgbAtr)),
  _pfnCardAttestContainer(NULL) {
}

Minidriver::~Minidriver() {
  Close();
}

void Minidriver::Open() {

  LONG lResult = -1;
  OPENCARDNAME_EXW ocn;
  DWORD dwState = 0;
  DWORD dwProtocol = 0;

  // Establish the context.
  lResult = SCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &_ctx);

  if (lResult != 0) {
    throw runtime_error(formatString("Error 0x%08x in SCardEstablishContext()", lResult));
  }

  // Select and connect to card
  SecureZeroMemory(&ocn, sizeof(OPENCARDNAME_EXW));

  ocn.dwFlags = SC_DLG_MINIMAL_UI;
  ocn.hSCardContext = _ctx;
  ocn.dwShareMode = SCARD_SHARE_SHARED;
  ocn.dwPreferredProtocols = SCARD_PROTOCOL_Tx;
  ocn.lpstrRdr = _szReader;
  ocn.nMaxRdr = (DWORD)(sizeof(_szReader) / sizeof(wchar_t));
  ocn.lpstrCard = _szCard;
  ocn.nMaxCard = (DWORD)(sizeof(_szCard) / sizeof(wchar_t));
  ocn.dwStructSize = sizeof(OPENCARDNAME_EXW);

  lResult = SCardUIDlgSelectCardW(&ocn);

  if (lResult != SCARD_S_SUCCESS) {
    throw runtime_error(lResult == SCARD_E_NO_READERS_AVAILABLE ? "No smart card readers available" : formatString("Error 0x%08x in SCardUIDlgSelectCardW()", lResult));
  }

  _hCard = ocn.hCardHandle;

  // Start transaction
  lResult = SCardBeginTransaction(_hCard);

  if (lResult != 0) {
    throw runtime_error(formatString("Error 0x%08x in SCardBeginTransaction()", lResult));
  }

  _fTransactionOpen = true;

  // Get card ATR - required to acquire md context
  ocn.nMaxRdr = (DWORD)(sizeof(_szReader) / sizeof(wchar_t));
  lResult = SCardStatusW(_hCard, _szReader, &(ocn.nMaxRdr), &dwState, &dwProtocol, _rgbAtr, &_cbAtr);

  if (lResult != SCARD_S_SUCCESS) {
    throw runtime_error(formatString("Error 0x%08x in SCardStatusW()", lResult));
  }

  LPWSTR wszCardModule = NULL;
  DWORD cchCardModule = SCARD_AUTOALLOCATE;
  PFN_CARD_ACQUIRE_CONTEXT CardAcquireContextFn = NULL;

  try {
    // Load minidriver module
    lResult = SCardGetCardTypeProviderName(_ctx, _szCard, SCARD_PROVIDER_CARD_MODULE, (LPWSTR)&wszCardModule, &cchCardModule);

    if (lResult != SCARD_S_SUCCESS) {
      throw runtime_error(formatString("Error 0x%08x in ScardGetCardTypeProviderName()", lResult));
    }

    // Load cardmodule
    HMODULE module = LoadLibrary(wszCardModule);

    if (module == NULL) {
      DWORD dwErr = GetLastError();
      throw runtime_error(formatString("Cannot load module %S, last error = %d", wszCardModule, dwErr));
    }

    CardAcquireContextFn = (PFN_CARD_ACQUIRE_CONTEXT)GetProcAddress(module, "CardAcquireContext");

    if (!CardAcquireContextFn) {
      throw runtime_error(formatString("Cannot find address of CardAcquireContext in module %S", wszCardModule));
    }

    // also load CardAttestContainer, if available
    _pfnCardAttestContainer = (PFN_CARD_ATTEST_CONTAINER)GetProcAddress(module, "CardAttestContainer");

    SCardFreeMemory(_ctx, wszCardModule);
    wszCardModule = NULL;
  }
  catch (...) {
    if (wszCardModule) {
      SCardFreeMemory(_ctx, wszCardModule);
      wszCardModule = NULL;
    }
    throw;
  }

  // Acquire minidriver context

  _data.dwVersion = CARD_DATA_VERSION_SEVEN;
  _data.pbAtr = _rgbAtr;
  _data.cbAtr = _cbAtr;
  _data.hSCardCtx = _ctx;
  _data.hScard = _hCard;
  _data.pwszCardName = _szCard;
  _data.pfnCspAlloc = _alloc;
  _data.pfnCspReAlloc = _realloc;
  _data.pfnCspFree = _free;

  lResult = CardAcquireContextFn(&_data, 0);

  if (lResult != SCARD_S_SUCCESS) {
    _data.hSCardCtx = NULL;
    throw runtime_error(formatString("Error 0x%08x in CardAcquireContext()", lResult));
  }

}

void Minidriver::Close() {

  if (_data.hSCardCtx) {
    _data.pfnCardDeleteContext(&_data);
    SecureZeroMemory(&_data, sizeof(_data));
  }

  if (_fTransactionOpen) {
    DWORD res = SCardEndTransaction(_hCard, SCARD_LEAVE_CARD);

    if (res != SCARD_S_SUCCESS) {
      SCardDisconnect(_hCard, SCARD_RESET_CARD);
      SCardReleaseContext(_ctx);
      _ctx = NULL;
      _hCard = NULL;
    }

    _fTransactionOpen = false;
  }

  if (_hCard) {
    SCardDisconnect(_hCard, SCARD_LEAVE_CARD);
    _hCard = NULL;
  }

  if (_ctx) {
    SCardReleaseContext(_ctx);
    _ctx = NULL;
  }

  SecureZeroMemory(_szReader, sizeof(_szReader));
  SecureZeroMemory(_szCard, sizeof(_szCard));
}

void Minidriver::VerifyPin(const vector<BYTE>& pin) {
  DWORD dwErr = SCARD_S_SUCCESS;
  DWORD cAttRemain = 0;

  if (!_data.hSCardCtx || !_data.pfnCardAuthenticateEx) {
    throw runtime_error("Card not open");
  }

  if (pin.size() == 0) {
    throw runtime_error("Pin not supplied");
  }

  dwErr = _data.pfnCardAuthenticateEx(&_data, ROLE_USER, 0, (PBYTE)pin.data(), (DWORD)pin.size(), NULL, NULL, &cAttRemain);

  switch (dwErr) {
  case SCARD_W_WRONG_CHV:
  case SCARD_E_INVALID_CHV:
    throw runtime_error(formatString("The supplied pin is incorrect, %d attempts remaining.", cAttRemain));

  case SCARD_W_CHV_BLOCKED:
    throw runtime_error("The pin is blocked.");

  default:
    if (dwErr != SCARD_S_SUCCESS) {
      throw runtime_error(formatString("Error 0x%08x in CardAuthenticateEx", dwErr));
    }
  }
}

void Minidriver::UnblockPin(const vector<BYTE>& puk, const vector<BYTE>& newPin) {
  DWORD dwErr = SCARD_S_SUCCESS;
  DWORD cAttRemain = 0;

  if (!_data.hSCardCtx || !_data.pfnCardAuthenticateEx) {
    throw runtime_error("Card not open");
  }

  if (puk.size() == 0) {
    throw runtime_error("Invalid PUK supplied");
  }

  if (newPin.size() == 0) {
    throw runtime_error("Invalid PIN supplied");
  }

  dwErr = _data.pfnCardChangeAuthenticatorEx(&_data, PIN_CHANGE_FLAG_UNBLOCK, ROLE_PUK, (PBYTE)puk.data(), (DWORD)puk.size(), ROLE_USER, (PBYTE)newPin.data(), (DWORD)newPin.size(), 0, &cAttRemain);

  switch (dwErr) {
  case SCARD_W_WRONG_CHV:  
    throw runtime_error(formatString("The supplied puk is incorrect, %d attempts remaining.", cAttRemain));

  case SCARD_E_INVALID_CHV:
    throw runtime_error("Invalid puk supplied.");

  case SCARD_W_CHV_BLOCKED:
    throw runtime_error("The puk is blocked.");

  default:
    if (dwErr != SCARD_S_SUCCESS) {
      throw runtime_error(formatString("Error 0x%08x in CardChangeAuthenticatorEx", dwErr));
    }
  }
}

vector<BYTE> Minidriver::Attest(BYTE bIndex) {  
  DWORD dwErr = SCARD_S_SUCCESS;
  PBYTE pbData = NULL;
  DWORD cbData = 0;

  if (!_pfnCardAttestContainer) {
    throw runtime_error("Minidriver doesn't contain attestation function export");
  }

  dwErr = _pfnCardAttestContainer(&_data, bIndex, &pbData, &cbData);
  unique_ptr<BYTE, MDDeleter> upbData(pbData);

  if (dwErr != SCARD_S_SUCCESS) {
    throw runtime_error(formatString("Error 0x%08x in CardAttestContainer", dwErr));
  }

  return vector<BYTE>(upbData.get(), upbData.get() + cbData);
}

void Minidriver::ChangeAdminKey(const vector<BYTE>& curKey, const vector<BYTE>& newKey) {
  DWORD dwErr = 0;
  unique_mdblob_ptr pChallenge;
  unique_mdblob_ptr rgbFile;
  DWORD cbFile = 0;
  DWORD cbChallenge = 0;

  if (!_data.hSCardCtx || !_data.pfnCardGetChallengeEx) {
    throw runtime_error("Card not open");
  }

  if (curKey.size() != CB_YK_ADMINKEY) {
    throw runtime_error("Invalid current key supplied");
  }

  if (newKey.size() != CB_YK_ADMINKEY) {
    throw runtime_error("Invalid new key supplied");
  }

  dwErr = _data.pfnCardGetChallengeEx(&_data, ROLE_ADMIN, outparam(pChallenge), &cbChallenge, 0);

  // compute response

  computeResponse(curKey, vector<BYTE>(pChallenge.get(), pChallenge.get() + cbChallenge));

  _data.pfnCardReadFile(&_data, const_cast<LPSTR>(szBASE_CSP_DIR), const_cast<LPSTR>(szCONTAINER_MAP_FILE), 0, outparam(rgbFile), &cbFile);

   // TODO: don't use this, this is a test for deleting containers

  for (size_t i = 0; i < (cbFile / sizeof(CONTAINER_MAP_RECORD)); i++) {
    PCONTAINER_MAP_RECORD pCurrent = reinterpret_cast<PCONTAINER_MAP_RECORD>(rgbFile.get()) + i;


    if (pCurrent->wszGuid[0] && (pCurrent->bFlags & CONTAINER_MAP_VALID_CONTAINER)) {
      _data.pfnCardDeleteContainer(&_data, static_cast<BYTE>(i), 0);
    }
  }

  _data.pfnCardWriteFile(&_data, const_cast<LPSTR>(szBASE_CSP_DIR), const_cast<LPSTR>(szCONTAINER_MAP_FILE), 0, NULL, 0);
}
