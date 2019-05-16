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

#pragma once

#include <stdexcept>

#include "format.hpp"
#include "cardmod.h"

#define CCH_OCN_READER 256
#define CCH_OCN_CARD   256
#define CB_ATR_MAX     64

namespace y::win {

  typedef DWORD(WINAPI *PFN_CARD_ATTEST_CONTAINER)(PCARD_DATA, BYTE, PBYTE*, PDWORD);

  class Minidriver {
  public:
    Minidriver();
    virtual ~Minidriver();

    void Open();
    void Close();
    void VerifyPin(const std::vector<BYTE>& pin);
    void UnblockPin(const std::vector<BYTE>& puk, const std::vector<BYTE>& newPin);
    std::vector<BYTE> Attest(BYTE containerIndex);
    void ChangeAdminKey(const std::vector<BYTE>& curKey, const std::vector<BYTE>& newKey);

  private:
    SCARDCONTEXT     _ctx;
    SCARDHANDLE      _hCard;
    CARD_DATA        _data;
    bool             _fTransactionOpen;
    wchar_t          _szReader[CCH_OCN_READER];
    wchar_t          _szCard[CCH_OCN_READER];
    BYTE             _rgbAtr[CB_ATR_MAX];
    DWORD            _cbAtr;
    PFN_CARD_ATTEST_CONTAINER _pfnCardAttestContainer;
  };
}