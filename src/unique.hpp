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

#include <memory>

namespace y {
  namespace details {
    template <typename TPtr>
    class outparam_t
    {
      TPtr& m_p;
      typename TPtr::pointer m_raw;

    public:
      outparam_t(TPtr& p) :
        m_p{ p },
        m_raw(0)
      {

      }

      operator typename TPtr::pointer*()
      {
        return &m_raw;
      }

      ~outparam_t()
      {
        m_p.reset(m_raw);
      }
    };
  }

  // NOTE: This doesn't work with shared_ptr at all because it's fundamentally
  // different than unique_ptr.  None of its template parameters take a deleter
  // that can define ::pointer.
  template <typename TPtr>
  typename details::outparam_t<TPtr> outparam(TPtr& p) {
    details::outparam_t<TPtr> op(p);
    return op;
  }

#ifdef _WIN32

  namespace win {

    namespace deleters {

      struct deleter_handle {
        typedef HANDLE pointer;

        void operator() (HANDLE h) {
          if (h && (h != INVALID_HANDLE_VALUE)) {
            ::CloseHandle(h);
          }
        }
      };

      struct deleter_hwnd {
        typedef HWND pointer;

        void operator() (HWND h) {
          ::CloseHandle(h);
        }
      };

    }

    using unique_handle = std::unique_ptr<HANDLE, deleters::deleter_handle>;
    using unique_hwnd = std::unique_ptr<HWND, deleters::deleter_hwnd>;
  }

#endif

}
