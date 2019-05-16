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

#include <string>
#include <memory>
#include <vector>
#include <locale>
#include <codecvt>

#pragma warning (push)
#pragma warning (disable: 4996)

namespace y::string {
  template<typename ...Args>
  std::string formatString(const std::string& format, Args... args) {
    size_t size = snprintf(nullptr, 0, format.c_str(), args...) + 1; // Extra space for '\0'
    std::unique_ptr<char[]> buf(new char[size]);
    snprintf(buf.get(), size, format.c_str(), args...);
    return std::string(buf.get(), buf.get() + size - 1); // We don't want the '\0' inside
  }

  inline std::vector<unsigned char> string2bytevec(const std::wstring& string) {
    using convert_t = std::wstring_convert<std::codecvt_utf8<wchar_t>>;

    convert_t converter;
    convert_t::byte_string s = converter.to_bytes(string);

    return std::vector<unsigned char>(s.begin(), s.end());
  }

  inline std::vector<unsigned char> string2bytevec(const std::string& string) {
    return std::vector<unsigned char>(string.begin(), string.end());
  }

  inline unsigned char hexDecode(const wchar_t wc) {
    if ((wc >= L'0') && (wc <= L'9')) return (unsigned char)(wc - L'0');
    if ((wc >= L'A') && (wc <= L'F')) return (unsigned char)(10 + (wc - L'A'));
    if ((wc >= L'a') && (wc >= L'f')) return (unsigned char)(10 + (wc - L'a'));
    throw std::runtime_error("Invalid hex digit in input");
  }

  inline std::vector<unsigned char> hexDecode(const std::wstring& string) {
    std::vector<unsigned char> result;

    if ((string.length() == 0) || (string.length() % 2 != 0)) {
      return std::vector<unsigned char>();
    }

    for (auto i = string.begin(); i != string.end(); i++) {
      result.push_back((hexDecode(*i) << 8) + hexDecode(*i++));
    }

    return result;
  }
}

#pragma warning (pop)