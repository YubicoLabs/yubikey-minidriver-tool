#
# Copyright 2018-2019 Yubico AB
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

cmake_minimum_required(VERSION 3.0 FATAL_ERROR)

#
# Target definition
#

project(ykmdtool LANGUAGES CXX)
add_executable(ykmdtool)

#
# Target build options
#

target_compile_features(ykmdtool
	PRIVATE
		cxx_std_17
)

add_definitions(
  -DUNICODE
  -D_UNICODE
)

if (MSVC)
  add_compile_options(/W4 /WX)
else()
  add_compile_options(-Wall -Wextra -pedantic -Werror)
endif()

#
# Include / Library dependencies
#

target_include_directories(ykmdtool
	PRIVATE
		${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(ykmdtool
	PRIVATE
		winscard.lib
    scarddlg.lib
    crypt32.lib
    ncrypt.lib
)

#
# Source files
#

target_sources(ykmdtool
	PRIVATE
		md.cpp
		tool.cpp
    cng.cpp
)

#
# Install
#

install(
	TARGETS
		ykmdtool
	RUNTIME DESTINATION
		.
  COMPONENT "RUNTIME"
)