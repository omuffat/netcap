cmake_minimum_required(VERSION 3.18)
project(netcap C CXX)

# ---------------------------------------------------------------------------
# Language standards
# ---------------------------------------------------------------------------

# CMake 3.18 (Debian 11) does not know the GCC flag mapping for C17.
# Inject -std=c17 explicitly and tell CMake the standard is 11 (which it
# does know) so it does not generate a conflicting flag.
# CMake >= 3.21 has the mapping and can use CMAKE_C_STANDARD=17 directly.
if(CMAKE_VERSION VERSION_LESS "3.21")
    add_compile_options($<$<COMPILE_LANGUAGE:C>:-std=c17>)
    set(CMAKE_C_STANDARD 11)
else()
    set(CMAKE_C_STANDARD 17)
endif()
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(CMAKE_CXX_STANDARD   17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ---------------------------------------------------------------------------
# Compiler security flags (applied to all netcap targets)
# Third-party targets opt out via their own CMakeLists.txt.
# ---------------------------------------------------------------------------

add_compile_options(
    $<$<COMPILE_LANGUAGE:C>:-Wall>
    $<$<COMPILE_LANGUAGE:C>:-Wextra>
    $<$<COMPILE_LANGUAGE:C>:-Werror>
    $<$<COMPILE_LANGUAGE:C>:-Wformat-security>
    $<$<COMPILE_LANGUAGE:C>:-fstack-protector-strong>
)

# ---------------------------------------------------------------------------
# Development / production path selector
#
# When CMAKE_BUILD_TYPE is Debug, the compile-time flag CN_DEV_BUILD is
# defined.  All default file-system paths (ring_dir, savefile_dir, …) then
# point to directories relative to the repository root so that development
# and testing never touch system paths.
#
# Release builds use the OS-conventional production paths:
#   Linux   ring_dir=/var/lib/netcap/rings  savefile=/usr/share/netcap/captures
#   macOS   ring_dir=/Library/Application Support/netcap/rings  etc.
#   Windows ring_dir=C:\ProgramData\netcap\rings  etc.
#
# See config/config.h for the full set of CN_DEFAULT_* macros.
# ---------------------------------------------------------------------------

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_definitions(CN_DEV_BUILD=1)
    message(STATUS "netcap: Debug build — using repository-relative default paths (CN_DEV_BUILD=1)")
else()
    message(STATUS "netcap: Release build — using production default paths")
endif()

# ---------------------------------------------------------------------------
# Find libpcap (Linux/macOS) or Npcap SDK (Windows)
# ---------------------------------------------------------------------------

if(WIN32)
    # Point CMAKE_PREFIX_PATH or NPCAP_SDK_DIR to the Npcap SDK root.
    find_path(PCAP_INCLUDE_DIR pcap/pcap.h
        HINTS "$ENV{NPCAP_SDK_DIR}/Include"
              "${CMAKE_PREFIX_PATH}/Include")
    find_library(PCAP_LIBRARY
        NAMES wpcap Packet
        HINTS "$ENV{NPCAP_SDK_DIR}/Lib/x64"
              "${CMAKE_PREFIX_PATH}/Lib/x64")
    if(NOT PCAP_INCLUDE_DIR OR NOT PCAP_LIBRARY)
        message(FATAL_ERROR
            "Npcap SDK not found. Set CMAKE_PREFIX_PATH to the Npcap SDK root "
            "or set the NPCAP_SDK_DIR environment variable.")
    endif()
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(PCAP REQUIRED libpcap)
    set(PCAP_INCLUDE_DIR "${PCAP_INCLUDE_DIRS}")
    set(PCAP_LIBRARY     "${PCAP_LIBRARIES}")
endif()

# ---------------------------------------------------------------------------
# Find libcurl (must be built with TLS support)
# ---------------------------------------------------------------------------

find_package(CURL REQUIRED)
if(NOT CURL_FOUND)
    message(FATAL_ERROR "libcurl not found.")
endif()

# ---------------------------------------------------------------------------
# Propagate dependency paths to sub-modules via cache variables
# ---------------------------------------------------------------------------

set(NETCAP_PCAP_INCLUDE_DIR  "${PCAP_INCLUDE_DIR}"  CACHE INTERNAL "")
set(NETCAP_PCAP_LIBRARY      "${PCAP_LIBRARY}"       CACHE INTERNAL "")
set(NETCAP_CURL_INCLUDE_DIRS "${CURL_INCLUDE_DIRS}"  CACHE INTERNAL "")
set(NETCAP_CURL_LIBRARIES    "${CURL_LIBRARIES}"     CACHE INTERNAL "")

# ---------------------------------------------------------------------------
# Sub-modules (third_party first — config depends on tomlc99)
# ---------------------------------------------------------------------------

add_subdirectory(third_party/tomlc99)
add_subdirectory(core)
add_subdirectory(config)
add_subdirectory(uploader)
add_subdirectory(service)
add_subdirectory(gui)
add_subdirectory(cli)
enable_testing()
add_subdirectory(tests)

# ---------------------------------------------------------------------------
# Install rules
#
# All destinations are relative to CPACK_PACKAGING_INSTALL_PREFIX ("/").
# For a direct install use:  cmake --install build --prefix /
# ---------------------------------------------------------------------------

install(TARGETS netcapd    DESTINATION usr/sbin)
install(TARGETS netcap-ctl DESTINATION usr/bin)

install(FILES service/netcapd.service
        DESTINATION lib/systemd/system)

install(FILES netcap.toml.example
        DESTINATION etc/netcap
        RENAME netcap.toml)

# ---------------------------------------------------------------------------
# CPack — Debian package
#
# Build with:
#   cmake -B build -DCMAKE_BUILD_TYPE=Release
#   cmake --build build
#   cd build && cpack -G DEB
#
# Output: build/netcap_0.1.0_amd64.deb
# ---------------------------------------------------------------------------

set(CPACK_PACKAGE_NAME     "netcap")
set(CPACK_PACKAGE_VERSION  "0.1.0")
set(CPACK_PACKAGE_VENDOR   "Comoe Networks")
set(CPACK_PACKAGE_CONTACT  "contact@comoe-networks.com")

set(CPACK_PACKAGE_DESCRIPTION_SUMMARY
    "Cross-platform network capture agent")
set(CPACK_PACKAGE_DESCRIPTION
"netcap is a network capture daemon that writes rotating .pcap savefiles
 for each configured network interface. Savefiles can be uploaded to an
 HTTPS endpoint manually or automatically on rotation.
 Supports BPF filters, gzip compression, and mutual TLS (mTLS).")

set(CPACK_PACKAGING_INSTALL_PREFIX "/")
set(CPACK_GENERATOR                "DEB")

set(CPACK_DEBIAN_FILE_NAME         "DEB-DEFAULT")
set(CPACK_DEBIAN_PACKAGE_SECTION   "net")
set(CPACK_DEBIAN_PACKAGE_PRIORITY  "optional")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER
    "Comoe Networks <contact@comoe-networks.com>")
set(CPACK_DEBIAN_PACKAGE_DEPENDS
    "libpcap0.8, libcurl4, zlib1g, libcap2")

# /etc/netcap/netcap.toml is a conffile: dpkg preserves operator edits on upgrade.
set(CPACK_DEBIAN_PACKAGE_CONFFILES "/etc/netcap/netcap.toml")

set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA
    "${CMAKE_CURRENT_SOURCE_DIR}/package/debian/preinst"
    "${CMAKE_CURRENT_SOURCE_DIR}/package/debian/postinst"
    "${CMAKE_CURRENT_SOURCE_DIR}/package/debian/prerm"
    "${CMAKE_CURRENT_SOURCE_DIR}/package/debian/postrm")

include(CPack)
