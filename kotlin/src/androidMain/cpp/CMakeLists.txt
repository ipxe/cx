cmake_minimum_required(VERSION 3.0)
include(ExternalProject)

# Configuration
set(OPENSSL_VERSION 1.1.1g)
set(OPENSSL_MD5 76766e98997660138cdaf13a187bd234)

# Construct local installation directories
set(INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/install)
set(INSTALL_PREFIX /usr)
set(INSTALL_INCLUDEDIR ${INSTALL_DIR}/${INSTALL_PREFIX}/include)
set(INSTALL_LIBDIR ${INSTALL_DIR}/${INSTALL_PREFIX}/lib)

# Path for external project tools
set(ANDROID_PATH ${ANDROID_TOOLCHAIN_ROOT}/bin:$ENV{PATH})

# OpenSSL build
ExternalProject_Add(
  openssl-project
  URL https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz
  URL_MD5 ${OPENSSL_URL}
  SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/openssl
  BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR}/openssl-build
  CONFIGURE_COMMAND
    PATH=${ANDROID_PATH}
    ANDROID_NDK=${ANDROID_NDK}
    ${CMAKE_CURRENT_SOURCE_DIR}/openssl/Configure
      --prefix=${INSTALL_PREFIX}
      android-${ANDROID_ARCH_NAME}
  BUILD_COMMAND
    PATH=${ANDROID_PATH}
    ANDROID_NDK=${ANDROID_NDK}
    make -j
  INSTALL_COMMAND
    PATH=${ANDROID_PATH}
    ANDROID_NDK=${ANDROID_NDK}
    make install_sw DESTDIR=${INSTALL_DIR}
)

# libcx build
ExternalProject_Add(
  libcx-project
  SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/libcx
  BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR}/libcx-build
  DOWNLOAD_COMMAND
    test -e ${CMAKE_CURRENT_SOURCE_DIR}/libcx/configure ||
      ${CMAKE_CURRENT_SOURCE_DIR}/libcx/autogen.sh
  CONFIGURE_COMMAND
    PATH=${ANDROID_PATH}
    ${CMAKE_CURRENT_SOURCE_DIR}/libcx/configure
      --build=
      --host=${CMAKE_LIBRARY_ARCHITECTURE}
      --prefix=${INSTALL_PREFIX}
      --enable-jni
      "CC=${CMAKE_C_COMPILER}"
      "CPPFLAGS=-I${INSTALL_INCLUDEDIR}"
      "CFLAGS=--target=${CMAKE_C_COMPILER_TARGET}"
      "LDFLAGS=-XCClinker --target=${CMAKE_C_COMPILER_TARGET} \
               -L${INSTALL_LIBDIR}"
  BUILD_COMMAND
    PATH=${ANDROID_PATH}
    make -j
  INSTALL_COMMAND
    PATH=${ANDROID_PATH}
    make install DESTDIR=${INSTALL_DIR}
)
add_dependencies(libcx-project openssl-project)

# libcrypto.so
add_library(crypto SHARED IMPORTED)
add_dependencies(crypto openssl-project)
set_target_properties(
  crypto PROPERTIES IMPORTED_LOCATION ${INSTALL_LIBDIR}/libcrypto.so
)

# libssl.so
add_library(ssl SHARED IMPORTED)
add_dependencies(ssl openssl-project)
set_target_properties(
  ssl PROPERTIES IMPORTED_LOCATION ${INSTALL_LIBDIR}/libssl.so
)

# libcx.so
add_library(cx SHARED IMPORTED)
add_dependencies(cx libcx-project)
set_target_properties(
  cx PROPERTIES IMPORTED_LOCATION ${INSTALL_LIBDIR}/libcx.so
)

# libcxjni.so
add_library(cxjni SHARED IMPORTED)
add_dependencies(cxjni libcx-project)
set_target_properties(
  cxjni PROPERTIES IMPORTED_LOCATION ${INSTALL_LIBDIR}/libcxjni.so
)

# Dummy library to trick Gradle into actually building something,
# since it uses cmake-file-api(7) to identify build targets, and
# imported libraries do not show up within this list.
add_library(dummy SHARED dummy.c)
add_dependencies(dummy crypto ssl cx cxjni)
add_custom_command(TARGET dummy POST_BUILD COMMAND cp
  ${INSTALL_LIBDIR}/libcrypto.so
  ${INSTALL_LIBDIR}/libssl.so
  ${INSTALL_LIBDIR}/libcx.so
  ${INSTALL_LIBDIR}/libcxjni.so
  ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/
)
