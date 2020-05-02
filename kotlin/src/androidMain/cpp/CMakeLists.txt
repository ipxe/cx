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

# Dummy library to trick Gradle into actually building something,
# since it uses cmake-file-api(7) to identify build targets, and
# imported libraries do not show up within this list.
add_library(dummy SHARED dummy.c)
add_dependencies(dummy crypto ssl)
add_custom_command(TARGET dummy POST_BUILD COMMAND cp
  ${INSTALL_LIBDIR}/libcrypto.so
  ${INSTALL_LIBDIR}/libssl.so
  ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/
)
