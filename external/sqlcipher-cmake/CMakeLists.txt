cmake_minimum_required(VERSION 3.14)

project(sqlcipher-cmake LANGUAGES C)
include(ExternalProject)

set(SQLCIPHER_PREFIX ${CMAKE_CURRENT_BINARY_DIR}/install)
set(SQLCIPHER_LIBDIR ${SQLCIPHER_PREFIX}/lib)
set(SQLCIPHER_INCLUDEDIR ${SQLCIPHER_PREFIX}/include)
file(MAKE_DIRECTORY ${SQLCIPHER_INCLUDEDIR})

# NOTE: Detect if openssl is being built locally for libsession, if so this build step depends on
# that first before proceeding
set(sqlcipher_depends)
if (NOT APPLE AND TARGET openssl_external)
    set(sqlcipher_depends openssl_external)
endif()

set(sqlcipher_cflags "${sqlcipher_cflags} -O2")
if(USE_LTO)
    string(APPEND sqlcipher_cflags "${sqlcipher_cflags} -flto")
endif()

set(cross_host "")
set(cross_rc "")
if(CMAKE_CROSSCOMPILING)
  if(APPLE AND NOT ARCH_TRIPLET AND APPLE_TARGET_TRIPLE)
    set(ARCH_TRIPLET "${APPLE_TARGET_TRIPLE}")
  endif()
  set(cross_host "--host=${ARCH_TRIPLET}")
  if (ARCH_TRIPLET MATCHES mingw AND CMAKE_RC_COMPILER)
    set(cross_rc "WINDRES=${CMAKE_RC_COMPILER}")
  endif()
endif()

set(deps_cc ${CMAKE_C_COMPILER})
if(CMAKE_C_COMPILER_LAUNCHER)
  set(deps_cc "${CMAKE_C_COMPILER_LAUNCHER} ${deps_cc}")
endif()
if(ANDROID)
  set(android_toolchain_suffix linux-android)
  set(android_compiler_suffix linux-android${ANDROID_PLATFORM_LEVEL})
  if(CMAKE_ANDROID_ARCH_ABI MATCHES x86_64)
    set(cross_host "--host=x86_64-linux-android")
    set(android_compiler_prefix x86_64)
    set(android_compiler_suffix linux-android${ANDROID_PLATFORM_LEVEL})
    set(android_toolchain_prefix x86_64)
    set(android_toolchain_suffix linux-android)
  elseif(CMAKE_ANDROID_ARCH_ABI MATCHES x86)
    set(cross_host "--host=i686-linux-android")
    set(android_compiler_prefix i686)
    set(android_compiler_suffix linux-android${ANDROID_PLATFORM_LEVEL})
    set(android_toolchain_prefix i686)
    set(android_toolchain_suffix linux-android)
  elseif(CMAKE_ANDROID_ARCH_ABI MATCHES armeabi-v7a)
    set(cross_host "--host=armv7a-linux-androideabi")
    set(android_compiler_prefix armv7a)
    set(android_compiler_suffix linux-androideabi${ANDROID_PLATFORM_LEVEL})
    set(android_toolchain_prefix arm)
    set(android_toolchain_suffix linux-androideabi)
  elseif(CMAKE_ANDROID_ARCH_ABI MATCHES arm64-v8a)
    set(cross_host "--host=aarch64-linux-android")
    set(android_compiler_prefix aarch64)
    set(android_compiler_suffix linux-android${ANDROID_PLATFORM_LEVEL})
    set(android_toolchain_prefix aarch64)
    set(android_toolchain_suffix linux-android)
  else()
    message(FATAL_ERROR "unknown android arch: ${CMAKE_ANDROID_ARCH_ABI}")
  endif()
  set(deps_cc "${ANDROID_TOOLCHAIN_ROOT}/bin/${android_compiler_prefix}-${android_compiler_suffix}-clang")
endif()

set(deps_CFLAGS "-O2")
set(deps_CXXFLAGS "-O2")

set(apple_cflags_arch)
set(apple_cxxflags_arch)
set(apple_ldflags_arch)
if(APPLE AND CMAKE_CROSSCOMPILING)
    if(cross_host MATCHES "^(.*-.*-)ios([0-9.]+)(-.*)?$")
        set(cross_host "${CMAKE_MATCH_1}darwin${CMAKE_MATCH_2}${CMAKE_MATCH_3}")
    endif()
    if(cross_host MATCHES "^(.*-.*-.*)-simulator$")
        set(cross_host "${CMAKE_MATCH_1}")
    endif()

    set(apple_arch)
    if(ARCH_TRIPLET MATCHES "^(arm|aarch)64.*")
        set(apple_arch "arm64")
    elseif(ARCH_TRIPLET MATCHES "^x86_64.*")
        set(apple_arch "x86_64")
    else()
        message(FATAL_ERROR "Don't know how to specify -arch for GMP for ${ARCH_TRIPLET} (${APPLE_TARGET_TRIPLE})")
    endif()

    set(apple_cflags_arch " -arch ${apple_arch}")
    set(apple_cxxflags_arch " -arch ${apple_arch}")
    if(CMAKE_OSX_DEPLOYMENT_TARGET)
      if (SDK_NAME)
        set(apple_ldflags_arch " -m${SDK_NAME}-version-min=${CMAKE_OSX_DEPLOYMENT_TARGET}")
      elseif(CMAKE_OSX_DEPLOYMENT_TARGET)
        set(apple_ldflags_arch " -mmacosx-version-min=${CMAKE_OSX_DEPLOYMENT_TARGET}")
      endif()
    endif()
    set(apple_ldflags_arch "${apple_ldflags_arch} -arch ${apple_arch}")

    if(CMAKE_OSX_SYSROOT)
      foreach(f c cxx ld)
        set(apple_${f}flags_arch "${apple_${f}flags_arch} -isysroot ${CMAKE_OSX_SYSROOT}")
      endforeach()
    endif()
elseif(cross_host STREQUAL "" AND CMAKE_LIBRARY_ARCHITECTURE)
    set(cross_host "--build=${CMAKE_LIBRARY_ARCHITECTURE}")
endif()

set(sqlcipher_ldflags "")
set(sqlcipher_cflags "${sqlcipher_cflags} -DSQLITE_HAS_CODEC -DSQLITE_EXTRA_INIT=sqlcipher_extra_init -DSQLITE_EXTRA_SHUTDOWN=sqlcipher_extra_shutdown")

if(APPLE)
    set(sqlcipher_cflags "${sqlcipher_cflags} -DSQLCIPHER_CRYPTO_CC")
    set(sqlcipher_ldflags "${sqlcipher_ldflags} -framework Security -framework Foundation -framework CoreFoundation")
else()
    if(WIN32)
        # TODO: I'm unable to stop SQLCipher from building sqlite3.exe in the mingw cross-compile
        # so we need to augment that executable with some Window's libraries to get us through...
        set(sqlcipher_ldflags "${sqlcipher_ldflags} -lws2_32 -lcrypt32")
    endif()

    if(ANDROID)
        # NOTE: SQLite uses __android_log_print and __android_log_write which is in their liblog library
        set(sqlcipher_ldflags "${sqlcipher_ldflags} -llog")
    else()
        # NOTE: Apparently Android doesn't ship libmath, it's included in glibc itself
        set(sqlcipher_ldflags "${sqlcipher_ldflags} -lm")
    endif()

    set(sqlcipher_cflags "${sqlcipher_cflags} -DSQLCIPHER_CRYPTO_OPENSSL -I${OPENSSL_INCLUDE_DIRS}")
    if (TARGET openssl_external)
        set(sqlcipher_ldflags "${sqlcipher_ldflags} -L${OPENSSL_ROOT_DIR}/lib -lcrypto -lssl")
    else()
        set(sqlcipher_ldflags "${sqlcipher_ldflags} -lcrypto -lssl")
    endif()

endif()

ExternalProject_Add(sqlcipher_external
    SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/../sqlcipher
    DEPENDS ${sqlcipher_depends}
    LOG_CONFIGURE ON
    LOG_BUILD ON
    LOG_OUTPUT_ON_FAILURE ON
    CONFIGURE_COMMAND
        ${CMAKE_CURRENT_LIST_DIR}/../sqlcipher/configure ${cross_host} --disable-shared
        --enable-static --disable-tcl --disable-readline --fts5 --with-tempstore=always
        --prefix=${SQLCIPHER_PREFIX} CC=${deps_cc} CFLAGS=${apple_cflags_arch}${sqlcipher_cflags}
        LDFLAGS=${apple_ldflags_arch}${sqlcipher_ldflags} ${cross_rc}
    BUILD_COMMAND make libsqlite3.a
    INSTALL_COMMAND make install-lib install-headers
    BUILD_BYPRODUCTS
        ${SQLCIPHER_LIBDIR}/libsqlite3.a
)

add_library(sqlcipher::sqlcipher STATIC IMPORTED GLOBAL)
add_dependencies(sqlcipher::sqlcipher sqlcipher_external)
set_target_properties(sqlcipher::sqlcipher PROPERTIES
    IMPORTED_LOCATION ${SQLCIPHER_LIBDIR}/libsqlite3.a
    INTERFACE_INCLUDE_DIRECTORIES ${SQLCIPHER_INCLUDEDIR}
)
target_compile_definitions(sqlcipher::sqlcipher INTERFACE SQLITE_HAS_CODEC)
if(APPLE)
    target_link_libraries(sqlcipher::sqlcipher INTERFACE "-framework Security" "-framework Foundation" "-framework CoreFoundation")
else()
    target_link_libraries(sqlcipher::sqlcipher INTERFACE openssl::openssl)
    if (WIN32 OR MINGW)
        target_link_libraries(sqlcipher::sqlcipher INTERFACE ws2_32 crypt32)
    endif()
endif()
