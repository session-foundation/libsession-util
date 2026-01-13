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


set(sqlcipher_ldflags "")
set(sqlcipher_cflags "${sqlcipher_cflags} -DSQLITE_HAS_CODEC -DSQLITE_EXTRA_INIT=sqlcipher_extra_init -DSQLITE_EXTRA_SHUTDOWN=sqlcipher_extra_shutdown")

if(APPLE)
    set(sqlcipher_cflags "${sqlcipher_cflags} -DSQLCIPHER_CRYPTO_CC")
    set(sqlcipher_ldflags "-framework Security -framework Foundation -framework CoreFoundation")
else()
    set(sqlcipher_cflags "${sqlcipher_cflags} -DSQLCIPHER_CRYPTO_OPENSSL -I${OPENSSL_INCLUDE_DIRS}")
    # NOTE: For example libraries are "<blah>/libssl.so;/<blah>/libcrypto.so" the semicolon confuses
    # the linker so we remove the delimiter to make it compliant. Also note that -lm (math) is
    # needed if we choose OpenSSL as our encryption library for SQLCipher.
    string(REPLACE ";" " -l" OPENSSL_LIBRARIES_STR "-lcrypto -lssl}")
    if (TARGET openssl_external)
        set(sqlcipher_ldflags "-lm -L${OPENSSL_ROOT_DIR}/lib -lcrypto -lssl")
    else()
        set(sqlcipher_ldflags "-lm -lcrypto -lssl")
    endif()
endif()

if (ANDROID)
    # NOTE: SQLite uses __android_log_print and __android_log_write which is in their liblog library
    set(sqlcipher_ldflags "${sqlcipher_ldflags} -llog")
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
        --prefix=${SQLCIPHER_PREFIX} CC=${deps_cc} CFLAGS=${sqlcipher_cflags}
        LDFLAGS=${sqlcipher_ldflags} ${cross_rc}
    BUILD_COMMAND make lib
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
