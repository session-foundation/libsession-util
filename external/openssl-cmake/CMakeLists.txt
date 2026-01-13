set(LOCAL_MIRROR "" CACHE STRING "local mirror path/URL for lib downloads")

set(desired_version 3.5.4)
set(OPENSSL_VERSION ${desired_version} CACHE STRING "openssl version")

# NOTE: Workaround issue on CI where OpenSSL version seems to get blanked out on
# Debian 12 for some reason. Those machines have 3.0.18 found via pkgconfig
# which is insufficient and I suspect something there is blanking out the
# version causing this to fail that I can't figure out how to fix.
if(NOT OPENSSL_VERSION OR OPENSSL_VERSION STREQUAL "")
    set(OPENSSL_VERSION "${desired_version}" CACHE STRING "openssl version" FORCE)
endif()

set(OPENSSL_MIRROR ${LOCAL_MIRROR} https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION} CACHE STRING "openssl download mirror(s)")
set(OPENSSL_SOURCE openssl-${OPENSSL_VERSION}.tar.gz)
set(OPENSSL_HASH SHA256=967311f84955316969bdb1d8d4b983718ef42338639c621ec4c34fddef355e99
    CACHE STRING "openssl source hash")

set(DEPS_DESTDIR ${CMAKE_BINARY_DIR}/static-deps)
set(DEPS_SOURCEDIR ${CMAKE_BINARY_DIR}/static-deps-sources)
include_directories(BEFORE SYSTEM ${DEPS_DESTDIR}/include)
file(MAKE_DIRECTORY ${DEPS_DESTDIR}/include)

set(deps_cc "${CMAKE_C_COMPILER}")
set(deps_cxx "${CMAKE_CXX_COMPILER}")
if (ANDROID)
  if(NOT ANDROID_TOOLCHAIN_NAME)
    message(FATAL_ERROR "ANDROID_TOOLCHAIN_NAME not set; did you run with the proper android toolchain options?")
  endif()
  if(CMAKE_ANDROID_ARCH_ABI MATCHES x86_64)
    set(openssl_android_arch android-x86_64)
    set(android_clang x86_64-linux-android${ANDROID_PLATFORM_LEVEL}-clang)
  elseif(CMAKE_ANDROID_ARCH_ABI MATCHES x86)
    set(openssl_android_arch android-x86)
    set(android_clang i686-linux-android${ANDROID_PLATFORM_LEVEL}-clang)
  elseif(CMAKE_ANDROID_ARCH_ABI MATCHES armeabi-v7a)
    set(openssl_android_arch android-arm64)
    set(android_clang armv7a-linux-androideabi${ANDROID_PLATFORM_LEVEL}-clang)
  elseif(CMAKE_ANDROID_ARCH_ABI MATCHES arm64-v8a)
    set(openssl_android_arch android-arm64)
    set(android_clang aarch64-linux-android${ANDROID_PLATFORM_LEVEL}-clang)
  else()
    message(FATAL_ERROR "Don't know how to build for android arch abi ${CMAKE_ANDROID_ARCH_ABI}")
  endif()
  set(deps_cc "${ANDROID_TOOLCHAIN_ROOT}/bin/${android_clang}")
  set(deps_cxx "${deps_cc}++")
endif()

if(CMAKE_C_COMPILER_LAUNCHER)
  set(deps_cc "${CMAKE_C_COMPILER_LAUNCHER} ${deps_cc}")
endif()
if(CMAKE_CXX_COMPILER_LAUNCHER)
  set(deps_cxx "${CMAKE_CXX_COMPILER_LAUNCHER} ${deps_cxx}")
endif()

function(expand_urls output source_file)
  set(expanded)
  foreach(mirror ${ARGN})
    list(APPEND expanded "${mirror}/${source_file}")
  endforeach()
  set(${output} "${expanded}" PARENT_SCOPE)
endfunction()

function(add_static_target target ext_target libname)
  add_library(${target} STATIC IMPORTED GLOBAL)
  add_dependencies(${target} ${ext_target})
  set_target_properties(${target} PROPERTIES
    IMPORTED_LOCATION ${DEPS_DESTDIR}/lib/${libname}
  )
  if(ARGN)
    target_link_libraries(${target} INTERFACE ${ARGN})
  endif()
endfunction()

if(USE_LTO)
  set(flto "-flto")
else()
  set(flto "")
endif()

set(cross_host "")
set(cross_extra "")
if (ANDROID)
  set(cross_host "--host=${CMAKE_LIBRARY_ARCHITECTURE}")
  set(cross_extra "LD=${ANDROID_TOOLCHAIN_ROOT}/bin/${CMAKE_LIBRARY_ARCHITECTURE}-ld" "RANLIB=${CMAKE_RANLIB}" "AR=${CMAKE_AR}")
elseif(CMAKE_CROSSCOMPILING)
  if(APPLE)
    set(ARCH_TRIPLET "${APPLE_TARGET_TRIPLE}")
  endif()
  set(cross_host "--host=${ARCH_TRIPLET}")
  if (ARCH_TRIPLET MATCHES mingw AND CMAKE_RC_COMPILER)
    set(cross_extra "WINDRES=${CMAKE_RC_COMPILER}")
  endif()
endif()

set(apple_cflags_arch)
set(apple_cxxflags_arch)
set(apple_ldflags_arch)
set(sane_cross_host "${cross_host}")
if(APPLE AND CMAKE_CROSSCOMPILING)
    if(sane_cross_host MATCHES "^(.*-)ios([0-9.]+)(-.*)?$")
        set(sane_cross_host "${CMAKE_MATCH_1}darwin${CMAKE_MATCH_2}${CMAKE_MATCH_3}")
    endif()
    if(sane_cross_host MATCHES "^(.*)-simulator$")
        set(sane_cross_host "${CMAKE_MATCH_1}")
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
    set(build_host "--build=${CMAKE_LIBRARY_ARCHITECTURE}")
endif()

set(deps_CFLAGS "-O2 ${flto}")
set(deps_CXXFLAGS "-O2 ${flto}")
set(deps_noarch_CFLAGS "${deps_CFLAGS}")
set(deps_noarch_CXXFLAGS "${deps_CXXFLAGS}")

if(APPLE)
  foreach(lang C CXX)
    string(APPEND deps_${lang}FLAGS " ${CMAKE_${lang}_SYSROOT_FLAG} ${CMAKE_OSX_SYSROOT} ${CMAKE_${lang}_OSX_DEPLOYMENT_TARGET_FLAG}${CMAKE_OSX_DEPLOYMENT_TARGET}")

    set(deps_noarch_${lang}FLAGS "${deps_${lang}FLAGS}")

    foreach(arch ${CMAKE_OSX_ARCHITECTURES})
      string(APPEND deps_${lang}FLAGS " -arch ${arch}")
    endforeach()
  endforeach()
endif()

# Builds a target; takes the target name (e.g. "readline") and builds it in an external project with
# target name suffixed with `_external`.  Its upper-case value is used to get the download details
# (from the variables set above).  The following options are supported and passed through to
# ExternalProject_Add if specified.  If omitted, these defaults are used:
set(build_def_DEPENDS "")
set(build_def_PATCH_COMMAND "")
set(build_def_CONFIGURE_COMMAND ./configure ${sane_cross_host} --disable-shared --prefix=${DEPS_DESTDIR} --with-pic
    "CC=${deps_cc}" "CXX=${deps_cxx}" "CFLAGS=${deps_CFLAGS}" "CXXFLAGS=${deps_CXXFLAGS}" ${cross_extra})
set(build_def_BUILD_COMMAND make)
set(build_def_INSTALL_COMMAND make install)
set(build_def_BUILD_BYPRODUCTS ${DEPS_DESTDIR}/lib/lib___TARGET___.a ${DEPS_DESTDIR}/include/___TARGET___.h)
set(build_dep_TARGET_SUFFIX "")

function(build_external target)
  set(options TARGET_SUFFIX DEPENDS PATCH_COMMAND CONFIGURE_COMMAND BUILD_COMMAND INSTALL_COMMAND BUILD_BYPRODUCTS)
  cmake_parse_arguments(PARSE_ARGV 1 arg "" "" "${options}")
  foreach(o ${options})
    if(NOT DEFINED arg_${o})
      set(arg_${o} ${build_def_${o}})
    endif()
  endforeach()
  string(REPLACE ___TARGET___ ${target} arg_BUILD_BYPRODUCTS "${arg_BUILD_BYPRODUCTS}")

  set(externalproject_extra)
  if(NOT CMAKE_VERSION VERSION_LESS 3.24)
    # Default in cmake 3.24+ is to not extract timestamps for ExternalProject, which breaks pretty
    # much every autotools package (which thinks it must reconfigure) because timestamps got
    # updated).
    list(APPEND externalproject_extra DOWNLOAD_EXTRACT_TIMESTAMP ON)
  endif()

  string(TOUPPER "${target}" prefix)
  expand_urls(urls ${${prefix}_SOURCE} ${${prefix}_MIRROR})
  ExternalProject_Add("${target}${arg_TARGET_SUFFIX}_external"
    DEPENDS ${arg_DEPENDS}
    BUILD_IN_SOURCE ON
    PREFIX ${DEPS_SOURCEDIR}
    URL ${urls}
    URL_HASH ${${prefix}_HASH}
    DOWNLOAD_NO_PROGRESS ON
    PATCH_COMMAND ${arg_PATCH_COMMAND}
    CONFIGURE_COMMAND ${arg_CONFIGURE_COMMAND}
    BUILD_COMMAND ${arg_BUILD_COMMAND}
    INSTALL_COMMAND ${arg_INSTALL_COMMAND}
    BUILD_BYPRODUCTS ${arg_BUILD_BYPRODUCTS}
    ${externalproject_extra}
  )
endfunction()

if(NOT APPLE)
    if(CMAKE_CROSSCOMPILING)
      if(ARCH_TRIPLET STREQUAL x86_64-w64-mingw32)
        set(openssl_extra_opts mingw64 --cross-compile-prefix=x86_64-w64-mingw32-)
        set(deps_cc "")
      elseif(ARCH_TRIPLET STREQUAL i686-w64-mingw32)
        set(openssl_extra_opts mingw --cross-compile-prefix=i686-w64-mingw32-)
        set(deps_cc "")
      elseif(ANDROID)
        set(openssl_extra_opts ${openssl_android_arch} no-asm)
        set(openssl_extra_env ANDROID_NDK_ROOT=${CMAKE_ANDROID_NDK} PATH="${ANDROID_TOOLCHAIN_ROOT}/bin:$ENV{PATH}")
      endif()
    endif()
    build_external(openssl
      CONFIGURE_COMMAND ${CMAKE_COMMAND} -E env
        CC=${deps_cc}
        CFLAGS=${deps_CFLAGS}
        ${openssl_extra_env}
        ./Configure --prefix=${DEPS_DESTDIR} --libdir=lib ${openssl_extra_opts}
          no-shared no-capieng no-dso no-dtls1 no-ec_nistp_64_gcc_128 no-gost
          no-heartbeats no-md2 no-rc5 no-rdrand no-rfc3779 no-sctp no-ssl-trace no-ssl2 no-ssl3
          no-static-engine no-tests no-weak-ssl-ciphers no-zlib no-zlib-dynamic
      INSTALL_COMMAND make install_sw
      BUILD_BYPRODUCTS
        ${DEPS_DESTDIR}/lib/libssl.a ${DEPS_DESTDIR}/lib/libcrypto.a
        ${DEPS_DESTDIR}/include/openssl/ssl.h ${DEPS_DESTDIR}/include/openssl/crypto.h
    )
    add_static_target(OpenSSL::SSL openssl_external libssl.a)
    add_static_target(OpenSSL::Crypto openssl_external libcrypto.a)
    target_link_libraries(OpenSSL::SSL INTERFACE OpenSSL::Crypto)
    set(OPENSSL_ROOT_DIR ${DEPS_DESTDIR} CACHE PATH "" FORCE)

    # NOTE: FindOpenSSL defines OPENSSL_INCLUDE_DIR, we use pkg_check_modules which defines
    # OPENSSL_INCLUDE_DIRS, we define both for maximum compatibility...
    set(OPENSSL_INCLUDE_DIRS ${DEPS_DESTDIR}/include CACHE PATH "" FORCE)
    set(OPENSSL_INCLUDE_DIR ${DEPS_DESTDIR}/include CACHE PATH "" FORCE)

    # NOTE: Create <smallname> target so then libsession_system_or_submodule exports the
    # <smallname>::<smallname> target so that we can universally use that target for both PkgConfig
    # and non-pkconfig versions of OpenSSL.
    add_library(openssl INTERFACE)
    target_link_libraries(openssl INTERFACE OpenSSL::SSL OpenSSL::Crypto)
    target_include_directories(openssl INTERFACE ${OPENSSL_INCLUDE_DIRS})
endif()

