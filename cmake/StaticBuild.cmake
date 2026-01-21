set(LIBICU_VERSION 74_2)
set(LIBICU_DASH_VERSION 74-2)
set(LIBICU_MIRROR https://github.com/unicode-org/icu/releases/download/release-${LIBICU_DASH_VERSION} CACHE STRING "libicu download mirror(s)")
set(LIBICU_SOURCE icu4c-${LIBICU_VERSION}-src.tgz)
set(LIBICU_HASH SHA512=e6c7876c0f3d756f3a6969cad9a8909e535eeaac352f3a721338b9cbd56864bf7414469d29ec843462997815d2ca9d0dab06d38c37cdd4d8feb28ad04d8781b0 CACHE STRING "libicu source hash")

include(ExternalProject)
set(DEPS_DESTDIR ${CMAKE_BINARY_DIR}/static-deps)
set(DEPS_SOURCEDIR ${CMAKE_BINARY_DIR}/static-deps-sources)
set(DEPS_CMAKE_MODS ${DEPS_DESTDIR}/cmake-static-modules)
file(MAKE_DIRECTORY ${DEPS_CMAKE_MODS})
list(INSERT CMAKE_MODULE_PATH 0 ${DEPS_CMAKE_MODS})

include_directories(BEFORE SYSTEM ${DEPS_DESTDIR}/include)

file(MAKE_DIRECTORY ${DEPS_DESTDIR}/include)

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
  target_link_libraries(${target} INTERFACE ${target})
  set_target_properties(${target} PROPERTIES
    IMPORTED_LOCATION ${DEPS_DESTDIR}/lib/${libname}
  )
  if(ARGN)
      target_link_libraries(${target} INTERFACE ${ARGN})
  endif()
endfunction()

set(libicu_cflags "${libicu_cflags} -O2 -fPIC")
set(libicu_cxxflags "${libicu_cxxflags} -O2 -fPIC")
set(cross_host "")
if(CMAKE_CROSSCOMPILING)
  if(APPLE AND NOT ARCH_TRIPLET AND APPLE_TARGET_TRIPLE)
    set(ARCH_TRIPLET "${APPLE_TARGET_TRIPLE}")
  endif()
  set(cross_host "--host=${ARCH_TRIPLET}")
endif()

set(deps_cc ${CMAKE_C_COMPILER})
set(deps_cxx ${CMAKE_CXX_COMPILER})
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
  set(deps_cxx "${ANDROID_TOOLCHAIN_ROOT}/bin/${android_compiler_prefix}-${android_compiler_suffix}-clang++")
endif()

if(CMAKE_C_COMPILER_LAUNCHER)
  set(deps_c "${CMAKE_C_COMPILER_LAUNCHER} ${deps_cc}")
endif()

if(CMAKE_CXX_COMPILER_LAUNCHER)
  set(deps_cxx "${CMAKE_CXX_COMPILER_LAUNCHER} ${deps_cxx}")
endif()

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

# Builds a target; takes the target name (e.g. "readline") and builds it in an external project with
# target name suffixed with `_external`.  Its upper-case value is used to get the download details
# (from the variables set above).  The following options are supported and passed through to
# ExternalProject_Add if specified.  If omitted, these defaults are used:
set(build_def_DEPENDS "")
set(build_def_PATCH_COMMAND "")
set(build_def_CONFIGURE_COMMAND ./configure ${cross_host} --disable-shared --prefix=${DEPS_DESTDIR} --with-pic
    "CC=${deps_cc}" "CFLAGS=${deps_CFLAGS}" ${cross_extra})
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

if(CMAKE_CROSSCOMPILING)
  if(ARCH_TRIPLET STREQUAL x86_64-w64-mingw32)
    set(cross_host mingw64)
    set(openssl_extra_env RC=${CMAKE_RC_COMPILER})
  elseif(ARCH_TRIPLET STREQUAL i686-w64-mingw32)
    set(cross_host mingw)
    set(openssl_extra_env RC=${CMAKE_RC_COMPILER})
  elseif(ANDROID)
    set(openssl_extra_opts -D__ANDROID_API__=${ANDROID_PLATFORM_LEVEL} no-asm)
    set(openssl_extra_env "ANDROID_NDK_ROOT=${CMAKE_ANDROID_NDK}" "PATH=${ANDROID_TOOLCHAIN_ROOT}/bin:$ENV{PATH}")
    set(deps_CFLAGS "${deps_CFLAGS} --sysroot=${ANDROID_TOOLCHAIN_ROOT}/sysroot")
    if(CMAKE_ANDROID_ARCH_ABI MATCHES x86_64 OR CMAKE_ANDROID_ARCH_ABI MATCHES x86)
        # NOTE: Sysroot isn't sufficient to find the asm/ folder sitting in the host-tagged folder
        #  /usr/lib/android-ndk/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/include/linux/types.h:9:10: fatal error: 'asm/types.h' file not found
        # At
        #  /usr/lib/android-ndk/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/include/x86_64-linux-android/asm/
        if(CMAKE_ANDROID_ARCH_ABI MATCHES x86_64)
            set(deps_CFLAGS "${deps_CFLAGS} -I${ANDROID_TOOLCHAIN_ROOT}/sysroot/usr/include/x86_64-linux-android")
        else()
            set(deps_CFLAGS "${deps_CFLAGS} -I${ANDROID_TOOLCHAIN_ROOT}/sysroot/usr/include/i686-linux-android")
        endif()
    endif()
  endif()
endif()

build_external(libicu
    LOG_CONFIGURE ON
    LOG_BUILD ON
    LOG_OUTPUT_ON_FAILURE ON
    CONFIGURE_COMMAND
        ./source/configure ${cross_host} --enable-static
        --disable-shared --disable-icu-config --disable-strict --disable-dyload --disable-icuio
        --disable-tests --disable-samples --with-data-packaging=static
        --prefix=${DEPS_DESTDIR} CC=${deps_cc} CXX=${deps_cxx}
        C_FLAGS=${apple_cflags_arch}${libicu_cflags}
        CXXFLAGS=${apple_cxxflags_arch}${libicu_cxxflags}
    BUILD_BYPRODUCTS
        ${DEPS_DESTDIR}/lib/libicudata.a
        ${DEPS_DESTDIR}/lib/libicui18n.a
        ${DEPS_DESTDIR}/lib/libicutest.a
        ${DEPS_DESTDIR}/lib/libicutu.a
        ${DEPS_DESTDIR}/lib/libicuuc.a
)
add_static_target(libicu::libicudata libicu_external libicudata.a)
add_static_target(libicu::libicui18n libicu_external libicui18n.a)
add_static_target(libicu::libicutest libicu_external libicutest.a)
add_static_target(libicu::libicutu   libicu_external libicutu.a)
add_static_target(libicu::libicuuc   libicu_external libicuuc.a)

add_library(libicu::libicu INTERFACE IMPORTED GLOBAL)
add_dependencies(libicu::libicu libicu_external)
set_target_properties(libicu::libicu PROPERTIES INTERFACE_INCLUDE_DIRECTORIES ${DEPS_DESTDIR}/include)
target_link_libraries(libicu::libicu INTERFACE libicu::libicui18n libicu::libicuuc libicu::libicudata)
