<<<<<<< HEAD
option(SUBMODULE_CHECK "Enables checking that vendored library submodules are up to date" ON)

if(SUBMODULE_CHECK)
  find_package(Git)
  if(GIT_FOUND)
    function(check_submodule relative_path)
      execute_process(COMMAND git rev-parse "HEAD" WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/${relative_path} OUTPUT_VARIABLE localHead)
      execute_process(COMMAND git rev-parse "HEAD:external/${relative_path}" WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} OUTPUT_VARIABLE checkedHead)
      string(COMPARE EQUAL "${localHead}" "${checkedHead}" upToDate)
      if (upToDate)
        message(STATUS "Submodule 'external/${relative_path}' is up-to-date")
      else()
        message(FATAL_ERROR "Submodule 'external/${relative_path}' is not up-to-date. Please update with\ngit submodule update --init --recursive\nor run cmake with -DSUBMODULE_CHECK=OFF")
      endif()

      # Extra arguments check nested submodules
      foreach(submod ${ARGN})
        execute_process(COMMAND git rev-parse "HEAD" WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/${relative_path}/${submod} OUTPUT_VARIABLE localHead)
        execute_process(COMMAND git rev-parse "HEAD:${submod}" WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/${relative_path} OUTPUT_VARIABLE checkedHead)
        string(COMPARE EQUAL "${localHead}" "${checkedHead}" upToDate)
        if (NOT upToDate)
            message(FATAL_ERROR "Nested submodule '${relative_path}/${submod}' is not up-to-date. Please update with\ngit submodule update --init --recursive\nor run cmake with -DSUBMODULE_CHECK=OFF")
        endif()
      endforeach()
    endfunction ()

    message(STATUS "Checking submodules")
    check_submodule(ios-cmake)
    check_submodule(libsodium-internal)
    check_submodule(zstd)
    check_submodule(protobuf)
    check_submodule(session-router)
    check_submodule(date)
  endif()
endif()
=======
include(../cmake/session-deps/Deps.cmake)

message(STATUS "Checking submodules")
check_submodule(ios-cmake)
check_submodule(oxen-libquic external/oxen-logging external/oxen-encoding)
check_submodule(nlohmann-json)
check_submodule(protobuf)
check_submodule(session-sqlite SQLiteCpp cmake/session-deps)
>>>>>>> 46a23593 (Refactor internal dependencies to use session-deps)

if(NOT BUILD_STATIC_DEPS AND NOT FORCE_ALL_SUBMODULES)
  find_package(PkgConfig REQUIRED)
endif()

<<<<<<< HEAD
macro(libsession_system_or_submodule BIGNAME smallname target pkgconf subdir)
  if(NOT TARGET ${target})
    option(FORCE_${BIGNAME}_SUBMODULE "force using ${smallname} submodule" OFF)
    if(NOT BUILD_STATIC_DEPS AND NOT FORCE_${BIGNAME}_SUBMODULE AND NOT FORCE_ALL_SUBMODULES)
      pkg_check_modules(${BIGNAME} ${pkgconf} IMPORTED_TARGET GLOBAL)
    endif()
    if(${BIGNAME}_FOUND)
      add_library(${smallname} INTERFACE IMPORTED GLOBAL)
      if(NOT TARGET PkgConfig::${BIGNAME} AND CMAKE_VERSION VERSION_LESS "3.21")
        # Work around cmake bug 22180 (PkgConfig::THING not set if no flags needed)
      else()
        target_link_libraries(${smallname} INTERFACE PkgConfig::${BIGNAME})
      endif()
      message(STATUS "Found system ${smallname} ${${BIGNAME}_VERSION}")
    else()
      message(STATUS "using ${smallname} submodule ${subdir}")
      add_subdirectory(${subdir})
    endif()
    if(NOT TARGET ${target})
      add_library(${target} ALIAS ${smallname})
    endif()
    if(BUILD_STATIC_DEPS AND STATIC_BUNDLE)
      libsession_static_bundle(${smallname}::${smallname})
    endif()
  endif()
endmacro()


set(deps_cc "${CMAKE_C_COMPILER}")
set(cross_host "")
set(cross_rc "")
if(CMAKE_CROSSCOMPILING)
    if(APPLE_TARGET_TRIPLE)
        set(cross_host "--host=${APPLE_TARGET_TRIPLE}")
    elseif(ANDROID)
        if(CMAKE_ANDROID_ARCH_ABI MATCHES x86_64)
            set(cross_host "--host=x86_64-linux-android")
            set(android_compiler_prefix x86_64)
            set(android_compiler_suffix linux-android)
        elseif(CMAKE_ANDROID_ARCH_ABI MATCHES x86)
            set(cross_host "--host=i686-linux-android")
            set(android_compiler_prefix i686)
            set(android_compiler_suffix linux-android)
        elseif(CMAKE_ANDROID_ARCH_ABI MATCHES armeabi-v7a)
            set(cross_host "--host=armv7a-linux-androideabi")
            set(android_compiler_prefix armv7a)
            set(android_compiler_suffix linux-androideabi)
        elseif(CMAKE_ANDROID_ARCH_ABI MATCHES arm64-v8a)
            set(cross_host "--host=aarch64-linux-android")
            set(android_compiler_prefix aarch64)
            set(android_compiler_suffix linux-android)
        else()
            message(FATAL_ERROR "unknown android arch: ${CMAKE_ANDROID_ARCH_ABI}")
        endif()

        string(REPLACE "android-" "" android_platform_num "${ANDROID_PLATFORM}")
        set(deps_cc "${ANDROID_TOOLCHAIN_ROOT}/bin/${android_compiler_prefix}-${android_compiler_suffix}${android_platform_num}-clang")
    else()
        set(cross_host "--host=${ARCH_TRIPLET}")
        if (ARCH_TRIPLET MATCHES mingw AND CMAKE_RC_COMPILER)
            set(cross_rc "WINDRES=${CMAKE_RC_COMPILER}")
        endif()
    endif()
endif()

if(ENABLE_NETWORKING)
  set(LIBQUIC_BUILD_TESTS OFF CACHE BOOL "")
  libsession_system_or_submodule(OXENQUIC quic oxen::quic liboxenquic>=1.8 session-router/external/oxen-libquic)
endif()

libsession_system_or_submodule(OXENC oxenc oxenc::oxenc liboxenc>=1.5.0 session-router/external/oxen-libquic/external/oxen-encoding)

libsession_system_or_submodule(OXENLOGGING oxenlogging oxen::logging liboxen-logging>=1.2.0 session-router/external/oxen-libquic/external/oxen-logging)
if(OXENLOGGING_FOUND)
    if(NOT TARGET oxen::logging)
        # If we load oxen-logging via system lib then we won't necessarily have fmt/spdlog targets,
        # but this script will give us them:
        include(session-router/external/oxen-libquic/external/oxen-logging/cmake/load_fmt_spdlog.cmake)

        add_library(oxen-logging-fmt-spdlog INTERFACE)
        target_link_libraries(oxen-logging-fmt-spdlog INTERFACE oxenlogging::oxenlogging ${OXEN_LOGGING_FMT_TARGET} ${OXEN_LOGGING_SPDLOG_TARGET})
        add_library(oxen::logging ALIAS oxen-logging-fmt-spdlog)
    endif()
=======
set(LIBQUIC_BUILD_TESTS OFF CACHE BOOL "")
if(ENABLE_ONIONREQ)
  sessiondep_or_submodule(liboxenquic 1.3.0 oxen-libquic quic)
endif()

if(NOT TARGET oxenc::oxenc)
    # The oxenc target will already exist if we load libquic above via submodule
    set(OXENC_BUILD_TESTS OFF CACHE BOOL "")
    set(OXENC_BUILD_DOCS OFF CACHE BOOL "")
    sessiondep_or_submodule(liboxenc 1.3.0 oxen-libquic/external/oxen-encoding oxenc::oxenc)
>>>>>>> 46a23593 (Refactor internal dependencies to use session-deps)
endif()



if(CMAKE_C_COMPILER_LAUNCHER)
  set(deps_cc "${CMAKE_C_COMPILER_LAUNCHER} ${deps_cc}")
endif()
set(deps_CFLAGS "-O2")

if(IPO_ENABLED)
  set(deps_CFLAGS "${deps_CFLAGS} -flto")
endif()

if(APPLE)
    foreach(lang C CXX)
        string(APPEND deps_${lang}FLAGS " ${CMAKE_${lang}_SYSROOT_FLAG} ${CMAKE_OSX_SYSROOT} ${CMAKE_${lang}_OSX_DEPLOYMENT_TARGET_FLAG}${CMAKE_OSX_DEPLOYMENT_TARGET}")
        foreach(arch ${CMAKE_OSX_ARCHITECTURES})
            string(APPEND deps_${lang}FLAGS " -arch ${arch}")
        endforeach()
    endforeach()
endif()

function(add_static_subdirectory dir)
    set(BUILD_SHARED_LIBS OFF)
    add_subdirectory(${dir} ${ARGN})
endfunction()

add_static_subdirectory(libsodium-internal)
libsession_static_bundle(libsodium::sodium-internal)


set(protobuf_VERBOSE ON CACHE BOOL "" FORCE)
set(protobuf_INSTALL ON CACHE BOOL "" FORCE)
set(protobuf_WITH_ZLIB OFF CACHE BOOL "" FORCE)
set(protobuf_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(protobuf_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(protobuf_BUILD_LIBPROTOC OFF CACHE BOOL "" FORCE)
set(protobuf_BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(protobuf_ABSL_PROVIDER "module" CACHE STRING "" FORCE)
set(protobuf_BUILD_PROTOC_BINARIES OFF CACHE BOOL "")
set(protobuf_BUILD_PROTOBUF_BINARIES ON CACHE BOOL "" FORCE)
sessiondep_or_submodule(protobuf-lite 3.21 protobuf protobuf::libprotobuf-lite)

# Force a static libzstd: we want semi-stable compressed output, which means we want all session
# clients to use the same version (where that is guaranteed) as much as possible, so that duplicate
# configs get deduplicated at the swarm.
set(BUILD_STATIC_libzstd ON CACHE BOOL "" FORCE)
session_dep(libzstd 1.5)
libsession_static_bundle(sessiondep::libzstd)


set(JSON_BuildTests OFF CACHE INTERNAL "")
set(JSON_Install ON CACHE INTERNAL "") # Required to export targets that we use
sessiondep_or_submodule(nlohmann_json 3.7.0 nlohmann-json nlohmann_json::nlohmann_json)

if(ENABLE_NETWORKING AND ENABLE_NETWORKING_SROUTER)
    set(SROUTER_FULL OFF CACHE BOOL "")
    set(SROUTER_DAEMON OFF CACHE BOOL "")
    set(SROUTER_NATIVE_BUILD OFF CACHE BOOL "")
    set(SROUTER_JEMALLOC OFF CACHE BOOL "")

    add_library(sodium INTERFACE)
    target_link_libraries(sodium INTERFACE libsodium::sodium-internal)
    add_static_subdirectory(session-router EXCLUDE_FROM_ALL)
    libsession_static_bundle(session-router::libsessionrouter)
endif()

session_dep(simdutf 7)
libsession_static_bundle(sessiondep::simdutf)

# We need Howard Hinnant's header-only date library for now because the STL implementation of
# std::chrono::parse() is spotty or broken on:
# - Apple.  libc++ date parsing is only available when on XCode 16.3+ *and* targetting macOS 15+.
# - gcc before 13.
# - clang+libc++ before llvm-19.  (Real 19, not Apple's idiotic PR renumbering).
#
# On the plus side, this is header-only so we don't actually compile anything extra if we don't
# actually use it.
add_subdirectory(date)
