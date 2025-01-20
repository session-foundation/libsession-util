add_subdirectory(Catch2)

if(CMAKE_BUILD_TYPE STREQUAL "Release")
  add_definitions(-DRELEASE_BUILD)
endif()

set(LIB_SESSION_UTESTS_SOURCES
    test_blinding.cpp
    test_bt_merge.cpp
    test_bugs.cpp
    test_compression.cpp
    test_config_userprofile.cpp
    test_config_user_groups.cpp
    test_configdata.cpp
    test_config_contacts.cpp
    test_config_convo_info_volatile.cpp
    test_curve25519.cpp
    test_ed25519.cpp
    test_encrypt.cpp
    test_group_keys.cpp
    test_group_info.cpp
    test_group_members.cpp
    test_hash.cpp
    test_logging.cpp
    test_multi_encrypt.cpp
    test_proto.cpp
    test_random.cpp
    test_session_encrypt.cpp
    test_xed25519.cpp
)

if (ENABLE_ONIONREQ)
    list(APPEND LIB_SESSION_UTESTS_SOURCES test_network.cpp)
    list(APPEND LIB_SESSION_UTESTS_SOURCES test_onionreq.cpp)
endif()

add_executable(testAll ${LIB_SESSION_UTESTS_SOURCES})

add_library(Catch2Wrapper INTERFACE)
target_link_libraries(Catch2Wrapper INTERFACE Catch2::Catch2WithMain)

if(MSVC)
    target_compile_options(Catch2Wrapper INTERFACE /W0)
else()
    target_compile_options(Catch2Wrapper INTERFACE -w)
endif()

target_link_libraries(testAll PRIVATE
    libsession::config
    libsodium::sodium-internal
    nlohmann_json::nlohmann_json
    oxen::logging
    Catch2::Catch2WithMain)

if (ENABLE_ONIONREQ)
    target_link_libraries(testAll PRIVATE libsession::onionreq)
endif()

if(NOT TARGET check)
    add_custom_target(check COMMAND testAll)
endif()

add_executable(swarm-auth-test EXCLUDE_FROM_ALL swarm-auth-test.cpp)
target_link_libraries(swarm-auth-test PRIVATE config)

if(STATIC_BUNDLE)
    add_executable(static-bundle-test static_bundle.cpp)
    target_include_directories(static-bundle-test PUBLIC ../include)
    target_link_libraries(static-bundle-test PRIVATE "${PROJECT_BINARY_DIR}/libsession-util.a" oxenc::oxenc quic)
    add_dependencies(static-bundle-test session-util)
endif()
