
function(check_target target)
    if (NOT TARGET ${target})
        message(FATAL_ERROR "Project failed to compile required target: ${target}")
    endif()
endfunction()

if (BUILD_SHARED_LIBS AND NOT BUILD_STATIC_DEPS)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(PROTOBUF_LITE protobuf-lite>=3.21 IMPORTED_TARGET)
    if(PROTOBUF_LITE_FOUND)
        add_library(protobuf_lite INTERFACE IMPORTED)
        target_link_libraries(protobuf_lite INTERFACE PkgConfig::PROTOBUF_LITE)
        add_library(protobuf::libprotobuf-lite ALIAS protobuf_lite)
    endif()
endif()

check_target(protobuf::libprotobuf-lite)
libsession_static_bundle(protobuf::libprotobuf-lite)


add_library(protos
    SessionProtos.pb.cc
    WebSocketResources.pb.cc)
target_include_directories(protos PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(protos PUBLIC protobuf::libprotobuf-lite)
set_target_properties(
    protos PROPERTIES
    OUTPUT_NAME session-protos
    SOVERSION ${LIBSESSION_LIBVERSION})

libsession_static_bundle(protos)

add_library(libsession::protos ALIAS protos)
export(
    TARGETS protos
    NAMESPACE libsession::
    FILE libsessionTargets.cmake
)
list(APPEND libsession_export_targets protos)
set(libsession_export_targets "${libsession_export_targets}" PARENT_SCOPE)


add_custom_target(regen-protobuf
    protoc --cpp_out=. SessionProtos.proto WebSocketResources.proto
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
)
