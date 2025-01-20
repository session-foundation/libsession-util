
set(LIBSESSION_STATIC_BUNDLE_LIBS "" CACHE INTERNAL "list of libs to go into the static bundle lib")

function(_libsession_static_bundle_append tgt)
    list(APPEND LIBSESSION_STATIC_BUNDLE_LIBS "${tgt}")
    set(LIBSESSION_STATIC_BUNDLE_LIBS "${LIBSESSION_STATIC_BUNDLE_LIBS}" CACHE INTERNAL "")
endfunction()

# Call as:
#
#     libsession_static_bundle(target [target2 ...])
#
# to append the given target(s) to the list of libraries that will be combined to make the static
# bundled libsession-util.a.
function(libsession_static_bundle)
    foreach(tgt IN LISTS ARGN)
        if(TARGET "${tgt}" AND NOT "${tgt}" IN_LIST LIBSESSION_STATIC_BUNDLE_LIBS)
            get_target_property(tgt_type ${tgt} TYPE)
            
            if(tgt_type STREQUAL STATIC_LIBRARY)
                message(STATUS "Adding ${tgt} to libsession-util bundled library list")
                _libsession_static_bundle_append("${tgt}")
            endif()

            if(tgt_type STREQUAL INTERFACE_LIBRARY)
                get_target_property(tgt_link_deps ${tgt} INTERFACE_LINK_LIBRARIES)
            else()
                get_target_property(tgt_link_deps ${tgt} LINK_LIBRARIES)
            endif()

            if(tgt_link_deps)
                libsession_static_bundle(${tgt_link_deps})
            endif()
        endif()
    endforeach()
endfunction()
