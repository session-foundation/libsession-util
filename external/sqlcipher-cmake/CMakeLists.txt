cmake_minimum_required(VERSION 3.14)

project(sqlcipher-cmake LANGUAGES C)
include(ExternalProject)

set(SQLCIPHER_PREFIX ${CMAKE_CURRENT_BINARY_DIR}/install)
set(SQLCIPHER_LIBDIR ${SQLCIPHER_PREFIX}/lib)
set(SQLCIPHER_INCLUDEDIR ${SQLCIPHER_PREFIX}/include)
file(MAKE_DIRECTORY ${SQLCIPHER_INCLUDEDIR})

set(sqlcipher_cflags "${sqlcipher_cflags} -O2")
if(USE_LTO)
    string(APPEND sqlcipher_cflags "${sqlcipher_cflags} -flto")
endif()

set(cross_host "")
if(CMAKE_CROSSCOMPILING)
    if (APPLE)
        if(sane_cross_host MATCHES "^(.*-)ios([0-9.]+)(-.*)?$")
            set(cross_host "--host=${CMAKE_MATCH_1}darwin${CMAKE_MATCH_2}${CMAKE_MATCH_3}")
        endif()
        if(sane_cross_host MATCHES "^(.*)-simulator$")
            set(cross_host "--host=${CMAKE_MATCH_1}")
        endif()
    endif()
    if(CMAKE_SYSTEM_PROCESSOR)
        set(cross_host "--host=${CMAKE_SYSTEM_PROCESSOR}")
    endif()
endif()

set(sqlcipher_ldflags "")
set(sqlcipher_cflags "${sqlcipher_cflags} -DSQLITE_HAS_CODEC -DSQLITE_EXTRA_INIT=sqlcipher_extra_init -DSQLITE_EXTRA_SHUTDOWN=sqlcipher_extra_shutdown")
set(sqlcipher_link_libs "")

if(APPLE)
    set(sqlcipher_cflags "${sqlcipher_cflags} -DSQLCIPHER_CRYPTO_CC")
    list(APPEND sqlcipher_link_libs             "-framework Security" "-framework Foundation" "-framework CoreFoundation")
    set(sqlcipher_ldflags "${sqlcipher_ldflags}  -framework Security   -framework Foundation   -framework CoreFoundation")
else()
    set(sqlcipher_cflags "${sqlcipher_cflags} -DSQLCIPHER_CRYPTO_OPENSSL")
    list(APPEND sqlcipher_link_libs OpenSSL::SSL OpenSSL::Crypto)

    # NOTE: For example libraries are "/<blah>/lssl.so;/<blah>/lcrypto.so" the semicolon confuses
    # the linker so we remove the delimiter to make it compliant.
    string(REPLACE ";" " " OPENSSL_LIBRARIES_STR "${OPENSSL_LIBRARIES}")
    set(sqlcipher_ldflags "${sqlcipher_ldflags} ${OPENSSL_LIBRARIES_STR}")
endif()

ExternalProject_Add(sqlcipher_external
    SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/../sqlcipher
    CONFIGURE_COMMAND
            ${CMAKE_CURRENT_LIST_DIR}/../sqlcipher/configure ${cross_host} --disable-shared
            --enable-static --disable-tcl --disable-readline --fts5 --with-tempstore=always
            --prefix=${SQLCIPHER_PREFIX} CC=${CMAKE_C_COMPILER} CFLAGS=${sqlcipher_cflags}
            LDFLAGS=${sqlcipher_ldflags}
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
target_link_libraries(sqlcipher::sqlcipher      INTERFACE ${sqlcipher_link_libs})
