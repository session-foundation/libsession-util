# Watch the current directory so CMake re-runs if files are added/removed:
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ".")

file(GLOB SCHEMA_FILES "[0-9]*.sql" "[0-9]*.cpp")
list(SORT SCHEMA_FILES)

set(DECLARATIONS "")
set(SCHEMA_ENTRIES "")
set(SCHEMA_SOURCES "")

foreach(f IN LISTS SCHEMA_FILES)
    get_filename_component(filename "${f}" NAME)
    string(REGEX REPLACE "\\.(sql|cpp)$" "" basename "${filename}")
    if(CMAKE_MATCH_1 STREQUAL "sql")
        set(is_sql TRUE)
        list(APPEND SQL_BASENAMES "${basename}")
    else()
        set(is_sql FALSE)
        list(APPEND CPP_BASENAMES "${basename}")
    endif()
    list(APPEND SCHEMA_BASENAMES "${basename}")

    # Watch individual files so edits trigger a re-configure:
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${f}")

    string(MAKE_C_IDENTIFIER "apply_${basename}" FUNC_NAME)
    if(is_sql)
        file(RELATIVE_PATH SCHEMA_FULL_FILENAME "${PROJECT_SOURCE_DIR}" "${f}")
        file(READ "${f}" SCHEMA_SQL)
        set(wrapper_cpp "${CMAKE_CURRENT_BINARY_DIR}/apply_schema__${basename}__sql.cpp")
        configure_file("apply_schema.cpp.in" "${wrapper_cpp}" @ONLY)
        list(APPEND SCHEMA_SOURCES "${wrapper_cpp}")
    else()
        list(APPEND SCHEMA_SOURCES "${f}")
    endif()

    string(APPEND DECLARATIONS "extern void ${FUNC_NAME}(session::sqlite::Connection&, session::core::Core&);\n")
    string(APPEND SCHEMA_ENTRIES "    Migration{\"${basename}\", &${FUNC_NAME}},\n")
endforeach()

# Write the generated header with all migration function declarations, then the registry .cpp:
configure_file("schema_migrations.hpp.in" "${CMAKE_CURRENT_BINARY_DIR}/schema_migrations.hpp" @ONLY)
configure_file("schema_registry.cpp.in" "${CMAKE_CURRENT_BINARY_DIR}/schema_registry.cpp" @ONLY)
list(APPEND SCHEMA_SOURCES "${CMAKE_CURRENT_BINARY_DIR}/schema_registry.cpp")

target_sources(core PRIVATE ${SCHEMA_SOURCES})
