# Generates a database migration registry from a directory of migration files.
#
# Any file in the calling directory named NNN_*.sql or NNN_*.cpp is a one-time migration; see
# src/core/schema/README for the rules they follow.  This turns them into a
# `std::span<const session::core::schema::Migration>` named MIGRATIONS in the requested namespace,
# for passing to Core (as its own registry, or via a schema_extension option).
#
#   session_schema_dir(
#       TARGET <target>            # target the generated sources are compiled into
#       NAMESPACE <ns>             # namespace to define the registry in, e.g. session::core::schema
#       DECLARE_HEADER <header>    # header declaring `extern const std::span<const Migration>
#                                  # MIGRATIONS;` in that namespace, included by the generated
#                                  # definition so the two cannot drift apart
#   )
#
# Migration functions always take (session::sqlite::Connection&, session::core::Core&) regardless of
# which namespace they live in: the Migration type is Core's, and a layer above Core has no
# instance of itself to be handed during Core construction anyway.

set(SESSION_SCHEMA_TEMPLATE_DIR "${CMAKE_CURRENT_LIST_DIR}/schema")

function(session_schema_dir)
    cmake_parse_arguments(PARSE_ARGV 0 SCHEMA "" "TARGET;NAMESPACE;DECLARE_HEADER" "")

    foreach(required TARGET NAMESPACE DECLARE_HEADER)
        if(NOT SCHEMA_${required})
            message(FATAL_ERROR "session_schema_dir: ${required} is required")
        endif()
    endforeach()

    set(SCHEMA_NAMESPACE "${SCHEMA_NAMESPACE}")
    set(SCHEMA_DECLARE_HEADER "${SCHEMA_DECLARE_HEADER}")

    # Watch the directory so that adding or removing a migration re-runs CMake:
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ".")

    file(GLOB SCHEMA_FILES "[0-9]*.sql" "[0-9]*.cpp")

    # Order migrations by the name recorded in migrations_applied, not by filename: the extension
    # is not part of a migration's identity, and including it flips the order whenever one name is
    # a prefix of another, since "001_foo+002.sql" sorts before "001_foo.sql" ('+' is 0x2B, '.' is
    # 0x2E).
    #
    # Decorate, sort, undecorate.  The separator has to sort below every character a name can
    # contain or the prefix case breaks again one level down, so it is a control character rather
    # than any punctuation.
    string(ASCII 1 SCHEMA_SEP)
    list(TRANSFORM SCHEMA_FILES REPLACE "^(.*/)([^/]*)\\.(sql|cpp)$" "\\2${SCHEMA_SEP}\\1\\2.\\3"
        OUTPUT_VARIABLE SCHEMA_DECORATED)
    list(SORT SCHEMA_DECORATED)
    list(TRANSFORM SCHEMA_DECORATED REPLACE "^[^${SCHEMA_SEP}]*${SCHEMA_SEP}" ""
        OUTPUT_VARIABLE SCHEMA_FILES)

    set(DECLARATIONS "")
    set(SCHEMA_ENTRIES "")
    set(SCHEMA_SOURCES "")

    foreach(f IN LISTS SCHEMA_FILES)
        get_filename_component(filename "${f}" NAME)
        string(REGEX REPLACE "\\.(sql|cpp)$" "" basename "${filename}")
        if(CMAKE_MATCH_1 STREQUAL "sql")
            set(is_sql TRUE)
        else()
            set(is_sql FALSE)
        endif()

        # Watch individual files so edits trigger a re-configure:
        set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${f}")

        string(MAKE_C_IDENTIFIER "apply_${basename}" FUNC_NAME)
        if(is_sql)
            file(RELATIVE_PATH SCHEMA_FULL_FILENAME "${PROJECT_SOURCE_DIR}" "${f}")
            file(READ "${f}" SCHEMA_SQL)
            set(wrapper_cpp "${CMAKE_CURRENT_BINARY_DIR}/apply_schema__${basename}__sql.cpp")
            configure_file("${SESSION_SCHEMA_TEMPLATE_DIR}/apply_schema.cpp.in" "${wrapper_cpp}" @ONLY)
            list(APPEND SCHEMA_SOURCES "${wrapper_cpp}")
        else()
            list(APPEND SCHEMA_SOURCES "${f}")
        endif()

        string(APPEND DECLARATIONS "extern void ${FUNC_NAME}(session::sqlite::Connection&, session::core::Core&);\n")
        string(APPEND SCHEMA_ENTRIES "    session::core::schema::Migration{\"${basename}\", &${FUNC_NAME}},\n")
    endforeach()

    # An optional full_schema.sql holds the schema as it stands after every migration above.  A
    # database with none of this owner's migrations applied is built from it directly and has them
    # all recorded without running, so the file -- not the accumulated migration chain -- is what
    # anyone reads to see the current schema.  It has no numeric prefix, so the glob above skips it.
    set(SCHEMA_FULL "")
    set(full_schema "${CMAKE_CURRENT_SOURCE_DIR}/full_schema.sql")
    if(EXISTS "${full_schema}")
        set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${full_schema}")
        file(READ "${full_schema}" SCHEMA_FULL)
    endif()

    configure_file("${SESSION_SCHEMA_TEMPLATE_DIR}/schema_migrations.hpp.in"
        "${CMAKE_CURRENT_BINARY_DIR}/schema_migrations.hpp" @ONLY)
    configure_file("${SESSION_SCHEMA_TEMPLATE_DIR}/schema_registry.cpp.in"
        "${CMAKE_CURRENT_BINARY_DIR}/schema_registry.cpp" @ONLY)
    list(APPEND SCHEMA_SOURCES "${CMAKE_CURRENT_BINARY_DIR}/schema_registry.cpp")

    target_sources(${SCHEMA_TARGET} PRIVATE ${SCHEMA_SOURCES})
    # The generated wrappers include schema_migrations.hpp from alongside themselves.
    target_include_directories(${SCHEMA_TARGET} PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
endfunction()
