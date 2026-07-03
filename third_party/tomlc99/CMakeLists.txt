# Vendored tomlc99 — MIT licence — https://github.com/cktan/tomlc99
# Built as a static library so every consumer links a single copy.

add_library(tomlc99 STATIC toml.c)

target_include_directories(tomlc99
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
)

# toml.c uses POSIX functions (strdup, strndup) under C99/C11/C17 strict
# mode.  Expose them without switching the whole project to GNU dialect.
if(UNIX)
    target_compile_options(tomlc99 PRIVATE -D_POSIX_C_SOURCE=200809L)
endif()

# Suppress warnings that originate in third-party code.
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(tomlc99 PRIVATE
        -Wno-error
        -Wno-unused-parameter
        -Wno-sign-compare
    )
endif()
