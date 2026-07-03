add_library(netcap_config STATIC
    parser.c
    validator.c
)

target_include_directories(netcap_config
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(netcap_config
    PUBLIC  netcap_core
    PRIVATE tomlc99          # vendored — third_party/tomlc99
)
