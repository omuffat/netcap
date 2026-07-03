find_package(ZLIB REQUIRED)

add_library(netcap_uploader STATIC
    uploader.c
    http_client.c
    auth.c
)

target_include_directories(netcap_uploader
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}
    PRIVATE ${NETCAP_CURL_INCLUDE_DIRS}
)

target_link_libraries(netcap_uploader
    PUBLIC
        netcap_core
        netcap_config
    PRIVATE
        ${NETCAP_CURL_LIBRARIES}
        ZLIB::ZLIB
)
