add_executable(netcap-ctl
    netcap-ctl.c
)

target_include_directories(netcap-ctl
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(netcap-ctl
    PRIVATE
        netcap_core
        netcap_config
        netcap_uploader
)
