add_executable(netcapd
    main.c
    caps.c
    savefile.c
    upload_queue.c
)

# Platform-specific daemon integration source
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_sources(netcapd PRIVATE systemd.c)
    # libcap is required for CAP_NET_RAW drop via cap_set_proc().
    target_link_libraries(netcapd PRIVATE cap)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    target_sources(netcapd PRIVATE launchd.c)
elseif(WIN32)
    target_sources(netcapd PRIVATE winsvc.c)
    # Winsock2 is required for getaddrinfo / InetNtop.
    target_link_libraries(netcapd PRIVATE ws2_32)
endif()

target_include_directories(netcapd
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(netcapd
    PRIVATE
        netcap_core
        netcap_config
        netcap_uploader
)
