add_library(netcap_core STATIC
    ring.c
    capture.c
    filter.c
    pcap_writer.c
    ipc.c
    str.c
    log.c
)

target_include_directories(netcap_core
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}
    PRIVATE ${NETCAP_PCAP_INCLUDE_DIR}
)

target_link_libraries(netcap_core
    PRIVATE ${NETCAP_PCAP_LIBRARY}
)

# _DEFAULT_SOURCE enables POSIX (nanosleep) and glibc BSD compat types
# (u_char, u_int, u_short) that pcap headers require on Linux with -std=c17.
# PUBLIC so that every target linking netcap_core inherits the definition.
if(UNIX)
    target_compile_definitions(netcap_core PUBLIC _DEFAULT_SOURCE)
endif()

# POSIX threading (not needed on Windows — pcap threads use Win32 API directly).
if(UNIX)
    target_link_libraries(netcap_core PRIVATE pthread)
endif()

# syslog is available on all POSIX targets (Linux, macOS).
# Defining CN_LOG_USE_SYSLOG enables the syslog sink in log.c.
if(UNIX)
    target_compile_definitions(netcap_core PUBLIC CN_LOG_USE_SYSLOG)
endif()
