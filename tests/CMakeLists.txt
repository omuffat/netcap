enable_testing()

# ---------------------------------------------------------------------------
# Helper macro: declare a test executable and register it with CTest.
# ---------------------------------------------------------------------------

macro(netcap_add_test TEST_NAME SOURCE_FILE)
    add_executable(${TEST_NAME} ${SOURCE_FILE})
    target_include_directories(${TEST_NAME}
        PRIVATE ${CMAKE_SOURCE_DIR}
    )
    target_link_libraries(${TEST_NAME} PRIVATE ${ARGN})
    add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME})
endmacro()

# ---------------------------------------------------------------------------
# Test targets
# ---------------------------------------------------------------------------

netcap_add_test(test_ring        test_ring.c        netcap_core)
netcap_add_test(test_capture     test_capture.c     netcap_core)
netcap_add_test(test_config      test_config.c      netcap_config)
netcap_add_test(test_pcap_writer test_pcap_writer.c netcap_core)
netcap_add_test(test_filter      test_filter.c      netcap_core)
netcap_add_test(test_auth        test_auth.c        netcap_uploader)

# test_ipc requires pthread on Linux/macOS.
netcap_add_test(test_ipc test_ipc.c netcap_core)
if(NOT WIN32)
    target_link_libraries(test_ipc PRIVATE pthread)
endif()
