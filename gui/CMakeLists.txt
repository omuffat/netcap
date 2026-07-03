# The GUI is platform-specific. Linux has no GUI; configuration is file-based.
if(WIN32)
    add_subdirectory(win32)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    add_subdirectory(macos)
else()
    message(STATUS "netcap GUI: disabled on Linux (TOML configuration only).")
endif()
