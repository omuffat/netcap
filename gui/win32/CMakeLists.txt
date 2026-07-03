# WIN32 keyword suppresses the console window; the app is event-loop driven.
add_executable(netcap_gui WIN32
    systray.cpp
)

target_include_directories(netcap_gui
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(netcap_gui
    PRIVATE
        netcap_core
        shell32    # Shell_NotifyIconW, etc.
        user32     # CreateWindowExW, message loop
        comctl32   # Common controls (icons, menus)
)
