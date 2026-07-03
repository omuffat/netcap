# .mm extension triggers the Objective-C++ compiler automatically.
add_executable(netcap_gui MACOSX_BUNDLE
    systray.mm
)

set_target_properties(netcap_gui PROPERTIES
    MACOSX_BUNDLE_BUNDLE_NAME      "netcap"
    MACOSX_BUNDLE_GUI_IDENTIFIER   "com.netcap.gui"
    MACOSX_BUNDLE_SHORT_VERSION_STRING "1.0"
)

target_include_directories(netcap_gui
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(netcap_gui
    PRIVATE
        netcap_core
        "-framework Cocoa"
        "-framework AppKit"
)
