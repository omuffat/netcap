/*
 * macOS systray GUI for netcap — compiled as Objective-C++ (.mm).
 * Communicates with the netcap service via cn_ipc_client_t (core/ipc.h).
 */

#ifndef CN_SYSTRAY_MACOS_H
#define CN_SYSTRAY_MACOS_H

#ifdef __OBJC__

#import <Cocoa/Cocoa.h>
#import <AppKit/AppKit.h>

#include "../../core/constants.h"
#include "../../core/ipc.h"

/**
 * Application delegate that manages an NSStatusItem (menu bar icon) for netcap.
 *
 * Connects to the netcap service via cn_ipc_client_t on the Unix socket
 * configured in the TOML file. Reflects current capture state in the menu bar
 * icon image and the NSMenu items. IPC messages are received on a background
 * GCD queue and dispatched to the main queue for UI updates.
 */
@interface CNAppDelegate : NSObject <NSApplicationDelegate>

/**
 * Designated initializer.
 *
 * @param socketPath  Absolute path to the Unix domain socket used by the
 *                    netcap service. Must not be nil. Length < CN_PATH_MAX.
 */
- (instancetype)initWithSocketPath:(NSString *)socketPath
    NS_DESIGNATED_INITIALIZER;

/** Unavailable: use initWithSocketPath: instead. */
- (instancetype)init NS_UNAVAILABLE;

@end

#endif /* __OBJC__ */

#endif /* CN_SYSTRAY_MACOS_H */
