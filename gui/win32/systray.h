#ifndef CN_SYSTRAY_WIN32_H
#define CN_SYSTRAY_WIN32_H

/*
 * Windows systray GUI for netcap — compiled as C++ (Win32 API or Qt).
 * Communicates with the netcap service via cn_ipc_client_t (core/ipc.h).
 */

#ifdef __cplusplus

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>

extern "C" {
#include "../../core/constants.h"
#include "../../core/ipc.h"
}

namespace netcap {

/**
 * Manages a Win32 NotifyIcon (taskbar tray icon) for the netcap GUI.
 *
 * Creates a hidden message-only window to receive WM_TASKBARCALLBACK events,
 * registers a NOTIFYICONDATA entry, and connects to the netcap service via
 * the IPC client. The icon tooltip and context menu items reflect the current
 * capture state reported by the service.
 *
 * Usage:
 *   SystrayWin32 tray(L"\\\\.\\pipe\\netcap");
 *   return tray.run();
 */
class SystrayWin32 {
public:
    /**
     * Initialize the tray icon and open a connection to the service.
     *
     * @param ipc_pipe_name  Named Pipe path, e.g. L"\\\\.\\pipe\\netcap".
     *                       Must not be nullptr.
     */
    explicit SystrayWin32(const wchar_t *ipc_pipe_name);

    ~SystrayWin32();

    /**
     * Enter the Win32 message loop.
     *
     * Blocks until the user selects "Exit" from the tray context menu or the
     * service closes the IPC connection. Returns the process exit code.
     */
    int run();

private:
    SystrayWin32(const SystrayWin32 &)            = delete;
    SystrayWin32 &operator=(const SystrayWin32 &) = delete;

    /* Window procedure (static, dispatches to the instance method). */
    static LRESULT CALLBACK wnd_proc(HWND hwnd, UINT msg,
                                     WPARAM wparam, LPARAM lparam);

    /* Handle a WM_TASKBARCALLBACK notification from the tray icon. */
    void on_tray_callback(LPARAM event);

    /* Rebuild the context menu to reflect current capture state. */
    void update_menu();

    HWND             m_hwnd;  /* Hidden message-only window for tray events. */
    NOTIFYICONDATAW  m_nid;   /* Win32 tray icon descriptor. */
    HMENU            m_menu;  /* Context menu shown on right-click. */
    cn_ipc_client_t *m_ipc;   /* Live connection to the netcap service. */
};

} /* namespace netcap */

#endif /* __cplusplus */

#endif /* CN_SYSTRAY_WIN32_H */
