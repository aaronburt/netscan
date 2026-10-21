package main

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"github.com/aaronburt/netscan/internal/installer"
	"golang.org/x/sys/windows"
)

var (
	modUser32   = windows.NewLazySystemDLL("user32.dll")
	modComctl32 = windows.NewLazySystemDLL("comctl32.dll")
	modGdi32    = windows.NewLazySystemDLL("gdi32.dll")

	procRegisterClassExW      = modUser32.NewProc("RegisterClassExW")
	procCreateWindowExW       = modUser32.NewProc("CreateWindowExW")
	procDefWindowProcW        = modUser32.NewProc("DefWindowProcW")
	procShowWindow            = modUser32.NewProc("ShowWindow")
	procUpdateWindow          = modUser32.NewProc("UpdateWindow")
	procGetMessageW           = modUser32.NewProc("GetMessageW")
	procTranslateMessage      = modUser32.NewProc("TranslateMessage")
	procDispatchMessageW      = modUser32.NewProc("DispatchMessageW")
	procSendMessageW          = modUser32.NewProc("SendMessageW")
	procPostQuitMessage       = modUser32.NewProc("PostQuitMessage")
	procDestroyWindow         = modUser32.NewProc("DestroyWindow")
	procSetWindowTextW        = modUser32.NewProc("SetWindowTextW")
	procGetWindowTextW        = modUser32.NewProc("GetWindowTextW")
	procGetWindowTextLengthW  = modUser32.NewProc("GetWindowTextLengthW")
	procEnableWindow          = modUser32.NewProc("EnableWindow")
	procMessageBoxW           = modUser32.NewProc("MessageBoxW")
	procGetSystemMetrics      = modUser32.NewProc("GetSystemMetrics")
	procInitCommonControlsEx  = modComctl32.NewProc("InitCommonControlsEx")
	procCreateFontW           = modGdi32.NewProc("CreateFontW")
	procDeleteObject          = modGdi32.NewProc("DeleteObject")
)

const (
	WS_OVERLAPPED   = 0x00000000
	WS_CAPTION      = 0x00C00000
	WS_SYSMENU      = 0x00080000
	WS_MINIMIZEBOX  = 0x00020000
	WS_VISIBLE      = 0x10000000
	WS_CHILD        = 0x40000000
	WS_TABSTOP      = 0x00010000
	WS_BORDER       = 0x00800000
	BS_PUSHBUTTON   = 0x00000000
	BS_DEFPUSHBUTTON= 0x00000001
	BS_AUTOCHECKBOX = 0x00000003
	ES_AUTOHSCROLL  = 0x0080
	BM_GETCHECK     = 0x00F0
	BM_SETCHECK     = 0x00F1
	BST_CHECKED     = 1
	PBM_SETPOS      = 0x0402
	PBM_SETRANGE32  = 0x0406
	WM_COMMAND      = 0x0111
	WM_DESTROY      = 0x0002
	WM_SETFONT      = 0x0030
	WM_CLOSE        = 0x0010
	MB_OK           = 0x00000000
	MB_YESNO        = 0x00000004
	MB_ICONQUESTION = 0x00000020
	MB_ICONINFORMATION = 0x00000040
	MB_ICONERROR    = 0x00000010
	IDYES           = 6
	COLOR_WINDOW    = 5
	COLOR_BTNFACE   = 15
	SM_CXSCREEN     = 0
	SM_CYSCREEN     = 1
	ICC_PROGRESS_CLASS = 0x00000020
	FW_BOLD         = 700
	FW_NORMAL       = 400
	DEFAULT_CHARSET = 1
)

type WNDCLASSEXW struct {
	CbSize        uint32
	Style         uint32
	LpfnWndProc   uintptr
	CbClsExtra    int32
	CbWndExtra    int32
	HInstance     windows.Handle
	HIcon         windows.Handle
	HCursor       windows.Handle
	HbrBackground windows.Handle
	LpszMenuName  *uint16
	LpszClassName *uint16
	HIconSm       windows.Handle
}

type INITCOMMONCONTROLSEX struct {
	DwSize uint32
	DwICC  uint32
}

type MSG struct {
	Hwnd    windows.HWND
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      struct{ X, Y int32 }
}

var (
	hMainWnd       windows.HWND
	hTitleLabel    windows.HWND
	hSubtitleLabel windows.HWND
	hDirLabel      windows.HWND
	hDirEdit       windows.HWND
	hBrowseBtn     windows.HWND
	hChkDesktop    windows.HWND
	hChkStartMenu  windows.HWND
	hChkStartup    windows.HWND
	hChkLaunch     windows.HWND
	hStatusLabel   windows.HWND
	hProgressBar   windows.HWND
	hInstallBtn    windows.HWND
	hCancelBtn     windows.HWND

	hFontBold   windows.Handle
	hFontNormal windows.Handle

	isInstalling bool
	isFinished   bool
	installError error
)

const (
	ID_BROWSE_BTN  = 1001
	ID_INSTALL_BTN = 1002
	ID_CANCEL_BTN  = 1003
)

func runUninstallPrompt(silent bool) error {
	if silent {
		return installer.Uninstall()
	}

	title, _ := windows.UTF16PtrFromString("NetScan Uninstall")
	msg, _ := windows.UTF16PtrFromString("Are you sure you want to completely uninstall NetScan and all its components?")
	r, _, _ := procMessageBoxW.Call(
		0,
		uintptr(unsafe.Pointer(msg)),
		uintptr(unsafe.Pointer(title)),
		uintptr(MB_YESNO|MB_ICONQUESTION),
	)
	if r != IDYES {
		return nil
	}

	if err := installer.Uninstall(); err != nil {
		errMsg, _ := windows.UTF16PtrFromString("Uninstall encountered an error: " + err.Error())
		_, _, _ = procMessageBoxW.Call(0, uintptr(unsafe.Pointer(errMsg)), uintptr(unsafe.Pointer(title)), uintptr(MB_OK|MB_ICONERROR))
		return err
	}

	doneMsg, _ := windows.UTF16PtrFromString("NetScan was successfully removed from your computer.")
	_, _, _ = procMessageBoxW.Call(0, uintptr(unsafe.Pointer(doneMsg)), uintptr(unsafe.Pointer(title)), uintptr(MB_OK|MB_ICONINFORMATION))
	return nil
}

func runInstallerGUI(version string, initialOpts installer.Options) error {
	iccx := INITCOMMONCONTROLSEX{
		DwSize: uint32(unsafe.Sizeof(INITCOMMONCONTROLSEX{})),
		DwICC:  ICC_PROGRESS_CLASS,
	}
	_, _, _ = procInitCommonControlsEx.Call(uintptr(unsafe.Pointer(&iccx)))

	className, _ := windows.UTF16PtrFromString("NetScanInstallerClass")
	windowTitle, _ := windows.UTF16PtrFromString("NetScan Setup")

	segoe, _ := windows.UTF16PtrFromString("Segoe UI")
	rBold, _, _ := procCreateFontW.Call(
		uintptr(24), 0, 0, 0,
		uintptr(FW_BOLD),
		0, 0, 0,
		uintptr(DEFAULT_CHARSET),
		0, 0, 0, 0,
		uintptr(unsafe.Pointer(segoe)),
	)
	hFontBold = windows.Handle(rBold)

	rNorm, _, _ := procCreateFontW.Call(
		uintptr(16), 0, 0, 0,
		uintptr(FW_NORMAL),
		0, 0, 0,
		uintptr(DEFAULT_CHARSET),
		0, 0, 0, 0,
		uintptr(unsafe.Pointer(segoe)),
	)
	hFontNormal = windows.Handle(rNorm)

	wndProcCallback := syscall.NewCallback(wndProc)

	wc := WNDCLASSEXW{
		CbSize:        uint32(unsafe.Sizeof(WNDCLASSEXW{})),
		LpfnWndProc:   wndProcCallback,
		HInstance:     0,
		HbrBackground: windows.Handle(COLOR_BTNFACE + 1),
		LpszClassName: className,
	}
	_, _, _ = procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))

	width := int32(520)
	height := int32(430)
	rCX, _, _ := procGetSystemMetrics.Call(uintptr(SM_CXSCREEN))
	rCY, _, _ := procGetSystemMetrics.Call(uintptr(SM_CYSCREEN))
	x := (int32(rCX) - width) / 2
	y := (int32(rCY) - height) / 2

	rWnd, _, _ := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(windowTitle)),
		uintptr(WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_MINIMIZEBOX|WS_VISIBLE),
		uintptr(x),
		uintptr(y),
		uintptr(width),
		uintptr(height),
		0,
		0,
		0,
		0,
	)
	hMainWnd = windows.HWND(rWnd)
	if hMainWnd == 0 {
		return fmt.Errorf("failed to create window")
	}

	createControls(hMainWnd, initialOpts)

	_, _, _ = procShowWindow.Call(uintptr(hMainWnd), uintptr(windows.SW_SHOWNORMAL))
	_, _, _ = procUpdateWindow.Call(uintptr(hMainWnd))

	var msg MSG
	for {
		r, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
		_, _, _ = procTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
		_, _, _ = procDispatchMessageW.Call(uintptr(unsafe.Pointer(&msg)))
	}

	return installError
}

func createControls(parent windows.HWND, opts installer.Options) {
	staticClass, _ := windows.UTF16PtrFromString("STATIC")
	editClass, _ := windows.UTF16PtrFromString("EDIT")
	buttonClass, _ := windows.UTF16PtrFromString("BUTTON")
	progressClass, _ := windows.UTF16PtrFromString("msctls_progress32")

	hTitleLabel = createCtrl(staticClass, "NetScan Setup", WS_CHILD|WS_VISIBLE, 24, 18, 470, 28, parent, 0)
	applyFont(hTitleLabel, hFontBold)

	hSubtitleLabel = createCtrl(staticClass, "Network Stability & Micro-Drop Monitor", WS_CHILD|WS_VISIBLE, 24, 48, 470, 20, parent, 0)
	applyFont(hSubtitleLabel, hFontNormal)

	hDirLabel = createCtrl(staticClass, "Installation Folder:", WS_CHILD|WS_VISIBLE, 24, 82, 470, 18, parent, 0)
	applyFont(hDirLabel, hFontNormal)

	hDirEdit = createCtrl(editClass, opts.InstallDir, WS_CHILD|WS_VISIBLE|WS_BORDER|WS_TABSTOP|ES_AUTOHSCROLL, 24, 104, 370, 24, parent, 0)
	applyFont(hDirEdit, hFontNormal)

	hBrowseBtn = createCtrl(buttonClass, "Browse...", WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_PUSHBUTTON, 404, 103, 88, 26, parent, ID_BROWSE_BTN)
	applyFont(hBrowseBtn, hFontNormal)

	hChkDesktop = createCtrl(buttonClass, "Create a Desktop shortcut", WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_AUTOCHECKBOX, 24, 142, 450, 22, parent, 0)
	applyFont(hChkDesktop, hFontNormal)
	setCheck(hChkDesktop, opts.DesktopShortcut)

	hChkStartMenu = createCtrl(buttonClass, "Create a Start Menu shortcut", WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_AUTOCHECKBOX, 24, 168, 450, 22, parent, 0)
	applyFont(hChkStartMenu, hFontNormal)
	setCheck(hChkStartMenu, opts.StartMenuShortcut)

	hChkStartup = createCtrl(buttonClass, "Start NetScan automatically with Windows", WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_AUTOCHECKBOX, 24, 194, 450, 22, parent, 0)
	applyFont(hChkStartup, hFontNormal)
	setCheck(hChkStartup, opts.RunAtStartup)

	hChkLaunch = createCtrl(buttonClass, "Launch NetScan after installation", WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_AUTOCHECKBOX, 24, 220, 450, 22, parent, 0)
	applyFont(hChkLaunch, hFontNormal)
	setCheck(hChkLaunch, opts.LaunchAfterInstall)

	hStatusLabel = createCtrl(staticClass, "Ready to install.", WS_CHILD|WS_VISIBLE, 24, 262, 470, 20, parent, 0)
	applyFont(hStatusLabel, hFontNormal)

	hProgressBar = createCtrl(progressClass, "", WS_CHILD|WS_VISIBLE, 24, 286, 470, 18, parent, 0)
	_, _, _ = procSendMessageW.Call(uintptr(hProgressBar), uintptr(PBM_SETRANGE32), 0, 100)
	_, _, _ = procSendMessageW.Call(uintptr(hProgressBar), uintptr(PBM_SETPOS), 0, 0)

	hInstallBtn = createCtrl(buttonClass, "Install", WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_DEFPUSHBUTTON, 296, 335, 96, 30, parent, ID_INSTALL_BTN)
	applyFont(hInstallBtn, hFontNormal)

	hCancelBtn = createCtrl(buttonClass, "Cancel", WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_PUSHBUTTON, 400, 335, 94, 30, parent, ID_CANCEL_BTN)
	applyFont(hCancelBtn, hFontNormal)
}

func createCtrl(className *uint16, text string, style uint32, x, y, w, h int32, parent windows.HWND, id uintptr) windows.HWND {
	textPtr, _ := windows.UTF16PtrFromString(text)
	r, _, _ := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(textPtr)),
		uintptr(style),
		uintptr(x),
		uintptr(y),
		uintptr(w),
		uintptr(h),
		uintptr(parent),
		id,
		0,
		0,
	)
	return windows.HWND(r)
}

func applyFont(h windows.HWND, font windows.Handle) {
	_, _, _ = procSendMessageW.Call(uintptr(h), uintptr(WM_SETFONT), uintptr(font), 1)
}

func setCheck(h windows.HWND, checked bool) {
	v := uintptr(0)
	if checked {
		v = uintptr(BST_CHECKED)
	}
	_, _, _ = procSendMessageW.Call(uintptr(h), uintptr(BM_SETCHECK), v, 0)
}

func isChecked(h windows.HWND) bool {
	r, _, _ := procSendMessageW.Call(uintptr(h), uintptr(BM_GETCHECK), 0, 0)
	return r == uintptr(BST_CHECKED)
}

func getEditText(h windows.HWND) string {
	rLen, _, _ := procGetWindowTextLengthW.Call(uintptr(h))
	if rLen == 0 {
		return ""
	}
	buf := make([]uint16, rLen+1)
	_, _, _ = procGetWindowTextW.Call(uintptr(h), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	return windows.UTF16ToString(buf)
}

func setLabelText(h windows.HWND, text string) {
	p, _ := windows.UTF16PtrFromString(text)
	_, _, _ = procSetWindowTextW.Call(uintptr(h), uintptr(unsafe.Pointer(p)))
}

func wndProc(hwnd windows.HWND, msg uint32, wParam uintptr, lParam uintptr) uintptr {
	switch msg {
	case WM_COMMAND:
		id := wParam & 0xFFFF
		switch id {
		case ID_BROWSE_BTN:
			if !isInstalling && !isFinished {
				current := getEditText(hDirEdit)
				selected := pickFolder(current)
				if selected != "" {
					setLabelText(hDirEdit, selected)
				}
			}
			return 0

		case ID_CANCEL_BTN:
			if !isInstalling {
				_, _, _ = procDestroyWindow.Call(uintptr(hwnd))
			}
			return 0

		case ID_INSTALL_BTN:
			if isFinished {
				_, _, _ = procDestroyWindow.Call(uintptr(hwnd))
				return 0
			}
			if !isInstalling {
				startInstallation()
			}
			return 0
		}

	case WM_CLOSE:
		if !isInstalling {
			_, _, _ = procDestroyWindow.Call(uintptr(hwnd))
		}
		return 0

	case WM_DESTROY:
		if hFontBold != 0 {
			_, _, _ = procDeleteObject.Call(uintptr(hFontBold))
			hFontBold = 0
		}
		if hFontNormal != 0 {
			_, _, _ = procDeleteObject.Call(uintptr(hFontNormal))
			hFontNormal = 0
		}
		_, _, _ = procPostQuitMessage.Call(0)
		return 0
	}

	r, _, _ := procDefWindowProcW.Call(uintptr(hwnd), uintptr(msg), wParam, lParam)
	return r
}

func pickFolder(initial string) string {
	safe := strings.ReplaceAll(initial, "'", "''")
	script := fmt.Sprintf(
		`Add-Type -AssemblyName System.Windows.Forms; $f = New-Object System.Windows.Forms.FolderBrowserDialog; $f.SelectedPath = '%s'; $f.Description = 'Select NetScan Install Directory'; if ($f.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { Write-Output $f.SelectedPath }`,
		safe,
	)
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", script)
	cmd.SysProcAttr = &windows.SysProcAttr{CreationFlags: windows.CREATE_NO_WINDOW}
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func startInstallation() {
	targetDir := strings.TrimSpace(getEditText(hDirEdit))
	if targetDir == "" {
		targetDir = installer.DefaultInstallDir()
		setLabelText(hDirEdit, targetDir)
	}

	opts := installer.Options{
		InstallDir:         filepath.Clean(targetDir),
		DesktopShortcut:    isChecked(hChkDesktop),
		StartMenuShortcut:  isChecked(hChkStartMenu),
		RunAtStartup:       isChecked(hChkStartup),
		LaunchAfterInstall: isChecked(hChkLaunch),
		Silent:             false,
	}

	isInstalling = true
	_, _, _ = procEnableWindow.Call(uintptr(hInstallBtn), 0)
	_, _, _ = procEnableWindow.Call(uintptr(hCancelBtn), 0)
	_, _, _ = procEnableWindow.Call(uintptr(hBrowseBtn), 0)
	_, _, _ = procEnableWindow.Call(uintptr(hDirEdit), 0)
	_, _, _ = procEnableWindow.Call(uintptr(hChkDesktop), 0)
	_, _, _ = procEnableWindow.Call(uintptr(hChkStartMenu), 0)
	_, _, _ = procEnableWindow.Call(uintptr(hChkStartup), 0)
	_, _, _ = procEnableWindow.Call(uintptr(hChkLaunch), 0)

	go func() {
		err := installer.Install(opts, version, func(pct int, msg string) {
			_, _, _ = procSendMessageW.Call(uintptr(hProgressBar), uintptr(PBM_SETPOS), uintptr(pct), 0)
			setLabelText(hStatusLabel, msg)
		})

		installError = err
		isInstalling = false
		isFinished = true

		if err != nil {
			setLabelText(hStatusLabel, "Error: "+err.Error())
			setLabelText(hInstallBtn, "Close")
		} else {
			setLabelText(hStatusLabel, "Installation completed successfully!")
			setLabelText(hInstallBtn, "Finish")
		}
		_, _, _ = procEnableWindow.Call(uintptr(hInstallBtn), 1)
	}()
}
