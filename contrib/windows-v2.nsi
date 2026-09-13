; Protected, machine-wide v2 payload. No legacy product lookup or uninstaller.
Unicode true
!include "MUI2.nsh"
!include "x64.nsh"
Name "Ekubo Wallet 2"
OutFile "..\target\release\ekubo-wallet-v2_${VERSION}_x64-setup.exe"
InstallDir "$PROGRAMFILES64\Ekubo Wallet 2"
RequestExecutionLevel admin
VIProductVersion "${VERSION}.0"
VIAddVersionKey "ProductName" "Ekubo Wallet 2"
VIAddVersionKey "ProductVersion" "${VERSION}"
VIAddVersionKey "FileVersion" "${VERSION}"
VIAddVersionKey "FileDescription" "Ekubo Wallet 2 installer"
VIAddVersionKey "LegalCopyright" "Ekubo, Inc."
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

; ExecToLog writes only to NSIS's details list, which does not exist under /S.
; Retain the bounded child output and also forward it to the caller's inherited
; stdout handle. The smoke runner owns that pipe/file: no elevated arbitrary
; logfile path or environment-controlled destination is introduced here.
!macro Lifecycle MODE SCRIPT
  ; A native intermediary otherwise carries PowerShell 7's module paths into
  ; Windows PowerShell 5, breaking Security module loading (and allowing user
  ; module paths into this privileged operation). This changes only our process.
  System::Call 'kernel32::SetEnvironmentVariableW(w "PSModulePath", w "$WINDIR\System32\WindowsPowerShell\v1.0\Modules") i.r6'
  StrCmp $6 0 0 +3
    SetErrorLevel 1
    Abort "Could not select the system PowerShell modules."
  nsExec::ExecToStack '"$WINDIR\Sysnative\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "${SCRIPT}" -Mode ${MODE}'
  Pop $0
  Pop $1
  DetailPrint "V2 lifecycle ${MODE}: exit=$0; $1"
  System::Call 'kernel32::GetStdHandle(i -11) p.r2'
  ; Match PowerShell 7's redirected stdout reader with explicit UTF-8 bytes.
  StrCpy $1 "V2 lifecycle ${MODE}: exit=$0; $1$\r$\nPS=$WINDIR\Sysnative\WindowsPowerShell\v1.0\powershell.exe; script=${SCRIPT}$\r$\n"
  System::Call 'kernel32::WideCharToMultiByte(i 65001, i 0, w r1, i -1, p 0, i 0, p 0, p 0) i.r3'
  System::Alloc $3
  Pop $4
  System::Call 'kernel32::WideCharToMultiByte(i 65001, i 0, w r1, i -1, p r4, i r3, p 0, p 0)'
  IntOp $3 $3 - 1
  System::Call 'kernel32::WriteFile(p r2, p r4, i r3, *i.r5, p 0)'
  System::Free $4
  StrCmp $0 0 +3
    SetErrorLevel 1
    Abort "V2 lifecycle ${MODE} failed (exit $0). See installer diagnostic output."
!macroend

Function .onInit
  ${IfNot} ${RunningX64}
    Abort "Ekubo Wallet 2 requires 64-bit Windows."
  ${EndIf}
  SetRegView 64
  ClearErrors
  ReadRegStr $0 HKLM "SOFTWARE\Microsoft\Windows NT\CurrentVersion" "CurrentBuildNumber"
  IfErrors unsupported_windows
  IntCmpU $0 22000 supported_windows unsupported_windows supported_windows
unsupported_windows:
  Abort "Ekubo Wallet 2 requires Windows 11 (build 22000 or later) and Windows Hello. Existing 1.x installations are unchanged."
supported_windows:
  ; /D cannot redirect protected service code into an owner-writable directory.
  StrCpy $INSTDIR "$PROGRAMFILES64\Ekubo Wallet 2"
FunctionEnd

Section "Install"
  SetShellVarContext all
  StrCpy $INSTDIR "$PROGRAMFILES64\Ekubo Wallet 2"
  InitPluginsDir
  SetOutPath "$PLUGINSDIR"
  File "package-windows-v2.ps1"
  !insertmacro Lifecycle Before "$PLUGINSDIR\package-windows-v2.ps1"
  SetOutPath "$INSTDIR"
  File "..\target\release\ekubo-wallet-v2.exe"
  File "..\target\release\ekubo-wallet-v2-mcp-bridge.exe"
  File "..\target\release\ekubo-wallet-service.exe"
  File "..\target\release\ekubo-wallet-v2-owner-auth.exe"
  File "..\target\release\ekubo-wallet-v2-enroll.exe"
  File "install-windows-v2.ps1"
  File "recover-windows-v2.ps1"
  File "register-windows-v2-auth.ps1"
  File "package-windows-v2.ps1"
  SetOutPath "$INSTDIR\schemas"
  File /r "..\schemas\*"
  WriteUninstaller "$INSTDIR\uninstall.exe"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\org.ekubo.wallet.v2" "DisplayName" "Ekubo Wallet 2"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\org.ekubo.wallet.v2" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\org.ekubo.wallet.v2" "UninstallString" '"$INSTDIR\uninstall.exe"'
  CreateShortcut "$SMPROGRAMS\Ekubo Wallet 2.lnk" "$INSTDIR\ekubo-wallet-v2.exe"
  ; Toast identity is installer-owned; desktop startup does not write registry state.
  WriteRegStr HKLM "Software\Classes\AppUserModelId\org.ekubo.wallet.v2" "DisplayName" "Ekubo Wallet 2"
  !insertmacro Lifecycle After "$INSTDIR\package-windows-v2.ps1"
SectionEnd

Section "Uninstall"
  SetRegView 64
  SetShellVarContext all
  StrCpy $INSTDIR "$PROGRAMFILES64\Ekubo Wallet 2"
  !insertmacro Lifecycle Remove "$INSTDIR\package-windows-v2.ps1"
  Delete "$SMPROGRAMS\Ekubo Wallet 2.lnk"
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\org.ekubo.wallet.v2"
  DeleteRegKey HKLM "Software\Classes\AppUserModelId\org.ekubo.wallet.v2"
  Delete "$INSTDIR\ekubo-wallet-v2.exe"
  Delete "$INSTDIR\ekubo-wallet-v2-mcp-bridge.exe"
  Delete "$INSTDIR\ekubo-wallet-service.exe"
  Delete "$INSTDIR\ekubo-wallet-v2-owner-auth.exe"
  Delete "$INSTDIR\ekubo-wallet-v2-enroll.exe"
  Delete "$INSTDIR\install-windows-v2.ps1"
  Delete "$INSTDIR\recover-windows-v2.ps1"
  Delete "$INSTDIR\register-windows-v2-auth.ps1"
  Delete "$INSTDIR\package-windows-v2.ps1"
  RMDir /r "$INSTDIR\schemas"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"
  ; Keep v2 authority metadata, custody and service registrations for reinstall.
SectionEnd
