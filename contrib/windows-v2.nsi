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
  nsExec::ExecToLog '"$WINDIR\Sysnative\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "$PLUGINSDIR\package-windows-v2.ps1" -Mode Before'
  Pop $0
  StrCmp $0 0 +3
    SetErrorLevel 1
    Abort "Could not stop v2 services safely."
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
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\org.ekubo.wallet.v2" "UninstallString" '$"$INSTDIR\uninstall.exe$"'
  CreateShortcut "$SMPROGRAMS\Ekubo Wallet 2.lnk" "$INSTDIR\ekubo-wallet-v2.exe"
  ; Toast identity is installer-owned; desktop startup does not write registry state.
  WriteRegStr HKLM "Software\Classes\AppUserModelId\org.ekubo.wallet.v2" "DisplayName" "Ekubo Wallet 2"
  nsExec::ExecToLog '"$WINDIR\Sysnative\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\package-windows-v2.ps1" -Mode After'
  Pop $0
  StrCmp $0 0 +3
    SetErrorLevel 1
    Abort "V2 payload installed; service restart failed. Inspect Services before opening v2."
SectionEnd

Section "Uninstall"
  SetRegView 64
  SetShellVarContext all
  StrCpy $INSTDIR "$PROGRAMFILES64\Ekubo Wallet 2"
  nsExec::ExecToLog '"$WINDIR\Sysnative\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\package-windows-v2.ps1" -Mode Remove'
  Pop $0
  StrCmp $0 0 +3
    SetErrorLevel 1
    Abort "Could not stop v2 services safely."
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
