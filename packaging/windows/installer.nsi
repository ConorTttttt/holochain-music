; Holochain Music - Windows x64 installer (NSIS 3, Unicode).
;
; Built by packaging/windows/build-windows.sh:
;   makensis -DVERSION=1.0.0-rc1 -DSTAGE=<staged tree> -DOUTFILE=<exe> installer.nsi
;
; * Per-machine install into Program Files (needs admin once, for the
;   Program Files folder and the private-network firewall rules).
; * User data is never written here: it lives in %LOCALAPPDATA%\HolochainMusic
;   and survives upgrades and uninstallation.
; * Silent mode (/S) is supported for CI and scripted upgrades.

Unicode true
ManifestDPIAware true
!include MUI2.nsh
!include LogicLib.nsh
!include x64.nsh

!ifndef VERSION
  !error "VERSION not defined"
!endif
!ifndef STAGE
  !error "STAGE not defined"
!endif
!ifndef OUTFILE
  !define OUTFILE "HolochainMusic-${VERSION}-windows-x64.exe"
!endif

!define APPNAME "Holochain Music"
!define UNINSTKEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\HolochainMusic"
!define FWPREFIX "Holochain Music"

Name "${APPNAME} ${VERSION}"
Caption "${APPNAME} ${VERSION} - unsigned development build"
BrandingText "Unsigned private test build - not for public distribution"
OutFile "${OUTFILE}"
InstallDir "$PROGRAMFILES64\${APPNAME}"
InstallDirRegKey HKLM "${UNINSTKEY}" "InstallLocation"
RequestExecutionLevel admin
SetCompressor /SOLID lzma
SetOverwrite on
ShowInstDetails show
ShowUninstDetails show

VIProductVersion "1.0.0.0"
VIAddVersionKey /LANG=1033 "ProductName" "${APPNAME}"
VIAddVersionKey /LANG=1033 "ProductVersion" "${VERSION}"
VIAddVersionKey /LANG=1033 "FileVersion" "${VERSION}"
VIAddVersionKey /LANG=1033 "FileDescription" "${APPNAME} installer (unsigned development build)"
VIAddVersionKey /LANG=1033 "LegalCopyright" "See licenses\THIRD-PARTY.txt"
VIAddVersionKey /LANG=1033 "Comments" "Private hardware test build. Not for public distribution."

!define MUI_ICON "${STAGE}\HolochainMusic.ico"
!define MUI_UNICON "${STAGE}\HolochainMusic.ico"
!define MUI_ABORTWARNING
!define MUI_WELCOMEPAGE_TITLE "${APPNAME} ${VERSION} (unsigned test build)"
!define MUI_WELCOMEPAGE_TEXT "This is an UNSIGNED development build of ${APPNAME} for private hardware testing.$\r$\n$\r$\nIt installs the player, the Holochain conductor and the encrypted MoQ/QUIC streaming host.$\r$\n$\r$\nYour identity and music library are stored in your own user profile and are kept when you upgrade or uninstall.$\r$\n$\r$\nClick Next to read the test-build notice."
!define MUI_LICENSEPAGE_TEXT_TOP "Please read this notice about the test build."
!define MUI_LICENSEPAGE_BUTTON "I &understand"
!define MUI_LICENSEPAGE_TEXT_BOTTOM "Click 'I understand' to continue."
!define MUI_FINISHPAGE_TEXT "${APPNAME} is installed.$\r$\n$\r$\nStart it from the Start menu: ${APPNAME}. It opens in your web browser. Use 'Quit ${APPNAME}' in the Start menu to stop it.$\r$\n$\r$\nThe guide is in the Start menu folder too."

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "${STAGE}\PRIVATE-TEST-NOTICE.txt"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

; Program-scoped inbound rules, PRIVATE profile only. Nothing is opened on
; public or domain networks, and no other Windows protection is changed.
!macro FirewallAdd LABEL EXE
  nsExec::ExecToLog 'netsh advfirewall firewall delete rule name="${FWPREFIX} - ${LABEL}"'
  Pop $0
  nsExec::ExecToLog 'netsh advfirewall firewall add rule name="${FWPREFIX} - ${LABEL}" dir=in action=allow program="$INSTDIR\bin\${EXE}" enable=yes profile=private'
  Pop $0
  ${If} $0 != 0
    DetailPrint "Warning: could not add firewall rule for ${EXE} (exit $0)."
  ${EndIf}
!macroend

!macro FirewallRemove LABEL
  nsExec::ExecToLog 'netsh advfirewall firewall delete rule name="${FWPREFIX} - ${LABEL}"'
  Pop $0
!macroend

!macro StopRunningApp
  ; Ask a running instance (of this user) to shut down cleanly, so its
  ; conductor and MoQ host release their files before they are replaced.
  ${If} ${FileExists} "$INSTDIR\holochain-music.exe"
    nsExec::ExecToLog '"$INSTDIR\holochain-music.exe" quit'
    Pop $0
    Sleep 3000
  ${EndIf}
!macroend

Function .onInit
  ${IfNot} ${RunningX64}
    MessageBox MB_ICONSTOP "${APPNAME} requires 64-bit Windows 10 or 11."
    Abort
  ${EndIf}
  SetRegView 64
FunctionEnd

Function un.onInit
  SetRegView 64
FunctionEnd

Section "Install"
  SetShellVarContext all
  !insertmacro StopRunningApp

  ; Upgrade: replace program folders wholesale so no stale modules remain.
  ; These folders contain only installed program files, never user data.
  RMDir /r "$INSTDIR\runtime"
  RMDir /r "$INSTDIR\python"
  RMDir /r "$INSTDIR\bin"
  RMDir /r "$INSTDIR\docs"
  RMDir /r "$INSTDIR\licenses"

  SetOutPath "$INSTDIR"
  File /r "${STAGE}\*.*"

  WriteUninstaller "$INSTDIR\Uninstall.exe"

  CreateDirectory "$SMPROGRAMS\${APPNAME}"
  CreateShortcut "$SMPROGRAMS\${APPNAME}\${APPNAME}.lnk" "$INSTDIR\HolochainMusic.exe" "" "$INSTDIR\HolochainMusic.ico" 0 SW_SHOWNORMAL "" "Artist-first decentralised music player"
  CreateShortcut "$SMPROGRAMS\${APPNAME}\Quit ${APPNAME}.lnk" "$INSTDIR\HolochainMusic.exe" "quit" "$INSTDIR\HolochainMusic.ico" 0 SW_SHOWMINIMIZED "" "Shut down Holochain Music"
  CreateShortcut "$SMPROGRAMS\${APPNAME}\${APPNAME} guide.lnk" "$INSTDIR\docs\windows-installation.txt"
  CreateShortcut "$SMPROGRAMS\${APPNAME}\Uninstall ${APPNAME}.lnk" "$INSTDIR\Uninstall.exe"

  !insertmacro FirewallAdd "Holochain conductor" "holochain.exe"
  !insertmacro FirewallAdd "MoQ streaming host" "holochain-music-moq.exe"
  !insertmacro FirewallAdd "LAN bootstrap server" "kitsune2-bootstrap-srv.exe"

  WriteRegStr HKLM "${UNINSTKEY}" "DisplayName" "${APPNAME} ${VERSION} (unsigned test build)"
  WriteRegStr HKLM "${UNINSTKEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "${UNINSTKEY}" "Publisher" "Holochain Music developers"
  WriteRegStr HKLM "${UNINSTKEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "${UNINSTKEY}" "DisplayIcon" "$INSTDIR\HolochainMusic.ico"
  WriteRegStr HKLM "${UNINSTKEY}" "UninstallString" '"$INSTDIR\Uninstall.exe"'
  WriteRegStr HKLM "${UNINSTKEY}" "QuietUninstallString" '"$INSTDIR\Uninstall.exe" /S'
  WriteRegDWORD HKLM "${UNINSTKEY}" "NoModify" 1
  WriteRegDWORD HKLM "${UNINSTKEY}" "NoRepair" 1
  WriteRegDWORD HKLM "${UNINSTKEY}" "EstimatedSize" ${SIZE_KB}
SectionEnd

Section "Uninstall"
  SetShellVarContext all
  !insertmacro StopRunningApp

  !insertmacro FirewallRemove "Holochain conductor"
  !insertmacro FirewallRemove "MoQ streaming host"
  !insertmacro FirewallRemove "LAN bootstrap server"

  Delete "$SMPROGRAMS\${APPNAME}\*.lnk"
  RMDir "$SMPROGRAMS\${APPNAME}"

  ; Remove only what the installer put here (never a recursive delete of a
  ; folder the user might have chosen for other things too).
  RMDir /r "$INSTDIR\runtime"
  RMDir /r "$INSTDIR\python"
  RMDir /r "$INSTDIR\bin"
  RMDir /r "$INSTDIR\docs"
  RMDir /r "$INSTDIR\licenses"
  Delete "$INSTDIR\HolochainMusic.exe"
  Delete "$INSTDIR\holochain-music.exe"
  Delete "$INSTDIR\HolochainMusic.ico"
  Delete "$INSTDIR\holochain_music.happ"
  Delete "$INSTDIR\PRIVATE-TEST-NOTICE.txt"
  Delete "$INSTDIR\SHA256SUMS.txt"
  Delete "$INSTDIR\Uninstall.exe"
  RMDir "$INSTDIR"

  DeleteRegKey HKLM "${UNINSTKEY}"

  IfSilent +2
    MessageBox MB_ICONINFORMATION "${APPNAME} was removed.$\r$\n$\r$\nYour identity, keys and music library were NOT deleted. They are in:$\r$\n%LOCALAPPDATA%\HolochainMusic$\r$\n$\r$\nDelete that folder yourself only if you no longer need them and have an encrypted backup."
SectionEnd
