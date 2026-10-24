@echo off
rem ---------------------------------------------------------------------------
rem One-click repack: two packages.
rem   FastPassword-v1.1.0-win-x64.zip       = self-contained folder, Win10 1809+ x64
rem   FastPassword-v1.1.0-win-x64-lite.zip  = framework-dependent, needs .NET 10
rem                                            Desktop Runtime + Windows App Runtime 2.5.x
rem
rem Both zips contain a single top-level folder, so unzipping does not spill
rem hundreds of files into whatever folder the user picked.
rem
rem data\ is NEVER shipped. It holds the local vault (fastpassword.db),
rem settings.json, logs and the self-check fingerprint - shipping it would hand
rem someone else's password database and machine fingerprint to whoever gets the
rem zip. It is stashed out of the folder before zipping and moved back after,
rem so it is neither packed nor destroyed by the clean step.
rem
rem Keep this file ASCII-only: cmd.exe reads .bat as ANSI, so UTF-8 Chinese
rem comments get mis-parsed and can turn a rem line into a bogus command.
rem
rem Bump <Version> in Directory.Build.props, then update the zip names below.
rem ---------------------------------------------------------------------------
cd /d %~dp0

set KEEP=dist\_keep

echo [1/7] Stashing data folders (never shipped, never deleted)...
if exist "%KEEP%" rmdir /s /q "%KEEP%"
mkdir "%KEEP%" >nul 2>&1
if exist "dist\FastPassword\data" move "dist\FastPassword\data" "%KEEP%\data" >nul
if exist "dist\FastPassword-lite\data" move "dist\FastPassword-lite\data" "%KEEP%\data-lite" >nul

echo [2/7] Cleaning old publish output...
if exist dist\FastPassword rmdir /s /q dist\FastPassword
if exist dist\FastPassword-lite rmdir /s /q dist\FastPassword-lite

echo [3/7] Publishing self-contained (folder)...
dotnet publish src\FastPassword.App -c Release -p:PublishProfile=win-x64-selfcontained || goto :fail

echo [4/7] Publishing lite (framework-dependent folder)...
dotnet publish src\FastPassword.App -c Release -p:PublishProfile=win-x64-frameworkdependent || goto :fail

echo [5/7] Trimming debug symbols and unused UI languages...
rem pdb are debug symbols; not needed at runtime, they only clutter the folder.
del /q dist\FastPassword\*.pdb >nul 2>&1
del /q dist\FastPassword-lite\*.pdb >nul 2>&1
rem WinUI ships 60+ language folders (af-ZA, ar-SA, ...), two ~20 KB .mui each.
rem This app's UI strings are hard-coded Chinese; only framework prompts use
rem these resources, so zh-CN is enough. Dropping the rest removes 60 folders.
rem data is whitelisted too, in case a previous step ever misses stashing it.
for /d %%D in (dist\FastPassword\*) do (
    if /i not "%%~nxD"=="Assets" if /i not "%%~nxD"=="Microsoft.UI.Xaml" if /i not "%%~nxD"=="zh-CN" if /i not "%%~nxD"=="data" rd /s /q "%%D"
)

echo [6/7] Zipping both packages (data excluded by construction)...
if exist dist\FastPassword-v1.1.0-win-x64.zip del /q dist\FastPassword-v1.1.0-win-x64.zip >nul 2>&1
if exist dist\FastPassword-v1.1.0-win-x64-lite.zip del /q dist\FastPassword-v1.1.0-win-x64-lite.zip >nul 2>&1
powershell -NoProfile -Command "Compress-Archive -Path 'dist\FastPassword' -DestinationPath 'dist\FastPassword-v1.1.0-win-x64.zip' -Force" || goto :fail
powershell -NoProfile -Command "Compress-Archive -Path 'dist\FastPassword-lite' -DestinationPath 'dist\FastPassword-v1.1.0-win-x64-lite.zip' -Force" || goto :fail

echo [7/7] Restoring data folders (after the zips are sealed)...
if exist "%KEEP%\data" move "%KEEP%\data" "dist\FastPassword\data" >nul
if exist "%KEEP%\data-lite" move "%KEEP%\data-lite" "dist\FastPassword-lite\data" >nul
rmdir "%KEEP%" >nul 2>&1

echo.
echo Done:
echo   dist\FastPassword-v1.1.0-win-x64.zip        self-contained folder (share this by default)
echo   dist\FastPassword-v1.1.0-win-x64-lite.zip   small folder, needs runtimes installed first
echo.
echo data\ folders were kept on disk and left out of both zips.
pause
exit /b 0

:fail
echo FAILED - check errors above.
if exist "%KEEP%\data" move "%KEEP%\data" "dist\FastPassword\data" >nul
if exist "%KEEP%\data-lite" move "%KEEP%\data-lite" "dist\FastPassword-lite\data" >nul
rmdir "%KEEP%" >nul 2>&1
pause
exit /b 1
