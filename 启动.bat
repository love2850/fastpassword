@echo off
rem 优先跑 打包.bat 发布好的 dist 包，其次跑 Release 构建产物（两者的输出目录结构不同，
rem 以前只写死了 bin\x64\Release 那一条，容易悄悄启动到旧 exe）。
cd /d %~dp0

set "APP=%~dp0dist\FastPassword-lite\FastPassword.exe"
if exist "%APP%" goto run

set "APP=%~dp0dist\FastPassword\FastPassword.exe"
if exist "%APP%" goto run

set "APP=%~dp0src\FastPassword.App\bin\x64\Release\net10.0-windows10.0.19041.0\win-x64\FastPassword.exe"
if exist "%APP%" goto run

set "APP=%~dp0src\FastPassword.App\bin\Release\net10.0-windows10.0.19041.0\win-x64\FastPassword.exe"
if exist "%APP%" goto run

echo [X] 没找到构建产物。先运行 打包.bat，或执行：
echo     dotnet build src\FastPassword.App -c Release
pause
exit /b 1

:run
start "" "%APP%"
