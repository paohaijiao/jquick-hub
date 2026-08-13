@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"

rem ============ locate java: PATH first, then JAVA_HOME ============
set "JAVA_CMD="
where java >nul 2>nul
if errorlevel 1 goto :java_home
set "JAVA_CMD=java"
goto :locate_javac

:java_home
if not defined JAVA_HOME goto :no_java
if not exist "%JAVA_HOME%\bin\java.exe" goto :no_java
set "JAVA_CMD=%JAVA_HOME%\bin\java.exe"

:locate_javac
set "JAVAC_CMD="
where javac >nul 2>nul
if errorlevel 1 goto :javac_home
set "JAVAC_CMD=javac"
goto :compile_check

:javac_home
if not defined JAVA_HOME goto :no_javac
if not exist "%JAVA_HOME%\bin\javac.exe" goto :no_javac
set "JAVAC_CMD=%JAVA_HOME%\bin\javac.exe"

:compile_check
if exist GatewayClient.class goto :run
if not defined JAVAC_CMD goto :no_javac
echo [INFO] First run: compiling GatewayClient.java ...
"%JAVAC_CMD%" -encoding UTF-8 GatewayClient.java
if errorlevel 1 goto :compile_fail

:run
echo [INFO] Starting GatewayClient ... press Ctrl+C to stop.
"%JAVA_CMD%" -Dfile.encoding=UTF-8 GatewayClient %*
goto :end

:no_java
echo [ERROR] Java not found. Please install JDK 1.8+ and set JAVA_HOME.
goto :end_fail

:no_javac
echo [ERROR] javac not found. Please install a full JDK (not JRE).
goto :end_fail

:compile_fail
echo [ERROR] Compile failed. Please check your JDK.
goto :end_fail

:end_fail
pause
exit /b 1

:end
pause
