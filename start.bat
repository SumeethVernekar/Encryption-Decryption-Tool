@echo off
echo ================================
echo Encryption/Decryption Tool Setup
echo ================================
echo.

echo [1/3] Installing backend dependencies...
cd backend
call npm install

if %errorlevel% neq 0 (
    echo.
    echo ERROR: Failed to install dependencies!
    echo Please ensure Node.js is installed.
    pause
    exit /b 1
)

echo.
echo [2/3] Dependencies installed successfully!
echo.
echo [3/3] Starting the server...
echo.
echo ================================
echo  Server will start shortly...
echo  Access the app at: http://localhost:3000
echo ================================
echo.

call npm start
