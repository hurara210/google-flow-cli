@echo off
title Ship gflow to GitHub
echo.
echo ============================================
echo   Google Flow CLI - Ship to GitHub
echo ============================================
echo.

REM ── Step 0: Clean out anything that shouldn't be committed ──
echo [1/5] Cleaning build artifacts...
rmdir /s /q __pycache__ 2>nul
rmdir /s /q gflow\__pycache__ 2>nul
rmdir /s /q gflow\api\__pycache__ 2>nul
rmdir /s /q gflow\auth\__pycache__ 2>nul
rmdir /s /q gflow\batchexecute\__pycache__ 2>nul
rmdir /s /q gflow\cli\__pycache__ 2>nul
rmdir /s /q tests\__pycache__ 2>nul
rmdir /s /q gflow.egg-info 2>nul
rmdir /s /q .pytest_cache 2>nul
rmdir /s /q .git 2>nul
echo Done.
echo.

REM ── Step 1: Init fresh git repo ──
echo [2/5] Initializing git repo...
git init -b main
echo.

REM ── Step 2: Stage only source files ──
echo [3/5] Staging source files...
git add .gitignore README.md pyproject.toml gflow\ tests\
echo.

REM ── Step 3: Verify nothing sensitive is staged ──
echo [4/5] Verifying staged files (review this list!)
echo ──────────────────────────────────────
git status
echo ──────────────────────────────────────
echo.
echo IMPORTANT: Make sure NO .env, .mp4, .png, cookie, or capture files are listed above!
echo.
pause

REM ── Step 4: Commit ──
echo [5/5] Creating initial commit...
git commit -m "Initial release - Google Flow CLI (gflow)"
echo.

REM ── Step 5: Create GitHub repo and push ──
echo Creating GitHub repo and pushing...
gh repo create google-flow-cli --public --source=. --remote=origin --push --description "CLI for Google Flow - Generate images (Imagen 4) and videos (Veo 3.1) from your terminal. Built for workflows, scripts, and AI agents."
echo.

echo ============================================
echo   Done! Your repo should be live at:
echo   https://github.com/YOUR_USERNAME/google-flow-cli
echo ============================================
pause
