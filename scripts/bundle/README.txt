Paddock {{VERSION}} - Windows / Mac / Linux installer
=====================================================

Paddock is a self-hosted security platform. This folder installs it on your
own computer. You do not need to build anything, use a terminal, or have any
API keys.

BEFORE YOU START
  1. Install Docker Desktop (free): https://www.docker.com/products/docker-desktop/
     Choose the "WSL 2" option if it asks. Restart Windows if it tells you to.
  2. Start Docker Desktop and wait until it says "Engine running".

INSTALL (Windows)
  Double-click  install.bat
  If Windows shows "Windows protected your PC", click "More info", then
  "Run anyway" (the file is unsigned but is plain text you can open and read).

INSTALL (Mac / Linux)
  Open a terminal in this folder and run:   sh install.sh

WHAT HAPPENS
  - Paddock's ready-made images are downloaded (about 1.5 GB, 1-2 minutes on
    a normal connection).
  - Strong passwords are generated for you and stored in  <your home>\paddock\.env
  - When it says "Paddock is running", open  http://localhost:3000
    and sign in as  admin  with the password the installer prints.

OPTIONAL: AI FEATURES
  Paddock works without any key. To turn on AI triage and "Ask", add an
  Anthropic API key in Settings after you sign in.

STOP / UNINSTALL
  Windows:  powershell -File "%USERPROFILE%\paddock\scripts\install.ps1" -Uninstall
  (this keeps your data; add -Purge to delete everything)

UPGRADE
  Download the newest release zip and run install.bat again. Your data and
  passwords are kept.

PROBLEMS?
  The installer checks your PC first and prints a plain-English fix for the
  common problems (Docker not running, virtualization off, WSL missing, low
  memory or disk, ports 3000/8080 in use, Docker in Windows-containers mode).
  To run just those checks without installing, open PowerShell in this folder:
      powershell -ExecutionPolicy Bypass -File install.ps1 -Doctor
  Details and source code: https://github.com/brandongraff-dev/paddock
