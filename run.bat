@echo off
title InfraShield — The Living Security Blueprint
echo ==========================================================
echo   InfraShield -- The Living Security Blueprint
echo   Dev Sprint '26 Hackathon Command Center
echo ==========================================================
echo.
echo Starting InfraShield on http://127.0.0.1:8000 ...
python -m uvicorn infrashield.backend.main:app --host 127.0.0.1 --port 8000 --reload
pause
