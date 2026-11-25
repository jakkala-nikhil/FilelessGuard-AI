@echo off
cd /d "%~dp0"
python -m streamlit run app_v40.py --server.address localhost
pause
