@ECHO OFF
call env.bat
pip3.11.exe install -r requirements.txt
pip3.11.exe install watchfiles
python3.11.exe -m watchfiles "python3.11.exe main.py" .\trumbification\