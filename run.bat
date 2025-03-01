@echo off
D:
cd path\to\your\script
call conda activate dlib_env
streamlit run streamlit_app.py --server.port 840
