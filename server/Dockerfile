FROM nvidia/cuda:12.1.1-cudnn8-runtime-ubuntu22.04

ENV DEBIAN_FRONTEND=noninteractive

# System deps for Python, nmap, and building wheels
RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv python3-dev \
    build-essential git nmap curl ca-certificates \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies (server + ML engine + shared root requirements)
COPY server/requirements.txt ./server-requirements.txt
COPY ml_engine/requirements.txt ./ml_engine-requirements.txt
COPY requirements.txt ./root-requirements.txt
# GPU-enabled torch first, then the rest
RUN python3 -m pip install --no-cache-dir --extra-index-url https://download.pytorch.org/whl/cu121 torch==2.4.1
RUN python3 -m pip install --no-cache-dir -r server-requirements.txt -r ml_engine-requirements.txt -r root-requirements.txt python-nmap uvicorn

# Copy application code
COPY server ./server
COPY ml_engine ./ml_engine
COPY scan_stage_1.py scan_stage_2.py scan_stage_3.py ./
COPY exploits ./exploits
COPY models ./models
COPY saved_model ./saved_model

ENV PYTHONPATH=/app
EXPOSE 8000

ENV NVIDIA_VISIBLE_DEVICES=all
ENV NVIDIA_DRIVER_CAPABILITIES=compute,utility

CMD ["uvicorn", "server.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
