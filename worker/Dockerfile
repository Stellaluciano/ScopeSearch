FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY scopesearch_worker ./scopesearch_worker
CMD ["python", "-m", "scopesearch_worker.worker"]
