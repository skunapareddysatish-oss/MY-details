FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV DATA_DIR=/data
EXPOSE 8080
CMD ["sh", "-c", "gunicorn --workers 1 --bind 0.0.0.0:${PORT:-8080} app:app"]