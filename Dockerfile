FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN python -m pip install --no-cache-dir -r requirements.txt

COPY . .

ENV DATA_DIR=/data

EXPOSE 8080

CMD ["sh", "-c", "python -m gunicorn --workers 1 --bind 0.0.0.0:${PORT:-8080} app:app"]
