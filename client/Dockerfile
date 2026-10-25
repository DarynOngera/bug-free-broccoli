# Exploit client: raw-socket HTTP/2 frames, no third-party packages.
FROM python:3.11-slim

WORKDIR /app

COPY poc_http2.py .

CMD ["python", "poc_http2.py"]