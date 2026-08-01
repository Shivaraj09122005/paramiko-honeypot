# Fake SSH Honeypot - Docker image
# Same image is used for both the honeypot server and the dashboard;
# docker-compose.yml picks which command to run for each service.

FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# logs/, keys/, and quarantine/ are mounted as volumes in docker-compose.yml
# so captured data survives container restarts.

CMD ["python", "server.py"]
