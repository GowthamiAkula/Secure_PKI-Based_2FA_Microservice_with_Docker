#########################
# Stage 1: Builder
#########################
FROM python:3.11-slim AS builder

WORKDIR /app

# Install build deps (needed for cryptography)
RUN apt-get update && apt-get install -y build-essential && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --prefix=/install -r requirements.txt

#########################
# Stage 2: Runtime
#########################
FROM python:3.11-slim

WORKDIR /app

# Install system deps: cron + timezone data
RUN apt-get update && \
    apt-get install -y cron tzdata && \
    rm -rf /var/lib/apt/lists/*

# Set timezone to UTC
ENV TZ=UTC
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# Copy installed Python packages from builder
COPY --from=builder /install /usr/local

# Copy application code (includes cron/2fa-cron and scripts/log_2fa_cron.py)
COPY . /app

# Ensure entrypoint is executable
RUN chmod +x /app/start.sh

# Create mount points with safe permissions
RUN mkdir -p /data /cron && chmod 755 /data /cron

# Install cron configuration (uses cron/2fa-cron)
RUN crontab /app/cron/2fa-cron

# Expose API port
EXPOSE 8080

# Start cron and API
CMD ["/app/start.sh"]

