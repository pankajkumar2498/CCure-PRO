# ── Base Image ─────────────────────────────────────────────────────────────
FROM python:3.11-slim AS base

# Prevent Python from writing .pyc files and enable unbuffered logging
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PATH="/home/ccure/.local/bin:${PATH}"
ENV PYTHONPATH="/home/ccure/.local/lib/python3.11/site-packages:${PYTHONPATH}"

# Install system dependencies
# - nmap: essential for scanning
# - libcap2-bin: to grant raw socket permissions to non-root users if needed
# - gcc, libpq-dev: for building certain python packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    libcap2-bin \
    gcc \
    python3-dev \
    libpq-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# ── Dependency Stage ───────────────────────────────────────────────────────
FROM base AS builder

COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

# ── Final Runtime Image ────────────────────────────────────────────────────
FROM base AS runtime

# Create a non-privileged user for the API process
RUN useradd -m -s /bin/bash ccure

# Copy installed python packages from builder
COPY --from=builder /root/.local /home/ccure/.local
RUN chown -R ccure:ccure /home/ccure/.local

# Copy application code
COPY . .
RUN chown -R ccure:ccure /app

# Grant nmap binary the ability to perform raw socket scans without root
# This allows the worker to run with fewer privileges if desired, 
# though running worker as root in container is often acceptable.
RUN setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/bin/nmap

# Create directory for reports
RUN mkdir -p /app/reports && chown -R ccure:ccure /app/reports

# Default environment variables
ENV ENV=production
ENV PORT=8000

# Entrypoint script will handle switching between API and Worker roles
EXPOSE 8000

# Use ccure user by default (overridden for worker in docker-compose)
USER ccure

# Ensure start.sh has executable permissions
# We do this as root before switching user if we were copying it later,
# but since it's copied earlier with the app code and chowned, we just chmod it here.
RUN chmod +x /app/start.sh

CMD ["/app/start.sh"]
