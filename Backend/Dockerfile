# syntax=docker/dockerfile:1
# ── Base Image ─────────────────────────────────────────────────────────────
FROM python:3.11-slim AS base

# Prevent Python from writing .pyc files and enable unbuffered logging
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PATH="/home/ccure/.local/bin:${PATH}"
ENV PYTHONPATH="/home/ccure/.local/lib/python3.11/site-packages:${PYTHONPATH}"
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/playwright

# Install system dependencies
# - nmap: essential for network scanning
# - libcap2-bin: to grant raw socket permissions to non-root users
# - gcc, libpq-dev: for building certain python packages
# - wget, unzip, curl: for downloading security tool binaries
# - chromium: headless browser for Playwright-based web crawling
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    libcap2-bin \
    gcc \
    python3-dev \
    libpq-dev \
    wget \
    unzip \
    curl \
    chromium \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# ── Dependency Stage ───────────────────────────────────────────────────────
FROM base AS builder

# Install Python dependencies
COPY requirements.txt .
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --user -r requirements.txt

# Install Playwright browsers (Chromium only)
RUN --mount=type=cache,target=/root/.cache/ms-playwright \
    /root/.local/bin/playwright install chromium 2>/dev/null || echo "Playwright browser install skipped"

# ── Security Tools Stage ──────────────────────────────────────────────────
FROM base AS tools

# Nuclei — template-based vulnerability scanner (primary DAST engine)
RUN NUCLEI_VERSION=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | grep -oP '"tag_name": "\K[^"]+' || echo "v3.3.7") && \
    wget -q "https://github.com/projectdiscovery/nuclei/releases/download/${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION#v}_linux_amd64.zip" -O /tmp/nuclei.zip && \
    unzip -o /tmp/nuclei.zip -d /usr/local/bin/ && \
    chmod +x /usr/local/bin/nuclei && \
    rm -f /tmp/nuclei.zip || echo "Nuclei install skipped"

# Subfinder — passive subdomain enumeration
RUN SUBFINDER_VERSION=$(curl -s https://api.github.com/repos/projectdiscovery/subfinder/releases/latest | grep -oP '"tag_name": "\K[^"]+' || echo "v2.6.7") && \
    wget -q "https://github.com/projectdiscovery/subfinder/releases/download/${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION#v}_linux_amd64.zip" -O /tmp/subfinder.zip && \
    unzip -o /tmp/subfinder.zip -d /usr/local/bin/ && \
    chmod +x /usr/local/bin/subfinder && \
    rm -f /tmp/subfinder.zip || echo "Subfinder install skipped"

# ffuf — directory/file bruteforcing
RUN FFUF_VERSION=$(curl -s https://api.github.com/repos/ffuf/ffuf/releases/latest | grep -oP '"tag_name": "\K[^"]+' || echo "v2.1.0") && \
    wget -q "https://github.com/ffuf/ffuf/releases/download/${FFUF_VERSION}/ffuf_${FFUF_VERSION#v}_linux_amd64.tar.gz" -O /tmp/ffuf.tar.gz && \
    tar xf /tmp/ffuf.tar.gz -C /usr/local/bin/ ffuf && \
    chmod +x /usr/local/bin/ffuf && \
    rm -f /tmp/ffuf.tar.gz || echo "ffuf install skipped"

# Download nuclei templates
RUN nuclei -update-templates 2>/dev/null || echo "Nuclei template update skipped"

# Download common wordlist for ffuf
RUN mkdir -p /opt/wordlists && \
    wget -q "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt" \
    -O /opt/wordlists/common.txt || echo "Wordlist download skipped"

# Install sqlmap
RUN apt-get update && apt-get install -y --no-install-recommends sqlmap && apt-get clean && rm -rf /var/lib/apt/lists/*

# ── Final Runtime Image ────────────────────────────────────────────────────
FROM base AS runtime

# Create a non-privileged user for the API process
RUN useradd -m -s /bin/bash ccure

# Copy installed python packages from builder
COPY --from=builder /root/.local /home/ccure/.local
RUN chown -R ccure:ccure /home/ccure/.local

# Copy security tool binaries from tools stage
COPY --from=tools /usr/local/bin/nuclei /usr/local/bin/nuclei
COPY --from=tools /usr/local/bin/subfinder /usr/local/bin/subfinder
COPY --from=tools /usr/local/bin/ffuf /usr/local/bin/ffuf
COPY --from=tools /opt/wordlists /opt/wordlists

# Copy Playwright browsers from builder
COPY --from=builder /opt/playwright /opt/playwright
RUN chown -R ccure:ccure /opt/playwright

# Copy nuclei templates (may be in /root or /home)
COPY --from=tools /root/nuclei-templates /opt/nuclei-templates

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
ENV NUCLEI_TEMPLATES_DIR=/opt/nuclei-templates

# Entrypoint script will handle switching between API and Worker roles
EXPOSE 8000

# Use ccure user by default (overridden for worker in docker-compose)
USER ccure

# Ensure start.sh has executable permissions and LF line endings
RUN sed -i 's/\r$//' /app/start.sh && chmod +x /app/start.sh

CMD ["/app/start.sh"]
