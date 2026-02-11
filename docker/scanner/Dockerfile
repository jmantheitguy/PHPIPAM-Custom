FROM python:3.11-alpine

LABEL maintainer="IPAM System"
LABEL description="Subnet scanner for IPAM network discovery"

# Install system dependencies
RUN apk add --no-cache \
    bash \
    curl \
    iputils \
    nmap \
    net-tools \
    bind-tools \
    arp-scan \
    libcap \
    mariadb-client \
    redis \
    openldap-dev \
    gcc \
    musl-dev \
    python3-dev

# Set capabilities for network tools
RUN setcap cap_net_raw+ep /bin/ping \
    && setcap cap_net_raw+ep /usr/bin/nmap 2>/dev/null || true

# Install Python dependencies
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy application code
COPY scanner.py /app/scanner.py
COPY collectors/ /app/collectors/
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

WORKDIR /app

HEALTHCHECK --interval=60s --timeout=10s --start-period=10s --retries=3 \
    CMD pgrep -f scanner.py || exit 1

ENTRYPOINT ["/entrypoint.sh"]
CMD ["python", "-u", "scanner.py"]
