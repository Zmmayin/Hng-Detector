FROM python:3.11-slim AS builder

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir pip==26.0 && \
    pip install --no-cache-dir --requirement requirements.txt


FROM python:3.11-slim

WORKDIR /app

# Install iptables
RUN apt-get update && \
    apt-get install -y iptables && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN addgroup --system appuser && \
    adduser --system --ingroup appuser appuser

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages \
    /usr/local/lib/python3.11/site-packages

COPY --from=builder /usr/local/bin /usr/local/bin

# Copy app code
COPY . .

# Create audit log directory
RUN mkdir -p /var/log/detector && \
    chown -R appuser:appuser /var/log/detector

USER appuser

CMD ["python", "main.py"]
