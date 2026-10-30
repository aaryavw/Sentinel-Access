# Use official lightweight Python image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Create non-root system user for security compliance
RUN groupadd -r sentinel && useradd -r -g sentinel sentinel

# Install system dependencies if needed (none required for standard library core)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy project configuration and source code
COPY pyproject.toml ./
COPY src/ ./src/
COPY config/ ./config/

# Install package in editable/development mode or standard install
RUN pip install --no-cache-dir .

# Create working directory for runtime data
RUN mkdir -p /app/data && chown -R sentinel:sentinel /app

# Switch to non-root user
USER sentinel

# Expose API port
EXPOSE 8000

# Health check endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

# Default entrypoint for running the API server
ENTRYPOINT ["python", "-m", "sentinel"]
CMD ["serve", "--db", "/app/data/sentinel.db", "--tokens", "/app/data/tokens.json"]
