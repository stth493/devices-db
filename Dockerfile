# Use Python 3.11 image as base (more stable than 3.13)
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV FLASK_APP=main.py
ENV FLASK_ENV=production
ENV DOCKER_CONTAINER=true
ENV HOST_IP=192.168.1.104

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy requirements first to leverage Docker layer caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash app \
    && chown -R app:app /app
USER app

# Expose port 5100 to match OAuth2 redirect URI
EXPOSE 5100

# Health check - check both HTTP and HTTPS depending on USE_HTTPS environment variable
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD if [ "$USE_HTTPS" = "true" ]; then \
            curl -k -f https://localhost:5100/ || exit 1; \
        else \
            curl -f http://localhost:5100/ || exit 1; \
        fi

# Run the application with SSL support
CMD ["python", "main.py"]