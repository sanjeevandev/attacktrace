FROM python:3.11-slim

# Prevent Python from writing .pyc files and enable unbuffered logging
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install system dependencies (curl for container health check)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy dependencies list and install packages
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source directories and files
COPY src/ /app/src/
COPY templates/ /app/templates/
COPY data/ /app/data/
COPY scripts/ /app/scripts/
COPY main.py /app/main.py

# Setup persistent directory targets with wide access permissions
RUN mkdir -p /app/reports /app/data && chmod -R 777 /app/reports /app/data

EXPOSE 8000

# Run FastAPI backend by default
CMD ["uvicorn", "src.api:app", "--host", "0.0.0.0", "--port", "8000"]
