FROM python:3.11-slim

# Install system build dependencies for liboqs
RUN apt-get update && apt-get install -y \
    cmake ninja-build libssl-dev \
    python3-dev gcc g++ git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend application source code
COPY . .

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
