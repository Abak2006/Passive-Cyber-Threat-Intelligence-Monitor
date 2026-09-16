FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpcap-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Generate training data and train models inside container
RUN python -m training.generate_synthetic && python -m training.train --detector all

EXPOSE 8000 8501

CMD ["streamlit", "run", "dashboard/streamlit_app.py", "--server.port=8501", "--server.address=0.0.0.0"]
