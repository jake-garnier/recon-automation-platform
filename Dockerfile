FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /app/data

# Python modules live under src/ as the `app` package (src/app/, src/cli/).
ENV PYTHONPATH=/app/src

EXPOSE 5000

CMD ["python", "-m", "app.web"]
