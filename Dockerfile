FROM python:3.12-alpine

WORKDIR /app

COPY requirements.txt /app

RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r /app/requirements.txt

CMD gunicorn app:app --bind 0.0.0.0:8000 --worker-class aiohttp.GunicornWebWorker