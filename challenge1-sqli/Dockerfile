FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir flask

COPY app.py .

RUN adduser --disabled-password --gecos "" ctfuser
USER ctfuser

EXPOSE 5000

CMD ["python", "app.py"]
