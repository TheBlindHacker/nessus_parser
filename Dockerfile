FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY nessus_parser.py .

ENTRYPOINT ["python", "nessus_parser.py"]
CMD ["-h"]
