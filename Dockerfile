FROM python:latest
LABEL authors="anton"

RUN apt-get update
RUN apt-get install -y autoconf libpcap-dev tcpdump


COPY requirements.txt /tmp/requirements.txt

RUN pip install -r /tmp/requirements.txt

WORKDIR /app

COPY . /app

CMD ["python3", "main.py"]
