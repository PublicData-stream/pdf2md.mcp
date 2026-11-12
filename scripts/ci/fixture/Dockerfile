FROM python:3.15-slim-bookworm@sha256:96599df822d0e1c6bb700014a05c7f3c8cabc6e0f7ff3c4f9f69cee033b4b5d9
RUN apt-get update && apt-get install --yes --no-install-recommends iproute2 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY server.py /fixture/server.py
ENV PYTHONDONTWRITEBYTECODE=1 TMPDIR=/tmp
ENTRYPOINT ["python3", "/fixture/server.py"]
