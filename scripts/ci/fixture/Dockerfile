FROM python:3.15-slim-trixie@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928
RUN apt-get update && apt-get install --yes --no-install-recommends iproute2 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY server.py /fixture/server.py
ENV PYTHONDONTWRITEBYTECODE=1 TMPDIR=/tmp
ENTRYPOINT ["python3", "/fixture/server.py"]
