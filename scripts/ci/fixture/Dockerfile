FROM python:3.13-slim-bookworm@sha256:a5a7017efc5969e00ae2b91c8eb0631049a569652aa4ffc4501769049ae45c72
RUN apt-get update && apt-get install --yes --no-install-recommends iproute2 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY server.py /fixture/server.py
ENV PYTHONDONTWRITEBYTECODE=1 TMPDIR=/tmp
ENTRYPOINT ["python3", "/fixture/server.py"]
