# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
FROM rust:1.99.1-alpine3.24@sha256:44819b27be4c97b0e4d7203bd2e02c4820f97700211b6a37fb4c246a2de59383 AS build

ARG CARGO_BUILD_JOBS=2
ARG CMAKE_BUILD_PARALLEL_LEVEL=2

ENV CARGO_HOME=/usr/local/cargo \
    CARGO_TARGET_DIR=/tmp/rust/target \
    TMPDIR=/tmp

# Bindgen build scripts must load libclang through musl dynamic linking.
ENV RUSTFLAGS="-C target-feature=-crt-static"

WORKDIR /build

RUN apk add --no-cache \
        build-base \
        ca-certificates \
        clang \
        cmake \
        git \
        linux-headers \
        llvm-dev \
        clang-dev \
        openssl-dev \
        ninja \
        pkgconf \
        python3

COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY crates/obscura-worker/Cargo.toml crates/obscura-worker/Cargo.toml
COPY crates/obscura-worker/src crates/obscura-worker/src

# COPY mtimes can predate cached artifacts; rebuild both application packages.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git/db \
    --mount=type=cache,target=/tmp/rust/target,sharing=locked \
    --mount=type=secret,id=proxy_ca,required=false \
    if [ -s /run/secrets/proxy_ca ]; then \
        export CARGO_HTTP_CAINFO=/run/secrets/proxy_ca \
            SSL_CERT_FILE=/run/secrets/proxy_ca \
            REQUESTS_CA_BUNDLE=/run/secrets/proxy_ca \
            CURL_CA_BUNDLE=/run/secrets/proxy_ca \
            GIT_SSL_CAINFO=/run/secrets/proxy_ca; \
    fi \
    && cargo clean --release \
        --package pdf2md-mcp --package pdf2md-obscura-worker \
    && cargo build --locked --release \
        --package pdf2md-mcp --package pdf2md-obscura-worker \
    && install -D /tmp/rust/target/release/pdf2md-mcp /out/pdf2md-mcp \
    && install -D /tmp/rust/target/release/pdf2md-convert-worker /out/pdf2md-convert-worker \
    && install -D /tmp/rust/target/release/pdf2md-obscura-worker /out/pdf2md-obscura-worker \
    && python3 -c 'import json,pathlib,shutil,subprocess; m=json.loads(subprocess.check_output(["cargo","metadata","--locked","--format-version=1"])); p=next(p for p in m["packages"] if p["name"]=="obscura-browser" and (p.get("source") or "").endswith("#e3007167016b169bb58d8b5124ca9662a0b37f2d")); d=pathlib.Path(p["manifest_path"]).parent; parents=[d,*list(d.parents)[:4]]; license_path=next(x/"LICENSE" for x in parents if (x/"LICENSE").is_file()); o=pathlib.Path("/out/obscura"); o.mkdir(parents=True,exist_ok=True); shutil.copy2(license_path,o/"LICENSE"); n=license_path.parent/"NOTICE"; n.exists() and shutil.copy2(n,o/"NOTICE"); q=next(p for p in m["packages"] if p["name"]=="pdf_oxide" and p["version"]=="0.3.78"); d=pathlib.Path(q["manifest_path"]).parent; o=pathlib.Path("/out/pdf_oxide"); o.mkdir(parents=True,exist_ok=True); [shutil.copy2(d/n,o/n) for n in ("LICENSE-MIT","LICENSE-APACHE","NOTICE")]'

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git/db \
    python3 -c 'import json,pathlib,shutil,subprocess; m=json.loads(subprocess.check_output(["cargo","metadata","--locked","--offline","--format-version=1"])); [(lambda p: [(lambda f: (pathlib.Path("/out/http",p["name"]).mkdir(parents=True,exist_ok=True),shutil.copy2(f,pathlib.Path("/out/http",p["name"],f.name))))(f) for f in pathlib.Path(p["manifest_path"]).parent.glob("LICENSE*") if f.is_file()])(p) for p in m["packages"] if p["name"] in ("axum","utoipa","zip","rmcp","rmcp-macros","pulldown-cmark","hex")]'

FROM alpine:3.24.4@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf AS runtime

RUN apk add --no-cache \
        ca-certificates \
        libgcc \
        libssl3 \
        libstdc++ \
        ripgrep \
        ripgrep-doc \
    && addgroup -g 10001 pdf2md \
    && adduser -D -u 10001 -G pdf2md -h /home/pdf2md -s /sbin/nologin pdf2md \
    && mkdir -p /data /usr/share/licenses/pdf2md-mcp \
    && chown 10001:10001 /data

COPY --from=build --chown=10001:10001 /out/pdf2md-mcp /usr/local/bin/pdf2md-mcp
COPY --from=build --chown=10001:10001 /out/pdf2md-convert-worker /usr/local/bin/pdf2md-convert-worker
COPY --from=build --chown=10001:10001 /out/pdf2md-obscura-worker /usr/local/bin/pdf2md-obscura-worker
COPY LICENSE /usr/share/licenses/pdf2md-mcp/LICENSE
COPY licenses/ripgrep/ /usr/share/licenses/pdf2md-mcp/ripgrep/
COPY THIRD_PARTY_NOTICES.md /usr/share/licenses/pdf2md-mcp/THIRD_PARTY_NOTICES.md
COPY --from=build /out/obscura/ /usr/share/licenses/pdf2md-mcp/obscura/
COPY --from=build /out/pdf_oxide/ /usr/share/licenses/pdf2md-mcp/pdf_oxide/
COPY --from=build /out/http/ /usr/share/licenses/pdf2md-mcp/http/

ENV HOME=/tmp \
    TMPDIR=/tmp

WORKDIR /data
VOLUME ["/data"]
USER 10001:10001

ENTRYPOINT ["pdf2md-mcp"]
CMD ["--data-dir", "/data", "run"]
