# syntax=docker/dockerfile:1

# coraza-apilab images.
#
# Targets (pick one with `docker build --target <name>`):
#
#   waf       nginx + coraza-nginx connector + libcoraza + OWASP CRS +
#             plugins + the lab rules. Proxies to ${APILAB_UPSTREAM}.
#   api       only the API simulator binary (rs-http-apilab or
#             v-http-apilab), for the split example.
#   allinone  waf + the API binary in the same container, the API bound
#             to 127.0.0.1 so it is only reachable through nginx.
#
# Every third-party artifact is pinned by version and verified by
# sha256 (ADD --checksum): a changed upstream tarball breaks the build
# instead of silently changing the WAF.

ARG NGINX_VERSION=1.30.5
ARG GO_IMAGE=golang:1.26.9-trixie
# Which simulator ships in the image: rs (Rust/axum) or v (V/veb).
ARG APILAB=rs

# ---- libcoraza: the Go WAF engine exported as a C shared library ----
FROM ${GO_IMAGE} AS libcoraza
ARG LIBCORAZA_VERSION=v1.8.0
ARG LIBCORAZA_SHA256=f303f65d3bbd97e90aef5c26d2251949f4a8c7a4d8615a2d78c87455b0fa148c
# libcoraza v1.8.0 pins the engine at coraza v3.7.0. v3.8.1 is a
# security release (JSON nesting crash, multipart strict-error and
# jsDecode bypasses, see GHSA-6gcq-wc29-5xf2 and friends) and adds
# SecArgumentsLimit/URI_PARSE_ERROR, so the engine is bumped here.
# go.sum entries are verified against sum.golang.org by `go get`.
ARG CORAZA_VERSION=v3.8.1

RUN apt-get update \
	&& apt-get install -y --no-install-recommends autoconf automake libtool make gcc \
	&& rm -rf /var/lib/apt/lists/*

ADD --checksum=sha256:${LIBCORAZA_SHA256} \
	https://github.com/corazawaf/libcoraza/archive/refs/tags/${LIBCORAZA_VERSION}.tar.gz \
	/tmp/libcoraza.tar.gz

WORKDIR /src/libcoraza
RUN tar -xzf /tmp/libcoraza.tar.gz --strip-components=1 \
	&& go get github.com/corazawaf/coraza/v3@${CORAZA_VERSION} \
	&& go mod tidy \
	&& go list -m github.com/corazawaf/coraza/v3 \
	&& ./build.sh \
	&& ./configure --prefix=/usr/local \
	&& make \
	&& make install DESTDIR=/out \
	&& ls -l /out/usr/local/lib /out/usr/local/include/coraza

# ---- module: compile ngx_http_coraza_module.so for this exact nginx ----
# A dynamic module must be built from the same nginx version it will be
# loaded into; --with-compat makes the module binary-compatible with the
# official image without reproducing all of its configure flags.
FROM nginx:${NGINX_VERSION} AS module
ARG NGINX_VERSION
ARG NGINX_SHA256=6c20565aa2325cb82216ae804f4a4ff1875179014759a381c42ddc8e11c4906d
ARG CORAZA_NGINX_VERSION=v0.22.0
ARG CORAZA_NGINX_SHA256=d999699ed477a02015779104f86c8d7c5ea355088daf1fd06eb8a5a573c9139c

RUN apt-get update \
	&& apt-get install -y --no-install-recommends gcc make libc6-dev libpcre2-dev zlib1g-dev libssl-dev \
	&& rm -rf /var/lib/apt/lists/*

COPY --from=libcoraza /out/usr/local/ /usr/local/

ADD --checksum=sha256:${NGINX_SHA256} \
	https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz /tmp/nginx.tar.gz
ADD --checksum=sha256:${CORAZA_NGINX_SHA256} \
	https://github.com/corazawaf/coraza-nginx/archive/refs/tags/${CORAZA_NGINX_VERSION}.tar.gz \
	/tmp/coraza-nginx.tar.gz

# -Wno-unused-function: coraza.h carries cgo static shims that nginx's
# -Werror would otherwise reject (documented by coraza-nginx).
WORKDIR /src
RUN mkdir nginx coraza-nginx \
	&& tar -xzf /tmp/nginx.tar.gz -C nginx --strip-components=1 \
	&& tar -xzf /tmp/coraza-nginx.tar.gz -C coraza-nginx --strip-components=1 \
	&& cd nginx \
	&& ./configure --with-compat --add-dynamic-module=/src/coraza-nginx \
		--with-cc-opt="-I/usr/local/include -Wno-unused-function" \
	&& make modules \
	&& mkdir -p /out \
	&& cp objs/ngx_http_coraza_module.so /out/

# Rule-set validator (see docker/coraza-check.c).
COPY docker/coraza-check.c /src/coraza-check.c
RUN gcc -O2 -Wall -o /out/coraza-check /src/coraza-check.c -I/usr/local/include -L/usr/local/lib -lcoraza

# ---- rules: OWASP CRS and the CRS plugins used by the lab ----
FROM debian:trixie-slim AS rules
# v4.25.x is the CRS LTS line: security fixes without rule churn, the
# sensible default for a WAF you tune once and keep.
ARG CRS_VERSION=v4.25.2
ARG CRS_SHA256=a3ecf5d5b0f8001e2eaf2006448fc8e22d6b645d7fc1c71268be5b99a7395a2d
# CRS plugins have no release tags; they are pinned by commit.
#
# Plugins evaluated and NOT shipped, because Coraza cannot load them:
#   auto-decoding  uses t:sqlHexDecode (not implemented in Coraza)
#   fake-bot       needs Lua (Coraza has no SecRuleScript/Lua)
#   dos-protection needs persistent IP collections (initcol is a no-op
#                  in Coraza v3; rate limiting is done by nginx instead)
ARG REFERER_HARDENING_REF=3f3120dbb0b790e37c511cab6a009e7fcc5169da
ARG REFERER_HARDENING_SHA256=c9a36a6e5f7c88afb1dc375ad5ed3b2b3df97955614efb5816b2637b9049038c

ADD --checksum=sha256:${CRS_SHA256} \
	https://github.com/coreruleset/coreruleset/archive/refs/tags/${CRS_VERSION}.tar.gz /tmp/crs.tar.gz
ADD --checksum=sha256:${REFERER_HARDENING_SHA256} \
	https://github.com/coreruleset/referer-hardening-plugin/archive/${REFERER_HARDENING_REF}.tar.gz /tmp/referer-hardening.tar.gz

# Only rules/ is taken from CRS: crs-setup.conf is ours (coraza/crs-setup.conf).
RUN mkdir -p /out/crs /out/plugins /tmp/x \
	&& tar -xzf /tmp/crs.tar.gz -C /tmp/x \
	&& cp -r /tmp/x/coreruleset-*/rules /out/crs/ \
	&& cp /tmp/x/coreruleset-*/LICENSE /out/crs/ \
	&& for p in referer-hardening; do \
		tar -xzf "/tmp/$p.tar.gz" -C /tmp/x \
		&& cp /tmp/x/"$p"-plugin-*/plugins/*.conf /out/plugins/; \
	done \
	&& ls -l /out/crs/rules /out/plugins

# ---- the API simulator binaries (release assets, pinned by checksum) ----
FROM debian:trixie-slim AS apilab-rs
ADD --checksum=sha256:e2a216aa596914ce72663e6b111bf24192cb59216ddbe84c76d5c352c64e8cec \
	https://github.com/Esl1h/rs-http-apilab/releases/download/v1.0.0/rs-http-apilab-linux-amd64 \
	/out/apilab

FROM debian:trixie-slim AS apilab-v
ADD --checksum=sha256:a531c9d13c948b67d9c8db5fa36568dc927245441ff8596a4daeab1b68e1c389 \
	https://github.com/Esl1h/v-http-apilab/releases/download/v1.0.0/v-http-apilab-linux-amd64 \
	/out/apilab

FROM apilab-${APILAB} AS apilab
RUN chmod 0755 /out/apilab

# ---- api: the simulator alone (split example) ----
FROM debian:trixie-slim AS api
RUN apt-get update \
	&& apt-get install -y --no-install-recommends ca-certificates curl \
	&& rm -rf /var/lib/apt/lists/* \
	&& useradd --uid 10001 --system --no-create-home apilab
COPY --from=apilab /out/apilab /usr/local/bin/apilab
USER 10001:10001
ENV PORT=8080
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --start-period=3s --retries=3 \
	CMD curl -fsS "http://127.0.0.1:${PORT}/health" || exit 1
ENTRYPOINT ["/usr/local/bin/apilab"]

# ---- waf: nginx + Coraza ----
FROM nginx:${NGINX_VERSION} AS waf

# libcoraza is dlopen()ed by every worker after fork (a Go runtime does
# not survive fork), so it only has to be on the linker search path.
COPY --from=libcoraza /out/usr/local/lib/libcoraza.so* /usr/local/lib/
COPY --from=module /out/ngx_http_coraza_module.so /usr/lib/nginx/modules/
COPY --from=module /out/coraza-check /usr/local/bin/coraza-check
COPY docker/05-coraza-check.sh /docker-entrypoint.d/05-coraza-check.sh
RUN ldconfig \
	&& mkdir -p /var/log/coraza /var/cache/coraza \
	&& chown nginx:nginx /var/log/coraza /var/cache/coraza

COPY --from=rules /out/crs /etc/nginx/coraza/crs
COPY --from=rules /out/plugins /etc/nginx/coraza/plugins
COPY coraza/ /etc/nginx/coraza/
COPY nginx/nginx.conf /etc/nginx/nginx.conf
COPY nginx/templates/ /etc/nginx/templates/
COPY nginx/snippets/ /etc/nginx/snippets/
RUN rm -f /etc/nginx/conf.d/default.conf

# Where nginx proxies to; the official image renders
# /etc/nginx/templates/*.template with envsubst at startup.
ENV APILAB_UPSTREAM=api:8080
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
	CMD curl -fsS http://127.0.0.1:8081/waf-health || exit 1

# ---- allinone: waf + the API simulator in one container ----
FROM waf AS allinone
COPY --from=apilab /out/apilab /usr/local/bin/apilab
COPY docker/allinone-entrypoint.sh /usr/local/bin/allinone-entrypoint.sh
ENV APILAB_UPSTREAM=127.0.0.1:9000
ENTRYPOINT ["/usr/local/bin/allinone-entrypoint.sh"]
CMD ["nginx", "-g", "daemon off;"]
