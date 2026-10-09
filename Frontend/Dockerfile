# Base images are pinned by digest, so a rebuild of the same commit starts from
# the same bytes; Dependabot (docker ecosystem) proposes a new digest when the
# image behind the tag is rebuilt. Moving to another Node or nginx version is a
# deliberate edit of the tag, not a Dependabot PR. CI builds this once per
# commit and tags it with the commit SHA — see .github/workflows/images.yml and
# docs/ci/CONTAINER_IMAGES.md.
# ── Build Stage ────────────────────────────────────────────────────────────
# Node 22, the version CI tests and lints the frontend with. The image used to
# build on 20, so what shipped was compiled by a toolchain CI never ran.
FROM node:26-slim@sha256:ec7758ee051e457b468b32bde57b0879010b325bb9862718e9615225ce4aaae1 AS build

WORKDIR /app

# Install exactly what package-lock.json records. `npm install` re-resolves the
# ranges in package.json and may rewrite the lock, so two builds of one commit
# could bundle different code; `npm ci` refuses to run if the lock and
# package.json disagree.
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund

# Copy source and build
COPY . .

# Set API URL for Vite build process
ARG VITE_API_BASE_URL=/api
ENV VITE_API_BASE_URL=$VITE_API_BASE_URL

RUN npm run ux4g:check -- --dependencies-only && npm run build

# ── Production Stage ───────────────────────────────────────────────────────
FROM nginx:stable-alpine@sha256:985220252f3863977e468f611ef118ebd01421289dd86ee1ae99cb068c3bce2b AS runtime

# Patch the base-image packages the scan flags with a published fix:
# pcre2 10.48-r0 -> 10.49-r0 (CVE-2026-103111) and libexpat 2.8.4-r0 -> 2.8.5-r0
# (CVE-2026-93990, previously a dated exception in trivy-frontend.yaml). Scoped
# to those packages so the pinned base stays otherwise untouched; drop each
# once the digest moves to an nginx build that already carries the fix.
RUN apk upgrade --no-cache pcre2 libexpat

# Copy build artifacts from build stage
COPY --from=build /app/dist /usr/share/nginx/html

# Copy custom nginx config for SPA route fallback
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
