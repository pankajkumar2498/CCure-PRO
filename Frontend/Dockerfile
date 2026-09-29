# Base images are pinned by digest, so a rebuild of the same commit starts from
# the same bytes; Dependabot (docker ecosystem) proposes updates when the tags
# move. CI builds this once per commit and tags it with the commit SHA — see
# .github/workflows/images.yml and docs/ci/CONTAINER_IMAGES.md.
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

RUN npm run build

# ── Production Stage ───────────────────────────────────────────────────────
FROM nginx:stable-alpine@sha256:985220252f3863977e468f611ef118ebd01421289dd86ee1ae99cb068c3bce2b AS runtime

# Copy build artifacts from build stage
COPY --from=build /app/dist /usr/share/nginx/html

# Copy custom nginx config for SPA route fallback
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
