# ── Build Stage ────────────────────────────────────────────────────────────
FROM node:20-slim AS build

WORKDIR /app

# Install dependencies
COPY package*.json ./
RUN npm install

# Copy source and build
COPY . .

# Set API URL for Vite build process
ARG VITE_API_BASE_URL=http://localhost:8000
ENV VITE_API_BASE_URL=$VITE_API_BASE_URL

RUN npm run build

# ── Production Stage ───────────────────────────────────────────────────────
FROM nginx:stable-alpine AS runtime

# Copy build artifacts from build stage
COPY --from=build /app/dist /usr/share/nginx/html

# Copy custom nginx config for SPA route fallback
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
