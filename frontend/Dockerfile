# Step 1: Build stage
FROM node:22-alpine AS build

WORKDIR /app

# Install dependencies
COPY package*.json ./
RUN npm install

# Build arguments for Vite
ARG VITE_API_BASE=/api
ENV VITE_API_BASE=$VITE_API_BASE

# Copy source and build
COPY . .
RUN npm run build

# Step 2: Production web server
FROM nginx:alpine

# Copy nginx config
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Copy build artifacts from stage 1
COPY --from=build /app/dist /usr/share/nginx/html

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
