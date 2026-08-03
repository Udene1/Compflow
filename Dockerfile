# ComplianceFlow AI — Multi-Arch Dockerfile (Node.js 20 Alpine)
FROM --platform=$TARGETPLATFORM node:20-alpine AS base

WORKDIR /usr/src/app

# Install build dependencies if needed
RUN apk add --no-cache python3 make g++

# Copy package descriptors and install production dependencies
COPY package*.json ./
RUN npm install --omit=dev

# Copy application source code and assets
COPY . .

EXPOSE 3000

ENV PORT=3000 \
    NODE_ENV=production

CMD ["node", "server.js"]
