FROM node:20-alpine

WORKDIR /usr/src/app

# Copy package files and install dependencies
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

# Copy all application source code
COPY *.js ./
COPY api/ ./api/
COPY core/ ./core/

EXPOSE 3000

ENV PORT=3000

CMD ["node", "server.js"]
