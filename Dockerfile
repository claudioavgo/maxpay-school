FROM node:22-slim
RUN apt-get update && apt-get install -y --no-install-recommends openssl python3 make g++ && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run typecheck
EXPOSE 8443
CMD ["sh", "-c", "npm run keys >/dev/null && npm run seed && npm start"]
