FROM node:20-alpine
RUN apk add --no-cache openssh-client sshpass
WORKDIR /app
COPY server/package.json ./
RUN npm install --omit=dev
COPY server/ ./
COPY client/ ./client/
COPY agent/ ./agent/
RUN mkdir -p /app/data
ENV DB_PATH=/app/data/netctrl.db
ENV PORT=3000
EXPOSE 3000
CMD ["node", "server.js"]
