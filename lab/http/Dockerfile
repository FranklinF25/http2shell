ARG BASE_IMAGE=node:24.22.0
FROM ${BASE_IMAGE}
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev && npm cache clean --force
COPY server.js ./
USER node
EXPOSE 3000
CMD ["node", "server.js"]
