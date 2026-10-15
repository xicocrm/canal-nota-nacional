FROM node:20-alpine

RUN apk add --no-cache curl

WORKDIR /app
COPY server.mjs ./

ENV NODE_ENV=production
EXPOSE 3000

CMD ["node", "server.mjs"]
