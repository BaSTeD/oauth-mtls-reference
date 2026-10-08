# syntax=docker/dockerfile:1

FROM node:22.23.3-alpine3.23 AS build
WORKDIR /app
COPY package.json package-lock.json ./
COPY packages/auth-server/package.json packages/auth-server/
COPY packages/resource-server/package.json packages/resource-server/
COPY packages/demo-client/package.json packages/demo-client/
RUN npm ci
COPY tsconfig.json tsconfig.build.json ./
COPY packages packages
RUN npm run build && npm prune --omit=dev

FROM node:22.23.3-alpine3.23
# openssl is only needed by the certificate scripts
RUN apk add --no-cache openssl \
 && mkdir /certs && chown node:node /certs
ENV NODE_ENV=production
WORKDIR /app
COPY --from=build --chown=node:node /app/node_modules node_modules
COPY --from=build --chown=node:node /app/packages packages
COPY --from=build --chown=node:node /app/dist dist
COPY --chown=node:node package.json ./
COPY --chown=node:node scripts scripts
USER node
EXPOSE 8443
