FROM node:20-slim

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install

COPY . ./
RUN npm run build

ENV PORT=3000 \
	BACKEND_URL=https://topcoder-production.up.railway.app \
	USE_ASYNC_SCAN=true \
	MAX_FILES=200 \
	MAX_FILE_BYTES=200000 \
	OVERRIDE_LABEL=guardrails-override
EXPOSE 3000

CMD ["node", "/app/dist/action.js"]
