FROM node:20-alpine
RUN npm install -g airlock-rls-mcp
CMD ["airlock-rls-mcp"]
