FROM node:22-slim AS frontend-build

WORKDIR /workspace/MCP-Vul/frontend

COPY MCP-Vul/frontend/package.json MCP-Vul/frontend/package-lock.json ./

RUN npm ci

COPY MCP-Vul/frontend ./

RUN npm run build

FROM python:3.12-slim

WORKDIR /workspace

COPY mcp-memory-common ./mcp-memory-common
COPY MCP-Vul ./MCP-Vul
COPY --from=frontend-build /workspace/MCP-Vul/frontend/dist ./MCP-Vul/frontend/dist

RUN python -m pip install -e ./mcp-memory-common -e ./MCP-Vul

WORKDIR /workspace/MCP-Vul

ENV MEMORY_LEAK_APP_HOST=0.0.0.0 \
    MEMORY_LEAK_APP_PORT=8090 \
    MEMORY_LEAK_APP_WORKSPACE_ROOTS=/workspace/demo/memory_leak_corpus \
    MEMORY_LEAK_APP_ARTIFACT_DIR=/workspace/results/app_scans \
    MCP_STATIC_SERVER_URL=http://memory-static-analysis:8081/mcp \
    MCP_DYNAMIC_SERVER_URL=http://dynamic-analysis:8080/mcp

EXPOSE 8090

CMD ["mcp-vul-memory-app", "--host", "0.0.0.0", "--port", "8090"]
