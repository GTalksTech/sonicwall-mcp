# SonicWall NSM MCP server.
#     docker build -t sonicwall-nsm-mcp .
#
# Runtime env (inject secrets from your platform's secret store):
#   MSW_API_KEY_READONLY  read-only MySonicWall API key (vendor boundary)
#   MCP_INBOUND_API_KEY   inbound key checked by the ASGI middleware
#   MSW_TENANT_ID / NSM_TENANT_SERIAL / MSW_TENANT_NAME  tenant identity
#                         (optional — auto-discovered when unset)
#   NSM_URL               NSM region host (default nsm-uswest.sonicwall.com)
#   PORT                  listen port (default 8080)
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt constraints.txt ./
RUN pip install --no-cache-dir -r requirements.txt -c constraints.txt

COPY nsm_auth.py server.py ./

ENV PORT=8080
EXPOSE 8080

# stdout is the log stream: server.py prints one structured JSON line per tool
# call, which your container platform ships to its log store.
CMD ["python", "server.py"]
