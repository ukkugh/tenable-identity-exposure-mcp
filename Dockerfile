FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir uv

COPY pyproject.toml ./
COPY src/ ./src/

RUN uv pip install --system --no-cache .

ENV TIE_URL=""
ENV TIE_API_KEY=""
ENV TIE_VERIFY_SSL="true"

EXPOSE 8000

ENTRYPOINT ["tenable-tie-mcp"]
# 0.0.0.0 is required to reach the port from outside the container. The SSE
# endpoint has no authentication of its own, so publish it on loopback only
# (see docker-compose.yml) or front it with an authenticating proxy.
CMD ["--transport", "sse", "--host", "0.0.0.0", "--port", "8000"]
