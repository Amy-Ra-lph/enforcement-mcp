FROM registry.access.redhat.com/hi/python:latest

LABEL name="enforcement-mcp" \
      summary="SELinux/fapolicyd/MLS policy intelligence MCP server" \
      description="Diagnosis and management of host security enforcement policy via MCP" \
      version="0.1.0"

WORKDIR /app

RUN microdnf install -y openssh-clients && microdnf clean all

COPY pyproject.toml README.md LICENSE ./
COPY src/ src/

RUN pip install --no-cache-dir .

USER 1001

ENTRYPOINT ["enforcement-mcp"]
CMD ["--transport", "stdio"]
