FROM registry.access.redhat.com/ubi10/ubi-minimal:latest

LABEL name="enforcement-mcp" \
      summary="SELinux/fapolicyd/MLS policy intelligence MCP server" \
      description="Diagnosis and management of host security enforcement policy via MCP" \
      version="0.4.0"

WORKDIR /opt/app-root/src

RUN microdnf install -y python3 python3-pip openssh-clients && microdnf clean all

COPY pyproject.toml README.md LICENSE ./
COPY src/ src/

RUN pip install --no-cache-dir .

ENTRYPOINT ["enforcement-mcp"]
CMD ["--transport", "stdio"]
