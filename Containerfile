FROM registry.access.redhat.com/ubi9/python-312:latest

LABEL name="enforcement-mcp" \
      summary="SELinux/fapolicyd/MLS policy intelligence MCP server" \
      description="Diagnosis and management of host security enforcement policy via MCP" \
      version="0.4.0"

WORKDIR /opt/app-root/src

USER 0
RUN dnf install -y openssh-clients && dnf clean all
USER 1001

COPY pyproject.toml README.md LICENSE ./
COPY src/ src/

RUN pip install --no-cache-dir .

ENTRYPOINT ["enforcement-mcp"]
CMD ["--transport", "stdio"]
