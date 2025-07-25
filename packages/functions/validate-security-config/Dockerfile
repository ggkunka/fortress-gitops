# Security Configuration Validator kpt Function
FROM gcr.io/kpt-fn/starlark:v0.4.3

# Copy validation script
COPY validate-security.star /home/nonroot/validate-security.star

# Set the main script
ENV KPT_FN=/home/nonroot/validate-security.star

# Metadata
LABEL "kpt.dev/fn.name"="validate-security-config"
LABEL "kpt.dev/fn.description"="Validates security configurations for MCP Security Platform"
LABEL "kpt.dev/fn.keywords"="security,validation,mcp"
LABEL "kpt.dev/fn.version"="v1.0.0"