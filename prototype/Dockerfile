# Decoy MCP node. Standard library only, so no dependency layer.
FROM python:3.13-slim

# Runs unprivileged: a decoy is attacker-facing by design.
RUN useradd --create-home --shell /usr/sbin/nologin decoy
WORKDIR /app
COPY bitorus/ ./bitorus/
USER decoy

ENV NODE_ID=local PORT=8080
EXPOSE 8080

# Binds 0.0.0.0 inside the container only. Whether that is reachable from
# anywhere is a decision for the network policy, not this file.
CMD ["sh", "-c", "python3 -m bitorus.decoy.http --node \"$NODE_ID\" --port \"$PORT\" --host 0.0.0.0"]
