###########
# Builder #
###########
FROM python:3.8.6-slim AS builder

WORKDIR /build

# Setup virtualenv
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy requirements
COPY requirements.txt ./

# Install build dependencies
RUN apt-get update && \
  apt-get install -y \
  # git for installing eth2.0-deposit-cli from GitHub
  git \
  gcc \
  && rm -rf /var/lib/apt/lists/*

# Install dependencies
RUN pip install -r requirements.txt

####################
# Production image #
####################
FROM python:3.8.6-slim

ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /app

# Copy dependencies from build container
COPY --from=builder /opt/venv /opt/venv

# Copy source code
COPY . ./

ENTRYPOINT [ "python", "./horcrux.py"]
