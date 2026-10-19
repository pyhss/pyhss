FROM python:3.12-slim-trixie AS envsubst

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install go envsubst - needed for config processing
# It is mightier than the default envsubst from gettext
COPY docker/install-go-envsubst.sh /install-go-envsubst.sh
RUN chmod +x /install-go-envsubst.sh && \
    /install-go-envsubst.sh && \
    rm /install-go-envsubst.sh

FROM python:3.12-slim-trixie AS python-venv

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

# Create pyhss folder and install system dependencies for python setuptool + wheels
RUN mkdir -p /opt/pyhss && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        libmariadb-dev \
        libsctp-dev \
        lksctp-tools \
        pkg-config \
        gcc && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copy requirements.txt early to have cache hits
COPY requirements.txt /opt/pyhss
# Create and activate virtual environment
RUN python3 -m venv /opt/pyhss/venv
ENV PATH="/opt/pyhss/venv/bin:$PATH"

# Install Python dependencies
RUN pip install --upgrade pip setuptools wheel
RUN pip install --no-cache-dir -r /opt/pyhss/requirements.txt

FROM python:3.12-slim-trixie AS pyhss-runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libmariadb3 \
        libsctp1 \
        lksctp-tools \
        curl \
        netcat-traditional && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copy envsubst from the previous stage
COPY --from=envsubst /usr/local/bin/envsubst /usr/local/bin/envsubst

# Create application user and group
RUN useradd -d /opt/pyhss -r -m pyhss

# Copy Python virtual environment from the previous stage and set PATH
ENV PATH="/opt/venv/bin:$PATH"
COPY --from=python-venv /opt/pyhss/venv /opt/venv

# Copy application code
COPY . /opt/pyhss

# Change log directory ownership back to pyhss user and delete the docker folder
RUN chown pyhss:pyhss /opt/pyhss/log
VOLUME /opt/pyhss/log

# Create a volume for the sqlite database
RUN mkdir /var/lib/pyhss && \
    chown pyhss:pyhss /var/lib/pyhss/
VOLUME /var/lib/pyhss

# Delete docker folder from the final image. COPY --exclude and dockerignore are not an option here
RUN rm -rf /opt/pyhss/docker

# Copy configuration template and processing script
COPY docker/config.yaml /opt/pyhss/config.yaml.template
COPY docker/launch-container.sh /opt/pyhss/launch-container.sh

# HTTP API
EXPOSE 8080

# Diameter
EXPOSE 3868

# GSUP
EXPOSE 4222

# 5G UDR (Nudr_DataRepository, HTTP/2)
EXPOSE 7777

# Metrics
EXPOSE 9191

USER pyhss
WORKDIR /opt/pyhss/services
CMD ["/opt/pyhss/launch-container.sh"]
