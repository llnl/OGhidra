# Containerfile
FROM docker.io/eclipse-temurin:26.0.1_8-jdk-ubi10-minimal

# ENV DEBIAN_FRONTEND=noninteractive

RUN microdnf upgrade -y \
    && microdnf install -y git vim python3 python3-pip wget unzip

ENV GHIDRA_SHA256=aa5cbcbbf48f41ca185fce900e19592f1ade4cd5994eb6e0ede468dac8a6f302
ENV GHIDRA_VERSION=ghidra_12.1_PUBLIC_20260513

WORKDIR /opt
RUN wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1_build/ghidra_12.1_PUBLIC_20260513.zip -O ghidra.zip \
    && echo "${GHIDRA_SHA256} ghidra.zip" | sha256sum -c \
    && unzip ghidra.zip

ENV GHIDRA_INSTALL_DIR=/opt/ghidra_12.1_PUBLIC


RUN git clone -b pyghidra https://github.com/llnl/OGhidra.git \
    && wget -qO- https://astral.sh/uv/install.sh | sh \
    && source $HOME/.local/bin/env



WORKDIR /opt/OGhidra
RUN $HOME/.local/bin/uv sync --extra headless

ADD .env /opt/OGhidra/.env

RUN microdnf install -y python3-tkinter && microdnf clean all

RUN microdnf install -y libXext libXrender libXtst libXi libX11 && microdnf clean all

ENTRYPOINT [ "bash" ]
