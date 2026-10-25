# syntax=docker/dockerfile:1.7
#
# OpenCyber Harness image.
#
# The image is the execution substrate for an agent runtime: a stdio MCP server
# with 173 executable adapters (including optional integrations, SDR, Wi-Fi, Bluetooth, NFC, JTAG,
# serial, CAN, logic-analyzer, GPS, and IR tooling) and a native layer for
# hardware inventory, serial sessions, firmware triage, HTTP, browser, API,
# audit, and workspace work. Three properties matter more than image size:
#
# 1. Offline readiness. A fresh container must be able to run a real scan with
#    no egress. Nuclei templates, SecLists, rockyou, and exploitdb are baked in;
#    an asset manifest records them. Nmap and its dependent integrations
#    remain optional operator-supplied components pending redistribution review.
# 2. Verifiability. The build fails if any required catalog executable, template store,
#    wordlist, hardware binary, or agent tool is missing. `opencyber-doctor` is
#    the same gate at run time and is also the healthcheck.
# 3. Hardware is opt-in at the host. The binaries are installed; devices are
#    passed through with --device/--network host. `oc_hardware_readiness`
#    reports the difference instead of pretending a missing radio works.
#
# The runtime user is root on purpose: tcpdump, hashcat, aircrack-ng, and
# SDR tools need privileged access inside the container. Harden from the host:
#
#   docker run -d --name opencyber \
#     --cap-drop=ALL --cap-add=NET_RAW --cap-add=NET_ADMIN --cap-add=NET_BIND_SERVICE \
#     --security-opt no-new-privileges \
#     --read-only --tmpfs /tmp --tmpfs /run \
#     --tmpfs /root/.config --tmpfs /root/.cache \
#     -v opencyber-workspace:/workspace \
#     ghcr.io/mitkox/opencyber:0.5.0
#
# The /root/.config and /root/.cache tmpfs mounts are required under a read-only
# rootfs: Chromium's crashpad handler aborts with
# "chrome_crashpad_handler: --database is required" and browser tools fail.

FROM --platform=$BUILDPLATFORM golang:1.27.3-bookworm@sha256:972b4110ba0f47539a975c31e52c64765e1ff19f2d74469ae4a595c6676e80a5 AS go-tools

ARG TARGETOS
ARG TARGETARCH
ARG ANEW_VERSION=v0.1.1
ARG SUBZY_VERSION=v1.2.1

RUN apt-get update && apt-get install -y --no-install-recommends patch \
    && rm -rf /var/lib/apt/lists/*

COPY scripts/build-go-tools.sh /build/scripts/build-go-tools.sh
COPY compliance/patches/go /build/compliance/patches/go

RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go install github.com/tomnomnom/anew@$ANEW_VERSION \
    && CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go install github.com/PentestPad/subzy@$SUBZY_VERSION \
    && mkdir -p /out \
    && find /go/bin -type f -name anew -exec cp {} /out/anew \; \
    && find /go/bin -type f -name subzy -exec cp {} /out/subzy \;

RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    set -eu; \
    for tool in jaeles kube-bench urlfinder yq; do \
      bash /build/scripts/build-go-tools.sh "$tool" /src /out || exit "$?"; \
    done \
    && mkdir -p /out/licenses/go-modules \
    && cd /go/pkg/mod \
    && find . -type f \
        \( -iname "LICENSE" -o -iname "LICENSE.*" -o -iname "COPYING" -o -iname "COPYING.*" -o -iname "NOTICE" -o -iname "NOTICE.*" \) \
        -exec cp --parents {} /out/licenses/go-modules/ \; \
    && tar -czf /out/sources/go-modules.tar.gz -C /go/pkg mod \
    && cd /out && sha256sum anew urlfinder subzy jaeles kube-bench yq > /out/sources/binaries.sha256

FROM --platform=$TARGETPLATFORM rust:1.99-bookworm@sha256:48b7f435b8fc6378ce43b44f15e3a47fd8919b2825f835c39bd4bd3da50af5b8 AS rust-tools

ARG X8_VERSION=4.3.2
ARG PWNINIT_VERSION=3.3.3

RUN --mount=type=cache,target=/usr/local/cargo/registry --mount=type=cache,target=/usr/local/cargo/git \
    cargo install --version "$X8_VERSION" x8 \
    && cargo install --locked --version "$PWNINIT_VERSION" pwninit \
    && mkdir -p /out/licenses/rust-crates \
    && cd /usr/local/cargo \
    && find registry/src -type f \
        \( -iname 'LICENSE' -o -iname 'LICENSE.*' -o -iname 'COPYING' -o -iname 'COPYING.*' -o -iname 'NOTICE' -o -iname 'NOTICE.*' \) \
        -exec cp --parents {} /out/licenses/rust-crates/ \; \
    && if [ -d git/checkouts ]; then \
        find git/checkouts -type f \
            \( -iname 'LICENSE' -o -iname 'LICENSE.*' -o -iname 'COPYING' -o -iname 'COPYING.*' -o -iname 'NOTICE' -o -iname 'NOTICE.*' \) \
            -exec cp --parents {} /out/licenses/rust-crates/ \; ; \
    fi \
    && mkdir -p /out/sources \
    && tar -czf /out/sources/rust-crates.tar.gz -C /usr/local/cargo registry .crates.toml .crates2.json \
    && if [ -d /usr/local/cargo/git ]; then tar -czf /out/sources/rust-git.tar.gz -C /usr/local/cargo git; fi \
    && cd /usr/local/cargo/bin && sha256sum x8 pwninit > /out/sources/binaries.sha256

FROM --platform=$TARGETPLATFORM debian:bookworm@sha256:854dd8ab51d62866dbd8f5431d15ce77b12983a2a4a1e1fe43a2395dc7ef9f61 AS hashpump-tools

ARG HASHPUMP_COMMIT=b822764fa71209858c91378736d43d082c674e96

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates g++ git libssl-dev make \
    && git clone --depth 1 https://github.com/mheistermann/HashPump-partialhash.git /src/hashpump \
    && git -C /src/hashpump fetch --depth 1 origin "$HASHPUMP_COMMIT" \
    && git -C /src/hashpump checkout --detach "$HASHPUMP_COMMIT" \
    && make -C /src/hashpump \
    && mkdir -p /out/licenses/hashpump \
    && cp /src/hashpump/hashpump /out/hashpump \
    && cp /src/hashpump/LICENSE.TXT /out/licenses/hashpump/LICENSE.TXT \
    && mkdir -p /out/sources \
    && tar --exclude=.git --exclude=hashpump/hashpump --exclude='*.o' -czf /out/sources/hashpump.tar.gz -C /src hashpump \
    && cd /out && sha256sum hashpump > /out/sources/binaries.sha256

FROM kalilinux/kali-rolling:latest@sha256:4be87f78671419c13dcf4f207ead1cfc0de178ea281b3f69c0f49b69ba4e79b1 AS runtime

ARG DEBIAN_FRONTEND=noninteractive
ARG TARGETARCH
# Release version. Keep in sync with src/opencyber/__init__.py;
# scripts/check-version-consistency.py enforces this.
ARG OPENCYBER_VERSION=0.5.0
# Optional offline CVE index. Empty keeps the image smaller; set to e.g.
# "2024 2025 2026" to bake NVD-derived records into oc_cve_lookup.
ARG OPENCYBER_CVE_YEARS=""

# Pinned offline assets. Bump the version and the digest together.
ARG NUCLEI_TEMPLATES_VERSION=v10.5.1
ARG NUCLEI_TEMPLATES_SHA256=30fe1cfaced4635f886e4a2673641bba86998dceec28e468274524e789aa56eb
ARG YQ_VERSION=v4.54.1

COPY compliance/apt-public-exclusions.pref /etc/apt/preferences.d/opencyber-public-exclusions

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        aircrack-ng \
        amass \
        apktool \
        arjun \
        arp-scan \
        autopsy \
        avrdude \
        bettercap \
        binutils \
        binwalk \
        bladerf \
        bluez \
        bluez-tools \
        bully \
        can-utils \
        bulk-extractor \
        ca-certificates \
        checksec \
        cowpatty \
        curl \
        dalfox \
        dfu-util \
        dirb \
        dirsearch \
        dnsenum \
        dotdotpwn \
        enum4linux \
        enum4linux-ng \
        esptool \
        evil-winrm \
        exploitdb \
        feroxbuster \
        ffuf \
        fierce \
        file \
        flashrom \
        foremost \
        gdb \
        gdb-multiarch \
        getallurls \
        gpsd \
        gpsd-clients \
        ghidra \
        git \
        gobuster \
        hackrf \
        hakrawler \
        hash-identifier \
        hashcat \
        hashcat-utils \
        hcxdumptool \
        hcxtools \
        httpie \
        httpx-toolkit \
        hydra \
        iproute2 \
        iw \
        jadx \
        john \
        jq \
        katana \
        kismet \
        libcap2-bin \
        libimage-exiftool-perl \
        libnfc-bin \
        libnfc-examples \
        limesuite \
        lirc \
        masscan \
        mdk4 \
        medusa \
        mfcuk \
        mfoc \
        minicom \
        mitmproxy \
        nbtscan \
        netdiscover \
        nikto \
        nuclei \
        nodejs \
        node-playwright \
        openocd \
        ophcrack \
        paramspider \
        patator \
        pcsc-tools \
        picocom \
        pixiewps \
        proxmark3 \
        python3 \
        python3.13 \
        python3.13-venv \
        python3-aiohttp \
        python3-bs4 \
        python3-can \
        python3-flask \
        python3-mcp \
        python3-pip \
        python3-psutil \
        python3-pwntools \
        python3-playwright \
        python3-requests \
        python3-selenium \
        python3-setuptools \
        python3-shodan \
        python3-venv \
        qemu-system-arm \
        qemu-user \
        qsreplace \
        radare2 \
        recon-ng \
        reaver \
        responder \
        ripgrep \
        ropper \
        ruby \
        rtl-433 \
        rtl-sdr \
        samba-common-bin \
        scalpel \
        screen \
        seclists \
        sherlock \
        sigrok-cli \
        sigrok-firmware-fx2lafw \
        sleuthkit \
        smbmap \
        soapysdr-tools \
        socat \
        spiderfoot \
        sqlmap \
        steghide \
        stlink-tools \
        subfinder \
        tcpdump \
        testdisk \
        theharvester \
        tini \
        trivy \
        tshark \
        ubertooth \
        unblob \
        urjtag \
        uro \
        usbutils \
        usbguard \
        v4l-utils \
        wafw00f \
        webshells \
        whatweb \
        wfuzz \
        wifite \
        wireshark \
        wireless-tools \
        wordlists \
        xsser \
        xxd \
        zaproxy \
        chromium \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Prowler 5.45's published pyproject uses a uv override for PyMongo 4.18.2:
# Huawei SDK's wheel still pins 4.15.1 and only consumes its bson types. pip
# ignores uv overrides, so apply the same upstream override explicitly below.
RUN python3 -m venv --system-site-packages /opt/opencyber-analysis \
    && /opt/opencyber-analysis/bin/python -m pip install --no-cache-dir --upgrade pip==26.2.2 \
    && /opt/opencyber-analysis/bin/python -m pip install --no-cache-dir \
        angr==10.0.0 \
        volatility3==2.28.0 \
    && python3 -m venv --system-site-packages /opt/opencyber-checkov \
    && /opt/opencyber-checkov/bin/python -m pip install --no-cache-dir --upgrade pip==26.2.2 \
    && /opt/opencyber-checkov/bin/python -m pip install --no-cache-dir checkov==3.3.20 \
    && python3 -m venv --system-site-packages /opt/opencyber-kube-hunter \
    && /opt/opencyber-kube-hunter/bin/python -m pip install --no-cache-dir --upgrade pip==26.2.2 \
    && /opt/opencyber-kube-hunter/bin/python -m pip install --no-cache-dir kube-hunter==0.6.8 \
    && python3.13 -m venv /opt/opencyber-prowler \
    && /opt/opencyber-prowler/bin/python -m pip install --no-cache-dir --upgrade pip==26.2.2 \
    && /opt/opencyber-prowler/bin/python -m pip install --no-cache-dir prowler==5.45.0 \
    && /opt/opencyber-prowler/bin/python -m pip install --no-cache-dir --no-deps --upgrade pymongo==4.18.2

RUN gem install --no-document zsteg -v 0.2.14 \
    && gem install --no-document one_gadget -v 2.1.1

COPY --from=go-tools /out/anew /usr/local/bin/anew
COPY --from=go-tools /out/urlfinder /usr/local/bin/urlfinder
COPY --from=go-tools /out/subzy /usr/local/bin/subzy
COPY --from=go-tools /out/jaeles /usr/local/bin/jaeles
COPY --from=go-tools /out/kube-bench /usr/local/bin/kube-bench
COPY --from=go-tools /out/yq /usr/local/bin/yq
COPY --from=go-tools /out/licenses /usr/share/opencyber/licenses/go
COPY --from=rust-tools /usr/local/cargo/bin/x8 /usr/local/bin/x8
COPY --from=rust-tools /usr/local/cargo/bin/pwninit /usr/local/bin/pwninit
COPY --from=rust-tools /out/licenses /usr/share/opencyber/licenses/rust
COPY --from=hashpump-tools /out/hashpump /usr/local/bin/hashpump
COPY --from=hashpump-tools /out/licenses /usr/share/opencyber/licenses/hashpump

RUN ln -sf /opt/opencyber-analysis/bin/vol /usr/local/bin/vol \
    && ln -sf /opt/opencyber-analysis/bin/vol /usr/local/bin/volatility3 \
    && ln -sf /opt/opencyber-checkov/bin/checkov /usr/local/bin/checkov \
    && ln -sf /opt/opencyber-kube-hunter/bin/kube-hunter /usr/local/bin/kube-hunter \
    && ln -sf /opt/opencyber-prowler/bin/prowler /usr/local/bin/prowler \
    && ln -sf /usr/bin/getallurls /usr/local/bin/gau \
    && ln -sf /usr/bin/httpx-toolkit /usr/local/bin/httpx \
    && ln -sf /usr/bin/ROPgadget /usr/local/bin/ROPgadget \
    && ln -sf /usr/bin/shodan /usr/local/bin/shodan

ARG DOCKER_BENCH_COMMIT=154869da6418089decf7e1ab0cfca0e1cdfc5c49

RUN git clone --depth 1 https://github.com/docker/docker-bench-security.git /opt/docker-bench-security \
    && git -C /opt/docker-bench-security fetch --depth 1 origin "$DOCKER_BENCH_COMMIT" \
    && git -C /opt/docker-bench-security checkout --detach "$DOCKER_BENCH_COMMIT" \
    && rm -rf /opt/docker-bench-security/.git \
    && mkdir -p /usr/share/opencyber/licenses/docker-bench-security \
    && cp /opt/docker-bench-security/LICENSE.md /usr/share/opencyber/licenses/docker-bench-security/LICENSE.md \
    && ln -s /opt/docker-bench-security/docker-bench-security.sh /usr/local/bin/docker-bench-security

WORKDIR /opt/opencyber
COPY pyproject.toml README.md LICENSE THIRD_PARTY_NOTICES.md SOURCE_OFFER.md ./
COPY CONTRIBUTING.md SECURITY.md CHANGELOG.md SUPPORT.md CODE_OF_CONDUCT.md ./
COPY docs ./docs
COPY packaging ./packaging
COPY src ./src

RUN python3 -m venv --system-site-packages /opt/opencyber-venv \
    && /opt/opencyber-venv/bin/python -m pip install --no-cache-dir --upgrade pip==26.2.2 \
    && /opt/opencyber-venv/bin/python -m pip install --no-cache-dir --upgrade "mcp>=2.3,<3" "pycparser==3.0" playwright==1.64.1 \
    && /opt/opencyber-venv/bin/python -m pip install --no-cache-dir --no-deps --no-build-isolation /opt/opencyber \
    && pyver="$(/opt/opencyber-venv/bin/python -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')" \
    && printf '%s\n' "/opt/opencyber-analysis/lib/python${pyver}/site-packages" \
        > "/opt/opencyber-venv/lib/python${pyver}/site-packages/opencyber-analysis.pth" \
    && /opt/opencyber-venv/bin/python -c "import angr, volatility3" \
    && mkdir -p /workspace /usr/share/opencyber/licenses/opencyber \
        /usr/share/opencyber/docs /usr/share/opencyber/host \
    && cp LICENSE THIRD_PARTY_NOTICES.md SOURCE_OFFER.md /usr/share/opencyber/licenses/opencyber/ \
    && cp docs/HARDWARE.md docs/AIRGAP.md /usr/share/opencyber/docs/ \
    && cp docs/*.md /usr/share/opencyber/docs/ \
    && cp README.md CONTRIBUTING.md SECURITY.md CHANGELOG.md SUPPORT.md CODE_OF_CONDUCT.md \
        /usr/share/opencyber/docs/ \
    && cp packaging/99-opencyber-hw.rules /usr/share/opencyber/host/

ENV PATH="/opt/opencyber-venv/bin:/opt/opencyber-analysis/bin:/opt/opencyber-checkov/bin:/opt/opencyber-kube-hunter/bin:/opt/opencyber-prowler/bin:${PATH}" \
    OPENCYBER_WORKSPACE=/workspace \
    PYTHONUNBUFFERED=1

# Build-only pip copies contain an obsolete vendored pkg_resources snapshot.
# Remove those complete copies after installation; system tooling keeps the
# distro-maintained pip. Prowler has its own supported Python 3.13 environment.
RUN for environment in analysis checkov kube-hunter prowler venv; do \
      "/opt/opencyber-${environment}/bin/python" -m pip uninstall -y pip; \
    done \
    && prowler --version \
    && yq --version

# Nuclei templates, baked into the store nuclei expects. The store must be a
# real directory: nuclei silently lists zero templates when this path is a
# symlink, which turns oc_nuclei into a no-op.
RUN set -eux; \
    curl -fsSL -o /tmp/nuclei-templates.tar.gz \
      "https://codeload.github.com/projectdiscovery/nuclei-templates/tar.gz/refs/tags/${NUCLEI_TEMPLATES_VERSION}"; \
    echo "${NUCLEI_TEMPLATES_SHA256}  /tmp/nuclei-templates.tar.gz" | sha256sum -c -; \
    mkdir -p /root/.local/nuclei-templates; \
    tar -xzf /tmp/nuclei-templates.tar.gz \
      --directory /root/.local/nuclei-templates \
      --strip-components=1; \
    rm /tmp/nuclei-templates.tar.gz; \
    printf '%s\n' "${NUCLEI_TEMPLATES_VERSION}" > /root/.local/nuclei-templates/.opencyber-version; \
    ln -sfn /root/.local/nuclei-templates /usr/share/nuclei-templates; \
    test "$(find /root/.local/nuclei-templates -name '*.yaml' -type f | wc -l)" -gt 5000

# Prime nuclei's template cache before the asset manifest is recorded. The
# first `nuclei -tl` writes .checksum/.new-additions into the store; without
# this step the manifest would be stale the moment the acceptance gate runs.
RUN test "$(nuclei -tl -silent 2>/dev/null | wc -l)" -gt 1000

# Wordlists that every credential and content-discovery playbook assumes exist.
RUN set -eux; \
    cd /usr/share/wordlists; \
    gunzip -kf rockyou.txt.gz; \
    chmod 0644 rockyou.txt; \
    ln -sfn /usr/share/seclists seclists; \
    test -s rockyou.txt; \
    test -r seclists/Discovery/Web-Content/common.txt

# Optional NVD-derived CVE index for fully offline oc_cve_lookup.
RUN if [ -n "${OPENCYBER_CVE_YEARS}" ]; then \
      mkdir -p /usr/share/opencyber/cve /tmp/nvd; \
      /opt/opencyber-venv/bin/python -m opencyber.cve_index \
        --years "${OPENCYBER_CVE_YEARS}" \
        --download-dir /tmp/nvd \
        --output /usr/share/opencyber/cve/cve.sqlite; \
      rm -rf /tmp/nvd; \
    fi

# Record the offline asset inventory now that templates and wordlists are in
# place. The doctor compares measured counts and sizes against this manifest.
RUN /opt/opencyber-venv/bin/opencyber-assets --write /usr/share/opencyber/asset-manifest.json --deep --json \
    && /opt/opencyber-venv/bin/opencyber-assets --verify --deep --json

# Build-time acceptance gate. A release that cannot load templates, cannot
# scan, or has lost a catalog binary fails here instead of at first tool call.
RUN set -eux; \
    opencyber-doctor; \
    test -x /opt/opencyber-venv/bin/opencyber-assets; \
    test -x /opt/opencyber-venv/bin/opencyber-hardware; \
    test "$(command -v nuclei)" != ""; \
    test "$(nuclei -tl -silent 2>/dev/null | wc -l)" -gt 1000; \
    for binary in hackrf_info hackrf_transfer hackrf_sweep rtl_sdr rtl_test rtl_power rtl_433 \
        SoapySDRUtil LimeUtil bladeRF-cli ubertooth-util ubertooth-rx ubertooth-scan \
        iw iwconfig wifite hcxdumptool hcxpcapngtool reaver bully pixiewps mdk4 cowpatty bettercap \
        bluetoothctl btmon hcitool btmgmt proxmark3 nfc-list nfc-poll nfc-mfclassic mfoc mfcuk pcsc_scan \
        lsusb usbguard openocd jtag avrdude dfu-util esptool st-info st-flash minicom picocom screen \
        flashrom sigrok-cli qemu-arm qemu-system-arm gdb-multiarch unblob \
        candump cansend cansniffer canbusload isotpsend isotprecv \
        gpsmon gpspipe gpsfake lircd ip apktool jadx; do \
      command -v "$binary" >/dev/null || { echo "missing hardware binary: $binary" >&2; exit 1; }; \
    done

LABEL org.opencontainers.image.title="OpenCyber Harness" \
      org.opencontainers.image.description="Security MCP toolkit for authorized red and blue team work" \
      org.opencontainers.image.source="https://github.com/mitkox/opencyber" \
      org.opencontainers.image.url="https://github.com/mitkox/opencyber" \
      org.opencontainers.image.version="${OPENCYBER_VERSION}" \
      com.opencyber.harness.version="${OPENCYBER_VERSION}" \
      org.opencontainers.image.licenses="Apache-2.0 AND LicenseRef-OpenCyber-Third-Party" \
      ai.opencyber.nuclei-templates="${NUCLEI_TEMPLATES_VERSION}" \
      ai.opencyber.yq="${YQ_VERSION}"

# `opencyber-doctor` checks the catalog, offline assets and agent tooling, and
# exits non-zero when degraded. It is cheap (~0.2s) and does not import MCPServer.
HEALTHCHECK --interval=30s --timeout=15s --start-period=20s --retries=3 \
    CMD ["opencyber-doctor", "--quiet"]

VOLUME ["/workspace"]

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["sleep", "infinity"]

# Build this separate target with the same platform, arguments, and build cache
# as the tested runtime. Source archives never bloat the default runtime image.
FROM runtime AS source-capture
ARG TARGETARCH
COPY --from=go-tools /out/sources /source-inputs/go
COPY --from=rust-tools /out/sources /source-inputs/rust
COPY --from=hashpump-tools /out/sources /source-inputs/hashpump
COPY Dockerfile /source-inputs/Dockerfile
COPY scripts/capture-corresponding-source.py scripts/verify-corresponding-source.py /source-inputs/
COPY . /source-inputs/context/
RUN python3 /source-inputs/capture-corresponding-source.py --output /corresponding-source --platform "linux/${TARGETARCH}" \
    && python3 /source-inputs/verify-corresponding-source.py /corresponding-source

FROM scratch AS corresponding-source
COPY --from=source-capture /corresponding-source /

FROM runtime AS final
