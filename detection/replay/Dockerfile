# Test-only image for scripts/noise_report.py: the Wazuh manager plus clockshim, a tiny
# LD_PRELOAD library (clockshim.c, in this folder) that lets the replay set the engine's
# wall clock to each event's simulated timestamp. Never used by the lab.
ARG WAZUH_VERSION=4.14.9

FROM amazonlinux:2023 AS build
RUN dnf install -y gcc && dnf clean all
COPY clockshim.c /src/clockshim.c
RUN mkdir -p /out && gcc -O2 -Wall -Wextra -Werror -Wno-nonnull-compare -shared -fPIC -o /out/clockshim.so /src/clockshim.c -ldl

FROM wazuh/wazuh-manager:${WAZUH_VERSION}
COPY --from=build /out/clockshim.so /usr/local/lib/clockshim.so
COPY driver.py /replay/driver.py
# Offset 0 until the driver writes it. World-readable: analysisd runs as user wazuh.
RUN echo '+0                             ' > /var/ossec/tmp/clockshim.offset \
 && chmod 0644 /var/ossec/tmp/clockshim.offset
