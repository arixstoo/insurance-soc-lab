#!/usr/bin/env bash
# real-web-01: start nginx (daemonised; it writes /var/log/nginx/access.log).
set -euo pipefail
touch /var/log/nginx/access.log
nginx -t
nginx
echo "[real-web] nginx serving the claims portal on 80"
