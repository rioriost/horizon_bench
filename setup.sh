#!/bin/bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
install -d -m 700 /opt/horizon-bench
apt-get update -qq
apt-get install -y -qq ca-certificates curl gnupg python3-psycopg2 sysstat \
    libxft2 libxss1 libxrender1 libfontconfig1
install -d /usr/share/postgresql-common/pgdg
curl --fail --silent --show-error https://www.postgresql.org/media/keys/ACCC4CF8.asc \
    -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc
echo 'deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] https://apt.postgresql.org/pub/repos/apt noble-pgdg main' \
    > /etc/apt/sources.list.d/pgdg.list
apt-get update -qq
apt-get install -y -qq postgresql-client-17 postgresql-contrib-17
systemctl disable --now postgresql
curl --fail --location --silent --show-error \
    https://github.com/TPC-Council/HammerDB/releases/download/v6.1/HammerDB-6.1-Prod-Lin-UBU24-x64.tar.gz \
    -o /opt/horizon-bench/hammerdb.tar.gz
echo '9360e045b20ec489bd6de016fbea78df255428eb0f2698330a1db46c7a13e2b1  /opt/horizon-bench/hammerdb.tar.gz' \
    | sha256sum --check
tar -xzf /opt/horizon-bench/hammerdb.tar.gz -C /opt/horizon-bench
python3 -c 'import psycopg2'
/usr/lib/postgresql/17/bin/pgbench --version
