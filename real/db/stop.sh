#!/usr/bin/env bash
# real-db-01: clean PostgreSQL shutdown when the container stops.
pg_ctlcluster "$(ls /usr/lib/postgresql)" main stop -m fast
