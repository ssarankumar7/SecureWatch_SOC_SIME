#!/usr/bin/env bash
set -euo pipefail

# Restrict values interpolated into the mongosh expression. Passwords generated
# with `openssl rand -hex 32` satisfy this constraint and need no URI escaping.
for variable_name in MONGO_APP_USERNAME MONGO_APP_PASSWORD MONGO_APP_DATABASE; do
  value="${!variable_name:-}"
  if [[ -z "$value" || ! "$value" =~ ^[A-Za-z0-9_-]+$ ]]; then
    echo "Invalid or missing $variable_name; use only letters, digits, underscore, and hyphen." >&2
    exit 1
  fi
done

mongosh --quiet \
  --host 127.0.0.1 \
  --port 27017 \
  --eval '
    db.getSiblingDB("admin").auth(
      process.env.MONGO_INITDB_ROOT_USERNAME,
      process.env.MONGO_INITDB_ROOT_PASSWORD
    );
    db.getSiblingDB(process.env.MONGO_APP_DATABASE).createUser({
      user: process.env.MONGO_APP_USERNAME,
      pwd: process.env.MONGO_APP_PASSWORD,
      roles: [{ role: "readWrite", db: process.env.MONGO_APP_DATABASE }]
    });
  '
