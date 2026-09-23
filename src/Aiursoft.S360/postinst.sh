#!/bin/sh
set -e
mkdir -p /var/lib/aiursoft-s360
chown www-data:www-data /var/lib/aiursoft-s360

# Bootstrap config if missing (matching Docker entrypoint pattern)
if [ ! -f /etc/aiursoft-s360/appsettings.json ]; then
    cp /usr/share/aiursoft-s360/appsettings.json /etc/aiursoft-s360/appsettings.json
fi
# Replace /usr/share copy with symlink to /etc
rm -f /usr/share/aiursoft-s360/appsettings.json
ln -sf /etc/aiursoft-s360/appsettings.json /usr/share/aiursoft-s360/appsettings.json
