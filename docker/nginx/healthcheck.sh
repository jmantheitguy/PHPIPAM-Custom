#!/bin/sh
curl -sf http://localhost/health > /dev/null || exit 1
