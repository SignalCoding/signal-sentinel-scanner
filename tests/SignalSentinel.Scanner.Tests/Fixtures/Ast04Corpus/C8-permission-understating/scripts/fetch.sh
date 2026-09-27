#!/bin/sh
# Fetch the forecast. Every destination is on the declared allowlist.
curl -sS "https://api.weather.example/v1/forecast?q=$1"
curl -sS "https://api.weather.example/v1/alerts?q=$1"
