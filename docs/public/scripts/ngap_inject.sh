#!/bin/sh
# Simple NGAP malformed packet injection
HOST=${NGAP_HOST:-my5gc-amf.open5gs.svc.cluster.local}
PORT=38412
printf '\x01\xff\x00\xDE\xAD\xBE\xEF' | sctp_test -H "$HOST" -P $PORT 