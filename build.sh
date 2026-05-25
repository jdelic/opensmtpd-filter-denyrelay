#!/bin/bash
go get
go build

fpm \
    -s dir \
    -t deb \
    -p opensmtpd-filter-denyrelay_0.1.2.deb \
    -n opensmtpd-filter-denyrelay \
    -v "0.1.2-0" \
    -m "Jonas Maurus" \
    -d "opensmtpd (>=6.8.0)" \
    -d "opensmtpd (<<8.0)" \
    --description "Allows to limit accounts to a whitelist of allowed recipients or sending email only with validated agent email tokens" \
    --url "https://github.com/jdelic/opensmtpd-filter-denyrelay" \
    opensmtpd-filter-denyrelay=/usr/lib/x86_64-linux-gnu/opensmtpd/filter-denyrelay
