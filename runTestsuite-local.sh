#!/bin/bash
# run testsuite against local gsi-server

# this export is redundant as "tiger.yaml" is default
export TIGER_TESTENV_CFGFILE=tiger.yaml
mvn clean verify

# optional: skip unittests, overwrite filter:
# mvn clean verify-Dskip.unittests=true -Dcucumber.filter.tags="@Approval"
