#!/bin/bash

export TIGER_TESTENV_CFGFILE=tiger-external-Idp.yaml

mvn clean verify -pl=gsi-testsuite -Dskip.unittests=true -Dcucumber.filter.tags="@Approval and @EntityStatement"
