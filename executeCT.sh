#!/bin/bash
#set -x

exitCode=0;
export TIGER_TESTENV_CFGFILE=tiger-barmer-tu.yaml
mvn clean verify -pl=gsi-testsuite -Dskip.unittests=true -Dcucumber.filter.tags="@TCID:IDPSEKTORAL_ENTITY_STATEMENT_001"
if [[ "$?" -ne 0 ]] ; then
  exitCode=1;
fi
export TIGER_TESTENV_CFGFILE=tiger-ibm-tu.yaml
mvn clean verify -pl=gsi-testsuite -Dskip.unittests=true -Dcucumber.filter.tags="@TCID:IDPSEKTORAL_ENTITY_STATEMENT_001"
if [[ "$?" -ne 0 ]] ; then
  exitCode=1;
fi
export TIGER_TESTENV_CFGFILE=tiger-rise-tu.yaml
mvn clean verify -pl=gsi-testsuite -Dskip.unittests=true -Dcucumber.filter.tags="@TCID:IDPSEKTORAL_ENTITY_STATEMENT_001"
if [[ "$?" -ne 0 ]] ; then
  exitCode=1;
fi
exit $exitCode