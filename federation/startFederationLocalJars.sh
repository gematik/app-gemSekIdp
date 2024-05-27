#!/bin/bash

# Define an associative array
declare -A jar_enum

# Define your JARs (java applications to be started) here or comment out the ones you don't need
jar_enum["gsi-fedmaster"]="./gsi-fedmaster/target/gsi-fedmaster-6.0.0.jar"
jar_enum["gsi-server"]="./gsi-server/target/gsi-server-6.0.0.jar"
#jar_enum["auth-server"]="../gras/gra-server/target/gra-server-4.0.2.jar"

# should not be edited below this line

# Flags to check if any required JAR file is missing
missing_gsi=false
missing_other=false

# check if any JAR file is missing
detect_missing_jars() {
  for key in "${!jar_enum[@]}"; do
      if [ ! -f ${jar_enum[$key]} ]; then
          echo "Required file ${jar_enum[$key]} not found."
          if [ "$key" == "gsi-fedmaster" ] || [ "$key" == "gsi-server" ]; then
              missing_gsi=true
          else
              missing_other=true
          fi
      fi
  done
}

process_missing_jars() {
  if [ "$missing_gsi" = true ]; then
      echo "Some required GSI JAR files are missing. Start build..."
      mvn clean package -Dskip.unittests -DskipIntTests -Dskip.dockerbuild=true
      echo "Execute script again to verify all required JAR files exist."
  elif [ "$missing_other" = true ]; then
      echo "Exiting with status 1."
      exit 1
  else
      echo "All required JAR files exist."
  fi
}

check_gitrepo_root_dir(){
  # Check if the ".git" directory exists in the current directory
  if [ ! -d ".git" ]; then
      echo "Error: This script requires to run from the repository root directory."
      exit 1
  fi
}

start_servers(){
if [[ -n "${jar_enum["gsi-fedmaster"]}" ]]; then
  start sh -c "echo -ne '\033]0;Fedmaster\007'; java -jar \"${jar_enum["gsi-fedmaster"]}\" --server.port=8083 | tee gsi-fedmaster.log"
  echo "Fedmaster started successfully."
fi

if [[ -n "${jar_enum["gsi-server"]}" ]]; then
  start sh -c "echo -ne '\033]0;GSI\007'; java -jar \"${jar_enum["gsi-server"]}\" --server.port=8085 --spring.profiles.active=github | tee gsi-server.log"
  echo "gsi-server started successfully."
fi

if [[ -n "${jar_enum["auth-server"]}" ]]; then
  start sh -c "echo -ne '\033]0;Auth-Server\007'; java -jar \"${jar_enum["auth-server"]}\" --server.port=8084 --spring.profiles.active=github | tee auth-server.log"
  echo "auth-server started successfully."
fi
}

check_gitrepo_root_dir
detect_missing_jars
process_missing_jars
export FEDMASTER_SERVER_URL="http://127.0.0.1:8083"
start_servers
