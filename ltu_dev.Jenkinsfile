@Library('gematik-jenkins-shared-library') _

pipeline {
    agent { label 'LTU_DEV' }
    options { disableConcurrentBuilds() }
    stages {
        stage('docker compose') {
            steps {
                dockerLoginGematikRegistry()
                sh("""
                    export appVersion=3.0.1
                    export serverLoglevel=debug
                    echo '### Stopping services'
                    docker compose -f docker-compose-base.yml -f docker-compose-deployLTU_DEV.yml down -v
                    echo '### Checking for new Docker Image versions'
                    docker-compose -f docker-compose-base.yml -f docker-compose-deployLTU_DEV.yml pull --quiet
                    echo '### Creating services'
                    docker-compose -f docker-compose-base.yml -f docker-compose-deployLTU_DEV.yml up --no-start
                    echo '### Starting services'
                    docker compose -f docker-compose-base.yml -f docker-compose-deployLTU_DEV.yml up -d
                """)
            }
        }
        stage('Remove dangling and unused docker images') {
            steps {
                sh "chmod +x ./removeDockerImages.sh"
                sh './removeDockerImages.sh eu.gcr.io/gematik-all-infra-prod/idp/gsi-server'
            }
        }
    }
    post {
        always {
            sendEMailNotification(getIdpEMailList())
        }
    }
}
