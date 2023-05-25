@Library('gematik-jenkins-shared-library') _

pipeline {
    agent { label 'LTU_DEV' }
    options { disableConcurrentBuilds() }
    stages {
        stage('docker compose') {
            steps {
                dockerLoginGematikRegistry()
                sh("""
                    export appVersion=1.3.6
                    echo '### Stopping services'
                    docker compose -f docker-compose-base.yml -f docker-compose-deployLTU_DEV.yml down -v
                    IMAGES=\$(docker images | grep "gsi" | cut -d" " -f1)
                    docker rmi --force \$IMAGES
                    echo '### Checking for new Docker Image versions'
                    docker-compose -f docker-compose-base.yml -f docker-compose-deployLTU_DEV.yml pull --quiet
                    echo '### Creating services'
                    docker-compose -f docker-compose-base.yml -f docker-compose-deployLTU_DEV.yml up --no-start
                    echo '### Starting services'
                    docker compose -f docker-compose-base.yml -f docker-compose-deployLTU_DEV.yml up -d
                """)
            }
        }
    }
    post {
        always {
            sendEMailNotification(getIdpEMailList())
        }
    }
}
