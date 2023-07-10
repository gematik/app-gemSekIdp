@Library('gematik-jenkins-shared-library') _

def REPO_URL = createGitUrl('git/idp/gem-sek-idp')
def JIRA_PROJECT_ID = 'GSI'
def GITLAB_PROJECT_ID = '1173'
def BUILD_VERSION = '1-SNAPSHOT'
def CREDENTIAL_ID_GEMATIK_GIT = 'svc_gitlab_prod_credentials'
def DOCKER_IMAGES = ['idp/gsi-server']

pipeline {
    options {
        disableConcurrentBuilds()
        buildDiscarder logRotator(artifactDaysToKeepStr: '', artifactNumToKeepStr: '', daysToKeepStr: '5', numToKeepStr: '5')
    }

    agent { label 'k8-maven-small' }

    tools {
        maven 'Default'
    }

    stages {
        stage('Initialise') {
            steps {
                useJdk('OPENJDK17')
                gitSetIdentity()
            }
        }

        stage('set VERSION') {
            steps {
                script {
                    mavenSetVersion(BUILD_VERSION, 'pom.xml')
                }
            }
        }

        stage('Build') {
            steps {
                script {
                    echo BUILD_VERSION
                    sh label: 'maven clean install',
                            script: """
                                mvn clean install -ntp -Dskip.unittests -Dskip.inttests -Dcommit_hash=`git log --pretty=format:'%H' -n 1`
                             """
                }
            }
        }

        stage('Push docker images') {
            steps {
                script {
                    // Retag Images as 'latest', Push to Registry and cleanup
                    def pushTag = "latest"
                    for (int i = 0; i < DOCKER_IMAGES.size(); ++i) {
                        dockerReTagImage("${DOCKER_IMAGES[i]}", pushTag, BUILD_VERSION)
                        dockerPushImage("${DOCKER_IMAGES[i]}", pushTag)
                        dockerRemoveLocalImage("${DOCKER_IMAGES[i]}", pushTag)
                    }
                }
            }
        }

        stage('docker compose') {
            agent { label 'LTU_DEV' }
            steps {
                dockerLoginGematikRegistry()
                sh("""
                    export appVersion=latest
                    export serverLoglevel=debug
                    echo '### Print environment'
                    printenv | sort
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
            stage('Remove dangling and unused docker images') {
                steps {
                    sh "chmod +x ./removeDockerImages.sh"
                    sh './removeDockerImages.sh eu.gcr.io/gematik-all-infra-prod/idp/gsi-server'
                }
            }
        }

    }

}
