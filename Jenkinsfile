pipeline {
  agent any
  options {
    timestamps()
    timeout(time: 3600, unit: 'SECONDS')
  }
  parameters {
    string(name: 'CREATE_RELEASE', defaultValue: 'false')
    string(name: 'VERSION', defaultValue: '')
    string(name: 'REPO_URL', defaultValue: '')
    string(name: 'BROWSER', defaultValue: 'htmlunit')
    string(name: 'SKIP_TESTS', defaultValue: 'false')
  }
  environment{
    APP="keycloak-wsfed"
  }
  stages {
    stage('Build') {
      agent {
        label 'jenkins-slave-maven-ct'
      }
      steps {
        script {
          sh 'printenv'
          def options = ""
          def prefix = ""
          if (params.BROWSER == "chrome") {
            options = '-DwebdriverDownloadBinaries=false -DchromeOptions="--headless --no-sandbox --disable-setuid-sandbox --disable-gpu --disable-software-rasterizer --remote-debugging-port=9222 --disable-infobars"'
            prefix = 'xvfb-run --server-args="-screen 0 1920x1080x24" --server-num=99'
          } else if (params.BROWSER == "firefox") {
            options = '-DwebdriverDownloadBinaries=false -DchromeOptions="-headless"'
            prefix = 'xvfb-run --server-args="-screen 0 1920x1080x24" --server-num=99'
          }

          withCredentials([usernamePassword(credentialsId: 'sonarqube', usernameVariable: 'USER', passwordVariable: 'PASS')]) {
            def sonar_opts = "\"-Dsonar.login=${USER}\" \"-Dsonar.password=${PASS}\""
            sh """
              ${prefix} mvn -B -T4 clean package \
                -Dbrowser=\"${params.BROWSER}\" \
                ${options} \
                -DskipTests=${params.SKIP_TESTS} \
                spotbugs:spotbugs pmd:pmd dependency-check:check \
                -Dsonar.java.spotbugs.reportPaths=target/spotbugsXml.xml \
                -Dsonar.java.pmd.reportPaths=target/pmd.xml \
                ${sonar_opts} \
                sonar:sonar
            """
          }
          if (params.CREATE_RELEASE == "true"){
            echo "creating release ${VERSION} and uploading it to ${REPO_URL}"
            // upload to repo
            withCredentials([usernamePassword(credentialsId: 'cloudtrust-cicd-artifactory-opaque', usernameVariable: 'USR', passwordVariable: 'PWD')]){
              sh """
                cd "${APP}/target"
                mv "${APP}"-?.?.?*.tar.gz "${APP}-${params.VERSION}.tar.gz"
                curl --fail -k -u"${USR}:${PWD}" -T "${APP}-${params.VERSION}.tar.gz" --keepalive-time 2 "${REPO_URL}/${APP}-${params.VERSION}.tar.gz"
              """
            }
            if (!env.TAG_NAME && env.TAG_NAME != params.VERSION) {
              def git_url = "${env.GIT_URL}".replaceFirst("^(http[s]?://www\\.|http[s]?://|www\\.)","")
              withCredentials([usernamePassword(credentialsId: "support-triustid-ch",
                  passwordVariable: 'PWD',
                  usernameVariable: 'USR')]) {
                sh("git config --global user.email 'ci@dev.null'")
                sh("git config --global user.name 'ci'")
                sh("git tag ${VERSION} -m 'CI'")
                sh("git push https://${USR}:${PWD}@${git_url} --tags")
              }
            } else {
              echo "Tag ${env.TAG_NAME} already exists. Skipping."
            }
            echo "release ${VERSION} available at ${REPO_URL}/${APP}-${params.VERSION}.tar.gz"
          }
        }
      }
    }
  }
}
