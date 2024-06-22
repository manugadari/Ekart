pipeline { 
  agent any

    stages {    
    stage('checkout') {
      steps {
        git branch: 'main', url: 'https://github.com/manugadari/Ekart'
        sh 'git branch'
      }
    }
    stage('SAST Scan for whole project') {
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                    sh "python3 snyk.py --scan-for-push --scan-for-pr --repo-path "./" --base-branch "main" --pr-branch "feature-1" "
                }
            }
        }
    stage('SCA scan for files') {
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                  sh 'python3 snyk_test.py --repo-path "./" --base-branch "main" --pr-branch "feature-1" --scan-for-pr'  
                }
            }
      }
    // stage('SCA scan') {
    //     steps {
    //       sh "python3 snyk.py " +
    //           "--scan-for-pr"
    //   }
    // }
  }
}
