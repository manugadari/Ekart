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
                    sh 'python3 snyk.py --scan-for-push'
                }
            }
    }
    stage('SAST scan for changed files') {
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                  sh 'python3 snyk_changed.py --scan-for-pr --repo-path "./" --base-branch "main" --pr-branch "feature-1"'
                }
            }
      }
    stage('Synk Code Test') {
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                  sh 'python3 snyk_test.py --scan-for-push '
                }
            }
      }
    stage('Monitor scan') {
        steps {
          sh "python3 monitor.py " +
              "--scan-for-push"
      }
    }
  }
}
