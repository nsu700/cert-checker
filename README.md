# cert-checker

## Purpose

1. List all certificates of a OCP4 cluster
2. List all issuer, subjects and validity of each certs
3. TODO Verify when it will expire
4. TODO Fire an alert when cert coming expire
5. TODO Output all cert infomation in json format

## How to deploy as a cronjob run every 1AM
1. Create a new project, ex: oc new project cert-check
2. Create a cronjob, ex: oc create cronjob cert-check --image=$IMAGE --schedule="1 * * * *"
