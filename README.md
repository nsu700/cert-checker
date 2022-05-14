# cert-checker

## Purpose

1. List all certificates of a OCP4 cluster
2. List all issuer, subjects and validity of each certs
3. TODO parse a cert chain
4. TODO Verify when it will expire
5. TODO Fire an alert when cert coming expire
6. TODO Output all cert infomation in json format

## How to build this project
As simple as docker build
docker build -t $IMAGE .

## How to deploy as a cronjob run every 1AM
1. Create a new project, ex: oc new project cert-check
2. Grant secret get permission, for demo purpose, ex:  oc adm policy add-cluster-role-to-user cluster-admin -z default -n cert-check
3. Create a cronjob, ex: oc create cronjob cert-check --image=$IMAGE --schedule="1 * * * *" -n cert-check
