/* TODO:
1. Get all secrets
2. Filter those secret with type tls
3. Get the date of the cert
4. Return a json object of cert name, namespace, expiry
5. Alert cert which is expiring in a week, maybe send email
*/

package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"regexp"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type certificate struct {
	issuer     string
	subject    string
	expireDate time.Time
	signDate   time.Time
	namespace  string
	secretName string
}

func main() {
	// creates the in-cluster config
	config, err := rest.InClusterConfig()
	if err != nil {
		panic(err.Error())
	}
	// creates the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}

	today := time.Now()
	gap30day := today.Add(30 * 24 * time.Hour).UTC()
	gap7day := today.Add(7 * 24 * time.Hour).UTC()
	gap1day := today.Add(24 * time.Hour).UTC()

	// gets the secret list
	secrets, err := clientset.CoreV1().Secrets("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		panic(err.Error())
	}

	for _, secret := range secrets.Items {
		content, err := clientset.CoreV1().Secrets(secret.Namespace).Get(context.TODO(), secret.Name, metav1.GetOptions{})
		if err != nil {
			panic(err.Error())
		}
		if content.Type == "kubernetes.io/tls" || content.Type == "SecretTypeTLS" {
			// fmt.Println(content.Type, content.Name, content.Namespace)
			certChain := string(content.Data["tls.crt"])
			if certChain == "" {
				panic("no tls.crt in the secret")
			}
			certs := getCert(certChain)
			for i := range certs {
				block, _ := pem.Decode([]byte(certs[i]))
				if block == nil {
					panic("failed to decode PEM block containing public key")
				}
				cert := parseCertificate(block.Bytes, content.Name, content.Namespace)
				if cert.expireDate.Before(gap1day) {
					fmt.Printf("The cert %s of project %s is expring in 24 hours\n", cert.secretName, cert.namespace)
					fmt.Println(cert.subject, cert.expireDate)
				} else if cert.expireDate.Before(gap7day) {
					fmt.Printf("The cert %s of project %s is expring in 7 days\n", cert.secretName, cert.namespace)
					fmt.Println(cert.subject, cert.expireDate)
				} else if cert.expireDate.Before(gap30day) {
					fmt.Printf("The cert %s of project %s is expring in 30 days\n", cert.secretName, cert.namespace)
					fmt.Println(cert.subject, cert.expireDate)
				}
			}
		}
	}
}

// return current time in YYYY-MM-dd HH:mm:ss
func getCurrentTime() string {
	t := time.Now().UTC()
	currentTime := fmt.Sprintf("%d-%02d-%02d %02d:%02d:%02d UTC", t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second())
	return currentTime
}

func parseCertificate(block []byte, name, namespace string) certificate {
	certContent, err := x509.ParseCertificate(block)
	if err != nil {
		panic(err)
	}
	return certificate{subject: certContent.Subject.CommonName, issuer: certContent.Issuer.CommonName,
		expireDate: certContent.NotAfter, signDate: certContent.NotBefore, secretName: name, namespace: namespace}
}

func getCert(certChain string) []string {
	var certList []string
	certBeginMark, _ := regexp.Compile("-----BEGIN CERTIFICATE-----")
	certEndMark, _ := regexp.Compile("-----END CERTIFICATE-----")
	certStartList := certBeginMark.FindAllStringIndex(certChain, 10)
	certEndList := certEndMark.FindAllStringIndex(certChain, 10)
	for i := range certStartList {
		certStart := certStartList[i][0]
		certEnd := certEndList[i][1]
		certList = append(certList, certChain[certStart:certEnd])
	}
	return certList
}
