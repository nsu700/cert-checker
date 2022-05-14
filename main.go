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
			fmt.Println(content.Type, content.Name, content.Namespace)
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
				parseCertificate(block.Bytes)
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

func parseCertificate(block []byte) {
	certContent, err := x509.ParseCertificate(block)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Subject: %s\n", certContent.Subject.CommonName)
	fmt.Printf("Issuer: %s\n", certContent.Issuer)
	fmt.Printf("Not before: %s\n", certContent.NotBefore.String())
	fmt.Printf("Not after: %s\n", certContent.NotAfter.String())
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
