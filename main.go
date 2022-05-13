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
			cert := string(content.Data["tls.crt"])
			block, _ := pem.Decode([]byte(cert))
			if block == nil {
				panic("failed to decode PEM block containing public key")
			}
			certContent, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				panic(err)
			}
			fmt.Printf("Name %s\n", certContent.Subject.CommonName)
			fmt.Printf("Not before %s\n", certContent.NotBefore.String())
			fmt.Printf("Not after %s\n", certContent.NotAfter.String())

		}
	}
}

// return current time in YYYY-MM-dd HH:mm:ss
func getCurrentTime() string {
	t := time.Now().UTC()
	currentTime := fmt.Sprintf("%d-%02d-%02d %02d:%02d:%02d UTC", t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second())
	return currentTime
}
