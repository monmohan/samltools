package main

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"time"

	"github.com/monmohan/samltools"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/spf13/viper"
)

var defaultValidationContext *dsig.ValidationContext

func samlAssertionHandler(w http.ResponseWriter, req *http.Request) {
	var err error
	req.ParseForm()
	assertion := req.Form.Get("SAMLResponse")

	fmt.Printf("\n DEBUG: Raw SAML Assertion\n %s\n", assertion)

	if defaultValidationContext != nil {
		err = samltools.ValidateAssertion(assertion, defaultValidationContext)
		if err != nil {
			//Don't fail the request, just log it for now
			fmt.Printf("Signature Validation failed \n %s \n", err.Error())
		}
	}

	assertion, err = decodeSAMLResponse(assertion)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
	}
	w.Header().Add("Content-Type", "application/xml")
	w.Write([]byte(assertion))

}

func generateSAMLRequest(w http.ResponseWriter, req *http.Request) {
	samlreq := &samltools.AuthnRequest{
		SamlpAttr:       "urn:oasis:names:tc:SAML:2.0:protocol",
		ID:              fmt.Sprintf("_%d", rand.Int()),
		IssueInstant:    time.Now().Format(time.RFC3339),
		ProtocolBinding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
		Version:         "2.0",
		Issuer: samltools.Issuer{
			Namespace: "urn:oasis:names:tc:SAML:2.0:assertion",
			Value:     viper.GetString("issuer")},
	}
	output, err := xml.MarshalIndent(samlreq, "  ", "    ")
	decoded := req.URL.Query().Get("showdecoded")
	if decoded != "" {
		w.Header().Add("Content-Type", "application/xml")
		w.Write(output)
		return
	}
	if err != nil {
		fmt.Printf("error: %v\n", err)
	}
	s, err := encodeSAMLRequest(output)
	if err != nil {
		log.Fatalf("Error %s\n", err.Error())
	}

	u, _ := url.Parse(viper.GetString("ssoUrl"))

	q := u.Query()
	q.Add("SAMLRequest", s)
	u.RawQuery = q.Encode()
	w.Write([]byte(u.String()))

}

func main() {
	err := config()
	if err != nil {
		log.Fatalf("Unable to read config file, %s", err.Error())
	}
	defaultValidationContext, err = CreateDefaultValidationContext()
	if err != nil {
		log.Fatalf("Unable to read idp cert, Signature Validations will fail, %s", err.Error())
	}
	http.HandleFunc("/assertion", samlAssertionHandler)
	http.HandleFunc("/issue", generateSAMLRequest)
	fs := http.FileServer(http.Dir("../pages"))
	http.Handle("/pages/", http.StripPrefix("/pages/", fs))
	rand.Seed(time.Now().UnixNano())
	serverUrl := fmt.Sprintf("%s:%v", viper.GetString("host"), viper.GetInt("port"))
	fmt.Printf("Server URL : %s\n", serverUrl)
	fmt.Printf("Assertion URL : http://%s/assertion \n", serverUrl)
	log.Fatal(http.ListenAndServe(serverUrl, nil))

}

func config() error {
	viper.SetConfigName("spconfig")
	viper.SetConfigFile("../config/spconfig.yaml")
	return viper.ReadInConfig()
}

func CreateDefaultValidationContext() (*dsig.ValidationContext, error) {
	certFile := viper.GetString("idp_cert")
	return samltools.CreateValidationContextFromCertFile(certFile)
}

func decodeSAMLRequest(req string) error {
	data, err := base64.StdEncoding.DecodeString(string(req))
	if err != nil {
		return err
	}
	zr := flate.NewReader(bytes.NewReader([]byte(data)))
	var b bytes.Buffer
	if _, err := io.Copy(&b, zr); err != nil {
		return err
	}
	if err := zr.Close(); err != nil {
		fmt.Println(err)
	}

	fmt.Printf("%s\n", string(b.Bytes()))
	return nil
}

func decodeSAMLResponse(req string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(string(req))
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func encodeSAMLRequest(req []byte) (string, error) {
	var buf bytes.Buffer

	w, err := flate.NewWriter(&buf, 2)
	if err != nil {
		return "", err
	}
	_, e := w.Write(req)
	if e != nil {
		return "", e
	}
	if err := w.Close(); err != nil {
		fmt.Println(err)
	}
	data := base64.StdEncoding.EncodeToString(buf.Bytes())

	return data, nil
}
