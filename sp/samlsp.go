package main

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"text/template"
	"time"
)

const PORT = 4567

type SAMLRequest struct {
	Destination string
	ID          string
	Issuer      string
}

//const reqTemplate = `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"    	Destination="{{.Destination}}"    ID="{{.ID}}"    IssueInstant="2021-07-03T05:55:32Z"    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Version="2.0"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">{{.Issuer}}</saml:Issuer></samlp:AuthnRequest>`
const reqTemplate = `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"    ID="{{.ID}}"    IssueInstant="2021-07-03T05:55:32Z"    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Version="2.0"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">{{.Issuer}}</saml:Issuer></samlp:AuthnRequest>`

func samlRequestHandler(w http.ResponseWriter, req *http.Request) {
	body, _ := ioutil.ReadAll(req.Body)
	fmt.Printf("Body \n %s", body)
	var qv url.Values
	var err error
	if qv, err = url.ParseQuery(req.URL.RawQuery); err != nil {
		log.Fatal(err)
	}
	r := qv.Get("SAMLRequest")
	fmt.Printf("Incoming SAML Request %s\n", r)
	if err := decodeSAMLRequest(r); err != nil {
		log.Fatal(err)
	}

}

func samlAssertionHandler(w http.ResponseWriter, req *http.Request) {
	req.ParseForm()
	assertion := req.Form.Get("SAMLResponse")
	fmt.Println(assertion)
	var err error
	assertion, err = decodeSAMLResponse(assertion)
	if err != nil {
		log.Fatalf("Error %s\n", err.Error())
	}
	fmt.Println("-----XML----------")
	fmt.Println(assertion)

}

func sendSamlRequest(w http.ResponseWriter, req *http.Request) {
	t := template.Must(template.New("samlRequest").Parse(reqTemplate))
	samlReq := SAMLRequest{
		//Destination: "http://msinghlocal.samltools.com:4567/assertion",
		ID:     fmt.Sprintf("_%d", rand.Int()),
		Issuer: "http://msinghlocal.saml.com",
		//Issuer: "http://msinghlocal.samltools.com",
	}
	var buf bytes.Buffer
	err := t.Execute(&buf, samlReq)
	if err != nil {
		log.Fatalf("Error %s\n", err.Error())
	}
	s, err := encodeSAMLRequest(buf.Bytes())
	if err != nil {
		log.Fatalf("Error %s\n", err.Error())
	}
	fmt.Println(s)
	u, _ := url.Parse("https://dev-ejtl988w.auth0.com/samlp/lqrbWWMYc25UrCiYA5Pt06U625c4K6DO")

	q := u.Query()
	q.Add("SAMLRequest", s)
	u.RawQuery = q.Encode()
	fmt.Println(u.String())
	//http.Get(u.String())
}

func main() {
	http.HandleFunc("/saml-tools", samlRequestHandler)
	http.HandleFunc("/assertion", samlAssertionHandler)
	http.HandleFunc("/issue", sendSamlRequest)
	rand.Seed(time.Now().UnixNano())
	log.Fatal(http.ListenAndServe(fmt.Sprintf("msinghlocal.samltools.com:%v", PORT), nil))
	//req := "fZExT8MwEIVn/kXl3YnrxG1yaiIVdaASSFWpGFiQ6xgS5Ngh5wA/n8RhaJd6893zu3efNyhb08F28LU96q9Bo1/8tsYihEZBht6Ck9ggWNlqBK/gefv0CDxi0PXOO+UMWYznbje+baz0jbMFqb3vII5bbOxHbZySJpoMvXMGI+VaSMVqHU8lGmrBYr8ryNt7umQiz1KlkkRUQqfrXHN1FueM63yVsFmJOOi9RS+tLwhnfEnZivL1iQkQAhL+GmSH/4D3ja3GILe3Oc8ihIfT6UCPump6rTxZvOgew06jiJSbKTOE+f0FqdvWElH3ExhSTjI50mZQ6W+qP73Js+wHZlA0kKIBi0SK3Sa+GFfOt+vfKv8A"
	//req := "fZExT8MwEIVn%2FkXl3YnrxG1yaiIVdaASSFWpGFiQ6xgS5Ngh5wA%2Fn8RhaJd6893zu3efNyhb08F28LU96q9Bo1%2F8tsYihEZBht6Ck9ggWNlqBK%2Fgefv0CDxi0PXOO%2BUMWYznbje%2Bbaz0jbMFqb3vII5bbOxHbZySJpoMvXMGI%2BVaSMVqHU8lGmrBYr8ryNt7umQiz1KlkkRUQqfrXHN1FueM63yVsFmJOOi9RS%2BtLwhnfEnZivL1iQkQAhL%2BGmSH%2F4D3ja3GILe3Oc8ihIfT6UCPump6rTxZvOgew06jiJSbKTOE%2Bf0FqdvWElH3ExhSTjI50mZQ6W%2BqP73Js%2BwHZlA0kKIBi0SK3Sa%2BGFfOt%2BvfKv8A"

}

func decodeSAMLRequest(req string) error {

	//urlDec, err := url.QueryUnescape(req)
	//urlDec, err := base64.URLEncoding.DecodeString(req)
	//fmt.Printf("%s\n", string(urlDec))
	data, err := base64.StdEncoding.DecodeString(string(req))
	if err != nil {
		return err
	}
	//fmt.Printf("%q\n", data)
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

	//urlDec, err := url.QueryUnescape(req)
	//urlDec, err := base64.URLEncoding.DecodeString(req)
	//fmt.Printf("%s\n", string(urlDec))
	data, err := base64.StdEncoding.DecodeString(string(req))
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func encodeSAMLRequest(req []byte) (string, error) {
	fmt.Printf("Input %s\n", string(req))
	//urlDec, err := url.QueryUnescape(req)
	//urlDec, err := base64.URLEncoding.DecodeString(req)
	//fmt.Printf("%s\n", string(urlDec))
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
