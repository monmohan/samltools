package samltools

import (
	"encoding/xml"
	"fmt"
	"os"
	"testing"
)

func TestCert(t *testing.T) {
	readX509Certificate()
}

func TestXMLGen(t *testing.T) {
	req := &AuthnRequest{
		SamlpAttr:       "urn:oasis:names:tc:SAML:2.0:protocol",
		ID:              "123",
		IssueInstant:    "2021-07-03T05:55:32Z",
		ProtocolBinding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
		Version:         "2.0",
		Issuer:          Issuer{Name: "urn:oasis:names:tc:SAML:2.0:assertion", Value: "http://msinghlocal.saml.com"},
	}
	output, err := xml.MarshalIndent(req, "  ", "    ")
	if err != nil {
		fmt.Printf("error: %v\n", err)
	}

	os.Stdout.Write(output)
}
