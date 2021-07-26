package samltools

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"fmt"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

type Issuer struct {
	Namespace string `xml:"xmlns:saml,attr"`
	Value     string `xml:",chardata"`
}
type AuthnRequest struct {
	XMLName         xml.Name `xml:"samlp:AuthnRequest"`
	SamlpAttr       string   `xml:"xmlns:samlp,attr"`
	ID              string   `xml:"ID,attr"`
	IssueInstant    string   `xml:"IssueInstant,attr"`
	ProtocolBinding string   `xml:"ProtocolBinding,attr"`
	Version         string   `xml:"Version,attr"`
	Issuer          Issuer   `xml:"saml:Issuer"`
}

func ValidateAssertion(base64EncResp string) error {
	samlResp, err := base64.StdEncoding.DecodeString(base64EncResp)
	if err != nil {
		return err
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(samlResp); err != nil {
		return err
	}
	cert64El := doc.FindElement("//saml:Assertion/Signature/KeyInfo/X509Data/X509Certificate")
	if cert64El == nil {
		return fmt.Errorf("No Certificate Info found to match signature.")
	}
	certb64 := cert64El.Text()
	derBytesCert, err := base64.StdEncoding.DecodeString(certb64)
	if err != nil {
		return err
	}

	cert, err := x509.ParseCertificate(derBytesCert)
	if err != nil {
		return fmt.Errorf("x509 parse err %s\n", err.Error())

	}
	certificateStore := dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{cert},
	}

	validationContext := dsig.NewDefaultValidationContext(&certificateStore)
	validationContext.IdAttribute = "ID"
	el := doc.Root().FindElement("./saml:Assertion")
	elem, err := validationContext.Validate(el)
	if err != nil {
		return fmt.Errorf("Error validationContext, transformed =%v, Err=%s", elem, err)

	}
	return nil

}
