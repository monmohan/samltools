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

func ValidateAssertion(base64EncResp string, validationContext *dsig.ValidationContext) error {
	samlResp, err := base64.StdEncoding.DecodeString(base64EncResp)
	if err != nil {
		return err
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(samlResp); err != nil {
		return err
	}

	if validationContext == nil {
		validationContext, err = defaultValidationContext(doc)
		if err != nil {
			return err
		}
	}

	el := doc.Root().FindElement("./saml:Assertion")
	elem, err := validationContext.Validate(el)
	if err != nil {
		return fmt.Errorf("Error validationContext, transformed =%v, Err=%s", elem, err)

	}
	return nil

}

func defaultValidationContext(doc *etree.Document) (*dsig.ValidationContext, error) {
	cert64El := doc.FindElement("//saml:Assertion/Signature/KeyInfo/X509Data/X509Certificate")
	if cert64El == nil {
		return nil, fmt.Errorf("No Certificate Info found to match signature.")
	}
	certb64 := cert64El.Text()
	derBytesCert, err := base64.StdEncoding.DecodeString(certb64)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(derBytesCert)
	if err != nil {
		return nil, fmt.Errorf("x509 parse err %s\n", err.Error())

	}
	certificateStore := dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{cert},
	}

	validationContext := dsig.NewDefaultValidationContext(&certificateStore)
	validationContext.IdAttribute = "ID"
	return validationContext, nil
}
