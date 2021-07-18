package samltools

import "encoding/xml"

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
