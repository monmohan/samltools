package samltools

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	mrand "math/rand"
	"time"

	"github.com/beevik/etree"
	perrors "github.com/pkg/errors"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/russellhaering/goxmldsig/etreeutils"
)

var (
	xmlns_saml = "xmlns:saml"
	xmlns_xsi  = "xmlns:xsi"
)

//Test Cert
var Certb64 = `MIIDtDCCApwCCQCjWnFcIynj3DANBgkqhkiG9w0BAQsFADCBmzELMAkGA1UEBhMCU0cxCzAJBgNVBAgMAlNHMQswCQYDVQQHDAJTRzEWMBQGA1UECgwNaWRwLnNhbWx0b29sczEbMBkGA1UECwwSaWRwLnNhbWx0b29scy5pbXBsMRowGAYDVQQDDBFpZHAuc2FtbHRvb2xzLmNvbTEhMB8GCSqGSIb3DQEJARYSbW9ubW9oYW5AZ21haWwuY29tMB4XDTIxMDcyNjEzNDAxOFoXDTIyMDcyNjEzNDAxOFowgZsxCzAJBgNVBAYTAlNHMQswCQYDVQQIDAJTRzELMAkGA1UEBwwCU0cxFjAUBgNVBAoMDWlkcC5zYW1sdG9vbHMxGzAZBgNVBAsMEmlkcC5zYW1sdG9vbHMuaW1wbDEaMBgGA1UEAwwRaWRwLnNhbWx0b29scy5jb20xITAfBgkqhkiG9w0BCQEWEm1vbm1vaGFuQGdtYWlsLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJp86VwT5M+APXg7gjN7suJSF2ikanKplsM5S+/hGKuPUwUoNp+9urkRXwRyLTSkB12O/kwa8hlcFK1Cvlx9durfwp/B2h39hHEiXrhiIpbswjzPbZRWAts8FDmxLKU2vb9T8K9ZLTv4IiqtWC70eeFg4iVqQ6/pkHCpFLUfoBbNdEsqGCJO6uo5ivt8cPvlf52iJKFB55R2KQsEDxOqoUxrCeIhEY/mGoSd3LvqBSypwv4dNdpwWEavkyb7f8sWm98Rf4l/MND9evRGSII7g7xLBvjbXMQeZSVXL4bpFCGDsGjuKViTrjBJ2lvYEPrMlPDr0NjFK9ipe9NYYUiXBakCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAEAM0gblUq0KS3tr1qyGtQ8wp6NemoOua22iaZokRzjUi6XOHdHwMXZ+wcm5yUEaqgX/o+ZJoiEax7wNl2azJk/zHWwpxvfzScrYhvof/JintY8jVBQQIfbOotQ2xENVgw2//YS0VHrz10+8lFtXi1cqxK38OagNdG/lXLj8n0hV+RVlabLAYk8EQ5wUZrVBbvcnLBM+u7sHM+QlbAlIgu06QJiHg3YfnE3GdjgZxDuXjHXPHk5LNhhoFGwJdtDhje0+FF+uD+eCBLtsrZJx3uSuBOOpUF3Dhoe+4cVZx1UM8AHW3q8LVMf02vAu2NIfX1r51XoiQcHsefMDMY33MYg==`

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
		return perrors.Wrap(err, "Failed to create XML from decoded bytes")
	}
	var assertionEl *etree.Element
	etreeutils.NSFindIterate(doc.Root(), "urn:oasis:names:tc:SAML:2.0:assertion", "Assertion", func(n etreeutils.NSContext, e *etree.Element) error {
		fmt.Printf("Found Assertion element %v\n", e)
		assertionEl = e
		return etreeutils.ErrTraversalHalted
	})
	if assertionEl == nil {
		return fmt.Errorf("assertion element not found")
	}

	elem, err := validationContext.Validate(assertionEl)
	if err != nil {
		return perrors.Wrap(err, fmt.Sprintf("Error validationContext, transformed =%v", elem))

	}

	return nil

}

func CreateSAMLResponse(issuer string, inRespTo string, recipient string, audience string, signingCtx *dsig.SigningContext) (string, error) {
	mrand.Seed(time.Now().UnixNano())

	//create assertion
	assertionID := fmt.Sprintf("_%d", mrand.Int())
	issueTime := time.Now().Format(time.RFC3339)
	notOnOrAfter := time.Now().Add(2 * time.Hour).Format(time.RFC3339)
	requestId := inRespTo
	doc := etree.NewDocument()
	asEl := doc.CreateElement("saml:Assertion")
	asEl.CreateAttr(xmlns_saml, "urn:oasis:names:tc:SAML:2.0:assertion")
	asEl.CreateAttr("Version", "2.0")
	asEl.CreateAttr("ID", assertionID)
	asEl.CreateAttr("IssueInstant", issueTime)

	//add Issuer
	asEl.CreateElement("saml:Issuer").CreateText(issuer)

	addSubject(asEl, requestId, notOnOrAfter, recipient)
	addConditions(asEl, notOnOrAfter, audience)
	addAuthStatements(asEl, issueTime)

	attrStmts := asEl.CreateElement("saml:AttributeStatement")
	attrStmts.CreateAttr("xmlns", "http://www.w3.org/2001/XMLSchema")
	attrStmts.CreateAttr(xmlns_xsi, "http://www.w3.org/2001/XMLSchema-instance")
	createAttribute(attrStmts, "name", "IDPUser1")
	createAttribute(attrStmts, "email", "dev.null.dump.1@gmail.com")
	createAttribute(attrStmts, "userid", "IDPUser1")

	samlResp := createSAMLResponseElement(asEl, requestId)

	// Sign the element
	signedElement, err := signingCtx.SignEnveloped(asEl)
	if err != nil {
		return "", perrors.Wrap(err, "Signature generation failed")
	}
	samlResp.AddChild(signedElement)

	// Serialize the Response with signed assertion
	fdoc := etree.NewDocument()
	fdoc.SetRoot(samlResp)

	bytes, err := fdoc.WriteToBytes()
	if err != nil {
		return "", perrors.Wrap(err, "Failed to write bytes after adding signed element")
	}
	return base64.StdEncoding.EncodeToString(bytes), nil
}

func createSAMLResponseElement(assertion *etree.Element, requestId string) *etree.Element {
	doc := etree.NewDocument()
	resp := doc.CreateElement("samlp:Response")
	resp.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
	resp.CreateAttr("ID", fmt.Sprintf("_%d", mrand.Int()))
	resp.CreateAttr("InResponseTo", requestId)
	resp.CreateAttr("Version", "2.0")
	issuer := resp.CreateElement("saml:Issuer")
	issuer.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	issuer.CreateText("http://idp.samltools.com")
	status := resp.CreateElement("samlp:Status")
	stcode := status.CreateElement("samlp:StatusCode")
	stcode.CreateAttr("Value", "urn:oasis:names:tc:SAML:2.0:status:Success")
	return resp

}
func addSubject(assertionEl *etree.Element, requestId string, notOnOrAfter string, recipient string) {
	subject := assertionEl.CreateElement("saml:Subject")
	nameId := subject.CreateElement("saml:NameID")
	nameId.CreateAttr("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified")
	nameId.CreateText("IDPUser1")
	subjectConf := subject.CreateElement("saml:SubjectConfirmation")
	subjectConf.CreateAttr("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer")
	subjectConfData := subjectConf.CreateElement("saml:SubjectConfirmationData")
	subjectConfData.CreateAttr("NotOnOrAfter", notOnOrAfter)
	subjectConfData.CreateAttr("Recipient", recipient)
	subjectConfData.CreateAttr("InResponseTo", requestId)
}

func addConditions(assertionEl *etree.Element, notOnOrAfter string, audience string) {
	conditions := assertionEl.CreateElement("saml:Conditions")
	conditions.CreateAttr("NotBefore", time.Now().Add(-1*time.Minute).Format(time.RFC3339))
	conditions.CreateAttr("NotOnOrAfter", notOnOrAfter)
	audRest := conditions.CreateElement("saml:AudienceRestriction")
	aud := audRest.CreateElement("saml:Audience")
	aud.CreateText(audience)
}

func addAuthStatements(assertionEl *etree.Element, issueTime string) {
	authnStmt := assertionEl.CreateElement("saml:AuthnStatement")
	authnStmt.CreateAttr("AuthnInstant", issueTime)
	authnStmt.CreateAttr("SessionIndex", "_NOSESSION_")
	authCtx := authnStmt.CreateElement("saml:AuthnContext")
	authCtxRef := authCtx.CreateElement("saml:AuthnContextClassRef")
	authCtxRef.CreateText("urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified")
}

func createAttribute(parent *etree.Element, name string, val string) {
	attr := parent.CreateElement("saml:Attribute")
	attr.CreateAttr("Name", name)
	attr.CreateAttr("NameFormat", "urn:oasis:names:tc:SAML:2.0:attrname-format:basic")
	attrVal := attr.CreateElement("saml:AttributeValue")
	attrVal.CreateAttr("xsi:type", "xs:string")
	attrVal.CreateText(val)
}

type IDPKeyStore struct {
	key  *rsa.PrivateKey
	cert []byte
}

func NewIDPKeyStore(pKeyFile string) dsig.X509KeyStore {
	store := IDPKeyStore{}
	pemBlock, _ := ioutil.ReadFile(pKeyFile)
	block, _ := pem.Decode(pemBlock)
	if block == nil {
		panic("failed to parse PEM block containing the private key")
	}

	pvt, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		panic("failed to parse DER encoded public key: " + err.Error())
	}
	store.key = pvt.(*rsa.PrivateKey)
	derBytesCert, err := base64.StdEncoding.DecodeString(Certb64)
	store.cert = derBytesCert
	return &store

}

func (is *IDPKeyStore) GetKeyPair() (privateKey *rsa.PrivateKey, cert []byte, err error) {
	return is.key, is.cert, nil
}

func CreateValidationContextFromCertFile(certFile string) (*dsig.ValidationContext, error) {
	pemBlock, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, perrors.Wrap(err, "Failed to read idp_cert file")
	}

	block, rest := pem.Decode(pemBlock)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("unable to read the pem encoded block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, perrors.Wrap(err, "x509 parse err")

	}
	fmt.Printf("Got a %T, with remaining data: %q\n", cert, rest)

	certificateStore := dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{cert},
	}

	validationContext := dsig.NewDefaultValidationContext(&certificateStore)
	validationContext.IdAttribute = "ID"
	return validationContext, nil
}
