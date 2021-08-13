package main

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/beevik/etree"
	"github.com/monmohan/samltools"
	perrors "github.com/pkg/errors"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/spf13/viper"
)

var defaultSigningContext *dsig.SigningContext

func handleLogonRequest(w http.ResponseWriter, req *http.Request) {

	authnReq := req.URL.Query().Get("SAMLRequest")
	relayState := req.URL.Query().Get("RelayState")

	athnReqBytes, err := decodeSAMLRequest(authnReq)
	if err != nil {
		badRequest(err, w)
		return

	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(athnReqBytes); err != nil {
		badRequest(err, w)
		return
	}
	//DEBUG LOG
	doc.WriteTo(os.Stdout)
	fmt.Println()

	reqEl := doc.FindElement("./samlp:AuthnRequest")
	if reqEl == nil {
		badRequest(perrors.New("Can't read AuthnRequest element"), w)
		return
	}

	inResponseTo := reqEl.SelectAttr("ID")
	if inResponseTo == nil {
		badRequest(perrors.New("AuthnRequest element doesn't contain ID attribute"), w)
		return
	}
	issuerEl := reqEl.FindElement("./saml:Issuer")
	if issuerEl == nil {
		badRequest(perrors.New("Can't read Issuer element"), w)
		return
	}
	audience := issuerEl.Text()
	if len(audience) == 0 {
		badRequest(perrors.New("AuthnRequest element doesn't contain Issuer"), w)
		return
	}
	fmt.Printf("Generating response for request ID = %s, audience=%s\n", inResponseTo.Value, audience)

	acsUrl := viper.GetString("acs_url")
	idpIssuer := fmt.Sprintf("%s//%s", viper.GetString("protocol"), viper.GetString("host"))

	assertion, err := samltools.CreateSAMLResponse(idpIssuer, inResponseTo.Value, acsUrl, audience, defaultSigningContext)
	if err != nil {
		badRequest(err, w)
		return
	}
	fmt.Printf("\n------Assertion------\n\n%s\n--------END-----\n\n", assertion)
	if err != nil {
		fmt.Printf("Error generating assertion %s", err.Error())
	}
	t, err := template.ParseFiles("../pages/idpresp.html")
	if err != nil {
		fmt.Printf("Error generating template %s", err.Error())
	}
	t.Execute(w, map[string]string{
		"Base64Assertion": template.HTMLEscapeString(assertion),
		"RelayState":      relayState,
		"ACSUrl":          acsUrl})

}

func main() {
	err := config()
	createDefaultSigningContext()
	if err != nil {
		log.Fatalf("Unable to read config file, %s", err.Error())
	}
	http.HandleFunc(viper.GetString("logon_path"), handleLogonRequest)
	fs := http.FileServer(http.Dir("../pages"))
	http.Handle("/pages/", http.StripPrefix("/pages/", fs))
	serverUrl := fmt.Sprintf("%s:%v", viper.GetString("host"), viper.GetInt("port"))
	fmt.Printf("Server URL : %s\n", serverUrl)
	fmt.Printf("Logon URL : %s", fmt.Sprintf("%s%s\n", serverUrl, viper.GetString("logon_path")))
	log.Fatal(http.ListenAndServe(serverUrl, nil))

}

func createDefaultSigningContext() {
	keyStore := samltools.NewIDPKeyStore(viper.GetString("private_key_file"))
	defaultSigningContext = dsig.NewDefaultSigningContext(keyStore)
	defaultSigningContext.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")

}

func config() error {
	viper.SetConfigName("idpconfig")
	viper.SetConfigFile("../config/idpconfig.yaml")
	return viper.ReadInConfig()
}

func decodeSAMLRequest(req string) (decoded []byte, err error) {
	fmt.Printf("\nRaw SAML Request %s\n", req)

	data, err := base64.StdEncoding.DecodeString(string(req))
	if err != nil {
		return []byte{}, perrors.Wrap(err, "Base64 decoding failed")
	}
	zr := flate.NewReader(bytes.NewReader([]byte(data)))
	var b bytes.Buffer
	if _, err := io.Copy(&b, zr); err != nil {
		return []byte{}, perrors.Wrap(err, "Copy() while decoding request failed")
	}
	if err := zr.Close(); err != nil {
		return []byte{}, perrors.Wrap(err, "Close() while decoding request failed")
	}

	return b.Bytes(), nil

}

func badRequest(err error, w http.ResponseWriter) {
	fmt.Printf("%v\n", err)
	w.WriteHeader(http.StatusBadRequest)
	w.Write([]byte(fmt.Sprintf("Invalid Authentication Request: %s", err)))

}
