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
	"github.com/spf13/viper"
)

func handleLogonRequest(w http.ResponseWriter, req *http.Request) {

	authnReq := req.URL.Query().Get("SAMLRequest")
	relayState := req.URL.Query().Get("RelayState")

	athnReqBytes, err := decodeSAMLRequest(authnReq)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(athnReqBytes); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
	}
	//for debug purposes
	doc.WriteTo(os.Stdout)

	reqEl := doc.FindElement("./samlp:AuthnRequest")
	inResponseTo := reqEl.SelectAttr("ID").Value

	fmt.Printf("generating response for request ID %s\n", inResponseTo)
	assertion, err := samltools.CreateSAMLResponse(inResponseTo)
	fmt.Printf("\n------Assertion------\n\n%s\n--------END-----\n\n", assertion)
	if err != nil {
		fmt.Printf("Error generating assertion %s", err.Error())
	}
	t, err := template.ParseFiles("../pages/idpresp.html")
	if err != nil {
		fmt.Printf("Error generating template %s", err.Error())
	}
	t.Execute(w, map[string]string{"Base64Assertion": template.HTMLEscapeString(assertion), "RelayState": relayState})

}

func main() {
	err := config()
	if err != nil {
		log.Fatalf("Unable to read config file, %s", err.Error())
	}
	http.HandleFunc(viper.GetString("logon_path"), handleLogonRequest)
	fs := http.FileServer(http.Dir("../pages"))
	http.Handle("/pages/", http.StripPrefix("/pages/", fs))
	serverUrl := fmt.Sprintf("%s:%v", viper.GetString("host"), viper.GetInt("port"))
	fmt.Printf("Server URL : %s", serverUrl)
	fmt.Printf("Logon URL : %s", fmt.Sprintf("%s%s", serverUrl, viper.GetString("logon_path")))
	log.Fatal(http.ListenAndServe(serverUrl, nil))

}

func config() error {
	viper.SetConfigName("idpconfig")
	viper.SetConfigFile("../config/idpconfig.yaml")
	return viper.ReadInConfig()
}

func decodeSAMLRequest(req string) (decoded []byte, err error) {
	data, err := base64.StdEncoding.DecodeString(string(req))
	if err != nil {
		return []byte{}, err
	}
	zr := flate.NewReader(bytes.NewReader([]byte(data)))
	var b bytes.Buffer
	if _, err := io.Copy(&b, zr); err != nil {
		return []byte{}, err
	}
	if err := zr.Close(); err != nil {
		fmt.Println(err)
	}

	return b.Bytes(), nil

}
