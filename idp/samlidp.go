package main

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"time"

	"github.com/beevik/etree"
	"github.com/spf13/viper"
)

func handleLogonRequest(w http.ResponseWriter, req *http.Request) {

	authnReq := req.URL.Query().Get("SAMLRequest")

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
	fmt.Println(reqEl.SelectAttr("ID").Value)

}

func generateSAMLResponse(inResponseTo string) {

}

func main() {
	err := config()
	if err != nil {
		log.Fatalf("Unable to read config file, %s", err.Error())
	}
	http.HandleFunc("/logon", handleLogonRequest)
	fs := http.FileServer(http.Dir("../pages"))
	http.Handle("/pages/", http.StripPrefix("/pages/", fs))
	rand.Seed(time.Now().UnixNano())
	serverUrl := fmt.Sprintf("%s:%v", viper.GetString("idp_host"), viper.GetInt("port"))
	fmt.Printf("Server URL : %s", serverUrl)
	log.Fatal(http.ListenAndServe(serverUrl, nil))

}

func config() error {
	viper.SetConfigName("spconfig")
	viper.SetConfigFile("../config/spconfig.yaml")
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
