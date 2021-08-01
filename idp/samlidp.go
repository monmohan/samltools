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
	"time"

	"github.com/spf13/viper"
)

func handleLogonRequest(w http.ResponseWriter, req *http.Request) {

	authnReq := req.URL.Query().Get("SAMLRequest")

	err := decodeSAMLRequest(authnReq)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
	}

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
