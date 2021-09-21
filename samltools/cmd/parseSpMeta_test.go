package cmd

import (
	"log"
	"testing"

	"github.com/beevik/etree"
)

func TestFetchSigningCert(t *testing.T) {
	doc := etree.NewDocument()
	if err := doc.ReadFromFile("/Users/singhmo/Downloads/okta_metadata.xml"); err != nil {
		log.Fatalf("Error : %s", err.Error())
	}
	getSigningCert(doc)
}
