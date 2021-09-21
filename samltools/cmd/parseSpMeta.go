/*
Copyright © 2021 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"

	"github.com/beevik/etree"
	"github.com/russellhaering/goxmldsig/etreeutils"
	"github.com/spf13/cobra"
)

// parseSpMetaCmd represents the parseSpMeta command
var parseSpMetaCmd = &cobra.Command{
	Use:   "parse-sp-meta",
	Short: "Parse a SP metadata XML file",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("parseSpMeta called")
		filePath, err := cmd.Flags().GetString("metadata-file")
		if err != nil || len(filePath) == 0 {
			return fmt.Errorf("error in file path")
		}
		doc := etree.NewDocument()
		if err := doc.ReadFromFile(filePath); err != nil {
			return err
		}
		getSigningCert(doc)
		return nil
	},
}

func getSigningCert(doc *etree.Document) {

	var signKeyEl *etree.Element
	var ctx etreeutils.NSContext
	err := etreeutils.NSFindIterate(doc.Root(), "urn:oasis:names:tc:SAML:2.0:metadata", "KeyDescriptor", func(n etreeutils.NSContext, e *etree.Element) error {
		//fmt.Printf("\tFound KeyDescriptor Element %s\n", e)
		useAttr := e.SelectAttr("use")
		if useAttr == nil {
			return fmt.Errorf("Keydescriptor with no use defined")
		}

		/*if useAttr.Value == "encryption" {
			encKeyEl = e
		}*/
		if useAttr.Value == "signing" {
			signKeyEl = e
		}
		ctx = n
		return nil
	})
	if err != nil {
		fmt.Printf("Error in traversal %s", err.Error())
	}

	var signCert string

	err = etreeutils.NSFindIterateCtx(ctx, signKeyEl, "http://www.w3.org/2000/09/xmldsig#", "X509Certificate", func(n etreeutils.NSContext, e *etree.Element) error {
		fmt.Printf("\nFound Signing Cert Element %v\n", e.Tag)
		signCert = e.Text()

		certBytes, err := base64.RawStdEncoding.DecodeString(signCert)
		if err != nil {
			return err
		}
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			return err
		}
		fmt.Printf(" Cert Issuer => %v\n Subject => %v\n PK Algo=> %v\n Not Valid Before=> %v\n Not Valid After=> %v\n ",
			cert.Issuer, cert.Subject, cert.PublicKeyAlgorithm, cert.NotBefore, cert.NotAfter)
		err = cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
		if err != nil {
			return err
		}
		fmt.Println("Verified signature of the certificate using self Public Key.")

		return nil
	})
	if err != nil {
		fmt.Printf("Error in traversal 2 %s", err.Error())
	}

}

func init() {
	parseSpMetaCmd.Flags().StringP("metadata-file", "f", "", "path to metdata file")
	rootCmd.AddCommand(parseSpMetaCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// parseSpMetaCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:

}
