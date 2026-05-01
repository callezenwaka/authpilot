package saml

import (
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"strings"
	"time"
)

// Namespaces used in SAML 2.0 metadata and protocol.
const (
	nsMD       = "urn:oasis:names:tc:SAML:2.0:metadata"
	nsDS       = "http://www.w3.org/2000/09/xmldsig#"
	nsSAML     = "urn:oasis:names:tc:SAML:2.0:assertion"
	nsProtocol = "urn:oasis:names:tc:SAML:2.0:protocol"

	bindingPost     = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
	bindingRedirect = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"

	nameIDFormatUnspecified  = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
	nameIDFormatEmailAddress = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	nameIDFormatPersistent   = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"

	statusSuccess    = "urn:oasis:names:tc:SAML:2.0:status:Success"
	statusPartialLogout = "urn:oasis:names:tc:SAML:2.0:status:PartialLogout"
)

// --- IdP Metadata XML structures ---

type EntityDescriptor struct {
	XMLName          xml.Name         `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`
	EntityID         string           `xml:"entityID,attr"`
	IDPSSODescriptor IDPSSODescriptor `xml:"IDPSSODescriptor"`
}

type IDPSSODescriptor struct {
	XMLName                    xml.Name               `xml:"urn:oasis:names:tc:SAML:2.0:metadata IDPSSODescriptor"`
	WantAuthnRequestsSigned    bool                   `xml:"WantAuthnRequestsSigned,attr"`
	ProtocolSupportEnumeration string                 `xml:"protocolSupportEnumeration,attr"`
	KeyDescriptors             []KeyDescriptor        `xml:"KeyDescriptor"`
	NameIDFormats              []NameIDFormat         `xml:"NameIDFormat"`
	SingleSignOnServices       []SingleSignOnService  `xml:"SingleSignOnService"`
	SingleLogoutServices       []SingleLogoutService  `xml:"SingleLogoutService"`
}

type KeyDescriptor struct {
	Use     string  `xml:"use,attr"`
	KeyInfo KeyInfo `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`
}

type KeyInfo struct {
	X509Data X509Data `xml:"http://www.w3.org/2000/09/xmldsig# X509Data"`
}

type X509Data struct {
	X509Certificate string `xml:"http://www.w3.org/2000/09/xmldsig# X509Certificate"`
}

type NameIDFormat struct {
	Value string `xml:",chardata"`
}

type SingleSignOnService struct {
	Binding  string `xml:"Binding,attr"`
	Location string `xml:"Location,attr"`
}

type SingleLogoutService struct {
	Binding  string `xml:"Binding,attr"`
	Location string `xml:"Location,attr"`
}

// BuildMetadata returns the XML metadata document for this IdP, including SLO endpoints.
func BuildMetadata(entityID, ssoURL string, cm *CertManager) ([]byte, error) {
	return BuildMetadataWithSLO(entityID, ssoURL, entityID+"/saml/slo", cm)
}

// BuildMetadataWithSLO builds metadata with explicit SLO URL.
func BuildMetadataWithSLO(entityID, ssoURL, sloURL string, cm *CertManager) ([]byte, error) {
	certB64 := base64.StdEncoding.EncodeToString(cm.CertDER())

	meta := EntityDescriptor{
		EntityID: entityID,
		IDPSSODescriptor: IDPSSODescriptor{
			WantAuthnRequestsSigned:    false,
			ProtocolSupportEnumeration: nsProtocol,
			KeyDescriptors: []KeyDescriptor{
				{
					Use: "signing",
					KeyInfo: KeyInfo{
						X509Data: X509Data{X509Certificate: certB64},
					},
				},
			},
			NameIDFormats: []NameIDFormat{
				{Value: nameIDFormatEmailAddress},
				{Value: nameIDFormatPersistent},
				{Value: nameIDFormatUnspecified},
			},
			SingleSignOnServices: []SingleSignOnService{
				{Binding: bindingPost, Location: ssoURL},
				{Binding: bindingRedirect, Location: ssoURL},
			},
			SingleLogoutServices: []SingleLogoutService{
				{Binding: bindingPost, Location: sloURL},
				{Binding: bindingRedirect, Location: sloURL},
			},
		},
	}

	out, err := xml.MarshalIndent(meta, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("saml: marshal metadata: %w", err)
	}
	return append([]byte(xml.Header), out...), nil
}

// --- SP-initiated AuthnRequest parsing ---

type AuthnRequest struct {
	XMLName                       xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol AuthnRequest"`
	ID                            string   `xml:"ID,attr"`
	Version                       string   `xml:"Version,attr"`
	IssueInstant                  string   `xml:"IssueInstant,attr"`
	Destination                   string   `xml:"Destination,attr"`
	AssertionConsumerServiceURL   string   `xml:"AssertionConsumerServiceURL,attr"`
	AssertionConsumerServiceIndex string   `xml:"AssertionConsumerServiceIndex,attr"`
	ProtocolBinding               string   `xml:"ProtocolBinding,attr"`
	Issuer                        string   `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
}

// ParseAuthnRequest decodes a base64+XML AuthnRequest from the SAMLRequest parameter.
func ParseAuthnRequest(samlRequest string) (*AuthnRequest, error) {
	decoded, err := base64.StdEncoding.DecodeString(samlRequest)
	if err != nil {
		// Some SPs omit padding — try RawStdEncoding
		decoded, err = base64.RawStdEncoding.DecodeString(samlRequest)
		if err != nil {
			return nil, fmt.Errorf("saml: decode AuthnRequest: %w", err)
		}
	}
	var req AuthnRequest
	if err := xml.Unmarshal(decoded, &req); err != nil {
		return nil, fmt.Errorf("saml: parse AuthnRequest XML: %w", err)
	}
	if req.ID == "" {
		return nil, fmt.Errorf("saml: AuthnRequest missing ID attribute")
	}
	return &req, nil
}

// --- LogoutRequest parsing ---

type LogoutRequest struct {
	XMLName      xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol LogoutRequest"`
	ID           string   `xml:"ID,attr"`
	Version      string   `xml:"Version,attr"`
	IssueInstant string   `xml:"IssueInstant,attr"`
	Destination  string   `xml:"Destination,attr"`
	Issuer       string   `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	NameID       struct {
		Format string `xml:"Format,attr"`
		Value  string `xml:",chardata"`
	} `xml:"urn:oasis:names:tc:SAML:2.0:assertion NameID"`
	SessionIndex string `xml:"urn:oasis:names:tc:SAML:2.0:protocol SessionIndex"`
}

// ParseLogoutRequest decodes a base64+XML LogoutRequest from the SAMLRequest parameter.
func ParseLogoutRequest(samlRequest string) (*LogoutRequest, error) {
	decoded, err := base64.StdEncoding.DecodeString(samlRequest)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(samlRequest)
		if err != nil {
			return nil, fmt.Errorf("saml: decode LogoutRequest: %w", err)
		}
	}
	var req LogoutRequest
	if err := xml.Unmarshal(decoded, &req); err != nil {
		return nil, fmt.Errorf("saml: parse LogoutRequest XML: %w", err)
	}
	if req.ID == "" {
		return nil, fmt.Errorf("saml: LogoutRequest missing ID attribute")
	}
	return &req, nil
}

// BuildLogoutResponse builds a signed LogoutResponse XML.
func BuildLogoutResponse(entityID, destination, inResponseTo string, cm *CertManager) ([]byte, error) {
	responseID, err := randomSAMLID()
	if err != nil {
		return nil, err
	}
	instant := time.Now().UTC().Format("2006-01-02T15:04:05Z")

	// Build the response XML.
	xmlStr := fmt.Sprintf(
		`<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"`+
			` ID="%s" Version="2.0" IssueInstant="%s" Destination="%s" InResponseTo="%s">`+
			`<saml:Issuer>%s</saml:Issuer>`+
			`<samlp:Status><samlp:StatusCode Value="%s"/></samlp:Status>`+
			`</samlp:LogoutResponse>`,
		responseID, instant, escapeAttrVal(destination), escapeAttrVal(inResponseTo),
		escapeTextVal(entityID), statusSuccess,
	)

	signed, err := signXML([]byte(xmlStr), responseID, cm)
	if err != nil {
		return nil, fmt.Errorf("saml: sign logout response: %w", err)
	}
	return signed, nil
}

// acsFromRequest returns the AssertionConsumerServiceURL from the request,
// falling back to a known list of allowed URLs for the given SP issuer.
// Furnace has no SP registry, so allowedACS is always nil and the URL
// presented by the SP is accepted as-is. Callers should enforce network-level
// constraints (e.g. allow only known SP origins) until SP registration is
// implemented.
func acsFromRequest(req *AuthnRequest, allowedACS []string) (string, error) {
	acs := strings.TrimSpace(req.AssertionConsumerServiceURL)
	if acs == "" {
		if len(allowedACS) > 0 {
			return allowedACS[0], nil
		}
		return "", fmt.Errorf("saml: no AssertionConsumerServiceURL in request and no registered ACS")
	}
	return acs, nil
}

// escapeAttrVal escapes a string for use in an XML attribute value.
func escapeAttrVal(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, `"`, "&quot;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	return s
}

// escapeTextVal escapes a string for use as XML text content.
func escapeTextVal(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}
