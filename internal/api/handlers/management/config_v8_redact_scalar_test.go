package management

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestRedactReadOnlyYAMLNodeScalarTypes(t *testing.T) {
	raw := "oauth-include-create-api-key: false\nheaders:\n  x-api-key: 1234567890123456\nprovider:\n  api-key: [12345678901234567890, quoted-secret-value-1234]\n"
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatal(err)
	}
	redactReadOnlyYAMLNode(doc.Content[0])

	var got struct {
		Flag     bool              `yaml:"oauth-include-create-api-key"`
		Headers  map[string]string `yaml:"headers"`
		Provider struct {
			APIKey []string `yaml:"api-key"`
		} `yaml:"provider"`
	}
	if err := doc.Decode(&got); err != nil {
		t.Fatalf("redacted node must stay decodable: %v", err)
	}
	if got.Flag {
		t.Fatal("boolean flag with an -api-key suffix must keep its value")
	}
	if header := got.Headers["x-api-key"]; header != managementSecretMask+"3456" {
		t.Fatalf("bare numeric header credential = %q, want masked", header)
	}
	for _, key := range got.Provider.APIKey {
		if !strings.HasPrefix(key, managementSecretMask) {
			t.Fatalf("api-key list item = %q, want masked", key)
		}
	}
}
