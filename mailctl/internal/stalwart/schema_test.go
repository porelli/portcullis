package stalwart

import (
	"os"
	"strings"
	"testing"
)

func loadSnapshot(t *testing.T) *Schema {
	t.Helper()
	b, err := os.ReadFile("testdata/schema-v1.1.0.json")
	if err != nil {
		t.Fatal(err)
	}
	s, err := ParseSchema(b)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// M13: every object, field, variant and enum value mailctl sends exists in
// Stalwart v1.1.0's schema.
func TestEveryUsedFieldInSchema(t *testing.T) {
	s := loadSnapshot(t)
	if bad := s.Check(Used); len(bad) > 0 {
		t.Fatalf("not in schema-v1.1.0.json:\n%s", strings.Join(bad, "\n"))
	}
}

// The check itself refuses what isn't there.
func TestSchemaCheckRefuses(t *testing.T) {
	s := loadSnapshot(t)
	cases := []Use{
		{Object: "x:NoSuchObject"},
		{Object: "x:NetworkListener", Field: "noSuchField"},
		{Object: "x:NetworkListener", Variant: "Foo"},
		{Object: "x:DataStore", Variant: "LevelDb"},
		{Object: "x:DataStore", Variant: "RocksDb", Field: "host"},
		{Enum: "Permission", Value: "imapEverything"},
		{Enum: "NoSuchEnum", Value: "x"},
		{},
	}
	for _, u := range cases {
		if bad := s.Check([]Use{u}); len(bad) != 1 {
			t.Errorf("%v accepted", u)
		}
	}
	ok := []Use{
		{Object: "x:NetworkListener", Field: "bind"},
		{Object: "x:Account", Variant: "User", Field: "name"},
		{Object: "x:Account", Field: "emailAddress"},
		{Object: "x:DataStore", Variant: "RocksDb", Field: "path"},
		{Object: "x:PermissionsList"},
		{Enum: "Permission", Value: "authenticate"},
	}
	if bad := s.Check(ok); len(bad) > 0 {
		t.Fatalf("refused: %v", bad)
	}
}
