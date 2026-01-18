package database

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNullResolver(t *testing.T) {
	r := NewNullResolver()

	if got := r.Resolve(13335); got != "" {
		t.Errorf("NullResolver.Resolve() = %q, want empty string", got)
	}

	if got := r.ResolveFromPath([]int{13335, 6939}); got != "" {
		t.Errorf("NullResolver.ResolveFromPath() = %q, want empty string", got)
	}

	if got := r.Count(); got != 0 {
		t.Errorf("NullResolver.Count() = %d, want 0", got)
	}

	// These should not panic
	r.Start()
	r.Stop()
}

func TestFileResolver(t *testing.T) {
	// Create a temporary CSV file
	tmpDir := t.TempDir()
	csvPath := filepath.Join(tmpDir, "asn_countries.csv")

	csvContent := `asn,country_code
13335,US
15169,US
32934,US
6939,US
3356,US
`
	if err := os.WriteFile(csvPath, []byte(csvContent), 0644); err != nil {
		t.Fatalf("Failed to write test CSV: %v", err)
	}

	r, err := NewFileResolver(csvPath)
	if err != nil {
		t.Fatalf("NewFileResolver() error = %v", err)
	}

	tests := []struct {
		name     string
		asn      uint32
		expected string
	}{
		{"Cloudflare", 13335, "US"},
		{"Google", 15169, "US"},
		{"Facebook", 32934, "US"},
		{"HE", 6939, "US"},
		{"Unknown ASN", 99999, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := r.Resolve(tt.asn); got != tt.expected {
				t.Errorf("FileResolver.Resolve(%d) = %q, want %q", tt.asn, got, tt.expected)
			}
		})
	}

	// Test ResolveFromPath
	if got := r.ResolveFromPath([]int{99999, 13335, 15169}); got != "US" {
		t.Errorf("FileResolver.ResolveFromPath() = %q, want US", got)
	}

	// Test Count
	if got := r.Count(); got != 5 {
		t.Errorf("FileResolver.Count() = %d, want 5", got)
	}
}

func TestFileResolver_NoHeader(t *testing.T) {
	// Create CSV without header
	tmpDir := t.TempDir()
	csvPath := filepath.Join(tmpDir, "asn_countries.csv")

	csvContent := `13335,US
15169,US
`
	if err := os.WriteFile(csvPath, []byte(csvContent), 0644); err != nil {
		t.Fatalf("Failed to write test CSV: %v", err)
	}

	r, err := NewFileResolver(csvPath)
	if err != nil {
		t.Fatalf("NewFileResolver() error = %v", err)
	}

	// First line should be treated as data (numeric ASN)
	if got := r.Resolve(13335); got != "US" {
		t.Errorf("FileResolver.Resolve(13335) = %q, want US", got)
	}

	if got := r.Count(); got != 2 {
		t.Errorf("FileResolver.Count() = %d, want 2", got)
	}
}

func TestFileResolver_InvalidFile(t *testing.T) {
	_, err := NewFileResolver("/nonexistent/path/file.csv")
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
}

func TestFileResolver_LowercaseCountry(t *testing.T) {
	tmpDir := t.TempDir()
	csvPath := filepath.Join(tmpDir, "asn_countries.csv")

	// Lowercase country codes should be uppercased
	csvContent := `asn,country
13335,us
15169,de
`
	if err := os.WriteFile(csvPath, []byte(csvContent), 0644); err != nil {
		t.Fatalf("Failed to write test CSV: %v", err)
	}

	r, err := NewFileResolver(csvPath)
	if err != nil {
		t.Fatalf("NewFileResolver() error = %v", err)
	}

	if got := r.Resolve(13335); got != "US" {
		t.Errorf("FileResolver.Resolve(13335) = %q, want US (uppercased)", got)
	}

	if got := r.Resolve(15169); got != "DE" {
		t.Errorf("FileResolver.Resolve(15169) = %q, want DE (uppercased)", got)
	}
}

func TestCountryResolverInterface(t *testing.T) {
	// Verify all resolvers implement the interface
	var _ CountryResolver = (*NullResolver)(nil)
	var _ CountryResolver = (*FileResolver)(nil)
	var _ CountryResolver = (*DatabaseResolver)(nil)
}
