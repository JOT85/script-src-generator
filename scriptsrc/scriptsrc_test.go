package scriptsrc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHtmlFiles(t *testing.T) {
	testFiles, err := filepath.Glob("./tests/*.html")
	if err != nil {
		panic(err)
	}
	for _, file := range testFiles {
		scriptSrc, err := ScriptSrcFromHTMLFile(file, true)
		if err != nil {
			t.Error(err)
		} else {
			expectedBytes, err := os.ReadFile(file + "-script-src")
			if err != nil {
				panic(err)
			}
			expected := strings.TrimSpace(string(expectedBytes))
			got := scriptSrc.String()
			if got != expected {
				t.Errorf("mismatched script-src for %v: expected %v, got %v", file, expected, got)
			}
		}
	}
}
