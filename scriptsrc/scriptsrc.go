// Package scriptsrc provides auto-generation of script-src policy directives of Content Security
// Policies (CSP) by parsing **trusted** HTML files.
//
// For example, suppose you have the following HTML files inside of /web/root:
//
//	<!-- index.html -->
//	<!DOCTYPE html>
//	<html>
//	    <head>
//	        <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
//	        <script>
//	            // Some content to hash.
//	        </script>
//	    </head>
//	    <body>
//	        <button onclick="alert('Hello')">Hello</button>
//	        <script>
//	            // Some more content to hash.
//	        </script>
//	    </body>
//	</html>
//
//	<!-- just-self.html -->
//	<!DOCTYPE html>
//	<html>
//	    <head>
//	        <script src="foo.js"></script>
//	    </head>
//	    <body>
//	        I just need scripts from 'self'
//	    </body>
//	</html>
//
// The script-src required to successfully run these, is:
//
//	'self' 'sha512-nbfZ9uoH92o+408nb2dlJhQJZLFdbJjY4ntbG7YAE23fMsuuEg261l9jm2HCns29WgvqGsjhO6F5bLDlIdSSMw==' 'sha512-Vj66Rmbqm1b9qQrkUNDR0OzPiTjQZ9Ayf25jSMRKvOgNlqnzNa8cn35DOErR7+AyOIxMT/ZYNJic15+Rj6lbkg==' 'sha512-X+aeR+9dEmqY9SqucXOUgHMKCI8yYCIBSgAOUxQ41fJBfPlM2nLA24g8XIxq1XJNuU+7YcvnrSkKoL5u4QVj3w==' https://challenges.cloudflare.com
//
// This can be generated in a couple of ways.
//
// # CLI Usage
//
//	go install github.com/JOT85/script-src-generator@latest
//	script-src-generator /web/root/**.html
//	> 'self' 'sha512-...' ... https://challenges.cloudflare.com
//
// You can also specify a custom template (--csp-template-file can also be used to parse a template file):
//
//	script-src-generator --quiet --csp-template-string "Content-Security-Policy: script-src {{ .ScriptSrc }};" /web/root/**.html
//	> Content-Security-Policy: script-src 'self' 'sha512-...' ... https://challenges.cloudflare.com;
//
// See script-src-generator --help for more details, including templating support.
//
// If go/bin isn't in your path, the command will instead be ~/go/bin/script-src-generator.
//
// # Library Usage
//
//	import "github.com/JOT85/script-src-generator/scriptsrc"
//
//	func generateScriptSrc() (string, error) {
//	    scriptSrc, err := scriptsrc.ScriptSrcFromHTMLFileGlob("/web/root/**.html", true)
//	    if err != nil {
//	        return "", err
//	    }
//	    return scriptSrc.String()
//	}
//
// # Think about security
//
// This library must only be used to process trusted HTML. The point of the CSP script-src directive
// is to ensure that any JavaScript that gets injected cannot be run. Therefore, if you run this
// *after* code could be injected, you're negating the point of adding the security headers! The
// input to this must be trusted HTML code, i.e. your own static HTML files, and certainly not the
// output of a template that could accept user input!
package scriptsrc

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/net/html"
)

type HashAlgorithm uint8

const (
	Sha512 HashAlgorithm = 0
	Sha256 HashAlgorithm = 1
)

// ScriptSrc represents a script-src from a Content Security Policy (CSP)
//
// See https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy
type ScriptSrc struct {
	// Self indicates if 'self' should be included.
	Self bool

	// Hashes are sha256, sha384 or sha512 hashes of scripts that are allowed to be inline (inside script tags or event handlers).
	//
	// The entries in this array should be of the form <hash-algorithm>-<base64-hash>.
	//
	// Surrounding quotes will be added when formatted.
	Hashes []string

	// DefaultHashAlgorithm specified which hashing algorithm is used for generating hashes of inline scripts.
	//
	// The zero value for this is [Sha512].
	DefaultHashAlgorithm HashAlgorithm

	// Hosts are the host sources, such as https://example.com
	Hosts []string

	// Others are strings, to be added exactly as they appear (without quotes, but surrounding spaces will be added).
	Others []string
}

// String formats this scriptSrc as it should appear in the Content-Security-Policy header value.
//
// For example: "'self' https://challenges.cloudflare.com"
//
// In the header value, it should appear after "script-src", for example:
//
//	Content-Security-Policy: script-src 'self' https://challenges.cloudflare.com;
func (scriptSrc *ScriptSrc) String() string {
	srcs := make([]string, 0, 1+len(scriptSrc.Hashes)+len(scriptSrc.Hosts)+len(scriptSrc.Others))
	if scriptSrc.Self {
		srcs = append(srcs, "'self'")
	}
	for _, hash := range scriptSrc.Hashes {
		srcs = append(srcs, "'"+hash+"'")
	}
	srcs = append(srcs, scriptSrc.Hosts...)
	srcs = append(srcs, scriptSrc.Others...)
	return strings.Join(srcs, " ")
}

// AddInline adds the hash of some inline JavaScript to this scriptSrc.Hashes
//
// The hash type is specified by scriptSrc.DefaultHashAlgorithm
func (scriptSrc *ScriptSrc) AddInline(content string) {
	var hash string
	switch scriptSrc.DefaultHashAlgorithm {
	case Sha512:
		h := sha512.New()
		h.Write([]byte(content))
		hash = "sha512-" + base64.StdEncoding.EncodeToString(h.Sum(nil))
	case Sha256:
		h := sha256.New()
		h.Write([]byte(content))
		hash = "sha256-" + base64.StdEncoding.EncodeToString(h.Sum(nil))
	default:
		panic(fmt.Errorf("invalid HashAlgorithm value from DefaultHashAlgorithm: %v", scriptSrc.DefaultHashAlgorithm))
	}
	if !slices.Contains(scriptSrc.Hashes, hash) {
		scriptSrc.Hashes = append(scriptSrc.Hashes, hash)
	}
}

// AddSrc adds either 'self' or the required host entry to scriptSrc to allow the provided script source to be loaded.
//
// This function returns an error if the script src is http, not https.
func (scriptSrc *ScriptSrc) AddSrc(srcString string) error {
	src, err := url.Parse(srcString)
	if err != nil {
		return fmt.Errorf("failed to parse script src %v: %w", srcString, err)
	}
	switch src.Scheme {
	case "http":
		return fmt.Errorf("insecure script src: %v", srcString)
	case "https":
		host := "https://" + src.Host
		if !slices.Contains(scriptSrc.Hosts, host) {
			scriptSrc.Hosts = append(scriptSrc.Hosts, host)
		}
		return nil
	case "":
		scriptSrc.Self = true
		return nil
	default:
		return fmt.Errorf("failed to understand script src %v", srcString)
	}
}

// AddFromHTML adds the required script sources for loading all scripts, recursively, within the node.
//
// This adds entries from script src attributes, and content within script tags without src attributes.
//
// If includeEventHandlers, the content within any attribute starting with "on" is also allowed.
func (scriptSrc *ScriptSrc) AddFromHTML(n *html.Node, includeEventHandlers bool) error {
	// If the node is a script, add the src or content.
	if n.Type == html.ElementNode && n.Data == "script" {
		hasSrc := false
		for _, attr := range n.Attr {
			if attr.Key == "src" {
				if hasSrc {
					return fmt.Errorf("script tag had a second src attribute: %v", attr.Val)
				}
				scriptSrc.AddSrc(attr.Val)
				hasSrc = true
				// Don't return here, instead check there are no more src attributes.
			}
		}
		// If we found a src attribute, we're finished!
		if hasSrc {
			return nil
		}

		// Otherwise, this should be an inline script, so we should have exactly one child, which is
		// a text node.
		content := n.FirstChild
		if content == nil {
			return fmt.Errorf("script tag had no src attribute and no content")
		}
		if content.Type != html.TextNode {
			return fmt.Errorf("script tag had a child that was not a text node")
		}
		if content.NextSibling != nil || content.FirstChild != nil {
			return fmt.Errorf("script tag had multiple children")
		}
		scriptSrc.AddInline(content.Data)
		return nil
	}

	if includeEventHandlers {
		for _, attr := range n.Attr {
			if strings.HasPrefix(attr.Key, "on") {
				scriptSrc.AddInline(attr.Val)
			}
		}
	}

	// Otherwise, process all the children.
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		err := scriptSrc.AddFromHTML(c, includeEventHandlers)
		if err != nil {
			return err
		}
	}
	return nil
}

// AddFromHTMLFile parses the file from path, as HTML, and then calls scriptSrc.AddFromHTML with the result.
func (scriptSrc *ScriptSrc) AddFromHTMLFile(path string, includeEventHandlers bool) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	doc, err := html.Parse(f)
	if err != nil {
		return fmt.Errorf("failed to parse %v as HTML: %w", path, err)
	}
	err = scriptSrc.AddFromHTML(doc, includeEventHandlers)
	if err != nil {
		return fmt.Errorf("failed to process %v: %w", path, err)
	}
	return nil
}

// ScriptSrcFromHTMLFile generates the script-src required to load a requested HTML file.
//
// The input files must be truested HTML files! See the package documentation if you're unsure.
func ScriptSrcFromHTMLFile(path string, includeEventHandlers bool) (*ScriptSrc, error) {
	scriptSrc := &ScriptSrc{}
	return scriptSrc, scriptSrc.AddFromHTMLFile(path, includeEventHandlers)
}

// ScriptSrcFromHTMLFiles generates the script-src required to load any of the requested HTML files.
//
// The input files must be truested HTML files! See the package documentation if you're unsure.
func ScriptSrcFromHTMLFiles(paths []string, includeEventHandlers bool) (*ScriptSrc, error) {
	scriptSrc := &ScriptSrc{}
	var errors []error
	for _, path := range paths {
		err := scriptSrc.AddFromHTMLFile(path, includeEventHandlers)
		if err != nil {
			errors = append(errors, err)
		}
	}
	if len(errors) == 0 {
		return scriptSrc, nil
	} else if len(errors) == 1 {
		return nil, errors[0]
	} else {
		return nil, fmt.Errorf("multiple errors: %v", errors)
	}
}

// ScriptSrcFromHTMLFiles generates the script-src required to load any of the HTML files matching the glob pattern.
//
// The input files must be truested HTML files! See the package documentation if you're unsure.
func ScriptSrcFromHTMLFileGlob(pattern string, includeEventHandlers bool) (*ScriptSrc, error) {
	files, err := filepath.Glob(pattern)
	if err != nil {
		return nil, err
	}
	return ScriptSrcFromHTMLFiles(files, includeEventHandlers)
}
