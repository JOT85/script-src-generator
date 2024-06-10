package main

import (
	"fmt"
	"os"
	"strings"
	"text/template"

	"github.com/JOT85/script-src-generator/scriptsrc"
)

func exitWithError(msg ...any) {
	fmt.Fprintln(os.Stderr, msg...)
	os.Exit(1)
}

func main() {
	verbose := true
	cspTemplateFile := ""
	cspTemplateString := ""
	hashAlgorithm := scriptsrc.Sha512
	hashAlgorithmSet := false

	args := os.Args[1:]
argParser:
	for len(args) > 0 {
		switch args[0] {
		case "--help", "-h":
			fmt.Println("Usage: " + os.Args[0] + " [--quiet] [--sha256 | --sha512] [--csp-template-file template-file | --csp-template-string template-string] <html file>...")
			fmt.Println(`
  --quiet stops outputting the files being processed to stderr

  --sha256 or --sha512 specifies the hashing algorithm to use for inline
    scripts. This currently defaults sha512 but is subject to change.

  --csp-template-file or --csp-template-string specifies an optional output
    template. This file will be parsed as a text template (see
    https://pkg.go.dev/text/template) and executed to stdout.

  The template is executed with the following fields available:
  - {{ .ScriptSrc }} the value of the script-src CSP, for example 
    "'self' 'sha512-....'  https://example.com".
    The struct formats as a string by default, but does have other fields, see
    https://pkg.go.dev/github.com/JOT85/script-src-generator/scriptsrc#ScriptSrc

For example:

  script-src-generator --csp-template-string "Content-Security-Policy: script-src {{ .ScriptSrc }};" /web/root/**.html
  script-src-generator --quiet --csp-template-string "Content-Security-Policy: script-src {{ .ScriptSrc }};" /web/root/**.html

Will generate a content security policy for the files in /web/root.`)
			return

		case "--quiet":
			verbose = false

		case "--sha512":
			if hashAlgorithmSet && hashAlgorithm != scriptsrc.Sha512 {
				exitWithError("You must specify only one hash algorithm")
			}
			hashAlgorithmSet = true
			hashAlgorithm = scriptsrc.Sha512

		case "--sha256":
			if hashAlgorithmSet && hashAlgorithm != scriptsrc.Sha256 {
				exitWithError("You must specify only one hash algorithm")
			}
			hashAlgorithmSet = true
			hashAlgorithm = scriptsrc.Sha256

		case "--csp-template-file":
			args = args[1:]
			if len(args) == 0 {
				exitWithError("--csp-template-file expected a template filepath")
			}
			cspTemplateFile = args[0]

		case "--csp-template-string":
			args = args[1:]
			if len(args) == 0 {
				exitWithError("--csp-template-string expected a template string")
			}
			cspTemplateString = args[0]

		default:
			if strings.HasPrefix(args[0], "--") {
				exitWithError("Unknown argument:", args[0])
			}
			break argParser
		}
		args = args[1:]
	}

	scriptSrc := scriptsrc.ScriptSrc{
		DefaultHashAlgorithm: hashAlgorithm,
	}
	errored := false
	for _, path := range args {
		if verbose {
			fmt.Fprintln(os.Stderr, ">", path)
		}
		err := scriptSrc.AddFromHTMLFile(path, true)
		if err != nil {
			errored = true
			fmt.Fprintln(os.Stderr, err)
		}
	}
	if errored {
		os.Exit(1)
	}

	var cspTemplate *template.Template
	var err error
	if cspTemplateFile != "" {
		cspTemplate, err = template.ParseFiles(cspTemplateFile)
		if err != nil {
			exitWithError("Failed to parse CSP template from", cspTemplateFile, ":", err)
		}
	}
	if cspTemplateString != "" {
		if cspTemplate != nil {
			exitWithError("You may only specify one of --csp-template-file and --csp-template-string")
		}
		cspTemplate, err = template.New("csp-template-string").Parse(cspTemplateString)
		if err != nil {
			exitWithError("Failed to parse CSP template:", err)
		}
	}

	if cspTemplate != nil {
		err = cspTemplate.Execute(
			os.Stdout,
			struct{ *scriptsrc.ScriptSrc }{&scriptSrc},
		)
		if err != nil {
			exitWithError("Failed to execute CSP template:", err)
		}
	} else {
		fmt.Println(scriptSrc.String())
	}
}
