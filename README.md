# script-src-generator

[![Go Report Card](https://goreportcard.com/badge/github.com/JOT85/script-src-generator)](https://goreportcard.com/report/github.com/JOT85/script-src-generator)
[![GoDoc](https://pkg.go.dev/badge/github.com/JOT85/script-src-generator)](https://pkg.go.dev/github.com/JOT85/script-src-generator/scriptsrc)

script-src-generator provides the auto-generation of script-src policy directives of Content
Security Policies (CSP) by parsing **trusted** HTML files.

For example, suppose you have the following HTML files inside of /web/root:

```html
<!-- index.html -->
<!DOCTYPE html>
<html>
    <head>
        <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
        <script>
            // Some content to hash.
        </script>
    </head>
    <body>
        <button onclick="alert('Hello')">Hello</button>
        <script>
            // Some more content to hash.
        </script>
    </body>
</html>
```

```html
<!-- just-self.html -->
<!DOCTYPE html>
<html>
    <head>
        <script src="foo.js"></script>
    </head>
    <body>
        I just need scripts from 'self'
    </body>
</html>
```

The script-src required to successfully run these, is:

```
'self' 'sha512-nbfZ9uoH92o+408nb2dlJhQJZLFdbJjY4ntbG7YAE23fMsuuEg261l9jm2HCns29WgvqGsjhO6F5bLDlIdSSMw==' 'sha512-Vj66Rmbqm1b9qQrkUNDR0OzPiTjQZ9Ayf25jSMRKvOgNlqnzNa8cn35DOErR7+AyOIxMT/ZYNJic15+Rj6lbkg==' 'sha512-X+aeR+9dEmqY9SqucXOUgHMKCI8yYCIBSgAOUxQ41fJBfPlM2nLA24g8XIxq1XJNuU+7YcvnrSkKoL5u4QVj3w==' https://challenges.cloudflare.com
```

This can be generated in a couple of ways.

## CLI Usage

```bash
go install github.com/JOT85/script-src-generator@latest
script-src-generator /web/root/**.html
> 'self' 'sha512-...' ... https://challenges.cloudflare.com
```

You can also specify a custom template (--csp-template-file can also be used to parse a template file):

```bash
script-src-generator --quiet --csp-template-string "Content-Security-Policy: script-src {{ .ScriptSrc }};" /web/root/**.html
> Content-Security-Policy: script-src 'self' 'sha512-...' ... https://challenges.cloudflare.com;
```

See `script-src-generator --help` for more details, including templating support.

**If go/bin isn't in your path, the command will instead be `~/go/bin/script-src-generator`.**

# Library Usage

```go
import "github.com/JOT85/script-src-generator/scriptsrc"

func generateScriptSrc() (string, error) {
    scriptSrc, err := scriptsrc.ScriptSrcFromHTMLFileGlob("/web/root/**.html", true)
    if err != nil {
        return "", err
    }
    return scriptSrc.String()
}
```

# Think about security

This library must only be used to process trusted HTML. The point of the CSP script-src directive is
to ensure that any JavaScript that gets injected cannot be run. Therefore, if you run this *after*
code could be injected, you're negating the point of adding the security headers! The input to this
must be trusted HTML code, i.e. your own static HTML files, and certainly not the output of a
template that could accept user input!
