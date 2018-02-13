package main

import (
	"fmt"
	"html/template"
	"net/http"
	"os"
)

const page = `
<html>
	<head>
		<title>{{.App}}</title>
	</head>
	<body>
		<h3>Hi {{.User}}!</h3>
		<table>
			<tr><th>Header</th><th>Value</th></tr>
			{{range $name, $value := .Headers}}
				<tr><td>{{$name}}</td><td>{{$value}}</td>
			{{end}}
		</table>
	<body>
</html>
`

// Context is the page data.
type Context struct {
	App     string
	User    string
	Headers map[string][]string
}

var app string

func handler(w http.ResponseWriter, r *http.Request) {
	t := template.Must(template.New("index.html").Parse(page))

	var user string
	if len(r.Header["X-Auth-User"]) == 0 {
		user = "unknown"
	} else {
		user = r.Header["X-Auth-User"][0]
	}

	ctx := Context{
		App:     app,
		User:    user,
		Headers: r.Header,
	}

	w.Header()["Content-Type"] = []string{"text/html"}
	if err := t.Execute(w, ctx); err != nil {
		fmt.Printf("ERROR writing page: %s\n", err.Error())
		w.WriteHeader(500)
	}

}

func main() {
	app = os.Getenv("APP")

	http.HandleFunc("/", handler)
	http.ListenAndServe(":80", nil)
}
