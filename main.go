// Copyright 2021 Tamás Gulácsi.
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/signal"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gocolly/colly/v2"
)

func main() {
	if err := Main(); err != nil {
		log.Fatalf("%+v", err)
	}
}

func Main() error {
	//flagCookies := flag.String("cookiejar", "cookies.txt", "cookie jar")
	flagOut := flag.String("o", "mantis.zip", "output (zip) file's name")
	flagFirst := flag.Int("first", 1, "first issue to dump")
	flagLast := flag.Int("last", 0, "last issue to dump (finds from my_view_page if <1")
	flag.Parse()

	u, err := url.Parse(flag.Arg(0))
	if err != nil {
		return fmt.Errorf("%q: %w", flag.Arg(0), err)
	}
	var client http.Client
	if client.Jar, err = cookiejar.New(&cookiejar.Options{}); err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	client.Transport = contextInjectingTransport{ctx: ctx, tr: http.DefaultTransport}
	if err = doLogin(ctx, &client, u); err != nil {
		return err
	}
	host, _, _ := net.SplitHostPort(u.Host)
	if host == "" {
		host = u.Host
	}
	log.Println("allowed domains:", host)
	c := colly.NewCollector(colly.AllowedDomains(host),
		colly.MaxDepth(2), colly.AllowURLRevisit(), colly.Async(true))
	c.SetClient(&client)
	c.Limit(&colly.LimitRule{Parallelism: 8})

	max := *flagLast
	if max < 1 {
		maxer := c.Clone()
		var mu sync.RWMutex
		maxer.OnHTML(`a[href]`, func(e *colly.HTMLElement) {
			foundURL := e.Request.AbsoluteURL(e.Attr("href"))
			if i := strings.Index(foundURL, "/view.php?id="); i >= 0 {
				if i, err := strconv.Atoi(foundURL[i+13:]); err != nil {
					log.Printf("%q: %w", foundURL[i+13:], err)
				} else {
					mu.RLock()
					better := max < i
					mu.RUnlock()
					if better {
						mu.Lock()
						if max < i {
							max = i
						}
						mu.Unlock()
					}
				}
			}
		})
		if err = maxer.Visit(appendPath(u, "my_view_page.php")); err != nil {
			return err
		}
		maxer.Wait()
	}

	zipFh, err := os.Create(*flagOut)
	if err != nil {
		return err
	}
	defer zipFh.Close()

	cl := cloner{
		c:  c,
		zw: zip.NewWriter(zipFh),
		vl: &visitLimiter{prefix: (&url.URL{Scheme: u.Scheme, Host: u.Host, Path: path.Dir(u.Path)}).String()},
	}

	var index bytes.Buffer
	fmt.Fprintf(&index, `<!DOCTYPE html>
<html><head><title>%s</title><head><body><p>
`, path.Dir(u.Path))
	log.Println("first:", *flagFirst, "last:", max)
	for i := *flagFirst; i <= max; i++ {
		s := appendPath(u, "view.php") + "?id=" + strconv.Itoa(i)

		log.Println("***", s, "***")
		link, err := cl.Clone(ctx, s)
		if err != nil {
			return fmt.Errorf("visit %q: %w", u.String(), err)
		}

		if i != 0 && i%100 == 0 {
			io.WriteString(&index, "\n</p><p>\n")
		}
		if i := strings.LastIndexByte(s, '='); i >= 0 {
			s = s[i+1:]
		}
		fmt.Fprintf(&index, "<a href=\"%s\">%s</a>\n", link, s)
	}
	io.WriteString(&index, "\n</p></body></html>")

	w, err := cl.zw.CreateHeader(&zip.FileHeader{Name: "index.html", Flags: zip.Deflate, Modified: time.Now()})
	if err != nil {
		return err
	}
	if _, err = w.Write(index.Bytes()); err != nil {
		return err
	}

	if err = cl.Close(); err != nil {
		return err
	}
	return zipFh.Close()
}

type cloner struct {
	mu        sync.RWMutex
	c         *colly.Collector
	vl        *visitLimiter
	linkMap   map[string]string
	htmls     map[string]string
	linkPairs []string
	zw        *zip.Writer
}

func (cl *cloner) Close() error {
	zw := cl.zw
	cl.zw = nil
	if zw != nil {
		return zw.Close()
	}
	return nil
}

func (cl *cloner) Clone(ctx context.Context, URL string) (string, error) {
	if cl.linkMap == nil {
		cl.linkMap = make(map[string]string, 64)
		cl.htmls = make(map[string]string)
	} else {
		//cl.vl.Reset()
		for k := range cl.linkMap {
			delete(cl.linkMap, k)
		}
		for k := range cl.htmls {
			delete(cl.htmls, k)
		}
	}
	c := cl.collector()
	if err := c.Visit(URL); err != nil {
		return "", err
	}
	c.Wait()

	cl.linkPairs = cl.linkPairs[:0]
	for s, fn := range cl.linkMap {
		bn := s
		if i := strings.LastIndexByte(s, '/'); i >= 0 {
			bn = s[i+1:]
		}
		cl.linkPairs = append(cl.linkPairs,
			`="`+s+`"`, `="./`+fn+`"`,
			`="`+strings.ReplaceAll(bn, "&", "&amp;")+`"`, `="./`+fn+`"`,
		)
	}
	replacer := strings.NewReplacer(cl.linkPairs...)

	now := time.Now()
	for s, b := range cl.htmls {
		fn := cl.linkMap[s]
		cl.mu.Lock()
		w, err := cl.zw.CreateHeader(&zip.FileHeader{Name: fn, Method: zip.Deflate, Modified: now})
		if err != nil {
			cl.mu.Unlock()
			return "", err
		}
		//log.Println(s, "->", fn)
		_, err = replacer.WriteString(w, b)
		cl.mu.Unlock()
		if err != nil {
			return "", fmt.Errorf("%q: %w", fn, err)
		}
	}
	return cl.linkMap[URL], nil
}

func (cl *cloner) collector() *colly.Collector {
	c := cl.c.Clone()
	c.OnHTML(`a[href]`, func(e *colly.HTMLElement) {
		foundURL := e.Attr("href")
		bn := foundURL
		if i := strings.IndexByte(bn, '?'); i >= 1 {
			bn = bn[:i]
		}
		bn = path.Base(bn)
		if bn != "file_download.php" {
			return
		}
		e.Request.Ctx.Put("Referer", e.Request.URL.String())
		if cl.vl.Allow(foundURL) {
			e.Request.Visit(foundURL)
		}
	})

	c.OnHTML("link[rel='stylesheet']", func(e *colly.HTMLElement) {
		if URL := e.Attr("href"); cl.vl.Allow(URL) {
			e.Request.Visit(URL)
		}
	})

	// search for all script tags with src attribute -- JS
	c.OnHTML("script[src]", func(e *colly.HTMLElement) {
		if URL := e.Attr("src"); cl.vl.Allow(URL) {
			e.Request.Visit(URL)
		}
	})

	// serach for all img tags with src attribute -- Images
	c.OnHTML("img[src]", func(e *colly.HTMLElement) {
		if URL := e.Attr("src"); cl.vl.Allow(URL) {
			e.Request.Visit(URL)
		}
	})

	c.OnScraped(func(resp *colly.Response) {
		if resp.StatusCode >= 300 || len(resp.Body) == 0 {
			return
		}
		hsh := sha512.Sum512_224(resp.Body)
		u := resp.Request.URL
		fn := getFilename(u, resp.Headers, hsh[:])
		s := u.String()
		cl.mu.Lock()
		cl.linkMap[s] = fn
		cl.mu.Unlock()

		ext := strings.ToLower(path.Ext(fn))
		if ext == ".htm" || ext == ".html" {
			cl.mu.Lock()
			cl.htmls[s] = string(resp.Body)
			cl.mu.Unlock()
		} else {
			//log.Println(u.String(), "->", fn)
			method := zip.Store
			switch ext {
			case ".csv", ".txt", ".css", ".xml", ".log", ".js", ".php":
				method = zip.Deflate
			}
			cl.mu.Lock()
			w, _ := cl.zw.CreateHeader(&zip.FileHeader{Name: fn, Method: method, Modified: time.Now()})
			w.Write(resp.Body)
			cl.mu.Unlock()
		}
	})
	return c
}

func appendPath(u *url.URL, plusPath string) string {
	return (&url.URL{Scheme: u.Scheme, Host: u.Host, Path: path.Join(u.Path, plusPath)}).String()
}

func doLogin(ctx context.Context, client *http.Client, u *url.URL) error {
	username := u.User.Username()
	password, _ := u.User.Password()
	resp, err := client.PostForm(appendPath(u, "login.php"), url.Values{"username": []string{username}, "password": []string{password}})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		if bytes.Contains(scanner.Bytes(), []byte(`<form id="login-form"`)) {
			return fmt.Errorf("bad login")
		}
	}
	io.Copy(os.Stdout, resp.Body)
	return nil
}

type contextInjectingTransport struct {
	ctx context.Context
	tr  http.RoundTripper
}

func (tr contextInjectingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := tr.ctx.Err(); err != nil {
		return nil, err
	}
	return tr.tr.RoundTrip(req.WithContext(tr.ctx))
}

func getFilename(u *url.URL, headers *http.Header, hsh []byte) string {
	var ext string
	if headers != nil {
		_, params, err := mime.ParseMediaType(headers.Get("Content-Disposition"))
		if fn, ok := params["filename"]; ok && err == nil {
			ext = path.Ext(fn)
		} else {
			if ct, _, _ := mime.ParseMediaType(headers.Get("Content-Type")); ct != "" {
				exts, _ := mime.ExtensionsByType(ct)
				if len(exts) != 0 {
					ext = exts[0]
				}
			}
		}

	}
	if ext == "" {
		ext = path.Ext(u.Path)
	}
	return base64.URLEncoding.EncodeToString(hsh) + ext
}

type visitLimiter struct {
	mu     sync.RWMutex
	seen   map[string]struct{}
	prefix string
}

func (vl *visitLimiter) Allow(URL string) bool {
	if URL == "" || URL[0] == '#' || URL[len(URL)-1] == '/' || strings.IndexByte(URL, '.') < 0 ||
		strings.HasPrefix(URL, "mailto:") || strings.Contains(URL, "my_view_page.php") ||
		((strings.HasPrefix(URL, "http://") || strings.HasPrefix(URL, "https://")) && !strings.HasPrefix(URL, vl.prefix)) {
		return false
	}
	s := URL
	if i := strings.IndexByte(s, '#'); i >= 0 {
		s = s[:i]
	}
	vl.mu.RLock()
	_, ok := vl.seen[s]
	vl.mu.RUnlock()
	if ok {
		return false
	}
	vl.mu.Lock()
	defer vl.mu.Unlock()
	if _, ok = vl.seen[s]; ok {
		return false
	}
	if vl.seen == nil {
		vl.seen = make(map[string]struct{}, 8192)
	}
	vl.seen[s] = struct{}{}
	return true
}
func (vl *visitLimiter) Reset() {
	for k := range vl.seen {
		delete(vl.seen, k)
	}
}
