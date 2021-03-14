// Copyright 2021 Tamás Gulácsi.
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
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
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/gocolly/colly/v2"
	"github.com/google/renameio"
)

func main() {
	if err := Main(); err != nil {
		log.Fatalf("%+v", err)
	}
}

func Main() error {
	//flagCookies := flag.String("cookiejar", "cookies.txt", "cookie jar")
	flag.Parse()

	u, err := url.Parse(flag.Arg(0))
	if err != nil {
		return fmt.Errorf("%q: %w", flag.Arg(0), err)
	}
	projectPath := filepath.Join(u.Host, filepath.FromSlash(path.Dir(u.Path)))
	os.MkdirAll(projectPath, 0755)
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
		colly.MaxDepth(2), colly.AllowURLRevisit(), colly.Async(false))
	c.SetClient(&client)

	var mu sync.RWMutex
	var max int
	maxer := c.Clone()
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
	log.Print("max:", max)
	vl := visitLimiter{prefix: (&url.URL{Scheme: u.Scheme, Host: u.Host, Path: path.Dir(u.Path)}).String()}

	c.OnHTML(`a[href]`, func(e *colly.HTMLElement) {
		foundURL := e.Attr("href")
		bn := foundURL
		if i := strings.IndexByte(bn, '?'); i >= 0 {
			bn = bn[:i]
		}
		bn = path.Base(bn)
		if bn == "login.php" || bn == "logout_page.php" || strings.HasSuffix(bn, "delete.php") {
			return
		}
		e.Request.Ctx.Put("Referer", e.Request.URL.String())
		if vl.Allow(foundURL) {
			e.Request.Visit(foundURL)
		}
	})

	c.OnHTML("link[rel='stylesheet']", func(e *colly.HTMLElement) {
		if URL := e.Attr("href"); vl.Allow(URL) {
			e.Request.Visit(URL)
		}
	})

	// search for all script tags with src attribute -- JS
	c.OnHTML("script[src]", func(e *colly.HTMLElement) {
		if URL := e.Attr("src"); vl.Allow(URL) {
			e.Request.Visit(URL)
		}
	})

	// serach for all img tags with src attribute -- Images
	c.OnHTML("img[src]", func(e *colly.HTMLElement) {
		if URL := e.Attr("src"); vl.Allow(URL) {
			e.Request.Visit(URL)
		}
	})

	linkMap := make(map[string]string, 8192)
	htmls := make(map[string]string, 8192)
	c.OnScraped(func(resp *colly.Response) {
		if resp.StatusCode >= 300 || len(resp.Body) == 0 {
			return
		}
		hsh := sha512.Sum512_224(resp.Body)
		u := resp.Request.URL
		fn := getFilename(u, resp.Headers, hsh[:])
		s := u.String()
		mu.Lock()
		linkMap[s] = fn
		mu.Unlock()

		if strings.HasSuffix(fn, ".htm") || strings.HasSuffix(fn, ".html") {
			mu.Lock()
			htmls[s] = string(resp.Body)
			mu.Unlock()
		} else {
			fn = filepath.Join(projectPath, fn)
			log.Println(u.String(), "->", fn)
			renameio.WriteFile(fn, resp.Body, 0444)
		}
	})

	index := make([]string, 0, max)
	for i := 1; i <= max; i++ {
		path := appendPath(u, "view.php") + "?id=" + strconv.Itoa(i)
		if err := c.Visit(path); err != nil {
			return fmt.Errorf("visit %q: %w", u.String(), err)
		}
		index = append(index, path)
	}

	c.Wait()

	linkPairs := make([]string, 0, len(linkMap)*2)
	for s, fn := range linkMap {
		bn := s
		if i := strings.LastIndexByte(s, '/'); i >= 0 {
			bn = s[i+1:]
		}
		linkPairs = append(linkPairs,
			`="`+s+`"`, `="./`+fn+`"`,
			`="`+strings.ReplaceAll(bn, "&", "&amp;")+`"`, `="./`+fn+`"`,
		)
	}
	replacer := strings.NewReplacer(linkPairs...)
	for s, b := range htmls {
		fh, err := os.Create(filepath.Join(projectPath, linkMap[s]))
		if err != nil {
			return err
		}
		replacer.WriteString(fh, b)
		if err = fh.Close(); err != nil {
			return err
		}
	}

	fh, err := os.Create(filepath.Join(projectPath, "index.html"))
	if err != nil {
		return err
	}
	defer fh.Close()
	log.Printf("Writing %q...", fh.Name())
	bw := bufio.NewWriter(fh)
	fmt.Fprintf(bw, `<!DOCTYPE html>
<html><head><title>%s</title><head><body><p>
`, projectPath)
	for i, path := range index {
		if i%100 == 0 {
			bw.WriteString("\n</p><p>\n")
		}
		link := linkMap[path]
		if i := strings.LastIndexByte(path, '='); i >= 0 {
			path = path[i+1:]
		}
		fmt.Fprintf(bw, "<a href=\"%s\">%s</a>\n", link, path)
	}
	bw.WriteString("\n</p></body></html>")
	if err = bw.Flush(); err != nil {
		return err
	}
	return fh.Close()
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
	if URL[0] == '#' || URL[len(URL)-1] == '/' || strings.IndexByte(URL, '.') < 0 ||
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
