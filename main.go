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
	c := colly.NewCollector(colly.AllowedDomains(host), colly.MaxDepth(3))
	c.SetClient(&client)

	c.OnRequest(func(r *colly.Request) {
		fmt.Println("Visiting: ", r.URL.String())
	})

	var mu sync.RWMutex
	var max int
	c.OnHTML(`a[href]`, func(e *colly.HTMLElement) {
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
	if err = c.Visit(appendPath(u, "my_view_page.php")); err != nil {
		return err
	}
	log.Print("max:", max)

	c.OnHTML(`a[href]`, func(e *colly.HTMLElement) {
		foundURL := e.Request.AbsoluteURL(e.Attr("href"))
		if !strings.Contains(foundURL, "delete") {
			e.Request.Visit(foundURL)
		}
	})

	projectPath := host
	c.OnHTML("link[rel='stylesheet']", func(e *colly.HTMLElement) {
		e.Request.Visit(e.Attr("href"))
	})

	// search for all script tags with src attribute -- JS
	c.OnHTML("script[src]", func(e *colly.HTMLElement) {
		e.Request.Visit(e.Attr("src"))
	})

	// serach for all img tags with src attribute -- Images
	c.OnHTML("img[src]", func(e *colly.HTMLElement) {
		e.Request.Visit(e.Attr("src"))
	})

	linkMap := make(map[string]string, 8192)
	linkPairs := make([]string, 0, 16384)
	var replacer *strings.Replacer
	var pairLen int
	c.OnScraped(func(resp *colly.Response) {
		if resp.StatusCode >= 300 || len(resp.Body) == 0 {
			return
		}
		hsh := sha512.Sum512_224(resp.Body)
		fn := filepath.Join(
			projectPath,
			filepath.FromSlash(path.Join(path.Dir(resp.Request.URL.Path),
				base64.URLEncoding.EncodeToString(hsh[:]),
			)))
		s := resp.Request.URL.String()
		mu.Lock()
		linkMap[s] = fn
		linkPairs = append(linkPairs, `="`+s+`"`, `="`+fn+`"`)
		mu.Unlock()
		os.MkdirAll(filepath.Dir(fn), 0755)

		mu.RLock()
		if replacer == nil || pairLen != len(linkPairs) {
			replacer = strings.NewReplacer(linkPairs...)
			pairLen = len(linkPairs)
		}
		var buf bytes.Buffer
		buf.Grow(len(resp.Body))
		replacer.WriteString(&buf, string(resp.Body))
		mu.RUnlock()
		renameio.WriteFile(fn, buf.Bytes(), 0444)
	})

	for i := 1; i <= max; i++ {
		if err := c.Visit(appendPath(u, "view.php") + "?id=" + strconv.Itoa(i)); err != nil {
			return fmt.Errorf("visit %q: %w", u.String(), err)
		}
	}
	c.Wait()
	return nil
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
