// Copyright 2021, 2023 Tamás Gulácsi.
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
	"math/rand"
	"mime"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/exp/slog"
	"golang.org/x/net/html"
	"golang.org/x/sync/errgroup"

	"github.com/UNO-SOFT/zlog/v2"
	"github.com/google/renameio/v2"
	"github.com/peterbourgon/ff/v3/ffcli"
)

var verbose zlog.VerboseVar
var logger = zlog.NewLogger(zlog.MaybeConsoleHandler(&verbose, os.Stderr)).SLog()

func main() {
	if err := Main(); err != nil {
		logger.Error("Main", "error", err)
		os.Exit(1)
	}
}

func Main() error {
	prepare := func(ctx context.Context, args []string) (*collector, error) {
		if len(args) == 0 {
			return nil, fmt.Errorf("mantis URL with user:password is required")
		}
		u, err := url.Parse(args[0])
		if err != nil {
			return nil, fmt.Errorf("%q: %w", flag.Arg(0), err)
		}
		var client http.Client
		if client.Jar, err = cookiejar.New(&cookiejar.Options{}); err != nil {
			return nil, err
		}
		if err = doLogin(ctx, &client, u); err != nil {
			return nil, err
		}
		return newCollector(u, &client), nil
	}

	maxCmd := ffcli.Command{Name: "max", ShortHelp: "print out the max (visible) issue number",
		Exec: func(ctx context.Context, args []string) error {
			c, err := prepare(ctx, args)
			if err != nil {
				return nil
			}
			max, err := c.getMaxIssueID(ctx)
			if err != nil {
				return err
			}
			fmt.Println(max)
			return nil
		},
	}

	fs := flag.NewFlagSet("save", flag.ContinueOnError)
	fs.Var(&verbose, "v", "verbose logging")
	flagOut := fs.String("o", "mantis.squashfs", "output (squashfs) file's name")
	flagFirst := fs.Int("first", 1, "first issue to dump")
	flagLast := fs.Int("last", 0, "last issue to dump (finds from my_view_page if <1")
	flagConcurrency := fs.Int("concurrency", 8, "concurrency")
	saveCmd := ffcli.Command{Name: "save", FlagSet: fs,
		Exec: func(ctx context.Context, args []string) error {
			c, err := prepare(ctx, args)
			if err != nil {
				return nil
			}

			max := *flagLast
			if max < 1 {
				if max, err = c.getMaxIssueID(ctx); err != nil {
					return err
				}

			}

			tempDir, err := os.MkdirTemp("", *flagOut)
			if err != nil {
				return err
			}
			defer os.RemoveAll(tempDir)

			var zwMu sync.Mutex
			zwSeen := make(map[string]struct{})
			u := c.URL
			cl := cloner{
				c:  c,
				vl: &visitLimiter{prefix: (&url.URL{Scheme: u.Scheme, Host: u.Host, Path: path.Dir(u.Path)}).String()},
				WriteFile: func(fn string, compress bool, body []byte) error {
					zwMu.Lock()
					defer zwMu.Unlock()
					if _, ok := zwSeen[fn]; ok {
						return nil
					}
					zwSeen[fn] = struct{}{}
					return renameio.WriteFile(filepath.Join(tempDir, fn), body, 0640)
				},
			}

			links := make([]string, max-*flagFirst+1)
			logger.Info("links", "first:", *flagFirst, "last:", max)
			limitCh := make(chan struct{}, *flagConcurrency)
			errCh := make(chan error, 1000)
			var grp errgroup.Group
			for i := *flagFirst; i <= max; i++ {
				if err := ctx.Err(); err != nil {
					return err
				}
				i := i
				s := appendPath(u, "view.php") + "?id=" + strconv.Itoa(i)
				limitCh <- struct{}{}
				cl := cl
				grp.Go(func() error {
					defer func() { <-limitCh }()
					link, err := cl.Clone(ctx, s)
					if err != nil {
						err = fmt.Errorf("visit %q: %w", u.String(), err)
						select {
						case errCh <- err:
							return nil
						default:
							return err
						}
					}
					links[i-*flagFirst] = link
					return nil
				})
			}
			if err := grp.Wait(); err != nil {
				return err
			}
			close(errCh)
			var n int
			for err := range errCh {
				logger.Error("visit", "error", err.Error())
				n++
			}
			if n > 100 {
				return fmt.Errorf("too much errors: %d", n)
			}

			indexFh, err := renameio.NewPendingFile(filepath.Join(tempDir, "index.html"))
			if err != nil {
				return err
			}
			defer indexFh.Cleanup()
			w := indexFh
			fmt.Fprintf(w, `<!DOCTYPE html>
<html><head><title>%s</title><head><body><p>
`, path.Dir(u.Path))
			for i, link := range links {
				if i != 0 && i%100 == 0 {
					io.WriteString(w, "\n</p><p>\n")
				}
				fmt.Fprintf(w, "<a href=\"%s\">%d</a>\n", link, i+*flagFirst)
			}
			io.WriteString(w, "\n</p></body></html>")

			if err = indexFh.CloseAtomicallyReplace(); err != nil {
				return err
			}

			cmd := exec.CommandContext(ctx, "mksquashfs", tempDir, *flagOut, "-comp", "xz")
			cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr

			if err := cmd.Run(); err != nil {
				return fmt.Errorf("%q: %w", cmd.Args, err)
			}

			return nil
		},
	}

	appCmd := ffcli.Command{Name: "mantis-save",
		Subcommands: []*ffcli.Command{&saveCmd, &maxCmd},
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return appCmd.ParseAndRun(ctx, os.Args[1:])
}

func (c *collector) getMaxIssueID(ctx context.Context) (max int, err error) {
	var mu sync.RWMutex
	err = c.Visit(
		ctx,
		appendPath(c.URL, "my_view_page.php"),
		visitTodoMap{
			tagAttr{Tag: "a", Attr: "href"}: func(_ *url.URL, foundURL string) error {
				if i := strings.Index(foundURL, "/view.php?id="); i >= 0 {
					if i, err := strconv.Atoi(foundURL[i+13:]); err != nil {
						logger.Error("getMaxIssueID", "url", foundURL[i+13:], "error", err)
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
				return nil
			},
		},
		nil,
	)
	return max, err
}

type cloner struct {
	c         *collector
	vl        *visitLimiter
	linkMap   map[string]string
	linkPairs []string
	htmls     map[string]string
	WriteFile func(fn string, compress bool, body []byte) error
}

func (cl *cloner) Clone(ctx context.Context, URL string) (string, error) {
	//cl.mu.Lock()
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
	visit := cl.collector()
	//cl.mu.Unlock()
	if err := visit(ctx, URL); err != nil {
		return "", err
	}

	//cl.mu.Lock()
	//defer cl.mu.Unlock()
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

	var buf bytes.Buffer
	for s, b := range cl.htmls {
		fn := cl.linkMap[s]
		buf.Reset()
		_, err := replacer.WriteString(&buf, b)
		if err != nil {
			return "", fmt.Errorf("%q: %w", fn, err)
		}
		err = cl.WriteFile(fn, true, buf.Bytes())
		if err != nil {
			return "", err
		}
	}
	return cl.linkMap[URL], nil
}

func (cl *cloner) collector() (visit func(context.Context, string) error) {
	return func(ctx context.Context, URL string) error {
		saveResp := func(ctx context.Context, resp *http.Response) error {
			var body []byte
			brc, ok := resp.Body.(byteReadCloser)
			if ok {
				body = brc.p
			} else {
				var buf bytes.Buffer
				if _, err := io.Copy(&buf, resp.Body); err != nil {
					return err
				}
				body = buf.Bytes()
			}
			if len(body) == 0 {
				return nil
			}
			hsh := sha512.Sum512_224(body)
			u := resp.Request.URL
			fn := getFilename(u, resp.Header, hsh[:])
			s := u.String()
			//cl.mu.Lock()
			cl.linkMap[s] = fn
			//cl.mu.Unlock()

			ext := strings.ToLower(path.Ext(fn))
			if ext == ".htm" || ext == ".html" {
				//cl.mu.Lock()
				cl.htmls[s] = string(body)
				//cl.mu.Unlock()
			} else {
				var compress bool
				switch ext {
				case ".csv", ".txt", ".css", ".xml", ".log", ".js", ".php":
					compress = true
				}
				return cl.WriteFile(fn, compress, body)
			}
			return nil
		}
		save := func(ctx context.Context, URL string) error {
			req, err := http.NewRequest("GET", URL, nil)
			if err != nil {
				return err
			}
			resp, err := cl.c.Client.Do(req.WithContext(ctx))
			if err != nil {
				return err
			}
			return saveResp(ctx, resp)
		}

		return cl.c.Visit(ctx, URL, visitTodoMap{
			tagAttr{Tag: "a", Attr: "href"}: func(reqURL *url.URL, foundURL string) error {
				bn := foundURL
				if i := strings.IndexByte(bn, '?'); i >= 1 {
					bn = bn[:i]
				}
				bn = path.Base(bn)
				if bn != "file_download.php" {
					return nil
				}
				if cl.vl.Allow(foundURL) {
					return save(ctx, resolveURL(reqURL, foundURL))
				}
				return nil
			},

			tagAttr{Tag: "link", Attr: "href", AttrVal: attrVal{"rel", "stylesheet"}}: func(reqURL *url.URL, URL string) error {
				if cl.vl.Allow(URL) {
					return visit(ctx, resolveURL(reqURL, URL))
				}
				return nil
			},

			// search for all script tags with src attribute -- JS
			tagAttr{Tag: "script", Attr: "src"}: func(reqURL *url.URL, URL string) error {
				if cl.vl.Allow(URL) {
					return save(ctx, resolveURL(reqURL, URL))
				}
				return nil
			},

			// serach for all img tags with src attribute -- Images
			tagAttr{Tag: "img", Attr: "src"}: func(reqURL *url.URL, URL string) error {
				if cl.vl.Allow(URL) {
					return save(ctx, resolveURL(reqURL, URL))
				}
				return nil
			},
		},

			saveResp,
		)
	}
}

func resolveURL(base *url.URL, relative string) string {
	if strings.HasPrefix(relative, "https://") || strings.HasPrefix(relative, "http://") {
		return relative
	}
	ref, err := url.Parse(relative)
	if err != nil {
		panic(err)
	}
	return base.ResolveReference(ref).String()
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

func getFilename(u *url.URL, headers http.Header, hsh []byte) string {
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

type collector struct {
	*http.Client
	URL *url.URL
}

func newCollector(u *url.URL, client *http.Client) *collector {
	if client == nil {
		client = http.DefaultClient
		var err error
		if client.Jar, err = cookiejar.New(&cookiejar.Options{}); err != nil {
			panic(err)
		}
	}
	return &collector{URL: u, Client: client}
}
func (c *collector) Visit(ctx context.Context, URL string, todo visitTodoMap, respFun func(ctx context.Context, resp *http.Response) error) error {
	req, err := http.NewRequest("GET", URL, nil)
	if err != nil {
		return err
	}
	lvl := slog.LevelDebug
	if rand.Int31n(10) < 1 {
		lvl = slog.LevelInfo
	}
	logger.Log(ctx, lvl, "visig", "url", URL)
	resp, err := c.Client.Do(req.WithContext(ctx))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s: %s", URL, resp.Status)
	}
	if len(todo) == 0 && respFun == nil {
		return nil
	}
	if len(todo) == 0 {
		return respFun(ctx, resp)
	}

	tags := make(map[string]tagAttr, len(todo))
	for ta := range todo {
		tags[ta.Tag] = ta
	}
	r := io.Reader(resp.Body)
	var buf bytes.Buffer
	if respFun != nil {
		r = io.TeeReader(resp.Body, &buf)
	}
	z := html.NewTokenizer(r)
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			if err := z.Err(); err != nil && err != io.EOF {
				return err
			}
			break
		}
		if tt != html.StartTagToken {
			continue
		}
		tagB, hasAttr := z.TagName()
		if !hasAttr {
			continue
		}
		ta, ok := tags[string(tagB)]
		if !ok {
			continue
		}
		f := todo[ta]

		wantB := []byte(ta.Attr)
		if ta.AttrVal.Attr == "" {
			for {
				k, v, more := z.TagAttr()
				if bytes.Equal(k, wantB) {
					if err := f(resp.Request.URL, string(v)); err != nil {
						return err
					}
				}
				if !more {
					break
				}
			}
		} else {
			wantC := []byte(ta.AttrVal.Attr)
			var val string
			var found bool
			for {
				k, v, more := z.TagAttr()
				if bytes.Equal(k, wantB) {
					val = string(v)
				} else if !found && bytes.Equal(k, wantC) {
					found = bytes.Equal(v, []byte(ta.AttrVal.Val))
				}
				if val != "" && found || !more {
					break
				}
			}
			if found && val != "" {
				if err := f(resp.Request.URL, val); err != nil {
					return err
				}
			}
		}
	}
	if respFun != nil {
		if _, err := io.Copy(&buf, resp.Body); err != nil {
			return err
		}
		resp.Body = byteReadCloser{Reader: bytes.NewReader(buf.Bytes()), p: buf.Bytes()}
		return respFun(ctx, resp)
	}
	return nil
}

type attrVal struct {
	Attr, Val string
}
type tagAttr struct {
	Tag, Attr string
	AttrVal   attrVal
}
type visitTodoMap map[tagAttr]func(URL *url.URL, value string) error

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

type byteReadCloser struct {
	*bytes.Reader
	p []byte
}

func (b byteReadCloser) Close() error { return nil }
