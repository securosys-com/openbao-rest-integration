// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package http

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"testing"
	"time"

	cleanhttp "github.com/hashicorp/go-cleanhttp"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/helper/jsonutil"
)

func testHttpGet(t *testing.T, token string, addr string) *http.Response {
	loggedToken := token
	if len(token) == 0 {
		loggedToken = "<empty>"
	}
	t.Logf("Token is %s", loggedToken)
	return testHttpData(t, "GET", token, addr, nil, false, 0)
}

func testHttpDelete(t *testing.T, token string, addr string) *http.Response {
	return testHttpData(t, "DELETE", token, addr, nil, false, 0)
}

// Go 1.8+ clients redirect automatically which breaks our 307 standby testing
func testHttpDeleteDisableRedirect(t *testing.T, token string, addr string) *http.Response {
	return testHttpData(t, "DELETE", token, addr, nil, true, 0)
}

func testHttpPostWrapped(t *testing.T, token string, addr string, body interface{}, wrapTTL time.Duration) *http.Response {
	return testHttpData(t, "POST", token, addr, body, false, wrapTTL)
}

func testHttpPost(t *testing.T, token string, addr string, body interface{}) *http.Response {
	return testHttpData(t, "POST", token, addr, body, false, 0)
}

func testHttpPut(t *testing.T, token string, addr string, body interface{}) *http.Response {
	return testHttpData(t, "PUT", token, addr, body, false, 0)
}

// Go 1.8+ clients redirect automatically which breaks our 307 standby testing
func testHttpPutDisableRedirect(t *testing.T, token string, addr string, body interface{}) *http.Response {
	return testHttpData(t, "PUT", token, addr, body, true, 0)
}

func testHttpData(t *testing.T, method string, token string, addr string, body interface{}, disableRedirect bool, wrapTTL time.Duration) *http.Response {
	bodyReader := new(bytes.Buffer)
	if body != nil {
		enc := json.NewEncoder(bodyReader)
		if err := enc.Encode(body); err != nil {
			t.Fatalf("err:%s", err)
		}
	}

	req, err := http.NewRequest(method, addr, bodyReader)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	// Get the address of the local listener in order to attach it to an Origin header.
	// This will allow for the testing of requests that require CORS, without using a browser.
	hostURLRegexp, _ := regexp.Compile("http[s]?://.+:[0-9]+")
	req.Header.Set("Origin", hostURLRegexp.FindString(addr))

	req.Header.Set("Content-Type", "application/json")

	if wrapTTL > 0 {
		req.Header.Set("X-Vault-Wrap-TTL", wrapTTL.String())
	}

	if len(token) != 0 {
		req.Header.Set(consts.AuthHeaderName, token)
	}

	client := cleanhttp.DefaultClient()
	client.Timeout = 60 * time.Second

	// From https://github.com/michiwend/gomusicbrainz/pull/4/files
	defaultRedirectLimit := 30

	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if disableRedirect {
			return errors.New("checkRedirect disabled for test")
		}
		if len(via) > defaultRedirectLimit {
			return fmt.Errorf("%d consecutive requests(redirects)", len(via))
		}
		if len(via) == 0 {
			// No redirects
			return nil
		}
		// mutate the subsequent redirect requests with the first Header
		if token := via[0].Header.Get(consts.AuthHeaderName); len(token) != 0 {
			req.Header.Set(consts.AuthHeaderName, token)
		}
		return nil
	}

	resp, _ := client.Do(req)
	// if err != nil && !strings.Contains(err.Error(), "checkRedirect disabled for test") {
	// 	t.Fatalf("err: %s", err)
	// }

	return resp
}

func testResponseStatus(t *testing.T, resp *http.Response, code int) {
	t.Helper()
	if resp.StatusCode != code {
		body := new(bytes.Buffer)
		io.Copy(body, resp.Body)
		resp.Body.Close()

		t.Fatalf(
			"Expected status %d, got %d. Body:\n\n%s",
			code, resp.StatusCode, body.String())
	}
}

func testResponseHeader(t *testing.T, resp *http.Response, expectedHeaders map[string]string) {
	t.Helper()
	for k, v := range expectedHeaders {
		hv := resp.Header.Get(k)
		if v != hv {
			t.Fatalf("expected header value %v=%v, got %v=%v", k, v, k, hv)
		}
	}
}

func testResponseBody(t *testing.T, resp *http.Response, out interface{}) {
	defer resp.Body.Close()

	if err := jsonutil.DecodeJSONFromReader(resp.Body, out); err != nil {
		t.Fatalf("err: %s", err)
	}
}
