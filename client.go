package cveapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
)

var errNotFound = errors.New("Not found CVE")

// Client for interacting with CVEAPI.
type Client struct {
	BaseURL    *url.URL
	httpClient *http.Client
}

// NewClient is constructor
func NewClient() *Client {
	u, _ := url.Parse("https://v1.cveapi.com")
	return &Client{
		BaseURL:    u,
		httpClient: &http.Client{},
	}
}

// sendRequest sends a HTTP request to the CVEAPI.
func (c *Client) sendRequest(method, path string, body io.Reader) (*http.Response, error) {
	// Compose URL
	rel := &url.URL{Path: path}
	targetURL := c.BaseURL.ResolveReference(rel)

	// Write body
	var buf io.ReadWriter
	if body != nil {
		buf = new(bytes.Buffer)
		err := json.NewEncoder(buf).Encode(body)
		if err != nil {
			return nil, err
		}
	}

	// New HTTP GET request

	req, err := http.NewRequest(method, targetURL.String(), body)
	if err != nil {
		return nil, err
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	// log.Printf("Doing request: %s", targetURL.String())
	return (c.httpClient).Do(req)
}

// GetCVEData call api get detailed information on specific security issues, specified by CVE number.
func (c *Client) GetCVEData(cve string) (*Response, error) {
	path := fmt.Sprintf("/%s.json", cve)
	httpResp, err := c.sendRequest("GET", path, nil)
	if err != nil {
		return nil, err
	}
	result := &Response{}

	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		return nil, errNotFound
	}

	body, err := ioutil.ReadAll(httpResp.Body)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, err
	}
	return result, nil
}
