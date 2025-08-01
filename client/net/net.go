package net

import (
	"fmt"
	"net/http"
	"sync"
)

var (
	client     *http.Client
	clientOnce sync.Once
)

func getHTTPClient() (*http.Client, error) {
	var err error
	clientOnce.Do(func() {
		client = &http.Client{}
	})
	return client, err
}

func PerformRequest(req *http.Request) (*http.Response, error) {
	client, err := getHTTPClient()
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %v", err)
	}

	return resp, nil
}
