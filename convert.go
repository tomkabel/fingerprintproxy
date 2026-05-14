package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	stdurl "net/url"

	fhttp "github.com/saucesteals/fhttp"
)

const maxBufferBody = 10 << 20

func convertRequestToFHTTP(req *http.Request) (*fhttp.Request, error) {
	var bodyReader io.Reader
	if req.Body != nil {
		bodyBytes, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		req.Body.Close()
		bodyReader = bytes.NewReader(bodyBytes)
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}

	urlStr := req.URL.String()
	if urlStr == "" && req.Host != "" {
		urlStr = "http://" + req.Host + req.URL.Path
		if req.URL.RawQuery != "" {
			urlStr += "?" + req.URL.RawQuery
		}
	}

	fReq, err := fhttp.NewRequestWithContext(req.Context(), req.Method, urlStr, bodyReader)
	if err != nil {
		return nil, err
	}

	for key, values := range req.Header {
		for _, v := range values {
			fReq.Header.Add(key, v)
		}
	}

	fReq.Host = req.Host
	fReq.Proto = req.Proto
	fReq.ProtoMajor = req.ProtoMajor
	fReq.ProtoMinor = req.ProtoMinor
	fReq.ContentLength = req.ContentLength
	fReq.TransferEncoding = req.TransferEncoding
	fReq.Close = req.Close

	if req.Trailer != nil {
		fReq.Trailer = make(fhttp.Header)
		for k, vs := range req.Trailer {
			for _, v := range vs {
				fReq.Trailer.Add(k, v)
			}
		}
	}

	return fReq, nil
}

func convertResponseFromFHTTP(fResp *fhttp.Response, origReq *http.Request) (*http.Response, error) {
	resp := &http.Response{
		Status:     fResp.Status,
		StatusCode: fResp.StatusCode,
		Proto:      fResp.Proto,
		ProtoMajor: fResp.ProtoMajor,
		ProtoMinor: fResp.ProtoMinor,
		Header:     make(http.Header),
	}

	for key, values := range fResp.Header {
		for _, v := range values {
			resp.Header.Add(key, v)
		}
	}

	if fResp.Trailer != nil && len(fResp.Trailer) > 0 {
		resp.Trailer = make(http.Header)
		for key, values := range fResp.Trailer {
			for _, v := range values {
				resp.Trailer.Add(key, v)
			}
		}
	}

	if fResp.TLS != nil {
		resp.TLS = &tls.ConnectionState{
			Version:                     fResp.TLS.Version,
			HandshakeComplete:           fResp.TLS.HandshakeComplete,
			DidResume:                   fResp.TLS.DidResume,
			CipherSuite:                 fResp.TLS.CipherSuite,
			NegotiatedProtocol:          fResp.TLS.NegotiatedProtocol,
			ServerName:                  fResp.TLS.ServerName,
			PeerCertificates:            fResp.TLS.PeerCertificates,
			SignedCertificateTimestamps: fResp.TLS.SignedCertificateTimestamps,
			OCSPResponse:                fResp.TLS.OCSPResponse,
		}
	}

	resp.Request = buildResponseRequest(fResp, origReq)

	bodyBytes, err := io.ReadAll(io.LimitReader(fResp.Body, maxBufferBody+1))
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	bodyIsComplete := len(bodyBytes) <= maxBufferBody
	if bodyIsComplete {
		fResp.Body.Close()
		resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		resp.ContentLength = int64(len(bodyBytes))
	} else {
		pr, pw := io.Pipe()
		resp.Body = pr
		resp.ContentLength = -1

		go func() {
			defer fResp.Body.Close()
			_, err := io.Copy(pw, io.MultiReader(bytes.NewReader(bodyBytes), fResp.Body))
			if err != nil {
				pw.CloseWithError(err)
			} else {
				pw.Close()
			}
		}()
	}

	return resp, nil
}

func buildResponseRequest(fResp *fhttp.Response, origReq *http.Request) *http.Request {
	if fResp.Request != nil {
		return &http.Request{
			Method: fResp.Request.Method,
			URL: &stdurl.URL{
				Scheme:   fResp.Request.URL.Scheme,
				Host:     fResp.Request.URL.Host,
				Path:     fResp.Request.URL.Path,
				RawQuery: fResp.Request.URL.RawQuery,
			},
			Proto:      fResp.Request.Proto,
			ProtoMajor: fResp.Request.ProtoMajor,
			ProtoMinor: fResp.Request.ProtoMinor,
			Header:     make(http.Header),
			Host:       fResp.Request.Host,
		}
	}

	if origReq != nil {
		reqCopy := *origReq
		reqCopy.Body = nil
		reqCopy.GetBody = nil
		return &reqCopy
	}

	return &http.Request{
		Method: "GET",
		URL:    &stdurl.URL{Scheme: "https"},
		Header: make(http.Header),
	}
}
