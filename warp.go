package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"golang.org/x/crypto/curve25519"
)

// Cloudflare WARP 客户端 API（与官方 Android 客户端一致的接口版本）。
const (
	warpAPI           = "https://api.cloudflareclient.com/v0a2158"
	warpClientVersion = "a-6.11-2223"
	warpUserAgent     = "okhttp/3.12.1"
	DefaultEndpoint   = "engage.cloudflareclient.com:2408"
)

var warpHTTP = &http.Client{
	Timeout: 20 * time.Second,
	Transport: &http.Transport{
		// API 对 TLS 1.3 的部分客户端指纹会返回 403，固定 TLS 1.2 与官方客户端保持一致。
		TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12},
		ForceAttemptHTTP2: false,
	},
}

type warpAccount struct {
	ID                   string `json:"id"`
	AccountType          string `json:"account_type"`
	WarpPlus             bool   `json:"warp_plus"`
	PremiumData          int64  `json:"premium_data"`
	Quota                int64  `json:"quota"`
	License              string `json:"license"`
	ReferralCount        int    `json:"referral_count"`
	ReferralRenewalCount int    `json:"referral_renewal_countdown"`
}

type warpRegResp struct {
	ID      string      `json:"id"`
	Token   string      `json:"token"`
	Account warpAccount `json:"account"`
	Config  struct {
		ClientID string `json:"client_id"`
		Peers    []struct {
			PublicKey string `json:"public_key"`
			Endpoint  struct {
				V4   string `json:"v4"`
				V6   string `json:"v6"`
				Host string `json:"host"`
			} `json:"endpoint"`
		} `json:"peers"`
		Interface struct {
			Addresses struct {
				V4 string `json:"v4"`
				V6 string `json:"v6"`
			} `json:"addresses"`
		} `json:"interface"`
	} `json:"config"`
}

func warpDo(ctx context.Context, method, path, token string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, warpAPI+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", warpUserAgent)
	req.Header.Set("CF-Client-Version", warpClientVersion)
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := warpHTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		var e struct {
			Errors []struct {
				Message string `json:"message"`
			} `json:"errors"`
		}
		if json.Unmarshal(data, &e) == nil && len(e.Errors) > 0 {
			return fmt.Errorf("WARP API %d: %s", resp.StatusCode, e.Errors[0].Message)
		}
		return fmt.Errorf("WARP API %d: %.200s", resp.StatusCode, string(data))
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

func genWGKey() (priv, pub [32]byte, err error) {
	if _, err = rand.Read(priv[:]); err != nil {
		return
	}
	priv[0] &= 248
	priv[31] = (priv[31] & 127) | 64
	p, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	copy(pub[:], p)
	return
}

// warpRegister 注册一个新的 WARP 设备并返回可直接使用的隧道参数。
func warpRegister(ctx context.Context) (*Tunnel, error) {
	priv, pub, err := genWGKey()
	if err != nil {
		return nil, err
	}
	var r warpRegResp
	err = warpDo(ctx, "POST", "/reg", "", map[string]any{
		"install_id":   "",
		"fcm_token":    "",
		"tos":          time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		"key":          base64.StdEncoding.EncodeToString(pub[:]),
		"type":         "Android",
		"model":        "PC",
		"locale":       "en_US",
		"warp_enabled": true,
	}, &r)
	if err != nil {
		return nil, err
	}
	if len(r.Config.Peers) == 0 || r.Config.Interface.Addresses.V4 == "" {
		return nil, errors.New("WARP API 返回的配置不完整")
	}
	t := &Tunnel{
		DeviceID:    r.ID,
		Token:       r.Token,
		PrivateKey:  base64.StdEncoding.EncodeToString(priv[:]),
		PeerPublic:  r.Config.Peers[0].PublicKey,
		AddressV4:   r.Config.Interface.Addresses.V4,
		AddressV6:   r.Config.Interface.Addresses.V6,
		ClientID:    r.Config.ClientID,
		AccountType: r.Account.AccountType,
		License:     r.Account.License,
		CreatedAt:   time.Now().Unix(),
	}
	return t, nil
}

// warpApplyLicense 把 WARP+ 密钥绑定到设备所属账户。
func warpApplyLicense(ctx context.Context, t *Tunnel, license string) error {
	return warpDo(ctx, "PUT", "/reg/"+t.DeviceID+"/account", t.Token, map[string]string{"license": license}, nil)
}

func warpGetAccount(ctx context.Context, t *Tunnel) (*warpAccount, error) {
	var a warpAccount
	if err := warpDo(ctx, "GET", "/reg/"+t.DeviceID+"/account", t.Token, nil, &a); err != nil {
		return nil, err
	}
	return &a, nil
}

func warpDeleteDevice(ctx context.Context, t *Tunnel) error {
	return warpDo(ctx, "DELETE", "/reg/"+t.DeviceID, t.Token, nil, nil)
}
