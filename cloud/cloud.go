package cloud

import (
	"crypto/md5"
	"crypto/rc4"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var (
	userAgent       string
	ErrNoToken      = errors.New("no service token")
	ErrServiceLogin = errors.New("xiaomi service login fail")
	ErrMakeCall     = errors.New("error make api call")
	Err2factor      = errors.New("two factor auth required")
	ErrSsecurity    = errors.New("invalid ssecurity in 2th step")
)

type XiaomiCloud struct {
	did       string
	client    *http.Client
	Uid       string
	Password  string
	Server    string
	token     string
	sSecurity string
	cUserId   string
	passToken string
}

func NewConnection(uid string, pass string, server string) *XiaomiCloud {
	buff := make([]byte, 6)
	rand.Seed(time.Now().UnixNano())
	rand.Read(buff)
	did := strings.ToLower(base64.RawURLEncoding.EncodeToString(buff))

	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	userAgent = fmt.Sprintf("Android-7.1.1-1.0.0-ONEPLUS A3010-136-%s APP/xiaomi.smarthome APPV/62830",
		strings.ToUpper(did))

	return &XiaomiCloud{
		Uid:      uid,
		Password: pass,
		Server:   server,
		client:   &http.Client{Transport: transport},
		did:      did,
	}
}

func (c *XiaomiCloud) String() string {
	return fmt.Sprintf(`{"uid":"%s","pass":"%s","server":"%s","token":"%s","ssecurity":"%s","cuserid":"%s","passToken":%s}`,
		c.Uid, c.Password, c.Server, c.token, c.sSecurity, c.cUserId, c.passToken)
}

func (c *XiaomiCloud) Login() error {
	sdkVersion1 := &http.Cookie{Name: "sdkVersion", Value: "accountsdk-18.8.15", Domain: "mi.com"}
	sdkVersion2 := &http.Cookie{Name: "sdkVersion", Value: "accountsdk-18.8.15", Domain: "xiaomi.com"}
	did1 := &http.Cookie{Name: "deviceId", Value: c.did, Domain: "mi.com"}
	did2 := &http.Cookie{Name: "deviceId", Value: c.did, Domain: "xiaomi.com"}

	step1, err := http.NewRequest("GET", "https://account.xiaomi.com/pass/serviceLogin?sid=xiaomiio&_json=true", nil)
	if err != nil {
		return err
	}

	step1.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	step1.Header.Add("User-Agent", userAgent)
	step1.AddCookie(&http.Cookie{Name: "userId", Value: c.Uid})
	step1.AddCookie(sdkVersion1)
	step1.AddCookie(sdkVersion2)
	step1.AddCookie(did1)
	step1.AddCookie(did2)

	resp1, err := c.client.Do(step1)
	if err != nil || resp1.Status != "200 OK" {
		return ErrServiceLogin
	}

	body, err := ioutil.ReadAll(resp1.Body)
	if err != nil {
		return err
	}

	//log.Println("1st resp", string(body[11:]))

	var res1 interface{}
	err = json.Unmarshal(body[11:], &res1)
	if err != nil {
		return err
	}

	hash := md5.New()
	if _, err := hash.Write([]byte(c.Password)); err != nil {
		return err
	}

	step2url := fmt.Sprintf("https://account.xiaomi.com/pass/serviceLoginAuth2?sid=xiaomiio&_json=true&callback=https://sts.api.io.mi.com/sts&qs=%s&user=%s&_sign=%s&hash=%s",
		"%3Fsid%3Dxiaomiio%26_json%3Dtrue", c.Uid, res1.(map[string]interface{})["_sign"].(string), strings.ToUpper(hex.EncodeToString(hash.Sum(nil))))
	step2, err := http.NewRequest("POST", step2url, nil)
	if err != nil {
		return err
	}

	step2.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	step2.Header.Add("User-Agent", userAgent)
	step2.AddCookie(sdkVersion1)
	step2.AddCookie(sdkVersion2)
	step2.AddCookie(did1)
	step2.AddCookie(did2)

	resp2, err := c.client.Do(step2)
	if err != nil || resp2.Status != "200 OK" {
		return ErrServiceLogin
	}

	body, err = ioutil.ReadAll(resp2.Body)
	if err != nil {
		return err
	}

	//log.Println("2st resp", string(body[11:]))

	var res2 interface{}
	err = json.Unmarshal(body[11:], &res2)
	if err != nil {
		return err
	}

	notification := res2.(map[string]interface{})["notificationUrl"]
	if notification != nil {
		log.Printf("Two factor authentication required, please open %s and restart app\n", notification)
		return Err2factor
	}

	c.sSecurity = res2.(map[string]interface{})["ssecurity"].(string)
	if len(c.sSecurity) <= 4 {
		return ErrSsecurity
	}
	c.cUserId = res2.(map[string]interface{})["cUserId"].(string)
	c.passToken = res2.(map[string]interface{})["passToken"].(string)

	step3, err := http.NewRequest("GET", res2.(map[string]interface{})["location"].(string), nil)
	if err != nil {
		return err
	}
	step3.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	step3.Header.Add("User-Agent", userAgent)
	step3.AddCookie(sdkVersion1)
	step3.AddCookie(sdkVersion2)
	step3.AddCookie(did1)
	step3.AddCookie(did2)

	resp3, err := c.client.Do(step3)

	if err != nil || resp3.Status != "200 OK" {
		return ErrServiceLogin
	}

	body, err = ioutil.ReadAll(resp3.Body)
	if err != nil {
		return err
	}

	//log.Println("3st resp", string(body))

	for _, ck := range resp3.Cookies() {
		if ck.Name == "serviceToken" {
			c.token = ck.Value
			break
		}
	}

	if c.token == "" {
		return ErrNoToken
	}

	return nil
}

func (c *XiaomiCloud) GetApiUrl(method string) string {
	if c.Server == "cn" {
		return fmt.Sprintf("https://api.io.mi.com/app%s", method)
	}
	return fmt.Sprintf("https://%s.api.io.mi.com/app%s", c.Server, method)
}

func (c *XiaomiCloud) GetDevices() (string, error) {
	return c.MakeCall(c.GetApiUrl("/home/device_list"),
		`{"getVirtualModel":true,"getHuamiDevices":1,"get_split_device":false,"support_smart_home":true}`)
}

func (c *XiaomiCloud) MakeCall(addr string, data string) (string, error) {
	nonce := make([]byte, 12)
	rand.Seed(time.Now().UnixNano())
	rand.Read(nonce)
	binary.BigEndian.PutUint32(nonce[8:], uint32(time.Now().UnixMilli()/60000))
	signedNonce := signNonce(nonce, c.sSecurity)

	encRC4 := encryptRC4(signedNonce, c.signature(addr, "POST", signedNonce, data, ""))
	encData := encryptRC4(signedNonce, data)

	newurl := fmt.Sprintf("%s?data=%s&rc4_hash__=%s&signature=%s&ssecurity=%s&_nonce=%s",
		addr, url.QueryEscape(encData), url.QueryEscape(encRC4),
		url.QueryEscape(c.signature(addr, "POST", signedNonce, encData, encRC4)),
		url.QueryEscape(c.sSecurity), base64.StdEncoding.EncodeToString(nonce))

	//fmt.Println("  data =", encData)
	//fmt.Println("  rc4_hash__ =", encRC4)
	//fmt.Println("  signature =", c.signature(addr, "POST", signedNonce, encData, encRC4))
	//fmt.Println("  ssecurity =", c.sSecurity)
	//fmt.Println("  _nonce =", base64.StdEncoding.EncodeToString(nonce))

	r, err := http.NewRequest("POST", newurl, nil)
	if err != nil {
		return "", err
	}

	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Add("User-Agent", userAgent)
	r.Header.Add("Accept-Encoding", "identity")
	r.Header["x-xiaomi-protocal-flag-cli"] = []string{"PROTOCAL-HTTP2"}
	r.Header["MIOT-ENCRYPT-ALGORITHM"] = []string{"ENCRYPT-RC4"}

	r.AddCookie(&http.Cookie{Name: "userId", Value: c.Uid})
	r.AddCookie(&http.Cookie{Name: "yetAnotherServiceToken", Value: c.token})
	r.AddCookie(&http.Cookie{Name: "serviceToken", Value: c.token})
	r.AddCookie(&http.Cookie{Name: "locale", Value: "en_GB"})
	r.AddCookie(&http.Cookie{Name: "timezone", Value: "GMT+02:00"})
	r.AddCookie(&http.Cookie{Name: "is_daylight", Value: "1"})
	r.AddCookie(&http.Cookie{Name: "dst_offset", Value: "3600000"})
	r.AddCookie(&http.Cookie{Name: "channel", Value: "MI_APP_STORE"})

	resp, err := c.client.Do(r)

	if err != nil || resp.Status != "200 OK" {
		return "", ErrMakeCall
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	//log.Println("body ", string(body))
	decoded, err := decryptRC4(signedNonce, string(body))
	if err != nil {
		return "", err
	}

	return decoded, nil
}

func signNonce(nonce []byte, ssecurity string) string {
	buf, _ := base64.StdEncoding.DecodeString(ssecurity)
	buf = append(buf, nonce...)
	obj := sha256.Sum256(buf)
	return base64.StdEncoding.EncodeToString(obj[:])
}

func (c *XiaomiCloud) signature(url string, method string, signedNonce string, data string, rc4 string) string {
	sb := strings.Builder{}
	sb.WriteString(method)
	sb.WriteString("&")
	sb.WriteString(strings.Split(url, "/app")[1])

	sb.WriteString(fmt.Sprintf("&data=%s", data))
	if rc4 != "" {
		sb.WriteString(fmt.Sprintf("&rc4_hash__=%s", rc4))
	}

	sb.WriteString("&")
	sb.WriteString(signedNonce)

	//log.Println("signature for ", sb.String())

	sha := sha1.New()
	sha.Write([]byte(sb.String()))
	hash := sha.Sum(nil)

	return base64.StdEncoding.EncodeToString(hash)
}

func encryptRC4(signedNonce string, payload string) string {
	key, err := base64.StdEncoding.DecodeString(signedNonce)
	if err != nil {
		return ""
	}

	cipher, err := rc4.NewCipher(key)
	if err != nil {
		return ""
	}

	t := make([]byte, 1024)
	d := make([]byte, 1024)
	cipher.XORKeyStream(d, t)

	dst := make([]byte, len(payload))
	cipher.XORKeyStream(dst, []byte(payload))
	return base64.StdEncoding.EncodeToString(dst)
}

func decryptRC4(nonce string, payload string) (string, error) {
	key, err := base64.StdEncoding.DecodeString(nonce)
	if err != nil {
		return "", err
	}

	cipher, err := rc4.NewCipher(key)
	if err != nil {
		return "", err
	}

	t := make([]byte, 1024)
	d := make([]byte, 1024)
	cipher.XORKeyStream(d, t)

	dst, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return "", err
	}

	src := make([]byte, len(dst))
	cipher.XORKeyStream(src, dst)
	return string(src), nil
}
