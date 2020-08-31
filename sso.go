package go_sso

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

const accessTokenUrl = "/oauth/oauth2/access_token"
const urlInfoUrl = "/oauth/oauth2/userinfo"
const checkPrivilegeUrl = "/oauth/api/checkPrivilege"
const logOutUrl = "/oauth/oauth2/logout"
const authorizeUrl = "/oauth/oauth2/authorize"

type SSO struct {
	AppID  string // 由SSO平台统一分配的appid
	Secret string // 由SSO平台统一分配的secret。相当于appkey的做作用
	Host   string // 请求
	ServerOrigin string
}

func NewSSOInstance(appID, secret, host, origin string) *SSO {
	s := SSO{}
	s.AppID = appID
	s.Secret = secret
	s.Host = host
	s.ServerOrigin = origin
	return &s
}

// 发送 http 请求
func doRequest(url string) ([]byte, error) {
	//log.Printf("请求URL %s", url)
	res, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("error request: %w", err)
	}
	defer res.Body.Close()

	return ioutil.ReadAll(res.Body)
}

func hmacSha1(content, key []byte) string {
	mac := hmac.New(sha1.New, key)
	mac.Write(content)
	res := mac.Sum(nil)
	dst := make([]byte, hex.EncodedLen(mac.Size()))
	hex.Encode(dst, res)
	return string(dst)
}

type AccessTokenBody struct {
	Data struct {
		AccessToken  string `json:"access_token"`
		ExpiresIn    int    `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
		OpenID       string `json:"openid"`
		Scope        string `json:"scope"`
	} `json:"data"`
	Errno  int    `json:"errno"`
	ErrMsg string `json:"errmsg"`
}

// AccessToken 获取 access_token
func (s *SSO) AccessToken(code string) (*AccessTokenBody, error) {

	params := url.Values{}
	params.Set("appid", s.AppID)
	params.Set("secret", s.Secret)
	params.Set("code", code)
	params.Set("grant_type", "authorization_code")

	body, err := s.doGetRequest(accessTokenUrl, params, true)

	// log.Printf("AccessToken Content %s", string(body))

	if err != nil {
		return nil, fmt.Errorf("error request AccessToken api: %w", err)
	}

	var tokenBody AccessTokenBody
	err = json.Unmarshal(body, &tokenBody)
	return &tokenBody, err
}

func (s *SSO) doGetRequest(apiPath string, param url.Values, sign bool) ([]byte, error) {
	reqUrl, err := url.Parse(s.Host + apiPath)
	if err != nil {
		return nil, fmt.Errorf("error create url: %w", err)
	}

	if sign {

		param.Set("appid", s.AppID)
		ts := fmt.Sprintf("%d", time.Now().Unix())
		param.Set("ts", ts)
		//fmt.Println(s.AppID)
		//fmt.Println(ts)
		//fmt.Println(hmacSha1([]byte(fmt.Sprintf("%s%s", s.AppID, ts)), []byte(s.Secret)))
		//fmt.Println(fmt.Sprintf("%s%s", s.AppID, ts))
		//fmt.Println(s.Secret)
		param.Set("sign", hmacSha1([]byte(fmt.Sprintf("%s%s", s.AppID, ts)), []byte(s.Secret)))
	}

	reqUrl.RawQuery = param.Encode()
	return doRequest(reqUrl.String())
}

type UserInfo struct {
	ID        int    `json:"id"`
	UserName  string `json:"user_name"`
	LoginName string `json:"login_name"`
	NickName  string `json:"nick_name"`
	Phone     string `json:"phone"`
}

type GetUserInfoResVO struct {
	Errno  int      `json:"errno"`
	ErrMsg string   `json:"errmsg"`
	Data   UserInfo `json:"data"`
}

func (s *SSO) GetUserInfo(accessToken, openid string) (*UserInfo, error) {

	params := url.Values{}
	params.Set("access_token", accessToken)
	params.Set("openid", openid)

	body, err := s.doGetRequest(urlInfoUrl, params, true)

	if err != nil {
		return nil, fmt.Errorf("error request GetUserInfo: %w", err)
	}

	log.Printf("GetUserInfo Content %s", string(body))

	var res GetUserInfoResVO
	err = json.Unmarshal(body, &res)
	if err != nil {
		return nil, fmt.Errorf("error Unmarshal JSON: %w", err)
	}

	if res.Errno != 0 {
		return nil, fmt.Errorf("error GetUserInfo response: errno: %d, errmsg: %s", res.Errno, res.ErrMsg)
	}

	return &res.Data, nil
}

type CheckPrivilegeVO struct {
	Errno  int    `json:"errno"`
	ErrMsg string `json:"errmsg"`
}

// CheckPrivilege 检测权限
func (s *SSO) CheckPrivilege(accessToken, openid, key string) (bool, error) {

	// checkPrivilegeUrl
	params := url.Values{}
	params.Set("access_token", accessToken)
	params.Set("openid", openid)
	params.Set("key", key)

	body, err := s.doGetRequest(checkPrivilegeUrl, params, true)
	if err != nil {
		return false, fmt.Errorf("error do reqeust checkPrivilege: %w", err)
	}

	var res CheckPrivilegeVO
	err = json.Unmarshal(body, &res)

	if err != nil {
		return false, fmt.Errorf("error Unmarshal JSON: %w", err)
	}

	if res.Errno != 0 {
		return false, nil
	}

	return true, nil
}

type LogOutVO struct {
	Errno  int    `json:"errno"`
	ErrMsg string `json:"errmsg"`
}

func (s *SSO) LogOut(accessToken string, openid string) (bool, error) {
	params := url.Values{}
	params.Set("access_token", accessToken)
	params.Set("openid", openid)
	body, err := s.doGetRequest(logOutUrl, params, true)

	if err != nil {
		return false, fmt.Errorf("error do reqeust LogOut: %w", err)
	}

	var res LogOutVO
	err = json.Unmarshal(body, &res)

	if err != nil {
		return false, fmt.Errorf("error Unmarshal JSON: %w", err)
	}

	if res.Errno != 0 {
		return false, nil
	}

	return true, nil
}

func (s *SSO) CreateRedirectUrl(successUrl string) string {
	u0, _ := url.Parse(s.ServerOrigin +  "/sso/login")
	q0 := u0.Query()
	q0.Add("successUrl", successUrl)
	u0.RawQuery = q0.Encode()

	u1, _ := url.Parse(s.Host + authorizeUrl)

	q := u1.Query()
	q.Add("appid", s.AppID)
	q.Add("redirect_uri", u0.String())
	q.Add("response_type", "code")
	q.Add("scope", "snsapi_userinfo")
	q.Add("state", strconv.FormatInt(time.Now().Unix(), 10))

	u1.RawQuery = q.Encode()

	return u1.String()
}