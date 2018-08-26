package rucaptcha

import (
	"net/http"
	"io/ioutil"
	"encoding/base64"
	"net/url"
	"strings"
	"time"
	"errors"
	"crypto/tls"
)

const (
	in  string = "http://rucaptcha.com/in.php"
	res string = "http://rucaptcha.com/res.php"
)

type RuCaptcha struct {
	Id            string
	ApiKey        string
	Sleep         time.Duration
	ImageResponse http.Response
	Proxy         string
	ProxyType     string
	Debug         bool
}

type Parameter struct {
	name  string
	value string
}

// Default captcha
func (ruCaptcha *RuCaptcha) Default(urlOrBase64 string) (string, error) {
	var encoded string = urlOrBase64

	if isUrl(urlOrBase64) {
		encodedImage, err := ruCaptcha.convertToBase64(urlOrBase64)

		if err != nil {
			return "", err
		}

		encoded = encodedImage
	}

	var values = []Parameter{
		{"method", "base64"},
		{"body", encoded},
	}

	return ruCaptcha.Await(values)
}

// Trying to solve google Recaptcha
func (ruCaptcha *RuCaptcha) ReCaptcha(pageUrl string, googleSiteKey string) (string, error) {
	var names = []Parameter{
		{"method", "userrecaptcha"},
		{"pageurl", pageUrl},
		{"googlekey", googleSiteKey},
	}

	return ruCaptcha.Await(names)
}

// send image, and get his id.
func (ruCaptcha *RuCaptcha) getId(parameters []Parameter) error {
	formData := url.Values{}

	formData.Add("key", ruCaptcha.ApiKey)

	if ruCaptcha.Proxy != "" && ruCaptcha.ProxyType != "" {
		parameters = append(parameters, Parameter{"proxy", ruCaptcha.Proxy}, Parameter{"proxy", ruCaptcha.Proxy})
	}

	for _, elem := range parameters {
		formData.Add(elem.name, elem.value)
	}

	req, err := http.NewRequest("POST", in, strings.NewReader(formData.Encode()))

	if err != nil {
		return err
	}

	client := ruCaptcha.getClient()

	resp, err := client.Do(req)

	if err != nil {
		return err
	}

	body, _ := ioutil.ReadAll(resp.Body)
	result := string(body)
	exploded := strings.Split(result, "|")

	if !strings.Contains(result, "OK|") {
		return errors.New(exploded[0])
	}

	ruCaptcha.Id = exploded[1]

	return nil
}

// when we already have an Id
// we just need wait until captcha until it's ready.
func (ruCaptcha *RuCaptcha) Await(parameters []Parameter) (string, error) {
	err := ruCaptcha.getId(parameters)

	if err != nil {
		return "", err
	}

	var params = []Parameter{
		{"id", ruCaptcha.Id},
		{"action", "get"},
	}

	code := ""
	wasResolved := false

	for !wasResolved {

		resp, err := ruCaptcha.getRequest(res, params)

		if err != nil {
			return "", err
		}

		body, _ := ioutil.ReadAll(resp.Body)

		answer := string(body[:])

		isResolved := strings.Contains(answer, "OK|")
		isNotReady := strings.Contains(answer, "CAPCHA_NOT_READY")

		if ruCaptcha.Debug {
			print(answer)
			print("\n")
		}

		if isResolved {
			wasResolved = true
			exploded := strings.Split(answer, "|")
			code = exploded[1]
		}

		if isNotReady {
			time.Sleep(ruCaptcha.Sleep * time.Second)

			continue
		}

		if !isResolved && !isNotReady {
			return "", errors.New(answer)
		}
	}

	return code, nil
}

// Complain last solved a captcha,
// because she solved incorrectly
func (ruCaptcha *RuCaptcha) Report() (error) {
	var parameters = []Parameter{
		{"id", ruCaptcha.Id},
		{"action", "reportbad"},
	}
	serverStatus := ""
	resp, err := ruCaptcha.getRequest(res, parameters)

	if err != nil {
		return err
	}

	body, _ := ioutil.ReadAll(resp.Body)

	answer := string(body)

	if strings.Contains("OK_REPORT_RECORDED|", answer) {
		return nil
	}

	exploded := strings.Split(answer, "|")

	serverStatus = exploded[1]

	return errors.New(serverStatus)
}

func (ruCaptcha RuCaptcha) getRequest(url string, parameters []Parameter) (*http.Response, error) {

	request, _ := http.NewRequest("GET", url, nil)

	query := request.URL.Query()

	parameters = append(parameters, Parameter{"json", "0"})
	parameters = append(parameters, Parameter{"key", ruCaptcha.ApiKey})

	for _, param := range parameters {
		query.Add(param.name, param.value)
	}

	request.URL.RawQuery = query.Encode()

	client := http.Client{}

	return client.Do(request)
}

// If user give us link, not a base64, we need convert it
// to base64 format.
func (ruCaptcha *RuCaptcha) convertToBase64(url string) (string, error) {
	// lets make get request
	//print("-> -> 1")
	//print("\n")

	client := ruCaptcha.getClient()

	req, reqErr := http.NewRequest("GET", url, nil)

	//print("-> -> 2")
	//print("\n")

	if reqErr != nil {
		return "", reqErr
	}

	resp, err := client.Do(req)

	//print("-> -> 3")
	//print("\n")

	if err != nil {
		return "", err
	}

	ruCaptcha.ImageResponse = *resp

	//print("-> -> 4")
	//print("\n")

	defer resp.Body.Close()

	// Read entire JPG into byte slice.
	//reader := bufio.NewReader(resp.Body)
	content, err := ioutil.ReadAll(resp.Body)
	//
	//os.Remove("img.jpg")
	//f, err := os.Create("img.jpg")
	//
	//defer f.Close()
	//
	//f.Write(content)

	//print("-> -> 5")
	//print("\n")

	if err != nil {
		return "", err
	}

	// Encode as base64.
	encoded := base64.StdEncoding.EncodeToString(content)

	//print("-> -> 4")
	//print("\n")

	return encoded, nil
}

func (ruCaptcha *RuCaptcha) SetProxy(proxy string, proxyType string) {
	ruCaptcha.Proxy = proxy
	ruCaptcha.ProxyType = proxyType
}

func isUrl(toTest string) bool {
	_, err := url.ParseRequestURI(toTest)
	if err != nil {
		return false
	} else {
		return true
	}
}

func (ruCaptcha RuCaptcha) getClient() *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	if ruCaptcha.Proxy != "" {
		proxyUrl, _ := url.Parse(ruCaptcha.Proxy)
		tr.Proxy = http.ProxyURL(proxyUrl)
	}

	return &http.Client{Transport: tr}
}

func New(apiKey string) *RuCaptcha {
	return &RuCaptcha{
		ApiKey: apiKey,
		Sleep:  1,
	}
}
