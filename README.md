# ruCaptcha

# ruCaptcha
Little wrapper for rucaptcha API

## Go get
go get github.com/koteezy/ruCaptcha


## Solve a captcha from a url, or base64
```
re := ruCaptcha.New("APIKEY")
captcha, err := re.Default("url or base64")
```

## Solve a google recaptcha
```
re := ruCaptcha.New("APIKEY")
captcha, err := re.ReCaptcha("Page url", "Google Site Key")
```

## Incorrectly solved captcha
If, after the checks, it turns out that the captcha has been solved incorrectly - you can complain about the wrong captcha. The last captcha ID is sent to the server.
```
re := ruCaptcha.New("APIKEY")
captcha, err := re.Default("Page url")

if captcha !== 3952 {
    error := re.Report()

    // if error ...
}
```