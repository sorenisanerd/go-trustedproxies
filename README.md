# TrustedProxies
![Test results](https://github.com/sorenisanerd/go-trustedproxies/actions/workflows/test.yaml/badge.svg)


Web frameworks frequently use X-Forwarded-For in a way that trivially allows an attacker to spoof their IP. This library helps filter out untrusted information.

As requests go through proxies, each will append the client's IP to X-Forwarded-For. To mitigate malicious clients or proxies, we only accept information from trusted proxies.

Using the library is simple:


```
tp := trustedProxies.New()

// Suppose our proxy is 10.10.10.10
tp.AddFromString("10.10.10.10")

// There might be another proxy in front of that one, so let's add that, too.
tp.AddFromString("20.20.20.20")

XForwardedFor := "40.40.40.40, 30.30.30.30, 20.20.20.20"

ourProxyAddress := net.ParseIP("10.10.10.10")

checkedIP := tp.DeduceClientIP(ourProxyAddress, XForwardedFor)

// checkedIP will now hold "30.30.30.30": We trust the first two proxies
// but have no reason to trust the information from anything beyond that.

```
