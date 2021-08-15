# samltools
A playground to learn SAML. The source contains a simple Service Provider and an Identity Provider.
As of now, Service Provider is tested with Auth0 and Okta. IDP is tested with Auth0.

# How to setup a service provider locally?
- Clone the repo
- Setup a loopback mapping to "sp.samltools.com". For example on mac, I do the following
```
Edit /etc/hosts to add 127.0.0.7 sp.samltools.com
Run sudo ifconfig lo0 alias 127.0.0.7 up
```
- You should be able to use the IDP configured in spconfig.yml as-is
- Start the Service Provider
```
$ cd sp
$ go run samlsp.go
```
- Visit "http://sp.samltools.com:4567/pages/sp.html" in a browser and you will see the home page 

![SP Home](https://user-images.githubusercontent.com/1742745/126103350-dda74677-97d3-4e9f-933a-52a3b8257f3b.png)