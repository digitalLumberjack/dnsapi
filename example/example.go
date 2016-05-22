package main

import (
	"github.com/digitallumberjack/dnsapi"
	"github.com/Sirupsen/logrus"
	"github.com/miekg/dns"
)

func main() {

	/** Creates a new dns api (c2VjcmV0 = secret in base64) **/
	dnsapi := dnsapi.NewDNSApi("10.10.10.10", "53", "secret", "c2VjcmV0", "mydomain.org")
	{
		list, err := dnsapi.List()
		if (err != nil) {
			logrus.Fatalf("error %v", err)
		}
		for _, e := range list {
			switch e.(type){
			case *dns.A:
				logrus.Infof("%s", e.(*dns.A).A)
			}
			logrus.Infof("%s", e.String())
		}
	}
	{
		err := dnsapi.Add("www.mydomain.org", "1.1.1.1", "A", 60)
		if (err != nil) {
			logrus.Fatalf("error %v", err)
		}
	}
	{
		err := dnsapi.Remove("www.mydomain.org", "A")
		if (err != nil) {
			logrus.Fatalf("error %v", err)
		}
	}
}