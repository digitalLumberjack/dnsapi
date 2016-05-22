package main

import (
	"github.com/digitallumberjack/dnsapi"
	"github.com/Sirupsen/logrus"
)

func main() {

	/** Creates a new dns api (c2VjcmV0 = secret in base64) **/
	dns := dnsapi.NewDNSApi("10.10.10.10", "53", "secret", "c2VjcmV0", "mydomain.org")
	{
		list, err := dns.list()
		if (err != nil) {
			logrus.Fatalf("error %v", err)
		}
		for _, e := range list {
			logrus.Infof("%s", e.String())
		}
	}
	{
		err := dns.add("www.mydomain.org", "1.1.1.1", "A", 60)
		if (err != nil) {
			logrus.Fatalf("error %v", err)
		}
	}
	{
		err := dns.remove("www.mydomain.org", "A")
		if (err != nil) {
			logrus.Fatalf("error %v", err)
		}
	}
}