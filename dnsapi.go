package dnsapi

import (
	"github.com/Sirupsen/logrus"
	"github.com/miekg/dns"
	"fmt"
	"net"
	"time"
	"strings"
)

type DNSApi struct {
	server     string
	port       string
	keyname    string
	key        string
	rootdomain string
}

func NewDNSApi(server string, port string, keyname string, key string, rootdomain string) *DNSApi {
	return &DNSApi{server, port, keyname, key, rootdomain}
}

func needFQDN(domain string) string {
	if (strings.HasSuffix(domain, ".")) {
		return domain
	} else {
		return domain + "."
	}
}

func (b DNSApi) sendMessage(msg *dns.Msg) error {
	c := new(dns.Client)
	c.Net = "udp"
	t := new(dns.Transfer)

	nameserver := net.JoinHostPort(b.server, b.port)
	keydns := needFQDN(b.keyname)
	msg.SetTsig(keydns, "hmac-md5.sig-alg.reg.int.", 300, time.Now().Unix())
	c.TsigSecret = map[string]string{keydns: b.key}
	t.TsigSecret = map[string]string{keydns: b.key}

	_, err := t.In(msg, nameserver)
	t.Close()
	return err
}

func (b DNSApi) add(fqdn string, ip string, class string, ttl int) error {
	logrus.Debugf("adding entry %s %s %d", fqdn, ip, ttl)

	m := new(dns.Msg)
	root := needFQDN(b.rootdomain)
	m.SetUpdate(root)
	rr, err := dns.NewRR(fmt.Sprintf("%s %d %s %s", needFQDN(fqdn), ttl, class, ip))
	if (err != nil) {
		return err
	}
	rrs := make([]dns.RR, 1)
	rrs[0] = rr
	m.Insert(rrs)

	return b.sendMessage(m)
}

func (b DNSApi) remove(fqdn string, class string) error {
	logrus.Debugf("removing entry %s", fqdn)

	m := new(dns.Msg)
	root := needFQDN(b.rootdomain)
	m.SetUpdate(root)
	rr, rrerr := dns.NewRR(fmt.Sprintf("%s 0 %s 0.0.0.0", needFQDN(fqdn), class))
	if (rrerr != nil) {
		return rrerr
	}
	rr.Header().Class = dns.TypeANY
	rrs := make([]dns.RR, 1)
	rrs[0] = rr
	m.RemoveRRset(rrs)
	return b.sendMessage(m)
}

func (b DNSApi) list() ([]dns.RR, error) {
	logrus.Debugf("listing entries for %s", b.rootdomain)

	t := new(dns.Transfer)
	m := new(dns.Msg)
	m.Question = make([]dns.Question, 1)
	root := needFQDN(b.rootdomain)

	nameserver := net.JoinHostPort(b.server, b.port)
	m.SetAxfr(root)

	env, err := t.In(m, nameserver)
	if err != nil {
		return nil, err;
	}
	envelope := 0
	record := 0
	records := make([]dns.RR, 0)

	// TODO what is an enveloppe, can i receive several of them ?
	for e := range env {
		if e.Error != nil {
			fmt.Printf(";; %s\n", e.Error.Error())
			return nil, err
		}
		records = append(records, e.RR...)
		record += len(e.RR)
		envelope++
	}
	t.Close()
	return records, nil
}