package collector

import (
	"github.com/hillu/go-yara/v4"

	"bytes"
	"fmt"
	"sync"

	log "github.com/sirupsen/logrus"
)

func printMatches(item string, m []yara.MatchRule, err error) {
	if err != nil {
		log.Printf("%s: error: %s", item, err)
		return
	}
	if len(m) == 0 {
		log.Printf("%s: no matches", item)
		return
	}
	buf := &bytes.Buffer{}
	fmt.Fprintf(buf, "%s: [", item)
	for i, match := range m {
		if i > 0 {
			fmt.Fprint(buf, ", ")
		}
		fmt.Fprintf(buf, "%s:%s", match.Namespace, match.Rule)
	}
	fmt.Fprint(buf, "]")
	log.Print(buf.String())
}

func Scan(rules []string, packets []string) {
	threads := 1

	if len(rules) == 0 {
		log.Fatal("no rules specified")
	}

	c, err := yara.NewCompiler()
	if err != nil {
		log.Fatalf("Failed to initialize YARA compiler: %s", err)
	}
	for _, rule := range rules {
		err = c.AddString(rule, "")
		if err != nil {
			log.Fatalf("Could not parse rule %s: %s", rule, err)
		}
	}
	r, err := c.GetRules()
	if err != nil {
		log.Fatalf("Failed to compile rules: %s", err)
	}

	wg := sync.WaitGroup{}
	wg.Add(threads)

	ps := make(chan string, threads)
	for i := 0; i < threads; i++ {
		s, _ := yara.NewScanner(r)
		go func(ps chan string) {
			for p := range ps {
				var m yara.MatchRules
				log.Infof("Scanning process %s...", p)
				err := s.SetCallback(&m).ScanMem([]byte(p))
				printMatches(fmt.Sprintf("<packet %s", p), m, err)
			}
			wg.Done()
		}(ps)
	}
	for _, packets := range packets {
		ps <- packets
	}
	close(ps)

	wg.Wait()
}
