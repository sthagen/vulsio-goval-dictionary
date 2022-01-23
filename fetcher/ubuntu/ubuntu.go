package ubuntu

import (
	"fmt"
	"strings"

	"github.com/inconshreveable/log15"
	"golang.org/x/xerrors"

	"github.com/vulsio/goval-dictionary/config"
	"github.com/vulsio/goval-dictionary/fetcher/util"
)

func newFetchRequests(target []string) (reqs []util.FetchRequest) {
	for _, v := range target {
		switch url := getOVALURL(v); url {
		case "unknown":
			log15.Warn("Skip unknown ubuntu.", "version", v)
		case "unsupported":
			log15.Warn("Skip unsupported ubuntu version.", "version", v)
			log15.Warn("See https://wiki.ubuntu.com/Releases for supported versions")
		default:
			reqs = append(reqs, util.FetchRequest{
				Target:       v,
				URL:          url,
				Concurrently: true,
				MIMEType:     util.MIMETypeBzip2,
			})
		}
	}
	return
}

func getOVALURL(version string) string {
	ss := strings.Split(version, ".")
	if len(ss) != 2 {
		return "unknown"
	}

	const main = "https://security-metadata.canonical.com/oval/com.ubuntu.%s.cve.oval.xml.bz2"
	const sub = "https://people.canonical.com/~ubuntu-security/oval/com.ubuntu.%s.cve.oval.xml.bz2"
	major, minor := ss[0], ss[1]
	switch major {
	case "12":
		return "unsupported"
	case "14":
		if minor == "04" {
			return fmt.Sprintf(main, config.Ubuntu1404)
		}
		if minor == "10" {
			return "unsupported"
		}
	case "16":
		if minor == "04" {
			return fmt.Sprintf(main, config.Ubuntu1604)
		}
		if minor == "10" {
			return "unsupported"
		}
	case "17":
		return "unsupported"
	case "18":
		if minor == "04" {
			return fmt.Sprintf(main, config.Ubuntu1804)
		}
		if minor == "10" {
			return "unsupported"
		}
	case "19":
		if minor == "04" {
			return "unsupported"
		}
		if minor == "10" {
			return fmt.Sprintf(sub, config.Ubuntu1910)
		}
	case "20":
		if minor == "04" {
			return fmt.Sprintf(main, config.Ubuntu2004)
		} else if minor == "10" {
			return fmt.Sprintf(sub, config.Ubuntu2010)
		}
	case "21":
		if minor == "04" {
			return fmt.Sprintf(main, config.Ubuntu2104)
		} else if minor == "10" {
			return fmt.Sprintf(main, config.Ubuntu2110)
		}
	default:
		return "unknown"
	}
	return "unknown"
}

// FetchFiles fetch OVAL from Ubuntu
func FetchFiles(versions []string) ([]util.FetchResult, error) {
	reqs := newFetchRequests(versions)
	if len(reqs) == 0 {
		return nil, xerrors.New("There are no versions to fetch")
	}
	results, err := util.FetchFeedFiles(reqs)
	if err != nil {
		return nil, xerrors.Errorf("Failed to fetch. err: %w", err)
	}
	return results, nil
}
