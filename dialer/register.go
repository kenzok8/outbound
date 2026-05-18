/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"fmt"
	"strings"

	"github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/netproxy"
)

type FromLinkCreator func(gOption *ExtraOption, nextDialer netproxy.Dialer, link string) (dialer netproxy.Dialer, property *Property, err error)

var fromLinkCreators = make(map[string]FromLinkCreator)

func FromLinkRegister(name string, creator FromLinkCreator) {
	fromLinkCreators[name] = creator
}

func NewNetproxyDialerFromLink(d netproxy.Dialer, gOption *ExtraOption, link string) (netproxy.Dialer, *Property, error) {
	/// Get overwritten name.
	overwrittenName, linklike := common.GetTagFromLinkLikePlaintext(link)
	links := strings.Split(linklike, "->")
	p := &Property{
		Name:     "",
		Address:  "",
		Protocol: "",
		Link:     linklike,
	}
	for i := len(links) - 1; i >= 0; i-- {
		link := strings.TrimSpace(links[i])
		scheme, err := linkScheme(link)
		if err != nil {
			return nil, nil, err
		}
		creator, ok := fromLinkCreators[scheme]
		if !ok {
			return nil, nil, fmt.Errorf("unexpected link type: %v", scheme)
		}
		var _property *Property
		d, _property, err = creator(gOption, d, link)
		if err != nil {
			return nil, nil, fmt.Errorf("create %v: %w", link, err)
		}
		if p.Name == "" {
			p.Name = _property.Name
		} else {
			p.Name = _property.Name + "->" + p.Name
		}
		if p.Protocol == "" {
			p.Protocol = _property.Protocol
		} else {
			p.Protocol = _property.Protocol + "->" + p.Protocol
		}
		if p.Address == "" {
			p.Address = _property.Address
		} else {
			p.Address = _property.Address + "->" + p.Address
		}
	}
	if overwrittenName != "" {
		p.Name = overwrittenName
	}
	return d, p, nil
}

func linkScheme(link string) (string, error) {
	i := strings.IndexByte(link, ':')
	if i <= 0 || !isSchemeStart(link[0]) {
		return "", fmt.Errorf("missing link scheme")
	}
	for _, c := range link[1:i] {
		if !isSchemeChar(byte(c)) {
			return "", fmt.Errorf("invalid link scheme: %q", link[:i])
		}
	}
	return strings.ToLower(link[:i]), nil
}

func isSchemeStart(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z'
}

func isSchemeChar(c byte) bool {
	return isSchemeStart(c) || '0' <= c && c <= '9' || c == '+' || c == '-' || c == '.'
}
