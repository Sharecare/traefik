package state

import (
	"github.com/traefik/traefik/v2/pkg/server/service/roundrobin"
)

var LoadBalancer map[string]*roundrobin.RoundRobin

func init() {
	LoadBalancer = make(map[string]*roundrobin.RoundRobin)
}
