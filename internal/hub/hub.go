package hub

import (
	"sync"

	"github.com/aaronburt/netscan/internal/detector"
)

type HubMessageKind string

const (
	MessageSnapshot HubMessageKind = "snapshot"
	MessageEvent    HubMessageKind = "event"
)

type HubMessage struct {
	Kind     HubMessageKind     `json:"kind"`
	Snapshot *detector.Snapshot `json:"snapshot,omitempty"`
	Event    *detector.Event    `json:"event,omitempty"`
}

type Subscriber struct {
	ch   chan HubMessage
	done chan struct{}
}

func (s *Subscriber) Channel() <-chan HubMessage {
	return s.ch
}

type Hub struct {
	lock        sync.RWMutex
	subscribers map[*Subscriber]struct{}
}

func NewHub() *Hub {
	return &Hub{
		subscribers: make(map[*Subscriber]struct{}),
	}
}

func (h *Hub) Subscribe() *Subscriber {
	h.lock.Lock()
	defer h.lock.Unlock()

	sub := &Subscriber{
		ch:   make(chan HubMessage, 64),
		done: make(chan struct{}),
	}
	h.subscribers[sub] = struct{}{}
	return sub
}

func (h *Hub) Unsubscribe(sub *Subscriber) {
	h.lock.Lock()
	defer h.lock.Unlock()

	if _, ok := h.subscribers[sub]; ok {
		delete(h.subscribers, sub)
		close(sub.done)
	}
}

func (h *Hub) PublishSnapshot(snap detector.Snapshot) {
	msg := HubMessage{
		Kind:     MessageSnapshot,
		Snapshot: &snap,
	}
	h.broadcast(msg)
}

func (h *Hub) PublishEvent(evt detector.Event) {
	msg := HubMessage{
		Kind:  MessageEvent,
		Event: &evt,
	}
	h.broadcast(msg)
}

func (h *Hub) broadcast(msg HubMessage) {
	h.lock.RLock()
	defer h.lock.RUnlock()

	var toRemove []*Subscriber

	for sub := range h.subscribers {
		select {
		case <-sub.done:
			toRemove = append(toRemove, sub)
		case sub.ch <- msg:
		default:
			toRemove = append(toRemove, sub)
		}
	}

	if len(toRemove) > 0 {
		go func(subs []*Subscriber) {
			h.lock.Lock()
			defer h.lock.Unlock()
			for _, s := range subs {
				delete(h.subscribers, s)
			}
		}(toRemove)
	}
}
