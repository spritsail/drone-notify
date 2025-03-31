package registry

import (
	"github.com/puzpuzpuz/xsync"
)

func New[T any]() Registry[T] {
	return Registry[T]{*xsync.NewMapOf[T]()}
}

type Registry[T any] struct {
	entries xsync.MapOf[string, T]
}

func (r *Registry[T]) Register(name string, data T) {
	_, existed := r.entries.LoadAndStore(name, data)
	if existed {
		panic(name + " already in registry")
	}
}

func (r *Registry[T]) Find(name string) (T, bool) {
	return r.entries.Load(name)
}
func (r *Registry[T]) Get(name string) T {
	t, ok := r.entries.Load(name)
	if !ok {
		panic(name + " not found in registry")
	}
	return t
}
