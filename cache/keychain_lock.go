package cache

import "sync"

// flock protects between processes; this mutex also protects distinct store
// instances in the same process (and the keyring mock used by race tests).
var keychainMutexes sync.Map

func lockKeychainProcess(service, key string) func() {
	id := service + "\x00" + key
	value, _ := keychainMutexes.LoadOrStore(id, new(sync.Mutex))
	mu := value.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}
