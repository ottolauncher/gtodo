package helpers

func Subset[T comparable](subset interface{}, superset interface{}) bool {
	// Type assertion for safety (explained later)
	s1 := subset.([]T)
	s2 := superset.([]T)

	for _, value := range s2 {
		found := false
		for _, element := range s1 {
			if value == element {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
