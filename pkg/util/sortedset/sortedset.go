package sortedset

import "github.com/google/btree"

// SetItem represents a single object in a SortedSet.
type SetItem interface {
	// Key returns the unique identifier for this item.
	Key() string
	// Rank is used to sort items.
	// Items with the same rank are sorted lexicographically based on Key.
	Rank() int64
}

// SortedSet stores SetItems based on Key (uniqueness) and Rank (sorting).
type SortedSet struct {
	sorted *btree.BTree
	set    map[string]*treeItem
}

func New() *SortedSet {
	return &SortedSet{
		sorted: btree.New(32),
		set:    make(map[string]*treeItem),
	}
}

// Add inserts the item into the set.
// If an item with the same Key existed in the set, it is removed and returned.
func (s *SortedSet) Add(item SetItem) SetItem {
	old := s.Remove(item)

	key := item.Key()
	value := &treeItem{item: item}

	s.sorted.ReplaceOrInsert(value) // should always return nil because we call remove first
	s.set[key] = value

	return old
}

// Remove deletes the item from the set based on Key (Rank is ignored).
// The removed item is returned if it existed in the set.
func (s *SortedSet) Remove(item SetItem) SetItem {
	key := item.Key()
	value, ok := s.set[key]
	if !ok {
		return nil
	}

	s.sorted.Delete(value) // should always return the same data as value (non-nil)
	delete(s.set, key)

	return value.item
}

func (s *SortedSet) Min() SetItem {
	return s.sorted.Min().(*treeItem).item
}

func (s *SortedSet) Max() SetItem {
	return s.sorted.Max().(*treeItem).item
}

func (s *SortedSet) Len() int {
	return len(s.set)
}

func (s *SortedSet) Get(item SetItem) SetItem {
	if value, ok := s.set[item.Key()]; ok {
		return value.item
	}
	return nil
}

func (s *SortedSet) Has(item SetItem) bool {
	_, ok := s.set[item.Key()]
	return ok
}

// LessThan returns all items less than the given rank.
// If remove is set to true, the returned items are removed from the set.
func (s *SortedSet) LessThan(rank int64, remove bool) []SetItem {
	var items []SetItem
	s.sorted.Ascend(func(i btree.Item) bool {
		item := i.(*treeItem).item
		if item.Rank() >= rank {
			return false
		}
		items = append(items, item)
		return true
	})
	// remove after Ascend since it is probably not safe to delete while iterating
	if remove {
		for _, item := range items {
			s.Remove(item)
		}
	}
	return items
}

var _ btree.Item = &treeItem{}

type treeItem struct {
	item SetItem
}

func (i *treeItem) Less(than btree.Item) bool {
	other := than.(*treeItem).item

	selfKey := i.item.Key()
	otherKey := other.Key()

	// !a.Less(b) && !b.Less(a) means a == b
	if selfKey == otherKey {
		return false
	}

	selfRank := i.item.Rank()
	otherRank := other.Rank()

	if selfRank == otherRank {
		return selfKey < otherKey
	}

	return selfRank < otherRank
}
