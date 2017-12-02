package sortedset

import "testing"

func TestSortedSet(t *testing.T) {
	s := New()
	a := newTestSetItem("A", 5, "AD")
	b := newTestSetItem("B", 6, "BD")
	c := newTestSetItem("C", 4, "CD")
	d := newTestSetItem("D", 6, "DD")
	e := newTestSetItem("E", 1, "ED")

	for _, tc := range []struct {
		name string
		f    func(*testing.T)
	}{
		{
			name: "add",
			f: func(t *testing.T) {
				assertLen(s, 0, t)
				s.Add(a)
				assertLen(s, 1, t)
				s.Add(b)
				assertLen(s, 2, t)
				s.Add(c)
				assertLen(s, 3, t)
				s.Add(d)
				assertLen(s, 4, t)
				s.Add(e)
				assertLen(s, 5, t)
			},
		},
		{
			name: "list order",
			f: func(t *testing.T) {
				assertOrder(s.List(false), t, e, c, a, b, d)
				assertItem(e, s.Min(), t)
				assertItem(d, s.Max(), t)
			},
		},
		{
			name: "remove list order 1",
			f: func(t *testing.T) {
				assertItem(a, s.Remove(a), t)
				assertOrder(s.List(false), t, e, c, b, d)
				assertLen(s, 4, t)
				assertItem(e, s.Min(), t)
				assertItem(d, s.Max(), t)
			},
		},
		{
			name: "remove list order 2",
			f: func(t *testing.T) {
				assertItem(b, s.Remove(b), t)
				assertOrder(s.List(false), t, e, c, d)
				assertLen(s, 3, t)
				assertItem(e, s.Min(), t)
				assertItem(d, s.Max(), t)
			},
		},
		{
			name: "has",
			f: func(t *testing.T) {
				assertHas("A", false, s, t)
				assertHas("B", false, s, t)
				assertHas("C", true, s, t)
				assertHas("D", true, s, t)
				assertHas("E", true, s, t)
				assertHas("F", false, s, t)
			},
		},
		{
			name: "get",
			f: func(t *testing.T) {
				assertItem(nil, s.Get(SetString("A")), t)
				assertItem(nil, s.Get(SetString("B")), t)
				assertItem(c, s.Get(SetString("C")), t)
				assertItem(d, s.Get(SetString("D")), t)
				assertItem(e, s.Get(SetString("E")), t)
				assertItem(nil, s.Get(SetString("F")), t)
			},
		},
		{
			name: "remove list order 3",
			f: func(t *testing.T) {
				assertItem(nil, s.Remove(b), t)
				assertOrder(s.List(false), t, e, c, d)
				assertLen(s, 3, t)
				assertItem(e, s.Min(), t)
				assertItem(d, s.Max(), t)
			},
		},
		{
			name: "remove list order 4",
			f: func(t *testing.T) {
				assertItem(c, s.Remove(c), t)
				assertOrder(s.List(false), t, e, d)
				assertLen(s, 2, t)
				assertItem(e, s.Min(), t)
				assertItem(d, s.Max(), t)
			},
		},
		{
			name: "add list order",
			f: func(t *testing.T) {
				assertItem(nil, s.Add(a), t)
				assertOrder(s.List(false), t, e, a, d)
				assertLen(s, 3, t)
				assertItem(e, s.Min(), t)
				assertItem(d, s.Max(), t)
			},
		},
		{
			name: "less than order",
			f: func(t *testing.T) {
				assertOrder(s.LessThan(6, false), t, e, a)
				assertLen(s, 3, t)
				assertItem(e, s.Min(), t)
				assertItem(d, s.Max(), t)
			},
		},
		{
			name: "less than order remove",
			f: func(t *testing.T) {
				assertOrder(s.LessThan(6, true), t, e, a)
				assertLen(s, 1, t)
				assertItem(d, s.Min(), t)
				assertItem(d, s.Max(), t)
			},
		},
		{
			name: "list order remove",
			f: func(t *testing.T) {
				assertOrder(s.List(true), t, d)
				assertLen(s, 0, t)
				assertItem(nil, s.Min(), t)
				assertItem(nil, s.Max(), t)
			},
		},
		{
			name: "add min max",
			f: func(t *testing.T) {
				assertItem(nil, s.Add(b), t)
				assertItem(nil, s.Add(a), t)
				assertItem(nil, s.Add(e), t)
				assertOrder(s.List(false), t, e, a, b)
				assertLen(s, 3, t)
				assertItem(e, s.Min(), t)
				assertItem(b, s.Max(), t)
				assertItem(e, s.Remove(e), t)
				assertLen(s, 2, t)
				assertItem(a, s.Min(), t)
				assertItem(b, s.Max(), t)
			},
		},
		{
			name: "add replace",
			f: func(t *testing.T) {
				a0 := newTestSetItem("A", 1, "AD0")
				a1 := newTestSetItem("A", 2, "AD1")
				a2 := newTestSetItem("A", 3, "AD2")

				assertItem(nil, s.Add(e), t)
				assertOrder(s.List(false), t, e, a, b)
				assertLen(s, 3, t)
				assertItem(e, s.Min(), t)
				assertItem(b, s.Max(), t)

				assertItem(a, s.Add(a0), t)
				assertOrder(s.List(false), t, a0, e, b)
				assertLen(s, 3, t)
				assertItem(a0, s.Min(), t)
				assertItem(b, s.Max(), t)

				assertItem(a0, s.Add(a1), t)
				assertOrder(s.List(false), t, e, a1, b)
				assertLen(s, 3, t)
				assertItem(e, s.Min(), t)
				assertItem(b, s.Max(), t)

				assertItem(a1, s.Add(a2), t)
				assertOrder(s.List(false), t, e, a2, b)
				assertLen(s, 3, t)
				assertItem(e, s.Min(), t)
				assertItem(b, s.Max(), t)
			},
		},
	} {
		t.Run(tc.name, tc.f)
	}
}

func TestNoRank(t *testing.T) {
	aRank := &noRankA{}
	bRank := &noRankB{}

	s := New()
	a := newTestSetItem("A", 5, "AD")
	b := newTestSetItem("B", 6, "BD")

	assertItem(nil, s.Add(a), t)
	assertItem(nil, s.Add(b), t)

	assertItem(a, s.Get(aRank), t)
	assertItem(b, s.Get(bRank), t)

	assertItem(a, s.Add(aRank), t)
	assertItem(b, s.Add(bRank), t)

	okA := s.Get(aRank) == aRank
	okB := s.Get(bRank) == bRank

	okAKey := s.Get(aRank).Key() == "A"
	okBKey := s.Get(bRank).Key() == "B"

	_, okAType := s.Get(aRank).(*noRankA)
	_, okBType := s.Get(bRank).(*noRankB)

	if !okA || !okB || !okAKey || !okBKey || !okAType || !okBType {
		t.Errorf("expected all true, got okA=%v okB=%v okAKey=%v okBKey=%v okAType=%v okBType=%v",
			okA, okB, okAKey, okBKey, okAType, okBType)
	}
}

func assertLen(s *SortedSet, length int, t *testing.T) {
	if s.Len() != length {
		t.Errorf("%s expected len: %d got %d for %v", t.Name(), length, s.Len(), noPointerItems(s.List(false)))
	}
}

func assertOrder(actual []SetItem, t *testing.T, items ...*testSetItem) {
	if len(items) != len(actual) {
		t.Errorf("%s expected len: %d got %d for %v and %v", t.Name(), len(items), len(actual), noPointers(items), noPointerItems(actual))
		return
	}
	for i, item := range items {
		if actualItem := actual[i].(*testSetItem); *item != *actualItem {
			t.Errorf("%s expected item: %v got %v for idx %d", t.Name(), *item, *actualItem, i)
		}
	}
}

func assertItem(item *testSetItem, actual SetItem, t *testing.T) {
	itemNil := item == nil
	actualNil := actual == nil

	if itemNil != actualNil {
		t.Errorf("%s expected or actual is nil: %v vs %v", t.Name(), item, actual)
		return
	}

	if itemNil {
		return
	}

	if actualItem := actual.(*testSetItem); *item != *actualItem {
		t.Errorf("%s expected item: %v got %v", t.Name(), *item, *actualItem)
	}
}

func assertHas(key string, expected bool, s *SortedSet, t *testing.T) {
	if expected != s.Has(SetString(key)) {
		t.Errorf("%s expected %v for %s with %v", t.Name(), expected, key, noPointerItems(s.List(false)))
	}
}

func newTestSetItem(key string, rank int64, data string) *testSetItem {
	return &testSetItem{
		key:  key,
		rank: rank,
		data: data,
	}
}

type testSetItem struct {
	key  string
	rank int64
	data string
}

func (i *testSetItem) Key() string {
	return i.key
}

func (i *testSetItem) Rank() int64 {
	return i.rank
}

type noRankA struct {
	NoRank // embed struct
}

func (*noRankA) Key() string {
	return "A"
}

type noRankB struct {
	*NoRank // embed pointer struct
}

func (*noRankB) Key() string {
	return "B"
}

// funcs below make the printing of these slices better

func noPointers(items []*testSetItem) []testSetItem {
	var out []testSetItem
	for _, item := range items {
		out = append(out, *item)
	}
	return out
}

func noPointerItems(items []SetItem) []testSetItem {
	var out []testSetItem
	for _, item := range items {
		out = append(out, *(item.(*testSetItem)))
	}
	return out
}
