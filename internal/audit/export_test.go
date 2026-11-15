package audit

import "gorm.io/gorm"

// ListPageQueryForTest builds the page query List runs, so the EXPLAIN tests
// measure the real statement instead of a copy of it.
func ListPageQueryForTest(db *gorm.DB, filter Filter, page, pageSize int) *gorm.DB {
	return filterQuery(db, filter).
		Select(selectEventColumns).
		Order("created_at DESC, id DESC").
		Offset((page - 1) * pageSize).
		Limit(pageSize)
}
