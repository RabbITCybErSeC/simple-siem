package audit

import "gorm.io/gorm"

// ListPageQueryForTest builds the page query List runs.
func ListPageQueryForTest(db *gorm.DB, filter Filter, page, pageSize int) *gorm.DB {
	return pageQuery(db, filter, page, pageSize)
}
