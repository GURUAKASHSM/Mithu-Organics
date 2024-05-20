package models

import "time"

type DeveloperAudit struct {
	Audit     interface{} `json:"audit" bson:"audit"`
	ErrorTime time.Time   `json:"errortime" bson:"errortime"`
	ErrorID   string      `json:"errorid" bson:"errorid"`
	IsCleared bool        `json:"iscleared" bson:"iscleared"`
	Message   string      `json:"message" bson:"message"`
}
