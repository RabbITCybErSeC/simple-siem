// Package detections is the single list of compiled-in detections.
package detections

import (
	"github.com/RabbITCybErSeC/simple-siem/detections/bruteforcelogin"
	"github.com/RabbITCybErSeC/simple-siem/internal/detection"
)

// All is the single list of compiled-in detections. Adding a detection is one
// line here; there is no init() registration.
var All = []detection.Registration{
	bruteforcelogin.Registration,
}
