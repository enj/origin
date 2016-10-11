package api

import (
	"fmt"

	"github.com/openshift/origin/pkg/api/constants"
)

const (
	displayNameOldAnnotation = "displayName"
)

// DisplayNameAndNameForProject returns a formatted string containing the name
// of the project and includes the display name if it differs.
func DisplayNameAndNameForProject(project *Project) string {
	displayName := project.Annotations[constants.OpenShiftDisplayName]
	if len(displayName) == 0 {
		displayName = project.Annotations[displayNameOldAnnotation]
	}
	if len(displayName) > 0 && displayName != project.Name {
		return fmt.Sprintf("%s (%s)", displayName, project.Name)
	}
	return project.Name
}
