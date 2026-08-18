package deployment

import "sort"

// actionWritablePaths derives the module action's host write scope from the
// existing canonical persistent_storage declaration. It is execution policy,
// not a second action contract: individual actions cannot request extra paths.
func actionWritablePaths(req Request, mods []compiledModule, detachedSubject *compiledModule) []string {
	var subject *compiledModule
	for i := range mods {
		if mods[i].Desired.InstanceID == req.SubjectInstance {
			subject = &mods[i]
			break
		}
	}
	if subject == nil && detachedSubject != nil && detachedSubject.Desired.InstanceID == req.SubjectInstance {
		subject = detachedSubject
	}
	if subject == nil {
		return []string{}
	}
	paths := make([]string, 0, len(subject.Contract.Persistent))
	for _, storage := range subject.Contract.Persistent {
		paths = append(paths, storage.Path)
	}
	sort.Strings(paths)
	return paths
}
