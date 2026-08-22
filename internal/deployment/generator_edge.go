package deployment

import "strings"

func generateCaddy(mods []compiledModule) string {
	return renderLegacyCaddy(platformFromCompiledModules(mods))
}

func generateAuthelia(mods []compiledModule) string {
	return renderLegacyAuthelia(platformFromCompiledModules(mods))
}

func regexpQuote(v string) string {
	r := strings.NewReplacer(".", "\\.", "+", "\\+", "?", "\\?", "(", "\\(", ")", "\\)", "[", "\\[", "]", "\\]", "{", "\\{", "}", "\\}", "^", "\\^", "$", "\\$", "|", "\\|")
	return r.Replace(v)
}

func generateCaddyNetworks(mods []compiledModule) string {
	return renderPlatformNetworks(platformFromCompiledModules(mods))
}
