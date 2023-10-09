package accesscontrol

default allow = false

# Helper rule to check if an action is a read/list action
is_read_action {
	input.action == "read"
} else {
	input.action == "list"
}

# Helper rule to check if a user has admin access at a given level
has_admin_access(level) {
	level.admin_access[input.role]
}

# Helper rule to check if a user has read access at a given level
has_read_access(level) {
	level.read_access[input.role]
}

# Allow rule for organization level
allow {
	org_level := data.organization_attributes[input.organization]
	has_admin_access(org_level)
}

allow {
	org_level := data.organization_attributes[input.organization]
	has_read_access(org_level)
	is_read_action
}

# Allow rule for environment level
allow {
	org_level := data.organization_attributes[input.organization]
	env_level := org_level.environment_attributes[input.environment]
	has_admin_access(env_level)
}

allow {
	org_level := data.organization_attributes[input.organization]
	env_level := org_level.environment_attributes[input.environment]
	has_read_access(env_level)
	is_read_action
}

# Allow rule for flag level
allow {
	org_level := data.organization_attributes[input.organization]
	env_level := org_level.environment_attributes[input.environment]
	flag_level := env_level.flag_attributes[input.flag]
	has_admin_access(flag_level)
}

allow {
	org_level := data.organization_attributes[input.organization]
	env_level := org_level.environment_attributes[input.environment]
	flag_level := env_level.flag_attributes[input.flag]
	has_read_access(flag_level)
	is_read_action
}
