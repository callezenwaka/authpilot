package httpapi

import "encoding/json"

// buildOpenAPISpec constructs the OpenAPI 3.1 document for the Authpilot
// management and SCIM APIs as a Go value. It is called once at handler
// registration time and serialised to JSON. Adding or changing a route
// requires updating this function — there is no separate file to drift.
func buildOpenAPISpec() []byte {
	spec := map[string]any{
		"openapi": "3.1.0",
		"info": map[string]any{
			"title":       "Authpilot Management API",
			"description": "Local-first authentication development platform. Manage users, groups, flows, sessions, notifications, and SCIM provisioning.",
			"version":     "1.0.0",
		},
		"servers": []any{
			map[string]any{"url": "http://localhost:8025", "description": "Default local server"},
		},
		"security": []any{},
		"tags": []any{
			map[string]any{"name": "Health"},
			map[string]any{"name": "Users"},
			map[string]any{"name": "Groups"},
			map[string]any{"name": "Flows"},
			map[string]any{"name": "Sessions"},
			map[string]any{"name": "Notifications"},
			map[string]any{"name": "Export"},
			map[string]any{"name": "Tokens"},
			map[string]any{"name": "SCIM"},
			map[string]any{"name": "Meta"},
		},
		"components": components(),
		"paths":      paths(),
	}
	b, _ := json.MarshalIndent(spec, "", "  ")
	return b
}

// ---------------------------------------------------------------------------
// Components
// ---------------------------------------------------------------------------

func components() map[string]any {
	return map[string]any{
		"securitySchemes": map[string]any{
			"ApiKey": map[string]any{
				"type":        "apiKey",
				"in":          "header",
				"name":        "X-Authpilot-Api-Key",
				"description": "Static API key. Only required when AUTHPILOT_API_KEY is set.",
			},
			"BearerToken": map[string]any{
				"type":        "http",
				"scheme":      "bearer",
				"description": "Pass the API key as a Bearer token. Only required when AUTHPILOT_API_KEY is set.",
			},
		},
		"schemas": map[string]any{
			"User": map[string]any{
				"type":     "object",
				"required": []string{"id"},
				"properties": map[string]any{
					"id":           map[string]any{"type": "string", "example": "user_alice"},
					"email":        map[string]any{"type": "string", "format": "email", "example": "alice@example.com"},
					"display_name": map[string]any{"type": "string", "example": "Alice Smith"},
					"groups":       map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
					"mfa_method":   map[string]any{"type": "string", "enum": []string{"", "totp", "push", "sms", "magic_link"}},
					"next_flow":    map[string]any{"type": "string", "enum": []string{"normal", "mfa_fail", "account_locked", "slow_mfa", "expired_token"}},
					"phone_number": map[string]any{"type": "string", "example": "+15551234567"},
					"claims":       map[string]any{"type": "object", "additionalProperties": true},
					"created_at":   map[string]any{"type": "string", "format": "date-time"},
				},
			},
			"Group": map[string]any{
				"type":     "object",
				"required": []string{"id"},
				"properties": map[string]any{
					"id":           map[string]any{"type": "string", "example": "group_eng"},
					"name":         map[string]any{"type": "string", "example": "engineering"},
					"display_name": map[string]any{"type": "string", "example": "Engineering"},
					"member_ids":   map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
					"created_at":   map[string]any{"type": "string", "format": "date-time"},
				},
			},
			"Flow": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"id":           map[string]any{"type": "string"},
					"user_id":      map[string]any{"type": "string"},
					"state":        map[string]any{"type": "string", "enum": []string{"initiated", "user_picked", "mfa_pending", "mfa_approved", "mfa_denied", "complete", "error"}},
					"scenario":     map[string]any{"type": "string"},
					"protocol":     map[string]any{"type": "string", "enum": []string{"direct", "oidc", "saml", "wsfed"}},
					"client_id":    map[string]any{"type": "string"},
					"redirect_uri": map[string]any{"type": "string"},
					"scopes":       map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
					"created_at":   map[string]any{"type": "string", "format": "date-time"},
					"expires_at":   map[string]any{"type": "string", "format": "date-time"},
				},
			},
			"Session": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"id":         map[string]any{"type": "string"},
					"user_id":    map[string]any{"type": "string"},
					"flow_id":    map[string]any{"type": "string"},
					"created_at": map[string]any{"type": "string", "format": "date-time"},
					"expires_at": map[string]any{"type": "string", "format": "date-time"},
				},
			},
			"Notification": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"flow_id":         map[string]any{"type": "string"},
					"type":            map[string]any{"type": "string", "enum": []string{"totp", "push", "sms", "magic_link"}},
					"user_id":         map[string]any{"type": "string"},
					"user_email":      map[string]any{"type": "string"},
					"totp_code":       map[string]any{"type": "string"},
					"totp_expires_at": map[string]any{"type": "string", "format": "date-time"},
					"sms_code":        map[string]any{"type": "string"},
					"sms_target":      map[string]any{"type": "string"},
					"push_pending":    map[string]any{"type": "boolean"},
					"magic_link_url":  map[string]any{"type": "string"},
					"magic_link_used": map[string]any{"type": "boolean"},
				},
			},
			"ErrorEnvelope": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"error": map[string]any{
						"type": "object",
						"properties": map[string]any{
							"code":      map[string]any{"type": "string"},
							"message":   map[string]any{"type": "string"},
							"retryable": map[string]any{"type": "boolean"},
							"docs_url":  map[string]any{"type": "string", "description": "Link to documentation for this error code."},
							"details":   map[string]any{"type": "object", "additionalProperties": true, "description": "Structured context about the error (e.g. which field failed, which resource was not found)."},
						},
					},
					"request_id": map[string]any{"type": "string"},
				},
			},
			"SCIMUser": map[string]any{
				"type":     "object",
				"required": []string{"userName"},
				"properties": map[string]any{
					"schemas":     map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
					"id":          map[string]any{"type": "string"},
					"userName":    map[string]any{"type": "string", "example": "alice@example.com"},
					"displayName": map[string]any{"type": "string"},
					"active":      map[string]any{"type": "boolean"},
					"emails":      map[string]any{"type": "array", "items": map[string]any{"type": "object"}},
					"phoneNumbers": map[string]any{"type": "array", "items": map[string]any{"type": "object"}},
					"groups":      map[string]any{"type": "array", "items": map[string]any{"type": "object"}, "readOnly": true},
					"meta":        map[string]any{"type": "object"},
				},
			},
			"SCIMGroup": map[string]any{
				"type":     "object",
				"required": []string{"displayName"},
				"properties": map[string]any{
					"schemas":     map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
					"id":          map[string]any{"type": "string"},
					"displayName": map[string]any{"type": "string", "example": "Engineering"},
					"members":     map[string]any{"type": "array", "items": map[string]any{"type": "object"}},
					"meta":        map[string]any{"type": "object"},
				},
			},
			"SCIMPatchOp": map[string]any{
				"type":     "object",
				"required": []string{"schemas", "Operations"},
				"properties": map[string]any{
					"schemas":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
					"Operations": map[string]any{"type": "array", "items": map[string]any{"type": "object", "properties": map[string]any{"op": map[string]any{"type": "string", "enum": []string{"add", "replace", "remove"}}, "path": map[string]any{"type": "string"}, "value": map[string]any{}}}},
				},
			},
			"MintRequest": map[string]any{
					"type":     "object",
					"required": []string{"user_id"},
					"properties": map[string]any{
						"user_id":    map[string]any{"type": "string", "example": "usr_001", "description": "ID of the user to mint tokens for"},
						"client_id":  map[string]any{"type": "string", "example": "test-client"},
						"scopes":     map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "example": []string{"openid", "email", "profile"}},
						"expires_in": map[string]any{"type": "integer", "example": 3600, "description": "Token lifetime in seconds; defaults to 3600"},
					},
				},
				"MintedTokens": map[string]any{
					"type":     "object",
					"properties": map[string]any{
						"access_token": map[string]any{"type": "string", "description": "Signed JWT access token"},
						"id_token":     map[string]any{"type": "string", "description": "Signed JWT ID token with user claims"},
						"expires_in":   map[string]any{"type": "integer", "description": "Lifetime in seconds"},
					},
				},
				"SCIMListResponse": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"schemas":      map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
					"totalResults": map[string]any{"type": "integer"},
					"startIndex":   map[string]any{"type": "integer"},
					"itemsPerPage": map[string]any{"type": "integer"},
					"Resources":    map[string]any{"type": "array", "items": map[string]any{}},
				},
			},
		},
		"responses": map[string]any{
			"NotFound": map[string]any{
				"description": "Resource not found",
				"content":     jsonContent(ref("ErrorEnvelope")),
			},
			"BadRequest": map[string]any{
				"description": "Invalid request",
				"content":     jsonContent(ref("ErrorEnvelope")),
			},
			"Unauthorized": map[string]any{
				"description": "Missing or invalid API key",
				"content":     jsonContent(ref("ErrorEnvelope")),
			},
			"TooManyRequests": map[string]any{
				"description": "Rate limit exceeded",
				"content":     jsonContent(ref("ErrorEnvelope")),
			},
			"SCIMError": map[string]any{
				"description": "SCIM error",
				"content":     scimContent(map[string]any{"type": "object", "properties": map[string]any{"schemas": map[string]any{"type": "array"}, "status": map[string]any{"type": "string"}, "detail": map[string]any{"type": "string"}}}),
			},
		},
		"parameters": map[string]any{
			"IdempotencyKey": map[string]any{
				"name":        "Idempotency-Key",
				"in":          "header",
				"required":    false,
				"schema":      map[string]any{"type": "string"},
				"description": "Client-supplied key. Repeated requests with the same key within 5 minutes return the cached response.",
			},
			"ResourceID": map[string]any{
				"name":     "id",
				"in":       "path",
				"required": true,
				"schema":   map[string]any{"type": "string"},
			},
		},
	}
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

func paths() map[string]any {
	idParam := pathParam("id", "string")
	apiSecurity := []any{map[string]any{"ApiKey": []any{}}, map[string]any{"BearerToken": []any{}}}
	scimSecurity := apiSecurity

	return map[string]any{
		// Health
		"/health": map[string]any{
			"get": op("health", "Health check", "Health", nil, nil, nil,
				resp200("Service is healthy", nil), nil),
		},

		// Users
		"/api/v1/users": map[string]any{
			"get": op("listUsers", "List users", "Users", apiSecurity, nil, nil,
				resp200("Array of users", arrayOf(ref("User"))),
				apiErrs()),
			"post": op("createUser", "Create user", "Users", apiSecurity,
				[]any{paramRef("IdempotencyKey")},
				reqBody(ref("User")),
				resp("201", "Created user", jsonContent(ref("User"))),
				apiErrs()),
		},
		"/api/v1/users/{id}": map[string]any{
			"parameters": []any{idParam},
			"get": op("getUser", "Get user", "Users", apiSecurity, nil, nil,
				resp200("User", jsonContent(ref("User"))),
				map[string]any{"404": respRef("NotFound")}),
			"put": op("updateUser", "Update user", "Users", apiSecurity, nil,
				reqBody(ref("User")),
				resp200("Updated user", jsonContent(ref("User"))),
				map[string]any{"404": respRef("NotFound")}),
			"delete": op("deleteUser", "Delete user", "Users", apiSecurity, nil, nil,
				resp("204", "Deleted", nil),
				map[string]any{"404": respRef("NotFound")}),
		},

		// Groups
		"/api/v1/groups": map[string]any{
			"get": op("listGroups", "List groups", "Groups", apiSecurity, nil, nil,
				resp200("Array of groups", arrayOf(ref("Group"))),
				apiErrs()),
			"post": op("createGroup", "Create group", "Groups", apiSecurity,
				[]any{paramRef("IdempotencyKey")},
				reqBody(ref("Group")),
				resp("201", "Created group", jsonContent(ref("Group"))),
				apiErrs()),
		},
		"/api/v1/groups/{id}": map[string]any{
			"parameters": []any{idParam},
			"get": op("getGroup", "Get group", "Groups", apiSecurity, nil, nil,
				resp200("Group", jsonContent(ref("Group"))),
				map[string]any{"404": respRef("NotFound")}),
			"put": op("updateGroup", "Update group", "Groups", apiSecurity, nil,
				reqBody(ref("Group")),
				resp200("Updated group", jsonContent(ref("Group"))),
				map[string]any{"404": respRef("NotFound")}),
			"delete": op("deleteGroup", "Delete group", "Groups", apiSecurity, nil, nil,
				resp("204", "Deleted", nil),
				map[string]any{"404": respRef("NotFound")}),
		},

		// Flows
		"/api/v1/flows": map[string]any{
			"get": op("listFlows", "List flows", "Flows", apiSecurity, nil, nil,
				resp200("Array of flows", arrayOf(ref("Flow"))),
				apiErrs()),
			"post": op("createFlow", "Create flow", "Flows", apiSecurity,
				[]any{paramRef("IdempotencyKey")},
				reqBody(ref("Flow")),
				resp("201", "Created flow", jsonContent(ref("Flow"))),
				apiErrs()),
		},
		"/api/v1/flows/{id}": map[string]any{
			"parameters": []any{idParam},
			"get": op("getFlow", "Get flow", "Flows", apiSecurity, nil, nil,
				resp200("Flow", jsonContent(ref("Flow"))),
				map[string]any{"404": respRef("NotFound")}),
		},
		"/api/v1/flows/{id}/select-user": map[string]any{
			"parameters": []any{idParam},
			"post": op("selectUserFlow", "Select user for flow", "Flows", apiSecurity, nil,
				reqBodyInline(map[string]any{"type": "object", "properties": map[string]any{"user_id": map[string]any{"type": "string"}}}),
				resp200("Updated flow", nil),
				map[string]any{"404": respRef("NotFound")}),
		},
		"/api/v1/flows/{id}/verify-mfa": map[string]any{
			"parameters": []any{idParam},
			"post": op("verifyMFAFlow", "Verify MFA code for flow", "Flows", apiSecurity, nil,
				reqBodyInline(map[string]any{"type": "object", "properties": map[string]any{"code": map[string]any{"type": "string"}}}),
				resp200("Updated flow", nil),
				map[string]any{"404": respRef("NotFound")}),
		},
		"/api/v1/flows/{id}/approve": map[string]any{
			"parameters": []any{idParam},
			"post": op("approveFlow", "Approve push MFA for flow", "Flows", apiSecurity, nil, nil,
				resp200("Updated flow", nil),
				map[string]any{"404": respRef("NotFound")}),
		},
		"/api/v1/flows/{id}/deny": map[string]any{
			"parameters": []any{idParam},
			"post": op("denyFlow", "Deny push MFA for flow", "Flows", apiSecurity, nil, nil,
				resp200("Updated flow", nil),
				map[string]any{"404": respRef("NotFound")}),
		},

		// Sessions
		"/api/v1/sessions": map[string]any{
			"get": op("listSessions", "List sessions", "Sessions", apiSecurity, nil, nil,
				resp200("Array of sessions", arrayOf(ref("Session"))),
				apiErrs()),
		},

		// Notifications
		"/api/v1/notifications": map[string]any{
			"get": op("getNotification", "Get notification for a flow", "Notifications", apiSecurity,
				[]any{queryParam("flow_id", "string", true, "Flow ID")},
				nil,
				resp200("Notification payload", jsonContent(ref("Notification"))),
				map[string]any{"404": respRef("NotFound")}),
		},
		"/api/v1/notifications/all": map[string]any{
			"get": op("listNotifications", "List all pending notifications", "Notifications", apiSecurity, nil, nil,
				resp200("Array of notification payloads", arrayOf(ref("Notification"))),
				apiErrs()),
		},

		// Tokens
		"/api/v1/tokens/mint": map[string]any{
			"post": op("mintToken", "Mint tokens for a user (CI/CD shortcut)", "Tokens", apiSecurity,
				[]any{paramRef("IdempotencyKey")},
				reqBody(ref("MintRequest")),
				resp200("Minted access and ID tokens", jsonContent(ref("MintedTokens"))),
				map[string]any{
					"400": respRef("BadRequest"),
					"404": respRef("NotFound"),
					"401": respRef("Unauthorized"),
					"429": respRef("TooManyRequests"),
				}),
		},

		// Export
		"/api/v1/export": map[string]any{
			"get": op("exportUsers", "Export users and groups", "Export", apiSecurity,
				[]any{queryParam("format", "string", true, "Export format: scim, okta, azure, google")},
				nil,
				resp200("Export file (JSON or CSV depending on format)", nil),
				map[string]any{"400": respRef("BadRequest")}),
		},

		// SCIM
		"/scim/v2/ServiceProviderConfig": map[string]any{
			"get": op("scimServiceProviderConfig", "SCIM server capabilities", "SCIM", scimSecurity, nil, nil,
				resp200("ServiceProviderConfig", scimContent(map[string]any{"type": "object"})),
				nil),
		},
		"/scim/v2/Schemas": map[string]any{
			"get": op("scimSchemas", "List SCIM schemas", "SCIM", scimSecurity, nil, nil,
				resp200("ListResponse of schemas", scimContent(ref("SCIMListResponse"))),
				nil),
		},
		"/scim/v2/Schemas/{id}": map[string]any{
			"parameters": []any{pathParam("id", "string")},
			"get": op("scimSchemaByID", "Get SCIM schema by URN", "SCIM", scimSecurity, nil, nil,
				resp200("Schema definition", scimContent(map[string]any{"type": "object"})),
				map[string]any{"404": respRef("SCIMError")}),
		},
		"/scim/v2/Users": map[string]any{
			"get": op("scimListUsers", "List SCIM users", "SCIM", scimSecurity,
				[]any{queryParam("filter", "string", false, `SCIM filter, e.g. userName eq "alice@example.com"`)},
				nil,
				resp200("ListResponse of users", scimContent(ref("SCIMListResponse"))),
				map[string]any{"401": respRef("Unauthorized")}),
			"post": op("scimCreateUser", "Create SCIM user", "SCIM", scimSecurity, nil,
				scimReqBody(ref("SCIMUser")),
				resp("201", "Created SCIM user", scimContent(ref("SCIMUser"))),
				map[string]any{"400": respRef("SCIMError")}),
		},
		"/scim/v2/Users/{id}": map[string]any{
			"parameters": []any{idParam},
			"get": op("scimGetUser", "Get SCIM user", "SCIM", scimSecurity, nil, nil,
				resp200("SCIM user", scimContent(ref("SCIMUser"))),
				map[string]any{"404": respRef("SCIMError")}),
			"put": op("scimReplaceUser", "Replace SCIM user", "SCIM", scimSecurity, nil,
				scimReqBody(ref("SCIMUser")),
				resp200("Updated SCIM user", scimContent(ref("SCIMUser"))),
				map[string]any{"404": respRef("SCIMError")}),
			"patch": op("scimPatchUser", "Patch SCIM user", "SCIM", scimSecurity, nil,
				scimReqBody(ref("SCIMPatchOp")),
				resp200("Patched SCIM user", scimContent(ref("SCIMUser"))),
				map[string]any{"404": respRef("SCIMError")}),
			"delete": op("scimDeleteUser", "Delete SCIM user", "SCIM", scimSecurity, nil, nil,
				resp("204", "Deleted", nil),
				map[string]any{"404": respRef("SCIMError")}),
		},
		"/scim/v2/Groups": map[string]any{
			"get": op("scimListGroups", "List SCIM groups", "SCIM", scimSecurity, nil, nil,
				resp200("ListResponse of groups", scimContent(ref("SCIMListResponse"))),
				map[string]any{"401": respRef("Unauthorized")}),
			"post": op("scimCreateGroup", "Create SCIM group", "SCIM", scimSecurity, nil,
				scimReqBody(ref("SCIMGroup")),
				resp("201", "Created SCIM group", scimContent(ref("SCIMGroup"))),
				map[string]any{"400": respRef("SCIMError")}),
		},
		"/scim/v2/Groups/{id}": map[string]any{
			"parameters": []any{idParam},
			"get": op("scimGetGroup", "Get SCIM group", "SCIM", scimSecurity, nil, nil,
				resp200("SCIM group with member refs", scimContent(ref("SCIMGroup"))),
				map[string]any{"404": respRef("SCIMError")}),
			"put": op("scimReplaceGroup", "Replace SCIM group", "SCIM", scimSecurity, nil,
				scimReqBody(ref("SCIMGroup")),
				resp200("Updated SCIM group", scimContent(ref("SCIMGroup"))),
				map[string]any{"404": respRef("SCIMError")}),
			"patch": op("scimPatchGroup", "Patch SCIM group", "SCIM", scimSecurity, nil,
				scimReqBody(ref("SCIMPatchOp")),
				resp200("Patched SCIM group", scimContent(ref("SCIMGroup"))),
				map[string]any{"404": respRef("SCIMError")}),
			"delete": op("scimDeleteGroup", "Delete SCIM group", "SCIM", scimSecurity, nil, nil,
				resp("204", "Deleted", nil),
				map[string]any{"404": respRef("SCIMError")}),
		},

		// Meta
		"/api/v1/openapi.json": map[string]any{
			"get": op("openAPISpec", "OpenAPI specification", "Meta", []any{}, nil, nil,
				resp200("OpenAPI 3.1 JSON document", nil), nil),
		},
		"/api/v1/docs": map[string]any{
			"get": op("apiDocs", "API documentation viewer (Swagger UI)", "Meta", []any{}, nil, nil,
				resp200("HTML documentation page", nil), nil),
		},
	}
}

// ---------------------------------------------------------------------------
// Builder helpers — keep paths() readable without repetition
// ---------------------------------------------------------------------------

// op builds a single operation object.
func op(operationID, summary, tag string, security []any, params []any, body map[string]any, primary map[string]any, extra map[string]any) map[string]any {
	o := map[string]any{
		"summary":     summary,
		"operationId": operationID,
		"tags":        []string{tag},
	}
	if security != nil {
		o["security"] = security
	}
	if len(params) > 0 {
		o["parameters"] = params
	}
	if body != nil {
		o["requestBody"] = body
	}
	responses := map[string]any{}
	for k, v := range primary {
		responses[k] = v
	}
	for k, v := range extra {
		responses[k] = v
	}
	o["responses"] = responses
	return o
}

func ref(name string) map[string]any {
	return map[string]any{"$ref": "#/components/schemas/" + name}
}

func respRef(name string) map[string]any {
	return map[string]any{"$ref": "#/components/responses/" + name}
}

func paramRef(name string) map[string]any {
	return map[string]any{"$ref": "#/components/parameters/" + name}
}

func jsonContent(schema map[string]any) map[string]any {
	return map[string]any{"application/json": map[string]any{"schema": schema}}
}

func scimContent(schema map[string]any) map[string]any {
	return map[string]any{"application/scim+json": map[string]any{"schema": schema}}
}

func arrayOf(schema map[string]any) map[string]any {
	return jsonContent(map[string]any{"type": "array", "items": schema})
}

func resp(code, description string, content map[string]any) map[string]any {
	r := map[string]any{"description": description}
	if content != nil {
		r["content"] = content
	}
	return map[string]any{code: r}
}

func resp200(description string, content map[string]any) map[string]any {
	return resp("200", description, content)
}

func reqBody(schema map[string]any) map[string]any {
	return map[string]any{"required": true, "content": jsonContent(schema)}
}

func reqBodyInline(schema map[string]any) map[string]any {
	return reqBody(schema)
}

func scimReqBody(schema map[string]any) map[string]any {
	return map[string]any{"required": true, "content": scimContent(schema)}
}

func pathParam(name, typ string) map[string]any {
	return map[string]any{"name": name, "in": "path", "required": true, "schema": map[string]any{"type": typ}}
}

func queryParam(name, typ string, required bool, description string) map[string]any {
	return map[string]any{"name": name, "in": "query", "required": required, "schema": map[string]any{"type": typ}, "description": description}
}

// apiErrs returns the common 401 + 429 responses for management API endpoints.
func apiErrs() map[string]any {
	return map[string]any{
		"401": respRef("Unauthorized"),
		"429": respRef("TooManyRequests"),
	}
}

// ---------------------------------------------------------------------------
// Spec endpoint handler — built once at package init, served on every request
// ---------------------------------------------------------------------------

var cachedSpec = buildOpenAPISpec()

// openAPIDocsHTML is a minimal HTML page that loads the Swagger UI CDN and points it
// at the local /api/v1/openapi.json spec.
const openAPIDocsHTML = `<!DOCTYPE html>
<html>
<head>
  <title>Authpilot API Docs</title>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css">
</head>
<body>
<div id="swagger-ui"></div>
<script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
<script>
SwaggerUIBundle({
  url: "/api/v1/openapi.json",
  dom_id: "#swagger-ui",
  presets: [SwaggerUIBundle.presets.apis, SwaggerUIBundle.SwaggerUIStandalonePreset],
  layout: "BaseLayout",
  deepLinking: true,
});
</script>
</body>
</html>`
