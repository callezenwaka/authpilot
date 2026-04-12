package httpapi

// openAPISpec is the OpenAPI 3.1 document for the Authpilot management API.
// It is served at GET /api/v1/openapi.json and referenced by the docs viewer.
//
// Kept as a Go string constant so the binary ships the spec without needing
// an embedded file or separate asset pipeline.
const openAPISpec = `{
  "openapi": "3.1.0",
  "info": {
    "title": "Authpilot Management API",
    "description": "Local-first authentication development platform. Manage users, groups, flows, sessions, and notifications.",
    "version": "1.0.0"
  },
  "servers": [
    { "url": "http://localhost:8025", "description": "Default local server" }
  ],
  "security": [],
  "components": {
    "securitySchemes": {
      "ApiKey": {
        "type": "apiKey",
        "in": "header",
        "name": "X-Authpilot-Api-Key",
        "description": "Static API key. Only required when AUTHPILOT_API_KEY is set."
      },
      "BearerToken": {
        "type": "http",
        "scheme": "bearer",
        "description": "Pass the API key as a Bearer token. Only required when AUTHPILOT_API_KEY is set."
      }
    },
    "schemas": {
      "User": {
        "type": "object",
        "required": ["id"],
        "properties": {
          "id":           { "type": "string", "example": "user_alice" },
          "email":        { "type": "string", "format": "email", "example": "alice@example.com" },
          "display_name": { "type": "string", "example": "Alice Smith" },
          "groups":       { "type": "array", "items": { "type": "string" } },
          "mfa_method":   { "type": "string", "enum": ["", "totp", "push", "sms", "magic_link"] },
          "next_flow":    { "type": "string", "enum": ["normal", "mfa_fail", "account_locked", "slow_mfa", "expired_token"] },
          "phone_number": { "type": "string", "example": "+15551234567" },
          "claims":       { "type": "object", "additionalProperties": true },
          "created_at":   { "type": "string", "format": "date-time" }
        }
      },
      "Group": {
        "type": "object",
        "required": ["id"],
        "properties": {
          "id":           { "type": "string", "example": "group_eng" },
          "name":         { "type": "string", "example": "engineering" },
          "display_name": { "type": "string", "example": "Engineering" },
          "member_ids":   { "type": "array", "items": { "type": "string" } },
          "created_at":   { "type": "string", "format": "date-time" }
        }
      },
      "Flow": {
        "type": "object",
        "properties": {
          "id":           { "type": "string" },
          "user_id":      { "type": "string" },
          "state":        { "type": "string", "enum": ["initiated", "user_picked", "mfa_pending", "mfa_approved", "mfa_denied", "complete", "error"] },
          "scenario":     { "type": "string" },
          "protocol":     { "type": "string", "enum": ["direct", "oidc", "saml"] },
          "client_id":    { "type": "string" },
          "redirect_uri": { "type": "string" },
          "scopes":       { "type": "array", "items": { "type": "string" } },
          "created_at":   { "type": "string", "format": "date-time" },
          "expires_at":   { "type": "string", "format": "date-time" }
        }
      },
      "Session": {
        "type": "object",
        "properties": {
          "id":         { "type": "string" },
          "user_id":    { "type": "string" },
          "flow_id":    { "type": "string" },
          "created_at": { "type": "string", "format": "date-time" },
          "expires_at": { "type": "string", "format": "date-time" }
        }
      },
      "Notification": {
        "type": "object",
        "properties": {
          "flow_id":         { "type": "string" },
          "type":            { "type": "string", "enum": ["totp", "push", "sms", "magic_link"] },
          "user_id":         { "type": "string" },
          "user_email":      { "type": "string" },
          "totp_code":       { "type": "string" },
          "totp_expires_at": { "type": "string", "format": "date-time" },
          "sms_code":        { "type": "string" },
          "sms_target":      { "type": "string" },
          "push_pending":    { "type": "boolean" },
          "magic_link_url":  { "type": "string" },
          "magic_link_used": { "type": "boolean" }
        }
      },
      "ErrorEnvelope": {
        "type": "object",
        "properties": {
          "error": {
            "type": "object",
            "properties": {
              "code":      { "type": "string" },
              "message":   { "type": "string" },
              "retryable": { "type": "boolean" }
            }
          },
          "request_id": { "type": "string" }
        }
      }
    },
    "responses": {
      "NotFound": {
        "description": "Resource not found",
        "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorEnvelope" } } }
      },
      "BadRequest": {
        "description": "Invalid request",
        "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorEnvelope" } } }
      },
      "Unauthorized": {
        "description": "Missing or invalid API key",
        "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorEnvelope" } } }
      },
      "TooManyRequests": {
        "description": "Rate limit exceeded",
        "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorEnvelope" } } }
      }
    },
    "parameters": {
      "IdempotencyKey": {
        "name": "Idempotency-Key",
        "in": "header",
        "required": false,
        "schema": { "type": "string" },
        "description": "Client-supplied key. Repeated requests with the same key within 5 minutes return the cached response."
      }
    }
  },
  "paths": {
    "/health": {
      "get": {
        "summary": "Health check",
        "operationId": "health",
        "tags": ["Health"],
        "security": [],
        "responses": {
          "200": { "description": "Service is healthy" }
        }
      }
    },
    "/api/v1/users": {
      "get": {
        "summary": "List users",
        "operationId": "listUsers",
        "tags": ["Users"],
        "responses": {
          "200": { "description": "Array of users", "content": { "application/json": { "schema": { "type": "array", "items": { "$ref": "#/components/schemas/User" } } } } },
          "401": { "$ref": "#/components/responses/Unauthorized" },
          "429": { "$ref": "#/components/responses/TooManyRequests" }
        }
      },
      "post": {
        "summary": "Create user",
        "operationId": "createUser",
        "tags": ["Users"],
        "parameters": [ { "$ref": "#/components/parameters/IdempotencyKey" } ],
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/User" } } } },
        "responses": {
          "201": { "description": "Created user", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/User" } } } },
          "400": { "$ref": "#/components/responses/BadRequest" },
          "401": { "$ref": "#/components/responses/Unauthorized" },
          "429": { "$ref": "#/components/responses/TooManyRequests" }
        }
      }
    },
    "/api/v1/users/{id}": {
      "parameters": [ { "name": "id", "in": "path", "required": true, "schema": { "type": "string" } } ],
      "get": {
        "summary": "Get user",
        "operationId": "getUser",
        "tags": ["Users"],
        "responses": {
          "200": { "description": "User", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/User" } } } },
          "404": { "$ref": "#/components/responses/NotFound" }
        }
      },
      "put": {
        "summary": "Update user",
        "operationId": "updateUser",
        "tags": ["Users"],
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/User" } } } },
        "responses": {
          "200": { "description": "Updated user", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/User" } } } },
          "404": { "$ref": "#/components/responses/NotFound" }
        }
      },
      "delete": {
        "summary": "Delete user",
        "operationId": "deleteUser",
        "tags": ["Users"],
        "responses": {
          "204": { "description": "Deleted" },
          "404": { "$ref": "#/components/responses/NotFound" }
        }
      }
    },
    "/api/v1/groups": {
      "get": {
        "summary": "List groups",
        "operationId": "listGroups",
        "tags": ["Groups"],
        "responses": {
          "200": { "description": "Array of groups", "content": { "application/json": { "schema": { "type": "array", "items": { "$ref": "#/components/schemas/Group" } } } } }
        }
      },
      "post": {
        "summary": "Create group",
        "operationId": "createGroup",
        "tags": ["Groups"],
        "parameters": [ { "$ref": "#/components/parameters/IdempotencyKey" } ],
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/Group" } } } },
        "responses": {
          "201": { "description": "Created group", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/Group" } } } },
          "400": { "$ref": "#/components/responses/BadRequest" }
        }
      }
    },
    "/api/v1/groups/{id}": {
      "parameters": [ { "name": "id", "in": "path", "required": true, "schema": { "type": "string" } } ],
      "get": {
        "summary": "Get group",
        "operationId": "getGroup",
        "tags": ["Groups"],
        "responses": {
          "200": { "description": "Group", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/Group" } } } },
          "404": { "$ref": "#/components/responses/NotFound" }
        }
      },
      "put": {
        "summary": "Update group",
        "operationId": "updateGroup",
        "tags": ["Groups"],
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/Group" } } } },
        "responses": {
          "200": { "description": "Updated group", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/Group" } } } },
          "404": { "$ref": "#/components/responses/NotFound" }
        }
      },
      "delete": {
        "summary": "Delete group",
        "operationId": "deleteGroup",
        "tags": ["Groups"],
        "responses": {
          "204": { "description": "Deleted" },
          "404": { "$ref": "#/components/responses/NotFound" }
        }
      }
    },
    "/api/v1/flows": {
      "get": {
        "summary": "List flows",
        "operationId": "listFlows",
        "tags": ["Flows"],
        "responses": {
          "200": { "description": "Array of flows", "content": { "application/json": { "schema": { "type": "array", "items": { "$ref": "#/components/schemas/Flow" } } } } }
        }
      },
      "post": {
        "summary": "Create flow",
        "operationId": "createFlow",
        "tags": ["Flows"],
        "parameters": [ { "$ref": "#/components/parameters/IdempotencyKey" } ],
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/Flow" } } } },
        "responses": {
          "201": { "description": "Created flow", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/Flow" } } } }
        }
      }
    },
    "/api/v1/flows/{id}": {
      "parameters": [ { "name": "id", "in": "path", "required": true, "schema": { "type": "string" } } ],
      "get": {
        "summary": "Get flow",
        "operationId": "getFlow",
        "tags": ["Flows"],
        "responses": {
          "200": { "description": "Flow", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/Flow" } } } },
          "404": { "$ref": "#/components/responses/NotFound" }
        }
      }
    },
    "/api/v1/flows/{id}/select-user": {
      "parameters": [ { "name": "id", "in": "path", "required": true, "schema": { "type": "string" } } ],
      "post": {
        "summary": "Select user for flow",
        "operationId": "selectUserFlow",
        "tags": ["Flows"],
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "properties": { "user_id": { "type": "string" } } } } } },
        "responses": {
          "200": { "description": "Updated flow" },
          "404": { "$ref": "#/components/responses/NotFound" }
        }
      }
    },
    "/api/v1/flows/{id}/verify-mfa": {
      "parameters": [ { "name": "id", "in": "path", "required": true, "schema": { "type": "string" } } ],
      "post": {
        "summary": "Verify MFA code for flow",
        "operationId": "verifyMFAFlow",
        "tags": ["Flows"],
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "properties": { "code": { "type": "string" } } } } } },
        "responses": {
          "200": { "description": "Updated flow" },
          "404": { "$ref": "#/components/responses/NotFound" }
        }
      }
    },
    "/api/v1/flows/{id}/approve": {
      "parameters": [ { "name": "id", "in": "path", "required": true, "schema": { "type": "string" } } ],
      "post": {
        "summary": "Approve push MFA for flow",
        "operationId": "approveFlow",
        "tags": ["Flows"],
        "responses": {
          "200": { "description": "Updated flow" },
          "404": { "$ref": "#/components/responses/NotFound" }
        }
      }
    },
    "/api/v1/flows/{id}/deny": {
      "parameters": [ { "name": "id", "in": "path", "required": true, "schema": { "type": "string" } } ],
      "post": {
        "summary": "Deny push MFA for flow",
        "operationId": "denyFlow",
        "tags": ["Flows"],
        "responses": {
          "200": { "description": "Updated flow" },
          "404": { "$ref": "#/components/responses/NotFound" }
        }
      }
    },
    "/api/v1/sessions": {
      "get": {
        "summary": "List sessions",
        "operationId": "listSessions",
        "tags": ["Sessions"],
        "responses": {
          "200": { "description": "Array of sessions", "content": { "application/json": { "schema": { "type": "array", "items": { "$ref": "#/components/schemas/Session" } } } } }
        }
      }
    },
    "/api/v1/notifications": {
      "get": {
        "summary": "Get notification for a flow",
        "operationId": "getNotification",
        "tags": ["Notifications"],
        "parameters": [ { "name": "flow_id", "in": "query", "required": true, "schema": { "type": "string" } } ],
        "responses": {
          "200": { "description": "Notification payload", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/Notification" } } } },
          "404": { "$ref": "#/components/responses/NotFound" }
        }
      }
    },
    "/api/v1/notifications/all": {
      "get": {
        "summary": "List all pending notifications",
        "operationId": "listNotifications",
        "tags": ["Notifications"],
        "responses": {
          "200": { "description": "Array of notification payloads", "content": { "application/json": { "schema": { "type": "array", "items": { "$ref": "#/components/schemas/Notification" } } } } }
        }
      }
    },
    "/api/v1/export": {
      "get": {
        "summary": "Export users and groups",
        "operationId": "exportUsers",
        "tags": ["Export"],
        "parameters": [
          {
            "name": "format",
            "in": "query",
            "required": true,
            "schema": { "type": "string", "enum": ["scim", "okta", "azure", "google"] },
            "description": "Export format"
          }
        ],
        "responses": {
          "200": { "description": "Export file (JSON or CSV depending on format)" },
          "400": { "$ref": "#/components/responses/BadRequest" }
        }
      }
    },
    "/scim/v2/ServiceProviderConfig": {
      "get": {
        "summary": "SCIM server capabilities",
        "operationId": "scimServiceProviderConfig",
        "tags": ["SCIM"],
        "security": [{"ApiKey":[]},{"BearerToken":[]}],
        "responses": {
          "200": { "description": "ServiceProviderConfig document" }
        }
      }
    },
    "/scim/v2/Schemas": {
      "get": {
        "summary": "List SCIM schemas",
        "operationId": "scimSchemas",
        "tags": ["SCIM"],
        "security": [{"ApiKey":[]},{"BearerToken":[]}],
        "responses": {
          "200": { "description": "SCIM ListResponse of schemas" }
        }
      }
    },
    "/scim/v2/Schemas/{id}": {
      "parameters": [ { "name": "id", "in": "path", "required": true, "schema": { "type": "string" }, "description": "Schema URN" } ],
      "get": {
        "summary": "Get SCIM schema by URN",
        "operationId": "scimSchemaByID",
        "tags": ["SCIM"],
        "security": [{"ApiKey":[]},{"BearerToken":[]}],
        "responses": {
          "200": { "description": "Schema definition" },
          "404": { "description": "Schema not found" }
        }
      }
    },
    "/scim/v2/Users": {
      "get": {
        "summary": "List SCIM users",
        "operationId": "scimListUsers",
        "tags": ["SCIM"],
        "security": [{"ApiKey":[]},{"BearerToken":[]}],
        "parameters": [
          { "name": "filter", "in": "query", "required": false, "schema": { "type": "string" }, "description": "SCIM filter expression, e.g. userName eq \"alice@example.com\"" }
        ],
        "responses": {
          "200": { "description": "SCIM ListResponse of users" }
        }
      },
      "post": {
        "summary": "Create SCIM user",
        "operationId": "scimCreateUser",
        "tags": ["SCIM"],
        "security": [{"ApiKey":[]},{"BearerToken":[]}],
        "requestBody": { "required": true, "content": { "application/scim+json": { "schema": { "type": "object", "required": ["userName"], "properties": { "userName": { "type": "string" }, "displayName": { "type": "string" }, "emails": { "type": "array", "items": { "type": "object" } }, "phoneNumbers": { "type": "array", "items": { "type": "object" } } } } } } },
        "responses": {
          "201": { "description": "Created SCIM user" },
          "400": { "description": "userName is required" }
        }
      }
    },
    "/scim/v2/Users/{id}": {
      "parameters": [ { "name": "id", "in": "path", "required": true, "schema": { "type": "string" } } ],
      "get": {
        "summary": "Get SCIM user",
        "operationId": "scimGetUser",
        "tags": ["SCIM"],
        "security": [{"ApiKey":[]},{"BearerToken":[]}],
        "responses": {
          "200": { "description": "SCIM user" },
          "404": { "description": "User not found" }
        }
      },
      "put": {
        "summary": "Replace SCIM user",
        "operationId": "scimReplaceUser",
        "tags": ["SCIM"],
        "security": [{"ApiKey":[]},{"BearerToken":[]}],
        "requestBody": { "required": true, "content": { "application/scim+json": { "schema": { "type": "object" } } } },
        "responses": {
          "200": { "description": "Updated SCIM user" },
          "404": { "description": "User not found" }
        }
      },
      "patch": {
        "summary": "Patch SCIM user",
        "operationId": "scimPatchUser",
        "tags": ["SCIM"],
        "security": [{"ApiKey":[]},{"BearerToken":[]}],
        "requestBody": { "required": true, "content": { "application/scim+json": { "schema": { "type": "object", "properties": { "schemas": { "type": "array", "items": { "type": "string" } }, "Operations": { "type": "array", "items": { "type": "object" } } } } } } },
        "responses": {
          "200": { "description": "Patched SCIM user" },
          "404": { "description": "User not found" }
        }
      },
      "delete": {
        "summary": "Delete SCIM user",
        "operationId": "scimDeleteUser",
        "tags": ["SCIM"],
        "security": [{"ApiKey":[]},{"BearerToken":[]}],
        "responses": {
          "204": { "description": "Deleted" },
          "404": { "description": "User not found" }
        }
      }
    },
    "/scim/v2/Groups": {
      "get": {
        "summary": "List SCIM groups",
        "operationId": "scimListGroups",
        "tags": ["SCIM"],
        "security": [{"ApiKey":[]},{"BearerToken":[]}],
        "responses": {
          "200": { "description": "SCIM ListResponse of groups" }
        }
      },
      "post": {
        "summary": "Create SCIM group",
        "operationId": "scimCreateGroup",
        "tags": ["SCIM"],
        "security": [{"ApiKey":[]},{"BearerToken":[]}],
        "requestBody": { "required": true, "content": { "application/scim+json": { "schema": { "type": "object", "required": ["displayName"], "properties": { "displayName": { "type": "string" }, "members": { "type": "array", "items": { "type": "object" } } } } } } },
        "responses": {
          "201": { "description": "Created SCIM group" },
          "400": { "description": "displayName is required" }
        }
      }
    },
    "/scim/v2/Groups/{id}": {
      "parameters": [ { "name": "id", "in": "path", "required": true, "schema": { "type": "string" } } ],
      "get": {
        "summary": "Get SCIM group",
        "operationId": "scimGetGroup",
        "tags": ["SCIM"],
        "security": [{"ApiKey":[]},{"BearerToken":[]}],
        "responses": {
          "200": { "description": "SCIM group with member refs" },
          "404": { "description": "Group not found" }
        }
      },
      "put": {
        "summary": "Replace SCIM group",
        "operationId": "scimReplaceGroup",
        "tags": ["SCIM"],
        "security": [{"ApiKey":[]},{"BearerToken":[]}],
        "requestBody": { "required": true, "content": { "application/scim+json": { "schema": { "type": "object" } } } },
        "responses": {
          "200": { "description": "Updated SCIM group" },
          "404": { "description": "Group not found" }
        }
      },
      "patch": {
        "summary": "Patch SCIM group",
        "operationId": "scimPatchGroup",
        "tags": ["SCIM"],
        "security": [{"ApiKey":[]},{"BearerToken":[]}],
        "requestBody": { "required": true, "content": { "application/scim+json": { "schema": { "type": "object" } } } },
        "responses": {
          "200": { "description": "Patched SCIM group" },
          "404": { "description": "Group not found" }
        }
      },
      "delete": {
        "summary": "Delete SCIM group",
        "operationId": "scimDeleteGroup",
        "tags": ["SCIM"],
        "security": [{"ApiKey":[]},{"BearerToken":[]}],
        "responses": {
          "204": { "description": "Deleted" },
          "404": { "description": "Group not found" }
        }
      }
    },
    "/api/v1/openapi.json": {
      "get": {
        "summary": "OpenAPI specification",
        "operationId": "openAPISpec",
        "tags": ["Meta"],
        "security": [],
        "responses": {
          "200": { "description": "OpenAPI 3.1 JSON document" }
        }
      }
    },
    "/api/v1/docs": {
      "get": {
        "summary": "API documentation viewer",
        "operationId": "apiDocs",
        "tags": ["Meta"],
        "security": [],
        "responses": {
          "200": { "description": "HTML documentation page" }
        }
      }
    }
  }
}`

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
