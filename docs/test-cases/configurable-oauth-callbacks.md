# Test cases: configurable OAuth callback URLs

The OAuth facade keeps native-app loopback callbacks enabled and can additionally
allow stage-specific HTTPS callback URLs supplied through the SST
`OauthAllowedCallbackUrls` secret. The secret value is a JSON array of complete
URLs. Configured URLs are exact matches; host or path wildcards are not
supported.

| ID | Scenario | Expected result |
| --- | --- | --- |
| TC-OAUTH-CALLBACK-001 | Synthesize the OAuth facade | SST creates `OauthAllowedCallbackUrls` with an empty-list default and writes its value under the stage's OAuth SSM prefix |
| TC-OAUTH-CALLBACK-002 | Load a valid JSON array containing complete HTTPS callback URLs | The runtime config exposes the validated URLs |
| TC-OAUTH-CALLBACK-003 | Load malformed JSON, a non-array value, an HTTP remote URL, a URL with credentials or fragment, a URL too long for signed state, more than 20 unique URLs, or more than 1 KiB of JSON | Configuration fails closed before serving OAuth requests |
| TC-OAUTH-CALLBACK-004 | Authorize with a configured HTTPS callback and S256 PKCE | The facade sends Cognito its own callback URL and preserves the external callback in signed state |
| TC-OAUTH-CALLBACK-005 | Complete the callback for a configured HTTPS URL | The facade redirects the authorization code and original state to the exact configured URL |
| TC-OAUTH-CALLBACK-006 | Use an unconfigured URL, sibling path, or sibling host | Authorization, callback, and token exchange reject the redirect |
| TC-OAUTH-CALLBACK-007 | Exchange a signed code with the same configured HTTPS callback | The facade unwraps the Cognito code and sends Cognito its own callback URL |
| TC-OAUTH-CALLBACK-008 | Dynamically register only loopback and configured HTTPS redirects | Registration succeeds and echoes the accepted redirects |
| TC-OAUTH-CALLBACK-009 | Dynamically register any unsupported or intrinsically overlong redirect in a mixed list | The entire registration fails with `invalid_redirect_uri` |
| TC-OAUTH-CALLBACK-010 | Use an existing localhost, IPv4 loopback, or IPv6 loopback callback | Existing RFC 8252 loopback behavior remains unchanged |
| TC-OAUTH-CALLBACK-011 | Omit, empty, or change the redirect URI during authorization-code exchange, or exceed Cognito's state limit | The facade rejects the request before contacting Cognito |
