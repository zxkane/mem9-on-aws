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
| TC-OAUTH-CALLBACK-003 | Load malformed JSON, a non-array value, an HTTP remote URL, a URL with credentials or fragment, more than 20 unique URLs, or more than 1 KiB of JSON | Configuration fails closed before serving OAuth requests |
| TC-OAUTH-CALLBACK-004 | Authorize with a configured HTTPS callback and S256 PKCE | The facade sends Cognito its own callback URL plus a compact signed nonce and stores the external callback and client state in a signed callback-only cookie |
| TC-OAUTH-CALLBACK-005 | Complete the callback for a configured HTTPS URL with the matching transaction cookie | The facade verifies both signatures, clears the cookie, and redirects the authorization code and original state to the exact configured URL |
| TC-OAUTH-CALLBACK-006 | Use an unconfigured URL, sibling path, or sibling host | Authorization, callback, and token exchange reject the redirect |
| TC-OAUTH-CALLBACK-007 | Exchange a signed code with the same configured HTTPS callback | The facade unwraps the Cognito code and sends Cognito its own callback URL |
| TC-OAUTH-CALLBACK-008 | Dynamically register only loopback and configured HTTPS redirects | Registration succeeds and echoes the accepted redirects |
| TC-OAUTH-CALLBACK-009 | Dynamically register any unsupported redirect or one that cannot fit in the 4 KiB transaction cookie | The entire registration fails with `invalid_redirect_uri` |
| TC-OAUTH-CALLBACK-010 | Use an existing localhost, IPv4 loopback, or IPv6 loopback callback | Existing RFC 8252 loopback behavior remains unchanged |
| TC-OAUTH-CALLBACK-011 | Omit, empty, or change the redirect URI during authorization-code exchange | The facade rejects the request before contacting Cognito |
| TC-OAUTH-CALLBACK-012 | Authorize with a long opaque hosted-client state that exceeds Cognito's direct state capacity | The compact Cognito state remains within its limit and the original client state round-trips through the signed transaction cookie |
| TC-OAUTH-CALLBACK-013 | Complete a callback with a missing, tampered, duplicate, or expired transaction cookie | The facade returns `invalid_state` and does not redirect to the client |
| TC-OAUTH-CALLBACK-014 | Start a second authorization before the first callback returns | The fixed cookie slot contains only the newer transaction; the stale callback fails without clearing it, and the newer callback still succeeds |
