// Error type shared by every module. `code` is what crosses the socket, so it
// comes from a stable vocabulary:
//
//   session.open (docs/DESIGN.md section 4): login_failed totp_failed challenge_required
//                               needs_interactive site_unreachable
//                               recipe_error timeout
//   request level:              unauthorized bad_request unknown_op not_found
//                               conflict internal
//   helper-local:               needs_owner_ack (interactive site without a
//                               logout recipe and without acceptNoLogout),
//                               missing_credential, browser_unavailable,
//                               unsupported (site type not built in),
//                               bad_site, seal_unreadable, helper_down,
//                               needs_authorize (oauth site without a refresh
//                               token, or the provider rejected it),
//                               oauth_denied, oauth_error, dependency_missing
//                               (Xvfb / x11vnc not installed)
export class HelperError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'HelperError';
    this.code = code;
  }
}

export function bad(message) {
  return new HelperError('bad_request', message);
}

export function isHelperError(err) {
  return err instanceof HelperError;
}
