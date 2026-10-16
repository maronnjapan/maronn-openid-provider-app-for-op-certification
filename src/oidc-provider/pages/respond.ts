/**
 * Response helpers shared by the screen routes (pages/).
 *
 * The logic layer (routes/) describes what to do — which screen to show, where
 * to send the browser, which cookies to set — and never builds a Response. The
 * helpers below are how a page turns that description into HTTP.
 */

/**
 * Attach Set-Cookie headers to a Response a view already produced.
 *
 * renderView() builds its own Response, so headers staged on the framework
 * context never reach it; rebuilding the Response is the framework-neutral way
 * to add cookies without making views cookie-aware.
 */
export function withCookies(response: Response, cookies: readonly string[]): Response {
  if (cookies.length === 0) return response;
  const headers = new Headers(response.headers);
  for (const cookie of cookies) {
    headers.append('Set-Cookie', cookie);
  }
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

/**
 * Send the browser to location (302 unless told otherwise) with the given
 * cookies attached.
 */
export function redirectWithCookies(
  location: string,
  cookies: readonly string[] = [],
  status = 302,
): Response {
  const headers = new Headers({ Location: location });
  for (const cookie of cookies) {
    headers.append('Set-Cookie', cookie);
  }
  return new Response(null, { status, headers });
}
