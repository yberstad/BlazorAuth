using Microsoft.AspNetCore.Http;
using System;

namespace BlazorAuth
{

    public class StrictSameSiteOpenIdConnectOptions
    {
        /// <summary>
        /// Gets or sets the time at which the authentication ticket expires. Only applicable if the UseCustomSignIn is set to true.
        /// </summary>
        public TimeSpan AuthenticationTicketExpiration { get; set; }

        /// <summary>
        /// The policy that will be used to determine <seealso cref="P:Microsoft.AspNetCore.Http.CookieOptions.Secure" />.
        /// This is determined from the <see cref="T:Microsoft.AspNetCore.Http.HttpContext" /> passed to <see cref="M:Microsoft.AspNetCore.Http.CookieBuilder.Build(Microsoft.AspNetCore.Http.HttpContext,System.DateTimeOffset)" />.
        /// </summary>
        public CookieSecurePolicy SecurePolicy { get; set; }

        /// <summary>Gets or sets the name of the auth cookie</summary>
        public string AuthCookieName { get; set; }

        /// <summary>
        /// Use https schema on redirect to IdentityProvider
        /// </summary>
        public bool UseHttpsSchemaOnRedirectToIdentityProvider { get; set; }

        /// <summary>
        /// Override the OnTicketReceived and sign in the user ourselves using the SignInAsync().
        /// This will reduce the cookie size, but also loose the ability to use the refresh token to automatically reauthenticate, see UseAutomaticTokenManagement.
        /// </summary>
        public bool UseCustomSignIn { get; set; }

        /// <summary>
        /// The SlidingExpiration is set to true to instruct the handler to re-issue a new cookie with a new
        /// expiration time any time it processes a request which is more than halfway through the expiration window.
        /// </summary>
        public bool SlidingExpiration { get; set; }

        /// <summary>
        /// The maximum size of cookie to send back to the client. If a cookie exceeds this size it will be broken down into multiple
        /// cookies. Set this value to null to disable this behavior. The default is 4090 characters, which is supported by all
        /// common browsers.
        /// 
        /// Note that browsers may also have limits on the total size of all cookies per domain, and on the number of cookies per domain.
        /// </summary>
        public int CookieChunkSize { get; set; }

        /// <summary>
        /// On every incoming request, check the expiration time of the current access token, and if a certain threshold is reached, use the refresh token to get a new access token
        /// At sign-out time, call the revocation endpoint at the token service to revoke the refresh token
        /// </summary>
        public bool UseAutomaticTokenManagement { get; set; }

        /// <summary>
        /// Check the expiration time of the current access token, and if a certain threshold is reached, use the refresh token to get a new access token.
        /// Only applicable if UseAutomaticTokenManagement is set to true.
        /// </summary>
        public TimeSpan RefreshBeforeExpiration { get; set; }

        /// <summary>At sign-out time, call the revocation endpoint at the token service to revoke the refresh token.
        /// Only applicable if UseAutomaticTokenManagement is set to true.
        /// </summary>
        public bool RevokeRefreshTokenOnSignOut { get; set; }

        /// <summary>Return 401 instead of 403</summary>
        public bool Force401InsteadOf403 { get; set; }
    }
}
