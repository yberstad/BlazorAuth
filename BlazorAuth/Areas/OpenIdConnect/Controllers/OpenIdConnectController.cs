using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using BlazorAuth.Areas.OpenIdConnect.Models;
using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Swashbuckle.AspNetCore.Annotations;

namespace BlazorAuth.Areas.OpenIdConnect.Controllers
{
    [Authorize]
    [ApiController]
    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    [Route("api/[controller]")]
    public class OpenIdConnectController : ControllerBase
    {
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly ILogger<OpenIdConnectController> _logger;
        private readonly OpenIdConnectOptions _oidcOptions;

        public OpenIdConnectController(
            IHttpClientFactory httpClientFactory,
            ILogger<OpenIdConnectController> logger,
            IOptions<OpenIdConnectOptions> oidcOptions)
        {
            _httpClientFactory = httpClientFactory;
            _logger = logger;
            _oidcOptions = oidcOptions.Value;
        }

        /// <summary>
        /// Retrieve a the current authenticated user.
        /// </summary>
        /// <returns></returns>
        [HttpGet("user/")]
        [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(AuthenticatedUserResponse))]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        [SwaggerOperation(OperationId = "GetUser")]
        public async Task<AuthenticatedUserResponse> GetUser()
        {
            _logger.LogInformation("GetUser called");

            var accessToken = await HttpContext.GetTokenAsync("access_token");
            AuthenticatedUserResponse authenticatedUserModel = new AuthenticatedUserResponse
            {
                Name = User.Identity.Name,
                Email = User.Claims.FirstOrDefault(claim => claim.Type == Constants.EmailClaimType)?.Value,
                Roles = User.Claims.FirstOrDefault(claim => claim.Type == Constants.RoleClaimType)?.Value?.Split(','),
                EmployeeNumber = User.Claims.FirstOrDefault(claim => claim.Type == Constants.UpnClaimType)?.Value?.Split('@')[0],
                StatusCode = StatusCodes.Status200OK
            };
            
            return authenticatedUserModel;
        }

        [HttpGet("logout")]
        [SwaggerOperation(OperationId = "Logout")]
        public IActionResult Logout()
        {
            return new SignOutResult(new List<string>{CookieAuthenticationDefaults.AuthenticationScheme, OpenIdConnectDefaults.AuthenticationScheme}, 
                new AuthenticationProperties { RedirectUri = "/" });
        }


        [AllowAnonymous]
        [HttpGet("login")]
        [SwaggerOperation(OperationId = "Login")]
        public IActionResult Login()
        {
            return Challenge(new AuthenticationProperties {RedirectUri = "/"}, OpenIdConnectDefaults.AuthenticationScheme);
        }
        
        [AllowAnonymous]
        [HttpPost("login")]
        [SwaggerOperation(OperationId = "ResourceOwnerPasswordLogin")]
        public async Task<IActionResult> ResourceOwnerPasswordLogin([FromBody] [Required] LoginModel model)
        {
            try
            {
                var configuration = await _oidcOptions.ConfigurationManager.GetConfigurationAsync(default(CancellationToken));

                var client = _httpClientFactory.CreateClient();
                var request = new PasswordTokenRequest
                {
                    Address = configuration.TokenEndpoint,
                    ClientId = _oidcOptions.ClientId,
                    ClientSecret = _oidcOptions.ClientSecret,
                    UserName = model.UserName,
                    Password = model.Password,
                    Scope = OpenIdConnectDefaults.AuthenticationScheme
                };

                request.Parameters.Add("resource", _oidcOptions.ClientId);

                var response = await client.RequestPasswordTokenAsync(request);

                if (response.IsError)
                {
                    _logger.LogWarning($"Error RequestPasswordTokenAsync: {response.Error}, {response.ErrorDescription} ");
                    return StatusCode(StatusCodes.Status401Unauthorized);
                }

                var properties = new AuthenticationProperties();
                if (_oidcOptions.SaveTokens)
                {
                    properties.UpdateTokenValue("access_token", response.AccessToken);
                    properties.UpdateTokenValue("refresh_token", response.RefreshToken);
                    DateTime newExpiresAt = DateTime.UtcNow + TimeSpan.FromSeconds(response.ExpiresIn);
                    properties.UpdateTokenValue("expires_at", newExpiresAt.ToString("o", CultureInfo.InvariantCulture));
                }

                var principal = ValidateAndDecode(response.AccessToken, configuration.SigningKeys, configuration.Issuer, _oidcOptions.ClientId);
                await HttpContext.SignInAsync(principal, properties);
                return StatusCode(StatusCodes.Status200OK);
            }
            catch (Exception ex)
            {
                _logger.LogWarning("Error ResourceOwnerPasswordLogin: {error}", ex);
                return StatusCode(StatusCodes.Status401Unauthorized);
            }
        }

        private static ClaimsPrincipal ValidateAndDecode(string jwt, IEnumerable<SecurityKey> signingKeys, string issuer, string clientId)
        {
            var validationParameters = new TokenValidationParameters
            {
                // Clock skew compensates for server time drift.
                // We recommend 5 minutes or less:
                ClockSkew = TimeSpan.FromMinutes(5),
                // Specify the key used to sign the token:
                IssuerSigningKeys = signingKeys,
                RequireSignedTokens = true,
                // Ensure the token hasn't expired:
                RequireExpirationTime = true,
                ValidateLifetime = true,
                // Ensure the token audience matches our audience value (default true):
                ValidateAudience = true,
                ValidAudience = clientId,
                // Ensure the token was issued by a trusted authorization server (default true):
                ValidateIssuer = true,
                ValidIssuer = issuer,
                NameClaimType = Constants.NameClaimType,
                RoleClaimType = Constants.RoleClaimType
            };

            try
            {
                // https://leastprivilege.com/2017/11/15/missing-claims-in-the-asp-net-core-2-openid-connect-handler/
                JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();
                return new JwtSecurityTokenHandler()
                    .ValidateToken(jwt, validationParameters, out var rawValidatedToken);

                //return (JwtSecurityToken)rawValidatedToken;
                // Or, you can return the ClaimsPrincipal
                // (which has the JWT properties automatically mapped to .NET claims)
            }
            catch (SecurityTokenValidationException stvex)
            {
                // The token failed validation!
                throw new Exception($"Token failed validation: {stvex.Message}");
            }
            catch (ArgumentException argex)
            {
                // The token was not well-formed or was invalid for some other reason.
                throw new Exception($"Token was invalid: {argex.Message}");
            }
        }
    }
}