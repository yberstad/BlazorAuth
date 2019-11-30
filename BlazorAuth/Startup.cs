using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using BlazorAuth.Data;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authentication;
using System.Net;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using Microsoft.AspNetCore.HttpOverrides;

namespace BlazorAuth
{
    public class Startup
    {
        public IConfiguration _configuration { get; }

        public Startup(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        // This method gets called by the runtime. Use this method to add services to the container.
        // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddMvc().AddNewtonsoftJson();
            services.AddRazorPages();
            services.AddServerSideBlazor();
            services.AddSingleton<WeatherForecastService>();

            var strictSameSiteOpenIdConnectOptions = new StrictSameSiteOpenIdConnectOptions();
            _configuration.GetSection("StrictSameSiteOpenIdConnectOptions").Bind(strictSameSiteOpenIdConnectOptions);
            var openIdConnectOptions = new OpenIdConnectOptions();
            _configuration.GetSection("OpenIdConnectOptions").Bind(openIdConnectOptions);
            services.AddOption<OpenIdConnectOptions>(_configuration, "OpenIdConnectOptions");
            services.AddHttpClient();

            var authenticationBuilder = services.AddAuthentication(
                options =>
                {
                    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                                // we do not set a DefaultChallengeScheme to get 401 instead of a redirect to the challenge url.
                                //options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
                });

            authenticationBuilder.AddCookie(options =>
            {
                options.Cookie.SameSite = SameSiteMode.None;
                options.Cookie.Name = strictSameSiteOpenIdConnectOptions.AuthCookieName ?? "AuthCookie";
                options.Events = new CookieAuthenticationEvents
                {
                    OnRedirectToAccessDenied = ForbiddenResponse,
                    OnRedirectToLogin = UnAuthorizedResponse,
                    OnRedirectToReturnUrl = UnAuthorizedResponse
                };

                if (strictSameSiteOpenIdConnectOptions.Force401InsteadOf403)
                {
                    options.Events.OnRedirectToAccessDenied = UnAuthorizedResponse;
                }

                options.SlidingExpiration = strictSameSiteOpenIdConnectOptions.SlidingExpiration;
                options.Cookie.SecurePolicy = strictSameSiteOpenIdConnectOptions.SecurePolicy;

                if (strictSameSiteOpenIdConnectOptions.CookieChunkSize != 0)
                {
                    options.CookieManager = new ChunkingCookieManager
                    {
                        ChunkSize = strictSameSiteOpenIdConnectOptions.CookieChunkSize
                    };
                }
            });

            authenticationBuilder.AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
            {
                options.Authority = openIdConnectOptions.Authority;
                options.ClientId = openIdConnectOptions.ClientId;
                options.ClientSecret = openIdConnectOptions.ClientSecret;
                options.CallbackPath = new PathString(openIdConnectOptions.CallbackPath);
                options.SignedOutCallbackPath = new PathString(openIdConnectOptions.SignedOutCallbackPath);
                options.ResponseType = openIdConnectOptions.ResponseType;
                options.GetClaimsFromUserInfoEndpoint = true;

                options.Scope.Clear();
                foreach (var scope in openIdConnectOptions.Scope)
                {
                    options.Scope.Add(scope);
                }

                options.SaveTokens = openIdConnectOptions.SaveTokens;
                options.ClaimActions.MapJsonKey(ClaimTypes.Role, ClaimTypes.Role);

                options.TokenValidationParameters = new TokenValidationParameters
                {
                    NameClaimType = Constants.NameClaimType,
                    RoleClaimType = Constants.RoleClaimType,
                    ValidateIssuer = true
                };
                options.Events = new OpenIdConnectEvents
                {
                    // https://stackoverflow.com/a/50272428/3080858
                    OnRedirectToIdentityProvider = context =>
                    {
                        if (strictSameSiteOpenIdConnectOptions.UseHttpsSchemaOnRedirectToIdentityProvider &&
                            context.ProtocolMessage.RedirectUri.Contains("http:"))
                        {
                            context.ProtocolMessage.RedirectUri = context.ProtocolMessage.RedirectUri.Replace("http:", "https:");
                        }

                        return Task.CompletedTask;
                    },
                    OnRedirectToIdentityProviderForSignOut = context =>
                    {
                        if (strictSameSiteOpenIdConnectOptions.UseHttpsSchemaOnRedirectToIdentityProvider &&
                            context.ProtocolMessage.PostLogoutRedirectUri.Contains("http:"))
                        {
                            context.ProtocolMessage.PostLogoutRedirectUri = context.ProtocolMessage.PostLogoutRedirectUri.Replace("http:", "https:");
                        }

                        return Task.CompletedTask;
                    }
                };
                if (strictSameSiteOpenIdConnectOptions.UseCustomSignIn)
                {
                    // https://www.jerriepelser.com/blog/managing-session-lifetime-aspnet-core-oauth-providers/
                    openIdConnectOptions.Events.OnTicketReceived = context =>
                    {
                        // Sign the user in ourselves
                        context.HttpContext.SignInAsync(context.Options.SignInScheme, context.Principal,
                            new AuthenticationProperties
                            {
                                IsPersistent = true,
                                ExpiresUtc = DateTimeOffset.UtcNow.Add(strictSameSiteOpenIdConnectOptions.AuthenticationTicketExpiration)
                            });

                        // Indicate that we handled the login
                        context.HandleResponse();

                        // Default redirect path is the base path
                        if (string.IsNullOrEmpty(context.ReturnUri))
                        {
                            context.ReturnUri = "/";
                        }

                        context.Response.Redirect(context.ReturnUri);

                        return Task.FromResult(0);
                    };
                }
            });

        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseMiddleware<StrictSameSiteCookieFixMiddleware>();
            app.UseForwardedHeaders(new ForwardedHeadersOptions
            {
                RequireHeaderSymmetry = false,
                ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto
            });

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapDefaultControllerRoute();
                endpoints.MapBlazorHub();
                endpoints.MapFallbackToPage("/_Host");
            });
        }

        internal static Task UnAuthorizedResponse(RedirectContext<CookieAuthenticationOptions> context)
        {
            context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
            return Task.CompletedTask;
        }

        internal static Task ForbiddenResponse(RedirectContext<CookieAuthenticationOptions> context)
        {
            context.Response.StatusCode = (int)HttpStatusCode.Forbidden;
            return Task.CompletedTask;
        }
    }
}
