using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Http;
using System.Security.Claims;
using System.Threading.Tasks;

namespace BlazorAuth
{
    public class ServerAutStateProvider : AuthenticationStateProvider
    {
        private readonly IHttpContextAccessor _httpContextAccessor;
        public ServerAutStateProvider(IHttpContextAccessor httpContextAccessor)
        {
            _httpContextAccessor = httpContextAccessor;
        }

        public override Task<AuthenticationState> GetAuthenticationStateAsync()
        {
            return Task.Run(() =>
            {
                return new AuthenticationState(new ClaimsPrincipal(_httpContextAccessor.HttpContext.User.Identity));
            });
        }
    }
}