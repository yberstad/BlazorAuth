namespace BlazorAuth
{
    public class Constants
    {
        public const string RoleClaimType = "roles";
        public const string EmailClaimType = "email";
        public const string NameClaimType = "name";
        public const string UpnClaimType = "upn";
        public const string ScopeClaimType = "http://schemas.microsoft.com/identity/claims/scope";
    }

    public static class AuthClaimTypes
    {
        public static readonly string Role;
        public static readonly string FirstName;
        public static readonly string SurName;
        public static readonly string ProfileId;
        public static readonly string UserName;
        public static readonly string Commuter;
        public static readonly string CustomerId;
        public static readonly string RewardNumber;
        public static readonly string IpAddress;
        public static readonly string TrustedCookieName;
        public static readonly string ChannelId;
    }
}
