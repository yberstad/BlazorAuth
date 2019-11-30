using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace BlazorAuth
{
    public static class ServiceCollectionExtensions
    {
        public static void AddOption<TOptions>(this IServiceCollection services, IConfiguration configuration, string sectionName)
            where TOptions : class
        {
            services.Configure<TOptions>(options => configuration.GetSection(sectionName).Bind(options));
        }
    }
}
