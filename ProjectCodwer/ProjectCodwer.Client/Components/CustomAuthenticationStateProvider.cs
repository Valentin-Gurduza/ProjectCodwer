using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
using ProjectCodwer.Client.Services;
using System.Security.Claims;

namespace ProjectCodwer.Client.Components
{
    public class CustomAuthenticationStateProvider : AuthenticationStateProvider
    {
        private readonly ApiService _apiService;
        private readonly ILogger<CustomAuthenticationStateProvider> _logger;
        private ClaimsPrincipal _currentUser = new(new ClaimsIdentity());

        public CustomAuthenticationStateProvider(ApiService apiService, ILogger<CustomAuthenticationStateProvider> logger)
        {
            _apiService = apiService;
            _logger = logger;
        }

        public override Task<AuthenticationState> GetAuthenticationStateAsync()
        {
            return Task.FromResult(new AuthenticationState(_currentUser));
        }

        public async Task<bool> LoginAsync(string email, string password, bool rememberMe = false)
        {
            try
            {
                // This would call your API service
                // Implementation depends on how you want to handle JWT tokens in Blazor WASM
                // You might store them in localStorage or handle them differently
                
                return false; // Placeholder
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during login");
                return false;
            }
        }

        public async Task LogoutAsync()
        {
            _currentUser = new ClaimsPrincipal(new ClaimsIdentity());
            NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
        }
    }
}