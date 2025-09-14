using System.Net.Http.Json;
using ProjectCodwer.Shared.Contracts;
using ProjectCodwer.Shared.DTOs;

namespace ProjectCodwer.Client.Services
{
    public class ApiService
    {
        private readonly HttpClient _httpClient;

        public ApiService(HttpClient httpClient)
        {
            _httpClient = httpClient;
        }

        public async Task<Result<TResponse>> SendQueryAsync<TResponse>(IQuery<Result<TResponse>> query, string endpoint)
        {
            var response = await _httpClient.PostAsJsonAsync(endpoint, query);

            if (response.IsSuccessStatusCode)
            {
                return await response.Content.ReadFromJsonAsync<Result<TResponse>>()
                    ?? Result<TResponse>.Failure(new[] { "Failed to deserialize response" });
            }

            return Result<TResponse>.Failure(new[] { $"Error: {response.StatusCode}" });
        }

        public async Task<Result> SendCommandAsync<TCommand>(TCommand command, string endpoint)
            where TCommand : ICommand<Result>
        {
            var response = await _httpClient.PostAsJsonAsync(endpoint, command);

            if (response.IsSuccessStatusCode)
            {
                return await response.Content.ReadFromJsonAsync<Result>()
                    ?? Result.Failure(new[] { "Failed to deserialize response" });
            }

            return Result.Failure(new[] { $"Error: {response.StatusCode}" });
        }
    }
}