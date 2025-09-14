using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using ProjectCodwer.Client.Services;

var builder = WebAssemblyHostBuilder.CreateDefault(args);

builder.Services.AddAuthorizationCore();
builder.Services.AddCascadingAuthenticationState();
builder.Services.AddAuthenticationStateDeserialization();

// Register HTTP client
builder.Services.AddScoped(sp => new HttpClient { BaseAddress = new Uri(builder.HostEnvironment.BaseAddress) });

// Register ApiService
builder.Services.AddScoped<ApiService>();

await builder.Build().RunAsync();
