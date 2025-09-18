using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using ProjectCodwer.Client.Pages;
using ProjectCodwer.Components;
using ProjectCodwer.Components.Account;
using ProjectCodwer.Data;
using ProjectCodwer.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.Threading.RateLimiting;
using FluentValidation;
using ProjectCodwer.Behaviors;
using MediatR;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.EntityFrameworkCore;
using Microsoft.AspNetCore.RateLimiting;
using System.Globalization;

var builder = WebApplication.CreateBuilder(args);

// Honor container HTTPS port for redirects
builder.Services.AddHttpsRedirection(options =>
{
    // Our compose exposes HTTPS on 8081
    options.HttpsPort = 8081;
});

// Add services to the container.
builder.Services.AddRazorComponents()
    .AddInteractiveWebAssemblyComponents()
    .AddAuthenticationStateSerialization();

builder.Services.AddCascadingAuthenticationState();
builder.Services.AddScoped<IdentityUserAccessor>();
builder.Services.AddScoped<IdentityRedirectManager>();

// Configure Data Protection to persist keys
var dataProtection = builder.Services.AddDataProtection()
    .SetApplicationName("ProjectCodwer")
    .SetDefaultKeyLifetime(TimeSpan.FromDays(90));

var runningInContainer = string.Equals(
    Environment.GetEnvironmentVariable("DOTNET_RUNNING_IN_CONTAINER"),
    "true",
    StringComparison.OrdinalIgnoreCase);

// Configure DbContext once
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(connectionString));

// Persist Data Protection keys to SQL Server via EF Core to avoid filesystem permission issues and support scale-out
dataProtection.PersistKeysToDbContext<ApplicationDbContext>();

builder.Services.AddDatabaseDeveloperPageExceptionFilter();

builder.Services.AddIdentityCore<ApplicationUser>(options => options.SignIn.RequireConfirmedAccount = true)
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddSignInManager()
    .AddDefaultTokenProviders();

// Application services
builder.Services.AddSingleton<IEmailSender<ApplicationUser>, EmailService>();
builder.Services.AddScoped<SmsService>();
builder.Services.AddScoped<SecurityAuditService>();
builder.Services.AddScoped<JwtTokenService>();

// Add FluentValidation
builder.Services.AddValidatorsFromAssemblyContaining<Program>();

// Add MediatR for CQRS with behaviors
builder.Services.AddMediatR(cfg =>
{
    cfg.RegisterServicesFromAssembly(typeof(Program).Assembly);
    cfg.AddBehavior(typeof(IPipelineBehavior<,>), typeof(ValidationBehavior<,>));
});

// Configure Identity with enhanced security
builder.Services.Configure<IdentityOptions>(options =>
{
    // Password settings
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequireUppercase = true;
    options.Password.RequiredLength = 12;
    options.Password.RequiredUniqueChars = 6;

    // Lockout settings
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.AllowedForNewUsers = true;

    // User settings
    options.User.RequireUniqueEmail = true;
    options.SignIn.RequireConfirmedAccount = true;
});

// Add antiforgery for all environments
builder.Services.AddAntiforgery(options =>
{
    options.HeaderName = "X-XSRF-TOKEN";
    options.SuppressXFrameOptionsHeader = false;
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
    
    // Only require secure cookies in production
    options.Cookie.SecurePolicy = builder.Environment.IsDevelopment() 
        ? CookieSecurePolicy.SameAsRequest 
        : CookieSecurePolicy.Always;
});

var jwtKey = builder.Configuration["JwtSettings:Key"] ?? "your-super-secret-key-that-should-be-at-least-32-characters-long";

// Configure Authentication
var authBuilder = builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = IdentityConstants.ApplicationScheme;
    options.DefaultSignInScheme = IdentityConstants.ExternalScheme;
});

authBuilder.AddIdentityCookies();
authBuilder.AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = builder.Configuration["JwtSettings:Issuer"],
        ValidAudience = builder.Configuration["JwtSettings:Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey))
    };
});

builder.Services.AddAuthorization();

// Add Rate Limiting using System.Threading.RateLimiting
builder.Services.AddRateLimiter(options =>
{
    // Return 429 instead of 503 and include a Retry-After header
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.OnRejected = (context, token) =>
    {
        context.HttpContext.Response.Headers.RetryAfter = TimeSpan.FromMinutes(1).TotalSeconds.ToString(CultureInfo.InvariantCulture);
        return ValueTask.CompletedTask;
    };

    // Exclude Blazor/Identity/Static asset paths from limiting
    var excludedPrefixes = new[]
    {
        "/_blazor", "/_framework", "/_content", "/css", "/js", "/images", "/lib",
        "/favicon.ico", "/Account/Manage", "/Account/Login", "/Account/LoginWith2fa", "/Account/Logout", "/Account/Register"
    };

    options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(httpContext =>
    {
        var path = httpContext.Request.Path.Value ?? string.Empty;
        foreach (var prefix in excludedPrefixes)
        {
            if (path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                return RateLimitPartition.GetNoLimiter("excluded");
            }
        }

        var partitionKey = httpContext.Connection.RemoteIpAddress?.ToString()
            ?? httpContext.Request.Headers.Host.ToString();

        return RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: partitionKey,
            factory: _ => new FixedWindowRateLimiterOptions
            {
                AutoReplenishment = true,
                PermitLimit = 100,
                QueueLimit = 0,
                Window = TimeSpan.FromMinutes(1)
            });
    });

    options.AddPolicy("login", httpContext =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: httpContext.Connection.RemoteIpAddress?.ToString() ?? httpContext.Request.Headers.Host.ToString(),
            factory: _ => new FixedWindowRateLimiterOptions
            {
                AutoReplenishment = true,
                PermitLimit = 5,
                QueueLimit = 0,
                Window = TimeSpan.FromMinutes(15)
            }));
});

// Add Controllers for API endpoints
builder.Services.AddControllers();

var app = builder.Build();

// Initialize database on startup
using (var scope = app.Services.CreateScope())
{
    var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    var logger = scope.ServiceProvider.GetRequiredService<ILogger<Program>>();
    
    try
    {
        logger.LogInformation("Applying database migrations...");
        await context.Database.MigrateAsync();
        logger.LogInformation("Database migrations applied successfully.");
    }
    catch (Exception ex)
    {
        logger.LogError(ex, "An error occurred while applying database migrations.");
        throw;
    }
}

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseWebAssemblyDebugging();
    app.UseMigrationsEndPoint();
}
else
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    app.UseHsts();
}

// Configure forwarded headers if behind proxy
app.UseForwardedHeaders();

// Use HTTPS redirection
app.UseHttpsRedirection();

// Add Security Headers
app.Use(async (context, next) =>
{
    context.Response.Headers.Append("X-Content-Type-Options", "nosniff");
    context.Response.Headers.Append("X-Frame-Options", "DENY");
    context.Response.Headers.Append("X-XSS-Protection", "1; mode=block");
    context.Response.Headers.Append("Referrer-Policy", "strict-origin-when-cross-origin");
    
    // Blazor WebAssembly-compatible CSP
    var csp = "default-src 'self'; " +
              "script-src 'self' 'unsafe-eval' 'unsafe-inline'; " +  // unsafe-eval needed for WASM
              "style-src 'self' 'unsafe-inline'; " +
              "img-src 'self' data: blob:; " +  // data: URIs for SVG icons
              "font-src 'self'; " +
              "connect-src 'self' wss: ws:; " +  // WebSocket for Blazor SignalR
              "media-src 'self'; " +
              "object-src 'none'; " +
              "frame-src 'none'; " +
              "form-action 'self'; " +
              "frame-ancestors 'none';";
    
    context.Response.Headers.Append("Content-Security-Policy", csp);

    await next();
});

// Add Rate Limiting
app.UseRateLimiter();

// Add Authentication and Authorization
app.UseAuthentication();
app.UseAuthorization();

// Use antiforgery for all environments - must be after auth
app.UseAntiforgery();

app.MapStaticAssets();
var components = app.MapRazorComponents<App>()
    .AddInteractiveWebAssemblyRenderMode()
    .AddAdditionalAssemblies(typeof(ProjectCodwer.Client._Imports).Assembly);

// Add additional endpoints required by the Identity /Account Razor components.
app.MapAdditionalIdentityEndpoints();

// Map API Controllers
app.MapControllers();

app.Run();
