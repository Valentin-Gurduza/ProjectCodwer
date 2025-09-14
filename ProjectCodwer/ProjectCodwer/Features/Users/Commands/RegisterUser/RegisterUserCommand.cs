using MediatR;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using ProjectCodwer.Data;
using ProjectCodwer.Services;
using ProjectCodwer.Shared.Contracts;
using ProjectCodwer.Shared.DTOs;
using System.Text;
using System.Text.Encodings.Web;

namespace ProjectCodwer.Features.Users.Commands.RegisterUser
{
    public record RegisterUserCommand : ICommand<Result>, IRequest<Result>
    {
        public string Email { get; init; } = string.Empty;
        public string Password { get; init; } = string.Empty;
        public string ConfirmPassword { get; init; } = string.Empty;
    }

    public class RegisterUserCommandHandler : IRequestHandler<RegisterUserCommand, Result>
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IEmailSender<ApplicationUser> _emailSender;
        private readonly SecurityAuditService _auditService;
        private readonly ILogger<RegisterUserCommandHandler> _logger;

        public RegisterUserCommandHandler(
            UserManager<ApplicationUser> userManager,
            IEmailSender<ApplicationUser> emailSender,
            SecurityAuditService auditService,
            ILogger<RegisterUserCommandHandler> logger)
        {
            _userManager = userManager;
            _emailSender = emailSender;
            _auditService = auditService;
            _logger = logger;
        }

        public async Task<Result> Handle(RegisterUserCommand request, CancellationToken cancellationToken)
        {
            try
            {
                if (request.Password != request.ConfirmPassword)
                {
                    return Result.Failure(new[] { "Passwords do not match." });
                }

                var existingUser = await _userManager.FindByEmailAsync(request.Email);
                if (existingUser != null)
                {
                    return Result.Failure(new[] { "User with this email already exists." });
                }

                var user = new ApplicationUser
                {
                    UserName = request.Email,
                    Email = request.Email,
                    EmailConfirmed = false
                };

                var result = await _userManager.CreateAsync(user, request.Password);
                
                if (!result.Succeeded)
                {
                    return Result.Failure(result.Errors.Select(e => e.Description));
                }

                // Generate email confirmation token
                var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));

                // Note: In a real implementation, you would generate a proper callback URL
                var callbackUrl = $"https://localhost:7000/Account/ConfirmEmail?userId={user.Id}&code={code}";

                await _emailSender.SendConfirmationLinkAsync(user, request.Email, HtmlEncoder.Default.Encode(callbackUrl));

                await _auditService.LogSecurityEventAsync(user.Id, "USER_REGISTERED", "", $"Email: {request.Email}");

                _logger.LogInformation("User {Email} registered successfully", request.Email);

                return Result.Success();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error registering user {Email}", request.Email);
                return Result.Failure(new[] { "An error occurred during registration." });
            }
        }
    }
}