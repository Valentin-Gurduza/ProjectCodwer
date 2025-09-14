using MediatR;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using ProjectCodwer.Data;
using ProjectCodwer.Features.Users.Commands.RegisterUser;
using ProjectCodwer.Services;
using ProjectCodwer.Shared.DTOs;
using System.ComponentModel.DataAnnotations;

namespace ProjectCodwer.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [EnableRateLimiting("login")]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly JwtTokenService _jwtTokenService;
        private readonly SecurityAuditService _auditService;
        private readonly IMediator _mediator;
        private readonly ILogger<AuthController> _logger;

        public AuthController(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            JwtTokenService jwtTokenService,
            SecurityAuditService auditService,
            IMediator mediator,
            ILogger<AuthController> logger)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _jwtTokenService = jwtTokenService;
            _auditService = auditService;
            _mediator = mediator;
            _logger = logger;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterUserCommand command)
        {
            var result = await _mediator.Send(command);
            
            if (result.Succeeded)
            {
                return Ok(result);
            }
            
            return BadRequest(result);
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            try
            {
                var user = await _userManager.FindByEmailAsync(request.Email);
                if (user == null)
                {
                    await _auditService.LogSecurityEventAsync("", "LOGIN_FAILED_INVALID_USER", 
                        HttpContext.Connection.RemoteIpAddress?.ToString() ?? "", $"Email: {request.Email}");
                    return BadRequest(Result.Failure(new[] { "Invalid login attempt." }));
                }

                var result = await _signInManager.CheckPasswordSignInAsync(user, request.Password, lockoutOnFailure: true);
                
                if (result.Succeeded)
                {
                    if (!user.EmailConfirmed)
                    {
                        return BadRequest(Result.Failure(new[] { "Email not confirmed." }));
                    }

                    var token = await _jwtTokenService.GenerateTokenAsync(user);
                    await _auditService.LogSecurityEventAsync(user.Id, "LOGIN_SUCCESS", 
                        HttpContext.Connection.RemoteIpAddress?.ToString() ?? "");

                    return Ok(Result<LoginResponse>.Success(new LoginResponse
                    {
                        Token = token,
                        UserId = user.Id,
                        Email = user.Email!,
                        RequiresTwoFactor = result.RequiresTwoFactor
                    }));
                }

                if (result.IsLockedOut)
                {
                    await _auditService.LogSecurityEventAsync(user.Id, "LOGIN_LOCKED_OUT", 
                        HttpContext.Connection.RemoteIpAddress?.ToString() ?? "");
                    return BadRequest(Result.Failure(new[] { "Account locked out." }));
                }

                if (result.RequiresTwoFactor)
                {
                    return Ok(Result<LoginResponse>.Success(new LoginResponse
                    {
                        RequiresTwoFactor = true,
                        UserId = user.Id
                    }));
                }

                await _auditService.LogSecurityEventAsync(user.Id, "LOGIN_FAILED", 
                    HttpContext.Connection.RemoteIpAddress?.ToString() ?? "");
                return BadRequest(Result.Failure(new[] { "Invalid login attempt." }));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during login for {Email}", request.Email);
                return StatusCode(500, Result.Failure(new[] { "An error occurred during login." }));
            }
        }

        [HttpPost("verify-2fa")]
        public async Task<IActionResult> VerifyTwoFactor([FromBody] TwoFactorRequest request)
        {
            try
            {
                var user = await _userManager.FindByIdAsync(request.UserId);
                if (user == null)
                {
                    return BadRequest(Result.Failure(new[] { "Invalid request." }));
                }

                var result = await _signInManager.TwoFactorAuthenticatorSignInAsync(
                    request.Code, request.RememberMe, rememberClient: false);

                if (result.Succeeded)
                {
                    var token = await _jwtTokenService.GenerateTokenAsync(user);
                    await _auditService.LogSecurityEventAsync(user.Id, "2FA_SUCCESS", 
                        HttpContext.Connection.RemoteIpAddress?.ToString() ?? "");

                    return Ok(Result<LoginResponse>.Success(new LoginResponse
                    {
                        Token = token,
                        UserId = user.Id,
                        Email = user.Email!
                    }));
                }

                await _auditService.LogSecurityEventAsync(user.Id, "2FA_FAILED", 
                    HttpContext.Connection.RemoteIpAddress?.ToString() ?? "");
                return BadRequest(Result.Failure(new[] { "Invalid authenticator code." }));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during 2FA verification for user {UserId}", request.UserId);
                return StatusCode(500, Result.Failure(new[] { "An error occurred during verification." }));
            }
        }

        [HttpPost("logout")]
        [Authorize]
        public async Task<IActionResult> Logout()
        {
            var userId = _userManager.GetUserId(User);
            await _signInManager.SignOutAsync();
            
            if (!string.IsNullOrEmpty(userId))
            {
                await _auditService.LogSecurityEventAsync(userId, "LOGOUT", 
                    HttpContext.Connection.RemoteIpAddress?.ToString() ?? "");
            }

            return Ok(Result.Success());
        }
    }

    public class LoginRequest
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;

        [Required]
        public string Password { get; set; } = string.Empty;
        
        public bool RememberMe { get; set; }
    }

    public class TwoFactorRequest
    {
        [Required]
        public string UserId { get; set; } = string.Empty;

        [Required]
        public string Code { get; set; } = string.Empty;
        
        public bool RememberMe { get; set; }
    }

    public class LoginResponse
    {
        public string? Token { get; set; }
        public string UserId { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public bool RequiresTwoFactor { get; set; }
    }
}