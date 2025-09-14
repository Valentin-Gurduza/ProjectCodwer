using MediatR;
using Microsoft.AspNetCore.Identity;
using ProjectCodwer.Data;
using ProjectCodwer.Shared.Contracts;
using ProjectCodwer.Shared.DTOs;

namespace ProjectCodwer.Features.Users.Queries.GetUser
{
    public record UserDto
    {
        public string Id { get; init; } = string.Empty;
        public string? UserName { get; init; }
        public string? Email { get; init; }
        public string? PhoneNumber { get; init; }
    }

    public record GetUserQuery : IQuery<Result<UserDto>>, IRequest<Result<UserDto>>
    {
        public string Id { get; init; } = string.Empty;
    }

    public class GetUserQueryHandler : IRequestHandler<GetUserQuery, Result<UserDto>>
    {
        private readonly UserManager<ApplicationUser> _userManager;

        public GetUserQueryHandler(UserManager<ApplicationUser> userManager)
        {
            _userManager = userManager;
        }

        public async Task<Result<UserDto>> Handle(GetUserQuery request, CancellationToken cancellationToken)
        {
            var user = await _userManager.FindByIdAsync(request.Id);

            if (user == null)
            {
                return Result<UserDto>.Failure(new[] { "User not found" });
            }

            return Result<UserDto>.Success(new UserDto
            {
                Id = user.Id,
                UserName = user.UserName,
                Email = user.Email,
                PhoneNumber = user.PhoneNumber
            });
        }
    }
}