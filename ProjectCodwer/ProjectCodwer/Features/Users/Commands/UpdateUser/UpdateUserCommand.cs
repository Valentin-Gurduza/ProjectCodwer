using MediatR;
using Microsoft.AspNetCore.Identity;
using ProjectCodwer.Data;
using ProjectCodwer.Shared.Contracts;
using ProjectCodwer.Shared.DTOs;

namespace ProjectCodwer.Features.Users.Commands.UpdateUser
{
    public record UpdateUserCommand : ICommand<Result>, IRequest<Result>
    {
        public string Id { get; init; } = string.Empty;
        public string? PhoneNumber { get; init; }
    }

    public class UpdateUserCommandHandler : IRequestHandler<UpdateUserCommand, Result>
    {
        private readonly UserManager<ApplicationUser> _userManager;

        public UpdateUserCommandHandler(UserManager<ApplicationUser> userManager)
        {
            _userManager = userManager;
        }

        public async Task<Result> Handle(UpdateUserCommand request, CancellationToken cancellationToken)
        {
            var user = await _userManager.FindByIdAsync(request.Id);

            if (user == null)
            {
                return Result.Failure(new[] { "User not found" });
            }

            if (request.PhoneNumber != user.PhoneNumber)
            {
                user.PhoneNumber = request.PhoneNumber;
                var result = await _userManager.UpdateAsync(user);

                if (!result.Succeeded)
                {
                    return Result.Failure(result.Errors.Select(e => e.Description));
                }
            }

            return Result.Success();
        }
    }
}