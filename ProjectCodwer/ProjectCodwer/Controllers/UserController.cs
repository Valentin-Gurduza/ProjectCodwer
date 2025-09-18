using MediatR;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using ProjectCodwer.Features.Users.Commands.UpdateUser;
using ProjectCodwer.Features.Users.Queries.GetUser;
using ProjectCodwer.Shared.DTOs;

namespace ProjectCodwer.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize]
    public class UserController : ControllerBase
    {
        private readonly IMediator _mediator;

        public UserController(IMediator mediator)
        {
            _mediator = mediator;
        }

        [HttpGet("{id}")]
        [IgnoreAntiforgeryToken] // API endpoints don't need antiforgery tokens
        public async Task<IActionResult> GetUser(string id)
        {
            var query = new GetUserQuery { Id = id };
            var result = await _mediator.Send(query);
            
            if (result.Succeeded)
            {
                return Ok(result);
            }
            
            return NotFound(result);
        }

        [HttpPut("{id}")]
        [IgnoreAntiforgeryToken] // API endpoints don't need antiforgery tokens
        public async Task<IActionResult> UpdateUser(string id, [FromBody] UpdateUserCommand command)
        {
            if (id != command.Id)
            {
                return BadRequest(Result.Failure(new[] { "User ID mismatch." }));
            }
            
            var result = await _mediator.Send(command);
            
            if (result.Succeeded)
            {
                return Ok(result);
            }
            
            return BadRequest(result);
        }
    }
}