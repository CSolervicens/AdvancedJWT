using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using AdvancedJWT.Models;


namespace AdvancedJWT.Controllers
{
    [ApiController]
    [Route("api/other")]
    public class OtherServices : ControllerBase
    {
        private readonly PasswordService _passwordService;
        public OtherServices(
            PasswordService passwordService
            )
        {
            _passwordService = passwordService;
        }

        [HttpPost("pass_hash")]
        public async Task<IActionResult> HashPassword( pass_request request)
        {
            Console.WriteLine($"Password: {request.Password}");
            var hashedPassword = _passwordService.HashPassword(request.Password);
            return Ok(new { hashed_password = hashedPassword });
        }


        [HttpGet("protected")]
        [Authorize]
        public IActionResult Protected()
        {
            return Ok(new { message = "This is a protected endpoint" });
        }

    }
}
