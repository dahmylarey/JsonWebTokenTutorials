using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;

namespace JsonWebTokenTutorials.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        [HttpPost]
        public IActionResult Login(UserLogin userLogin)
        {
            if (userLogin.UserName == "admin" && userLogin.Password == "password")
            {
                var token = GenerateJsonWebToken();
                return Ok(new { token });

            }
            return Unauthorized();

        }

        [Authorize]
        [HttpGet("securedata")]
        public IActionResult GetSecurityData()
        {
            return Ok("This is highly confidential data, accessible only with a valid JWT");


        }

        private string GenerateJsonWebToken()
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("YourSecurityKeyHereThatIsVeryVeryLong"));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            var token = new JwtSecurityToken(
                   issuer: "https://localhost:7220/",
                   audience: "https://localhost:7220/",
                   expires: DateTime.Now.AddMinutes(30)
                );

            return new JwtSecurityTokenHandler().WriteToken(token);

        }


        public class UserLogin
        {

            public required string UserName { get; set; }
            public required string Password { get; set; }


        }
    }
}
