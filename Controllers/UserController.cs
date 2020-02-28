using System.Linq;
using System.Text;
using System;
using System.Security.Claims;
using System.Collections.Generic;
using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authorization;
using System.Security;

namespace AuthNet.Controllers
{
    [ApiController]
    [Route("user")]
    [Authorize]
    public class UserController : ControllerBase
    {
        public UserController()
        {

        }


        [HttpGet]

        public IActionResult GetUser()
        {
            return Ok(new { hello = "world" });
        }

        [HttpPost]
        [AllowAnonymous]
        [Route("authenticate")]
        public IActionResult Authenticate(User user)
        {
            var users = new List<User>(){
                new User(){username="john", password="doe"},
                new User(){username="joni", password="jon"},
                new User(){username="lala", password="lele"},
            };

            var _user = users.Find(e => e.username == user.username);

            var tokenHandler = new JwtSecurityTokenHandler();

            var tokenDescription = new SecurityTokenDescriptor()
            {
                Subject = new ClaimsIdentity(new Claim[]{
                    new Claim(ClaimTypes.Name, _user.username),
                    new Claim(ClaimTypes.Country, "Indonesia")
                }),
                Expires = DateTime.UtcNow.AddDays(7),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(Encoding.ASCII.GetBytes("ini secret key nya harus panjang")), SecurityAlgorithms.HmacSha512Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescription);

            var tokenResponse = new {
                token = tokenHandler.WriteToken(token),
                user = _user.username
            };

            return Ok(tokenResponse);
        }

    }


    public class User
    {
        public string username { get; set; }
        public string password { get; set; }
    }
}