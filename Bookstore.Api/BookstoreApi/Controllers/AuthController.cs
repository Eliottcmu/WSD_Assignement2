using System.Security.Claims;
using Bookstore.Api.Exceptions;
using Bookstore.Api.Middleware;
using Bookstore.Api.Models;
using Bookstore.Api.Security;
using Bookstore.Api.Services;
using Microsoft.AspNetCore.Mvc;
using Swashbuckle.AspNetCore.Annotations;

namespace Bookstore.Api.Controllers
{
    [ApiController]
    [Route("api/auth")]
    public class AuthController : ControllerBase
    {
        private readonly UserService _userService;
        private readonly JwtService _jwtService;

        public AuthController(UserService userService, JwtService jwtService)
        {
            _userService = userService;
            _jwtService = jwtService;
        }

        [HttpPost("login")]
        [SwaggerOperation(
            Summary = "User login",
            Description = "Verifies credentials and returns a signed JWT on success."
        )]
        public virtual async Task<IActionResult> Login([FromBody] LoginDto dto)
        {
            if (!ModelState.IsValid)
                throw new BadRequestException("Invalid credentials format.");

            var user = await _userService.GetByEmailAsync(dto.Email);
            if (user == null)
                throw new UnauthorizedException("Invalid credentials.");

            var isValidPassword = PasswordHasher.Verify(dto.Password, user.Password);
            if (!isValidPassword)
                throw new UnauthorizedException("Invalid credentials.");

            var token = _jwtService.GenerateToken(user);
            var refreshToken = _jwtService.GenerateRefreshToken();
            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiry = DateTime.UtcNow.AddDays(7); // Set expiry
            await _userService.UpdateAsync(user.UserId, user);
            if (user.UserId == null)
                return Unauthorized();
            return Ok(
                new
                {
                    token,
                    refreshToken,
                    expiresIn = _jwtService.ExpirationMinutes,
                    user = new
                    {
                        user.UserId,
                        user.Email,
                        user.Name,
                        user.IsAdmin,
                    },
                }
            );
        }

        [HttpPost("logout")]
        [SwaggerOperation(
            Summary = "Logout user",
            Description = "Clears the authentication token on client side. Since JWT is stateless, the backend simply returns a success response."
        )]
        public IActionResult Logout()
        {
            return Ok(new { message = "User logged out successfully." });
        }

        // refresh token
        [HttpPost("refresh")]
        [SwaggerOperation(
            Summary = "Refresh JWT token",
            Description = "Provides a new access token using a valid refresh token."
        )]
        public async Task<IActionResult> Refresh([FromBody] RefreshTokenDto dto)
        {
            var principal = _jwtService.GetPrincipalFromExpiredToken(dto.AccessToken);
            var email = principal.FindFirstValue(ClaimTypes.Email);

            var user = await _userService.GetByEmailAsync(email!);
            if (
                user == null
                || user.RefreshToken != dto.RefreshToken
                || user.RefreshTokenExpiry <= DateTime.UtcNow
            )
                throw new UnauthorizedException("Invalid or expired refresh token.");

            var newAccessToken = _jwtService.GenerateToken(user);
            var newRefreshToken = _jwtService.GenerateRefreshToken();

            user.RefreshToken = newRefreshToken;
            await _userService.UpdateAsync(user.UserId, user);

            return Ok(
                new
                {
                    accessToken = newAccessToken,
                    refreshToken = newRefreshToken,
                    expiresIn = _jwtService.ExpirationMinutes,
                }
            );
        }
    }

    // DTOs
    public record RegisterDto(
        string Email,
        string Password,
        string Name,
        DateTime? BirthDate,
        Gender? Gender,
        string? Address,
        string? PhoneNumber,
        string? ProfileImage
    );

    public record LoginDto(string Email, string Password);

    public record RefreshTokenDto(string AccessToken, string RefreshToken);
}
