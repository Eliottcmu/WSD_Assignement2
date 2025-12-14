using System.Threading.Tasks;
using Bookstore.Api.Controllers;
using Bookstore.Api.Exceptions;
using Bookstore.Api.Models;
using Bookstore.Api.Security;
using Bookstore.Api.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using MongoDB.Bson;
using Moq;

namespace Bookstore.Api.Tests.Controllers
{
    [TestClass]
    public class TestAuthController
    {
        private Mock<UserService> _mockUserService = null!;
        private Mock<JwtService> _mockJwtService = null!;
        private AuthController _controller = null!;

        [TestInitialize]
        public void Setup()
        {
            _mockUserService = new Mock<UserService>();
            _mockJwtService = new Mock<JwtService>();

            _controller = new AuthController(_mockUserService.Object, _mockJwtService.Object);
        }

        // LOGIN TESTS
        [TestMethod]
        public async Task Login_ShouldReturnOk_WhenCredentialsAreValid()
        {
            string email = "test@example.com";
            string password = "Password123!";

            string hashedPassword = PasswordHasher.Hash(password);

            var user = new User
            {
                UserId = ObjectId.GenerateNewId(),
                Email = email,
                Password = hashedPassword, // Stored hashed password
                Name = "Test User",
                IsAdmin = false,
            };

            var loginDto = new LoginDto(email, password); // User sends raw password
            string expectedToken = "fake-jwt-token";

            // Setup Mocks
            _mockUserService.Setup(s => s.GetByEmailAsync(email)).ReturnsAsync(user);

            _mockJwtService.Setup(s => s.GenerateToken(user)).Returns(expectedToken);

            // Act
            var result = await _controller.Login(loginDto);

            // Assert
            Assert.IsInstanceOfType(result, typeof(OkObjectResult));
            var okResult = result as OkObjectResult;

            // Check that we got a token back (checking structure of anonymous object via Reflection)
            var responseData = okResult!.Value!;
            var tokenProperty = responseData.GetType().GetProperty("token");
            var tokenValue = tokenProperty?.GetValue(responseData, null) as string;

            Assert.AreEqual(expectedToken, tokenValue);
        }

        [TestMethod]
        public async Task Login_ShouldThrowUnauthorized_WhenUserNotFound()
        {
            // Arrange
            string email = "nonexistent@example.com";
            var loginDto = new LoginDto(email, "AnyPassword");

            _mockUserService.Setup(s => s.GetByEmailAsync(email)).ReturnsAsync((User?)null); // User not found

            // Act & Assert
            await Assert.ThrowsExceptionAsync<UnauthorizedException>(
                () => _controller.Login(loginDto)
            );
        }

        [TestMethod]
        public async Task Login_ShouldThrowUnauthorized_WhenPasswordIsInvalid()
        {
            // Arrange
            string email = "test@example.com";
            string correctPassword = "CorrectPassword";
            string wrongPassword = "WrongPassword";

            var user = new User
            {
                UserId = ObjectId.GenerateNewId(),
                Email = email,
                Password = PasswordHasher.Hash(correctPassword),
                Name = "Test User",
            };

            // DTO contains the wrong password
            var loginDto = new LoginDto(email, wrongPassword);

            _mockUserService.Setup(s => s.GetByEmailAsync(email)).ReturnsAsync(user);
            await Assert.ThrowsExceptionAsync<UnauthorizedException>(
                () => _controller.Login(loginDto)
            );
        }

        [TestMethod]
        public async Task Login_ShouldThrowBadRequest_WhenModelStateIsInvalid()
        {
            // Arrange
            _controller.ModelState.AddModelError("Email", "Required");
            var loginDto = new LoginDto("", "");

            // Act & Assert
            await Assert.ThrowsExceptionAsync<BadRequestException>(
                () => _controller.Login(loginDto)
            );
        }

        // LOGOUT TESTS
        [TestMethod]
        public void Logout_ShouldReturnOk()
        {
            // Act
            var result = _controller.Logout();

            // Assert
            Assert.IsInstanceOfType(result, typeof(OkObjectResult));
        }
    }
}
