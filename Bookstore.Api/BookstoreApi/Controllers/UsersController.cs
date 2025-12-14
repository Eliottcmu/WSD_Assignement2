using System.Security.Claims;
using Bookstore.Api.Models;
using Bookstore.Api.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using MongoDB.Bson;
using Swashbuckle.AspNetCore.Annotations;

namespace Bookstore.Api.Controllers
{
    [ApiController]
    [Route("api/users")]
    public class UsersController : ControllerBase
    {
        private readonly UserService _userService;

        public UsersController(UserService userService)
        {
            _userService = userService;
        }

        // ----------------------- UTILITIES -----------------------

        private IActionResult Error(int status, string message, object? details = null)
        {
            return StatusCode(
                status,
                new
                {
                    timestamp = DateTime.UtcNow.ToString("o"),
                    path = HttpContext.Request.Path.ToString(),
                    status,
                    message,
                    details,
                }
            );
        }

        private bool TryParseId(string id, out ObjectId objectId, out IActionResult? error)
        {
            if (!ObjectId.TryParse(id, out objectId))
            {
                error = Error(400, "Invalid ID format.", new { id });
                return false;
            }

            error = null;
            return true;
        }

        private string? CurrentUserId => User.FindFirstValue(ClaimTypes.NameIdentifier);

        private bool IsAdmin =>
            bool.TryParse(User.FindFirstValue("is_admin"), out var isAdmin) && isAdmin;

        private IActionResult ForbidAccess(string id) =>
            Error(403, "Access denied.", new { userId = id });

        // GetAll

        [HttpGet]
        [Authorize(Policy = "Admin")]
        [SwaggerOperation(
            Summary = "Get all users",
            Description = "Returns a full list of users. Admin only."
        )]
        [SwaggerResponse(200, "Users retrieved successfully", typeof(IEnumerable<User>))]
        [SwaggerResponse(401, "Authentication required")]
        [SwaggerResponse(403, "Admin access required")]
        [SwaggerResponse(500, "Unexpected server error")]
        public async Task<IActionResult> GetAll()
        {
            var users = await _userService.GetAllAsync();
            return Ok(users);
        }

        // GetById

        [HttpGet("{id}")]
        [Authorize(Policy = "User")]
        [SwaggerOperation(
            Summary = "Get a user by ID",
            Description = "Admin: can access any user. Normal users: can only access their own profile."
        )]
        [SwaggerResponse(200, "User found", typeof(User))]
        [SwaggerResponse(400, "Invalid ID format")]
        [SwaggerResponse(401, "Authentication required")]
        [SwaggerResponse(403, "Access denied")]
        [SwaggerResponse(404, "User not found")]
        [SwaggerResponse(500, "Unexpected server error")]
        public async Task<IActionResult> GetById(string id)
        {
            if (!TryParseId(id, out _, out var err))
                return err!;

            var user = await _userService.GetByIdAsync(id);
            if (user == null)
                return Error(404, "User not found.", new { id });

            if (!IsAdmin && user.UserId != CurrentUserId)
                return ForbidAccess(id);

            return Ok(user);
        }

        // Post - Create

        [HttpPost]
        [Authorize(Policy = "User")]
        [SwaggerOperation(
            Summary = "Create a new user account",
            Description = "Public registration endpoint. Email must be unique."
        )]
        [SwaggerResponse(201, "User created successfully", typeof(User))]
        [SwaggerResponse(400, "Invalid payload")]
        [SwaggerResponse(409, "Email already used")]
        [SwaggerResponse(422, "Validation error")]
        [SwaggerResponse(500, "Unexpected server error")]
        public async Task<IActionResult> Create([FromBody] CreateUserDto dto)
        {
            if (!ModelState.IsValid)
                return Error(400, "Invalid payload.", ModelState);

            if (await _userService.EmailExistsAsync(dto.Email))
                return Error(409, "Email already used.", new { dto.Email });

            var user = new User
            {
                Name = dto.Name,
                Email = dto.Email,
                Password = dto.Password,
                BirthDate = dto.BirthDate,
                Gender = dto.Gender,
                Address = dto.Address,
                PhoneNumber = dto.PhoneNumber,
                ProfileImage = dto.ProfileImage,
                ReviewCount = 0,
                IsAdmin = false,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow,
            };

            var created = await _userService.CreateAsync(user);
            if (created.UserId == null)
                return NotFound();
            return CreatedAtAction(
                nameof(GetById),
                new { id = created.UserId.ToString() },
                created
            );
        }

        // Update

        [HttpPut("{id}")]
        [Authorize(Policy = "User")]
        [SwaggerOperation(
            Summary = "Update an existing user",
            Description = "Admin can update any user. Normal users can only update their own profile."
        )]
        [SwaggerResponse(204, "User updated successfully")]
        [SwaggerResponse(400, "Invalid ID or payload")]
        [SwaggerResponse(401, "Authentication required")]
        [SwaggerResponse(403, "Access denied")]
        [SwaggerResponse(404, "User not found")]
        [SwaggerResponse(500, "Update failed")]
        public async Task<IActionResult> Update(string id, [FromBody] UpdateUserDto dto)
        {
            if (!TryParseId(id, out _, out var err))
                return err!;

            var existing = await _userService.GetByIdAsync(id);
            if (existing == null)
                return Error(404, "User not found.", new { id });

            if (!IsAdmin && existing.UserId != CurrentUserId)
                return ForbidAccess(id);

            existing.Name = dto.Name ?? existing.Name;
            existing.Password = dto.Password ?? existing.Password;
            existing.BirthDate = dto.BirthDate ?? existing.BirthDate;
            existing.Gender = dto.Gender ?? existing.Gender;
            existing.Address = dto.Address ?? existing.Address;
            existing.PhoneNumber = dto.PhoneNumber ?? existing.PhoneNumber;
            existing.ProfileImage = dto.ProfileImage ?? existing.ProfileImage;
            existing.UpdatedAt = DateTime.UtcNow;

            var success = await _userService.UpdateAsync(id, existing);
            return success ? NoContent() : Error(500, "Update failed.");
        }

        // Delete

        [HttpDelete("{id}")]
        [Authorize(Policy = "Admin")]
        [SwaggerOperation(
            Summary = "Delete a user",
            Description = "Admin-only operation. Permanently removes a user account."
        )]
        [SwaggerResponse(204, "User deleted successfully")]
        [SwaggerResponse(400, "Invalid ID")]
        [SwaggerResponse(401, "Authentication required")]
        [SwaggerResponse(403, "Admin access required")]
        [SwaggerResponse(404, "User not found")]
        [SwaggerResponse(500, "Unexpected server error")]
        public async Task<IActionResult> Delete(string id)
        {
            if (!TryParseId(id, out _, out var err))
                return err!;

            var success = await _userService.DeleteAsync(id);
            return success ? NoContent() : Error(404, "User not found.", new { id });
        }

        // EmailCheck

        [HttpGet("check-email")]
        [AllowAnonymous]
        [SwaggerOperation(
            Summary = "Check email availability",
            Description = "Returns whether an email already exists."
        )]
        [SwaggerResponse(200, "Status returned successfully")]
        [SwaggerResponse(500, "Unexpected server error")]
        public async Task<IActionResult> CheckEmail([FromQuery] string email)
        {
            var exists = await _userService.EmailExistsAsync(email);
            return Ok(new { exists });
        }
    }
}

// ------------------- DTOs -------------------
public class CreateUserDto
{
    public required string Name { get; set; }
    public required string Email { get; set; }
    public required string Password { get; set; }
    public DateTime? BirthDate { get; set; }
    public Gender? Gender { get; set; }
    public string? Address { get; set; }
    public string? PhoneNumber { get; set; }
    public string? ProfileImage { get; set; }
}

public class UpdateUserDto
{
    public string? Name { get; set; }
    public string? Password { get; set; }
    public DateTime? BirthDate { get; set; }
    public Gender? Gender { get; set; }
    public string? Address { get; set; }
    public string? PhoneNumber { get; set; }
    public string? ProfileImage { get; set; }
}
