using System.Security.Claims;
using Bookstore.Api.Common;
using Bookstore.Api.Models;
using Bookstore.Api.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using MongoDB.Bson;
using Swashbuckle.AspNetCore.Annotations;

namespace Bookstore.Api.Controllers
{
    [ApiController]
    [Route("api/reviews")]
    public class ReviewsController : ControllerBase
    {
        private readonly ReviewService _reviewService;

        public ReviewsController(ReviewService reviewService)
        {
            _reviewService = reviewService;
        }

        // ========================= UTILITIES =========================

        private IActionResult ErrorResponse(
            int status,
            string code,
            string message,
            object? details = null
        ) =>
            StatusCode(
                status,
                new
                {
                    timestamp = DateTime.UtcNow.ToString("o"),
                    path = HttpContext.Request.Path.ToString(),
                    status,
                    code,
                    message,
                    details,
                }
            );

        private bool TryParseId(
            string id,
            string errorCode,
            string message,
            out ObjectId objectId,
            out IActionResult? error
        )
        {
            if (!ObjectId.TryParse(id, out objectId))
            {
                error = ErrorResponse(400, errorCode, message, new { id });
                return false;
            }

            error = null;
            return true;
        }

        private ObjectId? GetUserObjectId()
        {
            var userString = User.FindFirstValue(ClaimTypes.NameIdentifier);
            return ObjectId.TryParse(userString, out var oid) ? oid : null;
        }

        private IActionResult Forbidden(string id) =>
            ErrorResponse(
                403,
                "FORBIDDEN",
                "You are not allowed to perform this action.",
                new { reviewid = id }
            );

        // GetAll
        [HttpGet]
        [Authorize(Policy = "User")]
        [SwaggerOperation(
            Summary = "Get list of all reviews",
            Description = "Optionally filters reviews by bookId."
        )]
        [SwaggerResponse(200, "Reviews retrieved successfully", typeof(PagedResponse<Review>))]
        [SwaggerResponse(400, "Invalid pagination parameters")]
        [SwaggerResponse(500, "Internal server error")]
        public async Task<IActionResult> GetAll(
            [FromQuery] string? bookId,
            [FromQuery] int page = 1,
            [FromQuery] int pageSize = 10
        )
        {
            if (page <= 0 || pageSize <= 0)
                return ErrorResponse(
                    400,
                    "INVALID_PAGINATION",
                    "Page and pageSize must be greater than 0.",
                    new { page, pageSize }
                );

            var (items, total) = await _reviewService.GetPagedAsync(bookId, page, pageSize);

            return Ok(
                new PagedResponse<Review>
                {
                    Items = items,
                    Page = page,
                    PageSize = pageSize,
                    TotalItems = total,
                }
            );
        }

        // GetById

        [HttpGet("{id}")]
        [AllowAnonymous]
        [SwaggerOperation(
            Summary = "Get review by ID",
            Description = "Fetches a review by its ObjectId."
        )]
        [SwaggerResponse(200, "Review retrieved", typeof(Review))]
        [SwaggerResponse(400, "Invalid ID")]
        [SwaggerResponse(404, "Review not found")]
        [SwaggerResponse(500, "Server error")]
        public async Task<IActionResult> GetById(string id)
        {
            if (
                !TryParseId(
                    id,
                    "INVALID_REVIEW_ID",
                    "Invalid review ID format.",
                    out _,
                    out var err
                )
            )
                return err!;

            var review = await _reviewService.GetByIdAsync(id);
            return review == null
                ? ErrorResponse(404, "REVIEW_NOT_FOUND", "Review not found.", new { id })
                : Ok(review);
        }

        // GetTop

        [HttpGet("top")]
        [AllowAnonymous]
        [SwaggerOperation(
            Summary = "Get top reviews",
            Description = "Retrieves top-rated reviews (algorithm defined in service)."
        )]
        [SwaggerResponse(200, "Top reviews retrieved", typeof(List<Review>))]
        public async Task<IActionResult> GetTop() => Ok(await _reviewService.GetTopReviewsAsync());

        // Create

        [HttpPost]
        [Authorize(Policy = "User")]
        [SwaggerOperation(Summary = "Create a new review", Description = "Requires user.")]
        [SwaggerResponse(201, "Review created", typeof(Review))]
        [SwaggerResponse(400, "Bad input data")]
        [SwaggerResponse(401, "Unauthorized user")]
        [SwaggerResponse(422, "Validation failure")]
        [SwaggerResponse(500, "Server error")]
        public async Task<IActionResult> Create(CreateReviewDto dto)
        {
            if (
                !TryParseId(
                    dto.BookId,
                    "INVALID_BOOK_ID",
                    "Invalid book ID format.",
                    out _,
                    out var err
                )
            )
                return err!;

            var userId = GetUserObjectId();
            if (userId == null)
                return ErrorResponse(401, "INVALID_USER", "Invalid or missing user identifier.");

            if (dto.Rating is < 1 or > 5)
                return ErrorResponse(400, "INVALID_RATING", "Rating must be between 1 and 5.");

            if (string.IsNullOrWhiteSpace(dto.Content))
                return ErrorResponse(400, "EMPTY_CONTENT", "Review content cannot be empty.");

            var review = new Review
            {
                BookId = dto.BookId,
                UserId = userId.Value.ToString(),
                Content = dto.Content.Trim(),
                Rating = dto.Rating,
                Likes = new List<string>(),
                CreatedAt = DateTime.UtcNow,
            };

            await _reviewService.CreateAsync(review);
            return StatusCode(201, review);
        }

        // Update

        [HttpPut("{id}")]
        [Authorize(Policy = "User")]
        [SwaggerOperation(
            Summary = "Update a review",
            Description = "Only the review owner or an admin may update."
        )]
        [SwaggerResponse(204, "Review updated")]
        [SwaggerResponse(400, "Invalid input")]
        [SwaggerResponse(401, "Unauthorized")]
        [SwaggerResponse(403, "Forbidden")]
        [SwaggerResponse(404, "Review not found")]
        [SwaggerResponse(500, "Server error")]
        public async Task<IActionResult> Update(string id, UpdateReviewDto dto)
        {
            if (
                !TryParseId(
                    id,
                    "INVALID_REVIEW_ID",
                    "Invalid review ID format.",
                    out _,
                    out var err
                )
            )
                return err!;

            var existing = await _reviewService.GetByIdAsync(id);
            if (existing == null)
                return ErrorResponse(404, "REVIEW_NOT_FOUND", "Review not found.", new { id });

            var userId = GetUserObjectId();
            var isAdmin = User.IsInRole("Admin");

            if (!isAdmin && existing.UserId != userId?.ToString())
                return Forbidden(id);

            if (dto.Rating.HasValue && (dto.Rating < 1 || dto.Rating > 5))
                return ErrorResponse(
                    400,
                    "INVALID_RATING",
                    "Rating must be between 1 and 5.",
                    new { dto.Rating }
                );

            existing.Content = string.IsNullOrWhiteSpace(dto.Content)
                ? existing.Content
                : dto.Content.Trim();
            existing.Rating = dto.Rating ?? existing.Rating;

            return await _reviewService.UpdateAsync(id, existing)
                ? NoContent()
                : ErrorResponse(500, "UPDATE_FAILED", "Failed to update the review.");
        }

        // Delete

        [HttpDelete("{id}")]
        [Authorize(Policy = "User")]
        [SwaggerOperation(
            Summary = "Delete a review",
            Description = "Only the reviewer or an admin can delete a review."
        )]
        [SwaggerResponse(204, "Review deleted")]
        [SwaggerResponse(400, "Invalid ID")]
        [SwaggerResponse(401, "Unauthorized")]
        [SwaggerResponse(403, "Forbidden")]
        [SwaggerResponse(404, "Review not found")]
        [SwaggerResponse(500, "Delete failed")]
        public async Task<IActionResult> Delete(string id)
        {
            if (
                !TryParseId(
                    id,
                    "INVALID_REVIEW_ID",
                    "Invalid review ID format.",
                    out _,
                    out var err
                )
            )
                return err!;

            var existing = await _reviewService.GetByIdAsync(id);
            if (existing == null)
                return ErrorResponse(404, "REVIEW_NOT_FOUND", "Review not found.", new { id });

            var userId = GetUserObjectId();
            var isAdmin = User.IsInRole("Admin");

            if (!isAdmin && existing.UserId != userId?.ToString())
                return Forbidden(id);

            return await _reviewService.DeleteAsync(id)
                ? NoContent()
                : ErrorResponse(500, "DELETE_FAILED", "Failed to delete the review.");
        }

        // Like

        [HttpPost("{id}/like")]
        [Authorize(Policy = "User")]
        [SwaggerOperation(
            Summary = "Toggle like on a review",
            Description = "Likes or unlikes the review for the authenticated user."
        )]
        [SwaggerResponse(200, "Like toggled successfully")]
        [SwaggerResponse(400, "Invalid review ID")]
        [SwaggerResponse(401, "Unauthorized")]
        [SwaggerResponse(404, "Review not found")]
        [SwaggerResponse(500, "Server error")]
        public async Task<IActionResult> ToggleLike(string id)
        {
            if (
                !TryParseId(
                    id,
                    "INVALID_REVIEW_ID",
                    "Invalid review ID format.",
                    out _,
                    out var err
                )
            )
                return err!;

            var userId = GetUserObjectId();
            if (userId == null)
                return ErrorResponse(401, "INVALID_USER", "Invalid or missing user identifier.");

            var success = await _reviewService.ToggleLikeAsync(id, userId.Value.ToString());

            return success
                ? Ok(new { liked = true })
                : ErrorResponse(
                    404,
                    "REVIEW_NOT_FOUND",
                    "Review not found or like operation failed.",
                    new { id }
                );
        }
    }

    // ---------------- DTOs ----------------

    public class CreateReviewDto
    {
        public required string BookId { get; set; }
        public required string Content { get; set; }
        public required int Rating { get; set; }
    }

    public class UpdateReviewDto
    {
        public string? Content { get; set; }
        public int? Rating { get; set; }
    }
}
