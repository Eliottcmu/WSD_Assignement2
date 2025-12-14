using Bookstore.Api.Exceptions;
using Bookstore.Api.Models;
using Bookstore.Api.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using MongoDB.Bson;
using Swashbuckle.AspNetCore.Annotations;

namespace Bookstore.Api.Controllers
{
    [ApiController]
    [Route("api/reviews/{reviewid}/comments")]
    public class CommentsController : ControllerBase
    {
        private readonly CommentService _commentService;

        public CommentsController(CommentService commentService)
        {
            _commentService = commentService;
        }

        private ObjectId ParseObjectId(string value, string fieldName)
        {
            if (!ObjectId.TryParse(value, out var id))
                throw new BadRequestException($"Invalid {fieldName} format.");
            return id;
        }

        [HttpGet]
        [AllowAnonymous]
        [SwaggerOperation(
            Summary = "Get comments for a review",
            Description = "Returns a paginated list of comments attached to a review."
        )]
        [SwaggerResponse(StatusCodes.Status200OK, "Comments retrieved successfully")]
        [SwaggerResponse(StatusCodes.Status400BadRequest, "Invalid reviewid format")]
        [SwaggerResponse(
            StatusCodes.Status404NotFound,
            "Review does not exist (if implemented upstream)"
        )]
        public async Task<IActionResult> GetComments(
            string reviewid,
            [FromQuery] int page = 1,
            [FromQuery] int pageSize = 10
        )
        {
            ParseObjectId(reviewid, "reviewid");

            page = Math.Max(page, 1);
            pageSize = Math.Clamp(pageSize, 1, 100);

            var comments = await _commentService.GetByReviewAsync(reviewid, page, pageSize);
            var total = await _commentService.CountByReviewAsync(reviewid);

            return Ok(
                new
                {
                    page,
                    pageSize,
                    total,
                    data = comments,
                }
            );
        }

        [HttpPost]
        [Authorize(Policy = "User")]
        [SwaggerOperation(
            Summary = "Create a comment",
            Description = "Creates a comment under the specified review."
        )]
        [SwaggerResponse(StatusCodes.Status201Created, "Comment created", typeof(Comment))]
        [SwaggerResponse(StatusCodes.Status400BadRequest, "Invalid reviewid or userId")]
        [SwaggerResponse(
            StatusCodes.Status401Unauthorized,
            "Authentication required (if enforced upstream)"
        )]
        [SwaggerResponse(
            StatusCodes.Status403Forbidden,
            "User cannot comment (if enforced upstream)"
        )]
        [SwaggerResponse(StatusCodes.Status500InternalServerError, "Server error")]
        public async Task<IActionResult> CreateComment(
            string reviewid,
            [FromBody] CreateCommentRequest request
        )
        {
            var objReviewId = ParseObjectId(reviewid, "reviewid");
            var objUserId = ParseObjectId(request.UserId, "userId");

            var comment = new Comment
            {
                ReviewId = reviewid,
                UserId = request.UserId,
                Content = request.Content,
                CreatedAt = DateTime.UtcNow,
            };

            await _commentService.CreateAsync(comment);

            return CreatedAtAction(nameof(GetComments), new { reviewid }, comment);
        }

        [HttpDelete("{commentid}")]
        [Authorize(Policy = "User")]
        [SwaggerOperation(
            Summary = "Delete a comment",
            Description = "Deletes a comment by its ID."
        )]
        [SwaggerResponse(StatusCodes.Status204NoContent, "Comment deleted")]
        [SwaggerResponse(StatusCodes.Status400BadRequest, "Invalid commentId")]
        [SwaggerResponse(StatusCodes.Status404NotFound, "Comment not found")]
        [SwaggerResponse(StatusCodes.Status500InternalServerError, "Server error")]
        public async Task<IActionResult> DeleteComment(string reviewid, string commentId)
        {
            ParseObjectId(commentId, "commentId");

            var deleted = await _commentService.DeleteAsync(commentId);
            if (!deleted)
                throw new NotFoundException("Comment not found.");

            return NoContent();
        }

        [HttpPost("{commentid}/like")]
        [Authorize(Policy = "User")]
        [SwaggerOperation(
            Summary = "Like a comment",
            Description = "Adds a like to the specified comment."
        )]
        [SwaggerResponse(StatusCodes.Status200OK, "Comment liked")]
        [SwaggerResponse(StatusCodes.Status400BadRequest, "Invalid commentId or userId")]
        [SwaggerResponse(
            StatusCodes.Status404NotFound,
            "Comment not found (if enforced by service)"
        )]
        [SwaggerResponse(StatusCodes.Status422UnprocessableEntity, "Failed to like comment")]
        [SwaggerResponse(StatusCodes.Status500InternalServerError, "Server error")]
        public async Task<IActionResult> Like(string commentId, [FromQuery] string userId)
        {
            ParseObjectId(commentId, "commentId");
            ParseObjectId(userId, "userId");

            var success = await _commentService.LikeAsync(commentId, userId);
            if (!success)
                throw new DatabaseException("Failed to like comment.");

            return Ok();
        }

        [HttpPut("{commentId}")]
        [Authorize(Policy = "User")]
        [SwaggerOperation(
            Summary = "Update a comment",
            Description = "Updates the content of an existing comment."
        )]
        [SwaggerResponse(StatusCodes.Status200OK, "Comment updated", typeof(Comment))]
        [SwaggerResponse(StatusCodes.Status400BadRequest, "Invalid commentId")]
        [SwaggerResponse(StatusCodes.Status404NotFound, "Comment not found")]
        [SwaggerResponse(StatusCodes.Status422UnprocessableEntity, "Failed to update comment")]
        [SwaggerResponse(StatusCodes.Status500InternalServerError, "Server error")]
        public async Task<IActionResult> UpdateComment(string commentId, [FromBody] string content)
        {
            ParseObjectId(commentId, "commentId");

            var comment = await _commentService.GetByIdAsync(commentId);
            if (comment == null)
                throw new NotFoundException("Comment not found.");

            comment.Content = content;

            var updated = await _commentService.UpdateAsync(commentId, comment);
            if (!updated)
                throw new DatabaseException("Failed to update comment.");

            return Ok(comment);
        }

        [HttpDelete("{commentid}/like")]
        [Authorize(Policy = "User")]
        [SwaggerOperation(
            Summary = "Unlike a comment",
            Description = "Removes a like from the comment."
        )]
        [SwaggerResponse(StatusCodes.Status200OK, "Comment unliked")]
        [SwaggerResponse(StatusCodes.Status400BadRequest, "Invalid commentId or userId")]
        [SwaggerResponse(
            StatusCodes.Status404NotFound,
            "Comment not found (if enforced by service)"
        )]
        [SwaggerResponse(StatusCodes.Status422UnprocessableEntity, "Failed to unlike comment")]
        [SwaggerResponse(StatusCodes.Status500InternalServerError, "Server error")]
        public async Task<IActionResult> Unlike(string commentId, [FromQuery] string userId)
        {
            ParseObjectId(commentId, "commentId");
            ParseObjectId(userId, "userId");

            var success = await _commentService.UnlikeAsync(commentId, userId);
            if (!success)
                throw new DatabaseException("Failed to unlike comment.");

            return Ok();
        }
    }

    public class CreateCommentRequest
    {
        public required string UserId { get; set; }
        public required string Content { get; set; }
    }
}
