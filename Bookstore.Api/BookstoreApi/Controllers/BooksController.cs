using Bookstore.Api.Common;
using Bookstore.Api.Exceptions;
using Bookstore.Api.Middleware;
using Bookstore.Api.Models;
using Bookstore.Api.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using MongoDB.Bson;
using Swashbuckle.AspNetCore.Annotations;

namespace Bookstore.Api.Controllers
{
    [ApiController]
    [Route("api/books")]
    public class BooksController : ControllerBase
    {
        private readonly BookService _service;

        public BooksController(BookService service)
        {
            _service = service;
        }

        // GET /api/books
        [HttpGet]
        [AllowAnonymous]
        [SwaggerOperation(
            Summary = "Get paginated list of books",
            Description = "Returns a paginated list of books, optionally filtered by keyword."
        )]
        [SwaggerResponse(
            StatusCodes.Status200OK,
            "Books retrieved successfully",
            typeof(PagedResponse<Book>)
        )]
        [SwaggerResponse(StatusCodes.Status400BadRequest, "Invalid pagination parameters")]
        [SwaggerResponse(StatusCodes.Status500InternalServerError, "Server error")]
        public async Task<IActionResult> GetAll(
            int page = 1,
            int pageSize = 10,
            string? keyword = null
        )
        {
            if (page <= 0 || pageSize <= 0)
                throw new BadRequestException("Page and pageSize must be > 0.");

            var (items, total) = await _service.GetPagedAsync(page, pageSize, keyword);

            return Ok(
                new PagedResponse<Book>
                {
                    Items = items,
                    Page = page,
                    PageSize = pageSize,
                    TotalItems = total,
                }
            );
        }

        // GET /api/books/{id}
        [HttpGet("{id}")]
        [AllowAnonymous]
        [SwaggerOperation(
            Summary = "Get a book by ID",
            Description = "Retrieves a single book by its MongoDB ObjectId."
        )]
        [SwaggerResponse(StatusCodes.Status200OK, "Book retrieved successfully", typeof(Book))]
        [SwaggerResponse(StatusCodes.Status400BadRequest, "Invalid book ID format")]
        [SwaggerResponse(StatusCodes.Status404NotFound, "Book not found")]
        [SwaggerResponse(StatusCodes.Status500InternalServerError, "Server error")]
        public async Task<IActionResult> GetById(string id)
        {
            if (!ObjectId.TryParse(id, out _))
                throw new BadRequestException("Invalid book ID.");

            var book = await _service.GetByIdAsync(id);
            if (book == null)
                throw new NotFoundException("Book not found.");

            return Ok(book);
        }

        // POST /api/books
        [HttpPost]
        [Authorize(Policy = "User")]
        [SwaggerOperation(
            Summary = "Create a new book",
            Description = "Creates a new book. Requires being connected ."
        )]
        [SwaggerResponse(StatusCodes.Status201Created, "Book created successfully", typeof(Book))]
        [SwaggerResponse(StatusCodes.Status400BadRequest, "Invalid input data")]
        [SwaggerResponse(StatusCodes.Status401Unauthorized, "Missing or invalid token")]
        [SwaggerResponse(StatusCodes.Status403Forbidden, "Permission required from connection")]
        [SwaggerResponse(StatusCodes.Status500InternalServerError, "Server error")]
        public async Task<IActionResult> Create([FromBody] CreateBookDto dto)
        {
            if (!ObjectId.TryParse(dto.SellerId, out _))
                throw new BadRequestException("Invalid seller ID format.");

            var book = new Book
            {
                SellerId = dto.SellerId,
                Title = dto.Title,
                Authors = dto.Authors,
                Categories = dto.Categories,
                Publisher = dto.Publisher,
                Summary = dto.Summary,
                Isbn = dto.Isbn,
                Price = dto.Price,
                PublicationDate = dto.PublicationDate,
                Stock = dto.Stock,
            };

            await _service.CreateAsync(book);

            return CreatedAtAction(nameof(GetById), new { id = book.BookId }, book);
        }

        // PUT /api/books/{id}
        [HttpPut("{id}")]
        [Authorize(Policy = "Admin")]
        [SwaggerOperation(
            Summary = "Update a book",
            Description = "Updates an existing book by its ID. Admin only."
        )]
        [SwaggerResponse(StatusCodes.Status204NoContent, "Book updated successfully")]
        [SwaggerResponse(StatusCodes.Status400BadRequest, "Invalid ID format")]
        [SwaggerResponse(StatusCodes.Status404NotFound, "Book not found")]
        [SwaggerResponse(StatusCodes.Status422UnprocessableEntity, "Update operation failed")]
        [SwaggerResponse(StatusCodes.Status500InternalServerError, "Server error")]
        public async Task<IActionResult> Update(string id, [FromBody] UpdateBookDto dto)
        {
            if (!ObjectId.TryParse(id, out _))
                throw new BadRequestException("Invalid ID.");

            var book = await _service.GetByIdAsync(id);
            if (book == null)
                throw new NotFoundException("Book not found.");

            book.Title = dto.Title ?? book.Title;
            book.Authors = dto.Authors ?? book.Authors;
            book.Categories = dto.Categories ?? book.Categories;
            book.Publisher = dto.Publisher ?? book.Publisher;
            book.Summary = dto.Summary ?? book.Summary;
            book.Isbn = dto.Isbn ?? book.Isbn;
            book.Price = dto.Price ?? book.Price;
            book.PublicationDate = dto.PublicationDate ?? book.PublicationDate;
            book.Stock = dto.Stock ?? book.Stock;

            var ok = await _service.UpdateAsync(id, book);
            if (!ok)
                throw new DatabaseException("Failed to update book.");

            return NoContent();
        }

        // DELETE /api/books/{id}
        [HttpDelete("{id}")]
        [Authorize(Policy = "Admin")]
        [SwaggerOperation(
            Summary = "Delete a book",
            Description = "Deletes a book by ID. Admin privileges required."
        )]
        [SwaggerResponse(StatusCodes.Status204NoContent, "Book deleted successfully")]
        [SwaggerResponse(StatusCodes.Status400BadRequest, "Invalid ID format")]
        [SwaggerResponse(StatusCodes.Status404NotFound, "Book not found")]
        [SwaggerResponse(StatusCodes.Status401Unauthorized, "Missing or invalid token")]
        [SwaggerResponse(StatusCodes.Status403Forbidden, "Admin permission required")]
        [SwaggerResponse(StatusCodes.Status500InternalServerError, "Server error")]
        public async Task<IActionResult> Delete(string id)
        {
            if (!ObjectId.TryParse(id, out _))
                throw new BadRequestException("Invalid ID.");

            var ok = await _service.DeleteAsync(id);
            if (!ok)
                throw new NotFoundException("Book not found.");

            return NoContent();
        }
    }
}

public class CreateBookDto
{
    public required string SellerId { get; set; }
    public required string Title { get; set; }
    public required List<string> Authors { get; set; }
    public required List<string> Categories { get; set; }

    public string? Publisher { get; set; }
    public string? Summary { get; set; }
    public string? Isbn { get; set; }
    public decimal Price { get; set; }
    public DateTime? PublicationDate { get; set; }
    public int Stock { get; set; }
}

public class UpdateBookDto
{
    public string? Title { get; set; }
    public List<string>? Authors { get; set; }
    public List<string>? Categories { get; set; }

    public string? Publisher { get; set; }
    public string? Summary { get; set; }
    public string? Isbn { get; set; }
    public decimal? Price { get; set; }
    public DateTime? PublicationDate { get; set; }
    public int? Stock { get; set; }
}
