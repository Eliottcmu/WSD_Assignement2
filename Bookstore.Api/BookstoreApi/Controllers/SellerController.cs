using Bookstore.Api.Common;
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
    [Route("api/sellers")]
    public class SellersController : ControllerBase
    {
        private readonly SellerService _service;

        public SellersController(SellerService service)
        {
            _service = service;
        }

        // GET /api/sellers
        [HttpGet]
        [Authorize(Policy = "Admin")]
        [SwaggerOperation(
            Summary = "Get paginated list of sellers",
            Description = "Admin only. Supports optional keyword filtering."
        )]
        [SwaggerResponse(200, "Sellers retrieved successfully", typeof(PagedResponse<Seller>))]
        [SwaggerResponse(400, "Invalid pagination parameters")]
        [SwaggerResponse(401, "Authentication required")]
        [SwaggerResponse(403, "Admin privilege required")]
        [SwaggerResponse(500, "Unexpected server error")]
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
                new PagedResponse<Seller>
                {
                    Items = items,
                    Page = page,
                    PageSize = pageSize,
                    TotalItems = total,
                }
            );
        }

        // GET /api/sellers/{id}
        [HttpGet("{id}")]
        [Authorize(Policy = "User")]
        [SwaggerOperation(
            Summary = "Get seller by ID",
            Description = "Returns a seller if exists. Admin only."
        )]
        [SwaggerResponse(200, "Seller retrieved", typeof(Seller))]
        [SwaggerResponse(400, "Invalid ID format")]
        [SwaggerResponse(401, "Unauthorized")]
        [SwaggerResponse(403, "Admin privilege required")]
        [SwaggerResponse(404, "Seller not found")]
        [SwaggerResponse(500, "Unexpected server error")]
        public async Task<IActionResult> GetById(string id)
        {
            if (!ObjectId.TryParse(id, out _))
                throw new BadRequestException("Invalid ID.");

            var seller = await _service.GetByIdAsync(id);
            if (seller == null)
                throw new NotFoundException("Seller not found.");

            return Ok(seller);
        }

        // POST /api/sellers
        [HttpPost]
        [Authorize(Policy = "Admin")]
        [SwaggerOperation(
            Summary = "Create a seller",
            Description = "Creates a new seller linked to a User. Admin only."
        )]
        [SwaggerResponse(201, "Seller created", typeof(Seller))]
        [SwaggerResponse(400, "Invalid user ID or invalid payload")]
        [SwaggerResponse(401, "Unauthorized")]
        [SwaggerResponse(403, "Admin privilege required")]
        [SwaggerResponse(422, "Unprocessable seller data")]
        [SwaggerResponse(500, "Server error")]
        public async Task<IActionResult> Create([FromBody] CreateSellerDto dto)
        {
            if (!ObjectId.TryParse(dto.UserId, out _))
                throw new BadRequestException("Invalid user ID.");

            var s = new Seller
            {
                UserId = dto.UserId,
                BusinessName = dto.BusinessName,
                BusinessNumber = dto.BusinessNumber,
                PayoutBank = dto.PayoutBank,
                PayoutAccount = dto.PayoutAccount,
                PayoutHolder = dto.PayoutHolder,
            };

            await _service.CreateAsync(s);

            return CreatedAtAction(nameof(GetById), new { id = s.SellerId }, s);
        }

        // PUT /api/sellers/{id}
        [HttpPut("{id}")]
        [Authorize(Policy = "Admin")]
        [SwaggerOperation(
            Summary = "Update an existing seller",
            Description = "Allows updating payout or business information. Admin only."
        )]
        [SwaggerResponse(204, "Seller updated successfully")]
        [SwaggerResponse(400, "Invalid seller ID")]
        [SwaggerResponse(401, "Unauthorized")]
        [SwaggerResponse(403, "Admin privilege required")]
        [SwaggerResponse(404, "Seller not found")]
        [SwaggerResponse(422, "Failed to update seller")]
        [SwaggerResponse(500, "Server error")]
        public async Task<IActionResult> Update(string id, [FromBody] UpdateSellerDto dto)
        {
            if (!ObjectId.TryParse(id, out _))
                throw new BadRequestException("Invalid ID.");

            var s = await _service.GetByIdAsync(id);
            if (s == null)
                throw new NotFoundException("Seller not found.");

            s.BusinessName = dto.BusinessName ?? s.BusinessName;
            s.BusinessNumber = dto.BusinessNumber ?? s.BusinessNumber;
            s.PayoutBank = dto.PayoutBank ?? s.PayoutBank;
            s.PayoutAccount = dto.PayoutAccount ?? s.PayoutAccount;
            s.PayoutHolder = dto.PayoutHolder ?? s.PayoutHolder;

            var ok = await _service.UpdateAsync(id, s);
            if (!ok)
                throw new DatabaseException("Failed to update seller.");

            return NoContent();
        }

        // DELETE /api/sellers/{id}
        [HttpDelete("{id}")]
        [Authorize(Policy = "Admin")]
        [SwaggerOperation(
            Summary = "Delete a seller",
            Description = "Permanently deletes a seller. Admin only."
        )]
        [SwaggerResponse(204, "Seller deleted")]
        [SwaggerResponse(400, "Invalid ID")]
        [SwaggerResponse(401, "Unauthorized")]
        [SwaggerResponse(403, "Admin privilege required")]
        [SwaggerResponse(404, "Seller not found")]
        [SwaggerResponse(500, "Unexpected server error")]
        public async Task<IActionResult> Delete(string id)
        {
            if (!ObjectId.TryParse(id, out _))
                throw new BadRequestException("Invalid ID.");

            var ok = await _service.DeleteAsync(id);
            if (!ok)
                throw new NotFoundException("Seller not found.");

            return NoContent();
        }
    }
}

public class CreateSellerDto
{
    public required string UserId { get; set; }
    public required string BusinessName { get; set; }
    public required string BusinessNumber { get; set; }
    public required string PayoutBank { get; set; }
    public required string PayoutAccount { get; set; }
    public required string PayoutHolder { get; set; }
}

public class UpdateSellerDto
{
    public string? BusinessName { get; set; }
    public string? BusinessNumber { get; set; }
    public string? PayoutBank { get; set; }
    public string? PayoutAccount { get; set; }
    public string? PayoutHolder { get; set; }
}
