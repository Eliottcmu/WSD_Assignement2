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
    [Route("api/orderitems")]
    public class OrderItemsController : ControllerBase
    {
        private readonly OrderItemService _service;

        public OrderItemsController(OrderItemService service)
        {
            _service = service;
        }

        [HttpPost]
        [Authorize(Policy = "User")]
        [SwaggerOperation(
            Summary = "Create an order item",
            Description = "Creates an order item associated with an order."
        )]
        [SwaggerResponse(StatusCodes.Status201Created, "Order item created", typeof(OrderItem))]
        [SwaggerResponse(StatusCodes.Status400BadRequest, "Invalid order item payload")]
        [SwaggerResponse(StatusCodes.Status401Unauthorized, "Authentication required")]
        [SwaggerResponse(StatusCodes.Status403Forbidden, "Insufficient permissions")]
        [SwaggerResponse(StatusCodes.Status422UnprocessableEntity, "Unprocessable order item data")]
        [SwaggerResponse(StatusCodes.Status500InternalServerError, "Server error")]
        public async Task<IActionResult> Create([FromBody] OrderItem item)
        {
            var created = await _service.CreateAsync(item);
            return CreatedAtAction(nameof(GetById), new { itemId = created.OrderItemId }, created);
        }

        [HttpGet("{itemId}")]
        [Authorize(Policy = "User")]
        [SwaggerOperation(
            Summary = "Get an order item by ID",
            Description = "Returns a single order item by its ID."
        )]
        [SwaggerResponse(StatusCodes.Status200OK, "Order item retrieved", typeof(OrderItem))]
        [SwaggerResponse(StatusCodes.Status400BadRequest, "Invalid itemId format")]
        [SwaggerResponse(StatusCodes.Status404NotFound, "Order item not found")]
        [SwaggerResponse(StatusCodes.Status500InternalServerError, "Server error")]
        public async Task<IActionResult> GetById(string itemId)
        {
            var orderItem = await _service.GetByIdAsync(itemId);
            if (orderItem == null)
                throw new NotFoundException("Order item not found.");

            return Ok(orderItem);
        }

        [HttpGet("order/{orderId}")]
        [Authorize(Policy = "User")]
        [SwaggerOperation(
            Summary = "Get items for an order",
            Description = "Returns all order items linked to a specific order."
        )]
        [SwaggerResponse(StatusCodes.Status200OK, "Order items retrieved", typeof(List<OrderItem>))]
        [SwaggerResponse(StatusCodes.Status400BadRequest, "Invalid orderId format")]
        [SwaggerResponse(StatusCodes.Status404NotFound, "Order not found (if enforced upstream)")]
        [SwaggerResponse(StatusCodes.Status500InternalServerError, "Server error")]
        public async Task<IActionResult> GetByOrder(string orderId)
        {
            if (!ObjectId.TryParse(orderId, out _))
                return BadRequest(new { error = "Invalid orderId format." });

            var items = await _service.GetByOrderAsync(orderId);
            return Ok(items);
        }

        [HttpGet]
        [Authorize(Policy = "Admin")]
        [SwaggerOperation(
            Summary = "Get all order items",
            Description = "Returns a list of all order items in the system."
        )]
        [SwaggerResponse(StatusCodes.Status200OK, "Order items retrieved", typeof(List<OrderItem>))]
        [SwaggerResponse(StatusCodes.Status500InternalServerError, "Server error")]
        public async Task<IActionResult> GetAll()
        {
            return Ok(await _service.GetAllAsync());
        }

        [HttpPut("{itemId}")]
        [Authorize(Policy = "User")]
        [SwaggerOperation(
            Summary = "Update an order item",
            Description = "Updates an existing order item entirely."
        )]
        [SwaggerResponse(StatusCodes.Status200OK, "Order item updated", typeof(OrderItem))]
        [SwaggerResponse(StatusCodes.Status400BadRequest, "Invalid itemId format")]
        [SwaggerResponse(StatusCodes.Status404NotFound, "Order item not found")]
        [SwaggerResponse(StatusCodes.Status422UnprocessableEntity, "Invalid update payload")]
        [SwaggerResponse(StatusCodes.Status500InternalServerError, "Server error")]
        public async Task<IActionResult> Update(string itemId, [FromBody] OrderItem update)
        {
            var item = await _service.UpdateAsync(itemId, update);
            return item == null ? NotFound() : Ok(item);
        }

        [HttpDelete("{itemId}")]
        [Authorize(Policy = "User")]
        [SwaggerOperation(
            Summary = "Delete an order item",
            Description = "Deletes an order item by its ID."
        )]
        [SwaggerResponse(StatusCodes.Status204NoContent, "Order item deleted")]
        [SwaggerResponse(StatusCodes.Status400BadRequest, "Invalid itemId format")]
        [SwaggerResponse(StatusCodes.Status404NotFound, "Order item not found")]
        [SwaggerResponse(StatusCodes.Status500InternalServerError, "Server error")]
        public async Task<IActionResult> Delete(string itemId)
        {
            if (!ObjectId.TryParse(itemId, out _))
                return BadRequest(new { error = "Invalid itemId format." });

            var ok = await _service.DeleteAsync(itemId);
            return ok ? NoContent() : NotFound();
        }
    }
}
