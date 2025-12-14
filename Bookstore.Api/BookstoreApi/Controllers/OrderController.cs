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
    [Route("api/orders")]
    public class OrdersController : ControllerBase
    {
        private readonly OrderService _orderService;

        public OrdersController(OrderService orderService)
        {
            _orderService = orderService;
        }

        [HttpPost]
        [Authorize(Policy = "User")]
        [SwaggerOperation(
            Summary = "Create a new order",
            Description = "Creates an order with items, userId, and total amount."
        )]
        [SwaggerResponse(StatusCodes.Status201Created, "Order created", typeof(Order))]
        [SwaggerResponse(StatusCodes.Status400BadRequest, "Invalid order payload")]
        [SwaggerResponse(StatusCodes.Status401Unauthorized, "Authentication required")]
        [SwaggerResponse(StatusCodes.Status403Forbidden, "Insufficient permissions")]
        [SwaggerResponse(StatusCodes.Status422UnprocessableEntity, "Invalid order data")]
        [SwaggerResponse(StatusCodes.Status500InternalServerError, "Server error")]
        public async Task<IActionResult> CreateOrder([FromBody] Order order)
        {
            var created = await _orderService.CreateOrderAsync(order);
            if (order == null)
                return NotFound();
            return CreatedAtAction(
                nameof(GetById),
                new { id = created.OrderId.ToString() },
                created
            );
        }

        [HttpGet("{id}")]
        [Authorize(Policy = "User")]
        [SwaggerOperation(
            Summary = "Get an order by ID",
            Description = "Returns the order associated with the given ID."
        )]
        [SwaggerResponse(StatusCodes.Status200OK, "Order retrieved", typeof(Order))]
        [SwaggerResponse(StatusCodes.Status400BadRequest, "Invalid orderId")]
        [SwaggerResponse(StatusCodes.Status404NotFound, "Order not found")]
        [SwaggerResponse(StatusCodes.Status500InternalServerError, "Server error")]
        public async Task<IActionResult> GetById(string id)
        {
            var order = await _orderService.GetByIdAsync(id);
            if (order == null)
                throw new NotFoundException("Order not found.");

            return Ok(order);
        }

        [HttpGet]
        [Authorize(Policy = "Admin")]
        [SwaggerOperation(
            Summary = "Get all orders",
            Description = "Returns a list of all orders in the system."
        )]
        [SwaggerResponse(StatusCodes.Status200OK, "Orders retrieved", typeof(List<Order>))]
        [SwaggerResponse(StatusCodes.Status500InternalServerError, "Server error")]
        public async Task<IActionResult> GetAll()
        {
            var orders = await _orderService.GetAllAsync();
            return Ok(orders);
        }

        [HttpPatch("{id}/status")]
        [Authorize(Policy = "Admin")]
        [SwaggerOperation(
            Summary = "Update order status",
            Description = "Updates the status of an existing order."
        )]
        [SwaggerResponse(StatusCodes.Status200OK, "Order status updated", typeof(Order))]
        [SwaggerResponse(StatusCodes.Status400BadRequest, "Invalid orderId or status")]
        [SwaggerResponse(StatusCodes.Status404NotFound, "Order not found")]
        [SwaggerResponse(StatusCodes.Status422UnprocessableEntity, "Invalid status transition")]
        [SwaggerResponse(StatusCodes.Status500InternalServerError, "Server error")]
        public async Task<IActionResult> UpdateStatus(string id, [FromBody] OrderStatus status)
        {
            var updated = await _orderService.UpdateStatusAsync(id, status);
            return updated == null ? NotFound() : Ok(updated);
        }

        [HttpPut("{id}")]
        [Authorize(Policy = "User")]
        [SwaggerOperation(
            Summary = "Update an order",
            Description = "Updates an existing order entirely."
        )]
        [SwaggerResponse(StatusCodes.Status200OK, "Order updated", typeof(Order))]
        [SwaggerResponse(StatusCodes.Status400BadRequest, "Invalid orderId or payload")]
        [SwaggerResponse(StatusCodes.Status404NotFound, "Order not found")]
        [SwaggerResponse(StatusCodes.Status422UnprocessableEntity, "Invalid order data")]
        [SwaggerResponse(StatusCodes.Status500InternalServerError, "Server error")]
        public async Task<IActionResult> Update(string id, [FromBody] Order update)
        {
            if (update == null)
                return BadRequest();

            var updated = await _orderService.UpdateAsync(id, update);
            return updated == null ? NotFound() : Ok(updated);
        }

        [HttpDelete("{id}")]
        [Authorize(Policy = "User")]
        [SwaggerOperation(
            Summary = "Delete an order",
            Description = "Deletes an order permanently."
        )]
        [SwaggerResponse(StatusCodes.Status204NoContent, "Order deleted")]
        [SwaggerResponse(StatusCodes.Status400BadRequest, "Invalid orderId")]
        [SwaggerResponse(StatusCodes.Status404NotFound, "Order not found")]
        [SwaggerResponse(StatusCodes.Status500InternalServerError, "Server error")]
        public async Task<IActionResult> Delete(string id)
        {
            var ok = await _orderService.DeleteAsync(id);
            return ok ? NoContent() : NotFound();
        }
    }
}
