using Bookstore.Api.Data;
using Bookstore.Api.Exceptions;
using Bookstore.Api.Models;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using MongoDB.Bson;
using MongoDB.Driver;

namespace Bookstore.Api.Services
{
    public class OrderService
    {
        private readonly IMongoCollection<Order> _orders;

        public OrderService(MongoDbContext db)
        {
            _orders = db.Orders;
        }

        public async Task<Order> CreateOrderAsync(Order order)
        {
            order.CreatedAt = DateTime.UtcNow;
            order.UpdatedAt = DateTime.UtcNow;

            await _orders.InsertOneAsync(order);
            return order;
        }

        public async Task<Order?> GetByIdAsync(string orderId)
        {
            var idStr = orderId.ToString();
            return await _orders.Find(o => o.OrderId == idStr).FirstOrDefaultAsync();
        }

        public async Task<IEnumerable<Order>> GetAllAsync()
        {
            return await _orders.Find(_ => true).ToListAsync();
        }

        public async Task<Order?> UpdateStatusAsync(string orderId, OrderStatus status)
        {
            var idStr = orderId.ToString();

            var update = Builders<Order>
                .Update.Set(o => o.Status, status)
                .Set(o => o.UpdatedAt, DateTime.UtcNow);

            var result = await _orders.FindOneAndUpdateAsync(
                o => o.OrderId == idStr,
                update,
                new FindOneAndUpdateOptions<Order> { ReturnDocument = ReturnDocument.After }
            );

            return result;
        }

        public async Task<Order?> UpdateAsync(string id, Order update)
        {
            if (!ObjectId.TryParse(id, out _))
                throw new BadRequestException("Invalid orderId.");

            update.OrderId = id;
            update.UpdatedAt = DateTime.UtcNow;

            return await _orders.FindOneAndReplaceAsync(
                o => o.OrderId == id,
                update,
                new FindOneAndReplaceOptions<Order> { ReturnDocument = ReturnDocument.After }
            );
        }

        public async Task<bool> DeleteAsync(string orderId)
        {
            var idStr = orderId.ToString();

            var result = await _orders.DeleteOneAsync(o => o.OrderId == idStr);
            return result.DeletedCount > 0;
        }
    }
}
