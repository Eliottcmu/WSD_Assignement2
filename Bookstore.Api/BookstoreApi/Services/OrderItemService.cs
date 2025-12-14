using Bookstore.Api.Data;
using Bookstore.Api.Models;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using MongoDB.Bson;
using MongoDB.Driver;

namespace Bookstore.Api.Services
{
    public class OrderItemService
    {
        private readonly IMongoCollection<OrderItem> _orderItems;

        public OrderItemService(MongoDbContext context)
        {
            _orderItems = context.Database.GetCollection<OrderItem>("order_items");
        }

        public async Task<OrderItem> CreateAsync(OrderItem item)
        {
            item.CreatedAt = DateTime.UtcNow;
            await _orderItems.InsertOneAsync(item);
            return item;
        }

        public async Task<OrderItem?> GetByIdAsync(string itemId)
        {
            return await _orderItems.Find(x => x.OrderItemId == itemId).FirstOrDefaultAsync();
        }

        public async Task<List<OrderItem>> GetByOrderAsync(string orderId)
        {
            return await _orderItems.Find(x => x.OrderId == orderId).ToListAsync();
        }

        public async Task<List<OrderItem>> GetAllAsync()
        {
            return await _orderItems.Find(_ => true).ToListAsync();
        }

        public async Task<OrderItem?> UpdateAsync(string id, OrderItem updated)
        {
            updated.OrderItemId = id;

            var options = new FindOneAndReplaceOptions<OrderItem>
            {
                ReturnDocument = ReturnDocument.After,
            };

            var result = await _orderItems.FindOneAndReplaceAsync(
                item => item.OrderItemId == id,
                updated,
                options
            );

            return result;
        }

        public async Task<bool> DeleteAsync(string itemId)
        {
            var result = await _orderItems.DeleteOneAsync(x => x.OrderItemId == itemId);
            return result.DeletedCount > 0;
        }
    }
}
