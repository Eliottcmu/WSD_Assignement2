// using Bogus;
// using Bookstore.Api.Models;
// using MongoDB.Bson;
// using MongoDB.Driver;

// namespace Bookstore.Api.Data
// {
//     public class SeedData
//     {
//         private readonly IMongoDatabase _db;

//         public SeedData(IMongoDatabase db)
//         {
//             _db = db;
//         }

//         public async Task SeedAsync()
//         {
//             var users = _db.GetCollection<User>("Users");
//             var sellers = _db.GetCollection<Seller>("Sellers");
//             var books = _db.GetCollection<Book>("Books");
//             var reviews = _db.GetCollection<Review>("Reviews");
//             var comments = _db.GetCollection<Comment>("Comments");
//             var orders = _db.GetCollection<Order>("Orders");
//             var orderItems = _db.GetCollection<OrderItem>("OrderItems");

//             // Clear tables before seeding
//             await _db.DropCollectionAsync("Users");
//             await _db.DropCollectionAsync("Sellers");
//             await _db.DropCollectionAsync("Books");
//             await _db.DropCollectionAsync("Reviews");
//             await _db.DropCollectionAsync("Comments");
//             await _db.DropCollectionAsync("Orders");
//             await _db.DropCollectionAsync("OrderItems");

//             // ============================
//             // USERS (200)
//             // ============================

//             var userFaker = new Faker<User>()
//                 .RuleFor(x => x.UserId, _ => ObjectId.GenerateNewId())
//                 .RuleFor(x => x.Name, f => f.Name.FullName())
//                 .RuleFor(x => x.Email, f => f.Internet.Email())
//                 .RuleFor(x => x.Password, f => f.Internet.Password())
//                 .RuleFor(x => x.BirthDate, f => f.Date.Past(30))
//                 .RuleFor(x => x.Gender, f => f.PickRandom<Gender>())
//                 .RuleFor(x => x.Address, f => f.Address.FullAddress())
//                 .RuleFor(x => x.PhoneNumber, f => f.Phone.PhoneNumber())
//                 .RuleFor(x => x.ProfileImage, f => f.Image.PicsumUrl())
//                 .RuleFor(x => x.ReviewCount, 0)
//                 .RuleFor(x => x.IsAdmin, f => f.Random.Bool(0.1f))
//                 .RuleFor(x => x.CreatedAt, f => f.Date.Past(1))
//                 .RuleFor(x => x.UpdatedAt, f => DateTime.UtcNow);

//             var USERS = userFaker.Generate(200);
//             await users.InsertManyAsync(USERS);

//             // ============================
//             // SELLERS (50)
//             // ============================

//             var sellerFaker = new Faker<Seller>()
//                 .RuleFor(x => x.SellerId, _ => ObjectId.GenerateNewId())
//                 .RuleFor(x => x.UserId, f => f.PickRandom(USERS).UserId)
//                 .RuleFor(x => x.BusinessName, f => f.Company.CompanyName())
//                 .RuleFor(x => x.BusinessNumber, f => f.Random.Replace("########"))
//                 .RuleFor(x => x.PayoutBank, f => f.Finance.AccountName())
//                 .RuleFor(x => x.PayoutAccount, f => f.Finance.Account())
//                 .RuleFor(x => x.PayoutHolder, f => f.Name.FullName())
//                 .RuleFor(x => x.CreatedAt, f => f.Date.Past(1))
//                 .RuleFor(x => x.UpdatedAt, f => DateTime.UtcNow);

//             var SELLERS = sellerFaker.Generate(50);
//             await sellers.InsertManyAsync(SELLERS);

//             // ============================
//             // BOOKS (300)
//             // ============================

//             var bookFaker = new Faker<Book>()
//                 .RuleFor(x => x.BookId, _ => ObjectId.GenerateNewId())
//                 .RuleFor(x => x.SellerId, f => f.PickRandom(SELLERS).SellerId)
//                 .RuleFor(x => x.Title, f => f.Lorem.Sentence(3))
//                 .RuleFor(x => x.Authors, f => f.Make(1, () => f.Name.FullName()))
//                 .RuleFor(x => x.Categories, f => f.Make(2, () => f.Commerce.Categories(1).First()))
//                 .RuleFor(x => x.Publisher, f => f.Company.CompanyName())
//                 .RuleFor(x => x.Summary, f => f.Lorem.Paragraph())
//                 .RuleFor(x => x.Isbn, f => f.Random.Replace("###-##########"))
//                 .RuleFor(x => x.Price, f => decimal.Parse(f.Commerce.Price(5, 80)))
//                 .RuleFor(x => x.PublicationDate, f => f.Date.Past(5))
//                 .RuleFor(x => x.Stock, f => f.Random.Int(0, 150))
//                 .RuleFor(x => x.ReviewCount, 0)
//                 .RuleFor(x => x.AverageRating, 0.0)
//                 .RuleFor(x => x.CreatedAt, f => f.Date.Past(1))
//                 .RuleFor(x => x.UpdatedAt, f => DateTime.UtcNow);

//             var BOOKS = bookFaker.Generate(300);
//             await books.InsertManyAsync(BOOKS);

//             // ============================
//             // REVIEWS (800)
//             // ============================

//             var reviewFaker = new Faker<Review>()
//                 .RuleFor(x => x.ReviewId, _ => ObjectId.GenerateNewId())
//                 .RuleFor(x => x.BookId, f => f.PickRandom(BOOKS).BookId)
//                 .RuleFor(x => x.UserId, f => f.PickRandom(USERS).UserId)
//                 .RuleFor(x => x.Content, f => f.Lorem.Sentences(2))
//                 .RuleFor(x => x.Rating, f => f.Random.Int(1, 5))
//                 .RuleFor(x => x.LikesCount, 0)
//                 .RuleFor(x => x.CreatedAt, f => f.Date.Past(1))
//                 .RuleFor(x => x.UpdatedAt, f => DateTime.UtcNow);

//             var REVIEWS = reviewFaker.Generate(800);
//             await reviews.InsertManyAsync(REVIEWS);

//             // ============================
//             // COMMENTS (1500)
//             // ============================

//             var commentFaker = new Faker<Comment>()
//                 .RuleFor(x => x.CommentId, _ => ObjectId.GenerateNewId())
//                 .RuleFor(x => x.ReviewId, f => f.PickRandom(REVIEWS).ReviewId)
//                 .RuleFor(x => x.UserId, f => f.PickRandom(USERS).UserId)
//                 .RuleFor(x => x.Content, f => f.Lorem.Sentence())
//                 .RuleFor(x => x.CreatedAt, f => f.Date.Past(1))
//                 .RuleFor(x => x.UpdatedAt, f => DateTime.UtcNow);

//             var COMMENTS = commentFaker.Generate(1500);
//             await comments.InsertManyAsync(COMMENTS);

//             // ============================
//             // ORDERS (400)
//             // ============================

//             var orderFaker = new Faker<Order>()
//                 .RuleFor(x => x.OrderId, _ => ObjectId.GenerateNewId())
//                 .RuleFor(x => x.UserId, f => f.PickRandom(USERS).UserId)
//                 .RuleFor(x => x.CouponId, _ => null)
//                 .RuleFor(x => x.TotalAmount, f => decimal.Parse(f.Commerce.Price(10, 300)))
//                 .RuleFor(x => x.Status, f => f.PickRandom<OrderStatus>())
//                 .RuleFor(x => x.CreatedAt, f => f.Date.Past(1))
//                 .RuleFor(x => x.UpdatedAt, f => DateTime.UtcNow);

//             var ORDERS = orderFaker.Generate(400);
//             await orders.InsertManyAsync(ORDERS);

//             // ============================
//             // ORDER ITEMS (1000)
//             // ============================

//             var orderItemFaker = new Faker<OrderItem>()
//                 .RuleFor(x => x.OrderItemId, _ => ObjectId.GenerateNewId())
//                 .RuleFor(x => x.OrderId, f => f.PickRandom(ORDERS).OrderId)
//                 .RuleFor(x => x.BookId, f => f.PickRandom(BOOKS).BookId)
//                 .RuleFor(x => x.Quantity, f => f.Random.Int(1, 3))
//                 .RuleFor(x => x.Price, f => decimal.Parse(f.Commerce.Price(5, 80)))
//                 .RuleFor(x => x.CreatedAt, f => f.Date.Past(1));

//             var ORDER_ITEMS = orderItemFaker.Generate(1000);
//             await orderItems.InsertManyAsync(ORDER_ITEMS);
//         }
//     }
// }
