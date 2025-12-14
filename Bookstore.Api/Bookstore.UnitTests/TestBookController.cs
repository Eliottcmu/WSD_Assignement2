using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Bookstore.Api.Common;
using Bookstore.Api.Controllers;
using Bookstore.Api.Exceptions;
using Bookstore.Api.Models;
using Bookstore.Api.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using MongoDB.Bson;
using Moq;

namespace Bookstore.Api.Tests.Controllers
{
    [TestClass]
    public class TestBooksController
    {
        private List<Book> GetTestBooks()
        {
            return new List<Book>
            {
                new Book
                {
                    BookId = ObjectId.GenerateNewId(),
                    SellerId = ObjectId.GenerateNewId(),
                    Title = "The C# Guide",
                    Authors = new List<string> { "John Doe" },
                    Categories = new List<string> { "Programming", "Technology" },
                    Price = 49.99m,
                    Stock = 10,
                },
                new Book
                {
                    BookId = ObjectId.GenerateNewId(),
                    SellerId = ObjectId.GenerateNewId(),
                    Title = "Cooking with MongoDB",
                    Authors = new List<string> { "Jane Smith" },
                    Categories = new List<string> { "Cooking", "Database" },
                    Price = 29.50m,
                    Stock = 5,
                },
            };
        }

        // Tests for GET /api/books (GetAll)
        [TestMethod]
        public async Task GetAll_ShouldReturnPagedResponse_WithCorrectData()
        {
            var mockService = new Mock<BookService>();
            var testData = GetTestBooks();
            int totalItems = testData.Count;

            mockService
                .Setup(s => s.GetPagedAsync(1, 10, null))
                .ReturnsAsync((testData, totalItems));

            var controller = new BooksController(mockService.Object);

            // Act
            var result = await controller.GetAll(1, 10, null);

            // Assert
            Assert.IsInstanceOfType(result, typeof(OkObjectResult));
            var okResult = result as OkObjectResult;
            var response = okResult!.Value as PagedResponse<Book>;

            Assert.IsNotNull(response);
            Assert.AreEqual(totalItems, response.TotalItems);
            Assert.AreEqual(2, response.Items.Count);
        }

        [TestMethod]
        public async Task GetAll_ShouldThrowBadRequestException_ForInvalidPagination()
        {
            var mockService = new Mock<BookService>();
            var controller = new BooksController(mockService.Object);

            // Act & Assert for page <= 0
            await Assert.ThrowsExceptionAsync<BadRequestException>(() => controller.GetAll(0, 10));

            // Act & Assert for pageSize <= 0
            await Assert.ThrowsExceptionAsync<BadRequestException>(() => controller.GetAll(1, 0));
        }

        // Tests for GET /api/books/{id} (GetById)
        [TestMethod]
        public async Task GetById_ShouldReturnOk_WithCorrectBook()
        {
            var expectedBook = GetTestBooks()[0];
            string bookId = expectedBook.BookId.ToString();

            var mockService = new Mock<BookService>();
            mockService.Setup(s => s.GetByIdAsync(bookId)).ReturnsAsync(expectedBook);

            var controller = new BooksController(mockService.Object);

            // Act
            var result = await controller.GetById(bookId);

            // Assert
            Assert.IsInstanceOfType(result, typeof(OkObjectResult));
            var okResult = result as OkObjectResult;
            Assert.AreEqual(expectedBook, okResult!.Value);
        }

        [TestMethod]
        public async Task GetById_ShouldThrowNotFoundException_WhenBookDoesNotExist()
        {
            // Arrange
            string nonExistentId = ObjectId.GenerateNewId().ToString();

            var mockService = new Mock<BookService>();
            // Correction : Simuler le retour de null pour un ID inexistant.
            mockService.Setup(s => s.GetByIdAsync(nonExistentId)).ReturnsAsync((Book)null!);

            var controller = new BooksController(mockService.Object);

            // Act & Assert
            await Assert.ThrowsExceptionAsync<NotFoundException>(
                () => controller.GetById(nonExistentId)
            );
        }

        // Tests for POST /api/books (Create)
        [TestMethod]
        public async Task Create_ShouldReturnCreatedAtAction_WithNewBook()
        {
            // Arrange
            var newBookId = ObjectId.GenerateNewId();
            var sellerId = ObjectId.GenerateNewId();
            var createDto = new CreateBookDto
            {
                SellerId = sellerId.ToString(),
                Title = "New Book Title",
                Authors = new List<string> { "Author 1" },
                Categories = new List<string> { "Category 1" },
                Price = 10.00m,
                Stock = 5,
            };
            var mockService = new Mock<BookService>();
            mockService
                .Setup(s => s.CreateAsync(It.IsAny<Book>()))
                .Callback<Book>(book => book.BookId = newBookId)
                .Returns<Book>(book => Task.FromResult(book));

            var controller = new BooksController(mockService.Object);

            // Act
            var result = await controller.Create(createDto);

            // Assert
            Assert.IsInstanceOfType(result, typeof(CreatedAtActionResult));
            var createdResult = result as CreatedAtActionResult;

            var createdBook = createdResult!.Value as Book;
            Assert.IsNotNull(createdBook);
            Assert.AreEqual(newBookId, createdBook.BookId);
            Assert.AreEqual(createDto.Title, createdBook.Title);

            mockService.Verify(
                s =>
                    s.CreateAsync(
                        It.Is<Book>(book =>
                            book.SellerId == sellerId && book.Title == createDto.Title
                        )
                    ),
                Times.Once
            );
        }

        // Tests for PUT /api/books/{id} (Update)
        [TestMethod]
        public async Task Update_ShouldReturnNoContent_OnSuccess()
        {
            // Arrange
            var existingBook = GetTestBooks()[0];
            string bookId = existingBook.BookId.ToString();
            string newTitle = "Updated Title";
            decimal newPrice = 55.99m;

            var updateDto = new UpdateBookDto { Title = newTitle, Price = newPrice };

            var mockService = new Mock<BookService>();
            mockService.Setup(s => s.GetByIdAsync(bookId)).ReturnsAsync(existingBook);
            mockService.Setup(s => s.UpdateAsync(bookId, It.IsAny<Book>())).ReturnsAsync(true); // Succès de l'update

            var controller = new BooksController(mockService.Object);

            // Act
            var result = await controller.Update(bookId, updateDto);

            // Assert
            Assert.IsInstanceOfType(result, typeof(NoContentResult));

            mockService.Verify(
                s =>
                    s.UpdateAsync(
                        bookId,
                        It.Is<Book>(book =>
                            book.Title == newTitle
                            && book.Price == newPrice
                            && book.Stock == existingBook.Stock
                        )
                    ),
                Times.Once
            );
        }

        [TestMethod]
        public async Task Update_ShouldThrowNotFoundException_WhenBookDoesNotExist()
        {
            string nonExistentId = ObjectId.GenerateNewId().ToString();

            var mockService = new Mock<BookService>();
            mockService.Setup(s => s.GetByIdAsync(nonExistentId)).ReturnsAsync((Book)null!);

            var controller = new BooksController(mockService.Object);
            var updateDto = new UpdateBookDto();

            await Assert.ThrowsExceptionAsync<NotFoundException>(
                () => controller.Update(nonExistentId, updateDto)
            );
        }

        // Tests for DELETE /api/books/{id} (Delete)
        [TestMethod]
        public async Task Delete_ShouldReturnNoContent_OnSuccess()
        {
            string existingId = ObjectId.GenerateNewId().ToString();

            var mockService = new Mock<BookService>();
            mockService.Setup(s => s.DeleteAsync(existingId)).ReturnsAsync(true);

            var controller = new BooksController(mockService.Object);

            // Act
            var result = await controller.Delete(existingId);

            // Assert
            Assert.IsInstanceOfType(result, typeof(NoContentResult));
            mockService.Verify(s => s.DeleteAsync(existingId), Times.Once);
        }

        [TestMethod]
        public async Task Delete_ShouldThrowNotFoundException_WhenBookDoesNotExist()
        {
            string nonExistentId = ObjectId.GenerateNewId().ToString();

            var mockService = new Mock<BookService>();
            mockService.Setup(s => s.DeleteAsync(nonExistentId)).ReturnsAsync(false); // Échec de la suppression (non trouvé)

            var controller = new BooksController(mockService.Object);

            // Act & Assert
            await Assert.ThrowsExceptionAsync<NotFoundException>(
                () => controller.Delete(nonExistentId)
            );
        }
    }
}
