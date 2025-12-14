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
    public class TestSellersController
    {
        private List<Seller> GetTestSellers()
        {
            return new List<Seller>
            {
                new Seller
                {
                    SellerId = ObjectId.GenerateNewId(),
                    UserId = ObjectId.GenerateNewId(),
                    BusinessName = "Biz1",
                    BusinessNumber = "111",
                    PayoutBank = "Bank1",
                    PayoutAccount = "Acc1",
                    PayoutHolder = "Hold1",
                },
                new Seller
                {
                    SellerId = ObjectId.GenerateNewId(),
                    UserId = ObjectId.GenerateNewId(),
                    BusinessName = "Biz2",
                    BusinessNumber = "222",
                    PayoutBank = "Bank2",
                    PayoutAccount = "Acc2",
                    PayoutHolder = "Hold2",
                },
            };
        }

        // Tests for GET /api/sellers (GetAll)
        [TestMethod]
        public async Task GetAll_ShouldReturnPagedResponse_WithCorrectData()
        {
            var mockService = new Mock<SellerService>();
            var testData = GetTestSellers();

            mockService
                .Setup(s => s.GetPagedAsync(1, 10, null))
                .ReturnsAsync((testData, testData.Count));

            var controller = new SellersController(mockService.Object);

            var result = await controller.GetAll(1, 10, null);

            Assert.IsInstanceOfType(result, typeof(OkObjectResult));
            var okResult = result as OkObjectResult;
            var response = okResult.Value as PagedResponse<Seller>;
            Assert.AreEqual(2, response.TotalItems);
        }

        [TestMethod]
        public async Task GetAll_ShouldThrowBadRequestException_ForInvalidPagination()
        {
            // Arrange
            var mockService = new Mock<SellerService>();
            var controller = new SellersController(mockService.Object);

            // Act & Assert for page <= 0
            await Assert.ThrowsExceptionAsync<BadRequestException>(() => controller.GetAll(0, 10));

            // Act & Assert for pageSize <= 0
            await Assert.ThrowsExceptionAsync<BadRequestException>(() => controller.GetAll(1, 0));
        }

        // Tests for GET /api/sellers/{id} (GetById)
        [TestMethod]
        public async Task GetById_ShouldReturnOk_WithCorrectSeller()
        {
            // Arrange
            var expectedSeller = GetTestSellers()[0];
            string sellerId = expectedSeller.SellerId.ToString();

            var mockService = new Mock<SellerService>();
            mockService.Setup(s => s.GetByIdAsync(sellerId)).ReturnsAsync(expectedSeller);

            var controller = new SellersController(mockService.Object);

            // Act
            var result = await controller.GetById(sellerId);

            // Assert
            Assert.IsInstanceOfType(result, typeof(OkObjectResult));
            var okResult = result as OkObjectResult;
            Assert.AreEqual(expectedSeller, okResult.Value);
        }

        [TestMethod]
        public async Task GetById_ShouldThrowNotFoundException_WhenSellerDoesNotExist()
        {
            // Arrange
            string nonExistentId = ObjectId.GenerateNewId().ToString();

            var mockService = new Mock<SellerService>();
            mockService.Setup(s => s.GetByIdAsync(nonExistentId)).ReturnsAsync((Seller)null);

            var controller = new SellersController(mockService.Object);

            // Act & Assert
            await Assert.ThrowsExceptionAsync<NotFoundException>(
                () => controller.GetById(nonExistentId)
            );
        }

        [TestMethod]
        public async Task GetById_ShouldThrowBadRequestException_ForInvalidIdFormat()
        {
            // Arrange
            string invalidId = "not-a-valid-object-id";
            var mockService = new Mock<SellerService>();
            var controller = new SellersController(mockService.Object);

            // Act & Assert
            await Assert.ThrowsExceptionAsync<BadRequestException>(
                () => controller.GetById(invalidId)
            );
        }

        // Tests for POST /api/sellers (Create)
        [TestMethod]
        public async Task Create_ShouldReturnCreatedAtAction_WithNewSeller()
        {
            // Arrange
            var newSellerId = ObjectId.GenerateNewId();
            var newUserId = ObjectId.GenerateNewId();
            var createDto = new CreateSellerDto
            {
                UserId = newUserId.ToString(),
                BusinessName = "New Biz",
                BusinessNumber = "NB01",
                PayoutBank = "New Bank",
                PayoutAccount = "New Acc",
                PayoutHolder = "New Holder",
            };

            var mockService = new Mock<SellerService>();
            mockService
                .Setup(s => s.CreateAsync(It.IsAny<Seller>()))
                .Callback<Seller>(s => s.SellerId = newSellerId) // Simulate setting the ID in the service
                .Returns<Seller>(s => Task.FromResult(s));

            var controller = new SellersController(mockService.Object);

            // Act
            var result = await controller.Create(createDto);

            // Assert
            Assert.IsInstanceOfType(result, typeof(CreatedAtActionResult));
            var createdResult = result as CreatedAtActionResult;
            Assert.AreEqual(nameof(controller.GetById), createdResult.ActionName);

            var createdSeller = createdResult.Value as Seller;
            Assert.IsNotNull(createdSeller);
            Assert.AreEqual(newSellerId, createdSeller.SellerId);
            Assert.AreEqual(createDto.BusinessName, createdSeller.BusinessName);

            mockService.Verify(
                s =>
                    s.CreateAsync(
                        It.Is<Seller>(seller =>
                            seller.UserId == newUserId
                            && seller.BusinessName == createDto.BusinessName
                        )
                    ),
                Times.Once
            );
        }

        [TestMethod]
        public async Task Create_ShouldThrowBadRequestException_ForInvalidUserIdFormat()
        {
            // Arrange
            var mockService = new Mock<SellerService>();
            var controller = new SellersController(mockService.Object);
            var createDto = new CreateSellerDto
            {
                UserId = "invalid-user-id",
                BusinessName = "New Biz",
                BusinessNumber = "NB01",
                PayoutBank = "New Bank",
                PayoutAccount = "New Acc",
                PayoutHolder = "New Holder",
            };

            // Act & Assert
            await Assert.ThrowsExceptionAsync<BadRequestException>(
                () => controller.Create(createDto)
            );
        }

        // Tests for PUT /api/sellers/{id} (Update)
        [TestMethod]
        public async Task Update_ShouldReturnNoContent_OnSuccess()
        {
            // Arrange
            var existingSeller = GetTestSellers()[0];
            string sellerId = existingSeller.SellerId.ToString();
            var updateDto = new UpdateSellerDto
            {
                BusinessName = "Updated Biz Name",
                PayoutBank = "Updated Bank",
            };

            var mockService = new Mock<SellerService>();
            mockService.Setup(s => s.GetByIdAsync(sellerId)).ReturnsAsync(existingSeller);
            mockService.Setup(s => s.UpdateAsync(sellerId, It.IsAny<Seller>())).ReturnsAsync(true); // Simulate successful update

            var controller = new SellersController(mockService.Object);

            // Act
            var result = await controller.Update(sellerId, updateDto);

            // Assert
            Assert.IsInstanceOfType(result, typeof(NoContentResult));

            // Verify update was called and properties were correctly merged
            mockService.Verify(
                s =>
                    s.UpdateAsync(
                        sellerId,
                        It.Is<Seller>(s =>
                            s.BusinessName == updateDto.BusinessName
                            && // Updated
                            s.PayoutBank == updateDto.PayoutBank
                            && // Updated
                            s.BusinessNumber == existingSeller.BusinessNumber // Unchanged
                        )
                    ),
                Times.Once
            );
        }

        [TestMethod]
        public async Task Update_ShouldThrowBadRequestException_ForInvalidIdFormat()
        {
            // Arrange
            string invalidId = "not-an-id";
            var mockService = new Mock<SellerService>();
            var controller = new SellersController(mockService.Object);
            var updateDto = new UpdateSellerDto();

            // Act & Assert
            await Assert.ThrowsExceptionAsync<BadRequestException>(
                () => controller.Update(invalidId, updateDto)
            );
        }

        [TestMethod]
        public async Task Update_ShouldThrowNotFoundException_WhenSellerDoesNotExist()
        {
            // Arrange
            string nonExistentId = ObjectId.GenerateNewId().ToString();

            var mockService = new Mock<SellerService>();
            mockService.Setup(s => s.GetByIdAsync(nonExistentId)).ReturnsAsync((Seller)null);

            var controller = new SellersController(mockService.Object);
            var updateDto = new UpdateSellerDto();

            // Act & Assert
            await Assert.ThrowsExceptionAsync<NotFoundException>(
                () => controller.Update(nonExistentId, updateDto)
            );
        }

        // Tests for DELETE /api/sellers/{id} (Delete)
        [TestMethod]
        public async Task Delete_ShouldReturnNoContent_OnSuccess()
        {
            // Arrange
            string existingId = ObjectId.GenerateNewId().ToString();

            var mockService = new Mock<SellerService>();
            mockService.Setup(s => s.DeleteAsync(existingId)).ReturnsAsync(true); // Simulate successful deletion

            var controller = new SellersController(mockService.Object);

            // Act
            var result = await controller.Delete(existingId);

            // Assert
            Assert.IsInstanceOfType(result, typeof(NoContentResult));
            mockService.Verify(s => s.DeleteAsync(existingId), Times.Once);
        }

        [TestMethod]
        public async Task Delete_ShouldThrowBadRequestException_ForInvalidIdFormat()
        {
            // Arrange
            string invalidId = "not-an-id";
            var mockService = new Mock<SellerService>();
            var controller = new SellersController(mockService.Object);

            // Act & Assert
            await Assert.ThrowsExceptionAsync<BadRequestException>(
                () => controller.Delete(invalidId)
            );
        }

        [TestMethod]
        public async Task Delete_ShouldThrowNotFoundException_WhenSellerDoesNotExist()
        {
            // Arrange
            string nonExistentId = ObjectId.GenerateNewId().ToString();

            var mockService = new Mock<SellerService>();
            mockService.Setup(s => s.DeleteAsync(nonExistentId)).ReturnsAsync(false); // Simulate deletion failed (e.g., not found)

            var controller = new SellersController(mockService.Object);

            // Act & Assert
            await Assert.ThrowsExceptionAsync<NotFoundException>(
                () => controller.Delete(nonExistentId)
            );
        }
    }
}
