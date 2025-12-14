# Bookstore API

## Project Overview

### Problem Definition

The Bookstore API provides a backend service for managing an online bookstore ecosystem. It centralizes authentication, user management, catalog management (books, sellers), transactional workflows (orders and order items), and community interactions (reviews and comments), while enforcing role-based access control and JWT-based security.

### Key Features

* JWT authentication with access and refresh tokens
* Role-based authorization (ROLE_USER, ROLE_ADMIN)
* CRUD operations for books, sellers, users, orders, order items, reviews, and comments
* Like/unlike mechanism for reviews and comments
* Pagination support for large collections
* MongoDB persistence
* Centralized exception handling middleware
* Swagger/OpenAPI documentation
* Health check endpoint for monitoring

---

## Deployment Address (JCloud)

* **Base URL**: `http://113.198.66.75:18164`
* **Swagger UI**: `http://113.198.66.75:18164/swagger`
* **Health Check**: `http://113.198.66.75:18164/health` 
---

## Environment Variable Descriptions (matching `.env.example`)

| Variable                            | Description                                        |
| ----------------------------------- | -------------------------------------------------- |
| `ASPNETCORE_ENVIRONMENT`            | Application environment (Development / Production) |
| `Jwt__Key`                          | Secret key used to sign JWT tokens                 |
| `Jwt__Issuer`                       | JWT token issuer                                   |
| `Jwt__Audience`                     | JWT token audience                                 |
| `Jwt__AccessTokenExpirationMinutes` | Access token lifetime                              |
| `Jwt__RefreshTokenExpirationDays`   | Refresh token lifetime                             |
| `MongoDbSettings__ConnectionString` | MongoDB connection string                          |
| `MongoDbSettings__DatabaseName`     | MongoDB database name                              |

---

## Authentication Flow

1. User submits credentials via `POST /api/auth/login`
2. API validates credentials and returns:

   * Access token (JWT)
   * Refresh token
3. Client includes the access token in subsequent requests:

   * `Authorization: Bearer <token>`
4. When the access token expires:

   * Client calls `POST /api/auth/refresh`
5. Logout invalidates the refresh token using `POST /api/auth/logout`

---

## Roles and Authorization Matrix

| Endpoint Category               | ROLE_USER     | ROLE_ADMIN |
| ------------------------------- | ------------- | ---------- |
| Auth (login, refresh, logout)   | ✓             | ✓          |
| Books (GET)                     | ✓             | ✓          |
| Books (POST, PUT, DELETE)       | ✗             | ✓          |
| Reviews & Comments (CRUD, like) | ✓             | ✓          |
| Orders & OrderItems             | ✓ (own scope) | ✓          |
| Sellers (CRUD)                  | ✗             | ✓          |
| Users (CRUD)                    | ✗             | ✓          |
| Health                          | ✓             | ✓          |

---

## Example Accounts

| Role  | Email                                         | Password  | Notes                      |
| ----- | --------------------------------------------- | --------- | -------------------------- |
| User  | [user1@example.com](mailto:user1@example.com) | P@ssw0rd! | Standard user permissions  |
| Admin | [admin@example.com](mailto:admin@example.com) | P@ssw0rd! | Full administrative access |

---

## Database Connection Information (Testing)

* **Database**: MongoDB
* **Host**: Provided via `MongoDbSettings__ConnectionString`
* **Port**: Managed by MongoDB Atlas / provider
* **Database Name**: Configurable via environment variable
* **Permissions**:

  * Read/Write access to application collections
  * No administrative cluster-level privileges required

---

## Endpoint Summary

### Authentication

| Method | URL               | Description       |
| ------ | ----------------- | ----------------- |
| POST   | /api/auth/login   | User login        |
| POST   | /api/auth/logout  | Logout user       |
| POST   | /api/auth/refresh | Refresh JWT token |

### Books

| Method | URL             | Description                 |
| ------ | --------------- | --------------------------- |
| GET    | /api/books      | Get paginated list of books |
| POST   | /api/books      | Create a new book           |
| GET    | /api/books/{id} | Get book by ID              |
| PUT    | /api/books/{id} | Update book                 |
| DELETE | /api/books/{id} | Delete book                 |

### Reviews & Comments

| Method | URL                                               | Description           |
| ------ | ------------------------------------------------- | --------------------- |
| GET    | /api/reviews                                      | Get all reviews       |
| POST   | /api/reviews                                      | Create review         |
| GET    | /api/reviews/{id}                                 | Get review by ID      |
| PUT    | /api/reviews/{id}                                 | Update review         |
| DELETE | /api/reviews/{id}                                 | Delete review         |
| GET    | /api/reviews/top                                  | Get top reviews       |
| POST   | /api/reviews/{id}/like                            | Toggle like on review |
| GET    | /api/reviews/{reviewId}/comments                  | Get comments          |
| POST   | /api/reviews/{reviewId}/comments                  | Create comment        |
| PUT    | /api/reviews/{reviewId}/comments/{commentId}      | Update comment        |
| DELETE | /api/reviews/{reviewId}/comments/{commentId}      | Delete comment        |
| POST   | /api/reviews/{reviewId}/comments/{commentId}/like | Like comment          |
| DELETE | /api/reviews/{reviewId}/comments/{commentId}/like | Unlike comment        |

### Orders & OrderItems

| Method | URL                             | Description          |
| ------ | ------------------------------- | -------------------- |
| POST   | /api/orders                     | Create order         |
| GET    | /api/orders                     | Get all orders       |
| GET    | /api/orders/{id}                | Get order by ID      |
| PUT    | /api/orders/{id}                | Update order         |
| DELETE | /api/orders/{id}                | Delete order         |
| PATCH  | /api/orders/{id}/status         | Update order status  |
| POST   | /api/orderitems                 | Create order item    |
| GET    | /api/orderitems                 | Get all order items  |
| GET    | /api/orderitems/{itemId}        | Get order item by ID |
| PUT    | /api/orderitems/{itemId}        | Update order item    |
| DELETE | /api/orderitems/{itemId}        | Delete order item    |
| GET    | /api/orderitems/order/{orderId} | Get items by order   |

### Sellers & Users

| Method | URL                    | Description              |
| ------ | ---------------------- | ------------------------ |
| GET    | /api/sellers           | Get sellers              |
| POST   | /api/sellers           | Create seller            |
| PUT    | /api/sellers/{id}      | Update seller            |
| DELETE | /api/sellers/{id}      | Delete seller            |
| GET    | /api/users             | Get users                |
| POST   | /api/users             | Create user              |
| PUT    | /api/users/{id}        | Update user              |
| DELETE | /api/users/{id}        | Delete user              |
| GET    | /api/users/check-email | Check email availability |

---

## Execution Methods

### Local Execution

1. **Install Dependencies**

   ```bash
   dotnet restore
   ```

2. **Environment Setup**

   ```bash
   cp .env.example .env
   ```

   Update JWT and MongoDB values.

3. **Run Application**

   ```bash
   dotnet run
   ```

4. **Access Swagger**

   * `http://localhost:<port>/swagger`

---

## Performance and Security Considerations

* JWT expiration and refresh strategy limits token abuse
* Role-based authorization policies enforced at controller level
* MongoDB indexes recommended on:

  * User email
  * Review likes
  * Order status
* Centralized exception handling prevents information leakage
* Clock skew disabled to avoid token replay window

---

## Limitations and Improvement Plans

* No rate limiting implemented (future: API Gateway / middleware)
* No caching for read-heavy endpoints (future: Redis)
* Limited audit logging (future: structured logging with correlation IDs)
* No automated database migration tooling for MongoDB
* No CI/CD pipeline integration yet
