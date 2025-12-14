# Bookstore API – Architecture

## 1. Overview

This repository implements a layered ASP.NET Core Web API for a bookstore system. The architecture follows a clear separation of concerns between **presentation (controllers)**, **application/services**, **domain models**, **data access**, and **cross‑cutting concerns** (security, middleware, configuration). Unit tests are isolated in a dedicated test project.

The solution is structured to support maintainability, testability, and extensibility, with explicit error handling and service abstraction.

---

## 2. Solution Structure

```
BOOKSTORE.API
│
├── Bookstore.Api.sln
│
├── BookstoreApi/                 # Main Web API project
│   ├── Controllers/              # HTTP API layer (REST endpoints)
│   ├── Services/                 # Business logic and application services
│   ├── Models/                   # Domain and DTO models
│   ├── Data/                     # Data access layer (repositories, DB context)
│   ├── Configurations/           # Application and infrastructure configuration
│   ├── Middlewares/              # Custom ASP.NET Core middlewares
│   ├── Exceptions/               # Custom exception types
│   ├── Properties/               # Launch settings
│   ├── Program.cs                # Application entry point and DI setup
│   ├── PasswordHasher.cs         # Security utility
│   ├── appsettings.Development.json
│   ├── .env / .env.example       # Environment variables
│   └── Bookstore.csproj
│
├── Bookstore.UnitTests/           # Unit test project
│   ├── TestAuthController.cs
│   ├── TestBookController.cs
│   ├── TestSellerController.cs
│   └── Bookstore.UnitTests.csproj
│
└── Bookstore.Api.http             # HTTP client test file
```

---

## 3. Layered Architecture

### 3.1 Controllers (Presentation Layer)

**Location:** `BookstoreApi/Controllers`

Responsibilities:

* Expose REST endpoints
* Validate HTTP input (route, query, body)
* Map requests to service calls
* Translate domain/application errors into HTTP responses

Controllers are thin by design: no business logic is implemented here. All processing is delegated to services.

---

### 3.2 Services (Application Layer)

**Location:** `BookstoreApi/Services`

Responsibilities:

* Implement business rules
* Orchestrate calls between repositories and utilities
* Enforce application-level validation
* Provide a testable abstraction for controllers

This layer is the core of the application logic and is heavily used by unit tests.

---

### 3.3 Models (Domain & DTO Layer)

**Location:** `BookstoreApi/Models`

Responsibilities:

* Represent domain entities (e.g. Book, User, Seller)
* Define request/response DTOs if separated from domain models

Models are framework-agnostic and should not depend on ASP.NET Core types.

---

### 3.4 Data (Persistence Layer)

**Location:** `BookstoreApi/Data`

Responsibilities:

* Handle database access
* Encapsulate persistence logic (repositories, collections, contexts)
* Abstract the underlying storage technology from services

This layer isolates infrastructure concerns from business logic.

---

### 3.5 Middleware (Cross-Cutting Concerns)

**Location:** `BookstoreApi/Middlewares`

Responsibilities:

* Global exception handling
* Request/response processing
* Authentication/authorization hooks (if applicable)

Middlewares are registered in `Program.cs` and apply to all incoming HTTP requests.

---

### 3.6 Exceptions

**Location:** `BookstoreApi/Exceptions`

Responsibilities:

* Define custom exception types (e.g. NotFound, Unauthorized, Validation)
* Provide semantic error signaling between layers

Exceptions are caught and translated into HTTP responses by middleware.

---

### 3.7 Configuration

**Location:** `BookstoreApi/Configurations`, `appsettings*.json`, `.env`

Responsibilities:

* Environment-specific configuration
* External service and database settings
* Security-related parameters (keys, tokens)

Configuration is injected via the ASP.NET Core configuration system.

---

## 4. Security Components

### 4.1 PasswordHasher

**File:** `PasswordHasher.cs`

Responsibilities:

* Hash and verify user passwords
* Isolate cryptographic logic from services

This component is used by authentication-related services and controllers.

---

## 5. Application Entry Point

### Program.cs

Responsibilities:

* Configure dependency injection
* Register controllers, services, and middleware
* Configure authentication, authorization, and routing
* Build and run the ASP.NET Core application

`Program.cs` defines the runtime composition of the entire application.

---

## 6. Testing Architecture

### Unit Tests

**Project:** `Bookstore.UnitTests`

Characteristics:

* Separate project from the API
* Focused on controllers and service behavior
* Uses test doubles or in-memory data where applicable

Tests validate:

* HTTP behavior of controllers
* Correct interaction with services
* Error handling and edge cases

---

## 7. Architectural Principles

* **Separation of concerns**: each layer has a single responsibility
* **Dependency inversion**: controllers depend on services, not implementations
* **Testability**: business logic isolated from infrastructure
* **Explicit error handling**: domain errors propagated via exceptions

This architecture is suitable for medium-scale APIs and can evolve toward clean architecture or hexagonal architecture if needed.

