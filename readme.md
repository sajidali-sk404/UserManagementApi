# 🛡️ User Management API

A secure, minimalistic RESTful API built with ASP.NET Core for managing users. This project demonstrates production-grade practices including JWT authentication, custom middleware for error handling and logging, and clean endpoint design.

---

## 🚀 Features

- ✅ JWT-based authentication
- ✅ Custom error-handling middleware
- ✅ Custom authentication middleware
- ✅ Request/response logging
- ✅ Role-based access control (optional)
- ✅ In-memory user store
- ✅ Swagger UI for testing

---

## 🧱 Tech Stack

- ASP.NET Core 7 / .NET 7
- Minimal APIs
- JWT (JSON Web Tokens)
- ConcurrentDictionary for thread-safe storage
- Swagger (Swashbuckle)

---

## 🔐 Authentication Flow

1. **Sign Up**: Register a new user with username, password, name, and email.
2. **Login**: Authenticate with credentials and receive a JWT token.
3. **Protected Endpoints**: Access user management routes using the token.

---

## 📦 Endpoints

### 🔑 Auth

| Method | Endpoint     | Description        |
|--------|--------------|--------------------|
| POST   | `/signup`    | Register a new user |
| POST   | `/login`     | Authenticate and get JWT |

### 👥 Users

| Method | Endpoint        | Description             |
|--------|------------------|-------------------------|
| GET    | `/users`         | Get all users (auth required) |
| GET    | `/users/{id}`    | Get user by ID (auth required) |
| POST   | `/users`         | Add new user (auth required) |
| PUT    | `/users/{id}`    | Update user (auth required) |
| DELETE | `/users/{id}`    | Delete user (auth required) |

---

## 🧪 Testing

Use tools like Postman, Swagger UI, or VS Code REST Client to test:

- Valid and invalid tokens
- Missing tokens
- Triggering exceptions
- Role-based access (if implemented)

---

## 🧰 Setup Instructions

1. Clone the repo:
   ```bash
   git clone https://github.com/your-username/UserManagementAPI.git
   cd UserManagementAPI
2. Restore packages:
   ```bash 
    dotnet restore
3. dotnet restore:
    ```bash
    dotnet run
4. Open Swagger UI:
    ```bash
    http://localhost:5000/swagger
## 📁 Project Structure
```
UserManagementAPI/
│
├── Program.cs
├── README.md
