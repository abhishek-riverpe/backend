# NeoBank Backend

This is the FastAPI backend for the NeoBank application.

## Prerequisites

- Python 3.8+
- A running PostgreSQL database instance.

## Setup Instructions

1.  **Navigate to the `backend` directory:**

    ```bash
    cd path/to/NeoBank/backend
    ```

2.  **Create and activate a virtual environment:**

    *   On Windows:
        ```bash
        python -m venv venv
        venv\Scripts\activate
        ```
    *   On macOS/Linux:
        ```bash
        python3 -m venv venv
        source venv/bin/activate
        ```

3.  **Install dependencies:**

    ```bash
    pip install -r requirements.txt
    ```

4.  **Install Prisma client:**
    The Prisma Python client needs to be generated from your schema.

    ```bash
    prisma generate
    ```

5.  **Configure Environment Variables:**

    Copy the example environment file and configure your settings:

    ```bash
    cp .env.example .env
    ```

    Edit the `.env` file with your actual values. At minimum, you need:

    ```
    DATABASE_URL="postgresql://user:password@localhost:5432/neobank?schema=public"
    JWT_SECRET="your_super_secret_key_that_is_long_and_random"
    SESSION_SECRET="your_different_secret_key_for_session_cookies"
    
    # Zynk Labs API (Required)
    ZYNK_BASE_URL="https://qaapi.zynklabs.xyz"
    ZYNK_API_KEY="your_zynk_api_key_here"
    ZYNK_DEFAULT_ROUTING_ID="your_routing_id_here"
    ZYNK_WEBHOOK_SECRET="your_webhook_secret_from_zynk_dashboard"
    
    # Test Constants (for unit tests only)
    # These values are loaded from .env.test file (created automatically) to avoid SonarCloud security warnings
    # You can override them in .env if needed, but .env.test is recommended for test-specific values
    ```
    
    **Note:** Test configuration values are automatically loaded from `.env.test` file. This file is created automatically with default test values. The configuration system loads both `.env` and `.env.test` files, with `.env` taking precedence if there are conflicts. This separation helps avoid SonarCloud security warnings for hardcoded test values.
    
    > **Security Note:** `ZYNK_WEBHOOK_SECRET` is required for webhook signature verification. Get this from your Zynk Labs dashboard webhook configuration.
    
    > **Security Note:** `SESSION_SECRET` must be different from `JWT_SECRET` to prevent single point of failure. If one secret is compromised, the other remains secure.

    > **Important Security Notes:**
    > - Replace all placeholder values with your actual credentials
    > - Never commit the `.env` file to version control (it's already in `.gitignore`)
    > - Get your Zynk Labs API credentials from your Zynk Labs dashboard
    > - Ensure the database `neobank` exists in your PostgreSQL instance

6.  **Apply the database schema:**

    This command will sync your Prisma schema with your database, creating the necessary tables (`User` and `Account`).

    ```bash
    prisma db push
    ```

## Running the Server

Once the setup is complete, you can run the FastAPI server using Uvicorn:

```bash
uvicorn app.main:app --reload
```

The `--reload` flag enables hot-reloading, so the server will restart automatically when you make changes to the code.

The API will be available at `http://localhost:8000`. You can access the interactive API documentation (Swagger UI) at `http://localhost:8000/docs`.
