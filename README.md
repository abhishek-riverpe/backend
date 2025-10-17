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

    Make sure you have a `.env` file in the `backend` directory with the following content:

    ```
    DATABASE_URL="postgresql://user:password@localhost:5432/neobank?schema=public"
    JWT_SECRET="your_super_secret_key_that_is_long_and_random"
    ```

    > **Note:** Replace `"postgresql://user:password@localhost:5432/neobank?schema=public"` with your actual PostgreSQL connection string. Ensure the database `neobank` exists in your PostgreSQL instance.

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
