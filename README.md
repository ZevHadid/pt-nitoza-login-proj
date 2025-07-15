# PT-Nitoza Login Project

Simple NestJS auth API using MongoDB and JWT (access + refresh tokens stored in HTTP-only cookies).

## Setup

1. Clone the repo:

   ```
   git clone https://github.com/ZevHadid/pt-nitoza-login-proj.git
   ```

3. Go to the backend directory:

   ```
   cd pt-nitoza-login-proj
   ```

5. Install dependencies:

   ```
   npm install
   ```

7. Create a .env file:

   ```
   MONGO_URI=mongodb://localhost:27017/nitoza-db
   JWT_ACCESS_SECRET=your_access_secret
   JWT_REFRESH_SECRET=your_refresh_secret
   ```

8. Start the MongoDB server (you can use MongoDB Compass or your local mongod process).

9. Start the NestJS server:

   ```
   npm run start:dev
   ```

## API Routes

POST /register    - Create a new user
POST /login       - Login and set JWT cookies
POST /refresh     - Get new tokens using refresh cookie
POST /logout      - Clear auth cookies and logout
GET  /status      - Check if user is logged in

## Notes

- Access token expires in 15 minutes.
- Refresh token expires in 7 days.
- Cookies are HTTP-only for better security.
