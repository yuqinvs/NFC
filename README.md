# NFC Product Verification System

A comprehensive NFC-based product verification system that allows users to verify product authenticity by scanning NFC codes.

## Features

- **Product Verification**: Scan NFC codes to verify product authenticity
- **Admin Dashboard**: Manage products and view statistics
- **Batch Import**: Import products via Excel files
- **Global Support**: Multi-country user tracking
- **Security**: Rate limiting and secure authentication
- **Responsive Design**: Mobile-friendly interface

## Technology Stack

- **Backend**: Node.js + Express
- **Database**: SQLite
- **Frontend**: HTML5 + CSS3 + JavaScript
- **File Processing**: Excel file import support
- **Security**: JWT authentication, rate limiting

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd nfc-verification-system
```

2. Install dependencies:
```bash
npm install
```

3. Configure environment variables:
```bash
cp .env.example .env
# Edit .env file with your configuration
```

4. Start the server:
```bash
npm start
```

5. Access the application:
- Main page: http://localhost:3000
- Admin login: http://localhost:3000/admin-login

## Usage

### For Users
1. Visit the main page
2. Enter the NFC code in the input field
3. Click "Verify Product" to check authenticity
4. View verification results

### For Administrators
1. Access the admin login page
2. Login with admin credentials
3. View system statistics
4. Add new products individually or via Excel import
5. Monitor user activity by country

## API Endpoints

- `POST /api/verify` - Verify product by NFC code
- `POST /api/admin/login` - Admin authentication
- `GET /api/admin/stats` - Get system statistics
- `POST /api/admin/products` - Add new product
- `POST /api/admin/products/import` - Batch import products

## File Structure

```
├── server.js              # Main server file
├── package.json           # Dependencies and scripts
├── .env.          # Environment variables template
├── database.db           # SQLite database
└── public/               # Static files
    ├── index.html        # Main verification page
    ├── verify.html       # Verification results page
    ├── admin-login.html  # Admin login page
    ├── admin-dashboard.html # Admin dashboard
    ├── styles.css        # Stylesheet
    ├── script.js         # Client-side JavaScript
    └── logo.png          # Application logo
```

## Environment Variables

- `PORT` - Server port (default: 3000)
- `ADMIN_USERNAME` - Admin username
- `ADMIN_PASSWORD` - Admin password
- `JWT_SECRET` - JWT signing secret

## Security Features

- Rate limiting (100 requests per 15 minutes per IP)
- JWT-based admin authentication
- Input validation and sanitization
- SQL injection prevention
- XSS protection headers

## License

This project is licensed under the MIT License.