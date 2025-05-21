# Document Management System

A secure and user-friendly document management system built with Flask and MySQL.

## Features

- User authentication with email/password
- Two-factor authentication (2FA)
- Dark/Light mode support
- Document upload and management
- Secure file storage
- User activity logging
- Admin dashboard

## Prerequisites

- Python 3.8 or higher
- XAMPP (for MySQL database)
- pip (Python package manager)

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd document-management-system
```

2. Create a virtual environment:
```bash
python -m venv venv
```

3. Activate the virtual environment:
- Windows:
```bash
venv\Scripts\activate
```
- Linux/Mac:
```bash
source venv/bin/activate
```

4. Install dependencies:
```bash
pip install -r requirements.txt
```

5. Set up the database:
- Start XAMPP and ensure MySQL service is running
- Open phpMyAdmin (http://localhost/phpmyadmin)
- Create a new database named `secure_docs`

6. Initialize the database:
```bash
flask db init
flask db migrate
flask db upgrade
```

## Running the Application

1. Make sure XAMPP is running with MySQL service started

2. Run the Flask application:
```bash
flask run
```

3. Access the application at http://127.0.0.1:5000

## Default Admin Account

- Email: admin@securedocs.com
- Password: Admin@123

## Security Features

- Password hashing using Werkzeug
- Two-factor authentication
- Secure session management
- File encryption
- Activity logging
- Audit trails

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details. 