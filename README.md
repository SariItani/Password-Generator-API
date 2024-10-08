# Password Generator API
 API Endpoint partial project for Two Of US internship completion.

# # Encryption API with Express.js

This project implements a custom encryption algorithm in Node.js and provides an API endpoint to generate encrypted passwords. The algorithm was originally written in Java and has been translated into JavaScript for use in this project.

## Directory Structure

The directory structure of the project is as follows:

│
├── app.js # Main application script
├── package.json # Project metadata and dependencies
└── node_modules/ # Installed dependencies (auto-generated)


## How the Code Works

### 1. **app.js**

The `app.js` file contains the implementation of the encryption algorithm and the Express.js server.

- **Encryption Functions**: 
  - **`rotator()`**: Generates a series of rotation shifts based on the key length.
  - **`getShift()`**: Retrieves a shift value from the array of rotation gears.
  - **`encodeString()` and `decodeString()`**: Convert strings to bit arrays and vice versa.
  - **`not()`**: Simple bit inversion function.
  - **`getMultiple()`**: Calculates a multiple for padding the key length.
  - **`encrypt()`**: The main encryption function that applies the custom algorithm to a given password.

- **Express Server**:
  - **POST `/generate-password`**: This endpoint accepts a password string (or generates a random one) and returns the encrypted password.

### 2. **package.json**

The `package.json` file is automatically generated by `npm init` and includes project metadata and dependencies. It includes:
- `express`: A lightweight web framework for Node.js, used to create the API server.

## Installation and Running the Project

### Prerequisites

- **Node.js** and **npm** must be installed on your machine. You can check if they are installed by running:
  node -v
  npm -v

## Steps to Set Up the Project

### 1. Clone the Repository (if using version control):

git clone https://github.com/yourusername/your-repo-name.git
cd your-repo-name

### 2. Initialize the Project:
If you haven't done this yet, you can initialize a new Node.js project:

npm init -y

### 3. Install Dependencies:
Install the required Node.js packages:

npm install express

### 4. Create app.js:
Create and edit the app.js file with the provided encryption code.

touch app.js
nano app.js

Paste the provided JavaScript code into the app.js file, save, and exit.

### 5. Run the Server:
Start the server with:

node app.js

The server will run on http://localhost:3000.

## Testing the API
You can test the API using curl, Postman, or any other API testing tool.

Example Request with curl:
To encrypt a provided password:

curl -X POST -H "Content-Type: application/json" -d '{"password": "yourPassword"}' http://localhost:3000/generate-password

To generate and encrypt a random password:

curl -X POST http://localhost:3000/generate-password

### Response Format
The response from the API will be a JSON object with the encrypted password:

{
  "encryptedPassword": "encrypted_string_here"
}
