# Use an official Node.js runtime as a parent image
FROM node:18-alpine

# Set the working directory in the container
WORKDIR /app

# Copy package.json and package-lock.json (if exists) to the working directory
# This step is done separately to leverage Docker's layer caching
COPY package*.json ./

# Install app dependencies
RUN npm install

# Copy the rest of the application code to the working directory
# This includes server.js and the entire public/ directory
COPY . .

# Expose the port your Express app is listening on
# Your server.js listens on process.env.PORT or 3000
EXPOSE 3000

# Command to run the application
# 'npm start' is defined in your package.json to run 'node server.js'
CMD [ "npm", "start" ]
