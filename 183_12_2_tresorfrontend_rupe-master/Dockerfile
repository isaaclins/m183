# Step one

# Build Stage: Node.js wird verwendet, um die App zu bauen
FROM node:14 AS build

# Set working directory
WORKDIR /App

# copy package.json and package-lock.json
COPY package*.json /App/

# install Node.js-dependencies
RUN npm install

# copy application files
COPY . /App/

# build the app
RUN npm run build

# Step two

# Serve Stage: use Nginx
FROM nginx:latest

# Copy the build files from the build stage to Nginx's html directory
COPY --from=build /App/build /usr/share/nginx/html

# copy nginx config to get a perfomanter app
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Expose the default Nginx port
EXPOSE 80

# Start Nginx
CMD ["nginx", "-g", "daemon off;"]