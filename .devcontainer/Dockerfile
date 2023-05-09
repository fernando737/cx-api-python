# Use the official Python image as the base image
FROM python:3.9-slim

# Set the working directory
WORKDIR /app

# Add the local user
RUN useradd -ms /bin/bash node

# Change to the non-root user
USER node

# Install any necessary packages
USER root

RUN apt-get update && \
    apt-get install -y --no-install-recommends git && \
    rm -rf /var/lib/apt/lists/*

# Copy the requirements.txt file into the container
COPY requirements.txt .

# Install any required packages from requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
