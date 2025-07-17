# Use a base Python image
FROM python:3.12-slim

# Set DEBIAN_FRONTEND to noninteractive to prevent interactive prompts during apt-get
ENV DEBIAN_FRONTEND=noninteractive

# Install required system dependencies:
# - openjdk-17-jdk: We need the JDK (Java Development Kit) for jpype.
# - fontconfig: Essential for Java applications to properly handle fonts.
# - ttf-mscorefonts-installer: Provides common Microsoft fonts.
# - libglib2.0-0: A dependency for some font-related libraries.
RUN apt-get update && \
    # Add contrib and non-free repositories to sources.list
    echo "deb http://deb.debian.org/debian/ bookworm main contrib non-free" >> /etc/apt/sources.list && \
    echo "deb http://deb.debian.org/debian/ bookworm-updates main contrib non-free" >> /etc/apt/sources.list && \
    echo "deb http://deb.debian.org/debian-security bookworm-security main contrib non-free" >> /etc/apt/sources.list && \
    # Update apt cache again after adding new repositories
    apt-get update && \
    # Accept the EULA for ttf-mscorefonts-installer silently BEFORE installing it
    echo "ttf-mscorefonts-installer msttcorefonts/accepted-mscorefonts-eula select true" | debconf-set-selections && \
    apt-get install -y --no-install-recommends \
        openjdk-17-jdk \
        fontconfig \
        ttf-mscorefonts-installer \
        libglib2.0-0 && \
    # Create the uploads directory and set permissions for the app to write to it
    # This is crucial for file uploads.
    mkdir -p /app/uploads && \
    chmod -R 777 /app/uploads && \
    # Clean up apt cache to reduce image size
    rm -rf /var/lib/apt/lists/*

# Set environment variable for Java Home
# This path is typical for openjdk-17-jdk on Debian-based systems.
ENV JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
ENV PATH="${JAVA_HOME}/bin:${PATH}"

# Set the working directory inside the container
WORKDIR /app

# Copy only the requirements file first to leverage Docker's build cache
COPY requirements.txt .

# Install Python dependencies
# IMPORTANT: Ensure 'jpype1' is in your requirements.txt file!
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of your application files
COPY . .

# Expose the port your Flask app listens on (default Flask port is 5000)
EXPOSE 5000

# Run the Flask app with Gunicorn
# -b 0.0.0.0:5000: Binds Gunicorn to all network interfaces on port 5000
# --workers 2: Number of worker processes (adjust based on your CPU cores/Render plan)
# --timeout 300: Request timeout in seconds (important for potentially long-running PDF ops)
# --max-requests-body 1073741824: Max request body size (1GB in bytes, adjust as needed for your PDFs)
# app:app: Assumes your Flask application instance is named 'app' in 'app.py'
CMD ["gunicorn", "-b", "0.0.0.0:5000", "--workers", "2", "--timeout", "300", "--max-requests-body", "1073741824", "app:app"]
