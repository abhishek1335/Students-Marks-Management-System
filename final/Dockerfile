# Use a base Python image
FROM python:3.12-slim

# Install required system dependencies:
# - openjdk-17-jdk: We need the JDK (Java Development Kit) for jpype, not just the JRE.
#   The JDK includes 'javac' and development tools that jpype might leverage.
# - fontconfig: Essential for Java applications to properly handle fonts.
# - ttf-mscorefonts-installer: Provides common Microsoft fonts (like Times New Roman, Arial, Courier New)
#   which often resolve the PDFBox font fallback warnings.
# - libglib2.0-0: A dependency for some font-related libraries.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openjdk-17-jdk \
        fontconfig \
        ttf-mscorefonts-installer \
        libglib2.0-0 && \
    # Accept the EULA for ttf-mscorefonts-installer silently
    echo "ttf-mscorefonts-installer msttcorefonts/accepted-mscorefonts-eula select true" | debconf-set-selections && \
    apt-get install -y --no-install-recommends ttf-mscorefonts-installer && \
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
# Ensure 'jpype1' is in your requirements.txt!
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of your application files
COPY . .

# Expose the port your Flask app listens on (default Flask port is 5000)
EXPOSE 5000

# Run the Flask app
CMD ["python", "app.py"]
