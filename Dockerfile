# Use an official Python runtime as a parent image
FROM python:3.10-slim

# Set the working directory in the container
WORKDIR /app

# Install system dependencies for mysqlclient if needed, 
# but the app uses pymysql so we just need basic build tools if any
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy the requirements file first to leverage Docker cache
# Since there is no requirements.txt, we will create one
RUN echo "Flask\nFlask-SQLAlchemy\nFlask-Login\nPyMySQL\nrequests\ngunicorn\nwerkzeug" > requirements.txt

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# Expose the port the app runs on
EXPOSE 5000

# Run the initialization and then start gunicorn
# Note: In a real production environment, you might want a separate init step
CMD ["sh", "-c", "python -c 'from app import init_db_and_admin; init_db_and_admin()' && gunicorn --bind 0.0.0.0:5000 app:app"]
