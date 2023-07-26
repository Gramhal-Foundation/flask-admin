# flask_jinja

1. Clone this repository and move to `flask_jinja` directory
   ```sh
    https://github.com/rohit123-rawat/flask_jinja.git
   ```
2. After successfully cloning run following commands.

   1. Create python environment
      ```sh
      python -m venv venv
      ```
   2. Activate the environment
      ```sh
      source venv/bin/activate
      ```
   3. Install dependence
      ```sh
      npm install
      ```
   4. Install dependencies
      ```sh
      pip install -r requirements.txt
      ```
   5. Run the application
      ```sh
      python app.py or flask run --port=8000
      ```
   6. Connect with database
      ```sh
      app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://user_name:Password@localhost/db_name'
      ```
   7. To run migrataions
      ```sh
      pip install Flask-Migrate
      flask db upgrade
      ```
