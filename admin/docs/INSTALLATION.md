## Installation

### Pre-requisites
1. PostgreSQL
2. Python 3.8 or higher


### Installation Steps
1. Clone this repository
   ```sh
   https://github.com/Gramhal-Foundation/flask_admin
   cd flask_admin/
   ```
2. Create python environment
   ```sh
   python -m venv venv
   ```
3. Activate the environment
   ```sh
   source venv/bin/activate
   ```
4. Install dependence
   ```sh
   npm install
   ```
5. Install dependencies
   ```sh
   pip install -r requirements.txt
   ```
6. Create `.env` and update environment variables
   ```sh
   cp .env.example .env
   ```
7. Run migrations
   ```sh
   flask db upgrade
   ```
8. Run the application
      ```sh
      python app.py or flask run --port=8000
      ```

