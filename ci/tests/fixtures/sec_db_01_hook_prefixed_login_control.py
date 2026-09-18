conn = psycopg2.connect(host="db", user="postgres_app", password=os.environ["DB_PASSWORD"])
