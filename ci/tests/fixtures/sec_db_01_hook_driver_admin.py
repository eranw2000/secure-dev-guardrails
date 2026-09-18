conn = psycopg2.connect(host="db", username="admin", password=os.environ["DB_PASSWORD"])
