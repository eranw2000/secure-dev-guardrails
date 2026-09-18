conn = psycopg2.connect(host="db", user="postgres", password=os.environ["DB_PASSWORD"])
