import re

def first_number(text):
    return re.search(r"\d+", text).group(0)

def pull(df):
    return df["name"].str.extract(r"(\w+)")
