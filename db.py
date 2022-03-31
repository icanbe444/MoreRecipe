import mysql.connector
from mysql.connector import Error
import sqlite3

conn = sqlite3.connect("more_recipes.sqlite")

cursor = conn.cursor()
sql_query = """ CREATE TABLE users (
    id integer primary key autoincrement,
    username text not null,
    password text not null
)"""
cursor.execute(sql_query)
