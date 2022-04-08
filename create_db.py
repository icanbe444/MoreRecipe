import mysql.connector

mydb = mysql.connector.connect(
    host= "localhost",
    user="root",
    passwd = "Sunk@nmi84!@",
)

my_cursor = mydb.cursor()

# my_cursor.execute("CREATE DATABASE more_recipe")

my_cursor.execute("SHOW DATABASES")
for db in my_cursor:
    print(db)
