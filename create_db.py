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



'''
top_recipe querry = SELECT count(l.recipe_id) as top, m.name, m.id, m.description 
FROM more_recipe.recipe as m join more_recipe.like as l on m.id = l.recipe_id 
group by l.recipe_id order by top desc
'''