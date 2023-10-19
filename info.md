Table User:

- Name, Surname, E-mail, Bio, Password
- 

### 1. Importez le module sqlite3

```
pythonCopy code
import sqlite3
```

### 2. Créez une connexion à la base de données

Si la base de données n'existe pas, SQLite la créera pour vous.

```
pythonCopy code
conn = sqlite3.connect('database_name.db')
```

### 3. Créez un curseur

Le curseur vous permet d'exécuter des commandes SQL sur la base de données.

```
pythonCopy code
cursor = conn.cursor()
```

### 4. Exécutez des commandes SQL

Par exemple, pour créer une nouvelle table :

```
pythonCopy codecursor.execute('''
CREATE TABLE example (
    id INTEGER PRIMARY KEY,
    name TEXT,
    age INTEGER
)
''')
```

### 5. Insérez des données dans la table

```
pythonCopy code
cursor.execute("INSERT INTO example (name, age) VALUES (?, ?)", ("John", 30))
```

### 6. Exécutez une requête

```
pythonCopy codecursor.execute("SELECT * FROM example")
rows = cursor.fetchall()
for row in rows:
    print(row)
```

### 7. Sauvegardez les modifications

Après avoir effectué des opérations telles que l'insertion, la mise à jour ou la suppression de données, vous devez valider pour enregistrer les modifications dans la base de données.

```
pythonCopy code
conn.commit()
```

### 8. Fermez la connexion

Lorsque vous avez terminé, il est important de fermer la connexion à la base de données.

```
pythonCopy code
conn.close()
```

Voilà les étapes de base pour connecter Python à une base de données SQLite. Bien sûr, il y a beaucoup d'autres opérations et fonctionnalités que vous pouvez explorer avec `sqlite3`, mais cela devrait vous donner un bon point de départ.