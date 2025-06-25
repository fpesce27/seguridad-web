1. Descubrir endpoints con burp: admin, logs, etc

2. Tratar de entrar a los endpoints. Están protegidos, pero nos dicen que hay un rol admin y un rol monitor

2. Checkear el JWT. Vemos que hay un campo rol adentro, así que lo tratamos de romper.

4. Cambiamos el rol a admin, pero no nos deja entrar a nada. Parece tener chequeos

5. Cambiamos el rol a monitor, y conseguimos entrar al endpoint de los logs

6. Vemos que hay un log de cambio de contraseña que expone los hashes. También vemos que el digest tiene la 
longitud correcta para ser MD5

7. Cambiamos la contraseña, buscamos el log, y obtenemos el digest para esa contraseña

8. Pasamos la contraseña por MD5, pero no coincide, por lo que asumimos que hay un salt

9. Lo crackeamos con fuerza bruta. Todavia no sabemos si es un salt estático, pero igual probamos

10. Hacemos un diccionario con el digest del salt + contraseñas más comunes. 

11. De los logs que tenemos, chequeamos si hay alguno que matchee con el diccionario. Auditor1 matchea, por lo que logramos hijackear ese usuario

12. Entramos con la cuenta, y vemos que nos manda a un panel con un campo.

13. Verificamos si es vulnerable a injection con " ' ", y lo es.

14. No sabemos el schema de la db, pero vamos insertando cosas que después podemos ver con queries del tipo
`' || (SELECT name FROM sqlite_master WHERE type='table' LIMIT 1 OFFSET 0) || '`
esperando lograr algo como
`INSERT INTO ??? (field) VALUES ('' || (SELECT name FROM sqlite_master WHERE type='table' LIMIT 1) || '')`

15. Iteramos sobre las tablas usando offset

16. Encontrar las columnas usando `' || (SELECT sql FROM sqlite_master WHERE type='table' AND name='users') || '`

17. Aprovechar el injection. Como ya tenemos el hash, se podrían cambiar la contraseña de admin con un 

`'); UPDATE users SET password_hash = '207acd61a3c1bd506d7e9a4535359f8a' WHERE username = 'admin'; --`

o cambiar las notas con

`'); UPDATE grades SET grade = 10 WHERE student = 'Juan'; --`