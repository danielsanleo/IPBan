<?php
$resultado = $db -> query('SHOW TABLES LIKE "ssh"');
	
if ($resultado -> num_rows == 0) {
	mostrar('[+] Creando la tabla ssh inexistente'."\n");

	##### Tabla SSH
	# Utilizada para almacenar los intentos de conexión
	## Contiene:
	# id -> clave primaria identificadora
	# usuario -> usuario con el que se intento iniciar sesion
	# ip -> Direccion desde donde se realizó la conexión
	# puerto -> puerto local dinámico que se abrió
	# pais -> Nación de la IP
	# estado -> El campo estado de la base de datos hace referencia a si tuvo exito o no durante la autenticación: 1 -> correcto, 2 -> incorrecto
	# nuevo -> Campo boleano: IP sin revisar -> nuevo = 0, IP revisada -> nuevo = 1
	# fecha_deteccion -> Fecha en la que se revisó la tupla
	# fecha -> Fecha del registro SSH
	# linea -> Linea donde se encuentra la regla, utilizada como marcador, para no tener que volver a leer todo el log en caso de reiniciar el servicio

	$db -> query('CREATE TABLE ssh (id int(11) PRIMARY KEY AUTO_INCREMENT, 
									usuario VARCHAR(50), 
									ip VARCHAR(30), 
									puerto VARCHAR(10), 
									pais VARCHAR(30), 
									estado tinyint(1), 
									nuevo tinyint(1) DEFAULT 0, 
									fecha_deteccion DATETIME, 
									fecha DATETIME, 
									linea int(11))');
	}
	
$resultado2 = $db -> query('SHOW TABLES LIKE "baneos"');

if ($resultado2 -> num_rows == 0) {
	mostrar('[+] Creando la tabla baneos inexistente'."\n");
	
	##### Tabla BANEOS
	# Utilizada para llevar el control e historial sobre las IPs baneadas
	## Contiene:
	# id -> clave primaria identificadora
	# fecha_fin -> Fecha en la que termina el baneo
	# fecha_baneo -> Fecha en la que se baneó
	# activo -> Campo boleano, indica si la regla esta actualmente cargada en iptables: 1 -> cargada, 0 -> cargada anteriormente
	
	$db -> query('CREATE TABLE baneos ( id int(11) PRIMARY KEY AUTO_INCREMENT, 
										ip VARCHAR(30), 
										fecha_fin DATETIME, 
										fecha_baneo DATETIME, 
										activo tinyint(1) DEFAULT 0)');
	}
?>
