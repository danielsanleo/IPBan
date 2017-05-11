#!/usr/bin/php
<?php
/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 * 
 */
error_reporting(E_ALL);
ini_set('display_errors','On');

if (posix_getuid() != 0) {
    echo 'Son necesarios privilegios de root'."\n";
    echo 'Newbie';
    exit(1);
    }

function mostrar($texto, $archivo) {
    echo $texto;
    fwrite($archivo, $texto);
    }

function isPublicIP ($user_ip) {
	if ( !empty(filter_var($user_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE |  FILTER_FLAG_NO_RES_RANGE)) ) {
		return true;
	}
	else {
		return false;
	}
}

#### Funciones del programa
function porcentaje_leido($n_linea, $total_lineas) {
	# Porcentaje lineas leidas
	$numero = floor(($n_linea/$total_lineas)*100);
	return $numero;	
	}

function ultima_linea($conexion) {
	# Devuelve la última línea leida guardada en la columna línea de la tabla ssh
	$lineas = $conexion -> query('SELECT linea FROM ssh ORDER BY id DESC LIMIT 1');
	$ultima_linea = $lineas -> fetch_array();
	return array($ultima_linea[0], $lineas -> num_rows);
	}

function limpiar_linea($linea) {
	# Dependiendo del mes hay mas o menos espacios
	# Así que eliminamos espacios sobrantes reduciendo cada separacion a un espacio
	# Ej: Jan 31 08:43:08 ragnar sshd[19291]: Failed password for invalid user support from 91.224.160.153 port 51431 ssh2
	# Ej: Jan 31 08:44:10 ragnar sshd[19294]: Failed password for root from 91.224.160.153 port 5609 ssh2
	$tmp = explode(' ', $linea);
	foreach ($tmp as $clave => $valor) {
		if (empty($valor)) {
			unset($tmp[$clave]);
			$tmp = array_merge($tmp);
		}
	}
	return $tmp;
}

function eliminar_baneadas ($conexion, $log) {
	    $fecha = date('Y-m-d H:i:s');
        
        $baneos_viejos = $conexion -> query("SELECT * FROM baneos WHERE fecha_fin < '$fecha' AND activo=1");

        # Entramos solo si hay IPs a desbanear
        if ($baneos_viejos -> num_rows > 0) {

            while ($baneo = $baneos_viejos -> fetch_array()) {
                mostrar("Eliminando baneo para la IP: {$baneo['ip']} \n", $log);
                
                # Actualizamos la IP al Whitelist
                $conexion -> query("UPDATE baneos SET activo=0 WHERE ip='{$baneo['ip']}'");
                
                # Eliminamos la regla de iptables
                $iptables = "iptables -D INPUT -p tcp -s {$baneo['ip']} -j DROP";
                exec($iptables);
                }
		}
	}

# Funcion para insertar un intento de conexion en la tabla SSH
function insertar_en_ssh($usuario, $ip, $fecha, $fecha_deteccion, $puerto, $linea, $estado, $conexion) {

	if (isPublicIP($ip)) {
		$pais = geoip_country_name_by_name($ip);
		}
	else {
		$pais = 'No';
		}
	
	if ($conexion -> query("INSERT INTO ssh SET usuario='$usuario',ip='$ip',pais='$pais',fecha='$fecha',fecha_deteccion='$fecha_deteccion',puerto='$puerto',linea='$linea',estado='$estado'")) {
		return true;
		}
	else {
		return false;
		}
	}
	
function existe_en_ssh($usuario, $ip, $fecha, $puerto, $estado, $conexion) {
	
	if ($conexion -> query("SELECT id FROM ssh WHERE usuario='$usuario' AND ip='$ip' AND fecha='$fecha' AND puerto='$puerto' AND estado='$estado'") -> num_rows > 0) {
		return true;
		}
	else {
		return false;
		}
	}

# Funcion para finalizar correctamente el programa dependiendo de las señales enviadas al mismo
declare(ticks = 1);
function sig_handler($signo) {
	echo 'Cerrando conexion con la BBDD'."\n";
	echo 'Cerrando Fichero de Log'."\n";

	switch ($signo) {
		# Señal de reinicio
		case SIGHUP:
		
		# Señal de terminar
		case SIGTERM: 
		
		# Señal de CTRL + C
		case SIGINT:
			# Cerramos la conexion si existe
			if (@$db) {
				$db -> close();
			}

			# Cerramos el fichero de logs si esta abierto
			if (@$log) {
				fclose($log);
			}

			exit(0);
		break;
	}
}

pcntl_signal(SIGINT, 'sig_handler');
pcntl_signal(SIGTERM, 'sig_handler');
pcntl_signal(SIGHUP, 'sig_handler');

# Leemos el fichero de configuración
$conf = parse_ini_file('/home/ragnar/Scripts/IPBan/monitor.conf');

# Creamos el array que contiene las IPs del whitelist
$whitelist = explode(',', $conf['whitelist']);

foreach ($whitelist as $clave => $ip) {
	$whitelist[$clave] = trim($ip);
	}

# Abrimos el fichero de log
$log = fopen($conf['Log'], "a");

# Patrones
$patron_correctas = '/Accepted password/';
$patron_incorrectas = '/Failed password/';

### Conectamos con la BBDD
# n_intentos es el nº de intentos de conexion con la BBDD
$n_intentos = 0;
reintentar_conexion:

$db = mysqli_connect($conf['host'], $conf['usuario'], $conf['pass'], $conf['bbdd']);

if ($db) {
	mostrar('Conectado a la BBDD correctamente'."\n", $log);
	
	# Confirmamos que las tablas existen
	# Si no existe las creamos
	$resultado = $db -> query("SHOW TABLES LIKE 'ssh'");
	if ($resultado -> num_rows == 0) {
		mostrar('Creando la tabla ssh inexistente'."\n",$log);
		
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
		
		$db -> query("CREATE TABLE ssh ( id int(11) PRIMARY KEY AUTO_INCREMENT, usuario VARCHAR(50), ip VARCHAR(30), puerto VARCHAR(10), pais VARCHAR(30), estado tinyint(1), nuevo tinyint(1) DEFAULT 0, fecha_deteccion DATETIME, fecha DATETIME, linea int(11))");
		}
		
	$resultado2 = $db -> query("SHOW TABLES LIKE 'baneos'");
	if ($resultado2 -> num_rows == 0) {
		mostrar('Creando la tabla baneos inexistente'."\n",$log);
		
		##### Tabla BANEOS
		# Utilizada para llevar el control e historial sobre las IPs baneadas
		## Contiene:
		# id -> clave primaria identificadora
		# fecha_fin -> Fecha en la que termina el baneo
		# fecha_baneo -> Fecha en la que se baneó
		# activo -> Campo boleano, indica si la regla esta actualmente cargada en iptables: 1 -> cargada, 0 -> cargada anteriormente
		
		$db -> query("CREATE TABLE baneos ( id int(11) PRIMARY KEY AUTO_INCREMENT, ip VARCHAR(30), fecha_fin DATETIME, fecha_baneo DATETIME, activo tinyint(1) DEFAULT 0) ");
		}

    while (true) {
		
		# Comprobamos si existen IPs baneadas que haya que desbanear
		eliminar_baneadas($db, $log);
        
        # Comprobamos si cambió el fichero de logs de SSH
        $flag = 0;
        if (empty($md5_ultimo) || ( md5_file($conf['SSHLog']) != $md5_ultimo )) {
            
            $SSHLog = fopen($conf['SSHLog'], "r") or die (mostrar("Error abriendo el archivo: {$conf['SSHLog']}",$log));
			
			$total_lineas = shell_exec("wc -l {$conf['SSHLog']} | cut -d ' ' -f 1");
			$total_lineas = intval($total_lineas);
			echo "Total Lineas: $total_lineas";
			
			
			//~ exit;
            $fecha_deteccion = date('Y-m-d H:i:s');
            
            # Recorremos cada linea del archivo en busca de coincidencias de intento o inicio de sesion
            list($ultima_linea, $lineas) = ultima_linea($db);
			
			mostrar('Comenzando desde la línea: '.$ultima_linea."\n", $log);

            # Nº Correctas e Incorrectas
            $n_correctas = 0;
            $n_incorrectas = 0;
            $n_linea = 0;
            while (!feof($SSHLog)) {
				
				$linea = fgets($SSHLog);
				
				# Se dan los siguientes casos: 1 - El ultimo registro contiene el ultimo numero de linea -> Proseguimos desde esa línea
				#							   2 - En la base de datos no existe el ultimo registro con el numero de linea -> Empieza desde la linea 0
				#							   3 - El servicio de logs ha archivado el log, pero existe la ultima línea indicada en la BBDD -> Si el numero de la ultima es superior a las lineas del log nuevo volvemos a empezar desde la linea 0
				if ( (!empty($ultima_linea) && $ultima_linea < $n_linea) || ($lineas==0) || ($total_lineas < $ultima_linea) ) {

					$porcentaje = porcentaje_leido($n_linea, $total_lineas);
					
					if ( $porcentaje != $porcentaje_anterior) {
						mostrar($porcentaje.'% completado'."\n", $log);
					}
					
					# Intentos de conexion CORRECTOS
					if (preg_match($patron_correctas ,$linea)) {
						$tmp = limpiar_linea($linea);
						
						$fecha = DateTime::createFromFormat('M d H:i:s', "$tmp[0] $tmp[1] $tmp[2]") -> format('Y-m-d H:i:s');

						$usuario = $tmp[8];
						$IPorigen = $tmp[10];
						$puerto = $tmp[12];

						# Validamos que la IP sea pública, debe estar indicado en el archivo de configuracion
						# Tambien se comprueba que la IP no esté en el Whitelist y que la lista blanca esté activada
						if ( (isPublicIP($IPorigen) && $conf['privadas']==false) && (!in_array($IPorigen, $whitelist) && $conf['activar_whitelist']) ) {

							# Si no existe el registro lo añadimos
							if (!existe_en_ssh($usuario, $IPorigen, $fecha, $puerto, 1, $db)) {

								if (insertar_en_ssh($usuario, $IPorigen, $fecha, $fecha_deteccion, $puerto, $n_linea, 1, $db)) {
									mostrar("El usuario: $usuario inicio sesion a: $fecha desde la IP: $IPorigen \n", $log);
									}
								else {
									mostrar("Error insertando registro en la BBDD \n", $log);
									}
							}
							else {
								mostrar("Existe correcta: $n_correctas\n", $log);
							}

							$n_correctas++;
						}
						else {
							mostrar('Saltando conexión correcta desde IP Privada o en el Whitelist: '.$IPorigen."\n", $log);
						}
					}
					# Intentos de conexion INCORRECTOS
					elseif (preg_match($patron_incorrectas ,$linea)) {
						
						$tmp = limpiar_linea($linea);
						
						$fecha = DateTime::createFromFormat('M d H:i:s', "$tmp[0] $tmp[1] $tmp[2]") -> format('Y-m-d H:i:s');
							
						# Las columnas dependen del registro
						if ($tmp[8] == 'invalid') {
							$usuario = $tmp[10];
							$IPorigen = $tmp[12];
							$puerto = $tmp[14];	
							}
						else {
							$usuario = $tmp[8];
							$IPorigen = $tmp[10];
							$puerto = $tmp[12];
							}
						
						# Validamos que la IP sea pública, debe estar indicado en el archivo de configuracion
						# Tambien se comprueba que la IP no esté en el Whitelist y que la lista blanca esté activada
						if ( (isPublicIP($IPorigen) && $conf['privadas']==false) && (!in_array($IPorigen, $whitelist) && $conf['activar_whitelist']) ) {
							
							# Si no existe el registro lo añadimos
							if (! existe_en_ssh($usuario, $IPorigen, $fecha, $puerto, 2, $db)) {

								if (insertar_en_ssh($usuario, $IPorigen, $fecha, $fecha_deteccion, $puerto, $n_linea, 2, $db)) {
									mostrar("El usuario $usuario intentó iniciar sesion a: $fecha desde la IP: $IPorigen\n", $log);
								}
								else {
									mostrar("Error insertando registro en la BBDD", $log);
								}
							}
							else {
								mostrar("Existe incorrecta: $n_incorrectas \n", $log);
								}

							$n_incorrectas++;
						}
						else {
							mostrar('Saltando conexión incorrecta desde IP Privada o en el Whitelist: '.$IPorigen."\n", $log);
						}
					}
				}
				$n_linea++;

				@$porcentaje_anterior = $porcentaje;
            }

        $md5_ultimo = md5_file($conf['SSHLog']);
        $flag = 1;
        fclose($SSHLog);
        }
        
        ##### Aplicamos las reglas o las desactivamos
        # SSH
        $total_intentos = $db -> query('SELECT count(*) AS intentos,ip, pais FROM ssh WHERE estado=2 AND nuevo=0 GROUP BY ip HAVING intentos >= '.$conf['intentos'].' ORDER BY intentos DESC');
        
        # Entramos solo si hay IPs que banear
        if ($total_intentos -> num_rows > 0) {
            
            # Fecha en la terminan los baneos
            $now = new DateTime;
            $fecha_fin = $now -> modify("+{$conf['tiempo']} {$conf['unidad']}") -> format('Y-m-d H:i:s');
            
            # Fecha actual
            $fecha_baneo = date('Y-m-d H:i:s');
                
            while ($intento = $total_intentos -> fetch_array()) {
                
                # Añadimos la IP al Blacklist
                $query = "INSERT INTO baneos SET 
                                            ip='{$intento['ip']}', 
                                            fecha_fin='$fecha_fin',
                                            fecha_baneo='$fecha_baneo',
                                            activo=1";
                
                if ($db -> query($query)) {

					    mostrar("Baneando la IP: {$intento['ip']} hasta: $fecha_fin \n", $log);

						# Desde las 7 a las 23 dirá si se ha baneado alguna IP
						# La directiva hablar ha de ser 1 para que hable
						if ($conf['hablar']==1 && (date('H') < 23 && date('H') > 7)) {
							exec("espeak -v es 'IP de {$intento['pais']} baneada' 2>/dev/null");
							}

						$db -> query("UPDATE ssh SET nuevo=1 WHERE ip='{$intento['ip']}'");
					}
				else {
					mostrar("Error insertando en la BBDD:\n". $db -> error ."\n", $log);
					}

                # Insertamos la regla en iptables
                $iptables = "iptables -A INPUT -p tcp -s {$intento['ip']} -j DROP";
                exec($iptables);
                }
        }
        sleep ($conf['intervalo']);
    }
}
else {
	$n_intentos++; # Sumamos uno al nº de intentos de conexion con la BBDD
	
	if ($n_intentos < $conf['max_reintentar']) {
		mostrar('Error conectando a la base de datos: '.mysqli_connect_error()."\n".'Reintentando en: '.$conf['reintentar'].' segundos'."\n", $log);
		sleep($conf['reintentar']); # Esperamos el tiempo especificado en la BBDD
		goto reintentar_conexion;   # Volvemos a intentar conectar
	}
	else {
		mostrar('Numero máximo de intentos e conexión con la BBDD alcanzado'."\n".'Saliendo'."\n",$log);
		fclose($log);
		exit(1);
	}
}
?>
