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
    echo '[-] Son necesarios privilegios de root'."\n";
    echo 'Newbie';
    exit(1);
    }

function mostrar($texto) {
    echo $texto;
    fwrite($GLOBALS['log'], $texto);
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
	
function barra ($porcentaje) {
	# Funcion que devuelve la barra de progreso de lineas leidas
	$caracter_relleno = '-';
	$caracter_final = '>';
	
	$progress_bar = floor($porcentaje/10);
	
	$barra_size = 3;
	$progress_bar = $progress_bar * $barra_size;
	
	$barra = '|';
	for ($p = 0; $p <= $progress_bar;$p++) {
		if ($p == $progress_bar) {
			$barra .= $caracter_final;
			}
		else {
			$barra .= $caracter_relleno;
			}
		}
	
	for ($p = $progress_bar; $p < 10 * $barra_size; $p++) {
		$barra .=' ';
		}
		
	$barra .='|';
	return $barra;
	}

function ultima_linea() {
	# Devuelve la última línea leida, guardada en la columna línea de la tabla ssh
	$lineas = $GLOBALS['db'] -> query('SELECT linea FROM ssh ORDER BY id DESC LIMIT 1');
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


# Funcion para insertar un intento de conexion en la tabla SSH
function insertar_en_ssh($usuario, $ip, $fecha, $fecha_deteccion, $puerto, $linea, $estado) {

	if (isPublicIP($ip)) {
		# Comprobamos que la extension geoip este cargada
		if (extension_loaded('geoip')) {
			$pais = geoip_country_name_by_name($ip);
			}
		else {
			$pais = '';
			}
		}
	else {
		$pais = 'No';
		}
	
	if ($GLOBALS['db'] -> query("INSERT INTO ssh SET usuario='$usuario',ip='$ip',pais='$pais',fecha='$fecha',fecha_deteccion='$fecha_deteccion',puerto='$puerto',linea='$linea',estado='$estado'")) {
		return true;
		}
	else {
		return false;
		}
	}
	
function existe_en_ssh($usuario, $ip, $fecha, $puerto, $estado) {
	
	if ($GLOBALS['db'] -> query("SELECT id FROM ssh WHERE usuario='$usuario' AND ip='$ip' AND fecha='$fecha' AND puerto='$puerto' AND estado='$estado'") -> num_rows > 0) {
		return true;
		}
	else {
		return false;
		}
	}
	
# Funcion para banear una ip proporcionada
function banear($ip, $pais, $fecha_fin, $fecha_baneo) {
	
	# Añadimos la IP al Blacklist
	$query = "INSERT INTO baneos SET 
								ip='$ip', 
								fecha_fin='$fecha_fin',
								fecha_baneo='$fecha_baneo',
								activo=1";

	if ($GLOBALS['db'] -> query($query)) {

			mostrar("[+] Baneando la IP: $ip hasta: $fecha_fin \n");

			# Desde las 7 a las 23 dirá si se ha baneado alguna IP
			# La directiva hablar ha de ser 1 para que hable
			if ($GLOBALS['conf']['hablar'] == 1 && (date('H') < 23 && date('H') > 7)) {
				exec("espeak -v es 'IP de $pais baneada' 2>/dev/null");
				}

			$GLOBALS['db'] -> query("UPDATE ssh SET nuevo=1 WHERE ip='$ip'");
		}
	else {
		mostrar('[-] Error insertando en la BBDD:'."\n". $GLOBALS['db'] -> error ."\n");
		}

	# Insertamos la regla en iptables
	exec("iptables -A INPUT -p tcp -s $ip -j DROP", $out, $return_var);
	
	if ($return_var == 0) {
		mostrar("[+] OK\n");
		}
	else {
		mostrar('[-] Error Baneando la IP: '."$ip \n");
		}
	}

function eliminar_baneadas () {
	    $fecha = date('Y-m-d H:i:s');
        
        $baneos_viejos = $GLOBALS['db'] -> query("SELECT * FROM baneos WHERE fecha_fin < '$fecha' AND activo=1");

        # Entramos solo si hay IPs a desbanear
        if ($baneos_viejos -> num_rows > 0) {

            while ($baneo = $baneos_viejos -> fetch_array()) {
                
                # Comprobamos sila regla existe en el listado de iptables
                # Solo la quitamos si existe, sino, solo actualizamos la tabla de baneos
                $existe_regla = shell_exec("iptables -nL INPUT | grep '{$baneo['ip']}' | /usr/bin/wc -l");
                
                if ($existe_regla >= 1) {
					mostrar("[+] Eliminando baneo para la IP: {$baneo['ip']} \n");
					
					# Actualizamos la IP al Whitelist
					$GLOBALS['db'] -> query("UPDATE baneos SET activo=0 WHERE ip='{$baneo['ip']}'");
					
					# Eliminamos la regla de iptables
					# Puede darse el caso (Aun no se porque) de que existan dos reglas para la misma IP en iptables, asi que la eliminamos tantas veces como este
					for ($i = 1; $i <= $existe_regla; $i++) {
						exec("iptables -D INPUT -p tcp -s {$baneo['ip']} -j DROP", $out, $return_var);
						
						if ($return_var == 0) {
							mostrar("[+] OK\n");
							}
						else {
							mostrar("[-] Error eliminando de baneos la IP: $ip \n");
							}
						}					
					}
				else {
					mostrar("[-] La IP: {$baneo['ip']} no se encuantra en iptables, actualizando BBDD \n");
					$GLOBALS['db'] -> query("UPDATE baneos SET activo=0 WHERE ip='{$baneo['ip']}'");
					}
                }
			
			$baneos_viejos -> free();
		}
	}
	
function ban_control() {
		##### Aplicamos las reglas o las desactivamos
        $total_intentos = $GLOBALS['db'] -> query('SELECT count(*) AS intentos,ip, pais FROM ssh WHERE estado=2 AND nuevo=0 GROUP BY ip HAVING intentos >= '.$GLOBALS['conf']['intentos'].' ORDER BY intentos DESC');
        
        # Entramos solo si hay IPs que banear
        if ($total_intentos -> num_rows > 0) {
            
            # Consultamos la fecha actual
            $now = new DateTime;

            # Formateamos la fecha
            $fecha_baneo = $now -> format('Y-m-d H:i:s');
            
            $fecha_fin = $now -> modify("+{$GLOBALS['conf']['tiempo']} {$GLOBALS['conf']['unidad']}") -> format('Y-m-d H:i:s');
            
            while ($intento = $total_intentos -> fetch_array()) {
                banear($intento['ip'], $intento['pais'], $fecha_fin, $fecha_baneo);
                }
            $total_intentos -> free();
        }
	}

# Funcion para finalizar correctamente el programa dependiendo de las señales enviadas al mismo
declare(ticks = 1);
function sig_handler($signo) {
	mostrar("\n".'[-] Cerrando conexion con la BBDD'."\n");
	mostrar('[-] Cerrando Fichero de Log'."\n");

	switch ($signo) {
		# Señal de reinicio
		case SIGHUP:
		
		# Señal de terminar
		case SIGTERM: 
		
		# Señal de CTRL + C
		case SIGINT:
			mostrar('[-] Finalizando el programa: '.date('d/m/Y H:i:s')."\n");
			
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

# No establecemos limite de tiempo para el script
set_time_limit(0);

# Leemos el fichero de configuración
$conf = parse_ini_file(__DIR__.'/monitor.conf');

# Configuramos la zona horaria
ini_set('date.timezone', $conf['zona_horaria']);

# Creamos el array que contiene las IPs del whitelist
$whitelist = explode(',', $conf['whitelist']);

foreach ($whitelist as $clave => $ip) {
	$whitelist[$clave] = trim($ip);
	}

# Abrimos el fichero de log
$log = fopen($conf['Log'], 'a');

# Patrones
$patron_correctas = '/Accepted password/';
$patron_incorrectas = '/Failed password/';

### Conectamos con la BBDD
$n_intentos = 0; # nº de intentos de conexion con la BBDD

while (!$db = mysqli_connect($conf['host'], $conf['usuario'], $conf['pass'], $conf['bbdd'])) {
		
	# Sumamos uno al nº de intentos de conexion con la BBDD
	$n_intentos++;
	
	# Si el nº de intentos es menor que el limite, seguimos intentandolo
	if ($n_intentos < $conf['max_reintentar']) {
		mostrar('[-] Error conectando a la base de datos: '."\n".'[+] '.mysqli_connect_error()."\n".'[+] Reintentando en: '.$conf['reintentar'].' segundos'."\n");
		sleep($conf['reintentar']); # Esperamos el tiempo especificado en el fichero de configuracion
	}
	else {
		mostrar('[-] Numero máximo de intentos de conexión con la BBDD alcanzado'."\n".'Saliendo'."\n");
		fclose($log);
		exit(1);
	}
}


if ($db) {
	mostrar("\n".'[+] Iniciando IPBan'."\n");
	mostrar('[+] Version: 1.0'."\n");
	mostrar('[+] Conectado a la BBDD correctamente'."\n");
	
	# Confirmamos que las tablas existen
	# Si no existen las creamos
	require_once('tablas.php');
	
	# Comprobamos que geoip este cargado
	if (!extension_loaded('geoip')) {
		mostrar('[-] El modulo de PHP geoip no esta cargado'."\n");
		}
	
	# Main Loop Like C :)
    while (true) {
		
		if (!$db -> ping()) {
			mostrar('[-] Se perdio la conexion con el servidor MySQL'."\n");
		}
		
		# Comprobamos si existen IPs baneadas que haya que desbanear
		eliminar_baneadas();
        
        # Comprobamos si cambió el fichero de logs de SSH
        $flag = 0;
        if (empty($md5_ultimo) || ( md5_file($conf['SSHLog']) != $md5_ultimo )) {

            $SSHLog = fopen($conf['SSHLog'], 'r') or die (mostrar("[-] Error abriendo el archivo: {$conf['SSHLog']} \n"));
			
			# Contamos las lineas actuales del fichero
			$total_lineas = shell_exec("wc -l {$conf['SSHLog']} | cut -d ' ' -f 1");
			$total_lineas = (int) $total_lineas;

            $fecha_deteccion = date('Y-m-d H:i:s');

            # Recorremos cada linea del archivo en busca de coincidencias de intento o inicio de sesion
            list($ultima_linea, $lineas) = ultima_linea();

			$lineas_restantes = $total_lineas - $ultima_linea;
			mostrar("\n[+] Lineas por leer: ".$lineas_restantes."\n");

            # Nº Correctas e Incorrectas
            $n_correctas = 0;
            $n_incorrectas = 0;
            $n_linea = 0;
            while ( !feof($SSHLog) ) {
				
				$linea = fgets($SSHLog);
				
				# Se dan los siguientes casos: 1 - El ultimo registro contiene el ultimo numero de linea -> Proseguimos desde esa línea
				#							   2 - En la base de datos no existe el ultimo registro con el numero de linea -> Empieza desde la linea 0
				#							   3 - El servicio de logs ha archivado el log, pero existe la ultima línea indicada en la BBDD -> Si el numero de la ultima es superior a las lineas del log nuevo volvemos a empezar desde la linea 0
				if ( (!empty($ultima_linea) && $ultima_linea < $n_linea) || ($lineas == 0) || ($total_lineas < $ultima_linea) ) {

					$porcentaje = porcentaje_leido($n_linea, $total_lineas);
					
					if ( $porcentaje != $porcentaje_anterior) {
						$barra = barra($porcentaje);
						mostrar('  '.$barra.' '.$porcentaje.'% completado'."\n");
					}

					# CONEXIONES CORRECTAS
					if ( preg_match($patron_correctas, $linea) ) {
						$tmp = limpiar_linea($linea);
						
						$fecha = DateTime::createFromFormat('M d H:i:s', "$tmp[0] $tmp[1] $tmp[2]") -> format('Y-m-d H:i:s');

						$usuario = $tmp[8];
						$IPorigen = $tmp[10];
						$puerto = $tmp[12];

						# Validamos que la IP sea pública, debe estar indicado en el archivo de configuracion
						# Tambien se comprueba que la IP no esté en el Whitelist y que la lista blanca esté activada
						# $conf['privadas'] == false --> significa no banear las IPs privadas
						if ( (isPublicIP($IPorigen) && $conf['privadas'] == false) && (!in_array($IPorigen, $whitelist) && $conf['activar_whitelist']) ) {

							# Si no existe el registro lo añadimos
							if (!existe_en_ssh($usuario, $IPorigen, $fecha, $puerto, 1)) {

								if (insertar_en_ssh($usuario, $IPorigen, $fecha, $fecha_deteccion, $puerto, $n_linea, 1)) {
									mostrar("[i] El usuario: $usuario inicio sesion a: $fecha desde la IP: $IPorigen \n");
									}
								else {
									mostrar('[-] Error insertando registro en la BBDD'."\n");
									}
							}
							else {
								mostrar('[i] Entrada leida, omitiendo: '."$IPorigen\n");
							}

							$n_correctas++;
						}
						else {
							mostrar('[i] Conexión permitida desde IP Privada o en el Whitelist: '.$IPorigen."\n");
						}
					}
					# CONEXIONES INCORRECTAS
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
						if ( (isPublicIP($IPorigen) && $conf['privadas'] == false) && (!in_array($IPorigen, $whitelist) && $conf['activar_whitelist']) ) {
							
							# Si no existe el registro lo añadimos
							if (! existe_en_ssh($usuario, $IPorigen, $fecha, $puerto, 2)) {

								if (insertar_en_ssh($usuario, $IPorigen, $fecha, $fecha_deteccion, $puerto, $n_linea, 2)) {
									mostrar("[i] El usuario $usuario intentó iniciar sesion a: $fecha desde la IP: $IPorigen\n");
								}
								else {
									mostrar("[-] Error insertando registro en la BBDD");
								}
							}
							else {
								mostrar("[i] Entrada leida, omitiendo: $n_incorrectas \n");
								}

							$n_incorrectas++;
						}
						else {
							mostrar('[i] Conexión incorrecta desde IP Privada o en el Whitelist: '.$IPorigen."\n");
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
		ban_control();
		
        sleep ($conf['intervalo']);
    }
}
?>

