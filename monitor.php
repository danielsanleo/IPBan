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

# Comprobamos si el usuario es root
if (posix_getuid() != 0) {
    echo '[-] ['.date($fecha_formato_salida).'] Son necesarios privilegios de root'."\n";
    echo '[-] ['.date($fecha_formato_salida).'] Newbie';
    exit(1);
    }

# Sin limite de tiempo para la ejecución del script
set_time_limit(0);

# Variables de fecha
$fecha_estandar = 'Y-m-d H:i:s';
$fecha_formato_salida = 'd/M/Y H:i';
$formato_fecha_logs = 'M d H:i:s';

require_once(__DIR__.'/funciones.php');

# Leemos el fichero de configuración y obtememos el hash MD5 
# para posteriormente actualizar las variables de configuración
# de forma dinámica
$ruta_conf = __DIR__.'/monitor.conf';

try {
	if (($conf = @parse_ini_file($ruta_conf)) == false) {
			throw new Exception('[-] ['.date($fecha_formato_salida).'] Error cargando el fichero de configuración: '.$ruta_conf."\n".'[i] Bye Bye'."\n");
		}
	else {
		mostrar("\n".'[+] ['.date($fecha_formato_salida).'] Iniciando IPBan'."\n");
		mostrar('[+] ['.date($fecha_formato_salida).'] Configuración cargada correctamente'."\n");
		
		if (!empty($conf['Locale'])) {
			setlocale(LC_TIME, $conf['Locale']);			
			}
			
		if (empty($conf['binario_iptables'])) {
			$conf['binario_iptables'] = shell_exec('which iptables');
			}
		}
}
catch (Exception $e) {
	die($e -> getMessage());
}

# Función para finalizar correctamente el programa dependiendo de las señales enviadas al mismo
# No esta declarada en el archivo de funciones porque devuelve un error
# Sin embargo, desde este php funciona correctamente
declare(ticks = 1);
function sig_handler($signo) {
	mostrar("\n".'[-] ['.date($GLOBALS['fecha_formato_salida']).'] Cerrando conexión con la BBDD'."\n");
	mostrar('[-] ['.date($GLOBALS['fecha_formato_salida']).'] Cerrando Fichero de Log'."\n");

	switch ($signo) {
		# Señal de reinicio
		case SIGHUP:
		
		# Señal de terminar
		case SIGTERM: 
		
		# Señal de CTRL + C
		case SIGINT:

			mostrar('[+] ['.date($GLOBALS['fecha_formato_salida']).'] Finalizando el programa'."\n");
			
			# Cerramos la conexion si existe
			if (@$db) {
				$db -> close();
			}

			exit(0);
		break;
	}
}

pcntl_signal(SIGINT, 'sig_handler');
pcntl_signal(SIGTERM, 'sig_handler');
pcntl_signal(SIGHUP, 'sig_handler');


# Cargamos la clase PHPMailer en Caso de ser necesaria para el envio de las Estadísticas
if ($conf['email']) {
	@require(__DIR__.'/PHPMailer/PHPMailerAutoload.php');
	}

$conf_md5 = md5_file($ruta_conf);

# Configuramos la zona horaria
ini_set('date.timezone', $conf['zona_horaria']);

# Creamos el array que contiene las IPs del whitelist
$whitelist = explode(',', $conf['whitelist']);

# Limpiamos los espacios 
foreach ($whitelist as $clave => $ip) {
	$whitelist[$clave] = trim($ip);
	}

# Patrones que coinciden con los intentos y éxitos de sessión
$patron_correctas = '/Accepted password/';
$patron_incorrectas = '/Failed password/';

# Declaramos la variable memoria_ultimo_valor, que nos servirá para el modo prueba de fallos
if ($conf['Debug']) {
	$memoria_ultimo_valor = 0;
}

#### Conectamos con la BBDD

# nº de intentos de conexion con la BBDD
$n_intentos = 0;

while (!$db = mysqli_connect($conf['host'], $conf['usuario'], $conf['pass'], $conf['bbdd'])) {
		
	# Sumamos uno al nº de intentos de conexion con la BBDD
	$n_intentos++;
	
	# Si el nº de intentos es menor que el limite, seguimos intentandolo
	if ($n_intentos < $conf['max_reintentar']) {
		mostrar('[-] ['.date($fecha_formato_salida).'] Error conectando a la base de datos: '."\n".'[+] '.mysqli_connect_error()."\n".'[+] Reintentando en: '.$conf['reintentar'].' segundos'."\n");
		
		# Esperamos el tiempo especificado en el fichero de configuracion
		sleep($conf['reintentar']);
		}
	else {
		mostrar('[-] ['.date($fecha_formato_salida).'] Numero máximo de intentos de conexión con la BBDD alcanzado'."\n".'[-] Saliendo'."\n");
		exit(1);
		}
	}

if ($db) {
	mostrar('[+] ['.date($fecha_formato_salida).'] Versión: 2.6'."\n");
	mostrar('[+] ['.date($fecha_formato_salida).'] Conectado a la BBDD correctamente'."\n");
	
	# Confirmamos que las tablas existen
	# Si no existen las creamos
	require_once('tablas.php');
	
	# Comprobamos que geoip este cargado
	if (!extension_loaded('geoip')) {
		mostrar('[-] ['.date($fecha_formato_salida).'] El módulo de PHP geoip no está cargado'."\n");
		mostrar('[-] ['.date($fecha_formato_salida).'] No se mostrarán los paises de las IPs'."\n");
		}

	# Comprobamos que las reglas esten cargadas en IPTables
	comprobar();

	# Mostramos el número de reglas cargadas
	mostrar('[i] ['.date($fecha_formato_salida).'] Nº de baneos activos: '.n_reglas()."\n");

	$fecha_proxima_ejecucion = (new DateTime()) -> modify("+{$conf['email_intervalo']}") -> getTimestamp();

	# Main Loop Like C :)
	$IPsBaneadas = array();
	$porcentaje_anterior = 0;
    while (True) {
		
		if (!$db -> ping()) {
			mostrar('[-] ['.date($fecha_formato_salida).'] Se perdió la conexión con el servidor MySQL'."\n");
		}
		
		# Obtenemos el hash del archivo de configuración 
		# para comprobar si ha sido modificado
		$conf_md5_nuevo = md5_file($ruta_conf);
		
		if ($conf_md5_nuevo != $conf_md5) {
			mostrar('[i] ['.date($fecha_formato_salida).'] Cargando nueva configuración'."\n");
			
			$conf_anterior = $conf;
			
			try {
				if (($conf = @parse_ini_file($ruta_conf)) == false) {
						throw new Exception('[-] ['.date($fecha_formato_salida).'] Error cargando el nuevo fichero de configuración: '.$ruta_conf."\n".'[i] ['.fecha(date($fecha_estandar), $fecha_estandar, $fecha_formato_salida).'] Volviendo a utilizar la configuración anterior'."\n");
					}
				else {
					mostrar('[+] ['.date($fecha_formato_salida).'] Configuración cargada correctamente'."\n");
					unset($conf_anterior);
					}
			}
			catch (Exception $e) {
				mostrar($e -> getMessage());
				$conf = $conf_anterior;
			}
			
			# Obtenemos el nuevo hash del fichero de configuracion
			$conf_md5 = md5_file($ruta_conf);
		}
		
		# CORREOS
		# Envío de correo con estadisticas sobre los baneos
		# Habria que añadir una nueva directiva en el fichero de configuracion, si es 0, que no haga nada.
		# En caso contrario, deberiamos introducir el intervalo de tiempo en el que el programa debe enviar las estadisticas
		# La siguiente consulta devuelve las IPs baneadas en el dia de hoy.
		//~ SELECT * FROM baneos WHERE DATE_FORMAT(baneos.fecha_baneo, "%M%d%Y") = DATE_FORMAT(NOW(), "%M%d%Y");
		
		# Consulta que devuelve las IPs baneadas en la hora actual
		//~ SELECT * FROM baneos WHERE DATE_FORMAT(baneos.fecha_baneo, "%m%d%H") = DATE_FORMAT(NOW(), "%m%d%H");
		
		if ($conf['email']) {
			correo();
		}
		
		# Comprobamos si existen IPs baneadas que haya que desbanear
		eliminar_baneadas();
        
        # Comprobamos si cambió el fichero de logs de SSH
        $flag = 0;
        if ( empty($md5_ultimo) || ( md5_file($conf['SSHLog']) != $md5_ultimo ) ) {

			debugging_memoria('Carga de memoria antes de abrir el fichero de logs de SSH');

            $SSHLog = fopen($conf['SSHLog'], 'r') or die (mostrar("[-] Error abriendo el archivo: {$conf['SSHLog']} \n"));
			
			debugging_memoria('Carga de memoria despues de abrir el fichero de logs de SSH');
			
			# Contamos las líneas actuales del fichero
			$total_lineas = count(file($conf['SSHLog']));

			debugging_memoria('Carga de memoria después de contar las líneas del fichero de logs');

			# Comprobamos que en el fichero de los haya registros. 
			# En caso de que este vacío, esperamos
			if ($total_lineas > 0) {
				
				$fecha_deteccion = date($fecha_estandar);

				# Recorremos cada línea del archivo en busca de coincidencias de intento o inicio de sesión
				list($ultima_linea, $lineas) = ultima_linea();
				
				if ($conf['mostrar_restante']) {
					$lineas_restantes = $total_lineas - $ultima_linea;
					mostrar('[+] ['.date($fecha_formato_salida).'] Lineas por leer: '.$lineas_restantes."\n");
					}
					
				debugging_memoria('Carga de memoria antes de empezar a leer el fichero de logs de SSH');

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
							# Antes mostraba una barra cutre del total de lineas que habia leido
							//~ $barra = barra($porcentaje);
							//~ mostrar('  '.$barra.' '.$porcentaje.'% completado'."\n");
							
							if ($conf['mostrar_restante']) {
								mostrar('[i] ['.date($fecha_formato_salida).'] '.$porcentaje.'% completado'."\n");							
								}
						}

						$fecha = '';

						debugging_memoria('Carga de memoria antes de filtrar por los patrones de líneas correctas e incorrectas');

						# CONEXIONES CORRECTAS
						if ( preg_match($patron_correctas, $linea) ) {
							$tmp = limpiar_linea($linea, 1);
							
							$fecha = fecha("$tmp[0] $tmp[1] $tmp[2]", $formato_fecha_logs, $fecha_estandar);
							
							if (!empty($fecha)) {
								
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
											mostrar('[i] ['.date($fecha_formato_salida).'] El usuario '.$usuario.' inició sesion desde la IP: '.$IPorigen.' ('.pais($IPorigen).') ('.fecha($fecha, $fecha_estandar, $fecha_formato_salida).') '."\n");
											}
										else {
											mostrar('[-] ['.date($fecha_formato_salida).'] Error insertando registro en la BBDD con fecha '.fecha($fecha, $fecha_estandar, $fecha_formato_salida)."\n");
											}
									}
									else {
										mostrar('[i] ['.date($fecha_formato_salida).'] Entrada leida, omitiendo: '."$IPorigen\n");
									}

									$n_correctas++;
								}
								else {
									if (!isPublicIP($IPorigen)) {
										mostrar('[i] ['.date($fecha_formato_salida).'] Conexión permitida desde IP Privada: '.$IPorigen.' ('.fecha($fecha, $fecha_estandar, $fecha_formato_salida).')'."\n");										
										}
									else {
										mostrar('[i] ['.date($fecha_formato_salida).'] Conexión permitida desde IP en el Whitelist: '.$IPorigen.' ('.pais($IPorigen).') ('.fecha($fecha, $fecha_estandar, $fecha_formato_salida).')'."\n");										
										}
								}
							}
							else {
								mostrar('[-] ['.date($fecha_formato_salida).'] Error al formatear la fecha de los logs, saltando al siguiente registro'."\n");
								}

						}
						# CONEXIONES INCORRECTAS
						elseif (preg_match($patron_incorrectas ,$linea)) {
							$tmp = limpiar_linea($linea, 2);
							
							$fecha = DateTime::createFromFormat('M d H:i:s', "$tmp[0] $tmp[1] $tmp[2]") -> format($fecha_estandar);
							
							if (!empty($fecha)) {
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

									# Si la IP aún no ha superado el límite de intentos entramos
									if (empty($IPsBaneadas[$IPorigen]) || (!empty($IPsBaneadas[$IPorigen]) && $IPsBaneadas[$IPorigen] <= $conf['intentos'])) {

										if (!empty($IPsBaneadas[$IPorigen]) && $IPsBaneadas[$IPorigen] == $conf['intentos']) {
											goto saltar;
											}

										# Si no existe el registro lo añadimos
										if (! existe_en_ssh($usuario, $IPorigen, $fecha, $puerto, 2)) {

											if (insertar_en_ssh($usuario, $IPorigen, $fecha, $fecha_deteccion, $puerto, $n_linea, 2)) {
												mostrar('[i] ['.date($fecha_formato_salida).'] El usuario '.$usuario.' intentó iniciar sesión desde la IP: '.$IPorigen.' ('.pais($IPorigen).') ('.fecha($fecha, $fecha_estandar, $fecha_formato_salida).')'."\n");
												
												if ($IPorigen == 'Sin Usuario') {
													echo 'Sinn';
													exit;
													}
												
												if (empty($IPsBaneadas[$IPorigen])) {
													$IPsBaneadas["$IPorigen"] = 1;
													}
												else {
													$IPsBaneadas["$IPorigen"] = $IPsBaneadas[$IPorigen] + 1;
													}
												
												mostrar('[i] ['.date($fecha_formato_salida).'] '.$IPsBaneadas[$IPorigen].($IPsBaneadas[$IPorigen]==2?'º':'er').'  intento'."\n");
											}
											else {
												mostrar('[-]  ['.date($fecha_formato_salida).'] Error insertando registro en la BBDD con fecha '.fecha($fecha, $fecha_estandar, $fecha_formato_salida)."\n");
											}
										}
										else {
											mostrar('[i] ['.date($fecha_formato_salida).'] Entrada leída, omitiendo: '.$n_incorrectas."\n");
											}
										}
									
									saltar:
									
									$n_incorrectas++;
								}
								else {
									if (!isPublicIP($IPorigen)) {
										mostrar('[i] ['.date($fecha_formato_salida).'] Conexión incorrecta desde IP Privada: '.$IPorigen.' ('.fecha($fecha, $fecha_estandar, $fecha_formato_salida).')'."\n");										
										}
									else {
										mostrar('[i] ['.date($fecha_formato_salida).'] Conexión incorrecta desde IP en el Whitelist: '.$IPorigen.' ('.pais($IPorigen).') ('.fecha($fecha, $fecha_estandar, $fecha_formato_salida).')'."\n");										
										}
								}	
							}
							else {
								mostrar('[-] ['.date($fecha_formato_salida).'] Error al formatear la fecha de los logs, saltando al siguiente registro'."\n");
							}
						}
					}
					$n_linea++;

					@$porcentaje_anterior = $porcentaje;	
				}
				
				debugging_memoria('Carga de memoria despues de leer los cambios del fichero de logs');
			}
			else {
				mostrar('[-] ['.date($fecha_formato_salida).'] No hay registros en el fichero de logs'."\n");
				}

        $flag = 1;
        fclose($SSHLog);
        
        debugging_memoria('Carga de memoria despues de cerrar el fichero de logs');
        }
        
        $md5_ultimo = md5_file($conf['SSHLog']);
        
		debugging_memoria('Carga de memoria antes de aplicar las reglas');
        
		##### Aplicamos las reglas o las desactivamos
		ban_control();
		
		debugging_memoria('Carga de memoria después de aplicar las reglas');
		
        sleep ($conf['intervalo']);
    }
}
?>
