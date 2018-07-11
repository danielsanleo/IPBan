<?php
function mostrar($texto) {
	
    # Abrimos el fichero de log
	$log = fopen($GLOBALS['conf']['Log'], 'a');

	$memoria = '';
	if ($GLOBALS['conf']['Debug']) {
		$memoria =  'Memoria Emalloc: '.(number_format(memory_get_usage()/1024, 2)).' KB'."\n";
		$memoria .= 'Memoria Real: '.(number_format(memory_get_usage(True)/1024, 2)).' KB'."\n";
		fwrite($log, $memoria);
		}
	
	echo $texto.$memoria;

    fwrite($log, $texto);

    fclose($log);
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

function ultima_linea() {
	# Devuelve la última línea leida, guardada en la columna línea de la tabla ssh
	$lineas = $GLOBALS['db'] -> query('SELECT linea FROM ssh ORDER BY id DESC LIMIT 1');
	$ultima_linea = $lineas -> fetch_array();
	return array($ultima_linea[0], $lineas -> num_rows);
	}

function debugging($mensaje) {
	# Debug
	if ($GLOBALS['conf']['Debug']) {
		mostrar('[+] ['.date($GLOBALS['fecha_formato_salida']).'] '.$mensaje."\n");
		}
	}

function existe_regla($ip) {
	# Comprobamos si la regla existe
	
	exec("{$GLOBALS['conf']['binario_iptables']} -C INPUT -p all -s $ip -j DROP 2>/dev/null", $salida, $var);

	if ($var == 1) {
		return False;
		}
	else {
		return True;
		}
	}

function n_reglas() {
	return $GLOBALS['db'] -> query('SELECT COUNT(*) FROM baneos WHERE activo = 1') -> fetch_array()[0];
	}

function comprobar() {
	# Devuelve las reglas que deberían estar cargadas en IPTables
	# En caso de que se hara reiniciado el servidor y las reglas hayan desaparecido
	# esta funcion se encarga de volver a cargarlas en caso de que no esten presentes
	
	$baneos = $GLOBALS['db'] -> query('SELECT * FROM baneos WHERE activo = 1 AND fecha_fin > NOW()');
	
	mostrar('[+] ['.date($GLOBALS['fecha_formato_salida']).'] Comprobando las reglas cargadas'."\n");
	
	# Si hay reglas que deberian estar cargadas entramos
	if ($baneos -> num_rows > 0) {
		$recargas = 0;
		$recargas_errores = 0;
		while ($baneo = $baneos -> fetch_array()) {
			
			if (!existe_regla($baneo['ip'])) {
				mostrar('[+] ['.date($GLOBALS['fecha_formato_salida']).'] La IP '.$baneo['ip'].' debería estar baneada'."\n".'[+] Baneando... ');
				
				# Insertamos la regla en iptables
				exec("{$GLOBALS['conf']['binario_iptables']} -A INPUT -p all -s {$baneo['ip']} -j DROP", $out, $return_var);
				
				if ($return_var == 0) {
					mostrar('OK'."\n");
					$recargas++;
					}
				else {
					mostrar('Error Baneando la IP: '."\n");
					$recargas_errores++;
					}
				}
			}
			
			if ($recargas > 0) {
				mostrar('[+] ['.date($GLOBALS['fecha_formato_salida']).'] '.$recargas.' reglas cargadas'."\n");
				}	
			
			
			if ($recargas_errores > 0) {
				mostrar('[-] ['.date($GLOBALS['fecha_formato_salida']).'] '.$recargas_errores.' reglas no pudieron ser cargadas: '."\n");
				}		
		}
	}

function limpiar_linea($linea, $tipo) {
	# Dependiendo del mes hay mas o menos espacios
	# Así que eliminamos espacios sobrantes reduciendo cada separacion a un espacio
	# Ej: Jan 31 08:43:08 ragnar sshd[19291]: Failed password for invalid user support from 91.224.160.153 port 51431 ssh2
	# Ej: Jan 31 08:44:10 ragnar sshd[19294]: Failed password for root from 91.224.160.153 port 5609 ssh2
	# Ej: Feb 25 00:39:15 elservidor.info sshd[26782]: Failed password for invalid user  from 193.201.224.109 port 8423 ssh2
	$tmp = explode(' ', $linea);
	
	# Si esta vacia la posicion 10 significa que probaron sin usuario
	if ($tipo == 2 && empty($tmp[10])) {
		$tmp[10] = 'Sin Usuario';
		}
	
	foreach ($tmp as $clave => $valor) {
		trim($valor);
		if (empty($valor)) {
			unset($tmp[$clave]);
			$tmp = array_merge($tmp);
		}
	}
	
	# Si el array tiene mas de 15 posiciones significa que el atacante probó un usuario con espacios
	if (count($tmp) > 15) {
		
		# Buscamos la clave de la posicion del 'from'
		$clave_from = array_search('from', $tmp);
		
		# Restamos la $clave_from - 9 ( la posicion de 'user' ) para saber cuantas posiciones existen entre los dos, y determinar cual fue el usuario que introdujo
		$resta = $clave_from - 9;
		
		# Rellenamos la posicion 10 ( donde se supone que esta la primera palabra del usuario) con las demas palabras pertenecientes al campo usuario
		# Eliminamos las posiciones sobrantes
		# Unimos el array de nuevo
		for ($i = 11; $i < $clave_from; $i++) {
			$tmp[10] .= ' '.$tmp[$i];
			unset($tmp[$i]);
			$tmp = array_merge($tmp);
			}
		}
	
	//~ print_r($tmp);
	
	return $tmp;
}

# Funcion que devuelve el pais de una IP
function pais($ip) {
	
	# Comprobamos que la extension geoip este cargada
	if (extension_loaded('geoip')) {
		return geoip_country_name_by_name($ip);
		}
	else {
		return 'GeoIP no cargado';
		}
	}

# Funcion para insertar un intento de conexion en la tabla SSH
function insertar_en_ssh($usuario, $ip, $fecha, $fecha_deteccion, $puerto, $linea, $estado) {

	if (isPublicIP($ip)) {
		$pais = pais($ip);
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
//~ banear('111.47.243.189', 'China', '2017-11-16 13:3...', '2017-11-16 10:3...')
function banear($ip) {
	
	debugging('Carga de memoria al comienzo de la función banear()');

	# Consultamos la fecha actual
	$fecha_inicio = fecha('', '', $GLOBALS['fecha_estandar']);
	
	# Calculamos la fecha de fin de baneo
	$fecha_fin = DateTime::createFromFormat($GLOBALS['fecha_estandar'], date($GLOBALS['fecha_estandar'])) 
							-> modify("+{$GLOBALS['conf']['tiempo']} {$GLOBALS['conf']['unidad']}") 
							-> format($GLOBALS['fecha_estandar']);
	
	# Añadimos la IP al Blacklist
	$query = "INSERT INTO baneos SET 
								ip='$ip', 
								fecha_fin='$fecha_fin',
								fecha_baneo='$fecha_inicio',
								activo=1";
	
	# Volvemos a formatear la fecha actual para mostrarla
	$fecha_inicio = fecha($fecha_inicio, $GLOBALS['fecha_estandar'], $GLOBALS['fecha_formato_salida']);
	
	$fecha_fin = fecha($fecha_fin, $GLOBALS['fecha_estandar'], $GLOBALS['fecha_formato_salida']);
	
	# Comprobamos primero que la regla no este cargada ya en IPTables
	exec("{$GLOBALS['conf']['binario_iptables']} -C INPUT -p all -s $ip -j DROP 2>/dev/null", $salida, $var);

	# Si var es 1 es que no esta cargada en IPTables
	if ($var == 1) {

		if ($GLOBALS['db'] -> query($query)) {

				# Mostramos la información sobre la IP baneada
				$veces_baneada = $GLOBALS['db'] -> query("SELECT COUNT(*) AS veces_baneada FROM baneos WHERE ip='$ip' GROUP BY ip") -> fetch_array()[0];
				
				if ($veces_baneada > 1) {
					$sql="SELECT fecha_baneo FROM baneos WHERE ip='$ip' ORDER BY 1 DESC LIMIT 1 OFfSET 1";
					//~ echo $sql;
					//~ exit;
					$ultima_vez = $GLOBALS['db'] -> query($sql) -> fetch_array()[0];
					$ultima_vez = fecha($ultima_vez, $GLOBALS['fecha_estandar'], $GLOBALS['fecha_formato_salida']);
					}
				
				mostrar('[+] Baneando la IP: '.$ip."\n".'[+] Pais: '.pais($ip)."\n".'[+] Fecha Inicio: '.$fecha_inicio."\n".'[+] Fecha Fin: '.$fecha_fin."\n".'[+] Veces Baneada: '.$veces_baneada."\n".(!empty($ultima_vez)?'[+] Última vez: '.$ultima_vez."\n":''));

				# Desde las 7 a las 23 dirá si se ha baneado alguna IP
				# La directiva hablar ha de ser 1 para que hable
				if ($GLOBALS['conf']['hablar'] && (date('H') < 23 && date('H') > 7)) {
					exec("espeak -v es 'IP de $pais baneada' 2>/dev/null");
					}

				$GLOBALS['db'] -> query("UPDATE ssh SET nuevo=1 WHERE ip='$ip'");
				unset($GLOBALS['IPsBaneadas'][$ip]);
			}
		else {
			mostrar('[-] Error insertando en la BBDD: '."\n". $GLOBALS['db'] -> error ."\n");
			}

		# Insertamos la regla en iptables
		exec("{$GLOBALS['conf']['binario_iptables']} -A INPUT -p all -s $ip -j DROP", $out, $return_var);
		
		if ($return_var == 0) {
			mostrar('[+] OK'."\n"."\n");
			}
		else {
			mostrar('[-] Error Baneando la IP: '.$ip."\n");
			}
		}
	else {
		if ($GLOBALS['db'] -> query($query)) {
			mostrar('[i] ['.date($GLOBALS['fecha_formato_salida']).'] La IP: '.$ip.' ya esta baneada, exportando la regla a la BBDD'."\n");
			}
		else {
			mostrar('[i] ['.date($GLOBALS['fecha_formato_salida']).'] La IP: '.$ip.' ya esta baneada, Error exportando la regla a la BBDD'."\n");
			}
		}
	
	debugging('Carga de memoria al final de la función banear()');
	}

function eliminar_baneadas () {
        $baneos_viejos = $GLOBALS['db'] -> query("SELECT * FROM baneos WHERE fecha_fin < NOW() AND activo=1");

        # Entramos solo si hay IPs a desbanear
        if ($baneos_viejos -> num_rows > 0) {

            while ($baneo = $baneos_viejos -> fetch_array()) {
                
                # Comprobamos si la regla existe en el listado de iptables
                # Solo la quitamos si existe, sino, solo actualizamos la tabla de baneos
                
                if (existe_regla($baneo['ip'])) {
					mostrar("[+] Eliminando baneo para la IP: {$baneo['ip']} (".pais($baneo['ip']).")\n");
					
					# Actualizamos la IP como neutral (Sin Banear)
					$GLOBALS['db'] -> query("UPDATE baneos SET activo=0 WHERE ip='{$baneo['ip']}'");
					
					# Eliminamos la regla de iptables
					exec("{$GLOBALS['conf']['binario_iptables']} -D INPUT -p all -s {$baneo['ip']} -j DROP", $out, $return_var);
					
					if ($return_var == 0) {
						mostrar("[+] OK\n");
						}
					else {
						mostrar("[-] Error eliminando de baneos la IP: $ip\n");
						}
					}
				else {
					mostrar("[-] La IP: {$baneo['ip']} no se encuentra en iptables, actualizando BBDD \n");
					$GLOBALS['db'] -> query("UPDATE baneos SET activo=0 WHERE ip='{$baneo['ip']}'");
					}
                }
			
			$baneos_viejos -> free();
		}
	}
	
# Funcion de manipulación de fechas
function fecha($fecha, $formato_fecha_entrada, $formato_fecha_salida = 'Y-m-d H:i:s') {
	try {
		return DateTime::createFromFormat($formato_fecha_entrada, $fecha) -> format($formato_fecha_salida);	
	} catch (Exception $e) {
		return 0;
	}
}

# Funcion que consulta las IPs que hay que banear
# las recorre y las va baneando una a una
function ban_control() {
		##### Aplicamos las reglas o las desactivamos
        $total_intentos = $GLOBALS['db'] -> query('SELECT count(*) AS intentos, ip, pais FROM ssh WHERE estado=2 AND nuevo=0 AND ip NOT IN (SELECT ip FROM baneos WHERE activo = 1) GROUP BY ip HAVING intentos >= '.$GLOBALS['conf']['intentos'].' ORDER BY intentos DESC');
        
        # Entramos solo si hay IPs que banear
        if ($total_intentos -> num_rows > 0) {
            
            mostrar('[i] ['.date($GLOBALS['fecha_formato_salida']).'] Comenzando a banear: '.$total_intentos -> num_rows.($total_intentos -> num_rows == 1?' IP':' IPs')."\n");
            
            # Baneamos la IP
            while ($intento = $total_intentos -> fetch_array()) {
                banear($intento['ip']);
                }
                
            $total_intentos -> free();
        }
	}
	
function correo() {
		$fecha_objeto = new DateTime();
		$fecha_actual = $fecha_objeto -> getTimestamp();

		if ($fecha_actual >= $GLOBALS['fecha_proxima_ejecucion']) {
			mostrar('[i] ['.date($GLOBALS['fecha_formato_salida']).'] Enviando el correo con las estadísticas'."\n");
			
			$mail = new PHPMailer(true);

			try {
				$mail -> CharSet = 'UTF-8';
				$mail -> SMTPDebug = 2;                                 
				$mail -> isSMTP();                                    
				$mail -> Host = $GLOBALS['conf']['email_host'];
				$mail -> SMTPAuth = True;                               
				$mail -> Username = $GLOBALS['conf']['email_usuario'];
				$mail -> Password = $GLOBALS['conf']['email_pass'];                           
				$mail -> SMTPSecure = $GLOBALS['conf']['email_seguridad'];                            
				$mail -> Port = $GLOBALS['conf']['email_puerto'];

				$mail -> setFrom($GLOBALS['conf']['email_usuario']);
				$mail -> addCC($GLOBALS['conf']['email_destino']);

				$mail -> isHTML(true);
				$mail -> Subject = 'Estadísticas de IPBan';
				$mail -> AltBody = 'Necesita un visor de correo compatible con HTML';

				$mail -> SMTPOptions = array('ssl' => array('verify_peer' => false,
															'verify_peer_name' => false,
															'allow_self_signed' => true));

				# Calculamos la fecha en la que se envi&oacute; el ultimo e-mail para consultar las IPs baneadas en ese interalo
				$fecha_ultimo_envio = $fecha_objeto -> modify("-{$GLOBALS['conf']['email_intervalo']}") -> format('Y-m-d H:i:s');

				# Baneos del último intervalo en el que no se envió el correo
				$baneos_intervalo = $GLOBALS['db'] -> query('SELECT ip, 
																	COUNT(ip) AS "N", 
																	MAX(baneos.fecha_baneo) AS ultima_vez 
															 FROM baneos 
															 WHERE baneos.fecha_baneo BETWEEN "'.$fecha_ultimo_envio.'" AND NOW() 
															 GROUP BY ip');

				$total_Intervalo = $baneos_dia -> num_rows;
				
				while ($baneo = $baneos_intervalo -> fetch_array()) {
					$ultimoIntervalo = <<<DIA
						<tr>
							<td>{$baneo['ip']}</td>
							<td>{$baneo['N']}</td>
							<td>{$baneo['ultima_vez']}</td>
						</tr>
DIA;
					}
				
				$baneos_intervalo -> free();
				
				# Baneos en lo que va de día
				$baneos_dia = $GLOBALS['db'] -> query('SELECT ip, 
															  COUNT(ip) AS "N", 
															  MAX(baneos.fecha_baneo) AS ultima_vez 
													   FROM baneos 
													   WHERE DATE_FORMAT(baneos.fecha_baneo, "%M%d%Y") = DATE_FORMAT(NOW(), "%M%d%Y") 
													   GROUP BY ip');
				
				$total_dia = $baneos_dia -> num_rows;
				
				$resumenDia = '';
				while ($baneo = $baneos_dia -> fetch_array()) {
					$resumenDia = <<<DIA
						<tr>
							<td>{$baneo['ip']}</td>
							<td>{$baneo['N']}</td>
							<td>{$baneo['ultima_vez']}</td>
						</tr>
DIA;
					}
				
				$baneos_dia -> free();
				
				# Baneos en lo que va de mes
				$baneos_mes = $GLOBALS['db'] -> query('SELECT ip, 
															  COUNT(ip) AS "N", 
															  MAX(baneos.fecha_baneo) AS ultima_vez 
													   FROM baneos 
													   WHERE DATE_FORMAT(baneos.fecha_baneo, "%M%Y") = DATE_FORMAT(NOW(), "%M%Y") 
													   GROUP BY ip');
				
				$total_mes = $baneos_mes -> num_rows;
				
				$resumenMes = '';
				while ($baneo = $baneos_mes -> fetch_array()) {
					$resumenMes = <<<DIA
						<tr>
							<td>{$baneo['ip']}</td>
							<td>{$baneo['N']}</td>
							<td>{$baneo['ultima_vez']}</td>
						</tr>
DIA;
					}
				
				$baneos_mes -> free();

				$mail -> Body = <<<BODY
						<!DOCTYPE html>
						<html>
							<head>
								<meta charset="UTF-8">
								<meta name="viewport" content="width=device-width, initial-scale=1.0">
							</head> 
							<img id='logo' src=' data:image/jpeg;base64,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'>

							<div id='cuerpo'>
								<table border="1">
									<tr>
										<th colspan="3"> <hr> </th>
									</tr>
									<tr>
										<th colspan="3"> <h4> IPs Baneadas en el último día: $total_Intervalo </h4> </th>
									</tr>
									<tr>
										<th> IP </th>
										<th> Nº Veces Baneada </th>
										<th> Último Baneo </th>
									</tr>
									$ultimoIntervalo
									<tr>
										<th colspan="3"> <hr> </th>
									</tr>
									<tr>
										<th colspan="3"> <h4> IPs Baneadas en el último día: $total_dia </h4> </th>
									</tr>
									<tr>
										<th> IP </th>
										<th> Nº Veces Baneada </th>
										<th> Último Baneo </th>
									</tr>
									$resumenDia
									<tr>
										<th colspan="3"> <hr> </th>
									</tr>
									<tr>
										<th colspan="3"> <h4> IPs Baneadas en el último mes: $total_mes </h4> </th>
									</tr>
									<tr>
										<th> IP </th>
										<th> Nº Veces Baneada </th>
										<th> Último Baneo </th>
									</tr>
									$resumenMes
								</table>
							</div>
							
							<style>
								#logo {
									width: 180px;
									}
								#titulo {
									padding-top: 75px;
									}
							</style>
						</html>
BODY;
				$mail -> send();
				mostrar('[+] ['.date($GLOBALS['fecha_formato_salida']).'] Email enviado con éxito'."\n");
			} 
			catch (Exception $e) {
				mostrar('[-] ['.date($GLOBALS['fecha_formato_salida']).'] Error al enviar el correo electrónico'."\n");
				mostrar('[-] ['.date($GLOBALS['fecha_formato_salida']).'] '.($mail -> ErrorInfo)."\n");
			}

			$GLOBALS['fecha_proxima_ejecucion'] = (new DateTime()) -> modify("+{$GLOBALS['conf']['email_intervalo']}") -> getTimestamp();
		}
	}
?>
