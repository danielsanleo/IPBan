# IPBan
Baneo de IPs para SSH y registro en MySQL

#### Probado en Arch Linux

# Dependencias
mysql
php
php-geoip

# Habilitar el modulo de MySQL en php.ini descomentando la siguiente linea
extension=mysqli.so

# Escribir la siguiente linea tambien en php.ini
extension=geoip.so
