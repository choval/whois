# Choval/Whois

## Description

WHOIS wrapper for PHP with Async, get the country, owner and range of an IP.


## Uses

* Get the raw response from a WHOIS query
* Get the country of an IP address
* Get the owner of an IP address
* Get the range assigned to the IP address

Note:  
This library does not cache results. Please implement a cache accordingly to avoid abusing WHOIS servers.  
The `range` can be retrieve for an IP query and saved to a database to check before querying WHOIS servers again.


## Requirements

* whois command
* PHP 7.1+


## Installation

```sh
composer intall choval\whois
```


## Usage

This can be used with ReactPHP or in regular blocking mode.

### With ReactPHP

```php
$loop = \React\EventLoop\Factory::create();
$whois = new \Choval\Whois\Factory($loop);
$query = $whois->query('8.8.8.8');
$query->run()     // Returns a promise
  ->then(function($query) {
    print_r( $query->getRaw() );
    print_r( $query->getCountry() );
    print_r( $query->getOwner() );
    print_r( $query->getRange() );
  });
$loop->run();
```

### Regular, blocking mode

```php
$query = new \Choval\Whois\Query('8.8.8.8');
$query->run();
print_r( $query->getRaw() );
print_r( $query->getCountry() );
print_r( $query->getOwner() );
print_r( $query->getRange() );
```


## Extras

This library contains a few extra functions for handling IPv4 and IPv6.

### is\_ipv6

```php
use function \Choval\Whois\is_ipv6;

var_dump( is_ipv6('::1') );
// Returns true

var_dump( is_ipv6('1.1.1.1') );
// Returns false
```

### is\_ipv4

```php
use function \Choval\Whois\is_ipv4;

var_dump( is_ipv4('1.1.1.1') );
// Returns true

var_dump( is_ipv4('::1') );
// Returns false
```

### ip\_version

```php
use function \Choval\Whois\ip_version;

var_dump( ip_version('::1') );
// Returns string ipv6

var_dump( ip_version('1.1.1.1') );
// Returns string ipv4
```

### ip\_expand

This functions expands compressed IPv6 addresses.
Partial IPv4 addresses used in ranges are expanded as well, and non-significant leading zeroes removed.

```php
use function \Choval\Whois\ip_expand;

var_dump( ip_expand('::1') );
// Returns 0000:0000:0000:0000:0000:0000:0000:0001

var_dump( ip_expand('1::1') );
// Returns 0001:0000:0000:0000:0000:0000:0000:0001

var_dump( ip_expand('192.168.0') );
// Returns 192.168.0.0

var_dump( ip_expand('192.168.001.001') );
// Returns 192.168.1.1
```

### ip2hex

Converts an IP to it's hexadecimal representation.

```php
use function \Choval\Whois\ip2hex;

var_dump( ip2hex('196.11.31.255') );
// Returns c40b1fff

var_dump( ip2hex('2a03:2880::') );
// Returns 2a032880000000000000000000000000
```

### parse\_range

This functions parses a subnet or range (usually from the WHOIS response) and returns the from and to limits in IP, hex and binary format.  
Binary format is suggested for database storage and hex format for comparisson.

```php
use function \Choval\Whois\parse_range;

print_r( parse_range( '186.19.128/18') );
/*
Returns an array
     [range] => 186.19.128/18
      [from] => 186.19.128.0
        [to] => 186.19.191.255
  [bin_from] => (BINARY)
    [bin_to] => (BINARY)
  [hex_from] => ba138000
    [hex_to] => ba13bfff
*/

print_r( parse_range( '2a03:2880::/29') );
/*
Returns an array
     [range] => 2a03:2880::/29
      [from] => 2a03:2880:0000:0000:0000:0000:0000:0000
        [to] => 2a03:2887:ffff:ffff:ffff:ffff:ffff:ffff
  [bin_from] => (BINARY)
    [bin_to] => (BINARY)
  [hex_from] => 2a032880000000000000000000000000
    [hex_to] => 2a032887ffffffffffffffffffffffff
*/

print_r( parse_range( '196.11.31.0 - 196.11.31.255') );
/*
Returns an array
     [range] => 196.11.31.0 - 196.11.31.255
      [from] => 196.11.31.0
        [to] => 196.11.31.255
  [bin_from] => (BINARY)
    [bin_to] => (BINARY)
  [hex_from] => c40b1f00
    [hex_to] => c40b1fff
*/
```

### ip\_in\_range

Checks if an IP ins in a range. The range is calculated using `parse_range`.

```php
use function \Choval\Whois\ip_in_range;

var_dump( ip_in_range( '186.19.128.0', '186.19.128/18') );
// Returns true

var_dump( ip_in_range( '186.19.192.0', '186.19.128/18') );
// Returns false
```


## Testsuite

```sh
git clone https://github.com/choval/whois.git --depth 1
composer install
./vendor/bin/phpunit --testdox
```


