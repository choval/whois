<?php

namespace Choval\Whois {


  function is_ipv6(string $addr): bool
  {
      return (ip_version($addr) == 'ipv6') ? true : false;
  }


  function is_ipv4(string $addr): bool
  {
      return (ip_version($addr) == 'ipv4') ? true : false;
  }


  function ip_version(string $addr, bool $force = false)
  {
      $bin = @inet_pton($addr);
      $len = strlen($bin);
      if ($len == 4) {
          return 'ipv4';
      }
      if ($len == 16) {
          return 'ipv6';
      }
      if ($force) {
          if (strpos($addr, ':', 1)) {
              return 'ipv6';
          } elseif (strpos($addr, '.', 1)) {
              return 'ipv4';
          }
      }
      return false;
  }


  /**
   * Acceps an IPv4 or IPv6 subnet or range like:
   * 10.0.0.1 - 10.0.255.255
   * 10.0.0.0/16
   *
   * Returns an array with:
   * - from
   * - to
   * - bin_from
   * - bin_to
   * - hex_from
   * - hex_to
   *
   * Or false if the range is not valid
   *
   * Addresses returned are in complete/expanded format,
   * this means aaaa::ffff gets expanded to
   * aaaa:0000:0000:0000:0000:0000:0000:ffff
   *
   * IPv6 are returned in lowercase.
   *
   */
  function parse_range(string $range)
  {
      if (empty($range)) {
          return false;
      }
      $from = false;
      $to = false;
      if (strpos($range, ' - ')) {
          $parts = explode(' - ', $range, 2);
          $from = ip_expand(trim($parts[0]));
          $to = ip_expand(trim($parts[1]));
      } else {
          if (strpos($range, '/')) {
              $parts = explode('/', $range, 2);
              $addr = ip_expand($parts[0]);
              $prefix = (int)$parts[1];
              $v = ip_version($addr);
          } else {
              $addr = ip_expand($range);
              $v = ip_version($addr);
              if ($v == 'ipv4') {
                  $prefix = 32;
              } elseif ($v == 'ipv6') {
                  $prefix = 128;
              }
          }
          if ($v == 'ipv4') {
              $start = ip2long($addr);
              $size = 1 << (32 - $prefix);
              $end = $start + $size - 1;
              $from = ip_expand($addr);
              $to = long2ip($end);
          } elseif ($v == 'ipv6') {
              $from_parts = explode(':', $addr);
              $from_binary = '';
              foreach ($from_parts as $part) {
                  $from_binary .= str_pad(decbin(hexdec($part)), 16, '0', STR_PAD_LEFT);
              }
              $to_binary = substr($from_binary, 0, $prefix);
              $to_binary = str_pad($to_binary, 128, '1');
              $to_parts = [];
              $parts = str_split($to_binary, 16);
              foreach ($parts as $part) {
                  $to_parts[] = str_pad(dechex(bindec($part)), 4, '0', STR_PAD_LEFT);
              }
              $from = $addr;
              $to = implode(':', $to_parts);
          }
      }
      if ($from && $to) {
          $bin_from = inet_pton($from);
          $bin_to = inet_pton($to);
          return [
            'range' => $range,
            'from' => $from,
            'to' => $to,
            'bin_from' => $bin_from,
            'bin_to' => $bin_to,
            'hex_from' => bin2hex($bin_from),
            'hex_to' => bin2hex($bin_to),
          ];
      }
      return false;
  }



  /**
   * Completes a partial address
   * Sometimes passed as inetnum/CIDR
   */
  function ip_expand(string $address)
  {
      $v = ip_version($address, true);
      if ($v == 'ipv4') {
          $parts = explode('.', $address);
          for ($i = 0;$i < 4;$i++) {
              $parts[$i] = (int)($parts[$i] ?? 0);
          }
          $addr = implode('.', $parts);
          return inet_pton($addr) ? $addr : false;
      } elseif ($v == 'ipv6') {
          if (strpos($address, '::')) {
              $ends = explode('::', $address, 2);
              $heads = explode(':', $ends[0]);
              $tails = explode(':', $ends[1]);
              $zeroes = 8 - count($heads) - count($tails);
              $parts = [];
              foreach ($heads as $part) {
                  $parts[] = str_pad($part, 4, '0', STR_PAD_LEFT);
              }
              for ($i = 0;$i < $zeroes;$i++) {
                  $parts[] = '0000';
              }
              foreach ($tails as $part) {
                  $parts[] = str_pad($part, 4, '0', STR_PAD_LEFT);
              }
          } else {
              $parts = explode(':', $address);
              foreach ($parts as $pos => $part) {
                  $parts[$pos] = str_pad($part, 4, '0', STR_PAD_LEFT);
              }
          }
          $addr = strtolower(implode(':', $parts));
          return inet_pton($addr) ? $addr : false;
      }
      return false;
  }



  /**
   * Returns wether an address is in the range.
   * Uses the hexadecimal to check if its between
   */
  function ip_in_range(string $addr, $range)
  {
      $ranges = explode(',', $range);
      foreach ($ranges as $range) {
          $range = trim($range);
          if (empty($range)) {
              continue;
          }
          $limits = parse_range($range);
          if (empty($limits)) {
              trigger_error('Range is not valid', \E_USER_WARNING);
              return false;
          }
          $addr = ip_expand($addr);
          $hex = bin2hex(inet_pton($addr));
          $smaller = strcmp($hex, $limits['hex_from']);
          $larger = strcmp($limits['hex_to'], $hex);
          if ($smaller >= 0 && $larger >= 0) {
              return true;
          }
      }
      return false;
  }



  /**
   * Converts an IP to hex
   */
  function ip2hex(string $addr)
  {
      $addr = ip_expand($addr);
      return bin2hex(inet_pton($addr));
  }



}
