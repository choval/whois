<?php
namespace Choval\Whois;

use React\EventLoop\LoopInterface;
use React\Promise\Deferred;
use React\ChildProcess\Process;

use function Choval\Whois\is_ipv6;
use function Choval\Whois\is_ipv4;
use function Choval\Whois\ip_version;
use function Choval\Whois\parse_range;
use function Choval\Whois\ip_expand;

final class Query {

  private $loop;
  private $timeout;

  private $addr;
  private $server;
  private $port;

  private $sections = [];
  private $lines = [];



  /**
   * Constructor
   */
  public function __construct(string $addr=null, string $server=null, integer $port=null, LoopInterface $loop=null, float $timeout=3) {
    $this->addr = $addr;
    $this->server = null;
    $this->port = null;
    $this->loop = $loop;
    $this->timeout = $timeout;
  }



  /**
   * Builds the command to execute
   */
  private function getCommand() {
    return sprintf('which whois && whois %s %s %s', ($this->server ? '-h '.$this->server : '' ), ($this->port ? '-p '.$this->port : ''), $this->addr);
  }



  /**
   * Runs a query
   */
  public function run() {
    return $this->query();
  }
  public function query() {
    $cmd = $this->getCommand();
    // Run in blocking mode if no loop
    if(empty($this->loop)) {
      exec($cmd, $lines);
      $this->sections = $this->parseSections($lines);
      $this->lines = $lines;
      return $this;
    }
    $defer = new Deferred;
    $proc = new Process($cmd);
    $proc->start( $this->loop );
    $buffer = '';
    $proc->stdout->on('data', function($data) use (&$buffer) {
      $buffer .= $data;
    });
    $proc->on('exit', function($exitCode) use ($defer, &$buffer) {
      $lines = explode("\n", $buffer);
      if($exitCode) {
        $defer->reject( new \Exception('WHOIS query failed') );
      }
      $this->sections = $this->parseSections($lines);
      $this->lines = $lines;
      $defer->resolve($this);
    });
    $this->loop->addTimer($this->timeout, function() use ($defer, $proc) {
      $proc->terminate();
      $defer->reject( new \Exception('WHOIS timed out') );
    });
    return $defer->promise();
  }



  /**
   * Parses the response from the WHOIS server
   */
  public function parseSections($response) {
    if(is_string($response)) {
      $response = explode("\n", $response);
    }
    $sections = [];
    $section = [];
    foreach($response as $line) {
      $line = trim($line);
      if(empty($line) || in_array($line[0], ['%', '#']) ) {
        if(!empty($section)) {
          $sections[] = $section;
          $section = [];
        }
        continue;
      }
      $parts = explode(':', $line, 2);
      $key = $parts[0];
      $data = trim($parts[1] ?? '');
      if(isset($section[$key])) {
        $section[$key] .= "\n".$data;
      } else {
        $section[$key] = $data;
      }
    }
    return $sections;
  }



  /**
   * Parse data
   */
  public function parseData($lines, array $columns, bool $reverse=false) {
    if(is_string($lines)) {
      $lines = explode("\n", $lines);
    }
    $res = false;
    if($reverse) {
      $lines = array_reverse($lines);
    }
    foreach($lines as $pos=>$line) {
      if(is_numeric($pos)) {
        $line = trim($line);
        if(empty($line) || in_array($line[0],['%', '#']) ){
          continue;
        }
        $parts = explode(': ', $line, 2);
        $key = strtolower(trim($parts[0]));
        $data = trim($parts[1]??'');
      } else {
        $key = $pos;
        $data = $line;
      }
      $lowdata = strtolower($data);
      if(!$res && in_array($key, $columns)) {
        $res = $data;
      } else if($lowdata == 'reallocated') {
        $res = false;
      }
    }
    return $res;
  }



  /**
   * Returns the sections
   */
  public function getSections() {
    return $this->sections;
  }



  /**
   * Returns the raw response
   */
  public function getRaw() {
    return utf8_encode(implode("\n", $this->lines));
  }
  public function __toString() {
    return $this->getRaw();
  }



  /**
   * Gets the country from sections
   */
  public function getCountry() {
    return $this->parseData($this->lines, ['country', 'registrant country']);
  }



  /**
   * Gets the company
   */
  public function getOwner() {
    return $this->parseData($this->lines, ['organization', 'org-name', 'orgname', 'owner', 'descr', 'registrant organization']);
  }



  /**
   * Gets the address
   */
  public function getIp() {
    return $this->addr;
  }
  public function getAddress() {
    return $this->addr;
  }



  /**
   * Returns boolean if its IPv6, otherwise its IPv4
   */
  public function isVersion6($ip=null) {
    return is_ipv6($ip ?? $this->addr);
  }
  public function isVersion4($ip=null) {
    return is_ipv6($ip ?? $this->addr);
  }



  /**
   * Returns the version
   */
  public function getVersion($ip=null) {
    return ip_version($ip ?? $this->addr, true);
  }



  /** 
   * Gets the range from-to
   */
  public function getRange() {
    $range = $this->parseData( $this->lines, ['inet6num', 'inetnum', 'route', 'netrange', 'cidr'], true );
    return $range ? parse_range($range) : false;
  }



}

