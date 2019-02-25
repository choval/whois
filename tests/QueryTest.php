<?php

use PHPUnit\Framework\TestCase;
use React\EventLoop\Factory as LoopFactory;
use React\Promise\Promise;
use Clue\React\Block;

use Choval\Whois\Query;
use Choval\Whois\Factory;

use function Choval\Whois\ip_in_range;

class QueryTest extends TestCase {

  static $loop;



  /**
   * Loads a React Loop
   */
  public static function setUpBeforeClass() {
    static::$loop = LoopFactory::create();
    static::$loop->run();
  }



  /**
   * Wait for a promise (makes code synchronous) or stream (buffers)
   */
  private function wait( $promise , $timeout = 5 ) {
    if($promise instanceof \React\Promise\PromiseInterface) {
      return Block\await( $promise, static::$loop, $timeout );
    } else if(is_array($promise)) {
      return Block\awaitAll( $promise, static::$loop, $timeout );
    }
    return $promise;
  }



  public function ipProvider() {
    return [
      [ '8.8.8.8', 'US', 'Google LLC (GOGL)', 'ipv4' ],
      [ '13.77.161.179', 'US', 'Microsoft Corporation (MSFT)', 'ipv4' ],
      [ '31.13.85.36', 'BR', 'Facebook', 'ipv4' ],
      [ '194.224.110.41', 'ES', 'Telefonica Soluciones', 'ipv4' ],
      [ '124.74.250.145', 'CN', 'CHINANET Shanghai province network', 'ipv4' ],
      [ '196.11.31.20', 'ZA', 'Bidorbuy (Pty) Ltd', 'ipv4' ],
      [ '2a03:2880:f11b:83:face:b00c:0:25', 'IE', 'Facebook Ireland Ltd', 'ipv6' ],
      [ '2001:4860:4860::8888', 'US', 'Google LLC (GOGL)', 'ipv6' ],
    ];
  }


  public function partialIpProvider() {
    return [
      [ '192.168.0', '192.168.0.0', 'ipv4' ],
      [ '2001:0db8::1428:57ab', '2001:0db8:0000:0000:0000:0000:1428:57ab', 'ipv6' ],
    ];
  }


  public function domainProvider() {
    return [
      ['google.com'],
      ['microsoft.com'],
    ];
  }


  public function singleProvider() {
    $ips = $this->ipProvider();
    $rand = array_rand( $this->ipProvider() );
    return [ $ips[$rand] ];
  }




  /**
   * @dataProvider ipProvider
   */
  public function testQueryAsync($ip, $country, $org) {
    $factory = new Factory( static::$loop );
    $query = $factory->create($ip);

    $this->assertInstanceOf(Query::class, $query);
    $this->assertEquals( $ip, $query->getIp() );

    $promise = $query->run();
    $this->assertInstanceOf(Promise::class, $promise);
    $res = static::wait( $promise );
    $this->assertInstanceOf(Query::class, $res);

    $this->assertEquals( $country, $query->getCountry());
    $this->assertEquals( $org, $query->getOwner());

    $range = $query->getRange();
    $this->assertNotFalse($range);
    $inRange = ip_in_range( $ip, $range['range'] );
    $this->assertTrue( $inRange );
  }



  /** 
   * @dataProvider singleProvider
   */
  public function  testQueryBlocking($ip, $country, $org) {
    $query = new Query($ip);
    $this->assertEquals( $ip, $query->getIp() );

    $query->run();

    $this->assertEquals( $country, $query->getCountry());
    $this->assertEquals( $org, $query->getOwner());
  }



  /**
   * @dataProvider domainProvider
   */
  public function testQueryDomain($domain) {
    $q = new Query($domain);
    $this->assertNotEmpty($q->run()->getRaw());
  }


}

